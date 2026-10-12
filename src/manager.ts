// kirari-net · src/manager.ts
// 组网门面：把身份、状态、主机端、叶子端串成一条可用的链路。
//
// 单独一层的理由：接线里有几个**必须成对发生**的动作，漏一个就会出诡异 bug：
//   - 配对成功后，必须同时保存「主机地址 + 端口 + 长期凭据」，否则重开组网连不上
//   - 角色切换只改 role，绝不能碰地址/凭据（否则「退出不清除」失效）
//   - 主机侧配对码被消费后要落盘，否则重启后同一个码能反复用
// 这些如果散落在 main.ts 的 IPC 回调里，迟早漏。所以收在这里。
//
// 阶段 2 范围：基础设施（配对 / 心跳 / 成员）。活锁路由在阶段 3 加。

import * as path from "node:path";
import { HostServer, guessHostAddress, localAddresses } from "./hostServer";
import type { MemberInfo } from "./hostServer";
import { LeafClient } from "./leafClient";
import type { LeafStatus } from "./leafClient";
import { loadOrCreateIdentity, renameIdentity } from "./identity";
import type { DeviceIdentity } from "./identity";
import {
    loadNetState,
    saveNetState,
    enableNetworking,
    disableNetworking,
    addPairing,
    revokePairing,
    pruneExpiredPairings,
    attachToHost,
    removeMember,
    detachFromHost,
    setSyncWhitelist,
    filterWhitelisted,
    DEFAULT_EXPIRY,
} from "./netStore";
import type { NetState, NetRole } from "./netStore";
import {
    generatePairingCode,
    parseAnyPairingCode,
    serializeInviteCode,
    serializePairingCode,
    describeRemaining,
    randomToken,
} from "./pairingCode";
import type { PairingCode, ExpiryKey } from "./pairingCode";
import { NET_PORT, PROTOCOL_VERSION, SYNC_FIELDS } from "./protocol";
import type { RelayResult, RelayBusy, RelayDelta, RelayBackfill, ConfigPush, SyncField, KbPassage } from "./protocol";
import { RelayRouter } from "./relayRouter";
import type { RelayExecutor } from "./relayRouter";
import { isNetEnabled, setNetSecret, newNetSecret } from "./secure";
import { setEnrolledSecret, setOwnSecret, storedSecret, forgetEnrolledSecret } from "./netStore";
export type NetSnapshot = {
    role: NetRole;
    deviceId: string;
    deviceName: string;
    /** 主机地址（叶子侧：已连的主机；主机侧：待展示给客人的地址） */
    address: string;
    port: number;
    hostName?: string;
    /** 主机侧：已生成的配对码 */
    pairings: { id: string; name: string; expiresAt: number; remaining: string; usedBy: string | null; revoked: boolean }[];
    /** 主机侧：成员 */
    members: MemberInfo[];
    /** 叶子侧：连接状态 */
    leafStatus?: LeafStatus;
    /** 叶子侧：待补传的离线对话条数 */
    pendingBackfill?: number;
    /** 主机侧：出口忙不忙 */
    relay?: { running: number; queued: number; maxConcurrent: number; maxQueue: number } | null;
    /** 主机侧：配置同步白名单 */
    syncWhitelist?: SyncField[];
};

export type NetManagerEvents = {
    onSnapshot?: (snap: NetSnapshot) => void;
    /** 自动退出组网时要告知用户（避免误以为程序崩了） */
    onFallbackNotice?: (message: string) => void;
    onLog?: (message: string) => void;
    /**
     * 收到全网广播的回复（阶段 3）。所有设备都会收到 —— 活锁模型的必然结果。
     * 请求方自己的发言已在本地显示，这里只管把回复显示出来。
     */
    onRelayResult?: (frame: RelayResult) => void;
    /** 主机拒绝了请求 */
    onRelayBusy?: (frame: RelayBusy) => void;
    /**
     * 流式增量（本机上行且请求了 stream 时，主机单播回来的正文增量）。
     * frame.reset=true 表示之前收到的作废，应清空重流。
     * 权威内容仍是 onRelayResult 的 speech —— 一条 delta 都没收到也必须能正常工作
     * （旧版主机不认识 stream 标志，一条都不会发）。
     */
    onRelayDelta?: (frame: RelayDelta) => void;
    /**
     * 配置被组网同步：主机侧是「批准叶子改动后应用到本机」，
     * 叶子侧是「收到主机下发后应用」。两者都落到同一个回调。
     */
    onConfigChanged?: (patch: Partial<Record<SyncField, string>>, fromDeviceId: string) => void;
    /** 叶子收到主机下发的配置 */
    onConfigPush?: (frame: ConfigPush) => void;
};

/**
 * 主机侧的模型执行器（阶段 3）。
 * 由 main.ts 注入本机 AI 引擎；不注入则主机不处理上行请求
 * （叶子会收到「主机还没准备好」而不是卡死）。
 */
export type HostExecutor = RelayExecutor;

export class NetManager {
    private userDataDir: string;
    private identity: DeviceIdentity;
    private state: NetState;
    private host: HostServer | null = null;
    private leaf: LeafClient | null = null;
    private events: NetManagerEvents;
    /** 主机侧活锁路由（阶段 3）。有执行器才会建。 */
    private router: RelayRouter | null = null;
    /** 叶子侧补传入库回调（只记对话，不调模型） */
    private backfillSink: ((msg: RelayBackfill) => Promise<void> | void) | null = null;
    /**
     * 「上行并等回包」的挂起请求：requestId → 兑现函数。
     *
     * 为什么需要它：桌面端是 UI 驱动 —— 上行之后回包走 events 广播，界面自己收到就画出来，
     * 不需要把「这一条问」和「那一条答」配对。但服务端形态的叶子（kirari-core）
     * 是请求—响应式的：拿到一条消息必须**同步等到**自己那条回包才能作答。
     * 只按 sessionId 配对是不行的（同一会话并发两条就串了），必须按 requestId。
     */
    private pendingRelays = new Map<
        string,
        { settle: (out: { ok: true; frame: RelayResult } | { ok: false; reason: string }) => void; timer: ReturnType<typeof setTimeout> }
    >();
    /**
     * 流式增量的投递目标：requestId → 回调。
     * relayAndWait(onDelta) 注册、settle（成功/超时）时注销。
     * 不在表里的 delta（fire-and-forget 的 relay() 没注册）直接丢弃 ——
     * 那种调用方式本来就不消费增量，攒着只会白占内存。
     */
    private pendingDeltas = new Map<string, (chunk: string | null) => void>();

    /**
     * 允许「本机没有密钥时，自己签一把」。
     *
     * **默认开启，且桌宠端与核心版行为完全一致**（能力对等是硬约束）：
     * 任何一份安装 —— 不管是我打的包、别人 fork 出来的、还是 docker 起的核心版 ——
     * 都能零配置起一个属于自己的网。签出来的是这台机器自己的随机数，
     * 谁也拿不到谁的上游：这里从来不读别人的密钥。
     *
     * 想做成「这个发行版不许组网」的部署者，可以显式调 setAutoProvisionSecret(false)。
     */
    private autoProvision = true;

    constructor(userDataDir: string, events: NetManagerEvents = {}) {
        this.userDataDir = userDataDir;
        this.events = events;
        this.identity = loadOrCreateIdentity(userDataDir);
        this.state = loadNetState(userDataDir, this.identity.deviceId, this.identity.name);
        /**
         * 密钥来源的优先级（定死，别再翻来覆去）：
         *   1. **本机主动加入过的那个网**（enrolledSecret）—— 用户亲手贴码换来的，
         *      意图最明确，压过其它一切来源；否则退出一个网之后又会滑回旧的那个。
         *   2. 宿主已经装上的那把（应用层自己调 setNetSecret 设的；两端产品都不再预置）
         *   3. 本机自己签的（ownSecret）—— 本机第一次当主机时生成的
         *
         * 于是两端彻底对等：源码里、构建产物里、配置文件里都**没有**密钥，
         * 每台机器要么自己签一把（当主机），要么凭一张邀请码领一把（当叶子）。
         */
        const learned = this.state.enrolledSecret;
        if (learned) {
            setNetSecret(learned);
        } else if (!isNetEnabled() && this.state.ownSecret) {
            setNetSecret(this.state.ownSecret);
        }
    }

    /**
     * 设置「本机手上没有密钥时，是否允许自己签一把」。默认开启，两端一致。
     *
     * 只有「我不希望这份发行版能开组网」的部署者才需要显式关掉：
     * `setAutoProvisionSecret(false)`。关掉之后，这台机器只能靠配对期
     * 从主机领密钥，自己开不了网。
     */
    setAutoProvisionSecret(enabled: boolean): void {
        this.autoProvision = enabled === true;
    }

    /**
     * 这台设备现在能不能开组网。UI 用它决定「组网」那一块要不要灰掉。
     *
     * ⚠️ 别拿 `isNetEnabled()` 当这个判断用。以前它等价于「这个构建带没带密钥」，
     *    但现在两端都**不预置密钥**，一台刚装好的机器 isNetEnabled() 必然是 false，
     *    而它其实完全可以自己开一个网 —— 拿它当开关可用性，会把整套组网设置
     *    灰掉，用户连「开启组网」都点不了，自签也就永远走不到。
     *
     * 判据与 ensureSecret() 完全一致，只是不产生副作用。
     */
    canStartNetworking(): boolean {
        return isNetEnabled() || !!storedSecret(this.state) || this.autoProvision;
    }

    /**
     * 确保手上有一把能用的密钥。
     * 返回值说明：true = 现在有密钥了（原本就有、或从文件/新签发得到）。
     */
    private ensureSecret(): boolean {
        if (isNetEnabled()) return true;
        const saved = storedSecret(this.state);
        if (saved) {
            setNetSecret(saved);
            return true;
        }
        if (!this.autoProvision) return false;
        // 第一把：本机自己签。签发完立即落盘，之后就一直用这一把
        // （同一个网的密钥必须稳定，不然之前接进来的设备会突然对不上）。
        const fresh = newNetSecret();
        setNetSecret(fresh);
        this.state = setOwnSecret(this.state, fresh);
        this.persist();
        this.log("[net] 本机手上还没有密钥，已自动签发一把（只存在本机）");
        return true;
    }

    /**
     * 装上主机侧的模型执行器（阶段 3）。
     *
     * 组网启动时才调用 —— 也就是说「主机能不能当出口」取决于本机有没有配好大脑。
     * 没配就应该是「不能当主机」，而不是让人配好了发现组网是坏的。
     * @param executor 调用本机 AI 引擎
     * @param onBackfill 补传入库（把断线期间的对话写进本机历史）
     */
    attachHostExecutor(executor: HostExecutor, onBackfill?: (msg: RelayBackfill) => Promise<void> | void): void {
        this.backfillSink = onBackfill ?? null;
        if (!this.router) {
            this.router = new RelayRouter({
                executor,
                maxConcurrent: Number(process.env.NET_MAX_CONCURRENT || 2),
                maxQueue: Number(process.env.NET_MAX_QUEUE || 20),
                events: {
                    // 广播：发给所有叶子 + 自己也收到（主机也是全网一员）
                    broadcast: (frame) => {
                        this.host?.broadcast(frame);
                        this.dispatchRelayResult(frame);
                    },
                    replyTo: (deviceId, frame) => this.host?.replyTo(deviceId, frame),
                    onBackfill: async (msg) => {
                        await this.backfillSink?.(msg);
                        // 回执让叶子清掉本地待补队列
                        this.host?.replyTo(msg.deviceId, {
                            type: "relay_backfill_ack",
                            v: PROTOCOL_VERSION,
                            count: msg.entries.length,
                        });
                    },
                    onLog: (m) => this.log(m),
                },
            });
        } else {
            this.router.setExecutor(executor);
        }
    }

    /** 活锁路由的运行状态，给 UI 显示「主机现在忙不忙」。 */
    relayStats(): { running: number; queued: number; maxConcurrent: number; maxQueue: number } | null {
        return this.router?.stats() ?? null;
    }

    /**
     * 连接码里对外公布的地址。空串 = 自动猜（guessHostAddress）。
     *
     * 为什么需要它：自动猜是「取第一个私有网段地址」，在多网卡机器上经常猜错
     * （本机就有 5 个地址：192.168.57 / 192.168.42 / 192.168.218 / 10.246 / 10.238），
     * 而在容器里更是必错 —— 猜出来的是容器内网地址，对方根本连不上。
     * 这两个场景都只能由部署者指定，所以留一个显式口子。
     */
    private advertiseHost = "";

    /**
     * 指定连接码里写的地址（多网卡 / 容器部署时用）。
     * 传空 = 恢复自动猜。只影响**新签发**的连接码，已发出去的不会变。
     */
    setAdvertiseHost(host: string | undefined | null): void {
        this.advertiseHost = typeof host === "string" ? host.trim() : "";
    }

    /** 连接码里该写哪个地址：显式指定的优先，否则自动猜。 */
    private hostAddressForCode(): string {
        return this.advertiseHost || guessHostAddress();
    }

    // ── 查询 ────────────────────────────────────────────────────

    snapshot(): NetSnapshot {
        const address =
            this.state.role === "leaf" && this.state.hostAddress
                ? this.state.hostAddress
                : this.hostAddressForCode();
        return {
            role: this.state.role,
            deviceId: this.identity.deviceId,
            deviceName: this.identity.name,
            address,
            port: this.state.role === "leaf" && this.state.hostPort ? this.state.hostPort : NET_PORT,
            hostName: this.state.hostDisplayName,
            pairings: this.state.pairings.map((p) => ({
                id: p.id,
                name: p.name,
                expiresAt: p.expiresAt,
                remaining: describeRemaining(p),
                usedBy: p.usedBy,
                revoked: p.revoked,
            })),
            members: this.host ? this.host.members() : [],
            leafStatus: this.leaf?.getStatus(),
            pendingBackfill: this.leaf?.pendingBackfillCount(),
            relay: this.relayStats(),
            syncWhitelist: this.state.role === "host" ? [...this.state.syncWhitelist] : undefined,
        };
    }

    /** 本机所有可用于组网的地址（给 UI 展示「用哪个地址连」）。 */
    addresses(): string[] {
        return localAddresses();
    }

    private persist(): void {
        saveNetState(this.userDataDir, this.state);
        this.events.onSnapshot?.(this.snapshot());
    }

    private log(message: string): void {
        // ⚠️ 组网内部各模块的日志前缀**不一致**：hostServer 那些是自带 `[net] ` 的，
        // 另有几处没带（历史原因）。这里统一补齐一次，而不是无脑再加一层 ——
        // 无脑加会出现 "[net] [net] ..." 这种重复前缀，看日志的人会以为嵌套了两层。
        const line = message.startsWith("[net]") ? message : `[net] ${message}`;
        // ⚠️ 每行日志**只能有一个输出方**。
        //    这里原先既 `console.log(line)` 又把 line 交给 events.onLog，而两个宿主
        //    （桌宠端 main.ts、核心版 bootstrap）的 onLog 都只是 `console.log` ——
        //    于是每一行都被打印两次。排障时看到重复行会误判成「重连了两次 / 起了两条
        //    连接」，是真实浪费过时间的坑（见 relay.integration.spec.ts 的注释）。
        //    规则：有消费者就交给消费者打，没有才自己打，保证日志至少出现在一个地方。
        if (this.events.onLog) this.events.onLog(line);
        else console.log(line);
    }

    // ── 身份 ────────────────────────────────────────────────────

    renameSelf(name: string): void {
        this.identity = renameIdentity(this.userDataDir, name);
        this.state = { ...this.state, deviceName: this.identity.name };
        this.persist();
    }

    // ── 组网开关 ────────────────────────────────────────────────

    /**
     * 开启组网并作为主机。
     * 之前当过叶子也没关系：主机不需要凭据，反之亦然 —— 角色只是「当前参与方式」。
     */
    async startHosting(expiryKey: ExpiryKey = DEFAULT_EXPIRY): Promise<{
        ok: true;
        code: PairingCode;
    } | { ok: false; error: string }> {
        // 密钥优先用宿主注入的那把；没有就用本机上次攒下的、或自己签的那把。
        // 都不行（宿主既没注入、也没打开自动签发）才退回「这个版本开不了组网」——
        // 从别人源码构建出来的人因此依然拿不到任何人的密钥，行为与以前一致。
        if (!this.ensureSecret()) {
            return { ok: false, error: "这个版本没有包含组网密钥，无法开启组网" };
        }
        this.state = enableNetworking(this.state, "host");
        // 主机不依赖凭据，但家庭标识要有（阶段 3 用它识别「同一伙设备」）
        if (!this.state.homeId) this.state = { ...this.state, homeId: randomToken(8) };
        this.persist();

        const hostAddress = this.hostAddressForCode();
        const { code, record } = generatePairingCode({
            host: hostAddress,
            name: this.identity.name,
            expiryKey,
            port: NET_PORT,
        });
        this.state = addPairing(this.state, record);
        this.persist();

        if (!this.host) {
            // HostServer 不再自己存状态：一律通过 getState/setState 走这里。
            // 单一数据源是必须的 —— 之前两边各存一份互相覆盖，循环下来
            // 成员会莫名丢失（叶子重连时主机说「不认识」）。
            this.host = new HostServer(
                () => this.state,
                (s) => {
                    this.state = s;
                    this.persist();
                },
                {
                    onLog: (m) => this.log(m),
                    onMembersChanged: () => this.events.onSnapshot?.(this.snapshot()),
                    // 阶段 3：上行请求交给活锁路由
                    onRelayRequest: (req) => this.router?.handle(req) ?? false,
                    onRelayBackfill: (msg) => void this.router?.handleBackfill(msg),
                    // 叶子上报配置改动：白名单内的字段应用到本机并转发给所有叶子
                    onConfigReport: (msg, allowed) => {
                        const fields = Object.keys(allowed) as SyncField[];
                        this.events.onConfigChanged?.(allowed, msg.deviceId);
                        this.log(`[net] 已批准 ${msg.deviceId.slice(0, 8)} 的配置改动：${fields.join("、")}`);
                        this.broadcastConfig(allowed, msg.deviceId);
                    },
                },
            );
        }

        const started = await this.host.start(NET_PORT);
        if (!started.ok) {
            // 端口起不来 → 退回独立工作，绝不让用户卡在「开了但用不了」的状态
            this.state = disableNetworking(this.state);
            this.persist();
            return { ok: false, error: started.error };
        }
        // 重新打开 → 路由恢复收单
        this.router?.reopen();

        this.host.updateState(this.state);
        return { ok: true, code };
    }

    /**
     * 造一个叶子客户端（首次配对与重连共用同一份事件接线）。
     *
     * ⚠️ 两条路径必须用**同一份**：以前各写一份，结果「刚配对上的设备」漏了
     *    消息处理 handler，配对成功之后心跳、成员、回复全都接不到。
     */
    private createLeaf(): LeafClient {
        return new LeafClient(this.identity.deviceId, this.identity.name, {
            onLog: (m) => this.log(m),
            onStatus: () => this.events.onSnapshot?.(this.snapshot()),
            onMembers: () => this.events.onSnapshot?.(this.snapshot()),
            onRelayResult: (f) => this.dispatchRelayResult(f),
            onRelayBusy: (f) => this.dispatchRelayBusy(f),
            onRelayDelta: (f) => this.dispatchRelayDelta(f),
            onConfigPush: (f) => this.events.onConfigPush?.(f),
            // 配对期从主机学到的密钥：立刻落盘。
            // 少了这一步，重启后又变回「没有密钥的机器」，只能重新贴码 ——
            // 「贴一次码，永久无感」就断了。
            onSecretLearned: (secret) => {
                this.state = setEnrolledSecret(this.state, secret);
                this.persist();
            },
            onFallback: (reason) => {
                // 关键：只改 role，不动地址与凭据 —— 退出不清除。
                // 下次用户打开开关，凭持久化的信息自动归位，无需重新配对。
                this.state = disableNetworking(this.state);
                this.persist();
                this.events.onFallbackNotice?.(
                    `已退出组网（${reason}），现在可以独立工作。主机那边重新打开组网后，这里打开开关就能自动接回去，不用重新配对。`,
                );
            },
        });
    }

    /**
     * 开启组网并作为叶子：填入连接码完成配对。
     * 配对成功会把主机地址与长期凭据一并落盘，下次打开开关直接连、免重新配对。
     *
     * 两种码：
     *  - 邀请码（kirari://join，默认签发）：**本机有没有密钥都能接**。
     *    没有密钥时先在配对那一步向主机索要（enroll），拿到后一切照旧。
     *  - 密文码（kirari://connect，旧格式）：需要本机本来就有同一把密钥 ——
     *    这条路径是给老客户端留的，不改变它「知道密钥才能解」的语义。
     */
    async startFollowing(pairingText: string): Promise<{ ok: true } | { ok: false; error: string }> {
        const parsed = parseAnyPairingCode(pairingText);
        if (!parsed) {
            return {
                ok: false,
                error: "这个连接码解不开。整串重新复制一次（别漏字符），或者让主机扫一下二维码。",
            };
        }
        const { code, kind } = parsed;
        if (kind === "sealed" && !isNetEnabled()) {
            return { ok: false, error: "这个版本没有包含组网密钥，无法接入" };
        }

        this.state = enableNetworking(this.state, "leaf");
        this.persist();

        if (!this.leaf) this.leaf = this.createLeaf();

        // 邀请码 = 无条件向主机要密钥（见 leafClient.pair 里关于覆盖既有密钥的说明）
        const result = await this.leaf.pair(code, { enroll: kind === "invite" });
        if (!result.ok) {
            this.state = disableNetworking(this.state);
            this.persist();
            return { ok: false, error: result.error };
        }

        // 配对成功的三件事必须一起做：存地址、存凭据、切角色
        this.state = attachToHost(
            this.state,
            { address: code.host, port: code.port, displayName: code.name },
            result.credential,
        );
        this.persist();
        return { ok: true };
    }

    /**
     * 重新加入已配对的主机（打开开关时若已有凭据，走这里而不是重新配对）。
     * 这就是「退出不清除」的兑现：用户零成本反复切换。
     */
    resumeFollowing(): { ok: true } | { ok: false; error: string } {
        if (!this.state.hostAddress || !this.state.hostPort || !this.state.credential) {
            return { ok: false, error: "还没连过主机，先让主机生成一个连接码" };
        }
        this.state = enableNetworking(this.state, "leaf");
        this.persist();
        // 与首次配对共用同一份事件接线（onSecretLearned / onFallback 一条都不能漏）
        if (!this.leaf) this.leaf = this.createLeaf();
        // 「有凭据却没密钥」这种残缺状态由 LeafClient.connect 兜住并给出可操作的提示
        const { hostAddress, hostPort, credential } = this.state;
        // 上面的判空已经保证了三个字段都有值，这里取局部变量让 TS 也认得
        this.leaf.connect(hostAddress!, hostPort!, credential!);
        return { ok: true };
    }

    /**
     * 关闭组网。
     * **只把角色改回独立，不清任何配置**（地址、凭据、配对码、成员全留着），
     * 下次打开开关自动归位。这是 ARCHITECTURE-PLAN 5.7 的硬要求。
     */
    stopNetworking(): void {
        this.leaf?.disconnect();
        // 先停路由：排队中的叶子要立刻收到「主机不接了」，而不是干等到超时
        this.router?.close();
        this.host?.stop();
        this.state = disableNetworking(this.state);
        this.persist();
    }

    // ── 主机侧管理 ──────────────────────────────────────────────

        /** 再生成一个连接码（支持多台设备分别配对）。 */
    issuePairing(expiryKey: ExpiryKey = DEFAULT_EXPIRY): PairingCode {
        const { code, record } = generatePairingCode({
            host: this.hostAddressForCode(),
            name: this.identity.name,
            expiryKey,
            port: NET_PORT,
        });
        this.state = addPairing(this.state, record);
        this.persist();
        return code;
    }

    /** 撤销配对码：作废配对入口，不影响已连上的设备。 */
    revokePairingCode(pairingId: string): void {
        this.state = revokePairing(this.state, pairingId);
        this.persist();
    }

    /** 清理过期且未被用过的配对码。 */
    prunePairings(): void {
        this.state = pruneExpiredPairings(this.state);
        this.persist();
    }

    /** 移除设备：作废其长期凭据，之后再也连不上（与「退出组网」语义不同）。 */
    removeDevice(deviceId: string): boolean {
        const ok = this.host?.kick(deviceId) ?? false;
        // kick() 内部已通过 onStateChanged 回流状态并落盘，这里只在
        // 「设备只存在于持久层、当前不在线」时补一次清理。
        if (!this.state.members.some((m) => m.deviceId === deviceId)) {
            this.state = removeMember(this.state, deviceId);
            this.persist();
        }
        return ok || true;
    }

    // ── 叶子侧管理 ──────────────────────────────────────────────

    /**
     * 断开与主机的绑定并清掉本地凭据（对应 UI 的「移除自己」）。
     *
     * 同时丢掉「从这个网学到的密钥」，并按优先级退回下一把
     * （本机自己签的那把 / 没有）。
     * ⚠️ 必须连**文件里的** enrolledSecret 一起清（forgetEnrolledSecret）：
     *    只改内存里的那把是不够的 —— 下次重启时构造函数会从文件里把它读回来，
     *    用户以为自己退出了，实际又被悄悄绑回那个网。
     */
    leaveHost(): void {
        this.leaf?.disconnect();
        this.state = forgetEnrolledSecret(detachFromHost(this.state));
        this.persist();
        // 退出这个网 = 连从它那里学到的密钥一起忘掉，退回「本机自己签的那把 / 没有」
        setNetSecret(this.state.ownSecret || "");
        this.log(this.state.ownSecret ? "[net] 已退出那个网，密钥还原成本机自己的" : "[net] 已退出那个网，本机现在没有组网密钥");
    }

    /**
     * 序列化配对码为**邀请码**（默认，供 UI 复制 / 生成二维码）。
     *
     * 为什么默认用邀请码：它不需要对方事先有密钥 —— 从源码跑、用 docker 跑的
     * 核心版才能接进来。这正是不匹配问题的解药。
     */
    serializePairing(code: PairingCode): string {
        // 原先是 require() 延迟引入（注释写「避免循环依赖」），但 pairingCode
        // 并不依赖 manager，没有环；require 在 ESM 下不可用，直接静态调用。
        return serializeInviteCode(code);
    }

    /** 生成旧格式密文码：只给「本来就带着同一把密钥」的老客户端用。 */
    serializeSealedPairing(code: PairingCode): string {
        return serializePairingCode(code);
    }

    /** 诊断用：透出叶子连接的真实状态。 */
    debugLeaf(): ReturnType<LeafClient["debug"]> | null {
        return this.leaf ? this.leaf.debug() : null;
    }

    /** 诊断用：主机是否在监听。 */
    get hostRunning(): boolean {
        return this.host?.isRunning ?? false;
    }

    /**
     * 叶子端上行请求（阶段 3）。回包走 events.onRelayResult 广播 —— 适合有界面的调用方。
     * @param kbContext 本机私人知识库的检索结果。主机没有它，不带就等于白配了。
     * @returns false 表示当前没连上，调用方应回退到本地独立处理
     */
    relay(content: string, sessionId: string, images?: string[], kbContext?: KbPassage[]): boolean {
        return (
            (this.leaf?.sendRelay(content, sessionId, images, this.identity.name, kbContext) ?? null) !== null
        );
    }

    /**
     * 叶子端上行请求并**等自己那一条回包**（Promise 版）。
     *
     * 给服务端形态的叶子用（kirari-core 接消息后必须给出回复）。
     * 按 requestId 精确配对，所以同一会话并发两条也不会串。
     *
     * @param opts.timeoutMs 等多久算超时。默认 60s —— 模型慢起来可能十几秒，
     *        但无限等会让调用方的 HTTP 请求悬挂，所以必须有上限。
     */
    relayAndWait(
        content: string,
        sessionId: string,
        opts: {
            images?: string[];
            timeoutMs?: number;
            kbContext?: KbPassage[];
            /** 提供了才向主机请求流式；增量在这里逐段回调（null = 作废重流） */
            onDelta?: (chunk: string | null) => void;
        } = {},
    ): Promise<{ ok: true; frame: RelayResult } | { ok: false; reason: string }> {
        const requestId =
            this.leaf?.sendRelay(content, sessionId, opts.images, this.identity.name, opts.kbContext, !!opts.onDelta) ?? null;
        if (!requestId) {
            // 没连上主机：这是可预期的状态（组网刚开、主机重启中），交给调用方决定回退策略
            return Promise.resolve({ ok: false, reason: "not-connected" });
        }
        const timeoutMs = opts.timeoutMs ?? 60000;
        if (opts.onDelta) this.pendingDeltas.set(requestId, opts.onDelta);
        return new Promise((resolve) => {
            const timer = setTimeout(() => {
                this.pendingRelays.delete(requestId);
                this.pendingDeltas.delete(requestId);
                resolve({ ok: false, reason: `等主机回复超时（${Math.round(timeoutMs / 1000)} 秒）` });
            }, timeoutMs);
            this.pendingRelays.set(requestId, {
                timer,
                settle: (out) => {
                    clearTimeout(timer);
                    this.pendingRelays.delete(requestId);
                    this.pendingDeltas.delete(requestId);
                    resolve(out);
                },
            });
        });
    }

    /** 流式增量分发：只投给注册了 onDelta 的等待者；没人等就丢弃（fire-and-forget 场景）。 */
    private dispatchRelayDelta(frame: RelayDelta): void {
        const sink = this.pendingDeltas.get(frame.requestId);
        if (!sink) return;
        if (frame.reset) {
            try {
                sink(null);
            } catch {
                /* 调用方的展示逻辑炸了不能影响组网 */
            }
        } else if (typeof frame.text === "string" && frame.text.length) {
            try {
                sink(frame.text);
            } catch {
                /* ignore */
            }
        }
    }

    /** 回包分发：先兑现等着的那条请求，再照常广播给 events。 */
    private dispatchRelayResult(frame: RelayResult): void {
        const waiter = this.pendingRelays.get(frame.requestId);
        if (waiter) waiter.settle({ ok: true, frame });
        this.events.onRelayResult?.(frame);
    }

    /** 拒包分发：同上，把「主机忙 / 处理失败」原样交给等待方。 */
    private dispatchRelayBusy(frame: RelayBusy): void {
        const waiter = this.pendingRelays.get(frame.requestId);
        if (waiter) waiter.settle({ ok: false, reason: frame.reason || "主机这次没能处理" });
        this.events.onRelayBusy?.(frame);
    }

    /**
     * 记录一条「本地独立工作期间产生的对话」（阶段 3 离线补传）。
     *
     * 只在**没连上主机**时才有意义 —— 连着的时候对话本来就走主机、不缺记录。
     * 这些内容会在下次连上主机时补传（只入库，不重放模型调用）。
     */
    recordLocalExchange(sessionId: string, role: "user" | "assistant", text: string): void {
        if (!this.leaf) return;
        // 已连上主机 → 对话已由主机记录，不需要补传
        if (this.leaf.getStatus() === "connected") return;
        this.leaf.recordLocalExchange(sessionId, role, text);
        this.events.onSnapshot?.(this.snapshot());
    }

    /** 手动触发一次补传（用户在 UI 上点「立即同步」时用）。 */
    flushBackfillNow(): void {
        this.leaf?.flushBackfill();
    }

    /**
     * 把配置广播给所有叶子（只带白名单内的字段）。
     * @param fromDeviceId 谁改的（主机自己或某个叶子）
     */
    private broadcastConfig(patch: Partial<Record<SyncField, string>>, fromDeviceId: string): void {
        const allowed = filterWhitelisted(this.state, patch);
        if (!Object.keys(allowed).length) return;
        const frame: ConfigPush = {
            type: "config_push",
            v: PROTOCOL_VERSION,
            fromDeviceId,
            patch: allowed,
        };
        this.host?.broadcast(frame);
        // 主机自己也应用（叶子改了、白名单批准 → 主机的配置跟着变，保持全网一致）
        this.events.onConfigChanged?.(allowed, fromDeviceId);
    }

    /**
     * 本机配置被用户改动时的统一入口。
     *
     * 主机：白名单内的字段广播给所有叶子。
     * 叶子：**无条件上报**给主机，由主机决定要不要传播（白名单是主机侧的东西）。
     * 独立模式（没组网）：什么都不做。
     */
    notifyLocalConfigChanged(patch: Partial<Record<SyncField, string>>): void {
        if (this.state.role === "host") {
            this.broadcastConfig(patch, this.identity.deviceId);
            return;
        }
        if (this.state.role === "leaf") {
            this.leaf?.reportConfigChange(patch);
        }
    }

    /** 当前同步白名单（只有主机侧有内容，叶子侧返回空数组）。 */
    syncWhitelist(): SyncField[] {
        return this.state.role === "host" ? [...this.state.syncWhitelist] : [];
    }

    /** 设置白名单（仅主机侧生效）。设置后立即生效，无需叶子重连。 */
    setSyncWhitelist(fields: SyncField[]): void {
        if (this.state.role !== "host") return;
        const clean = fields.filter((f) => SYNC_FIELDS.includes(f));
        this.state = setSyncWhitelist(this.state, clean);
        this.persist();
        // 白名单放开后，把当前值补推给所有叶子（否则用户要先改一次才生效）
        this.events.onSnapshot?.(this.snapshot());
    }

    dispose(): void {
        this.leaf?.disconnect();
        this.router?.close("主机已退出");
        this.host?.stop();
        this.leaf = null;
        this.host = null;
        // 挂起的上行请求不能悬着：调用方（服务端叶子）正 await 着，
        // 不兑现就是永久挂住 —— 比给个明确的失败更糟。
        for (const waiter of this.pendingRelays.values()) {
            clearTimeout(waiter.timer);
            waiter.settle({ ok: false, reason: "组网已退出，这条请求没能发出去" });
        }
        this.pendingRelays.clear();
        this.pendingDeltas.clear();
    }
}

/** 便捷工厂：主进程启动时调一次。 */
export function createNetManager(userDataDir: string, events: NetManagerEvents = {}): NetManager {
    const mgr = new NetManager(userDataDir, events);
    // 启动即清理过期配对码（过期的码留着只会让列表越来越乱）
    if (mgr.snapshot().role === "host") mgr.prunePairings();
    return mgr;
}

/** 组网状态文件所在路径（诊断用）。 */
export function netStatePath(userDataDir: string): string {
    return path.join(userDataDir, "net-state.json");
}
