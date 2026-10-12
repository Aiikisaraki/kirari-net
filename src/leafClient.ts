// kirari-net · src/leafClient.ts
// 叶子端：连主机、发心跳、断线自动回退独立工作。
//
// 核心是「断线回退」，三条规则（ARCHITECTURE-PLAN 3.4 / 3.9）：
//  1. **硬断线立即回退**：socket close/error 一到，立刻退出组网、恢复独立调用。
//     不等超时 —— 用户感知不到等待才有体感，等 5 秒会看到「桌宠卡住不动」。
//  2. **半开超时回退**：心跳 2 秒一次，5 秒没回应即判定已死，退出组网。
//  3. **回退不清配置**：只把 role 置回 off，主机地址与长期凭据留在磁盘上，
//     用户重新打开开关就能自动归位。
//
// 自动退出不需要用户确认：网络已不可用，保持组网态毫无意义。
// 上层只需监听 onFallback 提示一句「已退出组网，现在可以独立工作」。

import WebSocket from "ws";
import {
    CONNECT_TIMEOUT_MS,
    HANDSHAKE_TIMEOUT_MS,
    HEARTBEAT_INTERVAL_MS,
    HEARTBEAT_TIMEOUT_MS,
    PROTOCOL_VERSION,
    SeqTracker,
} from "./protocol";
import type { MembersMessage, RelayResult, RelayBusy, RelayBackfill, ConfigPush, SyncField, HelloAck, KbPassage, RelayDelta, EnrollGrant } from "./protocol";
import { isNetEnabled, getNetSecret, deriveKey, seal, open, ReplayGuard, setNetSecret } from "./secure";
import { newEnrollKeypair, openSecretOwnPair } from "./enroll";
import type { EnrollKeypair } from "./enroll";
import { randomBytes } from "crypto";

export type LeafStatus = "idle" | "connecting" | "paired" | "connected" | "fallback";

export type LeafEvents = {
    /** 状态变化，供 UI 显示 */
    onStatus?: (status: LeafStatus, detail?: string) => void;
    /** 掉线回退。reason 是给用户看的大白话 */
    onFallback?: (reason: string) => void;
    /** 成员列表更新 */
    onMembers?: (members: MembersMessage["members"]) => void;
    /**
     * 收到广播的回复（阶段 3）。
     * 注意是**全网广播**——别人的提问也会推过来，这是活锁模型的必然结果：
     * 请求统一走主机，结果广播，所以其他设备也会看到这次对话。
     */
    onRelayResult?: (frame: RelayResult) => void;
    /** 主机拒绝了这次请求（排队满 / 正在关停） */
    onRelayBusy?: (frame: RelayBusy) => void;
    /**
     * 流式增量（仅本机上行且带 stream 标志时，主机才会单播过来）。
     * frame.reset=true 表示之前收到的增量作废，应清空重流。
     * 权威内容仍是 onRelayResult 的 speech —— 一条 delta 都没收到也要能正常工作。
     */
    onRelayDelta?: (frame: RelayDelta) => void;
    /** 主机下发了配置（白名单内的字段），写进本机即生效 */
    onConfigPush?: (frame: ConfigPush) => void;
    /**
     * 配对期从主机学到了组网密钥。
     *
     * 宿主（桌宠 / 核心版）必须把它落盘 —— 否则下次重启又没密钥了，
     * 只能重新配对。这也是「第一次贴码之后永久免维护」得以成立的那一步。
     */
    onSecretLearned?: (secret: string) => void;
    onLog?: (message: string) => void;
};

export class LeafClient {
    private ws: WebSocket | null = null;
    private events: LeafEvents;
    private deviceId: string;
    private deviceName: string;

    /** 主机地址与端口 */
    private host = "";
    private port = 0;
    /** 长期凭据：重连用它，不再走配对流程 */
    private credential = "";

    private status: LeafStatus = "idle";
    private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
    private pongTimer: ReturnType<typeof setTimeout> | null = null;
    /** 本机累计请求 id（阶段 3 用） */
    private requestSeq = 0;
    /** 主机广播序号跟踪，保证顺序 */
    private seqTracker = new SeqTracker();
    /**
     * 连接代号：每次新建连接 +1。
     *
     * ⚠️ 必需：disconnect() 里的 close 事件是异步到达的，往往在 connect()
     *    已经建好新连接之后才触发。若不校验代号，这条「旧连接的关闭事件」
     *    会被当成「新连接断了」，把刚建好的连接又关掉 —— 表现为重连永远失败，
     *    报「WebSocket was closed before the connection was established」。
     */
    private connGeneration = 0;
    /** 建连超时定时器：CONNECTING 状态卡住时兜底 */
    private connectTimer: ReturnType<typeof setTimeout> | null = null;
    /** 会话密钥（握手后由 密钥+salt 派生得到），握手前为 null */
    private sessionKey: Buffer | null = null;
    /**
     * 加密帧自增序号（防重放）。
     * 注：握手时拿到的 salt / 主机 id / 主机名都不在这里存 —— salt 只在派生
     * 会话密钥那一刻用，重连会重新握手；主机名给界面看的是 state.hostDisplayName
     * （连接码里带过来的），跟握手无关。原先存了三个字段却没人读。
     */
    private txSeq = 0;
    /** 收到帧的重放窗口 */
    private rxGuard = new ReplayGuard();
    /** 首次配对用的连接码（握手完成后发出一次即清空） */
    private pendingToken = "";
    /**
     * 本轮是否需要「先要密钥再握手」。
     *
     * 为真表示这台设备手上没有组网密钥（从源码跑起来 / docker 起来的核心版最常见），
     * 连接建立后第一帧要发的不是 hello，而是 enroll_request ——
     * 拿到密钥之后才轮到原本那套握手。
     */
    private needEnroll = false;
    /** enroll 用的临时密钥对。只在等密钥那几秒里有值，用完立刻清掉。 */
    private enrollKeys: EnrollKeypair | null = null;
    /** 配对结果：由 attachMessage 的 pair_ok / pair_fail 分支落定，pair() 轮询取走 */
    private pairResult: { ok: true; credential: string } | { ok: false; error: string } | null = null;

    /** 本轮连接是否是有意的（关闭组网时不算异常） */
    private closingIntentionally = false;
    /**
     * 断线期间本地独立工作产生的对话，等主机回来后补传。
     * 只补记录、**不重放模型调用**（ARCHITECTURE-PLAN 3.5）——
     * 重放会让其他叶子看到重复内容，还等于白花主机的额度。
     */
    private pendingBackfill: { sessionId: string; entries: RelayBackfill["entries"] }[] = [];

    constructor(deviceId: string, deviceName: string, events: LeafEvents = {}) {
        this.deviceId = deviceId;
        this.deviceName = deviceName;
        this.events = events;
    }

    getStatus(): LeafStatus {
        return this.status;
    }

    /** 诊断用：连接的真实状态。排障时看这个比看 status 靠谱。 */
    debug(): { status: LeafStatus; hasSocket: boolean; readyState: number; closingIntentionally: boolean } {
        return {
            status: this.status,
            hasSocket: !!this.ws,
            readyState: this.ws ? this.ws.readyState : -1,
            closingIntentionally: this.closingIntentionally,
        };
    }

    getSeq(): number {
        return this.seqTracker.current;
    }

    nextRequestId(): string {
        return `${this.deviceId}:${++this.requestSeq}`;
    }

    private setStatus(s: LeafStatus, detail?: string): void {
        if (this.status === s) return;
        this.status = s;
        this.events.onStatus?.(s, detail);
    }

    /**
     * 发一帧：握手完成后自动加密，心跳保持明文。
     * 这是所有上行帧的唯一出口 —— 不要绕过它直接 ws.send。
     */
    private sendFrame(ws: WebSocket, payload: unknown): boolean {
        if (ws.readyState !== 1) return false;
        const type = (payload as { type?: string })?.type;
        const keepPlain = type === "ping";
        try {
            if (!keepPlain && isNetEnabled()) {
                if (!this.sessionKey) return false; // 握手没完，什么都不发
                const body = seal(this.sessionKey, { ...(payload as object), _s: ++this.txSeq });
                ws.send(JSON.stringify({ e: 1, d: body }));
                return true;
            }
            ws.send(JSON.stringify(payload));
            return true;
        } catch {
            return false;
        }
    }

    /** 明文发送（仅握手阶段使用） */
    private sendRaw(ws: WebSocket, payload: unknown): void {
        try {
            ws.send(JSON.stringify(payload));
        } catch {
            // 忽略：随后会由 close/error 兜到
        }
    }

    /**
     * 处理服务端帧：握手应答走明文，其余解信封。
     * 解不开一律当作没收到 —— 不暴露「密钥不对」这种信息。
     */
    private readFrame(raw: string): any | null {
        let envelope: { type?: string; e?: number; d?: string; salt?: string; hostId?: string; hostName?: string };
        try {
            envelope = JSON.parse(raw);
        } catch {
            return null;
        }
        if (envelope?.type === "hello_ack") {
            const ack = envelope as unknown as HelloAck;
            if (typeof ack.salt !== "string" || !ack.salt) return null;
            this.sessionKey = deriveKey(getNetSecret(), ack.salt);
            this.events.onLog?.(`[net] 密钥协商完成（主机盐 ${ack.salt.slice(0, 8)}…）`);
            return { type: "handshake_ok" };
        }
        if (envelope?.e === 1 && typeof envelope.d === "string") {
            if (!this.sessionKey) return null;
            const opened = open(this.sessionKey, envelope.d);
            if (!opened) {
                this.events.onLog?.("[net] 收到无法解开的帧（密钥不一致或数据被改动）");
                return null;
            }
            const seq = typeof opened._s === "number" ? opened._s : 0;
            if (!this.rxGuard.accept(seq)) {
                this.events.onLog?.(`[net] 丢弃重放帧 seq=${seq}`);
                return null;
            }
            delete opened._s;
            return opened;
        }
        return envelope as Record<string, unknown>;
    }

    /** 武装握手超时（复用 connectTimer 这个槽位：同一时刻只会有一个超时在手）。 */
    private armHandshakeTimeout(ws: WebSocket, gen: number): void {
        this.clearConnectTimeout();
        this.connectTimer = setTimeout(
            () => this.handshakeTimeout(ws, gen),
            HANDSHAKE_TIMEOUT_MS,
        );
    }

    /** 握手之前没收到任何东西时的超时（主机不回 hello_ack）。 */
    private handshakeTimeout(ws: WebSocket, gen: number): void {
        this.connectTimer = null; // 槽位已触发，清掉以维持「非 null ⟺ 有超时在等」
        if (gen !== this.connGeneration || this.sessionKey) return;
        this.events.onLog?.("[net] 密钥协商超时");
        try {
            ws.terminate();
        } catch {
            // 忽略
        }
        this.fallback("和主机对不上密钥，连不上");
    }

    /**
     * 挂上「断线即回退」的生命周期处理。
     *
     * ⚠️ 这段必须对**所有**连接路径生效 —— 首次配对（pair）与重连（connect）。
     *    之前只挂在 connect() 上，结果「刚配对上的设备」掉线时不会回退，
     *    表现为桌宠一直显示已连接、实际早就不通了。是阶段 2 的双机验收抓出来的。
     */
    private attachLifecycle(ws: WebSocket, gen: number): void {
        ws.on("close", () => {
            // 过期连接（如刚被 disconnect 的那条）的迟到 close 不能影响当前连接，
            // 否则重连会被自己刚发起的关闭打死。
            if (gen !== this.connGeneration) return;
            this.clearConnectTimeout();
            this.stopHeartbeat();
            // 规则 1：硬断线立即回退，不等超时
            if (!this.closingIntentionally) {
                this.fallback("和主机断开了");
            }
        });
        // 关掉心跳即可：ws 的 error 之后必然跟一个 close，
        // 回退统一由上面的 close 分支负责（避免同一件事提示两遍）。
        ws.on("error", (_err: unknown) => {
            this.stopHeartbeat();
        });
    }

    /**
     * 首次配对：用连接码里的口令换一个长期凭据。
     *
     * ⚠️ 刻意**复用 openSocket 那条连接路径**，不自己再写一套 WebSocket 逻辑。
     *    之前这里是独立实现，结果配对成功的连接收不到心跳、成员、回复 ——
     *    表现就是「配对成功但组网毫无反应」。新增连接逻辑时改一处就够。
     *
     * @param code 解析好的连接码（见 pairingCode.parsePairingCode）
     * @param opts.enroll true = 手里没有密钥，先向主机要一把（源泉式接入）
     */
    async pair(
        code: { host: string; port: number; token: string; name: string },
        opts: { enroll?: boolean } = {},
    ): Promise<{ ok: true; credential: string } | { ok: false; error: string }> {
        // 没有密钥时不能一上来就判死：只要同时带来了一个能证明身份的一次性口令，
        // 就可以先 enroll 拿密钥。反过来，既没密钥又不许 enroll，才真的连不了。
        if (!isNetEnabled() && !opts.enroll) {
            return { ok: false, error: "这个版本没有包含组网密钥，无法接入" };
        }
        if (!code.token) {
            return { ok: false, error: "连接码里没有接入口令，重新向主机要一个" };
        }
        /**
         * ⚠️ opts.enroll 显式为真时**覆盖**本机既有的密钥。
         *
         * 这一点必须无条件执行：本机可能正带着某个网的密钥（自己签的、或之前学来的），
         * 而用户现在要接的是**另一个**网。若「已经有密钥就不 enroll」，
         * 这把设备会拿着错误的密钥去握手，永远连不上 —— 正是「两头密钥对不上」的死结。
         * 所以：邀请码 = 「接进提出这个码的那个网」，与原先带着哪把无关。
         */
        this.needEnroll = opts.enroll === true || !isNetEnabled();
        this.host = code.host;
        this.port = code.port;
        // 握手完成后由 attachMessage 里的 handshake_ok 分支发出这个码
        this.pendingToken = code.token;
        this.closingIntentionally = false;
        this.setStatus("connecting", `正在连接 ${code.host}:${code.port}`);

        // 复用统一连接路径；结果由 pairResult 控制
        this.pairResult = null;
        this.openSocket();

        // 等配对结果（由 attachMessage 的 pair_ok / pair_fail 分支落定）
        for (let i = 0; i < 120; i++) {
            if (this.pairResult) {
                const r = this.pairResult;
                this.pairResult = null;
                return r;
            }
            await new Promise((r) => setTimeout(r, 100));
        }
        return { ok: false, error: "连不上主机或对方没有回应，检查地址和防火墙" };
    }

    /**
     * 用已有长期凭据连接主机（自动重连 / 打开组网开关时走这里，不再配对）。
     */
    connect(host: string, port: number, credential: string): void {
        if (!host || !port || !credential) {
            this.setStatus("idle");
            this.events.onFallback?.("还没连过主机，先填一个连接码");
            return;
        }
        // 有凭据却没有密钥 = 状态不完整（例如密钥文件被删/换了机器）。
        // 这时候硬连会卡在「密钥协商超时」，用户完全不知道发生了什么，
        // 不如直接说清楚该做什么。
        if (!isNetEnabled()) {
            this.events.onLog?.("[net] 本机没有组网密钥，无法用旧凭据重连");
            this.fallback("这台机器上没有组网密钥了，重新用主机给的邀请码接一次");
            return;
        }
        this.host = host;
        this.port = port;
        this.credential = credential;
        this.closingIntentionally = false;
        this.seqTracker.reset();
        this.openSocket();
    }

    private openSocket(): void {
        const gen = ++this.connGeneration;
        this.stopHeartbeat();
        const wasConnected = this.status === "connected";
        if (!wasConnected) this.setStatus("connecting", `正在连接 ${this.host}`);

        let ws: WebSocket;
        try {
            ws = new WebSocket(`ws://${this.host}:${this.port}`);
        } catch (e) {
            this.fallback((e as Error)?.message || "连接失败");
            return;
        }
        this.ws = ws;
        // 建连超时必须**在 new WebSocket 之后立刻**武装：此刻 readyState 是
        // CONNECTING，被静默丢弃的 SYN 才会被这个定时器兜住。
        // （原先唯一的调用点在下面 open 回调里，那时早就 OPEN 了，定时器一进来
        //  就 `readyState !== 0` 直接返回 —— 等于这个保护从没生效过。）
        this.armConnectTimeout(ws, gen);

        ws.on("open", () => {
            // ⚠️ 握手未完成前不要直接发 pair —— 主机只收加密帧，
            //    明文 pair 会被静默丢弃（表现为「连上了但永远配对不成功」）。
            this.clearConnectTimeout();
            this.setStatus("connecting", "正在与主机协商密钥");
            this.sessionKey = null;
            this.txSeq = 0;
            this.rxGuard.reset();
            // 已经是 OPEN 了，接下来等的是 hello_ack —— 换成握手超时。
            // （原先这里 re-arm 的是建连超时，而它一进来就 readyState !== 0 直接
            //  返回，等于握手阶段没有任何超时保护，见 protocol.ts 的说明。）
            this.armHandshakeTimeout(ws, gen);

            // ── 手上没有密钥：先向主机要一把，再走常规握手 ──
            if (this.needEnroll) {
                this.sendEnrollRequest(ws);
                return;
            }

            // 第一帧永远是明文 hello：主机用它回 salt，两边各自算出同一个会话密钥。
            // 密钥本身不上网络 —— 抓到包的人看不到它。
            this.sendRaw(ws, {
                type: "hello",
                v: PROTOCOL_VERSION,
                deviceId: this.deviceId,
                deviceName: this.deviceName,
                nonce: randomBytes(8).toString("hex"),
            });
        });

        this.attachMessage(ws, gen);
        // 断线回退统一交给 attachLifecycle，避免同一连接注册两份 handler
        // （重复注册会让 fallback 触发两次，用户收到两条一样的提示）。
        this.attachLifecycle(ws, gen);
    }

    /**
     * 发出「请把密钥给我」的请求。
     *
     * 临时密钥对是**每次重来都新建**的：同一台设备反复尝试也不会复用上一次的私钥，
     * 所以别人录到的密文在自己这里是解不开的（他从别处重放的旧公钥也换不来密钥）。
     */
    private sendEnrollRequest(ws: WebSocket): void {
        this.enrollKeys = newEnrollKeypair();
        this.setStatus("connecting", "正在向主机索取密钥");
        this.sendRaw(ws, {
            type: "enroll_request",
            v: PROTOCOL_VERSION,
            deviceId: this.deviceId,
            deviceName: this.deviceName,
            token: this.pendingToken || this.credential,
            ephPub: this.enrollKeys.publicKeyB64,
        });
    }

    /**
     * 收到加密的组网密钥：解开 → 装上 → 通知宿主落盘 → 接着走常规握手。
     *
     * 解不开只有一种可能（对方给的临时公钥和本机私钥对不上，或密文被改动），
     * 这时干净地回退：不留半截状态，用户看到的是「这次没接上」而不是卡住。
     */
    private handleEnrollGrant(ws: WebSocket, frame: EnrollGrant): void {
        const keys = this.enrollKeys;
        const secret = keys ? openSecretOwnPair(keys, String(frame.ephPub || ""), String(frame.secret || "")) : null;
        if (!secret) {
            this.enrollKeys = null;
            this.events.onLog?.("[net] 主机发来的密钥解不开，请让它重新生成一个邀请码");
            this.pairResult = { ok: false, error: "主机发来的东西没法用，让它重新生成一个邀请码试试" };
            this.fallback("和主机没对上号，接不进去");
            return;
        }
        // 临时密钥对用完即弃：它的唯一用途就是这一次的密钥下发
        this.enrollKeys = null;
        this.needEnroll = false;
        setNetSecret(secret);
        // 交给宿主落盘 → 之后重连用这把，不用再走一次 enroll
        this.events.onSecretLearned?.(secret);
        this.events.onLog?.("[net] 已拿到组网密钥，开始密钥协商");
        this.sendRaw(ws, {
            type: "hello",
            v: PROTOCOL_VERSION,
            deviceId: this.deviceId,
            deviceName: this.deviceName,
            nonce: randomBytes(8).toString("hex"),
        });
    }

    /**
     * 挂上「服务端帧处理」。
     *
     * ⚠️ 必须对**所有**连接路径生效 —— 首次配对（pair）与重连（connect）。
     *    之前这段只写在 openSocket() 里，而首次配对走的是 pair() 那条路，
     *    于是「刚配对上的设备」只能收到 pair_ok，之后所有广播（心跳 pong、
     *    成员变化、回复内容）都被静默丢弃 —— 表现为组网开着但永远没反应。
     *    是阶段 3 的三设备并发验收抓出来的。
     */
    private attachMessage(ws: WebSocket, gen: number): void {
        ws.on("message", (data: unknown) => {
            // 过期连接的迟到帧：忽略，否则会污染当前状态（重连后旧 socket 缓存的
            // 帧会重置新连接的半开计时、甚至覆盖状态）。
            // 注释一直这么写，但 gen 以前只是传进来没用上，等于没校验。
            if (gen !== this.connGeneration) return;
            // readFrame 负责解密 + 防重放；握手应答走明文，其余是信封
            const frame = this.readFrame(String(data));
            if (!frame) return;

            // 收到任何帧都算「对方活着」，重置半开计时
            this.armPongTimeout();

            // ── 密钥下发的结果（明文帧，见 enroll.ts）──
            if (frame.type === "enroll_grant") {
                this.handleEnrollGrant(ws, frame as EnrollGrant);
                return;
            }
            if (frame.type === "enroll_fail") {
                const why = frame.reason || "主机没有接受这台设备";
                this.enrollKeys = null;
                this.events.onLog?.(`[net] 拿不到密钥：${why}`);
                this.pairResult = { ok: false, error: why };
                this.fallback(why);
                return;
            }

            // ── 握手完成：现在才发身份、启动心跳 ──
            if (frame.type === "handshake_ok") {
                this.clearConnectTimeout(); // 撤销握手超时，别在正常连上之后把它掐了
                this.setStatus("connected");
                this.sendFrame(ws, {
                    type: "pair",
                    v: PROTOCOL_VERSION,
                    deviceId: this.deviceId,
                    deviceName: this.deviceName,
                    // 首次配对用连接码，之后用长期凭据；主机优先按已配对设备校验
                    token: this.pendingToken || this.credential,
                    v2: PROTOCOL_VERSION,
                });
                this.pendingToken = "";
                this.startHeartbeat();
                this.flushBackfill();
                return;
            }

            if (frame.type === "pong") {
                this.setStatus("connected");
                return;
            }
            if (frame.type === "pair_ok") {
                // 主机确认了身份（可能换了新凭据）
                if (frame.credential && frame.credential !== this.credential) {
                    this.credential = frame.credential;
                    this.events.onLog?.("[net] 收到主机签发的新凭据，已更新");
                }
                this.setStatus("connected");
                this.armPongTimeout();
                this.flushBackfill();
                // 首次配对：把结果交给 pair() 的等待循环
                this.pairResult = { ok: true, credential: this.credential };
                this.events.onLog?.(`[net] 配对成功`);
                return;
            }
            if (frame.type === "pair_fail") {
                // 凭据被吊销（主机移除了这台设备）→ 只能回独立工作
                const why = frame.reason || "主机不再接受这台设备";
                this.events.onLog?.(`[net] 主机拒绝了连接：${why}`);
                if (this.pendingToken) this.pairResult = { ok: false, error: why };
                this.fallback(why);
                return;
            }
            if (frame.type === "members") {
                this.events.onMembers?.((frame as MembersMessage).members);
                return;
            }
            if (frame.type === "host_shutdown") {
                // 主机主动通告关停：立刻回退，不等 socket 关闭握手。
                // 硬断线必须立即响应 —— 用户感知不到等待才有体感。
                this.events.onLog?.(`[net] ${frame.reason}`);
                this.fallback(frame.reason);
                return;
            }
            if (frame.type === "relay_result") {
                // 阶段 3：顺序保证 —— 交给重排序缓冲，按 seq 升序交付。
                // 注意**不是**「非递增就丢弃」：并发生成时完成顺序 ≠ seq 顺序，
                // 严格递增会真的把消息丢掉。缓冲负责排序，但不丢。
                if (this.seqTracker.accept(frame.seq)) {
                    this.events.onRelayResult?.(frame as RelayResult);
                } else {
                    this.events.onLog?.(`[net] 忽略重复广播 seq=${frame.seq}`);
                }
                return;
            }
            if (frame.type === "relay_busy") {
                this.events.onRelayBusy?.(frame as RelayBusy);
                return;
            }
            if (frame.type === "relay_delta") {
                // 主机的流式增量。旧版主机永远不会发这个类型 —— 不处理也不影响别的功能。
                this.events.onRelayDelta?.(frame as RelayDelta);
                return;
            }
            if (frame.type === "config_push") {
                // 主机批准下发的配置：写进本机即生效
                this.events.onConfigPush?.(frame as ConfigPush);
                return;
            }
            if (frame.type === "relay_backfill_ack") {
                // 主机确认收到补传，可以清本地待补队列了
                this.pendingBackfill = [];
                this.events.onLog?.(`[net] 补传已被主机接收（${frame.count} 条）`);
                return;
            }
        });
    }

    /** 建连超时：CONNECTING 卡住超过阈值就放弃，回退独立工作。 */
    private armConnectTimeout(ws: WebSocket, gen: number): void {
        this.clearConnectTimeout();
        this.connectTimer = setTimeout(() => {
            this.connectTimer = null;
            if (gen !== this.connGeneration) return;
            if (ws.readyState !== 0) return; // 已经连上了
            this.events.onLog?.("[net] 建连超时，放弃这次连接");
            try {
                ws.terminate();
            } catch {
                // 忽略
            }
            this.fallback("连不上主机");
        }, CONNECT_TIMEOUT_MS);
    }

    private clearConnectTimeout(): void {
        if (this.connectTimer) {
            clearTimeout(this.connectTimer);
            this.connectTimer = null;
        }
    }

    private startHeartbeat(): void {
        this.stopHeartbeat();
        this.heartbeatTimer = setInterval(() => {
            const ws = this.ws;
            if (!ws || ws.readyState !== 1) return;
            if (!this.sendFrame(ws, { type: "ping", v: PROTOCOL_VERSION, deviceId: this.deviceId })) {
                // 发送失败，等 close 事件
                return;
            }
            // 规则 2：半开 —— 发完心跳等回应，超时即判定已死
            this.armPongTimeout();
        }, HEARTBEAT_INTERVAL_MS);
    }

    private armPongTimeout(): void {
        if (this.pongTimer) clearTimeout(this.pongTimer);
        this.pongTimer = setTimeout(() => {
            this.events.onLog?.("[net] 心跳超时，判定连接已失效");
            try {
                this.ws?.close(4000, "heartbeat timeout");
            } catch {
                // 忽略
            }
            this.fallback("和主机联系不上了");
        }, HEARTBEAT_TIMEOUT_MS);
    }

    private stopHeartbeat(): void {
        if (this.heartbeatTimer) {
            clearInterval(this.heartbeatTimer);
            this.heartbeatTimer = null;
        }
        if (this.pongTimer) {
            clearTimeout(this.pongTimer);
            this.pongTimer = null;
        }
    }

    /** 回退到独立工作。**不清任何配置**，用户重新打开开关就能自动归位。 */
    private fallback(reason: string): void {
        this.clearConnectTimeout();
        this.stopHeartbeat();
        this.closingIntentionally = true;
        try {
            this.ws?.close();
        } catch {
            // 忽略
        }
        this.ws = null;
        this.setStatus("fallback", reason);
        this.events.onFallback?.(reason);
        // 复位标记，方便下次 connect
        setTimeout(() => {
            this.closingIntentionally = false;
        }, 0);
    }

    /** 用户主动关闭组网：安静断开，不算异常。 */
    disconnect(): void {
        this.closingIntentionally = true;
        this.clearConnectTimeout();
        this.stopHeartbeat();
        try {
            this.ws?.close(1000, "user closed networking");
        } catch {
            // 忽略
        }
        this.ws = null;
        this.setStatus("idle");
    }

    /**
     * 上行一条请求给主机（阶段 3）。
     *
     * @param sessionId 本机的会话 ID —— 主机据此取上下文，所以每台设备
     *        的对话脉络互不串味，且重连后上下文还在（存在主机那边）。
     * @param kbContext 本机私人知识库的检索结果（可选）。私人知识库存在本机，
     *        主机看不到它 —— 不带的话「本机配了知识库」在上行链路里就静默失效了。
     *        失败/为空就不带，不要因此阻塞发送。
     * 返回**本次请求的 requestId**（发不出去时返回 null）。
     * 必须把 requestId 交出去：服务端形态的叶子（kirari-core）是「请求—响应」的，
     * 拿到一条消息就得给出对应回复，没有界面去接广播 —— 它需要按 requestId
     * 精确等到自己那条回包。见 NetManager.relayAndWait()。
     */
    sendRelay(
        content: string,
        sessionId: string,
        images?: string[],
        nickname?: string,
        kbContext?: KbPassage[],
        stream?: boolean,
    ): string | null {
        const ws = this.ws;
        if (!ws || ws.readyState !== 1 || !this.sessionKey) return null;
        const requestId = this.nextRequestId();
        const sent = this.sendFrame(ws, {
            type: "relay_request",
            v: PROTOCOL_VERSION,
            deviceId: this.deviceId,
            requestId,
            sessionId,
            content,
            images,
            nickname,
            kbContext: Array.isArray(kbContext) && kbContext.length ? kbContext : undefined,
            // 只有调用方要流式才带标志：旧主机不认识就忽略，请求退化为「等整包」
            stream: stream ? true : undefined,
        });
        return sent ? requestId : null;
    }

    /**
     * 记录一条「本地独立工作期间产生的对话」，等主机回来后补传。
     * 只入库不重放 —— 详见 pendingBackfill 的注释。
     */
    recordLocalExchange(sessionId: string, role: "user" | "assistant", text: string): void {
        if (!text || !text.trim()) return;
        const bucket = this.pendingBackfill.find((b) => b.sessionId === sessionId);
        const entry = { role, text, at: Date.now() };
        if (bucket) {
            // 单次补传最多 200 条，避免长期离线攒出一大坨把主机库撑爆
            if (bucket.entries.length < 200) bucket.entries.push(entry);
        } else {
            this.pendingBackfill.push({ sessionId, entries: [entry] });
        }
    }

    /**
     * 上报配置改动给主机。
     *
     * **无条件上报**——叶子不判断该不该同步。判断在主机那边做（白名单是
     * 主机侧的东西，叶子看不到也不该管）。这样用户调整白名单立刻生效。
     * 返回 false 表示当前没连上主机。
     */
    reportConfigChange(patch: Partial<Record<SyncField, string>>): boolean {
        const ws = this.ws;
        if (!ws || ws.readyState !== 1) return false;
        const clean: Partial<Record<SyncField, string>> = {};
        let has = false;
        for (const [k, v] of Object.entries(patch)) {
            if (typeof v === "string") {
                clean[k as SyncField] = v;
                has = true;
            }
        }
        if (!has) return false;
        return this.sendFrame(ws, {
            type: "config_report",
            v: PROTOCOL_VERSION,
            deviceId: this.deviceId,
            patch: clean,
        });
    }

    /** 待补传的条数（给 UI 显示「有 N 条待同步」） */
    pendingBackfillCount(): number {
        return this.pendingBackfill.reduce((n, b) => n + b.entries.length, 0);
    }

    /** 重连成功后自动补传。主机确认（backfill_ack）后清空。 */
    flushBackfill(): void {
        if (!this.pendingBackfill.length) return;
        const ws = this.ws;
        if (!ws || ws.readyState !== 1) return;
        const deviceName = this.deviceName;
        for (const bucket of this.pendingBackfill) {
            const ok = this.sendFrame(ws, {
                type: "relay_backfill",
                v: PROTOCOL_VERSION,
                deviceId: this.deviceId,
                sessionId: bucket.sessionId,
                nickname: deviceName,
                entries: bucket.entries,
            });
            if (!ok) return; // 下次重连再试
        }
        this.events.onLog?.(`[net] 已补传 ${this.pendingBackfillCount()} 条离线对话`);
    }
}
