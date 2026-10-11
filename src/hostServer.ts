// kirari-net · src/hostServer.ts
// 主机端：监听固定端口，接受叶子配对与心跳，维持成员列表。
//
// 阶段 2 范围：只做「基础设施」——配对、心跳、成员管理。
// 活锁路由（请求上行 / 结果广播）在阶段 3 加进来。
//
// 几条硬规则（ARCHITECTURE-PLAN 3.3 / 3.4 / 7.1）：
//  - 关掉主机即全网停止：stop() 后端口释放，叶子超时各自回退独立工作
//  - 断线立即回退由叶子侧负责，主机这边只负责「不推送、清理成员」
//  - 配对码用一次即作废，长期凭据可单独吊销

import { WebSocketServer, type WebSocket } from "ws";
import * as os from "node:os";
import { NET_PORT, PROTOCOL_VERSION, parseClientFrame } from "./protocol";
import type { Hello, HelloAck } from "./protocol";
import { isNetEnabled, getNetSecret, deriveKey, newSalt, seal, open, ReplayGuard } from "./secure";
import type { MembersMessage, PairResponse, PongMessage, HostShutdown, RelayRequest, RelayBackfill, RelayBusy, ConfigReport, ClientFrame } from "./protocol";
import { filterWhitelisted } from "./netStore";
import type { SyncField } from "./protocol";
import { randomToken, verifyPairing } from "./pairingCode";
import type { NetState, LeafCredential } from "./netStore";
import { rememberLeaf, removeMember } from "./netStore";

export type MemberInfo = {
    deviceId: string;
    name: string;
    online: boolean;
    since: number;
};

export type HostEvents = {
    /** 状态变化（成员增减、开关切换）—— 由调用方负责广播给 UI */
    onMembersChanged?: (members: MemberInfo[]) => void;
    /** 有叶子接入或离开，供日志与后续阶段扩展 */
    onLog?: (message: string) => void;
    /**
     * 处理上行请求（阶段 3 活锁路由）。
     * 返回 true 表示已受理。由 NetManager 注入 RelayRouter。
     */
    onRelayRequest?: (req: RelayRequest) => boolean;
    /** 处理离线补传（只记对话，不调模型） */
    onRelayBackfill?: (msg: RelayBackfill) => void;
    /**
     * 叶子上报了配置改动。
     *
     * ⚠️ 白名单判定在**主机侧**做：叶子无条件上报，主机过滤后决定广播还是丢弃。
     *    这样用户调整白名单立刻生效，不必等叶子重新连接。
     */
    onConfigReport?: (msg: ConfigReport, allowed: Partial<Record<SyncField, string>>) => void;
};

/** 一条连接上握手之后产生的全部加密状态。断开即整条丢弃。 */
type ConnCrypto = {
    /** 会话密钥（由 密钥 + 主机 salt 派生） */
    key: Buffer;
    /** 本连接的重放窗口：只对**本连接内**的序号负责 */
    guard: ReplayGuard;
    /** 本连接发出的加密帧自增序号 */
    txSeq: number;
};

export class HostServer {
    private wss: WebSocketServer | null = null;
    /**
     * 状态**不在这里存**。
     *
     * ⚠️ 之前 HostServer 与 NetManager 各自持有一份 state，互相覆盖，
     *    循环下来成员会莫名丢失（叶子重连时主机说「不认识」，
     *    而主机界面明明显示它在线）。现在 HostServer 一律通过 getState()
     *    读上层的最新状态，改动则通过 onStateChanged 写回 —— 单一数据源。
     */
    private getState: () => NetState;
    private setState: (s: NetState) => void;
    private events: HostEvents;
    /** deviceId → 在线连接 */
    private clients = new Map<string, WebSocket>();
    /** deviceId → 连接建立时间 */
    private onlineSince = new Map<string, number>();
    /** 单调递增序号：阶段 3 广播时携带，保证叶子端顺序 */
    private seq = 0;
    /**
     * 本机 salt：与密钥一起派生会话密钥。每台主机一个，一台泄露不牵连其他主机。
     * 存在组网状态里（主机侧），叶子握手时拿到。
     */
    private salt: string;
    /**
     * 每连接的加密材料，**按 WebSocket 索引**。
     *
     * ⚠️ 必须按「连接」而不是按「设备」存 —— 这是踩过的坑：
     *    叶子每次重连都会把加密帧自增序号从 0 重新开始（见 LeafClient.openSocket），
     *    而重放窗口如果按 deviceId 复用，重连后的第 1 帧 `_s=1` 会落进上一次连接
     *    留下的窗口里，被判成「重放」**静默丢弃**。
     *    症状极具迷惑性：握手是明文所以照常成功（日志里能看到「密钥协商完成」），
     *    但此后所有加密帧（pair、心跳之外的一切）全被吃掉 ——
     *    表现为「重连显示已连上，但发什么都石沉大海」。
     *    TLS / SSH / WireGuard 的重放窗口同样是每连接的，这才是一致的设计。
     *
     * 顺带的好处：连接一断就整条删掉，不会随「历史设备数」慢慢涨。
     */
    private conns = new Map<WebSocket, ConnCrypto>();

    constructor(getState: () => NetState, setState: (s: NetState) => void, events: HostEvents = {}) {
        this.getState = getState;
        this.setState = setState;
        this.events = events;
        // salt 复用状态里的，缺省新建一个并落盘
        const st = getState();
        if (st.hostSalt) {
            this.salt = st.hostSalt;
        } else {
            this.salt = newSalt();
            setState({ ...st, hostSalt: this.salt });
        }
    }

    /** 本机 salt（供 UI 诊断用） */
    getSalt(): string {
        return this.salt;
    }

    /** 当前状态（实时向上层取，不缓存）。 */
    private get state(): NetState {
        return this.getState();
    }

    get isRunning(): boolean {
        return !!this.wss;
    }

    /** 当前在线成员 + 已配对但离线的成员。 */
    members(): MemberInfo[] {
        const offline = this.state.members
            .filter((m) => !this.clients.has(m.deviceId))
            .map((m) => ({ deviceId: m.deviceId, name: m.assignedName || m.deviceName, online: false, since: m.issuedAt }));
        const online = [...this.clients.keys()].map((id) => ({
            deviceId: id,
            name: this.displayNameOf(id),
            online: true,
            since: this.onlineSince.get(id) ?? Date.now(),
        }));
        return [...online, ...offline];
    }

    private displayNameOf(deviceId: string): string {
        const m = this.state.members.find((x) => x.deviceId === deviceId);
        return m?.assignedName || m?.deviceName || deviceId.slice(0, 8);
    }

    /**
     * 开始监听。端口被占用时返回错误信息（不抛），由上层决定怎么提示用户
     * —— 常见原因是上一实例没退干净，或被别的程序占了 19760。
     */
    start(port = NET_PORT): Promise<{ ok: true; port: number } | { ok: false; error: string }> {
        if (this.wss) return Promise.resolve({ ok: true, port });
        return new Promise((resolve) => {
            let settled = false;
            const finish = (r: { ok: true; port: number } | { ok: false; error: string }) => {
                if (settled) return;
                settled = true;
                resolve(r);
            };

            const wss = new WebSocketServer({ port, host: "0.0.0.0" });
            this.wss = wss;

            wss.on("listening", () => {
                this.events.onLog?.(`[net] 主机已启动，端口 ${port}，本机地址 ${localAddresses().join(" / ")}`);
                finish({ ok: true, port });
            });
            wss.on("error", (err: NodeJS.ErrnoException) => {
                const msg =
                    err.code === "EADDRINUSE"
                        ? `端口 ${port} 已被占用。可能有另一个 Kirari 还在运行，或被其他程序占了。可以关掉那个程序，或等它退出后重试。`
                        : `主机启动失败：${err.message}`;
                this.events.onLog?.(`[net] ${msg}`);
                this.wss = null;
                finish({ ok: false, error: msg });
            });
            wss.on("connection", (ws: WebSocket) => this.handleConnection(ws));
        });
    }

    /** 停止监听并断开所有叶子（「主机退出即全网停止」）。 */
    stop(): void {
        // 先广播关停通告，再关连接。
        // 只靠 socket.close() 的话，优雅关闭要等对端回应，期间叶子毫无感知，
        // 用户看到的就是「桌宠卡住不动」——这正是要避免的体感。
        this.broadcast({
            type: "host_shutdown",
            v: PROTOCOL_VERSION,
            reason: "主机这边关掉了组网",
        } satisfies HostShutdown);

        // ⚠️ send() 只是把帧写进 socket 缓冲，立刻 close() 会让缓冲里的帧来不及
        // 发出去（表现为叶子「什么都没收到」）。留 150ms 让它真正 flush 到网卡。
        //
        // 但「已停止」的标记必须**立即**置位：否则这 150ms 内调用 start() 会被
        // 「还在运行」的判断挡掉，端口其实随后就被关掉了。
        const clients = [...this.clients.values()];
        const wss = this.wss;
        this.wss = null;
        this.clients.clear();
        this.onlineSince.clear();

        setTimeout(() => {
            for (const ws of clients) {
                try {
                    ws.close(1001, "host shutdown");
                } catch {
                    // 已经断了
                }
            }
            try {
                wss?.close();
            } catch {
                // 忽略
            }
        }, 150);
        this.events.onLog?.("[net] 主机已关闭，其他设备会自动转为独立工作");
    }

    /** 移除设备：作废其长期凭据，之后再也连不上。 */
    kick(deviceId: string): boolean {
        const existed = this.state.members.some((m) => m.deviceId === deviceId);
        this.setState(removeMember(this.getState(), deviceId));
        const ws = this.clients.get(deviceId);
        if (ws) {
            try {
                ws.close(1008, "removed by host");
            } catch {
                // 忽略
            }
            this.clients.delete(deviceId);
        }
        if (existed) {
            this.events.onLog?.(`[net] 已移除设备 ${this.displayNameOf(deviceId)}`);
            this.emitMembers();
        }
        return existed;
    }

    /** 广播成员列表变化给所有叶子。 */
    emitMembers(): void {
        const frame: MembersMessage = { type: "members", v: PROTOCOL_VERSION, members: this.members() };
        this.broadcast(frame);
        this.events.onMembersChanged?.(this.members());
    }

    /**
     * 向所有叶子广播。
     *
     * 每台设备单独加密 —— 会话密钥虽由同一个密钥派生，但每台主机一个 salt，
     * 且按连接隔离密钥材料。广播到多人时不能共用一份密文。
     */
    broadcast(payload: unknown): void {
        for (const ws of this.clients.values()) {
            this.sendTo(ws, payload);
        }
    }

    /** 只回给某一个叶子（限流拒绝、私密回执等）。 */
    replyTo(deviceId: string, payload: unknown): void {
        const ws = this.clients.get(deviceId);
        if (!ws || ws.readyState !== 1) return;
        this.sendTo(ws, payload);
    }

    /**
     * 发一帧：握手完成且该帧非心跳时加密，否则明文。
     *
     * 心跳（pong）与握手应答保持明文 —— 不含任何信息，加密只是白烧 CPU，
     * 而且明文心跳让「连不上」这类问题能直接抓包看。
     *
     * `ws` 同时也是加密材料的索引：配对应答、成员列表、回复广播都要经过这里，
     * 所以不再需要在别处记录「这一帧属于哪台设备」。
     */
    private sendTo(ws: WebSocket, payload: unknown): void {
        if (ws.readyState !== 1) return;
        const type = (payload as { type?: string })?.type;
        const keepPlain = type === "pong" || type === "hello_ack" || type === "host_shutdown";
        try {
            const conn = this.conns.get(ws);
            if (!keepPlain && isNetEnabled() && conn) {
                const body = seal(conn.key, { ...(payload as object), _s: ++conn.txSeq });
                ws.send(JSON.stringify({ e: 1, d: body }));
                return;
            }
            ws.send(JSON.stringify(payload));
        } catch {
            // 发送失败不必惊动谁：叶子会靠心跳超时自己回退
        }
    }

    /** 下一个序号（阶段 3 广播时用）。 */
    nextSeq(): number {
        return ++this.seq;
    }

    /** 替换状态（上层改动后调用）。 */
    updateState(state: NetState): void {
        this.setState(state);
    }

    /** 当前状态的快照（调试与 UI 用）。 */
    currentState(): NetState {
        return this.state;
    }

    private send(ws: WebSocket, frame: PairResponse | MembersMessage | PongMessage | RelayBusy): void {
        // 明文还是加密由 sendTo 按类型决定；加密材料的索引就是这条连接本身。
        // （原先这里靠一个 `pendingDeviceId` 字段记「配对这一刻算哪台设备」——
        //  因为那时设备还没进 clients、按 deviceId 反查不到连接。改成按连接
        //  索引之后这个补丁自然消失了。）
        this.sendTo(ws, frame);
    }

    /**
     * 解开一个加密帧。
     *
     * 三道关：
     *   1. 必须已完成握手（否则没有会话密钥）
     *   2. 必须能解密（密钥不对 / 数据被改都会在这里失败）
     *   3. 序号必须没被用过（防重放 —— GCM 挡篡改，挡不住重发）
     *
     * 任何一关不过都返回 null 且**不告诉对方原因**，避免被拿来探测。
     */
    private unsealFrame(ws: WebSocket, raw: string): any | null {
        const conn = this.conns.get(ws);
        if (!conn || !isNetEnabled()) return null;
        let envelope: { e?: number; d?: string };
        try {
            envelope = JSON.parse(raw);
        } catch {
            return null;
        }
        if (envelope?.e !== 1 || typeof envelope.d !== "string") return null;
        const opened = open(conn.key, envelope.d);
        if (!opened) return null;
        const seq = typeof opened._s === "number" ? opened._s : 0;
        if (!conn.guard.accept(seq)) return null;
        // _s 只是防重放用的序号，不往上层暴露
        delete opened._s;
        return opened;
    }

    private handleConnection(ws: WebSocket): void {
        /** 本连接是否已通过鉴权（配对或长期凭据）。未鉴权的连接只能发 pair。 */
        let authedDeviceId = "";
        /**
         * 本连接绑定的设备标识。握手阶段建立（hello 里带来），
         * 用来取会话密钥。空串 = 还没握手。
         */
        let connId = "";
        /**
         * 握手超时：连上但一直不发 hello 的，直接踢掉。
         * 防止有人扫到端口只连不发、白占一个连接。
         */
        const helloTimeout = setTimeout(() => {
            if (!connId) {
                try {
                    ws.close(1008, "handshake timeout");
                } catch {
                    // 忽略
                }
            }
        }, 10000);

        /**
         * 处理明文 hello：派生会话密钥、回 hello_ack。
         *
         * 密钥不在网络上传输 —— 两边各自用同一串密钥 + 主机的 salt 算出来。
         * 拿到错密钥的设备算出的 key 不一样，后续所有密文它都解不开，
         * 自然连不上。这正是「有密钥才能用组网」的落地点。
         */
        const handleHello = (hello: Hello): void => {
            const deviceId = String(hello.deviceId || "").trim();
            // hello 里的 deviceName 不用取 —— 真正的设备名在随后的加密 pair 帧里，
            // 那边会校验并入库（这里原先取了一次却没人用，是死代码）。
            if (!deviceId) {
                try {
                    ws.close(1008, "bad hello");
                } catch {
                    // 忽略
                }
                return;
            }
            connId = deviceId;
            clearTimeout(helloTimeout);
            // ⚠️ 每次都**新建**这条连接的加密材料，不能复用上一轮的。
            //    同一台设备重连时序号从 0 重来（LeafClient.openSocket 里有 txSeq = 0），
            //    若沿用旧窗口，它的第一帧 `_s=1` 会被判成重放而丢弃 ——
            //    症状是「重连后握手成功、之后所有加密帧石沉大海」。详见 conns 注释。
            //    这个行为已有回归用例守着：relay.integration.spec.ts 的「叶子重启后…」。
            this.conns.set(ws, {
                key: deriveKey(getNetSecret(), this.salt),
                guard: new ReplayGuard(),
                txSeq: 0,
            });
            const st = this.state;
            const ack: HelloAck = {
                type: "hello_ack",
                v: PROTOCOL_VERSION,
                salt: this.salt,
                hostId: st.deviceId,
                hostName: st.deviceName,
            };
            this.sendTo(ws, ack);
        };

        ws.on("message", (data: unknown) => {
            const raw = typeof data === "string" ? data : String(data);

            // ── 路径 1：明文握手 ──
            const plain = parseClientFrame(raw) as (ClientFrame & { type: string }) | null;
            if (plain && plain.type === "hello") {
                handleHello(plain as unknown as Hello);
                return;
            }
            // ── 路径 2：明文心跳 ──（未握手不发 pong）
            if (plain && plain.type === "ping") {
                if (!connId) return;
                this.sendTo(ws, { type: "pong", v: PROTOCOL_VERSION, seq: this.nextSeq(), serverTime: Date.now() });
                const m = this.state.members.find((x) => x.deviceId === connId);
                if (m) this.setState(rememberLeaf(this.getState(), { ...m, lastSeenAt: Date.now() }));
                return;
            }

            // ── 路径 3：加密帧 ──
            // 解不开就静默丢弃 —— 不告诉对方「你的密钥不对」，避免被拿来探测。
            const frame = this.unsealFrame(ws, raw);
            if (!frame) return;

            // ── 配对 ──
            if (frame.type === "pair") {
                const f = frame as { deviceId: string; deviceName: string; token: string };
                const deviceId = String(f.deviceId || "").trim();
                const deviceName = String(f.deviceName || "未命名设备").trim().slice(0, 24);
                const token = String(f.token || "").trim();

                if (!deviceId || !token) {
                    this.send(ws, { type: "pair_fail", v: PROTOCOL_VERSION, reason: "连接码信息不完整，重新复制一次" });
                    return;
                }

                // ── 先看是不是已配对过的设备拿长期凭据回来（重连）──
                // 这一步必须在配对码校验之前：配对码用一次就作废了，
                // 设备之后每次重连都只带长期凭据。若这里也去查配对码表，
                // 会把「已经配对好的设备」判成「连接码不认识」而拒绝，
                // 表现为：退出组网后再打开永远连不上。
                const known = this.state.members.find(
                    (m) => m.deviceId === deviceId && m.credential === token,
                );
                if (known) {
                    const now = Date.now();
                    authedDeviceId = deviceId;
                    clearTimeout(helloTimeout);
                    this.clients.set(deviceId, ws);
                    this.onlineSince.set(deviceId, now);
                    this.setState(rememberLeaf(this.getState(), { ...known, lastSeenAt: now }));
                    this.send(ws, {
                        type: "pair_ok",
                        v: PROTOCOL_VERSION,
                        credential: known.credential,
                        assignedName: known.assignedName || known.deviceName,
                        memberCount: this.state.members.length,
                    });
                    this.events.onLog?.(`[net] 设备已重连：${known.deviceName}（当前 ${this.clients.size} 台在线）`);
                    this.emitMembers();
                    return;
                }

                const err = verifyPairing(this.state.pairings, token, deviceId);
                if (err) {
                    this.events.onLog?.(`[net] 配对被拒：${err.error}`);
                    this.send(ws, { type: "pair_fail", v: PROTOCOL_VERSION, reason: err.error });
                    try {
                        ws.close(1008, "pair rejected");
                    } catch {
                        // 忽略
                    }
                    return;
                }

                // 签发长期凭据：配对码此后作废，重连靠这个
                const credential = randomToken(32);
                const now = Date.now();
                const leaf: LeafCredential = {
                    deviceId,
                    deviceName: deviceName || "未命名设备",
                    credential,
                    issuedAt: now,
                    lastSeenAt: now,
                };
                this.setState(rememberLeaf(this.getState(), leaf));
                // 把用掉的配对码标记为已使用（同时仍允许同一设备用它重连，见 verifyPairing）
                const used = this.state.pairings.find((p) => p.tokenHash && !p.revoked && p.usedBy === null);
                if (used) {
                    this.setState({
                        ...this.getState(),
                        pairings: this.getState().pairings.map((p) =>
                            p.id === used.id ? { ...p, usedBy: deviceId } : p,
                        ),
                    });
                }

                authedDeviceId = deviceId;
                clearTimeout(helloTimeout);
                this.clients.set(deviceId, ws);
                this.onlineSince.set(deviceId, now);

                this.send(ws, {
                    type: "pair_ok",
                    v: PROTOCOL_VERSION,
                    credential,
                    assignedName: leaf.deviceName,
                    memberCount: this.state.members.length,
                });
                this.events.onLog?.(`[net] 设备已接入：${leaf.deviceName}（当前 ${this.clients.size} 台在线）`);
                this.emitMembers();
                return;
            }

            // ── 以下需要先通过鉴权 ──
            if (!authedDeviceId) {
                try {
                    ws.close(1008, "not authenticated");
                } catch {
                    // 忽略
                }
                return;
            }

            // ── 活锁路由（阶段 3）──
            if (frame.type === "relay_request") {
                const handler = this.events.onRelayRequest;
                if (!handler) {
                    this.send(ws, {
                        type: "relay_busy",
                        v: PROTOCOL_VERSION,
                        requestId: frame.requestId,
                        reason: "主机还没准备好，稍后再试",
                    });
                    return;
                }
                handler(frame);
                return;
            }

            if (frame.type === "relay_backfill") {
                this.events.onRelayBackfill?.(frame);
                return;
            }

            // ── 配置同步（白名单在主机侧判定）──
            if (frame.type === "config_report") {
                const msg = frame as ConfigReport;
                // 只放行白名单内的字段；没勾的字段直接丢掉，不传播
                const allowed = filterWhitelisted(this.state, msg.patch || {});
                if (Object.keys(allowed).length) {
                    this.events.onConfigReport?.(msg, allowed);
                } else {
                    this.events.onLog?.(
                        `[net] 收到 ${msg.deviceId.slice(0, 8)} 的配置上报，但都不在同步范围内，已忽略`,
                    );
                }
                return;
            }
        });

        ws.on("close", () => {
            clearTimeout(helloTimeout);
            // 本连接的加密材料随连接一起丢掉（只删自己这一条 —— 若该设备已经
            // 换了新连接，新连接的材料挂在另一个 ws 上，不受影响）。
            this.conns.delete(ws);
            if (authedDeviceId && this.clients.get(authedDeviceId) === ws) {
                this.clients.delete(authedDeviceId);
                this.onlineSince.delete(authedDeviceId);
                this.events.onLog?.(`[net] 设备已离线：${this.displayNameOf(authedDeviceId)}`);
                this.emitMembers();
            }
        });

        ws.on("error", () => {
            // close 会紧随其后，这里不重复处理
        });
    }
}

/** 取本机可用于组网的 IPv4 地址（优先私有网段，其次回环以外的一切）。 */
export function localAddresses(): string[] {
    const out: string[] = [];
    for (const list of Object.values(os.networkInterfaces())) {
        for (const ni of list || []) {
            if (ni.family === "IPv4" && !ni.internal) out.push(ni.address);
        }
    }
    return out;
}

/** 猜测最适合填进连接码的地址：私有网段优先。 */
export function guessHostAddress(): string {
    const addrs = localAddresses();
    const priv = addrs.find((a) => /^192\.168\./.test(a) || /^10\./.test(a) || /^172\.(1[6-9]|2\d|3[01])\./.test(a));
    return priv || addrs[0] || "127.0.0.1";
}
