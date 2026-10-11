// kirari-net · src/protocol.ts
// 组网协议定义：主机与叶子之间跑的消息格式。
//
// 设计原则（来自 ARCHITECTURE-PLAN 阶段 2）：
//  - 阶段 2 只做「基础设施」：配对、心跳、成员管理。**不含**活锁路由
//    （请求上行 / 结果广播属于阶段 3）。这里先把帧格式定好，阶段 3 往里加消息类型即可。
//  - 纯数据层，不 import electron / node 特有 API，因此核心版（kirari-core）
//    能直接复用同一份协议定义。
//  - 所有消息都带 `type` 与 `v`（协议版本），未知类型一律忽略而不是报错，
//    这样 v1 客户端连上 v2 主机不会崩。

/** 协议版本。主机与叶子版本不一致时，仍以能处理的最低能力为准。 */
export const PROTOCOL_VERSION = 1;

/** 固定端口：动态端口无法写进连接码（地址要能提前填进去）。 */
export const NET_PORT = 19760;

/** 心跳节奏：2 秒一次，超过 5 秒没回应即判定连接已死。 */
export const HEARTBEAT_INTERVAL_MS = 2000;
export const HEARTBEAT_TIMEOUT_MS = 5000;

/**
 * 建连超时：CONNECTING 状态最多等这么久。
 *
 * ⚠️ 必需：被丢弃的 SYN（防火墙静默丢包、或本机 TCP TIME_WAIT 撞车）会让
 *    连接**永远停在 CONNECTING**，既不成功也不报错。没有这个超时，
 *    桌宠会一直显示「连接中」——正是历史上修过的「一直硬卡着」问题。
 */
export const CONNECT_TIMEOUT_MS = 8000;

/**
 * 握手超时：socket 已经连上、但主机迟迟不回 hello_ack 最多等这么久。
 *
 * 和建连超时是**两件事**，不能合并：
 *   - 建连超时管的是 CONNECTING 阶段（连不上）
 *   - 握手超时管的是已 OPEN、hello 发出去但没回音
 *     （主机密钥不一致把它静默丢了 / 主机卡住 / 中间设备丢包）
 *
 * ⚠️ 之前这个保护是断的：open 之后又重新武装了「建连超时」，而那个定时器一进来
 *    就 `if (ws.readyState !== 0) return` —— 此时 readyState 早就是 OPEN 了，
 *    于是直接返回、什么也不做。症状是叶子永远停在「正在与主机协商密钥」，
 *    既不成功也不回退，正是历史上修过的「一直硬卡着」的同一类问题。
 */
export const HANDSHAKE_TIMEOUT_MS = 8000;

/**
 * 配对码格式版本。用于将来扩展字段时区分旧码。
 * 形如：kirari://connect?host=192.168.57.23&port=19760&token=xxx&name=Aki-台式机&exp=1789xxxxxx&v=1
 */
export const PAIRING_SCHEME = "kirari://connect";

/**
 * 可以跟随主机的配置项。
 *
 * ⚠️ 刻意**不含** key / searchKey：组网内所有调用都用主机的凭证，
 *    把钥匙下发出去等于让叶子能拿去别处用（ARCHITECTURE-PLAN 6.5）。
 * ⚠️ 也不含 seeded：那是「本机是否已初始化过」的标记，各机自管。
 */
export type SyncField = "model" | "endpoint" | "basePersona" | "searchEndpoint" | "searchProvider";
export const SYNC_FIELDS: SyncField[] = ["model", "endpoint", "basePersona", "searchEndpoint", "searchProvider"];

/** 默认全部同步 —— 用户可以逐项取消。 */
export const DEFAULT_SYNC_WHITELIST: SyncField[] = [...SYNC_FIELDS];

// ── 加密信封（握手之后的帧都裹在这层里）────────────────────
//
// 线格式：{ e: 1, d: "<base64 密文>" }
//   d 的内容 = iv(12) + authTag(16) + AES-256-GCM(明文 JSON)
//
// 为什么单独一层而不是直接改各帧的格式：
//   握手/心跳保持明文、其余加密这条规则集中在一处，将来要调（比如加调试模式
//   走明文）只改这一处，不必在每个帧上打补丁。
//
// 序号作用：防重放。GCM 能挡篡改，挡不住「抓一条密文反复重发」。
export type SealedFrame = { e: 1; d: string };

/** 叶子 → 主机：明文握手。带上 nonce 让主机能识别「这是新连接」而不是重放。 */
export type Hello = {
    type: "hello";
    v: number;
    deviceId: string;
    deviceName: string;
    /** 客户端随机数。主机用它判断是首次握手还是重发 */
    nonce: string;
};

/**
 * 主机 → 叶子：明文握手应答，携带 salt。
 *
 * 双方各自 scrypt(密钥, salt) 派生出同一个会话密钥。
 * salt 每台主机不同 —— 这样同一把密钥在不同主机上派生出不同密钥，
 * 一台被攻破不牵连其他主机。
 */
export type HelloAck = {
    type: "hello_ack";
    v: number;
    salt: string;
    /** 主机顺带把自己的 deviceId/deviceName 带上，省一次来回 */
    hostId: string;
    hostName: string;
};

// ── 客户端 → 主机 ────────────────────────────────────────────────

/** 配对：用一次性配对码换一个长期凭据。 */
export type PairRequest = {
    type: "pair";
    v: number;
    /** 本机设备标识（持久化生成，不可变） */
    deviceId: string;
    /** 设备显示名，让主人能在成员列表里认出来 */
    deviceName: string;
    /** 配对码里的口令 */
    token: string;
    /** 协议版本，用于主机侧判断能力 */
    v2?: number;
};

/** 心跳：叶子每 2 秒一次，主机回 pong。兼作「叶子还活着」的证据。 */
export type PingMessage = {
    type: "ping";
    v: number;
    deviceId: string;
};

// ── 主机 → 客户端 ────────────────────────────────────────────────

/** 配对结果。 */
export type PairResponse = {
    type: "pair_ok" | "pair_fail";
    v: number;
    /** 失败原因（pair_fail 时给用户看，必须是大白话） */
    reason?: string;
    /** 长期凭据：配对码用一次就作废，之后靠这个自动重连 */
    credential?: string;
    /** 主机分配的设备名（叶子可能被主机改名，便于辨认） */
    assignedName?: string;
    /** 当前在线成员数 */
    memberCount?: number;
};

/** 心跳回应。 */
export type PongMessage = {
    type: "pong";
    v: number;
    /** 主机侧维护的单调递增序号，叶子据此保证顺序 */
    seq: number;
    /** 服务器时间（毫秒），叶子据此估算时钟偏差 */
    serverTime: number;
};

/** 成员变化通知（阶段 2 只用于刷新 UI 列表）。 */
export type MembersMessage = {
    type: "members";
    v: number;
    members: { deviceId: string; name: string; online: boolean; since: number }[];
};

/**
 * 主机即将关闭的通告。
 *
 * 为什么不能只靠 TCP close 通知：服务端 close() 是「发起优雅关闭」，
 * 要等对端回应才真正断开；期间叶子那边完全无感知，桌宠看起来就是「卡住了」。
 * 明确发一帧通告，叶子能立刻带着原因回退独立工作 —— 符合「硬断线立即响应」
 * 和「退出要告知用户」两条要求。
 */
export type HostShutdown = {
    type: "host_shutdown";
    v: number;
    /** 给用户看的大白话 */
    reason: string;
};

/**
 * ── 活锁路由（阶段 3）───────────────────────────────────────────
 * 核心模型：请求上行主机，主机是唯一出口，结果广播给全网。
 * 因此一条消息在任何时候都只有一份回复。
 */

/** 叶子 → 主机：把请求上行（请求方要答，由主机的凭证付账）。 */
export type RelayRequest = {
    type: "relay_request";
    v: number;
    deviceId: string;
    requestId: string;
    /**
     * 请求方的会话 ID。主机据此取历史上下文 ——
     * 这样每台设备有自己的对话脉络，互不串味，且断线重连后上下文还在
     * （上下文存在主机的库里，不是叶子本地）。
     */
    sessionId: string;
    content: string;
    images?: string[];
    /** 请求方昵称，仅用于日志与广播显示 */
    nickname?: string;
};

/** 主机 → 全网：生成好的回复。 */
export type RelayResult = {
    type: "relay_result";
    v: number;
    requestId: string;
    speech: string;
    emotion?: string | null;
    /** 单调递增：叶子只接受递增的，保证多端并发时顺序不乱 */
    seq: number;
    /** 是谁问的 */
    fromDeviceId: string;
    fromName?: string;
    /** 请求方的会话 ID，便于其他叶子决定要不要记进自己的历史 */
    sessionId: string;
    /** 发起时刻（毫秒），广播里带着，各端算延迟方便排查 */
    askedAt: number;
};

/** 主机 → 请求方：主机忙不过来（队列满 / 正在关停）。 */
export type RelayBusy = {
    type: "relay_busy";
    v: number;
    requestId: string;
    reason: string;
    /** 建议等待多久再试（毫秒） */
    retryAfterMs?: number;
};

/**
 * 叶子 → 主机：补传断线期间的对话记录。
 *
 * 只入库、**不重新触发模型调用** —— 否则其他叶子会看到重复内容，
 * 而且等于凭空多花主机的额度（ARCHITECTURE-PLAN 3.5）。
 */
export type RelayBackfill = {
    type: "relay_backfill";
    v: number;
    deviceId: string;
    sessionId: string;
    nickname?: string;
    /** 本地独立工作期间产生的对话（按时间顺序） */
    entries: { role: "user" | "assistant"; text: string; at: number }[];
};

/** 主机 → 叶子：补传已入库，可以清掉本地的待补队列。 */
export type RelayBackfillAck = {
    type: "relay_backfill_ack";
    v: number;
    count: number;
};

/**
 * 叶子 → 主机：上报配置改动。
 *
 * 叶子**无条件上报**，不自己判断该不该同步 —— 白名单是主机侧的东西，
 * 叶子看不到也不该管（ARCHITECTURE-PLAN 6.6）。主机收到后决定
 * 是广播给全网还是丢弃，这样用户改白名单能立即生效，不必等叶子重连。
 */
export type ConfigReport = {
    type: "config_report";
    v: number;
    deviceId: string;
    patch: Partial<Record<SyncField, string>>;
};

/** 主机 → 叶子：下发配置。只会包含白名单内的字段。 */
export type ConfigPush = {
    type: "config_push";
    v: number;
    /** 来源："host" 或某个叶子 deviceId（叶子改了、主机批准后转发） */
    fromDeviceId: string;
    patch: Partial<Record<SyncField, string>>;
};

export type ServerFrame =
    | PairResponse
    | PongMessage
    | MembersMessage
    | HostShutdown
    | RelayResult
    | RelayBusy
    | RelayBackfillAck
    | ConfigPush
    | HelloAck;
export type ClientFrame = Hello | PairRequest | PingMessage | RelayRequest | RelayBackfill | ConfigReport;

/** 解析服务端发来的文本帧。非法 JSON / 缺 type 一律返回 null（不抛）。 */
export function parseServerFrame(raw: unknown): ServerFrame | null {
    return parseFrame(raw) as ServerFrame | null;
}

/** 解析叶子发来的文本帧。非法 JSON / 缺 type 一律返回 null（不抛）。 */
export function parseClientFrame(raw: unknown): ClientFrame | null {
    return parseFrame(raw) as ClientFrame | null;
}

function parseFrame(raw: unknown): Record<string, unknown> | null {
    if (typeof raw !== "string") return null;
    let obj: unknown;
    try {
        obj = JSON.parse(raw);
    } catch {
        return null;
    }
    if (!obj || typeof obj !== "object") return null;
    const frame = obj as Record<string, unknown>;
    if (typeof frame.type !== "string") return null;
    return frame;
}

/**
 * 广播序号跟踪：**只做去重，不做乱序丢弃**。
 *
 * ⚠️ 这里踩过两个坑，最终结论是「宁可顺序不完美，也不能丢消息」：
 *    1. 一开始实现成「只接受递增 seq，否则丢弃」→ 并发时完成顺序 ≠ seq 顺序，
 *       真的把用户该看到的回复丢了。
 *    2. 改成带定时器的重排序缓冲 → 逻辑太复杂，反而在并发下漏交付。
 *
 * 现在：全部收下、按 seq 去重后立即交付。**顺序由上层按 seq 排**（阶段 4 的 UI），
 * 这样多端看到的顺序仍然一致，而一条都不会丢。
 */
export class SeqTracker {
    private seen = new Set<number>();
    private last = 0;

    /** 返回 true 表示这是首次收到（应交付给上层）。 */
    accept(seq: number): boolean {
        if (typeof seq !== "number" || !Number.isFinite(seq)) return false;
        if (this.seen.has(seq)) return false; // 重复帧
        this.seen.add(seq);
        // 只保留最近 200 个序号，防止长时间运行后 Set 无限增长
        if (this.seen.size > 200) {
            const keep = [...this.seen].sort((a, b) => b - a).slice(0, 100);
            this.seen = new Set(keep);
        }
        this.last = Math.max(this.last, seq);
        return true;
    }

    get current(): number {
        return this.last;
    }

    reset(): void {
        this.seen.clear();
        this.last = 0;
    }
}
