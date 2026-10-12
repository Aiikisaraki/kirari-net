// kirari-net · src/pairingCode.ts
// 连接码：生成、解析、校验、哈希。
//
// 「连接码」是设备之间配对用的通行证，**两种形态**（详见 ARCHITECTURE-PLAN §5.2）：
//   · 邀请码（默认）    kirari://join?d=<base64(JSON)>
//       不需要密钥就能解析 —— 新设备本来就没有密钥，若码必须用密钥才能解，
//       就成了「要有密钥才能拿到密钥」的死循环。安全性靠里面的一次性口令。
//   · 密文码（旧，兼容） kirari://connect?d=<密文>
//       整包加密，给「本来就带着密钥的旧客户端」用。
//   两者统一走 parseAnyPairingCode() 解析。
//
// 三个关键设计（来自 ARCHITECTURE-PLAN §5.4~5.6）：
//  1. **只管首次配对**。用掉一次就作废，之后设备靠长期凭据自动重连。
//     所以它过期影响的是「新设备还能不能配对」，不是「已连上的设备断不断」。
//  2. **只存哈希，不存明文**。载体是文本/二维码，极易被截图转发。
//  3. 过期用**绝对时间戳**（expiresAt），不用相对时长——否则重启后会漂移。
//
// 本模块是纯逻辑，不碰文件系统与 electron，便于单测。

// 与 secure.ts 一样直接静态 import：主进程构建目标就是 node，crypto 不会被
// 内联进产物。原先这里用 `eval("require")` 间接拿 —— 那个 hack 在 ESM 环境下
// 直接抛错（连单测都跑不起来），而且没必要（secure.ts 早就在静态 import 了）。
import { createHash } from "crypto";
import { NET_PORT, PAIRING_SCHEME, PROTOCOL_VERSION } from "./protocol";
import { getNetSecret, deriveKey, seal, open } from "./secure";

/**
 * 连接码用的固定 salt。
 *
 * 刻意固定（而不是像组网会话那样每台主机一个）：连接码是**离线凭证**，
 * 要能让任何一台 Kirari 独立解开 —— 它不知道该找谁要 salt。
 * 用固定 salt + 程序内的组网密钥派生，谁装了同一个版本的程序谁都能解，
 * 但外部的人（截图转发者）没有这个密钥，解不开就是一堆乱码。
 */
const PAIRING_SALT = "kirari-pairing-v1";

/** 密文码的加密密钥 —— 由本机组网密钥派生。手上还没有密钥时生成/解析不了密文码。 */
function pairingKey(): Buffer | null {
    if (!getNetSecret()) return null;
    return deriveKey(getNetSecret(), PAIRING_SALT);
}

/** 过期档位（用户自选）。 */
export const EXPIRY_PRESETS = [
    { key: "1h", label: "1 小时", ms: 60 * 60 * 1000 },
    { key: "1d", label: "1 天", ms: 24 * 60 * 60 * 1000 },
    { key: "7d", label: "7 天", ms: 7 * 24 * 60 * 60 * 1000 },
    { key: "30d", label: "30 天", ms: 30 * 24 * 60 * 60 * 1000 },
    { key: "forever", label: "永不过期", ms: 0 },
] as const;

export type ExpiryKey = (typeof EXPIRY_PRESETS)[number]["key"];

/** 连接码里携带的信息（明文形态，用于展示/复制/扫码）。 */
export type PairingCode = {
    /** 主机地址（IP 或主机名） */
    host: string;
    /** 固定端口 */
    port: number;
    /** 配对口令（明文，只在生成时存在，存储用哈希） */
    token: string;
    /** 主机显示名，便于辨认 */
    name: string;
    /** 绝对过期时间戳（ms）。0 表示永不过期 */
    expiresAt: number;
    /** 协议版本 */
    v: number;
};

/** 存储形态：只有哈希，没有明文口令。 */
export type PairingRecord = {
    /** 记录 id（用于撤销单个） */
    id: string;
    /** 口令哈希（sha256 十六进制） */
    tokenHash: string;
    /** 主机显示名 */
    name: string;
    /** 绝对过期时间戳；0 = 永不过期 */
    expiresAt: number;
    createdAt: number;
    /** 已配对过的设备 id（用于「这码用过了就作废」） */
    usedBy: string | null;
    revoked: boolean;
};

/** 生成随机十六进制串。用于配对口令与长期凭据。 */
export function randomToken(bytes = 24): string {
    // 浏览器与 Node 都有的取随机方式；Electron 主进程有 globalThis.crypto。
    const c = globalThis.crypto;
    if (c && typeof c.getRandomValues === "function") {
        const arr = new Uint8Array(bytes);
        c.getRandomValues(arr);
        return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
    }
    // 兜底（极老的运行时才会走到）
    let out = "";
    for (let i = 0; i < bytes * 2; i++) {
        out += Math.floor(Math.random() * 16).toString(16);
    }
    return out;
}

/** 口令哈希。只存这个，不存明文。 */
export function hashToken(token: string): string {
    const c = globalThis.crypto;
    const text = `kirari-pair:${token}`;
    if (c && typeof c.subtle !== "undefined") {
        // subtle 是异步的，这里需要同步版本，故用 Node 的 crypto 走同步哈希。
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        return nodeSha256(text);
    }
    return nodeSha256(text);
}

/**
 * 同步 SHA-256。
 * 用 node:crypto 而不是 crypto.subtle（后者是异步的，会把整个调用链变成异步，
 * 配对校验这种热路径不值得）。
 */
function nodeSha256(text: string): string {
    return createHash("sha256").update(text, "utf8").digest("hex");
}

/** 按档位算出绝对过期时间戳。forever → 0。 */
export function resolveExpiry(key: ExpiryKey, now = Date.now()): number {
    if (key === "forever") return 0;
    const preset = EXPIRY_PRESETS.find((p) => p.key === key);
    if (!preset) return now + EXPIRY_PRESETS[2].ms; // 未知档位退回 7 天
    return now + preset.ms;
}

/** 生成一条连接码（明文形态，用于展示给用户复制/扫码）。 */
export function generatePairingCode(opts: {
    host: string;
    name: string;
    expiryKey: ExpiryKey;
    port?: number;
    now?: number;
}): { code: PairingCode; record: PairingRecord } {
    const now = opts.now ?? Date.now();
    const token = randomToken(24);
    const expiresAt = resolveExpiry(opts.expiryKey, now);
    return {
        code: {
            host: opts.host,
            port: opts.port ?? NET_PORT,
            token,
            name: opts.name,
            expiresAt,
            v: PROTOCOL_VERSION,
        },
        record: {
            id: randomToken(8),
            tokenHash: hashToken(token),
            name: opts.name,
            expiresAt,
            createdAt: now,
            usedBy: null,
            revoked: false,
        },
    };
}

/**
 * 序列化成一条**密文**连接码。
 *
 * 形如：kirari://c?d=<base64 密文>
 *   密文里包着 {host, port, token, name, expiresAt, v}
 *
 * 为什么整包加密而不是只保护 token：
 *   - 主机地址、设备名同样属于「不该随便被外人看到」的信息
 *     （暴露了地址就能直接扫端口）
 *   - 整包密文还有个额外好处：**截图转发也没用**。别人拿到这串东西
 *     没有你的组网密钥，解不开，填进去只会得到「这个连接码解不开」。
 *   这正是「连接码即密码」的含义 —— 它本来就该是个秘密。
 *
 * 代价：用户肉眼看不出连接码对不对（地址错了也看不出来）。
 * 界面上用二维码兜住这个问题，扫比手打靠谱。
 */
export function serializePairingCode(code: PairingCode): string {
    const key = pairingKey();
    // 没有密钥就不给生成密文码 —— 与其悄悄降级成不安全，不如明确失败。
    // （这条路径不该出现在正常流程里：新设备一律发邀请码，那个不需要密钥。）
    if (!key) throw new Error("本机还没有组网密钥，生成不了密文码");
    const payload = {
        h: code.host,
        p: code.port,
        t: code.token,
        n: code.name,
        e: code.expiresAt,
        v: code.v,
    };
    // ⚠️ 必须 encodeURIComponent：base64 里的 "+" 会被 URLSearchParams
    //    当成空格解码，"/" 也会破坏 URL 结构。不编码的话自己生成的码
    //    自己都解不开（这正是下面测试发现的问题）。
    return `${PAIRING_SCHEME}?d=${encodeURIComponent(seal(key, payload))}`;
}

/**
 * 解析连接码 —— 现在**只会**认密文码。
 *
 * 不再保留明文解析的兼容分支：留一个「明文也能用」的后门等于加密白做。
 * 旧码直接失效，让主人重新生成一个即可（成本很低）。
 */
export function parsePairingCode(raw: string): PairingCode | null {
    const text = String(raw || "").trim();
    if (!text.toLowerCase().startsWith(PAIRING_SCHEME)) return null;
    let q: URLSearchParams;
    try {
        q = new URL(text).searchParams;
    } catch {
        return null;
    }
    const d = q.get("d");
    if (!d) return null;

    const key = pairingKey();
    if (!key) return null;

    const payload = open(key, d) as
        | { h?: unknown; p?: unknown; t?: unknown; n?: unknown; e?: unknown; v?: unknown }
        | null;
    if (!payload) return null;

    const host = typeof payload.h === "string" ? payload.h.trim() : "";
    const token = typeof payload.t === "string" ? payload.t.trim() : "";
    // 口令与地址缺一不可；name / exp / v 可缺（容错，老版本生成的码也能用）
    if (!host || !token) return null;

    const portNum = Number(payload.p);
    const expNum = Number(payload.e);
    const vNum = Number(payload.v ?? PROTOCOL_VERSION);

    return {
        host,
        port: Number.isFinite(portNum) && portNum > 0 && portNum < 65536 ? portNum : NET_PORT,
        token,
        name: typeof payload.n === "string" && payload.n.trim() ? payload.n.trim().slice(0, 40) : "未命名设备",
        expiresAt: Number.isFinite(expNum) && expNum >= 0 ? expNum : 0,
        v: Number.isFinite(vNum) && vNum > 0 ? vNum : PROTOCOL_VERSION,
    };
}

/**
 * ── 邀请码（新格式，密钥的无感分发全靠它）──────────────────────
 *
 * 形如：kirari://join?d=<base64(JSON)>
 *
 * 与上面那种密文码的区别：**不需要先有密钥就能解开**。这一点是刻意的，
 * 也是整条链路能跑通的前提 —— 新设备本来就没有密钥，若码必须用密钥才能解，
 * 就成了「要有密钥才能拿到密钥」的死循环。
 *
 * 那么密钥的安全性靠什么？靠**一次性口令 t**：
 *   - 口令是一次性的：用过一次即作废（usedBy），可单独撤销（revoked），有过期时间
 *   - 光拿到码、在局域网里对着主机扫端口是没用的 —— 第二轮握手（enroll）
 *     会校验这个口令，不对的话主机一个字节的密钥都不会吐出来
 *   - 类比 WiFi 分享二维码：里面确实是明文的，但「看得见」不等于「能连上」
 *
 * ⚠️ 与密文码的安全差别要说清楚：密文码被截图转发后，没有那把组网密钥的人
 *    连里面的口令都看不到；邀请码被转发后，转发者可以拿着口令去 enroll，
 *    **从而拿到组网密钥**。所以邀请码必须按「等同密码」对待 ——
 *    一次性、短期有效、可撤销，判罚标准与密文码一致。
 */
export const JOIN_SCHEME = "kirari://join";

export function serializeInviteCode(code: PairingCode): string {
    const payload = {
        h: code.host,
        p: code.port,
        t: code.token,
        n: code.name,
        e: code.expiresAt,
        v: code.v,
    };
    return `${JOIN_SCHEME}?d=${encodeURIComponent(Buffer.from(JSON.stringify(payload), "utf8").toString("base64"))}`;
}

/** 解析邀请码。解不开返回 null。 */
export function parseInviteCode(raw: string): PairingCode | null {
    const text = String(raw || "").trim();
    if (!text.toLowerCase().startsWith(JOIN_SCHEME)) return null;
    let q: URLSearchParams;
    try {
        q = new URL(text).searchParams;
    } catch {
        return null;
    }
    const d = q.get("d");
    if (!d) return null;
    let payload: Record<string, unknown>;
    try {
        payload = JSON.parse(Buffer.from(d, "base64").toString("utf8"));
    } catch {
        return null;
    }
    if (!payload || typeof payload !== "object") return null;
    const host = typeof payload.h === "string" ? payload.h.trim() : "";
    const token = typeof payload.t === "string" ? payload.t.trim() : "";
    if (!host || !token) return null;
    const portNum = Number(payload.p);
    const expNum = Number(payload.e);
    const vNum = Number(payload.v ?? PROTOCOL_VERSION);
    return {
        host,
        port: Number.isFinite(portNum) && portNum > 0 && portNum < 65536 ? portNum : NET_PORT,
        token,
        name: typeof payload.n === "string" && payload.n.trim() ? payload.n.trim().slice(0, 40) : "未命名设备",
        expiresAt: Number.isFinite(expNum) && expNum >= 0 ? expNum : 0,
        v: Number.isFinite(vNum) && vNum > 0 ? vNum : PROTOCOL_VERSION,
    };
}

/**
 * 两种码都认。
 *
 * 密文码给「本来就带着密钥的旧客户端」用（那台设备多半是我自己发出去的桌宠包），
 * 邀请码给「手上一把密钥也没有的新部署」用。判不出来返回 null。
 */
export function parseAnyPairingCode(raw: string): { code: PairingCode; kind: "invite" | "sealed" } | null {
    const text = String(raw || "").trim();
    const invite = parseInviteCode(text);
    if (invite) return { code: invite, kind: "invite" };
    const sealed = parsePairingCode(text);
    if (sealed) return { code: sealed, kind: "sealed" };
    return null;
}

/** 配对码是否还在有效期内（永不过期返回 true）。 */
export function isPairingValid(record: PairingRecord, now = Date.now()): boolean {
    if (record.revoked) return false;
    if (record.expiresAt === 0) return true;
    return record.expiresAt > now;
}

/** 剩余有效期的中文描述，用于 UI 提示。 */
export function describeRemaining(record: PairingRecord, now = Date.now()): string {
    if (record.revoked) return "已撤销";
    if (record.expiresAt === 0) return "永不过期";
    const left = record.expiresAt - now;
    if (left <= 0) return "已过期";
    const hours = Math.floor(left / 3600000);
    if (hours >= 24) return `还有 ${Math.floor(hours / 24)} 天`;
    if (hours >= 1) return `还有 ${hours} 小时`;
    return `还有 ${Math.max(1, Math.floor(left / 60000))} 分钟`;
}

/**
 * 校验一次配对请求。
 * @returns 成功返回 null，失败返回给用户看的大白话原因。
 */
export function verifyPairing(
    records: PairingRecord[],
    presentedToken: string,
    deviceId: string,
    now = Date.now(),
): { error: string } | null {
    const presented = hashToken(String(presentedToken || "").trim());
    const record = records.find((r) => r.tokenHash === presented);
    if (!record) {
        return { error: "这个连接码不认识，检查是不是复制全了，或者已经撤销了" };
    }
    if (record.revoked) {
        return { error: "这个连接码已经被撤销了，让主人在设置里重新生成一个" };
    }
    if (record.usedBy && record.usedBy !== deviceId) {
        return { error: "这个连接码已经用过了，让主人生成一个新的" };
    }
    if (!isPairingValid(record, now)) {
        return { error: "这个连接码已经过期了，让主人在设置里重新生成一个" };
    }
    return null;
}
