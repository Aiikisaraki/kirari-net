// kirari-net · src/netStore.ts
// 组网状态的持久化。
//
// 落实 ARCHITECTURE-PLAN 5.7「退出不清除」这条铁律：
// 主机地址、端口、长期凭据、自己的角色、配对码列表，**一律只存不清**。
// 用户关掉组网开关 = 暂停参与；下次打开凭这些信息自动归位，不需要重新配对。
//
// 唯一会被清的是「成员列表里的在线状态」——那是运行时状态，不是配置。

import * as fs from "node:fs";
import * as path from "node:path";
import type { PairingRecord, ExpiryKey } from "./pairingCode";
import type { SyncField } from "./protocol";
import { DEFAULT_SYNC_WHITELIST } from "./protocol";

export type NetRole = "off" | "host" | "leaf";

/** 已配对设备的长期凭据（主机签发给叶子）。 */
export type LeafCredential = {
    deviceId: string;
    deviceName: string;
    /** 长期凭据明文（只存本机，用于自动重连） */
    credential: string;
    issuedAt: number;
    lastSeenAt: number;
    /** 主机给出的显示名（主机可改名） */
    assignedName?: string;
};

export type NetState = {
    /** 组网总开关对应的角色：off = 独立工作，host = 提供出口，leaf = 请求上行 */
    role: NetRole;
    /** 本机在组网中的身份 */
    deviceId: string;
    deviceName: string;

    // ── 主机侧 ──
    /** 家庭标识：用于识别「是不是同一个局域网里的同一伙设备」 */
    homeId: string;
    /**
     * 本机 salt：与密钥一起派生会话密钥。
     * 每台主机一个，握手时下发给叶子 —— 这样同一把密钥在不同主机上
     * 派生出不同密钥，一台被攻破不牵连其他主机。
     */
    hostSalt?: string;
    /** 已生成的配对码（只存哈希） */
    pairings: PairingRecord[];
    /** 已配对成功的叶子设备及其长期凭据（可单独吊销） */
    members: LeafCredential[];
    /**
     * 配置同步白名单：**只有主机侧有这个东西**，叶子看不到也改不了。
     *
     * 勾选的字段会下发给所有叶子；没勾的各设备自管，互不干扰。
     * 刻意不含钥匙类字段 —— 组网内用主机的凭证就够。
     */
    syncWhitelist: SyncField[];

    // ── 叶子侧 ──
    /** 主机的地址与端口（从连接码解析而来） */
    hostAddress?: string;
    hostPort?: number;
    hostName?: string;
    /** 主机签发的长期凭据 */
    credential?: string;
    /** 配对码里承诺的主机名（仅展示） */
    hostDisplayName?: string;

    /**
     * 本机签发/保管的组网密钥。
     *
     * 两种来源：
     *  - `ownSecret`：本机第一次当主机时临时生成的（源码里不带任何密钥，
     *    也从源码里导出不来 —— 它就是这台机器自己的秘密）
     *  - `enrolledSecret`：本机当叶子时，主机在配对那一刻加密发过来的
     *
     * 落盘是**必需**的：不然每次重连都要重新配对。这个文件权限收紧到 600，
     * 且这两个字段**绝不出现在 snapshot() 里**（界面、组网同步都不知道有它）。
     */
    ownSecret?: string;
    enrolledSecret?: string;
};

const FILE_NAME = "net-state.json";

export function defaultNetState(deviceId: string, deviceName: string): NetState {
    return {
        role: "off",
        deviceId,
        deviceName,
        homeId: "",
        pairings: [],
        members: [],
        syncWhitelist: [...DEFAULT_SYNC_WHITELIST],
    };
}

/** 读取；文件不存在或损坏时返回默认状态（不会抛）。 */
export function loadNetState(userDataDir: string, deviceId: string, deviceName: string): NetState {
    const file = path.join(userDataDir, FILE_NAME);
    try {
        if (fs.existsSync(file)) {
            const raw = JSON.parse(fs.readFileSync(file, "utf8"));
            if (raw && typeof raw === "object") {
                const base = defaultNetState(deviceId, deviceName);
                return {
                    ...base,
                    ...raw,
                    // 这几个字段永远以本机实际身份为准，不能被文件里的旧值带偏
                    deviceId,
                    deviceName,
                    role: raw.role === "host" || raw.role === "leaf" ? raw.role : "off",
                    pairings: Array.isArray(raw.pairings) ? raw.pairings : [],
                    syncWhitelist: Array.isArray(raw.syncWhitelist) ? raw.syncWhitelist : base.syncWhitelist,
                };
            }
        }
    } catch {
        // 损坏 → 重新开始
    }
    return defaultNetState(deviceId, deviceName);
}

/** 保存（原子写：先写临时文件再改名，避免断电写坏半个文件）。 */
export function saveNetState(userDataDir: string, state: NetState): void {
    const file = path.join(userDataDir, FILE_NAME);
    const tmp = `${file}.tmp`;
    try {
        fs.mkdirSync(userDataDir, { recursive: true });
        // 600：这个文件里可能躺着组网密钥与长期凭据。
        fs.writeFileSync(tmp, JSON.stringify(state, null, 2), { encoding: "utf8", mode: 0o600 });
        fs.renameSync(tmp, file);
    } catch (e) {
        console.warn("[net] 组网状态写入失败:", (e as Error)?.message || e);
        try {
            if (fs.existsSync(tmp)) fs.unlinkSync(tmp);
        } catch {
            // 清理失败无所谓，下次保存会覆盖
        }
    }
}

// ── 便捷操作 ─────────────────────────────────────────────────────

/** 开启组网：主机或叶子。切角色不清任何配置。 */
export function enableNetworking(state: NetState, role: "host" | "leaf"): NetState {
    return { ...state, role };
}

/**
 * 关闭组网：只是「暂停参与」。
 * 主机地址、长期凭据、配对码全部保留 —— 这是「退出无损」的关键。
 */
export function disableNetworking(state: NetState): NetState {
    return { ...state, role: "off" };
}

/** 主机新增一条配对码记录。 */
export function addPairing(state: NetState, record: PairingRecord): NetState {
    return { ...state, pairings: [record, ...state.pairings].slice(0, 20) };
}

/** 撤销一条配对码（作废配对入口，不影响已连设备）。 */
export function revokePairing(state: NetState, pairingId: string): NetState {
    return {
        ...state,
        pairings: state.pairings.map((p) => (p.id === pairingId ? { ...p, revoked: true } : p)),
    };
}

/** 清理过期且从未被用过的配对码（保持列表干净，不影响任何已连设备）。 */
export function pruneExpiredPairings(state: NetState, now = Date.now()): NetState {
    const keep = state.pairings.filter(
        (p) => p.usedBy || p.expiresAt === 0 || p.expiresAt > now,
    );
    return keep.length === state.pairings.length ? state : { ...state, pairings: keep };
}

/** 叶子侧记录配对成功：保存主机地址与长期凭据。 */
export function attachToHost(
    state: NetState,
    host: { address: string; port: number; displayName: string },
    credential: string,
): NetState {
    return {
        ...state,
        hostAddress: host.address,
        hostPort: host.port,
        hostDisplayName: host.displayName,
        credential,
    };
}

/** 主机侧记录/更新某叶子的长期凭据（按 deviceId 覆盖）。 */
export function rememberLeaf(state: NetState, leaf: LeafCredential): NetState {
    const rest = state.members.filter((m) => m.deviceId !== leaf.deviceId);
    return { ...state, members: [leaf, ...rest].slice(0, 50) };
}

/**
 * 主机侧移除设备。
 *
 * 与「退出组网」语义不同（ARCHITECTURE-PLAN 6.5）：
 *   退出组网 = 暂停参与，凭据保留，下次打开自动归位；
 *   移除设备 = 作废该设备的长期凭据，它再也连不上。
 */
export function removeMember(state: NetState, deviceId: string): NetState {
    return { ...state, members: state.members.filter((m) => m.deviceId !== deviceId) };
}

/** 叶子侧：断开与主机的绑定（对应「移除自己」，会作废本地凭据）。 */
export function detachFromHost(state: NetState): NetState {
    return {
        ...state,
        role: "off",
        hostAddress: undefined,
        hostPort: undefined,
        hostDisplayName: undefined,
        credential: undefined,
    };
}

/**
 * 本机自己签发一把组网密钥（第一次当主机、手上还没有任何密钥时）。
 * 有了它，「从源码构建 / 用 docker 跑」的人也能组自己的网 —— 不用先知道密钥。
 */
export function setOwnSecret(state: NetState, secret: string): NetState {
    return { ...state, ownSecret: secret };
}

/** 叶子侧记下从主机 enroll 学到的密钥。值没变就返回同一个对象（避免调用方无谓写盘）。 */
export function setEnrolledSecret(state: NetState, secret: string): NetState {
    if (state.enrolledSecret === secret) return state;
    return { ...state, enrolledSecret: secret };
}

/**
 * 本机该用哪把组网密钥（不含宿主环境变量注入的那把 —— 那个由宿主负责判断优先级）。
 * 叶子优先用连进来学到的（就是当前这个网的），其次用自己签的。
 */
export function storedSecret(state: NetState): string | undefined {
    return state.enrolledSecret || state.ownSecret || undefined;
}

/** 叶子侧彻底退出某个网：连从它那里学到的密钥一起忘掉（否则下次还会滑回那个网）。 */
export function forgetEnrolledSecret(state: NetState): NetState {
    const next = { ...state, enrolledSecret: undefined };
    delete next.enrolledSecret;
    return next;
}

/** 设置主机侧同步白名单。叶子侧调用会被忽略（白名单只在主机生效）。 */
export function setSyncWhitelist(state: NetState, fields: SyncField[]): NetState {
    return { ...state, syncWhitelist: [...fields] };
}

/** 取白名单内的字段（用于过滤上报/下发的 patch）。 */
export function filterWhitelisted(
    state: NetState,
    patch: Partial<Record<SyncField, string>>,
): Partial<Record<SyncField, string>> {
    const out: Partial<Record<SyncField, string>> = {};
    for (const key of Object.keys(patch) as SyncField[]) {
        if (state.syncWhitelist.includes(key) && typeof patch[key] === "string") {
            out[key] = patch[key];
        }
    }
    return out;
}

/** 生成配对码时用到的默认过期档位。 */
export const DEFAULT_EXPIRY: ExpiryKey = "7d";
