// kirari-net · src/identity.ts
// 设备标识：每台设备一个稳定 id，用于组网中区分「谁是谁」。
//
// 为什么需要（ARCHITECTURE-PLAN 4.3 核查结论：桌面端此前完全没有这个概念）：
//   组网里主机要认出「这台设备上次来过」，长期凭据也要挂在设备 id 上，
//   否则每台设备一个 key 就退化成全局密钥，无法单独吊销某台设备。
//
// 规则：
//   - 首次启动生成，随机且不可变，持久化在 userData
//   - 不含任何硬件指纹（换网卡/重装系统不该影响，但也不该被收集）
//   - 卸载重装 = 新设备（凭据也就失效了，符合预期）

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { randomToken } from "./pairingCode";

export type DeviceIdentity = {
    deviceId: string;
    /** 设备默认名，用户可改 */
    name: string;
    createdAt: number;
};

const FILE_NAME = "net-identity.json";

/** 取本机默认设备名（用于主机名，太怪就退回用户名）。 */
function defaultDeviceName(): string {
    const h = os.hostname().trim();
    if (h && h.length <= 24) return h;
    const u = (os.userInfo?.()?.username || "这台设备").trim();
    return u.slice(0, 24);
}

/**
 * 读取设备身份；不存在则创建并写入。
 * @param userDataDir Electron 的 userData 目录
 */
export function loadOrCreateIdentity(userDataDir: string): DeviceIdentity {
    const file = path.join(userDataDir, FILE_NAME);
    try {
        if (fs.existsSync(file)) {
            const raw = JSON.parse(fs.readFileSync(file, "utf8"));
            if (raw && typeof raw.deviceId === "string" && raw.deviceId.trim()) {
                return {
                    deviceId: raw.deviceId,
                    name: typeof raw.name === "string" && raw.name.trim() ? raw.name.trim() : defaultDeviceName(),
                    createdAt: typeof raw.createdAt === "number" ? raw.createdAt : Date.now(),
                };
            }
        }
    } catch {
        // 文件损坏 → 重新生成（等价于换了一台设备，可接受）
    }

    const identity: DeviceIdentity = {
        deviceId: randomToken(16),
        name: defaultDeviceName(),
        createdAt: Date.now(),
    };
    try {
        fs.mkdirSync(userDataDir, { recursive: true });
        fs.writeFileSync(file, JSON.stringify(identity, null, 2), "utf8");
    } catch (e) {
        console.warn("[net] 设备标识写入失败（本次运行有效，重启后会变）:", (e as Error)?.message || e);
    }
    return identity;
}

/** 改设备名（用户在设置里改的）。 */
export function renameIdentity(userDataDir: string, name: string): DeviceIdentity {
    const file = path.join(userDataDir, FILE_NAME);
    const clean = String(name || "").trim().slice(0, 24) || defaultDeviceName();
    let deviceId = randomToken(16);
    try {
        if (fs.existsSync(file)) {
            const raw = JSON.parse(fs.readFileSync(file, "utf8"));
            if (raw && typeof raw.deviceId === "string" && raw.deviceId) deviceId = raw.deviceId;
        }
    } catch {
        // 读失败就当新建
    }
    const identity: DeviceIdentity = { deviceId, name: clean, createdAt: Date.now() };
    try {
        fs.mkdirSync(userDataDir, { recursive: true });
        fs.writeFileSync(file, JSON.stringify(identity, null, 2), "utf8");
    } catch (e) {
        console.warn("[net] 设备名写入失败:", (e as Error)?.message || e);
    }
    return identity;
}
