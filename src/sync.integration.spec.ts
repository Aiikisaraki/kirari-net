// @vitest-environment node
//
// 组网配置同步的**端到端**验证：真的起一个主机、真的让一台叶子通过连接码接进来，
// 走完 握手 → 加密 → 上报 → 主机白名单过滤 → 广播下发 的全过程。
//
// 这不是单测能替代的：白名单之前「逻辑写完了但从没联起来跑过」。单测只能证明
// filterWhitelisted 这个纯函数是对的，证明不了「叶子改的东西真的会经过它、
// 主机真的只广播勾上的那几项」。

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { NetManager } from "./manager";
import { parseAnyPairingCode } from "./pairingCode";
import type { ConfigPush, SyncField } from "./protocol";
import { setNetSecret, isNetEnabled } from "./secure";

// 这个文件只关心**配置同步**这一条链路，故意在全局预置一把密钥：
// 这样主机不必自签、叶子也不必走配对期领取（enroll），直接用同一把密钥握手，
// 把被测对象（白名单过滤 / 广播下发）从密钥分发里隔离出来。
// 密钥分发本身由 enroll.integration.spec.ts 专门守。
setNetSecret("kirari-net-package-test-only-secret");

const tmpDirs: string[] = [];
const managers: NetManager[] = [];

function tmpDir(tag: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), `kirari-net-${tag}-`));
    tmpDirs.push(dir);
    return dir;
}

function track<T extends NetManager>(m: T): T {
    managers.push(m);
    return m;
}

/** 轮询等条件成立，避免写死 sleep */
async function waitFor(cond: () => boolean, timeoutMs = 8000, step = 50): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (cond()) return true;
        await new Promise((r) => setTimeout(r, step));
    }
    return cond();
}

afterEach(async () => {
    while (managers.length) {
        try {
            managers.pop()!.dispose();
        } catch {
            /* 关不掉就算了 */
        }
    }
    // 端口固定 19760，而 ws server 的 close 是异步的 —— 不等它真正释放，
    // 下一个用例 startHosting 就会抢不到端口，表现为「叶子连不上」的假失败。
    await new Promise((r) => setTimeout(r, 1000));
    while (tmpDirs.length) {
        const dir = tmpDirs.pop()!;
        try {
            fs.rmSync(dir, { recursive: true, force: true });
        } catch {
            /* 临时目录清不掉不影响结果 */
        }
    }
});

describe("组网配置同步（真实两端）", () => {
    it("前置条件：测试密钥已注入，组网功能是启用的", () => {
        expect(isNetEnabled()).toBe(true);
    });

    it("叶子能通过连接码接进来", async () => {
        const host = track(new NetManager(tmpDir("host")));
        const started = await host.startHosting();
        expect(started.ok).toBe(true);

        const text = host.serializePairing(host.issuePairing());
        // 默认签发的就是**邀请码**（kirari://join）：不需要对方事先有密钥，
        // 手上没有密钥的机器因此也能接进来（配对期现领，见 enroll.ts）。
        expect(text.startsWith("kirari://join?d=")).toBe(true);

        const leaf = track(new NetManager(tmpDir("leaf")));
        const joined = await leaf.startFollowing(text);
        expect(joined.ok).toBe(true);

        expect(await waitFor(() => leaf.snapshot().leafStatus === "connected")).toBe(true);
        expect(await waitFor(() => host.snapshot().members.some((m) => m.online))).toBe(true);
    }, 15000);

    it("连接码里的地址可以显式指定（多网卡 / 容器部署必需）", async () => {
        const host = track(new NetManager(tmpDir("host")));
        // 自动猜是「取第一个私有网段地址」：多网卡机器上常猜错，
        // 容器桥接网络里更是必错（猜到容器内网地址，对方根本连不上）。
        host.setAdvertiseHost("10.20.30.40");
        expect((await host.startHosting()).ok).toBe(true);

        const parsedAny = parseAnyPairingCode(host.serializePairing(host.issuePairing()));
        expect(parsedAny?.kind).toBe("invite");
        const parsed = parsedAny?.code;
        expect(parsed?.host).toBe("10.20.30.40");
        expect(parsed?.port).toBe(19760);
        // 界面上展示的地址也要跟着走，否则用户看到 A、实际连的是 B
        expect(host.snapshot().address).toBe("10.20.30.40");
    }, 15000);

    it("主机改配置 → 只有白名单内的字段下发到叶子", async () => {
        const pushes: ConfigPush[] = [];
        const host = track(new NetManager(tmpDir("host")));
        expect((await host.startHosting()).ok).toBe(true);
        // 只让「大脑型号」跟随主机，连接地址各管各的
        host.setSyncWhitelist(["model"]);

        const leaf = track(
            new NetManager(tmpDir("leaf"), { onConfigPush: (f) => pushes.push(f) }),
        );
        await leaf.startFollowing(host.serializePairing(host.issuePairing()));
        expect(await waitFor(() => leaf.snapshot().leafStatus === "connected")).toBe(true);

        pushes.length = 0; // 丢掉接入时的历史帧
        host.notifyLocalConfigChanged({
            model: "gpt-from-host",
            endpoint: "https://host-only.example/v1",
        });

        expect(await waitFor(() => pushes.length > 0)).toBe(true);
        const patch = pushes[pushes.length - 1].patch;
        expect(patch.model).toBe("gpt-from-host");
        expect(patch.endpoint).toBeUndefined();
    }, 15000);

    it("没勾的字段根本不进网络 —— 叶子改了也白改", async () => {
        const pushes: ConfigPush[] = [];
        const hostApplied: Partial<Record<SyncField, string>> = {};

        const host = track(
            new NetManager(tmpDir("host"), {
                onConfigChanged: (patch) => Object.assign(hostApplied, patch),
            }),
        );
        await host.startHosting();
        host.setSyncWhitelist(["model"]);

        const leaf = track(
            new NetManager(tmpDir("leaf"), { onConfigPush: (f) => pushes.push(f) }),
        );
        await leaf.startFollowing(host.serializePairing(host.issuePairing()));
        expect(await waitFor(() => leaf.snapshot().leafStatus === "connected")).toBe(true);

        pushes.length = 0;
        // 叶子改了两项：勾了的和没勾的
        leaf.notifyLocalConfigChanged({
            model: "gpt-from-leaf",
            endpoint: "https://leaf-only.example/v1",
        });

        expect(await waitFor(() => pushes.length > 0)).toBe(true);
        const patch = pushes[pushes.length - 1].patch;
        expect(patch.model).toBe("gpt-from-leaf");
        expect(patch.endpoint).toBeUndefined();
        // 主机侧也只应用了勾上的那项
        expect(hostApplied.model).toBe("gpt-from-leaf");
        expect(hostApplied.endpoint).toBeUndefined();
    }, 15000);

    it("白名单调完立刻生效，不用等叶子重连", async () => {
        const pushes: ConfigPush[] = [];
        const host = track(new NetManager(tmpDir("host")));
        expect((await host.startHosting()).ok).toBe(true);

        const leaf = track(
            new NetManager(tmpDir("leaf"), { onConfigPush: (f) => pushes.push(f) }),
        );
        await leaf.startFollowing(host.serializePairing(host.issuePairing()));
        expect(await waitFor(() => leaf.snapshot().leafStatus === "connected")).toBe(true);

        // 先只同步 model：改 endpoint 不应该有任何下发
        host.setSyncWhitelist(["model"]);
        pushes.length = 0;
        host.notifyLocalConfigChanged({ endpoint: "https://a.example/v1" });
        await new Promise((r) => setTimeout(r, 500));
        expect(pushes).toHaveLength(0);

        // 现在把 endpoint 也勾上，同样一次改动就该过来了
        host.setSyncWhitelist(["model", "endpoint"]);
        pushes.length = 0;
        host.notifyLocalConfigChanged({ endpoint: "https://b.example/v1" });
        expect(await waitFor(() => pushes.length > 0)).toBe(true);
        expect(pushes[pushes.length - 1].patch.endpoint).toBe("https://b.example/v1");
    }, 15000);
});
