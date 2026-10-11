// @vitest-environment node
//
// 上行链路 + 重连的**端到端**验证：真的起主机、真的让叶子接进来，
// 走完 叶子 → 加密 → 主机 → 执行器 → 广播回叶子 的全过程。
//
// 为什么要单独一个文件、而不是并进配置同步那份：
//   这里验的是「请求-响应」这条链路本身，以及**重连之后还通不通**。
//
// 重连那一条是踩过的 bug 的回归防线：
//   主机侧的重放窗口一度按 deviceId 存，重连时复用上一轮的窗口，而叶子每次重连
//   都把加密帧序号从 0 重新开始 —— 于是重连后第 1 帧就被判成「重放」静默丢弃。
//   症状极具迷惑性：握手是明文所以照常成功，日志里还能看到「密钥协商完成」，
//   但之后所有加密帧石沉大海，表现为「显示已连上，发什么都不回」。
//   单测测不出来（ReplayGuard 本身是对的，错的是它的**生命周期**）。

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { NetManager } from "./manager";
import { setNetSecret } from "./secure";

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
    // 端口固定 19760，ws server 的 close 是异步的 —— 不等它真正释放，
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

/** 主机侧执行器：不调模型，只回声 —— 验的是链路是否打通，不是模型有没有回话。 */
const echoExecutor = async ({ content, deviceId }: { content: string; deviceId: string }) => ({
    speech: `主机回声[${deviceId.slice(0, 6)}]：${content}`,
    emotion: "happy",
});

/** 主机侧是不是已经把某台设备算成在线。 */
function hostHasOnlineLeaf(host: NetManager): boolean {
    return host.snapshot().members.some((m) => m.online);
}

describe("上行链路（真实两端）", () => {
    it("叶子提问 → 主机执行器 → 回复按 requestId 回到提问方", async () => {
        const host = track(new NetManager(tmpDir("host")));
        host.attachHostExecutor(echoExecutor);
        expect((await host.startHosting()).ok).toBe(true);

        const leaf = track(new NetManager(tmpDir("leaf")));
        const joined = await leaf.startFollowing(host.serializePairing(host.issuePairing()));
        expect(joined.ok).toBe(true);
        expect(await waitFor(() => hostHasOnlineLeaf(host))).toBe(true);

        const out = await leaf.relayAndWait("在吗", "s1", undefined, 8000);
        expect(out.ok).toBe(true);
        if (out.ok) {
            expect(out.frame.speech).toContain("在吗");
            expect(out.frame.sessionId).toBe("s1");
        }
    }, 25000);

    it("叶子重启后用长期凭据重连，上行仍然通", async () => {
        const host = track(new NetManager(tmpDir("host")));
        host.attachHostExecutor(echoExecutor);
        expect((await host.startHosting()).ok).toBe(true);

        // 叶子与主机各用一个状态目录；「重启」= 关掉旧的、用**同一个目录**重建
        const leafDir = tmpDir("leaf-node");
        const first = track(new NetManager(leafDir));
        const joined = await first.startFollowing(host.serializePairing(host.issuePairing()));
        expect(joined.ok).toBe(true);
        expect(await waitFor(() => hostHasOnlineLeaf(host))).toBe(true);

        // 先确认第一次接入是通的 —— 否则这个用例证明不了「重连坏了」，
        // 只证明了「本来就没通」。
        const before = await first.relayAndWait("第一轮", "s1", undefined, 8000);
        expect(before.ok).toBe(true);

        // ── 模拟进程重启 ──
        first.dispose();
        expect(await waitFor(() => !hostHasOnlineLeaf(host))).toBe(true);

        const second = track(new NetManager(leafDir));
        expect(second.resumeFollowing().ok).toBe(true);

        // ⚠️ 判据必须放在**主机侧**「认没认下这台设备」。
        //    不能只看叶子自己的状态：握手是明文，叶子一收到 hello_ack 就把自己
        //    标成 connected 了，后面 pair 被丢掉它根本看不出来 ——
        //    这正是当初这个 bug 能一路瞒过日志的原因。
        expect(await waitFor(() => hostHasOnlineLeaf(host))).toBe(true);

        const after = await second.relayAndWait("重启后还在吗", "s1", undefined, 8000);
        expect(after.ok).toBe(true);
        if (after.ok) expect(after.frame.speech).toContain("重启后还在吗");
    }, 30000);
});
