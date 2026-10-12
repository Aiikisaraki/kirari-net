// @vitest-environment node
//
// 配对期下发密钥（enroll）的验证。
//
// 验的是这个能力解决了什么：一台手上**完全没有密钥**的机器
// （docker 起的核心版、从源码跑起来的第二个实例），只凭一张邀请码
// 就能接进一个网 —— 源码里没有密钥、构建产物里没有密钥、用户也没碰过密钥。
//
// ⚠️ 写这类测试有个绕不开的坑，先记在这里，免得下次又踩：
//    vitest 是**单进程**，主机侧与叶子侧共用同一个模块级密钥（src/secure.ts 的
//    let netSecret）。所以「用 setNetSecret("") 模拟一台没密钥的新机器」是**错的** ——
//    它会把正在当主机的那个实例也一起清空，于是主机的 handleEnroll 第一道闸就把它
//    挡掉（日志：拒绝密钥下发：这台主机还没开组网），用例全挂，而且看起来像
//    功能坏了。真实部署里两端是两个进程，不存在这个问题。
//    正确写法：
//      · 「无密钥」只在本用例**还没起主机之前**断言（那时全局确实是空的）
//      · 「重启后密钥还在」不靠清全局，改成直接读/写 net-state.json 的纯状态测试
//
// 三条必须守住：
//   1. 邀请码本身**不含**密钥；机器在配对那一刻才领到，并且上行链路真的通
//   2. 接过一次之后，重启用学到的密钥自动接续 —— 否则每次重启都要重新贴码
//   3. 一次性口令作废后，密钥**一个字节都不给** —— 这是唯一发放密钥的口子

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { NetManager } from "./manager";
import { getNetSecret, isNetEnabled, setNetSecret } from "./secure";

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
    // 端口固定 19760，ws server 的 close 是异步的 —— 不等它释放，
    // 下一个用例抢不到端口会伪装成「叶子连不上」的假失败。
    await new Promise((r) => setTimeout(r, 1000));
    while (tmpDirs.length) {
        const dir = tmpDirs.pop()!;
        try {
            fs.rmSync(dir, { recursive: true, force: true });
        } catch {
            /* 清不掉不影响结果 */
        }
    }
});

const echoExecutor = async ({ content, deviceId }: { content: string; deviceId: string }) => ({
    speech: `主机回声[${deviceId.slice(0, 6)}]：${content}`,
    emotion: "happy",
});

function hostHasOnlineLeaf(host: NetManager): boolean {
    return host.snapshot().members.some((m) => m.online);
}

/** 直接把一个 net-state.json 摆到目录里 —— 用来复现「这台机器上次运行过」的状态。 */
function writeNetState(dir: string, patch: Record<string, unknown>): void {
    fs.writeFileSync(path.join(dir, "net-state.json"), JSON.stringify(patch, null, 2), "utf8");
}

describe("配对期下发密钥（真实两端）", () => {
    it("一把密钥都没有的机器：开组网就自签一把；贴邀请码的机器在配对期领到钥匙并真的通上行", async () => {
        // 起点：全局也没有密钥 —— 等价于「从仓库 clone 下来直接跑」的核心版
        setNetSecret("");
        expect(isNetEnabled()).toBe(false);

        const hostLogs: string[] = [];
        const host = track(new NetManager(tmpDir("host"), { onLog: (m) => hostLogs.push(m) }));
        host.attachHostExecutor(echoExecutor);
        expect((await host.startHosting()).ok).toBe(true);

        // 自己签了一把：没有从任何地方读来，就是本机的随机数
        expect(isNetEnabled()).toBe(true);
        const hostSecret = getNetSecret();
        expect(hostSecret.length).toBeGreaterThanOrEqual(16);
        expect(hostLogs.some((l) => l.includes("已自动签发"))).toBe(true);

        const invite = host.serializePairing(host.issuePairing());
        expect(invite.startsWith("kirari://join?d=")).toBe(true);
        // 邀请码里没有密钥明文 —— 这是「密钥可以完全不给用户看见」的前提
        expect(invite.includes(hostSecret)).toBe(false);

        const leafLogs: string[] = [];
        const leaf = track(new NetManager(tmpDir("leaf"), { onLog: (m) => leafLogs.push(m) }));
        expect((await leaf.startFollowing(invite)).ok).toBe(true);
        expect(await waitFor(() => hostHasOnlineLeaf(host))).toBe(true);

        // 两个可观测的实锤：主机侧「下发了」、叶子侧「领到了」
        // （不这么验的话，叶子可能只是靠全局残留的密钥蒙混过关）
        expect(hostLogs.some((l) => l.includes("下发组网密钥"))).toBe(true);
        expect(leafLogs.some((l) => l.includes("已拿到组网密钥"))).toBe(true);
        // 领到的就是主机那把
        expect(getNetSecret()).toBe(hostSecret);

        // 上行真的通 —— 不是「显示连上」而已
        const out = await leaf.relayAndWait("在吗", "s1", { timeoutMs: 8000 });
        expect(out.ok).toBe(true);
        if (out.ok) expect(out.frame.speech).toContain("在吗");
    }, 30000);

    it("邀请码被撤销后：一个字节的密钥都不给，这台机器只能退回独立工作", async () => {
        setNetSecret("");
        const host = track(new NetManager(tmpDir("host"), { onLog: () => {} }));
        host.attachHostExecutor(echoExecutor);
        expect((await host.startHosting()).ok).toBe(true);

        const invite = host.serializePairing(host.issuePairing());
        // 主人把这张码作废了
        host.revokePairingCode(host.snapshot().pairings[0].id);

        const leafLogs: string[] = [];
        const leaf = track(new NetManager(tmpDir("leaf-denied"), { onLog: (m) => leafLogs.push(m) }));
        const joined = await leaf.startFollowing(invite);
        expect(joined.ok).toBe(false);
        if (!joined.ok) expect(joined.error).toContain("撤销");
        // 叶子侧明确说了「拿不到密钥」，并且退回独立工作（没留下半截状态）
        expect(leafLogs.some((l) => l.includes("拿不到密钥"))).toBe(true);
        expect(leaf.snapshot().role).toBe("off");
    }, 30000);

    it("重启（同一个目录重建实例）后直接接回主机，不用再贴码", async () => {
        setNetSecret("");
        const host = track(new NetManager(tmpDir("host"), { onLog: () => {} }));
        host.attachHostExecutor(echoExecutor);
        expect((await host.startHosting()).ok).toBe(true);

        const leafDir = tmpDir("leaf-restart");
        const first = track(new NetManager(leafDir, { onLog: () => {} }));
        expect((await first.startFollowing(host.serializePairing(host.issuePairing()))).ok).toBe(true);
        expect(await waitFor(() => hostHasOnlineLeaf(host))).toBe(true);
        first.dispose();
        expect(await waitFor(() => !hostHasOnlineLeaf(host))).toBe(true);

        // ⚠️ 这里**不能** setNetSecret("")：那会把还在跑的主机也清空。
        //    第二个实例该靠文件里的 enrolledSecret 自己认回密钥（另见下面的纯状态用例）。
        const second = track(new NetManager(leafDir, { onLog: () => {} }));
        expect(second.resumeFollowing().ok).toBe(true);
        expect(await waitFor(() => hostHasOnlineLeaf(host))).toBe(true);

        const out = await second.relayAndWait("还在吗", "s2", { timeoutMs: 8000 });
        expect(out.ok).toBe(true);
    }, 30000);
});

describe("密钥的来与去（纯状态，不起网络）", () => {
    it("重启后从 net-state.json 认回密钥：自己签的、从主机学来的都认", () => {
        // 自己签的那把（本机当主机时产生的）
        const ownDir = tmpDir("restore-own");
        const own = "1111222233334444555566667777888899990000";
        writeNetState(ownDir, { role: "host", ownSecret: own });
        setNetSecret(""); // 环境里什么都没有 —— 能认回来说明值确实来自文件
        track(new NetManager(ownDir, { onLog: () => {} }));
        expect(getNetSecret()).toBe(own);

        // 从主机学来的那把：优先级更高，压过自己签的
        const enrolledDir = tmpDir("restore-enrolled");
        const enrolled = "aaaabbbbccccddddeeeeffff00001111";
        writeNetState(enrolledDir, { role: "leaf", ownSecret: own, enrolledSecret: enrolled });
        setNetSecret("");
        track(new NetManager(enrolledDir, { onLog: () => {} }));
        expect(getNetSecret()).toBe(enrolled);
    });

    it("「移除自己」之后重启，不会再悄悄绑回那个网", () => {
        const dir = tmpDir("leave");
        const thatNet = "0123456789abcdef0123456789abcdef";
        const mine = "fedcba9876543210fedcba9876543210";
        writeNetState(dir, {
            role: "leaf",
            ownSecret: mine,
            enrolledSecret: thatNet,
            hostAddress: "127.0.0.1",
            hostPort: 19760,
            credential: "cred-from-that-net",
        });

        setNetSecret(thatNet); // 此刻正身处那个网
        const mgr = track(new NetManager(dir, { onLog: () => {} }));
        expect(getNetSecret()).toBe(thatNet);

        mgr.leaveHost();
        // 退回本机自己签的那把，不再用那个网的
        expect(getNetSecret()).toBe(mine);
        expect(mgr.snapshot().role).toBe("off");

        // ⚠️ 关键：文件里也不能再留着。只清内存是不够的 ——
        //    下次重启构造函数会把它读回来，用户以为退出了、实际又被绑回去。
        const saved = JSON.parse(fs.readFileSync(path.join(dir, "net-state.json"), "utf8"));
        expect(saved.enrolledSecret).toBeUndefined();
        expect(saved.credential).toBeUndefined();

        // 重启后确实回不去：凭据已清，只能重新贴码
        setNetSecret(mine);
        const restarted = track(new NetManager(dir, { onLog: () => {} }));
        expect(restarted.resumeFollowing().ok).toBe(false);
    });
});
