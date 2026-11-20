// @vitest-environment node
//
// 阶段 5：远程工具执行（MCP / skill）的**端到端**验证。
//
// 真的起一个主机、真的让叶子通过连接码接进来，走完
//   能力上报 → 主机点名调用 → 叶子本地执行 → 结果回传 → 主机拿到结果
// 的全过程。
//
// 为什么必须端到端：MCP 与 skill 的配置存在**各节点本地**（也刻意不同步），
// 所以"让书房那台电脑用它自己的技能"只能靠这条链路。单测能证明 callToolOnDevice
// 的方法体是对的，但证明不了帧真的发出去、对端真的收到、callId 真的能对上。
//
// 这里要守住的不变量：
//   1. 叶子连上后主机会收到它的工具能力清单（否则模型无从知道点名什么）
//   2. 一次调用一次回执，callId 精确配对（并发时不串）
//   3. 叶子**无论成功失败都必须回 tool_result**（不回主机只能等超时，
//      而超时无法区分「工具报错」和「设备掉线」）
//   4. 超时/掉线的情况必须给出明确错误，不能永远悬着
//   5. 组网退出时把未完成的调用全部结清（否则调用方永远 await）

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { NetManager } from "./manager";
import type { ToolCapsReport, ToolCall } from "./protocol";
import { setNetSecret } from "./secure";

// 与本仓其它集成测试一致：预置一把密钥，把被测对象从密钥分发里隔离出来
// （密钥分发由 enroll.integration.spec.ts 专门守）。
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
    // 端口固定，ws server 的 close 是异步的——不等它释放，下个用例会抢不到端口。
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

/** 起一对已连上的 host/leaf，并等叶子进 connected。 */
async function connectPair(leafEvents: Parameters<typeof NetManager>[1] = {}) {
    const host = track(new NetManager(tmpDir("host")));
    expect((await host.startHosting()).ok).toBe(true);
    const leaf = track(new NetManager(tmpDir("leaf"), leafEvents));
    await leaf.startFollowing(host.serializePairing(host.issuePairing()));
    expect(await waitFor(() => leaf.snapshot().leafStatus === "connected")).toBe(true);
    // 等主机侧把成员标成在线（callToolOnDevice 会检查这个）
    expect(await waitFor(() => host.snapshot().members.some((m) => m.online))).toBe(true);
    return { host, leaf };
}

describe("阶段 5 · 远程工具执行（真实两端）", () => {
    it("叶子连上后能上报工具能力，主机侧可查", async () => {
        const reports: ToolCapsReport[] = [];
        const { host, leaf } = await connectPair();

        // 主机侧监听能力上报
        // （NetManagerEvents 上的 onToolCaps，不是底层 hostServer）
        const hostMgr: any = host;
        expect(typeof leaf.reportToolCaps).toBe("function");

        const caps = {
            mcpServers: ["filesystem", "github"],
            skills: ["demo-skill"],
            toolNames: [
                { name: "filesystem__read_file", source: "mcp" as const, owner: "filesystem" },
                { name: "skill__demo-skill__run", source: "skill" as const, owner: "skill" },
            ],
        };
        leaf.reportToolCaps(caps);

        // 主机侧：能力清单最终会存进 manager 的 toolCaps
        const got = await waitFor(() => !!hostMgr.toolCapsOf(leaf.snapshot().deviceId));
        expect(got).toBe(true);
        const stored = hostMgr.toolCapsOf(leaf.snapshot().deviceId);
        expect(stored.mcpServers).toEqual(["filesystem", "github"]);
        expect(stored.skills).toEqual(["demo-skill"]);
        expect(reports).toEqual([]); // 没用到底层事件，占位说明
    }, 20000);

    it("主机 → 叶子：一次调用一次回执，结果能回来", async () => {
        const seen: ToolCall[] = [];
        const { host, leaf } = await connectPair({
            onToolCall: (frame) => {
                seen.push(frame);
                // 叶子侧：不管是本地 MCP 还是 skill，最终都要回 tool_result
                leaf.replyToolResult({
                    callId: frame.callId,
                    ok: true,
                    result: `在叶子上跑完了 ${frame.name}`,
                });
            },
        });

        expect(await waitFor(() => host.snapshot().members.some((m) => m.online))).toBe(true);
        const deviceId = leaf.snapshot().deviceId;

        const out = await host.callToolOnDevice(deviceId, "filesystem__read_file", {
            path: "/tmp/a.txt",
        });

        expect(out.ok).toBe(true);
        expect(out.result).toContain("在叶子上跑完了 filesystem__read_file");
        expect(out.deviceId).toBe(deviceId);
        // 帧里带上了参数（叶子侧要能拿到真正要跑的东西）
        expect(seen.length).toBe(1);
        expect(seen[0].name).toBe("filesystem__read_file");
        expect(seen[0].args).toEqual({ path: "/tmp/a.txt" });
    }, 20000);

    it("叶子执行失败也会回执：错误原因能传回主机（不是超时）", async () => {
        const { host, leaf } = await connectPair({
            onToolCall: (frame) => {
                if (!frame.callId) return;
                leaf.replyToolResult({
                    callId: frame.callId,
                    ok: false,
                    error: "那台机器上没有这个工具",
                });
            },
        });
        expect(await waitFor(() => host.snapshot().members.some((m) => m.online))).toBe(true);

        const started = Date.now();
        const out = await host.callToolOnDevice(
            leaf.snapshot().deviceId,
            "nonexistent__tool",
            {},
        );
        expect(out.ok).toBe(false);
        expect(out.error).toContain("那台机器上没有这个工具");
        // 关键：立刻失败而不是等到超时。等到超时说明回执丢了。
        expect(Date.now() - started).toBeLessThan(5000);
    }, 20000);

    it("并发调用按 callId 精确配对，结果不串", async () => {
        const { host, leaf } = await connectPair({
            onToolCall: (frame) => {
                if (!frame.callId) return;
                // 故意让先到的调用后回：验证按 callId 配对，而不是按先来后到
                const payload = frame.args as { tag: string };
                const delay = payload.tag === "first" ? 120 : 10;
                setTimeout(() => {
                    leaf.replyToolResult({
                        callId: frame.callId,
                        ok: true,
                        result: `结果-${payload.tag}`,
                    });
                }, delay);
            },
        });
        expect(await waitFor(() => host.snapshot().members.some((m) => m.online))).toBe(true);
        const deviceId = leaf.snapshot().deviceId;

        const [a, b] = await Promise.all([
            host.callToolOnDevice(deviceId, "tool_a", { tag: "first" }),
            host.callToolOnDevice(deviceId, "tool_b", { tag: "second" }),
        ]);

        expect(a.result).toBe("结果-first");
        expect(b.result).toBe("结果-second");
    }, 20000);

    it("叶子不回执时按超时失败，并给出可读原因", async () => {
        const { host, leaf } = await connectPair({
            // 故意什么都不回：模拟叶子侧执行器卡死/没装
            onToolCall: () => {},
        });
        expect(await waitFor(() => host.snapshot().members.some((m) => m.online))).toBe(true);

        const out = await host.callToolOnDevice(
            leaf.snapshot().deviceId,
            "slow_tool",
            {},
            { timeoutMs: 400 },
        );
        expect(out.ok).toBe(false);
        expect(String(out.error)).toMatch(/超时|timeout/i);
    }, 20000);

    it("设备不在线/不存在时不发帧，直接给明确错误", async () => {
        const { host } = await connectPair();

        const missing = await host.callToolOnDevice("no-such-device-id", "some_tool", {});
        expect(missing.ok).toBe(false);
        expect(String(missing.error).length).toBeGreaterThan(0);

        // 空参数也要拒绝，而不是发一个没人能处理的帧
        const emptyName = await host.callToolOnDevice("whatever", "", {});
        expect(emptyName.ok).toBe(false);
    }, 20000);

    it("非主机角色调用远程工具会被拒绝（不冒充主机）", async () => {
        const { leaf } = await connectPair();
        const out = await leaf.callToolOnDevice("any-device", "any_tool", {});
        expect(out.ok).toBe(false);
        expect(String(out.error)).toMatch(/主机|host/i);
    }, 20000);
});
