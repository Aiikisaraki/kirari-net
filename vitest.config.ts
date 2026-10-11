import { defineConfig } from "vitest/config";

// 本包的自测。
//
// 组网层是桌面端与核心版**共用**的实现，测试跟着代码走 —— 留在一侧的话，
// 另一侧的用法就完全没有验证。
//
// 不需要在这里注入密钥：密钥已改成显式注入（见 src/secure.ts），
// 测试文件里自己调 setNetSecret() 就行，不再依赖「env 必须早于模块加载」那种时序技巧。
export default defineConfig({
    test: {
        // 全部是主进程/服务端代码（node:fs、crypto、ws），没有 DOM。
        environment: "node",
        include: ["src/**/*.spec.ts"],
        // 组网端到端要真起 WebSocket、走握手+加密，比普通单测慢。
        testTimeout: 15000,
        // ⚠️ 必须关掉「多文件并行」：端到端用例都真的起 ws server，而端口是
        //    固定 19760（协议的一部分，不能改成随机端口）。并行跑必然互相抢端口，
        //    表现为随机报「地址已被占用」或「叶子连不上」的假失败。
        //    单测文件互相独立，关掉并行只多花一点时间，换来的是确定性。
        fileParallelism: false,
    },
});
