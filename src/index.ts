// kirari-net · 组网层公共入口
//
// 这一层被**两个仓库共用**（ARCHITECTURE-PLAN §1.2 的硬约束：能力对等，
// 桌面端与核心版都能当主机、都能当叶子，不因产品形态分叉）：
//   - kirari-desktop  桌面桌宠（vite 打包进 Electron 主进程）
//   - kirari-core     服务器机器人核心运行时（纯 CJS，直接 require）
//
// ⚠️ 本层**不得 import electron** —— 一旦引入，核心版就用不了了。
//    Electron 专属的接线（IPC / 二维码渲染）留在桌面端自己的 electron/net/ipc.ts。
//
// 密钥注入：见 secure.ts 的 setNetSecret()。这里不做任何「编译期魔法」，
// 因为本包是**预先编译**的产物，打包器的 define 够不到（详见 secure.ts 的说明）。

export * from "./protocol";
export * from "./secure";
export * from "./pairingCode";
export * from "./identity";
export * from "./netStore";
export * from "./relayRouter";
export * from "./hostServer";
export * from "./leafClient";
export * from "./manager";
