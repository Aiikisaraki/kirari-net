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
// 密钥：本层**不含任何密钥**，两端也不预置。
//   谁要用谁在运行时拿到 —— 当主机就自己签一把（NetManager 默认自动签发），
//   当叶子就凭一张邀请码在配对那一刻向主机领（enroll）。详见 secure.ts。
//   两个宿主都不需要写密钥相关的代码，接上 NetManager 即可。
//   唯一例外是测试：它用 setNetSecret() 显式塞一把，把密钥分发本身隔离掉。

export * from "./protocol";
export * from "./secure";
export * from "./pairingCode";
export * from "./identity";
export * from "./netStore";
export * from "./relayRouter";
export * from "./hostServer";
export * from "./leafClient";
export * from "./manager";
