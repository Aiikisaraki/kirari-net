# kirari-net

Kirari 的**组网层**：让多台设备共用一个「大脑」。

与 `kirari-desktop`（桌宠）、`kirari-core`（机器人运行时）**平级**，三个仓库各自独立发版。
本包不含任何 Electron 代码，也不依赖任何 AI 引擎 —— 执行器由宿主注入。

```
叶子 A ─┐
叶子 B ─┼─→ 主机（全网唯一出口，排队 + 限流）─→ 大模型
叶子 C ─┘        └─→ 一份结果广播给全网
```

## 为什么是独立包

架构方案 §1.2 把「能力对等」列为硬约束：
「桌面版和核心版都能当主机，也都能当叶子」「任一侧若只能当一种角色即为设计缺陷；
两侧共用同一套组网代码」。抽成一个包就是这条约束的落地方式 ——
协议、加密、配对、路由只有一份，改一处两端同时受益。

**不要在本包里 import electron。** 宿主的胶水（IPC、窗口、配置读写）留在各宿主里：
桌面端在 `kirari-desktop/electron/net/ipc.ts` + `electron/net-secret.ts`，
核心版在 `kirari-core/src/net/bootstrap.js`。

## 装法

本地开发用平级目录（三个仓库放在同一个父目录下）：

```json
{ "dependencies": { "kirari-net": "file:../kirari-net" } }
```

⚠️ `npm ci` 对 `file:` 依赖**不校验目标是否存在** —— 目标目录缺了只会在 `node_modules`
里留一个悬空软链，安装日志一切正常，启动时才 `MODULE_NOT_FOUND`。
所以安装脚本/CI 里请自己补一次真实的 `require("kirari-net")` 自检。

## 用法

```ts
import { NetManager, setNetSecret, NET_PORT } from "kirari-net";

// 1) 密钥：显式注入。**不要**指望打包器的 define —— 见 src/secure.ts 的说明。
setNetSecret(process.env.KIRARI_NET_SECRET);   // 空串 = 没密钥 = 组网整体禁用

// 2) 造一个实例：目录由宿主给（桌面端 userData / 核心版 data/net）
const net = new NetManager(userDataDir, { onLog: (m) => console.log(m) });

// 3) 主机：注入「本机大脑」，当全网唯一出口
net.attachHostExecutor(async ({ content, sessionId, deviceId }) => ({ speech: "…" }));
net.setAdvertiseHost(process.env.NET_ADVERTISE_HOST);  // 容器/多网卡必填
const { code } = await net.startHosting();

// 4) 叶子：拿主机给的连接码接入（首次），之后 resumeFollowing() 即可自动重连
await net.startFollowing(pairingText);
// 或 net.resumeFollowing();

// 5) 服务端形态的叶子：上行并按 requestId 等自己那一条回包
const out = await net.relayAndWait(content, sessionId, images, 45_000);
if (out.ok) { /* out.frame.speech / out.frame.emotion */ }
```

## 组成

| 文件 | 职责 |
| --- | --- |
| `protocol.ts` | 帧格式、端口 `19760`、心跳 2s / 超时 5s、`SeqTracker`。**不 import electron** |
| `secure.ts` | 密钥注入、`scrypt` 派生会话密钥、AES-256-GCM 封解帧、`ReplayGuard` |
| `identity.ts` | `deviceId`：随机生成、持久化、**不含硬件指纹** |
| `pairingCode.ts` | 连接码生成/解析/过期。密文形态 `kirari://connect?d=...`，**只存哈希** |
| `netStore.ts` | `net-state.json`：角色、地址、凭据、配对码、白名单 |
| `hostServer.ts` | 主机：监听、握手、鉴权、成员、广播。**每连接一份加密材料** |
| `leafClient.ts` | 叶子：连接、心跳、断线回退、上行、离线补传 |
| `relayRouter.ts` | 活锁路由：排队 + 限流 + 单份回复广播。**不依赖 AI 引擎** |
| `manager.ts` | 门面：把上面这些串成一条可用链路 |

## 几条容易踩的

- **重放窗口必须按连接重置**。叶子每次重连都把加密帧序号从 0 重来；窗口若按设备复用，
  重连后的第一帧就会被判成「重放」静默丢弃 —— 握手照常成功（明文），
  之后所有加密帧石沉大海。回归用例守着这条（见下）。
- **`seal` 里带的 `_s` 序号放在密文内部**：GCM 能挡篡改，挡不住重发，所以需要它。
- **`SeqTracker` 只去重、不乱序丢弃**。曾实现成「只接受递增 seq」，并发时完成顺序 ≠ seq 顺序，
  会真的把用户该看到的回复丢掉。顺序交给上层排，丢消息比顺序乱严重得多。
- **退出组网只改 role**，地址/凭据/配对码全留 —— 重开开关即可自动归位。
- **密钥 <16 位即视为未配置**；`.env` 里的值含 `#` 会被 dotenv 当行内注释截断，从而被静默禁用。

## 开发

```bash
npm run build      # tsc → dist/（宿主引的是 dist，不是 src）
npm run typecheck  # 两份 tsconfig（含测试）
npm test           # vitest
```

`src/relay.integration.spec.ts` 会**真的起一个主机、真的让叶子接进来**，走完
握手 → 加密 → 上行 → 广播，其中「叶子重启后用长期凭据重连仍能上行」是一条回归防线
（单测测不出它 —— `ReplayGuard` 本身是对的，错的是它的生命周期）。

⚠️ 端到端用例都占固定端口 **19760**，所以 `vitest.config.ts` 里必须保持
`fileParallelism: false`，否则文件并行会互相抢端口。

## 安全边界

能挡住：局域网里扫端口试探的陌生设备、蹭网抓包偷看对话的人
（密钥本身不上网络，握手后全部加密 + 防重放）。
**挡不住**：拿到程序并解包提取出密钥的人 —— 密钥必然在产物里。
即防「随手接入」，不防「定向破解」。
