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
桌面端在 `kirari-desktop/electron/net/ipc.ts`，核心版在 `kirari-core/src/net/bootstrap.js`。
两边都**不碰密钥** —— 那是本层的事。

## 装法

本地开发用平级目录（三个仓库放在同一个父目录下）：

```json
{ "dependencies": { "kirari-net": "file:../kirari-net" } }
```

⚠️ `npm ci` 对 `file:` 依赖**不校验目标是否存在** —— 目标目录缺了只会在 `node_modules`
里留一个悬空软链，安装日志一切正常，启动时才 `MODULE_NOT_FOUND`。
所以安装脚本/CI 里请自己补一次真实的 `require("kirari-net")` 自检。

## 密钥：没有「配置密钥」这一步

两端的地位完全一样，谁也不带密钥出厂。密钥只有两个来源，都在运行时产生：

| 本机角色 | 密钥从哪来 | 落在哪 |
| --- | --- | --- |
| 当主机 | 第一次开组网时**自己签一把** | 自己的 `net-state.json` 的 `ownSecret` |
| 当叶子 | 贴邀请码，**配对那一刻**由主机加密发过来（enroll） | `net-state.json` 的 `enrolledSecret` |

于是同一个安装包发出去，是十个互不相通、也互不可见的网 —— 源码、构建产物、CI、
`.env`、配置文件里都**没有**密钥可泄漏。想彻底禁掉组网能力的发行版，
显式调 `setAutoProvisionSecret(false)` 即可。

优先级（定死）：`enrolledSecret`（主动加入过的网，意图最明确）> 宿主已装上的 > `ownSecret`。

## 用法

```ts
import { NetManager } from "kirari-net";

// 1) 造一个实例：目录由宿主给（桌面端 userData / 核心版 data/net）
const net = new NetManager(userDataDir, { onLog: (m) => console.log(m) });

// 2) 主机：注入「本机大脑」，当全网唯一出口
net.attachHostExecutor(async ({ content, sessionId, deviceId }) => ({ speech: "…" }));
net.setAdvertiseHost(process.env.NET_ADVERTISE_HOST);  // 容器/多网卡必填
const started = await net.startHosting();
if (started.ok) {
    // 把这张邀请码交给别的设备（复制 / 二维码）。它里面**没有密钥**。
    const invite = net.serializePairing(net.issuePairing());
}

// 3) 叶子：贴邀请码接入（首次）。手里有没有密钥都能接 —— 没有就当场领
await net.startFollowing(invite);
// 之后打开组网走 net.resumeFollowing() 自动重连，不用再贴码

// 4) 服务端形态的叶子：上行并按 requestId 等自己那一条回包
const out = await net.relayAndWait(content, sessionId, { timeoutMs: 45_000 });
if (out.ok) { /* out.frame.speech / out.frame.emotion */ }
```

## 组成

| 文件 | 职责 |
| --- | --- |
| `protocol.ts` | 帧格式、端口 `19760`、心跳 2s / 超时 5s、`SeqTracker`。**不 import electron** |
| `secure.ts` | 密钥（自签 / 领取）、`scrypt` 派生会话密钥、AES-256-GCM 封解帧、`ReplayGuard` |
| `enroll.ts` | 配对期下发密钥：X25519 临时密钥对 + ECDH 派生一次性 AES key（密钥不上网络） |
| `identity.ts` | `deviceId`：随机生成、持久化、**不含硬件指纹** |
| `pairingCode.ts` | 连接码生成/解析/过期。**邀请码** `kirari://join?d=...`（默认，无需密钥即可解析）+ 兼容密文码 `kirari://connect?d=...`；**只存哈希** |
| `netStore.ts` | `net-state.json`（权限 600）：角色、地址、凭据、配对码、白名单、密钥 |
| `hostServer.ts` | 主机：监听、握手、鉴权、**密钥发放**、成员、广播。**每连接一份加密材料** |
| `leafClient.ts` | 叶子：连接、心跳、断线回退、**领密钥**、上行、离线补传 |
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
  （但 UI 上的「移除自己」是另一回事：那会连凭据和领来的密钥一起清掉，
  见 `manager.leaveHost()`。）
- **密钥 <16 位即视为「没配」**（`isNetEnabled()` 返回 false）：这个门槛拦的是
  「随手填个 123 就当加密用了」。
  ⚠️ 但**别拿它当「组网这块能不能用」的判据** —— 一台刚装好的机器本来就是 false，
  拿它当开关可用性会把整页灰掉、连自签都走不到（这正是修过的死局）。
  要判可用性用 `NetManager.canStartNetworking()`。
- **enroll 必须在 hello 之前处理**。领密钥那一刻叶子手上没有密钥，既派不出会话密钥、
  也发不出加密帧；把它放到 hello 之后 = 永远收不到（`hostServer` 里走的是「路径 0」）。
- **邀请码按「等同密码」对待**。它不需要密钥就能解析（否则就成了「要有密钥才能拿到密钥」
  的死循环），所以转发出去别人就能拿去领密钥。安全性全压在**一次性口令**上：
  用过作废、可单独撤销、有绝对过期时间。

## 开发

```bash
npm run build      # tsc → dist/（宿主引的是 dist，不是 src）
npm run typecheck  # 两份 tsconfig（含测试）
npm test           # vitest
```

`src/relay.integration.spec.ts` 会**真的起一个主机、真的让叶子接进来**，走完
握手 → 加密 → 上行 → 广播，其中「叶子重启后用长期凭据重连仍能上行」是一条回归防线
（单测测不出它 —— `ReplayGuard` 本身是对的，错的是它的生命周期）。

`src/enroll.integration.spec.ts` 同样真起两端，验「一把密钥都没有的机器贴一张邀请码
就能接进来、且上行真的通」。⚠️ 写这类用例时注意：vitest 是**单进程**，主机与叶子
共用同一个模块级密钥，所以「用 `setNetSecret("")` 模拟新机器」会把主机自己也清空。
「重启后密钥还在」用纯状态用例验（直接读写 `net-state.json`）。

⚠️ 端到端用例都占固定端口 **19760**，所以 `vitest.config.ts` 里必须保持
`fileParallelism: false`，否则文件并行会互相抢端口。

## 安全边界

能挡住：局域网里扫端口试探的陌生设备、蹭网抓包偷看对话的人
（密钥本身不上网络，握手后全部加密 + 防重放）。

还挡住了「拿到安装包就等于拿到密钥」这条老路 —— **安装包里不含密钥**：
每台设备要么当主机时自己签一把，要么在配对那一刻由主机加密发过来。
同一个包发给十个人，是十个互不相通、也互不可见的网。

挡不住：主机那台机器本身被翻（密钥落在它的 `net-state.json` 里，权限 600），
或者邀请码被转发出去（邀请码等同密码：一次性、短期、可撤销）。
即防「随手接入」，不防「人已经坐到那台设备前面」。
