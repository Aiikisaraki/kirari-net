// kirari-net · src/secure.ts
// 组网通信加密：对称加密 + 防重放。
//
// ── 为什么用预共享密钥（PSK）而不是 TLS ──
//   家用组网没有公网基础设施，也不该要求每台设备装证书。PSK 只要两边
//   拿着同一串密钥就能安全通信，实现和维护成本都低得多。
//
// ── 安全边界（务必明白它能挡什么、不能挡什么）──
//   能挡住：局域网里扫端口试探的陌生设备、蹭网抓包偷看对话的人。
//   还挡住了「拿到安装包就等于拿到密钥」这条老路 —— 安装包里**不含密钥**：
//   每台设备要么在当主机时自己签一把，要么在配对那一刻由主机加密发过来。
//   同一个包发给十个人，是十个互不相通、也互不可见的网。
//   挡不住：主机那台机器本身被翻（密钥落在它的 net-state.json 里，权限 600），
//   或者邀请码被转发出去（邀请码等同密码：一次性、短期、可撤销）。
//   所以它防的是「随手接入」，不是「人已经坐到那台设备前面」。
//
// ── 加密范围 ──
//   hello / hello_ack 保持明文（握手必须明文，否则无法协商 salt）
//   心跳 ping / pong 保持明文（不含信息，加密纯浪费 CPU，且明文方便排障）
//   其余**全部**加密：配对结果、长期凭据、对话内容、配置同步、成员列表
//
// ── 每帧独立 IV，不做流式同步 ──
//   自包含、无需维护序号窗口的流状态，代价只是每帧多 28 字节。
//   聊天场景的量级下这个开销可以忽略。

import { createCipheriv, createDecipheriv, randomBytes, scryptSync, timingSafeEqual } from "crypto";

// ── 组网密钥：运行时产生，源码/产物/CI/配置里都没有 ────────────────────
//
// 历史做法是 `declare const __KIRARI_NET_SECRET__` + 打包器 define 替换。
// 它有两个越用越明显的问题：
//   1. 打包器的 define 够不到本文件的**预编译产物**，而
//      `typeof 未声明变量` **不抛错、只返回 "undefined"** —— 于是密钥静默为空、
//      组网整体失效，而且**没有任何报错**。属于最难查的那类故障。
//   2. 密钥一旦写进构建产物，装了这个包的人就都拿着同一把密钥 ——
//      而「谁的设备谁负责」本来就不该存在一把统一的密钥。
//
// 现在密钥只有两个来源，都在**运行时**产生：
//   - 本机当主机：自己签一把（newNetSecret → setNetSecret → 落盘 ownSecret）
//   - 本机当叶子：配对那一刻由主机加密发过来
//     （enroll → setNetSecret → 落盘 enrolledSecret）
// 两者机会均等 —— 桌宠端与核心版在网络里的地位完全一样，没有「官方的网」。
//
// setNetSecret() 保留下来，作为「把密钥装上」的唯一入口（上述两条路径都用它），
// 也是宿主显式指定密钥的入口（测试里就是这么干的）。
let netSecret = "";

/** 注入组网密钥。传空串等于关闭组网。应在创建 NetManager 之前调用。 */
export function setNetSecret(secret: string | undefined | null): void {
    netSecret = typeof secret === "string" ? secret.trim() : "";
}

/** 当前组网密钥。正常业务代码不要直接读它 —— 用 isNetEnabled() 判断、用 deriveKey() 派生。 */
export function getNetSecret(): string {
    return netSecret;
}

/**
 * 本机此刻手上有没有一把可用的组网密钥。
 *
 * ⚠️ 它**不是**「这个版本能不能组网」，也**不要**拿它当「组网设置那块要不要灰掉」的判据 ——
 *    两端都不预置密钥，一台刚装好的机器必然是 false；拿它当可用性会把整页灰掉、
 *    用户连「开启组网」都点不了，自签也就永远走不到。要判可用性用
 *    `NetManager.canStartNetworking()`。
 *
 * 它的真实含义只有一条：此刻手上还没有密钥 —— 自签成功、或从主机领到之后就会变成 true。
 *
 * 长度门槛 16：短于这个长度当「没配」，避免有人随手填个 "123" 就当加密用了。
 */
export function isNetEnabled(): boolean {
    return netSecret.length >= 16;
}

const ALGO = "aes-256-gcm";
const IV_LEN = 12; // GCM 推荐 12 字节
const TAG_LEN = 16;
/** 加密帧的线格式标识 */
export const SEALED_MARK = "e";

/**
 * 由密钥 + salt 派生会话密钥。
 *
 * 用 scrypt 而不是直接拿密钥当 AES key：
 *   - 密钥是给人输入/构建时注入的短串，不是合规的 32 字节密钥材料
 *   - scrypt 慢，能大幅提高暴力猜解的成本
 *   - 加 salt 后不同主机派生出不同会话密钥 —— 一台被攻破不牵连其他主机
 */
export function deriveKey(secret: string, salt: string): Buffer {
    return scryptSync(secret, salt, 32, { N: 16384, r: 8, p: 1 });
}

/** 生成 salt（主机首次启动时生成一次并持久化） */
export function newSalt(): string {
    return randomBytes(16).toString("hex");
}

/**
 * 生成一把全新的组网密钥。
 *
 * 用在「本机手上还没有任何密钥、但用户要为自己搭一个网」的场景 ——
 * 以前没密钥就不能组网，从源码构建的人（桌宠端与核心版都一样）
 * 只能开出「组网功能灰着」的版本。现在每台机器都能给自己签一把。
 *
 * 生成之后由调用方立刻 setNetSecret() 让它生效，并负责落盘保存
 * （落盘了才算「这台机器自己的」，见 netStore 的 ownSecret）。
 */
export function newNetSecret(): string {
    return randomBytes(24).toString("hex"); // 48 个十六进制字符，远高于 16 位门槛
}

/** 加密一帧。返回可直接放进 {e,d} 的 base64 串。 */
export function seal(key: Buffer, frame: unknown): string {
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv(ALGO, key, iv);
    const plaintext = Buffer.from(JSON.stringify(frame), "utf8");
    const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), enc]).toString("base64");
}

/**
 * 解密一帧。失败返回 null（密钥不对 / 数据被篡改 / 不是密文）。
 *
 * 不抛异常是刻意的：握手阶段会拿各种畸形数据来试，不该因此崩掉。
 */
export function open(key: Buffer, payload: string): Record<string, unknown> | null {
    try {
        const raw = Buffer.from(payload, "base64");
        if (raw.length <= IV_LEN + TAG_LEN) return null;
        const iv = raw.subarray(0, IV_LEN);
        const tag = raw.subarray(IV_LEN, IV_LEN + TAG_LEN);
        const data = raw.subarray(IV_LEN + TAG_LEN);
        const decipher = createDecipheriv(ALGO, key, iv);
        decipher.setAuthTag(tag);
        const dec = Buffer.concat([decipher.update(data), decipher.final()]);
        const obj = JSON.parse(dec.toString("utf8"));
        return obj && typeof obj === "object" ? (obj as Record<string, unknown>) : null;
    } catch {
        return null;
    }
}

/**
 * 常量时间比较两个字符串，避免时序侧信道。
 * 用于比对长期凭据。
 */
export function safeEqual(a: string, b: string): boolean {
    const ba = Buffer.from(String(a), "utf8");
    const bb = Buffer.from(String(b), "utf8");
    if (ba.length !== bb.length) return false;
    return timingSafeEqual(ba, bb);
}

/**
 * 防重放窗口。
 *
 * AES-GCM 能防篡改，但**不能防重放**：抓到一条合法密文就能无限重发。
 * 加密帧里带一个自增序号，接收端只接受「比已见最大值大」的帧，
 * 并保留最近 N 个序号 —— 既挡住重放，又允许轻微乱序。
 *
 * 这里用「水位 + 环形缓冲」而不是位图：逻辑简单，且窗口大小固定不增长。
 */
export class ReplayGuard {
    private highWater = 0;
    private seen: number[] = [];
    // 不用构造参数属性（parameter property）—— erasableSyntaxOnly 下不允许，
    // 显式声明字段再赋值，行为完全一致。
    private readonly windowSize: number;
    constructor(windowSize = 256) {
        this.windowSize = windowSize;
    }

    /** 返回 true 表示这是首次出现、应当接受。 */
    accept(seq: number): boolean {
        if (!Number.isSafeInteger(seq) || seq <= 0) return false;
        if (seq > this.highWater) {
            this.highWater = seq;
            this.remember(seq);
            return true;
        }
        // 落在历史窗口内：见过就丢
        if (this.seen.includes(seq)) return false;
        // 离水位太远（远超窗口）的旧帧也丢：多半是重放
        if (this.highWater - seq > this.windowSize) return false;
        this.remember(seq);
        return true;
    }

    private remember(seq: number): void {
        this.seen.push(seq);
        if (this.seen.length > this.windowSize) {
            this.seen.shift();
        }
    }

    reset(): void {
        this.highWater = 0;
        this.seen = [];
    }

    /** 诊断用 */
    get state(): { highWater: number; windowUsed: number } {
        return { highWater: this.highWater, windowUsed: this.seen.length };
    }
}