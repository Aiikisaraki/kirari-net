// kirari-net · src/enroll.ts
// 配对期的密钥下发（enroll）：把组网密钥在**配对那一刻**交给新设备。
//
// ── 为什么要有这一层 ──
//   原先密钥必须「提前存在两边」—— 桌宠端靠打包时注入、核心版靠部署者往 .env 里填。
//   两处对不上就永远接不进同一个网（部署者手里那把和别人包里那把不是一个东西），
//   而且让用户手填密钥本身就是有感知的操作。
//   结论：只要密钥还得「事先分发」，「无感」和「源码/产物里不带密钥」就不可兼得。
//
//   现在改成分发时发：**密钥由主机在配对那一刻经加密通道交给这一台新设备**。
//   于是密钥不出现在源码里、不出现在配置文件里、用户也看不见它 ——
//   他做的全部事情就是「贴一个邀请码」。
//
// ── 怎么保证只有目标设备拿得到 ──
//   1. 叶子先生成一把**临时** X25519 密钥对，公钥随 enroll_request 一起发出。
//   2. 主机校验一次性邀请口令（verifyPairing）——不过关一律不吐密钥。
//   3. 主机用自己的临时私钥 + 叶子公钥做 ECDH，拿这个共享秘密派生一次性 AES 密钥，
//      把组网密钥封进密文回执。
//   4. 只有持有对应私钥的那台叶子能解开；解开即 setNetSecret()，之后走原本的
//      握手（hello → salt → 会话密钥）完全不变。
//
// ── 安全边界（别夸大）──
//   这条通道**没有服务端证书可以校**，所以并不防御「在你 review 邀请码之前就
//   劫持了这条连接」的主动中间人。但它和原本的设计同量级：邀请码本身就是
//   一次性口令（拿到码 ≈ 拿到一次接入资格），又有过期、用一次作废、可撤销三道闸。
//   真正要挡的是「局域网里扫端口的陌生人 / 蹭网抓包的人」——那一类它挡得住。

import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, type KeyObject } from "crypto";
import { deriveKey, open, seal } from "./secure";

/** 派生密钥用的固定 salt（enroll 专用，与会话密钥、配对码的 salt 互不相干）。 */
const ENROLL_SALT = "kirari-enroll-v1";

/** 一把临时密钥对（只在这一次 enroll 期间有效，用完即弃）。 */
export type EnrollKeypair = { publicKeyB64: string; privateKeyB64: string };

function publicFromB64(b64: string): KeyObject {
    return createPublicKey({ key: Buffer.from(b64, "base64"), format: "der", type: "spki" });
}

function privateFromB64(b64: string): KeyObject {
    return createPrivateKey({ key: Buffer.from(b64, "base64"), format: "der", type: "pkcs8" });
}

/**
 * 生成一次性密钥对。
 *
 * 指定了 encoding 时 generateKeyPairSync 直接给 DER Buffer（而不是 KeyObject）——
 * 这里要的就是能过网络与 JSON 的字符串，Buffer 正合适。
 */
export function newEnrollKeypair(): EnrollKeypair {
    const { publicKey, privateKey } = generateKeyPairSync("x25519", {
        publicKeyEncoding: { type: "spki", format: "der" },
        privateKeyEncoding: { type: "pkcs8", format: "der" },
    }) as unknown as { publicKey: Buffer; privateKey: Buffer };
    return { publicKeyB64: publicKey.toString("base64"), privateKeyB64: privateKey.toString("base64") };
}

/**
 * ECDH → 派生本次用的对称密钥。
 *
 * 中间那份共享秘密不直接当 AES key：它长度虽够但熵分布不受控，
 * 统一交给 scrypt 派生（与 secure.deriveKey 同一套规矩）。
 */
function sharedKey(privateB64: string, peerPublicB64: string): Buffer {
    const shared = diffieHellman({ privateKey: privateFromB64(privateB64), publicKey: publicFromB64(peerPublicB64) });
    return deriveKey(shared.toString("hex"), ENROLL_SALT);
}

/**
 * 主机侧：把组网密钥密封给对方报上来的临时公钥。
 *
 * 每次都新造一把临时密钥对 —— 每台设备 enroll 用的是不同的一次性密钥，
 * 密文互不影响，主机私钥本身从不出现在网络上。
 */
export function sealSecretFor(peerPublicB64: string, secret: string): { ephPub: string; sealed: string } {
    const mine = newEnrollKeypair();
    const key = sharedKey(mine.privateKeyB64, peerPublicB64);
    return { ephPub: mine.publicKeyB64, sealed: seal(key, { secret }) };
}

/**
 * 叶子侧：用主机的临时公钥解出组网密钥。
 *
 * 失败返回 null（密文被改动 / 公私钥不匹配）。不抛，因为这属于「对方可能有问题」
 * 的正常分支，上层要的是回退而不是崩溃。
 */
export function openSecretOwnPair(keypair: EnrollKeypair, hostPublicB64: string, sealed: string): string | null {
    try {
        const key = sharedKey(keypair.privateKeyB64, hostPublicB64);
        const obj = open(key, sealed);
        return obj && typeof obj.secret === "string" && obj.secret.length >= 16 ? obj.secret : null;
    } catch {
        return null;
    }
}
