// kirari-net · src/relayRouter.ts
// 活锁路由：主机是全网唯一出口。
//
//   叶子 A ─┐
//   叶子 B ─┼─→ 主机（唯一出口，排队 + 限流）─→ 大模型
//   叶子 C ─┘        └─→ 结果广播给所有叶子
//
// 「单一响应者」是活锁模型的核心价值：一条消息在任何时候只有一份回复，
// 不需要任何仲裁逻辑，也不会出现多端同时应答。
//
// 三条约束（ARCHITECTURE-PLAN 3.1 / 3.6 / 3.7）：
//  - 凭证用主机的：叶子不需要配 Key，因此这里调用的是**主机自己的**模型客户端
//  - 并发保护：N 台设备同时提问要排队，否则会打爆模型（也是保护主机的额度）
//  - 顺序保证：广播带单调递增 seq，叶子只接受递增的
//
// 本模块**不依赖 AI 引擎**：执行器由外部注入（见 RelayExecutor），
// 所以组网层可以独立测试，core 也能塞进不同的执行器。

import { PROTOCOL_VERSION } from "./protocol";
import type { RelayRequest, RelayResult, RelayBackfill, KbPassage } from "./protocol";

/**
 * 执行器：拿到一条上行请求，返回一段回复。
 * 由 main.ts 注入本机 AI 引擎（engine.chat）；测试里注入假实现。
 */
export type RelayExecutor = (req: {
    sessionId: string;
    content: string;
    images: string[];
    deviceId: string;
    nickname?: string;
    /**
     * 请求方自带的私人知识库检索结果（可选，可能为空数组）。
     * 主机应把它当最高优先级参考注入提示词 —— 它来自叶子本地，
     * 主机这边没有别的途径拿到。
     */
    kbContext?: KbPassage[];
    /**
     * 正文逐字回调（仅请求方带 stream 标志时提供）。
     * 约定与两端内核一致：onDelta(text) 追加增量；onDelta(null) 表示之前流出的
     * 作废（模型转去调工具了），由路由转发为 relay_delta{reset:true} 让请求方清空。
     * 回调异常由执行器自己吞掉，不能影响生成。
     */
    onDelta?: (chunk: string | null) => void;
}) => Promise<{ speech: string; emotion?: string | null }>;

export type RelayRouterEvents = {
    /** 把结果广播给全网（含主机自己） */
    broadcast: (frame: RelayResult) => void;
    /** 只回给某一个叶子（限流拒绝等） */
    replyTo: (deviceId: string, frame: unknown) => void;
    /** 补传入库：只记对话，不调模型 */
    onBackfill?: (msg: RelayBackfill) => Promise<void> | void;
    onLog?: (message: string) => void;
};

export type RelayRouterOptions = {
    /** 同时最多处理几个请求。默认 2 —— 再多会明显拖慢每个请求，且容易触发上游限流 */
    maxConcurrent?: number;
    /** 排队上限。超出直接拒绝（让叶子知道"主机忙"，比无限排队好） */
    maxQueue?: number;
    executor: RelayExecutor;
    events: RelayRouterEvents;
};

type QueueItem = {
    req: RelayRequest;
    enqueuedAt: number;
};

/** 单条知识片段的正文上限（字符）。提示词空间有限，超长的片段截断比照单全收诚实。 */
const KB_PASSAGE_MAX_CHARS = 2000;
/** 一条请求最多带几条片段。叶子端本来也只检索 top 5。 */
const KB_PASSAGE_MAX_COUNT = 5;

/**
 * 收敛叶子上带来的知识片段：只留认识的字段、去掉空正文、限条数与长度。
 *
 * 为什么不照单全收：这是**别的设备**发来的内容，会被拼进主机的提示词。
 * 不设上限的话，一个异常（或恶意）的叶子就能用超大 kbContext 把主机的
 * 上下文窗口撑爆、把主机的额度烧光。
 */
function clampKbContext(passages: unknown): KbPassage[] | undefined {
    if (!Array.isArray(passages)) return undefined;
    const out: KbPassage[] = [];
    for (const raw of passages) {
        if (!raw || typeof raw !== "object") continue;
        const p = raw as Partial<KbPassage>;
        const text = typeof p.text === "string" ? p.text.trim().slice(0, KB_PASSAGE_MAX_CHARS) : "";
        if (!text) continue;
        out.push({
            text,
            source: typeof p.source === "string" ? p.source.slice(0, 80) : undefined,
            url: typeof p.url === "string" ? p.url.slice(0, 500) : undefined,
            score: typeof p.score === "number" && p.score >= 0 && p.score <= 1 ? p.score : undefined,
        });
        if (out.length >= KB_PASSAGE_MAX_COUNT) break;
    }
    return out.length ? out : undefined;
}

export class RelayRouter {
    private executor: RelayExecutor;
    private events: RelayRouterEvents;
    private maxConcurrent: number;
    private maxQueue: number;

    private running = 0;
    private queue: QueueItem[] = [];
    private seq = 0;
    /** 正在关停：拒绝新请求，已在排队的也停掉 */
    private closing = false;

    constructor(opts: RelayRouterOptions) {
        this.executor = opts.executor;
        this.events = opts.events;
        this.maxConcurrent = opts.maxConcurrent ?? 2;
        this.maxQueue = opts.maxQueue ?? 20;
    }

    /** 换一个执行器（主机改了模型配置后调用，不必重启路由）。 */
    setExecutor(executor: RelayExecutor): void {
        this.executor = executor;
    }

    /** 当前排队情况，给 UI 显示用。 */
    stats(): { running: number; queued: number; maxConcurrent: number; maxQueue: number } {
        return { running: this.running, queued: this.queue.length, maxConcurrent: this.maxConcurrent, maxQueue: this.maxQueue };
    }

    /** 主机关闭组网时调用：停止接收新请求，并告知排队中的叶子。 */
    close(reason = "主机正在关闭组网"): void {
        this.closing = true;
        const pending = this.queue.splice(0, this.queue.length);
        for (const item of pending) {
            this.events.replyTo(item.req.deviceId, {
                type: "relay_busy",
                v: PROTOCOL_VERSION,
                requestId: item.req.requestId,
                reason,
            });
        }
    }

    /** 重新开启（对应「主机重新打开组网」）。 */
    reopen(): void {
        this.closing = false;
    }

    /** 收到叶子请求时的入口。返回 true 表示已受理。 */
    handle(req: RelayRequest): boolean {
        if (this.closing) {
            this.events.replyTo(req.deviceId, {
                type: "relay_busy",
                v: PROTOCOL_VERSION,
                requestId: req.requestId,
                reason: "主机正在关闭组网，等它重新打开就好",
            });
            return false;
        }

        // 限流：排队区满了就拒绝。无限排队会让叶子一直干等，
        // 而这些请求最终都会消耗主机额度 —— 早失败、早知情更诚实。
        if (this.queue.length >= this.maxQueue) {
            this.events.replyTo(req.deviceId, {
                type: "relay_busy",
                v: PROTOCOL_VERSION,
                requestId: req.requestId,
                reason: `主机排队的人太多了（最多等 ${this.maxQueue} 个），等一会儿再发吧`,
                retryAfterMs: 5000,
            });
            this.events.onLog?.(`[relay] 队列已满(${this.maxQueue})，拒绝来自 ${req.deviceId} 的请求`);
            return false;
        }

        this.queue.push({ req, enqueuedAt: Date.now() });
        this.events.onLog?.(
            `[relay] 已受理（运行中 ${this.running}，排队 ${this.queue.length}）来自 ${req.deviceId}`,
        );
        void this.drain();
        return true;
    }

    /** 补传：只记对话，不调模型。 */
    async handleBackfill(msg: RelayBackfill): Promise<void> {
        if (!Array.isArray(msg.entries) || msg.entries.length === 0) return;
        try {
            await this.events.onBackfill?.(msg);
            this.events.onLog?.(`[relay] 补传 ${msg.entries.length} 条离线对话（不重放模型调用）`);
        } catch (e) {
            this.events.onLog?.(`[relay] 补传失败：${(e as Error)?.message || e}`);
        }
    }

    private async drain(): Promise<void> {
        while (this.running < this.maxConcurrent && this.queue.length > 0) {
            const item = this.queue.shift()!;
            this.running++;
            void this.process(item).finally(() => {
                this.running--;
                void this.drain();
            });
        }
    }

    private async process(item: QueueItem): Promise<void> {
        const { req } = item;
        const waitMs = Date.now() - item.enqueuedAt;
        // 流式：请求方要了 stream 才把 onDelta 递给执行器；增量单播给请求方（不广播）。
        // 旧版主机没有这段逻辑 → 请求方一条 delta 都收不到、只等 result，行为不变。
        const onDelta = req.stream
            ? (chunk: string | null) => {
                  this.events.replyTo(req.deviceId, {
                      type: "relay_delta",
                      v: PROTOCOL_VERSION,
                      requestId: req.requestId,
                      ...(chunk === null ? { reset: true } : { text: chunk }),
                  });
              }
            : undefined;
        try {
            const out = await this.executor({
                sessionId: req.sessionId,
                content: req.content || "",
                images: Array.isArray(req.images) ? req.images : [],
                deviceId: req.deviceId,
                nickname: req.nickname,
                kbContext: clampKbContext(req.kbContext),
                onDelta,
            });
            const speech = (out?.speech || "").trim();
            if (!speech) {
                // 模型没给出有效回复：只回给请求方，不广播（广播空内容会让所有端都显示空白）
                this.events.replyTo(req.deviceId, {
                    type: "relay_busy",
                    v: PROTOCOL_VERSION,
                    requestId: req.requestId,
                    reason: "这次没想出说什么，再说一次吧",
                });
                return;
            }

            const frame: RelayResult = {
                type: "relay_result",
                v: PROTOCOL_VERSION,
                requestId: req.requestId,
                speech,
                emotion: out.emotion ?? null,
                seq: ++this.seq,
                fromDeviceId: req.deviceId,
                fromName: req.nickname,
                sessionId: req.sessionId,
                askedAt: Date.now() - waitMs,
            };
            // 广播给全网（含主机自己）——这就是"一份回复"的落地方式：
            // 只生成一次，然后所有人拿同一份。
            this.events.broadcast(frame);
        } catch (e) {
            const reason = (e as Error)?.message || "处理失败";
            this.events.onLog?.(`[relay] 处理失败（${reason}）`);
            this.events.replyTo(req.deviceId, {
                type: "relay_busy",
                v: PROTOCOL_VERSION,
                requestId: req.requestId,
                reason: `主机这边处理失败了：${reason}`,
            });
        }
    }
}
