// @vitest-environment node
//
// 主进程侧纯函数测试：配置同步白名单。
// 白名单判定在**主机侧**做（叶子无条件上报，主机过滤后广播），所以这里测的就是
// 「主机到底放不放行」这一件事 —— 这正是之前从没被验证过的部分。

import { describe, expect, it } from "vitest";
import { defaultNetState, filterWhitelisted, setSyncWhitelist } from "./netStore";
import { DEFAULT_SYNC_WHITELIST, SYNC_FIELDS } from "./protocol";
import type { SyncField } from "./protocol";

function hostState() {
    return defaultNetState("dev-host", "主机");
}

describe("配置同步白名单", () => {
    it("默认全部字段都同步", () => {
        expect(DEFAULT_SYNC_WHITELIST).toEqual([...SYNC_FIELDS]);
        expect(hostState().syncWhitelist).toEqual([...SYNC_FIELDS]);
    });

    it("白名单里不含密钥类字段（组网内用主机的凭证，下发=让叶子能拿去别处用）", () => {
        for (const secret of ["key", "searchKey", "token", "apiKey"]) {
            expect(SYNC_FIELDS).not.toContain(secret);
        }
    });

    it("勾上的字段放行", () => {
        const state = setSyncWhitelist(hostState(), ["model"]);
        const out = filterWhitelisted(state, { model: "gpt-5.4-mini" });
        expect(out).toEqual({ model: "gpt-5.4-mini" });
    });

    it("没勾的字段被丢掉 —— 叶子改了也不传播", () => {
        const state = setSyncWhitelist(hostState(), ["model"]);
        const out = filterWhitelisted(state, {
            model: "gpt-5.4-mini",
            endpoint: "https://example.com/v1",
        });
        expect(out).toEqual({ model: "gpt-5.4-mini" });
        expect(out.endpoint).toBeUndefined();
    });

    it("一次上报多个字段时逐个判定，不是全有或全无", () => {
        const state = setSyncWhitelist(hostState(), ["model", "searchProvider"]);
        const out = filterWhitelisted(state, {
            model: "a",
            endpoint: "b",
            basePersona: "c",
            searchProvider: "d",
            searchEndpoint: "e",
        });
        expect(Object.keys(out).sort()).toEqual(["model", "searchProvider"]);
    });

    it("值不是字符串的一律丢掉（脏数据不能污染叶子）", () => {
        const state = setSyncWhitelist(hostState(), [...SYNC_FIELDS]);
        const out = filterWhitelisted(state, {
            model: "ok",
            endpoint: undefined as unknown as string,
        });
        expect(out).toEqual({ model: "ok" });
    });

    it("白名单清空后什么都不下发", () => {
        const state = setSyncWhitelist(hostState(), []);
        expect(filterWhitelisted(state, { model: "x" })).toEqual({});
    });

    it("setSyncWhitelist 不改动原 state（返回新对象）", () => {
        const before = hostState();
        const after = setSyncWhitelist(before, ["model"]);
        expect(before.syncWhitelist).toEqual([...SYNC_FIELDS]);
        expect(after.syncWhitelist).toEqual(["model"]);
    });

    it("非法字段名不会被塞进白名单以外的路径（未知 key 直接丢弃）", () => {
        const state = setSyncWhitelist(hostState(), ["model"]);
        const out = filterWhitelisted(state, {
            key: "sk-xxx",
        } as Partial<Record<SyncField, string>>);
        expect(out).toEqual({});
    });
});
