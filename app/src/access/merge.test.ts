import { describe, expect, it } from "vitest";
import { mergeAccess } from "./merge";
import { account, item, NEVER, ORDER, report, tile } from "./testData";

const B = "b@contoso.example";
const mailRead = (m: ReturnType<typeof mergeAccess>) => m.tiles.find((t) => t.category === "mail_read")!;

describe("mergeAccess", () => {
  it("sums_counts_across_accounts", () => {
    const a = account({ tiles: ORDER.map((c) => tile(c, c === "mail_read" ? { direct: 3, by_time: 1, pending: 1 } : {})) });
    const b = account({ account: B, tiles: ORDER.map((c) => tile(c, c === "mail_read" ? { direct: 4, adhoc: 2 } : {})) });
    const t = mailRead(mergeAccess(report([a, b]), null));
    expect([t.direct, t.by_time, t.pending, t.adhoc]).toEqual([7, 1, 1, 2]);
    expect(mergeAccess(report([a, b]), null).tiles.map((x) => x.category)).toEqual(ORDER);
  });

  it("none_seen_only_when_every_account_says_so", () => {
    const missing = { status: "not_collected", reason: "Mailbox audit not collected", remediation: null };
    const a = account({ tiles: ORDER.map((c) => tile(c)) });
    const b = account({ account: B, tiles: ORDER.map((c) => tile(c, c === "mail_read" ? { none_seen: false, coverage: missing } : {})) });
    const t = mailRead(mergeAccess(report([a, b]), null));
    expect(t.none_seen).toBe(false);
    expect(t.notCollectedFor).toBe(1);
    expect(t.of).toBe(2);
    expect(t.coverage).toEqual(missing);
  });

  it("coverage_collected_when_all_collected", () => {
    const t = mailRead(mergeAccess(report([account(), account({ account: B })]), null));
    expect(t.coverage.status).toBe("collected");
    expect(t.notCollectedFor).toBe(0);
    expect(t.none_seen).toBe(true);
  });

  it("gaps_name_their_account", () => {
    const a = account({ gaps: ["Mail: x"] });
    const m = mergeAccess(report([a, account({ account: B })]), null);
    expect(m.gaps).toEqual([`${a.account}: Mail: x`, ...NEVER]);
  });

  it("scope_union", () => {
    const w2 = { start: "2026-10-22T01:00:00Z", end: "2026-10-22T02:00:00Z" };
    const a = account();
    const b = account({ account: B, scope: [{ ...a.scope[0], windows: [w2] }] });
    const m = mergeAccess(report([a, b]), null);
    expect(m.scope).toHaveLength(1);
    expect(m.scope[0].windows).toEqual([w2, ...a.scope[0].windows]);
  });

  it("filter_to_one_account", () => {
    const a = account({ items: [item({ record_key: "a1" })], gaps: ["Mail: x"], tiles: ORDER.map((c) => tile(c, c === "mail_read" ? { direct: 1 } : {})) });
    const b = account({
      account: B,
      items: [item({ account: B, record_key: "b1" })],
      gaps: ["Files: y"],
      tiles: ORDER.map((c) => tile(c, c === "mail_read" ? { direct: 5 } : {})),
    });
    const m = mergeAccess(report([a, b]), B);
    expect(m.accounts).toEqual([a.account, B]);
    expect(m.items.map((i) => i.record_key)).toEqual(["b1"]);
    expect(mailRead(m).direct).toBe(5);
    expect(m.gaps).toEqual([`${B}: Files: y`, ...NEVER]);
  });

  it("items_by_time", () => {
    const a = account({ items: [item({ record_key: "a1", accessed: "2026-10-23T10:00:00Z" }), item({ record_key: "a2", accessed: "2026-10-23T12:00:00Z" })] });
    const b = account({ account: B, items: [item({ account: B, record_key: "b1", accessed: "2026-10-23T11:00:00Z" })] });
    expect(mergeAccess(report([a, b]), null).items.map((i) => i.record_key)).toEqual(["a1", "b1", "a2"]);
  });

  it("single_account_is_unchanged", () => {
    const a = account({ items: [item({})], gaps: ["Mail: x"], tiles: ORDER.map((c) => tile(c, c === "file" ? { direct: 2, qualifier: "q" } : {})) });
    const m = mergeAccess(report([a]), null);
    expect(m.items).toEqual(a.items);
    expect(m.tiles.map((t) => Object.fromEntries(Object.entries(t).filter(([k]) => k !== "notCollectedFor" && k !== "of")))).toEqual(a.tiles);
    expect(m.gaps).toEqual(["Mail: x", ...NEVER]);
  });

  it("no_accounts_gives_empty_tiles", () => {
    const m = mergeAccess(report([]), null);
    expect(m.accounts).toEqual([]);
    expect(m.items).toEqual([]);
    expect(m.tiles).toEqual([]);
  });

  it("items_by_instant_not_text", () => {
    const a = account({
      items: [
        item({ record_key: "late", accessed: "2026-10-23T10:00:00.500Z" }),
        item({ record_key: "whole", accessed: "2026-10-23T10:00:00Z" }),
        item({ record_key: "short", accessed: "2026-10-23T10:00:00.25Z" }),
        item({ record_key: "micro", accessed: "2026-10-23T10:00:00.250001Z" }),
      ],
    });
    const b = account({ account: B, items: [item({ account: B, record_key: "same", accessed: "2026-10-23T10:00:00.250000Z" })] });
    expect(mergeAccess(report([a, b]), null).items.map((i) => i.record_key)).toEqual(["whole", "short", "same", "micro", "late"]);
  });

  it("a_synced_only_tile_stays_exposed_and_names_its_account", () => {
    const a = account({ tiles: ORDER.map((c) => tile(c, c === "mail_read" ? { qualifier: "1 folder synced", none_seen: false } : {})) });
    const b = account({ account: B, tiles: ORDER.map((c) => tile(c, c === "mail_read" ? { direct: 2, qualifier: "1 folder · 0.1 MB", none_seen: false } : {})) });
    const c = account({ account: "c@contoso.example" });
    const t = mailRead(mergeAccess(report([a, b, c]), null));
    expect(t.qualifier).toBe(`${a.account}: 1 folder synced · ${B}: 1 folder · 0.1 MB`);
    expect(mailRead(mergeAccess(report([a, b, c]), a.account)).qualifier).toBe("1 folder synced");
    expect(mailRead(mergeAccess(report([a, c]), "c@contoso.example")).qualifier).toBeNull();
  });
});
