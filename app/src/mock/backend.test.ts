import { describe, expect, it, vi } from "vitest";
import { MOCK_COMMANDS, mockCall, mockOpen, mockSave } from "./backend";
import { GEN_COLUMNS, GEN_ROWS, genRows } from "./generated";
import apiSource from "../api.ts?raw";
import type { BrowsePage, CmdError, QueueItem, QueryResult, SqlCheck } from "../api";

const apiCommands = [...apiSource.matchAll(/\bcall(?:<[^(]*>)?\(\s*"([a-z_]+)"/g)].map((m) => m[1]);

describe("mock backend", () => {
  it("answers exactly the commands api.ts calls", () => {
    expect(apiCommands.length).toBeGreaterThan(30);
    expect([...new Set(apiCommands)].sort()).toEqual(MOCK_COMMANDS);
  });

  it("returns contract-shaped data for every read command", async () => {
    const info = await mockCall<{ case_id: string }>("case_open", { path: "/x.duckdb", allowUpgrade: false });
    expect(info.case_id).toBeTruthy();
    expect((await mockCall<unknown[]>("review_queue")).length).toBeGreaterThan(0);
    const id = (await mockCall<{ finding: { finding_id: string } }>("finding_detail", { findingId: "abc" })).finding.finding_id;
    expect(id).toBe("abc");
    expect((await mockCall<unknown[]>("timeline_list")).length).toBeGreaterThan(0);
    expect((await mockCall<{ accounts: unknown[] }>("accounts_list")).accounts.length).toBeGreaterThan(0);
    for (const cmd of ["pivot_ip", "pivot_user"]) {
      const p = await mockCall<{ sections: { rows: unknown[] }[] }>(cmd, { value: "x" });
      expect(p.sections.some((s) => s.rows.length === 200)).toBe(true);
    }
    expect((await mockCall<string[]>("browse_tables")).length).toBeGreaterThan(0);
    expect((await mockCall<unknown[]>("sql_schema")).length).toBeGreaterThan(0);
    expect((await mockCall<unknown[]>("indicators_active")).length).toBeGreaterThan(0);
    expect((await mockCall<{ items: number }>("share_preview", { path: "/b.json" })).items).toBeGreaterThan(0);
    expect((await mockCall<{ table: string }>("evidence_filter", { table: "signins", key: "k" })).table).toBe("signins");
    expect(await mockCall("export_report", { path: "/o", reviewedOnly: false })).toBeNull();
  });

  it("generates a wide, long table with long cells and hostile strings", () => {
    expect(GEN_COLUMNS.length).toBe(40);
    const rows = genRows();
    expect(rows.length).toBe(GEN_ROWS);
    expect(rows.every((r) => r.length === 40)).toBe(true);
    expect(String(rows[0][GEN_COLUMNS.indexOf("raw")]).length).toBeGreaterThanOrEqual(2048);
    expect(String(rows[0][GEN_COLUMNS.indexOf("user_agent")]).length).toBeGreaterThanOrEqual(300);
    const upns = rows.map((r) => String(r[GEN_COLUMNS.indexOf("user_upn")]));
    expect(upns.some((u) => u.includes("‮"))).toBe(true);
    expect(upns.some((u) => u.includes("<"))).toBe(true);
  });

  it("answers sql_check with a located error, and sql_run with offset and ordered", async () => {
    const bad = await mockCall<{ ok: boolean; error: { from: number; to: number } }>("sql_check", { sql: "select error" });
    expect(bad.ok).toBe(false);
    expect([bad.error.from, bad.error.to]).toEqual([7, 12]);
    const p0 = await mockCall<QueryResult>("sql_run", { sql: "SELECT * FROM signins ORDER BY 1", limit: 50, offset: 0, queryId: "a" });
    const p1 = await mockCall<QueryResult>("sql_run", { sql: "SELECT * FROM signins", limit: 50, offset: 50, queryId: "b" });
    expect(p0.ordered).toBe(true);
    expect(p1.ordered).toBe(false);
    expect(p1.rows[0]).not.toEqual(p0.rows[0]);
  });

  it("pages, sorts, filters and caps browse_page", async () => {
    const page = (a: Record<string, unknown>) =>
      mockCall<BrowsePage>("browse_page", { table: "signins", filters: [], sort: null, offset: 0, limit: 100, queryId: "q", ...a });
    const p0 = await page({});
    expect(p0.rows.length).toBe(100);
    expect(p0.total_capped).toBe(true);
    const p1 = await page({ offset: 100 });
    expect(p1.rows[0]).not.toEqual(p0.rows[0]);
    const sorted = await page({ sort: { column: "error_code", descending: true }, limit: 5 });
    expect(sorted.rows[0][GEN_COLUMNS.indexOf("error_code")]).toBe(50126);
    const f = await page({ filters: [{ op: "eq", column: "status", value: "Failure" }] });
    expect(f.total).toBeGreaterThan(0);
    expect(f.total_capped).toBe(false);
    expect(f.rows.every((r) => r[GEN_COLUMNS.indexOf("status")] === "Failure")).toBe(true);
    const c = await page({ filters: [{ op: "contains", column: "ip", value: "203.0.113." }], limit: 3 });
    expect(c.rows.length).toBe(3);
  });

  it("accept and discard remove the queue item and record an audit entry", async () => {
    const q = await mockCall<QueueItem[]>("review_queue");
    const d = q.find((i) => i.source === "decision")!;
    if (d.source !== "decision") throw new Error("unreachable");
    const e = await mockCall<{ action: string }>("review_accept", { objectType: d.object_type, objectId: d.object_id, decisionSeq: d.decision_seq });
    expect(e.action).toBe("review_accept");
    const after = await mockCall<QueueItem[]>("review_queue");
    expect(after.length).toBe(q.length - 1);
    await expect(
      mockCall("review_discard", { objectType: d.object_type, objectId: d.object_id, decisionSeq: d.decision_seq }),
    ).rejects.toMatchObject({ kind: "not_found" });
  });

  it("a slow sql_run waits and query_cancel interrupts it", async () => {
    const run = mockCall<QueryResult>("sql_run", { sql: "SELECT slow", limit: 10, queryId: "slow-1" });
    const settled = run.then(() => "done", (e: CmdError) => e.kind);
    await new Promise((r) => setTimeout(r, 100));
    await mockCall("query_cancel", { queryId: "slow-1" });
    expect(await settled).toBe("interrupted");
    const wide = await mockCall<QueryResult>("sql_run", { sql: "SELECT * FROM signins", limit: 50, queryId: "w" });
    expect(wide.columns.length).toBe(40);
    expect(wide.truncated).toBe(true);
  });

  it("pages sql_run, flags ORDER BY, checks and exports like the backend's contract", async () => {
    const run = (a: Record<string, unknown>) => mockCall<QueryResult>("sql_run", { sql: "SELECT * FROM signins", limit: 100, queryId: "p", ...a });
    const p0 = await run({});
    const p1 = await run({ offset: 100 });
    expect(p1.rows[0]).not.toEqual(p0.rows[0]);
    expect(p0.ordered).toBe(false);
    expect((await run({ sql: "SELECT * FROM signins ORDER BY ip" })).ordered).toBe(true);
    expect(await mockCall("sql_check", { sql: "SELECT 1 AS n -- fine" })).toEqual({ ok: true });
    for (const [sql, kind] of [["DELETE FROM findings", "syntax"], ["SELECT 1; SELECT 2", "syntax"], ["SELECT *\nFROM findngs", "catalog"], ["SELECT 1 FRM t", "syntax"]]) {
      const c = await mockCall<SqlCheck>("sql_check", { sql });
      expect(c.ok ? null : c.error.kind).toBe(kind);
    }
    const c = await mockCall<SqlCheck>("sql_check", { sql: "SELECT *\nFROM findngs" });
    if (c.ok) throw new Error("expected an error");
    expect([c.error.from, c.error.to, c.error.suggestions]).toEqual([14, 21, ["findings"]]);
    const slow = mockCall("sql_export_csv", { sql: "SELECT slow", path: "/o.csv", queryId: "e-slow" });
    const settled = slow.then(() => "done", (e: CmdError) => e.kind);
    await new Promise((r) => setTimeout(r, 100));
    await mockCall("query_cancel", { queryId: "e-slow" });
    expect(await settled).toBe("interrupted");
  });

  it("names an unknown command in an internal error", async () => {
    await expect(mockCall("no_such_command")).rejects.toMatchObject({ kind: "internal", message: expect.stringContaining("no_such_command") });
  });

  it("answers the dialogs with fixed paths", () => {
    expect(mockOpen({ filters: [{ name: "Sparrow case", extensions: ["duckdb"] }] })).toMatch(/\.duckdb$/);
    expect(mockSave({ defaultPath: "r.md" })).toBe("/mock/out/r.md");
  });
});

// ---------------------------------------------------------------- every command, valid args, response shape

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const keys = (v: unknown, ks: string[]) => {
  expect(isObj(v)).toBe(true);
  for (const k of ks) expect(Object.keys(v as Obj), `missing ${k}`).toContain(k);
};
const arrOf = (v: unknown, ks: string[]) => {
  expect(Array.isArray(v)).toBe(true);
  expect((v as unknown[]).length).toBeGreaterThan(0);
  for (const x of v as unknown[]) keys(x, ks);
};
const AUDIT = ["seq", "ts", "actor", "action", "object_type", "object_id", "before", "after", "reason", "prev_hash", "hash"];
const ENTRY = ["entry_id", "event_time", "title", "phase", "status", "review_state", "evidence"];
const fresh = async () => {
  vi.resetModules();
  return import("./backend");
};

const TABLE: { cmd: string; args?: Obj; check: (r: unknown) => void }[] = [
  { cmd: "settings_get", check: (r) => keys(r, ["analyst", "recent"]) },
  { cmd: "settings_set_analyst", args: { name: "dana" }, check: (r) => expect((r as Obj).analyst).toBe("dana") },
  { cmd: "case_open", args: { path: "/c.duckdb", allowUpgrade: false }, check: (r) => { keys(r, ["path", "case_id", "schema_version", "audit_ok", "read_only_reason", "tenants", "warnings"]); expect((r as Obj).path).toBe("/c.duckdb"); } },
  { cmd: "case_close", check: (r) => expect(r).toBeNull() },
  { cmd: "review_queue", check: (r) => arrOf(r, ["source"]) },
  { cmd: "finding_detail", args: { findingId: "f1" }, check: (r) => { keys(r, ["finding", "evidence", "analyst_guidance", "notes", "audit"]); arrOf((r as Obj).evidence, ["source_table", "record_key", "role", "event_time", "source_refs", "timeline", "context"]); } },
  { cmd: "review_accept", args: { objectType: "finding", objectId: "1c8b18eff09c880c", decisionSeq: 1, comment: "ok" }, check: (r) => keys(r, AUDIT) },
  { cmd: "review_discard", args: { objectType: "indicator", objectId: "c0138dfabda9ce43", decisionSeq: 2 }, check: (r) => keys(r, AUDIT) },
  { cmd: "proposal_accept", args: { bundleSha256: "BUNDLE", itemKey: "KEY" }, check: (r) => arrOf(r, AUDIT) },
  { cmd: "proposal_discard", args: { bundleSha256: "BUNDLE", itemKey: "KEY", comment: "no" }, check: (r) => keys(r, AUDIT) },
  { cmd: "timeline_list", check: (r) => arrOf(r, ENTRY) },
  { cmd: "timeline_propose", args: { args: { eventTime: "2026-08-14T10:00:00Z", title: "t", phase: "persistence", evidence: ["signins:k1"] } }, check: (r) => { keys(r, ["entryId", "audit"]); keys((r as Obj).audit, AUDIT); } },
  { cmd: "timeline_edit", args: { entryId: "mock-entry-00", args: { title: "edited" } }, check: (r) => keys(r, ["entryId", "audit"]) },
  { cmd: "timeline_verify", args: { entryId: "mock-entry-01" }, check: (r) => keys(r, AUDIT) },
  { cmd: "timeline_reject", args: { entryId: "mock-entry-02", reason: "dup" }, check: (r) => keys(r, AUDIT) },
  { cmd: "accounts_list", args: {}, check: (r) => { keys(r, ["accounts", "total", "truncated", "warnings"]); arrOf((r as Obj).accounts, ["tenant_key", "upn", "worst_severity", "finding_count", "stages", "addresses"]); } },
  { cmd: "export_report", args: { path: "/o.md", reviewedOnly: true }, check: (r) => expect(r).toBeNull() },
  { cmd: "export_timeline_csv", args: { path: "/o.csv" }, check: (r) => expect(r).toBeNull() },
  { cmd: "export_workbook", args: { path: "/o.xlsx" }, check: (r) => expect(r).toBeNull() },
  { cmd: "pivot_ip", args: { value: "203.0.113.5", cap: 50 }, check: (r) => { keys(r, ["sections"]); arrOf((r as Obj).sections, ["name", "rows", "total", "truncated"]); } },
  { cmd: "pivot_user", args: { value: "a@contoso.example" }, check: (r) => arrOf((r as Obj).sections, ["name", "rows", "total", "truncated"]) },
  { cmd: "highlights_get", args: { caseId: "c" }, check: (r) => expect(r).toEqual([]) },
  { cmd: "highlights_set", args: { caseId: "c", sets: [{ name: "s", rules: [] }] }, check: (r) => expect(r).toEqual([{ name: "s", rules: [] }]) },
  { cmd: "highlights_clear", args: { caseId: "c" }, check: (r) => expect(r).toBeNull() },
  { cmd: "evidence_filter", args: { table: "signins", key: "k" }, check: (r) => { keys(r, ["table", "filters"]); arrOf((r as Obj).filters, ["op", "column"]); } },
  { cmd: "browse_tables", check: (r) => { expect(Array.isArray(r)).toBe(true); expect((r as unknown[]).every((x) => typeof x === "string")).toBe(true); expect((r as unknown[]).length).toBeGreaterThan(0); } },
  { cmd: "browse_page", args: { table: "signins", filters: [], sort: null, offset: 0, limit: 10, queryId: "q" }, check: (r) => { keys(r, ["table", "columns", "rows", "offset", "total", "total_capped"]); const p = r as BrowsePage; expect(p.rows.length).toBe(10); expect(p.rows.every((x) => x.length === p.columns.length)).toBe(true); } },
  { cmd: "sql_schema", args: {}, check: (r) => arrOf(r, ["name", "comment", "kind", "columns"]) },
  { cmd: "sql_run", args: { sql: "select 1", limit: 5, queryId: "q", offset: 0 }, check: (r) => { keys(r, ["columns", "rows", "truncated", "ordered"]); const q = r as QueryResult; expect(q.rows.every((x) => x.length === q.columns.length)).toBe(true); } },
  { cmd: "sql_check", args: { sql: "SELECT rule_idd FROM findings" }, check: (r) => { keys(r, ["ok", "error"]); keys((r as Obj).error, ["message", "kind", "from", "to", "suggestions"]); } },
  { cmd: "sql_export_csv", args: { sql: "SELECT * FROM signins", path: "/o.csv", queryId: "e" }, check: (r) => { keys(r, ["rows", "capped"]); expect((r as Obj).rows).toBeGreaterThan(0); } },
  { cmd: "query_cancel", args: { queryId: "nothing-runs" }, check: (r) => expect(r).toBeNull() },
  { cmd: "indicators_active", check: (r) => arrOf(r, ["ioc_type", "value", "verdict"]) },
  { cmd: "share_export", args: { path: "/b.json" }, check: (r) => { keys(r, ["sha256", "items"]); expect((r as Obj).items).toBeGreaterThan(0); } },
  { cmd: "share_preview", args: { path: "/b.json" }, check: (r) => keys(r, ["sha256", "summary", "analyst", "exported_at", "items"]) },
  { cmd: "share_import", args: { path: "/b.json", sha256: "SHA" }, check: (r) => keys(r, ["bundle_sha256", "analyst", "new", "agrees", "conflicts", "missing", "superseded", "already_imported"]) },
];

describe("every command, valid arguments", () => {
  it("covers every command the mock answers", () => {
    expect(TABLE.map((t) => t.cmd).sort()).toEqual(MOCK_COMMANDS);
  });

  it.each(TABLE.map((t) => [t.cmd, t] as const))("%s returns the contract shape", async (_cmd, t) => {
    const m = await fresh();
    let args = t.args;
    if (t.cmd === "proposal_accept" || t.cmd === "proposal_discard") {
      const p = (await m.mockCall<QueueItem[]>("review_queue")).find((q) => q.source === "proposal");
      if (!p || p.source !== "proposal") throw new Error("no proposal in the queue");
      args = { ...t.args, bundleSha256: p.bundle_sha256, itemKey: p.item_key };
    }
    if (t.cmd === "share_import") args = { ...t.args, sha256: (await m.mockCall<{ sha256: string }>("share_preview", { path: "/b" })).sha256 };
    t.check(await m.mockCall(t.cmd, args));
  });
});

describe("state transitions", () => {
  it("accept, discard (decisions and proposals) remove exactly their item and write audit entries", async () => {
    const m = await fresh();
    const q0 = await m.mockCall<QueueItem[]>("review_queue");
    const d = q0.find((i) => i.source === "decision" && i.object_type === "finding");
    const p = q0.find((i) => i.source === "proposal");
    if (!d || d.source !== "decision" || !p || p.source !== "proposal") throw new Error("fixture lacks items");
    await m.mockCall("review_accept", { objectType: d.object_type, objectId: d.object_id, decisionSeq: d.decision_seq });
    await m.mockCall("proposal_discard", { bundleSha256: p.bundle_sha256, itemKey: p.item_key });
    const q1 = await m.mockCall<QueueItem[]>("review_queue");
    expect(q1.length).toBe(q0.length - 2);
    expect(q1.some((i) => i === d || (i.source === "decision" && i.object_id === d.object_id && i.decision_seq === d.decision_seq))).toBe(false);
    const detail = await m.mockCall<{ audit: { action: string }[] }>("finding_detail", { findingId: d.object_id });
    expect(detail.audit.some((a) => a.action === "review_accept")).toBe(true);
  });

  it("highlights set/get/clear round-trip per case", async () => {
    const m = await fresh();
    const sets = [{ name: "s", rules: [{ column: null, op: "contains", value: "x", colour: "red" }] }];
    await m.mockCall("highlights_set", { caseId: "a", sets });
    expect(await m.mockCall("highlights_get", { caseId: "a" })).toEqual(sets);
    expect(await m.mockCall("highlights_get", { caseId: "b" })).toEqual([]);
    await m.mockCall("highlights_clear", { caseId: "a" });
    expect(await m.mockCall("highlights_get", { caseId: "a" })).toEqual([]);
  });

  it("share import adds the bundle's proposals once, and refuses a stale sha", async () => {
    const m = await fresh();
    const pre = await m.mockCall<{ sha256: string; summary: { new: number } }>("share_preview", { path: "/b" });
    const n0 = (await m.mockCall<QueueItem[]>("review_queue")).length;
    await expect(m.mockCall("share_import", { path: "/b", sha256: "stale" })).rejects.toMatchObject({ kind: "invalid" });
    const s = await m.mockCall<{ already_imported: boolean }>("share_import", { path: "/b", sha256: pre.sha256 });
    expect(s.already_imported).toBe(false);
    const q = await m.mockCall<QueueItem[]>("review_queue");
    expect(q.length).toBe(n0 + pre.summary.new);
    expect(new Set(q.filter((i) => i.source === "proposal").map((i) => (i as { item_key: string }).item_key)).size).toBe(q.filter((i) => i.source === "proposal").length);
    expect((await m.mockCall<{ already_imported: boolean }>("share_import", { path: "/b", sha256: pre.sha256 })).already_imported).toBe(true);
    expect((await m.mockCall<QueueItem[]>("review_queue")).length).toBe(q.length);
  });

  it("timeline propose, edit, verify and reject change the list", async () => {
    const m = await fresh();
    type E = { entry_id: string; title: string; status: string };
    const n0 = (await m.mockCall<E[]>("timeline_list")).length;
    const w = await m.mockCall<{ entryId: string }>("timeline_propose", { args: { eventTime: "2026-08-14T10:00:00Z", title: "new", phase: "persistence", evidence: [] } });
    await m.mockCall("timeline_edit", { entryId: w.entryId, args: { title: "renamed" } });
    let l = await m.mockCall<E[]>("timeline_list");
    expect(l.length).toBe(n0 + 1);
    expect(l.find((e) => e.entry_id === w.entryId)?.title).toBe("renamed");
    await m.mockCall("timeline_verify", { entryId: w.entryId });
    expect((await m.mockCall<E[]>("timeline_list")).find((e) => e.entry_id === w.entryId)?.status).toBe("verified");
    await m.mockCall("timeline_reject", { entryId: w.entryId, reason: "x" });
    l = await m.mockCall<E[]>("timeline_list");
    expect(l.find((e) => e.entry_id === w.entryId)?.status).toBe("rejected");
    await expect(m.mockCall("timeline_verify", { entryId: "nope" })).rejects.toMatchObject({ kind: "not_found" });
  });
});

describe("api.call routing", () => {
  it("goes to the mock only when the compile-time constant is true", async () => {
    vi.resetModules();
    vi.stubGlobal("__SPARROW_MOCK__", true);
    try {
      const { call } = await import("../api");
      expect(await call("settings_get")).toMatchObject({ recent: expect.any(Array) });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
