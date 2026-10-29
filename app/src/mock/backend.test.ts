import { describe, expect, it, vi } from "vitest";
import { MOCK_COMMANDS, mockCall, mockOpen, mockSave } from "./backend";
import { GEN_COLUMNS, GEN_ROWS, genRows } from "./generated";
import apiSource from "../api.ts?raw";
import * as fx from "../test/fixtures";
import type { BrowsePage, CmdError, EventQuery, EventRow, EventsAdded, EventsPage, EventsSummary, Histogram, QueueItem, QueryResult, RowRef, SqlCheck, TimelineEntry } from "../api";

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
const Q: EventQuery = { fields: [], flag: "all", ai: "all" };
const EVENT_ROW_KEYS = Object.keys(fx.eventsList()[0]);
const ref = (r: EventRow): RowRef => ({ source_table: r.source_table, record_key: r.record_key });
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
  { cmd: "devices_list", args: {}, check: (r) => { arrOf(r, ["tenant_key", "device_id", "confidence", "reasons", "users", "malicious_ips", "other_ips", "sightings", "lifecycle"]); const d = (r as Obj[])[0]; keys(d.lifecycle, ["status", "registered", "removed", "disabled", "last_active", "latest_inventory_at"]); arrOf(d.sightings, ["device_id", "event_time", "activity", "source_table", "record_key"]); } },
  { cmd: "export_report", args: { path: "/o.md", reviewedOnly: true }, check: (r) => expect(r).toBeNull() },
  { cmd: "export_timeline_csv", args: { path: "/o.csv" }, check: (r) => expect(r).toBeNull() },
  { cmd: "export_workbook", args: { path: "/o.xlsx" }, check: (r) => expect(r).toBeNull() },
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
  { cmd: "ingest_discover", args: { path: "/evidence/run" }, check: (r) => { keys(r, ["path", "collections", "recognised", "unrecognised", "too_large", "unreadable", "max_file_bytes"]); arrOf((r as Obj).collections, ["tool", "root", "tenant_hint", "started_hint", "files"]); } },
  { cmd: "ingest_run", args: { path: "/evidence/run", target: "open", culture: null, detect: true, runId: "r-1" }, check: (r) => { keys(r, ["case_path", "cancelled", "report", "files_loaded", "error", "files_total", "rows_by_source", "file_notes", "not_loaded", "profile_error", "profile_warnings", "detect", "detect_error"]); expect((r as Obj).cancelled).toBe(false); arrOf((r as Obj).rows_by_source, ["source", "files", "rows"]); } },
  { cmd: "ingest_cancel", args: { runId: "r-0" }, check: (r) => expect(r).toBeNull() },
  { cmd: "ingest_unprofiled", check: (r) => expect(r).toEqual([]) },
  { cmd: "ingest_profile", check: (r) => keys(r, ["profile_error", "profile_warnings", "detect", "detect_error"]) },
  { cmd: "share_export", args: { path: "/b.json" }, check: (r) => { keys(r, ["sha256", "items"]); expect((r as Obj).items).toBeGreaterThan(0); } },
  { cmd: "share_preview", args: { path: "/b.json" }, check: (r) => keys(r, ["sha256", "summary", "analyst", "exported_at", "items"]) },
  { cmd: "events_page", args: { query: Q, sort: null, offset: 0, limit: 10 }, check: (r) => { keys(r, ["rows", "offset", "total", "total_capped"]); const p = r as EventsPage; expect(p.rows.length).toBe(10); expect(p.total).toBe(fx.eventsList().length); arrOf(p.rows, EVENT_ROW_KEYS); } },
  { cmd: "events_summary", args: { query: Q }, check: (r) => { keys(r, ["total", "suspicious", "malicious", "per_source", "hidden_trace_events"]); expect((r as EventsSummary).total).toBe(fx.eventsList().length); } },
  { cmd: "events_histogram", args: { query: Q, maxBuckets: 24 }, check: (r) => { keys(r, ["start", "bucket_seconds", "series", "findings"]); expect((r as Histogram).series.length).toBeGreaterThan(0); } },
  { cmd: "events_detail", args: { sourceTable: "ROW", recordKey: "ROW" }, check: (r) => { keys(r, ["row", "raw", "source_refs", "tags", "notes", "flag", "flag_sources"]); keys((r as Obj).row, EVENT_ROW_KEYS); } },
  { cmd: "events_suggest", args: { field: "source", prefix: "sign" }, check: (r) => expect(r).toEqual(["signin_interactive", "signin_noninteractive"]) },
  { cmd: "events_export_csv", args: { query: Q, path: "/o.csv" }, check: (r) => expect(r).toBe(fx.eventsList().length) },
  { cmd: "events_values", args: { query: Q, field: "source", prefix: "", limit: 200 }, check: (r) => { keys(r, ["values", "total"]); arrOf((r as Obj).values, ["value", "count"]); } },
  { cmd: "entity_summary", args: { entity: { kind: "session", value: "S" } }, check: (r) => { keys(r, ["entity", "first_seen", "last_seen", "events", "distinct", "open_findings", "roles_matched", "ip_intel", "device"]); keys((r as Obj).distinct, ["accounts", "ips", "countries", "asns", "devices", "sessions"]); } },
  { cmd: "entity_pivot", args: { entity: { kind: "account", value: "a@contoso.example" }, of: "ips", limit: 5 }, check: (r) => { keys(r, ["rows", "total"]); arrOf((r as Obj).rows, ["value", "label", "count", "first_seen", "last_seen", "is_new", "flag", "extra"]); expect(((r as Obj).rows as unknown[]).length).toBe(5); } },
  { cmd: "entity_findings", args: { entity: { kind: "account", value: "a@contoso.example" } }, check: (r) => arrOf(r, ["finding_id", "rule_id", "title", "severity", "status", "first_seen"]) },
  { cmd: "entity_coverage", args: { entity: { kind: "account", value: "a@contoso.example" } }, check: (r) => { keys(r, ["from", "to", "tenants"]); arrOf((r as Obj).tenants, ["tenant_key", "accounts", "sources"]); } },
  { cmd: "marks_flag_rows", args: { rows: "ROWS", level: "suspicious" }, check: (r) => keys(r, AUDIT) },
  { cmd: "marks_flag_value", args: { kind: "ip", value: "192.0.2.19", scope: null, level: "malicious" }, check: (r) => { keys(r, ["audit", "indicators"]); keys((r as { audit: unknown }).audit, AUDIT); } },
  { cmd: "marks_tag_rows", args: { rows: "ROWS", tag: "relay", add: true }, check: (r) => keys(r, AUDIT) },
  { cmd: "marks_list_tags", check: (r) => arrOf(r, ["name", "count", "agent_unreviewed"]) },
  { cmd: "marks_review", args: { rows: "AI_ROWS", accept: true }, check: (r) => arrOf(r, AUDIT) },
  { cmd: "notes_add_rows", args: { rows: "ROWS", text: "a note" }, check: (r) => { arrOf(r, AUDIT); expect((r as unknown[]).length).toBe(2); } },
  { cmd: "timeline_add_events", args: { args: { rows: "ROWS", mode: "group" } }, check: (r) => { keys(r, ["entryIds", "outcome"]); expect((r as EventsAdded).entryIds.length).toBe(1); } },
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
    // Row arguments name real events of the recorded list: two of them, or two carrying an agent mark.
    if (args && ("rows" in args || "recordKey" in args || (isObj(args.args) && "rows" in args.args))) {
      const list = fx.eventsList();
      const pick = (rows: EventRow[]) => rows.slice(0, 2).map(ref);
      const rows = args.rows === "AI_ROWS" ? pick(list.filter((r) => r.flag_ai || r.tags.some((x) => x.ai))) : pick(list);
      if (t.cmd === "events_detail") args = { sourceTable: rows[0].source_table, recordKey: rows[0].record_key };
      else if (isObj(args.args)) args = { args: { ...args.args, rows } };
      else args = { ...args, rows };
    }
    if (t.cmd === "share_import") args = { ...t.args, sha256: (await m.mockCall<{ sha256: string }>("share_preview", { path: "/b" })).sha256 };
    t.check(await m.mockCall(t.cmd, args));
  });
});

describe("mock import", () => {
  it("emits progress in order, and a cancel leaves the rest not loaded", async () => {
    const m = await fresh();
    await m.mockCall("case_open", { path: "/x.duckdb", allowUpgrade: false });
    const seen: string[] = [];
    const off = await m.mockOnIngestProgress((p) => seen.push(p.stage === "file" ? `file ${p.index}` : p.stage));
    const run = m.mockCall<{ cancelled: boolean; files_loaded: number; not_loaded: unknown[]; detect: unknown }>("ingest_run", { path: "/evidence/run", target: "open", culture: null, detect: true, runId: "r-2" });
    await new Promise((r) => setTimeout(r, 600));
    await m.mockCall("ingest_cancel", { runId: "r-2" });
    const r = await run;
    off();
    expect(seen.slice(0, 3)).toEqual(["discover", "collection", "file 1"]);
    expect(seen.at(-1)).toBe("profile");
    expect(r.cancelled).toBe(true);
    expect(r.files_loaded).toBeLessThan(6);
    expect(r.files_loaded + r.not_loaded.length).toBe(6);
    expect(r.detect).toBeNull();
  });

  it("refuses a read-only case, a folder with nothing, and a second run at once", async () => {
    const m = await fresh();
    await m.mockCall("case_open", { path: "/readonly.duckdb", allowUpgrade: false });
    await expect(m.mockCall("ingest_run", { path: "/evidence/run", target: "open", culture: null, detect: true, runId: "r-3" })).rejects.toMatchObject({ kind: "read_only" });
    await expect(m.mockCall("ingest_run", { path: "/evidence/empty", target: { new_case: "/c.duckdb" }, culture: null, detect: true, runId: "r-3" })).rejects.toMatchObject({ kind: "invalid" });
    expect((await m.mockCall<{ collections: unknown[] }>("ingest_discover", { path: "/evidence/empty" })).collections).toEqual([]);
    const first = m.mockCall("ingest_run", { path: "/evidence/run", target: { new_case: "/c.duckdb" }, culture: null, detect: false, runId: "r-4" });
    await new Promise((r) => setTimeout(r, 100));
    await expect(m.mockCall("ingest_run", { path: "/evidence/run", target: { new_case: "/d.duckdb" }, culture: null, detect: false, runId: "r-5" })).rejects.toMatchObject({ message: "an import is already running" });
    await m.mockCall("ingest_cancel", { runId: "r-4" });
    await first;
  });

  it("the dialogs answer a folder and a save path", async () => {
    const m = await fresh();
    expect(m.mockOpen({ directory: true })).toBe("/mock/evidence/invictus-run");
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

// ---------------------------------------------------------------- events grid, entity tabs and marks

describe("events mock: queries", () => {
  const page = async (m: typeof import("./backend"), q: Partial<EventQuery>, extra: Record<string, unknown> = {}) =>
    m.mockCall<EventsPage>("events_page", { query: { ...Q, ...q }, sort: null, offset: 0, limit: 500, ...extra });
  const summary = (m: typeof import("./backend"), q: Partial<EventQuery>) => m.mockCall<EventsSummary>("events_summary", { query: { ...Q, ...q } });
  const list = fx.eventsList();
  const bySource = (s: string) => list.filter((r) => r.source === s);

  it("pages newest first and sorts on a column; an unknown column is refused", async () => {
    const m = await fresh();
    const p = await m.mockCall<EventsPage>("events_page", { query: Q, sort: null, offset: 5, limit: 5 });
    expect(p.offset).toBe(5);
    expect(p.rows.map((r) => r.record_key)).toEqual(list.slice(5, 10).map((r) => r.record_key));
    const times = (await page(m, {})).rows.map((r) => Date.parse(r.event_time!));
    expect(times).toEqual([...times].sort((a, b) => b - a));
    const asc = await m.mockCall<EventsPage>("events_page", { query: Q, sort: { column: "event_time", descending: false }, offset: 0, limit: 3 });
    expect(Date.parse(asc.rows[0].event_time!)).toBe(Math.min(...times));
    await expect(m.mockCall("events_page", { query: Q, sort: { column: "nope", descending: false }, offset: 0, limit: 3 })).rejects.toMatchObject({ kind: "invalid" });
  });

  it("applies Harrier filter text: lists, excludes, wildcards, only-excludes", async () => {
    const m = await fresh();
    const total = list.length;
    const src = (text: string) => summary(m, { fields: [["source", text]] });
    expect((await src("signin_interactive")).total).toBe(bySource("signin_interactive").length);
    expect((await src("  signin_interactive , ual ")).total).toBe(bySource("signin_interactive").length + bySource("ual").length);
    expect((await src("!ual")).total).toBe(total - bySource("ual").length);
    expect((await src("signin_*,!signin_interactive")).total).toBe(bySource("signin_noninteractive").length);
    expect((await src("SIGNIN_*")).total).toBe(list.filter((r) => r.source.startsWith("signin_")).length);
    expect((await src("")).total).toBe(total);
    expect((await src("no_such_source")).total).toBe(0);
    // Account matches the actor or the owner, in any case.
    const someone = list.find((r) => r.owner_upn !== null && r.owner_upn.includes("@"))!.owner_upn!;
    const n = list.filter((r) => [r.actor_upn, r.owner_upn].some((u) => u?.toLowerCase() === someone.toLowerCase())).length;
    expect((await summary(m, { fields: [["account", someone.toUpperCase()]] })).total).toBe(n);
  });

  it("refuses awkward filter text instead of matching everything", async () => {
    const m = await fresh();
    for (const text of ["!", " ! ", ",,", ",", "a, !", "!,"]) {
      for (const read of [() => page(m, { fields: [["source", text]] }), () => summary(m, { fields: [["source", text]] })]) {
        await expect(read(), text).rejects.toMatchObject({ kind: "invalid", message: expect.stringContaining("Source filter") });
      }
    }
    await expect(summary(m, { from: "yesterday" })).rejects.toMatchObject({ kind: "invalid" });
    await expect(summary(m, { entity: { kind: "ip", value: "not-an-ip" } })).rejects.toMatchObject({ kind: "invalid" });
  });

  it("includes both ends of a range and filters by entity in any spelling", async () => {
    const m = await fresh();
    const at = list[10].event_time!;
    const same = list.filter((r) => r.event_time === at).length;
    expect((await summary(m, { from: at, to: at })).total).toBe(same);
    const last = list[0].event_time!;
    expect((await summary(m, { from: last })).total).toBe(list.filter((r) => r.event_time === last).length);
    const account = list.find((r) => r.actor_upn?.includes("@"))!.actor_upn!;
    const want = list.filter((r) => [r.actor_upn, r.owner_upn].some((u) => u?.toLowerCase() === account.toLowerCase())).length;
    const a = await summary(m, { entity: { kind: "account", value: `  ${account.toUpperCase()} ` } });
    const b = await summary(m, { entity: { kind: "account", value: account } });
    expect([a.total, b.total]).toEqual([want, want]);
  });

  it("counts flags in the summary and filters on flag and AI marks", async () => {
    const m = await fresh();
    const s = await summary(m, {});
    expect([s.total, s.suspicious, s.malicious, s.hidden_trace_events]).toEqual([
      list.length, list.filter((r) => r.flag === "suspicious").length, list.filter((r) => r.flag === "malicious").length, 0,
    ]);
    expect(s.malicious).toBe(1);
    expect(s.per_source.map(([k]) => k)).toEqual(["ual", "signin_interactive", "signin_noninteractive", "message_trace", "entra_audit", "mailbox_audit", "risk_detection", "azure_activity", "security_alert"]);
    expect((await page(m, { flag: "malicious" })).rows.length).toBe(1);
    const ai = await page(m, { ai: "unreviewed" });
    expect(ai.rows.length).toBe(list.filter((r) => r.flag_ai || r.tags.some((t) => t.ai)).length);
    expect(ai.rows.length).toBeGreaterThan(0);
  });

  it("builds a histogram whose buckets add up to the matching events, with the core's bucket sizes", async () => {
    const m = await fresh();
    const hist = (q: Partial<EventQuery>, max: number) => m.mockCall<Histogram>("events_histogram", { query: { ...Q, ...q }, maxBuckets: max });
    const h = await hist({}, 12);
    const days = h.series[0][1].length;
    expect(days).toBeLessThanOrEqual(41);
    expect([60, 300, 900, 3600, 10800, 21600, 43200, 86400]).toContain(h.bucket_seconds);
    expect(h.series.every(([, c]) => c.length === days)).toBe(true);
    expect(h.series.flatMap(([, c]) => c).reduce((a, b) => a + b, 0)).toBe(list.length);
    const fine = await hist({}, 1000);
    expect(fine.bucket_seconds).toBeLessThan(h.bucket_seconds);
    // A range of one instant still returns the event; an empty result is no buckets, not an error.
    const at = list[3].event_time!;
    const one = await hist({ from: at, to: at }, 24);
    expect(one.series.flatMap(([, c]) => c).reduce((a, b) => a + b, 0)).toBe(list.filter((r) => r.event_time === at).length);
    expect((await hist({ fields: [["source", "no_such_source"]] }, 24)).series).toEqual([]);
    await expect(hist({}, 0)).rejects.toMatchObject({ kind: "invalid" });
    // The empty histogram's start is core's rule (the query's `from`, else its `to`, else the epoch), written with
    // six fractional digits like every core time, and does not depend on the clock.
    const none = [["source", "no_such_source"]] as EventQuery["fields"];
    const e1 = await hist({ fields: none, to: "2026-09-01T10:00:00Z" }, 24);
    expect([e1.start, e1.bucket_seconds, e1.series, e1.findings]).toEqual(["2026-09-01T10:00:00.000000Z", 60, [], []]);
    const e2 = await hist({ fields: none, from: "2026-08-01T00:00:00Z", to: "2026-09-01T10:00:00Z" }, 24);
    expect(e2.start).toBe("2026-08-01T00:00:00.000000Z");
    const e3 = await hist({ fields: none }, 24);
    expect(e3.start).toBe("1970-01-01T00:00:00.000000Z");
    expect((await hist({ fields: none }, 24)).start).toBe(e3.start);
    // Times are in core's six-digit form when there is data too.
    expect(h.start).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/);
    // The bucket count asked for is clamped to 500 (so 500, 501 and a huge number agree), and 0 is refused.
    const at500 = await hist({}, 500);
    for (const over of [501, 100_000, Number.MAX_SAFE_INTEGER]) expect(await hist({}, over)).toEqual(at500);
    // 3-hour buckets are the smallest that fit 500; the boundary is the exact bucket count of that layout.
    const n3h = at500.series[0][1].length;
    expect([at500.bucket_seconds, n3h]).toEqual([10_800, 294]);
    expect((await hist({}, n3h)).bucket_seconds).toBe(10_800);
    expect((await hist({}, n3h - 1)).bucket_seconds).toBe(21_600);
    // A range wider than core's hard cap (2,000 buckets) widens the bucket to whole days instead: an exact
    // 1,999-day span is 2,000 day buckets, 2,000 days is 2,001, so two-day buckets (1,001).
    const day = 86_400_000;
    const first = Date.parse(list[list.length - 1].event_time!);
    const wide = async (days: number) => {
      const w = await hist({ from: new Date(first).toISOString(), to: new Date(first + days * day).toISOString(), fields: [["source", "ual"]] }, 500);
      return [w.bucket_seconds, w.series[0][1].length];
    };
    expect(await wide(1_999)).toEqual([86_400, 2_000]);
    expect(await wide(2_000)).toEqual([172_800, 1_001]);
  });

  it("answers detail, suggestions and the CSV export of the current query", async () => {
    const m = await fresh();
    const r = list[0];
    const d = await m.mockCall<{ row: EventRow; flag: string | null; flag_sources: { origin: string }[] }>("events_detail", { sourceTable: r.source_table, recordKey: r.record_key });
    expect(d.row.record_key).toBe(r.record_key);
    expect([d.flag, d.flag_sources.map((f) => f.origin)]).toEqual(["malicious", ["row"]]);
    await expect(m.mockCall("events_detail", { sourceTable: r.source_table, recordKey: "nope" })).rejects.toMatchObject({ kind: "not_found" });
    await expect(m.mockCall("events_detail", { sourceTable: "ual", recordKey: "x" })).rejects.toMatchObject({ kind: "invalid" });
    const mail = list.find((x) => x.actor_upn?.includes("@"))!.actor_upn!.toLowerCase();
    const sg = await m.mockCall<string[]>("events_suggest", { field: "account", prefix: mail.slice(0, 4).toUpperCase() });
    expect(sg).toContain(mail);
    expect(sg.every((s) => s.toLowerCase().startsWith(mail.slice(0, 4)))).toBe(true);
    expect(sg).toEqual([...sg].sort());
    expect(await m.mockCall("events_suggest", { field: "tag", prefix: "phish" })).toEqual(["phish-lure"]);
    const q = { ...Q, fields: [["source", "ual"]] };
    expect(await m.mockCall("events_export_csv", { query: q, path: "/o.csv" })).toBe(bySource("ual").length);
    await expect(m.mockCall("events_export_csv", { query: q, path: "" })).rejects.toMatchObject({ kind: "invalid" });
  });

  it("lists a field's values with counts under the other filters, ignoring its own", async () => {
    const m = await fresh();
    type V = { values: { value: string; count: number }[]; total: number };
    const values = (q: unknown, field: string, prefix = "", limit = 200) => m.mockCall<V>("events_values", { query: q, field, prefix, limit });
    const all = await values(Q, "source");
    // Most events first, then by value; every source counted (the hidden trace rows too: they can be ticked).
    const want = new Map<string, number>();
    for (const r of list) want.set(r.source, (want.get(r.source) ?? 0) + 1);
    expect(all.values).toEqual([...want].map(([value, count]) => ({ value, count })).sort((a, b) => b.count - a.count || (a.value < b.value ? -1 : 1)));
    expect(all.total).toBe(want.size);
    // Its own filter is left out; another field's applies.
    expect(await values({ ...Q, fields: [["source", "ual"]] }, "source")).toEqual(all);
    const ual = await values({ ...Q, fields: [["source", "ual"]] }, "operation");
    expect(ual.values.reduce((n, v) => n + v.count, 0)).toBe(bySource("ual").filter((r) => r.operation).length);
    // A prefix (case-insensitive, `*` wildcard) and a limit, the total uncut.
    expect((await values(Q, "source", "SIGN")).values.map((v) => v.value).sort()).toEqual(["signin_interactive", "signin_noninteractive"]);
    expect((await values(Q, "source", "*active")).values.map((v) => v.value).sort()).toEqual(["signin_interactive", "signin_noninteractive"]);
    const cut = await values(Q, "source", "", 2);
    expect([cut.values.length, cut.total]).toEqual([2, want.size]);
    // A quoted value is literal: `"*"` names no source (unquoted it is every source).
    expect((await m.mockCall<{ total: number }>("events_page", { query: { ...Q, fields: [["source", '"*"']] }, sort: null, offset: 0, limit: 1 })).total).toBe(0);
    await expect(values({ ...Q, fields: [["ip", "!"]] }, "source")).rejects.toMatchObject({ kind: "invalid", message: expect.stringMatching(/^IP filter: /) });
    await expect(values({ ...Q, search: "x" }, "source")).rejects.toMatchObject({ kind: "invalid" });
    await expect(values(Q, "source", "", 0)).rejects.toMatchObject({ kind: "invalid", message: "a values list needs a limit of at least 1" });
  });

  it("needs a query id for a raw search, and a slow search is cancellable", async () => {
    const m = await fresh();
    const q = { ...Q, search: "192.0.2" };
    for (const cmd of ["events_page", "events_summary", "events_histogram", "events_export_csv"]) {
      await expect(m.mockCall(cmd, { query: q, sort: null, offset: 0, limit: 5, maxBuckets: 5, path: "/o" }), cmd).rejects.toMatchObject({ kind: "invalid", message: expect.stringContaining("query id") });
    }
    const hits = await m.mockCall<EventsSummary>("events_summary", { query: q, queryId: "s-1" });
    expect(hits.total).toBe(list.filter((r) => JSON.stringify(r).toLowerCase().includes("192.0.2")).length);
    expect(hits.total).toBeGreaterThan(0);
    const slow = m.mockCall("events_page", { query: { ...Q, search: "slow" }, sort: null, offset: 0, limit: 5, queryId: "s-slow" });
    const settled = slow.then(() => "done", (e: CmdError) => e.kind);
    await new Promise((r) => setTimeout(r, 100));
    await m.mockCall("query_cancel", { queryId: "s-slow" });
    expect(await settled).toBe("interrupted");
  });
});

describe("events mock: entity tabs", () => {
  it("keeps one stored spelling per entity and refuses what is not an entity", async () => {
    const m = await fresh();
    const s = (value: string, kind = "ip") => m.mockCall<{ entity: Record<string, string> }>("entity_summary", { entity: { kind, value } });
    expect((await s("  2001:DB8::1 ")).entity).toEqual({ kind: "ip", value: "2001:db8::1" });
    expect((await s("JDoe@Contoso.Example", "account")).entity).toEqual({ kind: "account", value: "jdoe@contoso.example" });
    expect((await s("4F1C-9A2E", "session")).entity).toEqual({ kind: "session", value: "4f1c-9a2e" });
    for (const bad of ["not-an-ip", "", "  "]) await expect(s(bad)).rejects.toMatchObject({ kind: "invalid" });
    await expect(s("x", "tenant")).rejects.toMatchObject({ kind: "invalid" });
  });

  it("has the right tiles per kind, and empties them for a range past the entity", async () => {
    const m = await fresh();
    for (const kind of ["account", "ip", "device", "session"] as const) {
      const rec = fx.entitySummary(kind);
      const value = kind === "ip" ? "192.0.2.5" : "x1";
      const got = await m.mockCall<typeof rec>("entity_summary", { entity: { kind, value } });
      expect([got.events, got.distinct, got.open_findings, got.first_seen]).toEqual([rec.events, rec.distinct, rec.open_findings, rec.first_seen]);
      expect(rec.events).toBeGreaterThan(0);
      const none = await m.mockCall<typeof rec>("entity_summary", { entity: { kind, value }, from: "2030-01-01T00:00:00Z" });
      expect([none.events, none.first_seen, Object.values(none.distinct).every((n) => n === 0)]).toEqual([0, null, true]);
    }
  });

  it("limits a pivot, reports its full total and only offers the tables the kind has", async () => {
    const m = await fresh();
    const e = { kind: "account", value: "a@contoso.example" };
    const full = await m.mockCall<{ rows: unknown[]; total: number }>("entity_pivot", { entity: e, of: "ips" });
    const two = await m.mockCall<{ rows: unknown[]; total: number }>("entity_pivot", { entity: e, of: "ips", limit: 2 });
    expect(two.rows).toEqual(full.rows.slice(0, 2));
    expect(two.total).toBe(full.total);
    expect(full.total).toBeGreaterThan(full.rows.length);
    await expect(m.mockCall("entity_pivot", { entity: e, of: "ips", limit: 0 })).rejects.toMatchObject({ kind: "invalid" });
    await expect(m.mockCall("entity_pivot", { entity: e, of: "accounts" })).rejects.toMatchObject({ kind: "invalid" });
    await expect(m.mockCall("entity_pivot", { entity: e, of: "device_changes" })).rejects.toMatchObject({ kind: "invalid" });
    const changes = await m.mockCall<{ rows: { extra: Record<string, unknown> }[] }>("entity_pivot", { entity: { kind: "device", value: "d1" }, of: "device_changes" });
    expect(changes.rows.length).toBeGreaterThan(0);
    expect(Object.keys(changes.rows[0].extra).sort()).toEqual(["actor", "record_key", "result", "source_table", "target"]);
    expect((await m.mockCall<{ rows: unknown[] }>("entity_pivot", { entity: e, of: "ips", to: "2001-01-01T00:00:00Z" })).rows).toEqual([]);
    expect(await m.mockCall("entity_findings", { entity: e, from: "2030-01-01T00:00:00Z" })).toEqual([]);
    expect((await m.mockCall<unknown[]>("entity_findings", { entity: e })).length).toBeGreaterThan(0);
    // Outside the entity's events the range is still judged.
    const far = await m.mockCall<{ from: string; to: string; tenants: unknown[] }>("entity_coverage", { entity: e, from: "2030-01-01T00:00:00Z" });
    expect([far.from, far.tenants.length]).toEqual(["2030-01-01", 1]);
    expect((await m.mockCall<{ tenants: unknown[] }>("entity_coverage", { entity: e })).tenants).toHaveLength(1);
  });
});

describe("events mock: marks and add to timeline", () => {
  const list = fx.eventsList();
  const plain = list.filter((r) => r.flag === null && r.tags.length === 0 && r.note_count === 0);
  const pageOf = (m: typeof import("./backend"), q: Partial<EventQuery> = {}) =>
    m.mockCall<EventsPage>("events_page", { query: { ...Q, ...q }, sort: null, offset: 0, limit: 500 });
  const find = async (m: typeof import("./backend"), r: EventRow) => (await pageOf(m)).rows.find((x) => x.record_key === r.record_key)!;

  it("flags rows and shows it on the next page; clearing removes it", async () => {
    const m = await fresh();
    const [a, b] = plain;
    const e = await m.mockCall<{ action: string; object_type: string }>("marks_flag_rows", { rows: [ref(a), ref(b)], level: "suspicious" });
    expect([e.action, e.object_type]).toEqual(["flag_rows", "event_flag"]);
    expect([(await find(m, a)).flag, (await find(m, b)).flag_ai]).toEqual(["suspicious", false]);
    expect((await summary(m)).suspicious).toBe(list.filter((r) => r.flag === "suspicious").length + 2);
    await m.mockCall("marks_flag_rows", { rows: [ref(a)], level: null });
    expect((await find(m, a)).flag).toBeNull();
    await expect(m.mockCall("marks_flag_rows", { rows: [], level: "malicious" })).rejects.toMatchObject({ kind: "invalid" });
    await expect(m.mockCall("marks_flag_rows", { rows: [{ source_table: a.source_table, record_key: "ghost" }], level: "malicious" })).rejects.toMatchObject({ kind: "decision" });
    await expect(m.mockCall("marks_flag_rows", { rows: [ref(a)], level: "bad" })).rejects.toMatchObject({ kind: "invalid" });
  });
  const summary = (m: typeof import("./backend")) => m.mockCall<EventsSummary>("events_summary", { query: Q });

  it("malicious_on_an_ip_or_account_reports_the_indicators_added_or_updated", async () => {
    const m = await fresh();
    const flag = (kind: string, value: string, level: string | null, scope: unknown = null) =>
      m.mockCall<{ indicators: { tenant_key: string | null; indicator_id: string; created: boolean }[] }>("marks_flag_value", { kind, value, scope, level });
    const ip = plain.find((r) => r.ip !== null)!.ip!;
    const tenants = [...new Set(list.filter((r) => r.ip === ip).map((r) => r.tenant_key))];
    // Suspicious, and kinds core makes no indicator for: none reported.
    expect((await flag("ip", ip, "suspicious")).indicators).toEqual([]);
    expect((await flag("asn", "64496", "malicious")).indicators).toEqual([]);
    expect((await flag("ip", ip, null)).indicators).toEqual([]);
    // New: one per tenant of the matching events.
    const first = (await flag("ip", ip, "malicious")).indicators;
    expect(first.map((i) => i.tenant_key).sort()).toEqual([...tenants].sort());
    expect(first.every((i) => i.created)).toBe(true);
    // Flagged again, the indicators exist: updated, same ids.
    await flag("ip", ip, null);
    const again = (await flag("ip", ip, "malicious")).indicators;
    expect(again.map((i) => [i.indicator_id, i.created])).toEqual(first.map((i) => [i.indicator_id, false]));
    // No event matches: a flag, but no tenant to attach an indicator to.
    expect((await flag("ip", "198.51.100.200", "malicious")).indicators).toEqual([]);
    expect((await flag("account", "ghost@contoso.example", "malicious")).indicators).toEqual([]);
  });

  it("a standing value flag covers every event with the value, and a scope narrows it", async () => {
    const m = await fresh();
    const ip = plain.find((r) => r.ip !== null && plain.filter((x) => x.ip === r.ip).length > 1)!.ip!;
    await m.mockCall("marks_flag_value", { kind: "ip", value: ip, scope: null, level: "malicious" });
    const hit = list.filter((r) => r.ip === ip);
    const covered = new Set([...hit, ...list.filter((r) => r.flag === "malicious")].map((r) => r.record_key));
    expect((await pageOf(m, { flag: "malicious" })).rows.map((r) => r.record_key).sort()).toEqual([...covered].sort());
    const d = await m.mockCall<{ flag_sources: { origin: string; kind: string; value: string }[] }>("events_detail", { sourceTable: hit[0].source_table, recordKey: hit[0].record_key });
    expect(d.flag_sources.map((f) => [f.origin, f.kind, f.value])).toContainEqual(["value", "ip", ip]);
    await m.mockCall("marks_flag_value", { kind: "ip", value: ip, scope: null, level: null });
    expect((await pageOf(m, { flag: "malicious" })).rows.length).toBe(1);
    // Scoped to an account: only that account's events with the IP.
    const who = hit.find((r) => r.actor_upn)!.actor_upn!;
    await m.mockCall("marks_flag_value", { kind: "ip", value: ip, scope: { kind: "account", value: who.toUpperCase() }, level: "suspicious" });
    const scoped = (await pageOf(m, { flag: "suspicious" })).rows.filter((r) => r.ip === ip);
    // (A row with its own malicious flag stays malicious: the strongest flag wins.)
    const mine = hit.filter((r) => [r.actor_upn, r.owner_upn].some((u) => u?.toLowerCase() === who.toLowerCase()));
    expect(mine.length).toBeGreaterThan(0);
    expect(scoped.map((r) => r.record_key).sort()).toEqual(mine.filter((r) => r.flag !== "malicious").map((r) => r.record_key).sort());
    await expect(m.mockCall("marks_flag_value", { kind: "colour", value: "x", scope: null, level: "malicious" })).rejects.toMatchObject({ kind: "invalid" });
  });

  it("tags rows (lower-case), counts them, and removes them", async () => {
    const m = await fresh();
    const [a, b] = plain;
    await m.mockCall("marks_tag_rows", { rows: [ref(a), ref(b)], tag: "  Relay-Session ", add: true });
    expect((await find(m, a)).tags).toEqual([{ name: "relay-session", ai: false }]);
    expect(await m.mockCall<{ name: string; count: number }[]>("marks_list_tags")).toContainEqual({ name: "relay-session", count: 2, agent_unreviewed: 0 });
    expect((await pageOf(m, { fields: [["tag", "RELAY-SESSION"]] })).total).toBe(2);
    await m.mockCall("marks_tag_rows", { rows: [ref(a)], tag: "relay-session", add: false });
    expect((await pageOf(m, { fields: [["tag", "relay-session"]] })).total).toBe(1);
    await expect(m.mockCall("marks_tag_rows", { rows: [ref(a)], tag: "  ", add: true })).rejects.toMatchObject({ kind: "invalid" });
  });

  it("confirms or removes agent marks, and says when nothing was pending", async () => {
    const m = await fresh();
    const aiFlag = list.find((r) => r.flag_ai)!;
    const aiTag = list.find((r) => r.tags.some((t) => t.ai))!;
    const done = await m.mockCall<{ object_type: string }[]>("marks_review", { rows: [ref(aiFlag), ref(aiTag)], accept: true });
    expect(done.map((e) => e.object_type).sort()).toEqual(["event_flag", "event_tag"]);
    expect([(await find(m, aiFlag)).flag, (await find(m, aiFlag)).flag_ai]).toEqual([aiFlag.flag, false]);
    expect((await find(m, aiTag)).tags.every((t) => !t.ai)).toBe(true);
    expect(await m.mockCall("marks_review", { rows: [ref(aiFlag)], accept: true })).toEqual([]);
    const m2 = await fresh();
    await m2.mockCall("marks_review", { rows: [ref(aiFlag), ref(aiTag)], accept: false });
    expect((await find(m2, aiFlag)).flag).toBeNull();
    expect((await find(m2, aiTag)).tags.some((t) => t.ai)).toBe(false);
  });

  it("writes one note per row, shown on the row, and caps the rows", async () => {
    const m = await fresh();
    const [a, b] = plain;
    const done = await m.mockCall<{ action: string }[]>("notes_add_rows", { rows: [ref(a), ref(b), ref(a)], text: "seen in relay" });
    expect(done.map((e) => e.action)).toEqual(["add_note", "add_note"]);
    expect([(await find(m, a)).note_count, (await find(m, b)).latest_note]).toEqual([1, "seen in relay"]);
    const d = await m.mockCall<{ notes: { text: string }[] }>("events_detail", { sourceTable: a.source_table, recordKey: a.record_key });
    expect(d.notes.map((n) => n.text)).toEqual(["seen in relay"]);
    await expect(m.mockCall("notes_add_rows", { rows: [ref(a)], text: "  " })).rejects.toMatchObject({ kind: "decision" });
  });

  it("refuses every write on a read-only case and changes nothing", async () => {
    const m = await fresh();
    await m.mockCall("case_open", { path: "/cases/readonly.duckdb", allowUpgrade: false });
    const [a] = plain;
    const writes: [string, Record<string, unknown>][] = [
      ["marks_flag_rows", { rows: [ref(a)], level: "malicious" }],
      ["marks_flag_value", { kind: "ip", value: "192.0.2.19", scope: null, level: "malicious" }],
      ["marks_tag_rows", { rows: [ref(a)], tag: "x", add: true }],
      ["marks_review", { rows: [ref(a)], accept: true }],
      ["notes_add_rows", { rows: [ref(a)], text: "x" }],
      ["timeline_add_events", { args: { rows: [ref(a)], mode: "group" } }],
    ];
    const before = await m.mockCall<unknown[]>("timeline_list");
    for (const [cmd, args] of writes) await expect(m.mockCall(cmd, args), cmd).rejects.toMatchObject({ kind: "read_only" });
    expect(await find(m, a)).toEqual(a);
    expect(await m.mockCall<unknown[]>("timeline_list")).toEqual(before);
    expect(writes.length).toBe(6);
  });

  it("adds events to the timeline one by one or as one grouped entry", async () => {
    const m = await fresh();
    const n0 = (await m.mockCall<TimelineEntry[]>("timeline_list")).length;
    const signins = list.filter((r) => r.source === "signin_interactive");
    const refs = signins.slice(0, 3).map(ref);
    const each = await m.mockCall<EventsAdded>("timeline_add_events", { args: { rows: refs, mode: "each" } });
    expect([each.entryIds.length, each.outcome]).toEqual([3, "Added 3 timeline entries"]);
    const grouped = await m.mockCall<EventsAdded>("timeline_add_events", { args: { rows: refs, mode: "group", title: " Relay sign-ins " } });
    expect(grouped.outcome).toBe("Added 1 grouped timeline entry covering 3 events");
    const all = await m.mockCall<TimelineEntry[]>("timeline_list");
    expect(all.length).toBe(n0 + 4);
    const g = all.find((e) => e.entry_id === grouped.entryIds[0])!;
    const times = signins.slice(0, 3).map((r) => Date.parse(r.event_time!));
    expect([g.title, g.phase, g.status, g.review_state, g.event_count, g.evidence.length]).toEqual(["Relay sign-ins", "initial_access", "verified", "accepted", 3, 3]);
    expect([Date.parse(g.event_time), Date.parse(g.end_time!)]).toEqual([Math.min(...times), Math.max(...times)]);
    const e1 = all.find((e) => e.entry_id === each.entryIds[0])!;
    expect([e1.event_count, e1.end_time, e1.evidence.length]).toEqual([null, null, 1]);
    // From a query: every match is cited, not a page of them.
    const q = await m.mockCall<EventsAdded>("timeline_add_events", { args: { query: { ...Q, fields: [["source", "ual"]] }, mode: "group", phase: "persistence" } });
    const gq = (await m.mockCall<TimelineEntry[]>("timeline_list")).find((e) => e.entry_id === q.entryIds[0])!;
    expect([gq.event_count, gq.evidence.length, gq.phase]).toEqual([list.filter((r) => r.source === "ual").length, list.filter((r) => r.source === "ual").length, "persistence"]);
    // Bad calls.
    const bad = (args: Record<string, unknown>) => m.mockCall("timeline_add_events", { args });
    await expect(bad({ mode: "group" })).rejects.toMatchObject({ kind: "invalid" });
    await expect(bad({ rows: refs, query: Q, mode: "group" })).rejects.toMatchObject({ kind: "invalid" });
    await expect(bad({ rows: refs, mode: "group", phase: "bogus" })).rejects.toMatchObject({ kind: "invalid" });
    await expect(bad({ query: { ...Q, fields: [["source", "none"]] }, mode: "group" })).rejects.toMatchObject({ kind: "invalid" });
    await expect(bad({ rows: [{ source_table: refs[0].source_table, record_key: "ghost" }], mode: "each" })).rejects.toMatchObject({ kind: "decision" });
  });
});
