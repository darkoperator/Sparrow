import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

import * as api from "./api";
import { call, isCmdError } from "./api";

describe("call", () => {
  beforeEach(() => {
    invoke.mockReset();
  });

  it("passes the command and its args to invoke and returns the result", async () => {
    invoke.mockResolvedValue({ ok: 1 });
    await expect(call("case_open", { path: "/c.duckdb" })).resolves.toEqual({ ok: 1 });
    expect(invoke).toHaveBeenCalledWith("case_open", { path: "/c.duckdb" });
  });

  it("rethrows a command error unchanged", async () => {
    invoke.mockRejectedValue({ kind: "writer_busy", message: "busy" });
    await expect(call("case_open")).rejects.toEqual({ kind: "writer_busy", message: "busy" });
  });

  it("keeps an interrupted query's kind (a cancelled sql_run)", async () => {
    invoke.mockRejectedValue({ kind: "interrupted", message: "the query was cancelled" });
    await expect(call("sql_run")).rejects.toEqual({ kind: "interrupted", message: "the query was cancelled" });
  });

  it("turns any other rejection into an internal command error", async () => {
    invoke.mockRejectedValue("command case_x not found");
    await expect(call("case_x")).rejects.toEqual({ kind: "internal", message: "command case_x not found" });
  });

  it("turns an error with an unknown kind into an internal command error", async () => {
    invoke.mockRejectedValue({ kind: "timeout", message: "plugin timed out" });
    await expect(call("case_open")).rejects.toEqual({ kind: "internal", message: "plugin timed out" });
  });
});

describe("isCmdError", () => {
  it("accepts only {kind, message} with string fields", () => {
    expect(isCmdError({ kind: "invalid", message: "m" })).toBe(true);
    expect(isCmdError({ kind: "invalid" })).toBe(false);
    expect(isCmdError({ kind: 1, message: "m" })).toBe(false);
    expect(isCmdError({ kind: "timeout", message: "m" })).toBe(false);
    for (const kind of [
      "not_found",
      "invalid",
      "decision",
      "writer_busy",
      "read_only",
      "no_case",
      "needs_upgrade",
      "needs_acknowledge",
      "internal",
    ]) {
      expect(isCmdError({ kind, message: "m" })).toBe(true);
    }
    expect(isCmdError("invalid")).toBe(false);
    expect(isCmdError(null)).toBe(false);
  });
});

describe("events, entity and marks commands", () => {
  const query: api.EventQuery = { entity: { kind: "ip", value: "192.0.2.19" }, fields: [["source", "ual"]], flag: "all", ai: "all" };
  const rows: api.RowRef[] = [{ source_table: "ual_rows", record_key: "k1" }];
  const entity: api.EntityArg = { kind: "session", value: "S" };

  // [wrapper, expected command, expected argument names (what the Rust command takes, camelCased by Tauri)]
  const CASES: [string, () => Promise<unknown>, string, string[]][] = [
    ["eventsPage", () => api.eventsPage(query, null, 0, 50, "q1"), "events_page", ["limit", "offset", "query", "queryId", "sort"]],
    ["eventsSummary", () => api.eventsSummary(query, "q1"), "events_summary", ["query", "queryId"]],
    ["eventsHistogram", () => api.eventsHistogram(query, 24, "q1"), "events_histogram", ["maxBuckets", "query", "queryId"]],
    ["eventsDetail", () => api.eventsDetail("ual_rows", "k1"), "events_detail", ["recordKey", "sourceTable"]],
    ["eventsSuggest", () => api.eventsSuggest("account", "jd"), "events_suggest", ["field", "prefix"]],
    ["eventsExportCsv", () => api.eventsExportCsv(query, "/o.csv", "q1"), "events_export_csv", ["path", "query", "queryId"]],
    ["entitySummary", () => api.entitySummary(entity, "2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z"), "entity_summary", ["entity", "from", "to"]],
    ["entityPivot", () => api.entityPivot(entity, "ips", "2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z", 25), "entity_pivot", ["entity", "from", "limit", "of", "to"]],
    ["entityFindings", () => api.entityFindings(entity, "2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z"), "entity_findings", ["entity", "from", "to"]],
    ["marksFlagRows", () => api.marksFlagRows(rows, "malicious"), "marks_flag_rows", ["level", "rows"]],
    ["marksFlagValue", () => api.marksFlagValue("ip", "192.0.2.19", entity, "suspicious"), "marks_flag_value", ["kind", "level", "scope", "value"]],
    ["marksTagRows", () => api.marksTagRows(rows, "relay", true), "marks_tag_rows", ["add", "rows", "tag"]],
    ["marksListTags", () => api.marksListTags(), "marks_list_tags", []],
    ["marksReview", () => api.marksReview(rows, false), "marks_review", ["accept", "rows"]],
    ["notesAddRows", () => api.notesAddRows(rows, "a note"), "notes_add_rows", ["rows", "text"]],
    ["timelineAddEvents", () => api.timelineAddEvents({ query, mode: "group", title: "t", phase: "persistence" }), "timeline_add_events", ["args"]],
  ];

  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue(null);
  });

  it.each(CASES)("%s calls %s with exactly its argument names", async (_name, run, cmd, names) => {
    await run();
    expect(invoke).toHaveBeenCalledTimes(1);
    const [got, args] = invoke.mock.calls[0] as [string, Record<string, unknown> | undefined];
    expect(got).toBe(cmd);
    expect(Object.keys(args ?? {}).sort()).toEqual(names);
  });

  it("passes the values through unchanged", async () => {
    await api.eventsPage(query, { column: "event_time", descending: false }, 100, 50, "q1");
    expect(invoke).toHaveBeenLastCalledWith("events_page", { query, sort: { column: "event_time", descending: false }, offset: 100, limit: 50, queryId: "q1" });
    await api.entityPivot(entity, "device_changes");
    expect(invoke).toHaveBeenLastCalledWith("entity_pivot", { entity, of: "device_changes", from: undefined, to: undefined, limit: undefined });
    await api.marksFlagRows(rows, null);
    expect(invoke).toHaveBeenLastCalledWith("marks_flag_rows", { rows, level: null });
    await api.marksFlagValue("asn", "64496", null, null);
    expect(invoke).toHaveBeenLastCalledWith("marks_flag_value", { kind: "asn", value: "64496", scope: null, level: null });
    await api.timelineAddEvents({ rows, mode: "each" });
    expect(invoke).toHaveBeenLastCalledWith("timeline_add_events", { args: { rows, mode: "each" } });
  });

  it("returns what the command returns, and a command error unchanged", async () => {
    invoke.mockResolvedValueOnce({ entryIds: ["e1"], outcome: "Added 1 timeline entry" });
    await expect(api.timelineAddEvents({ rows, mode: "each" })).resolves.toEqual({ entryIds: ["e1"], outcome: "Added 1 timeline entry" });
    invoke.mockRejectedValueOnce({ kind: "read_only", message: "the case is read-only" });
    await expect(api.marksTagRows(rows, "x", true)).rejects.toEqual({ kind: "read_only", message: "the case is read-only" });
  });

  it("serializes no key for an omitted optional argument (the backend reads it as none)", async () => {
    await api.eventsSummary({ fields: [], flag: "all", ai: "all" });
    const args = invoke.mock.calls[0][1] as Record<string, unknown>;
    expect(JSON.parse(JSON.stringify(args))).toEqual({ query: { fields: [], flag: "all", ai: "all" } });
  });
});
