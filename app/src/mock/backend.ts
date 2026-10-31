// DEV ONLY: a fake backend so the UI can be inspected in a plain browser (`npm run dev:mock`). Loaded by a dynamic
// import behind `MOCK_BACKEND`, so a production build holds none of it. All data is synthetic.
import type {
  AgentActivity,
  AuditEntry,
  CaseChanged,
  CaseInfo,
  CmdError,
  CmdErrorKind,
  DiscoveryPreview,
  EntryEditArgs,
  EntryWritten,
  Filter,
  HighlightSet,
  IngestProgress,
  IngestResult,
  IngestTarget,
  NewEntryArgs,
  PreviewFile,
  QueryResult,
  QueueItem,
  Settings,
  Sort,
  SqlCheck,
  SqlExported,
  TimelineEntry,
} from "../api";
import { ACCESS_TITLES } from "../api";
import * as fx from "../test/fixtures";
import { GEN_COLUMNS, GEN_ROWS, selectRows } from "./generated";
import { eventHandlers } from "./events";
import { deviceStatusHandlers, withDecision } from "./deviceStatus";

export const MOCK_MARKER = "sparrow-mock-backend-9f3c1e";

const fail = (kind: CmdErrorKind, message: string): never => {
  const e: CmdError = { kind, message };
  throw e;
};
const nap = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const hex = (n: number) => n.toString(16).padStart(64, "0");

// ------------------------------------------------------------------------------------------------ state

let settings: Settings = { analyst: "carlos", recent: ["/cases/synthetic-bec-aitm.duckdb"] };
let info: CaseInfo | null = null;
let queue: QueueItem[] = fx.queue();
let timeline: TimelineEntry[] = makeTimeline();
const audit: AuditEntry[] = [];
let importedBundle = false;
const highlights = new Map<string, HighlightSet[]>();
const running = new Map<string, (e: CmdError) => void>();

function auditEntry(action: string, objectType: string, objectId: string, reason: string | null = null): AuditEntry {
  const seq = audit.length + 100;
  const e: AuditEntry = {
    seq, ts: new Date().toISOString(), actor: `analyst:${settings.analyst ?? "unknown"}`, on_behalf_of: null, action,
    object_type: objectType, object_id: objectId, before: null, after: null, reason, prev_hash: hex(seq - 1), hash: hex(seq),
  };
  audit.push(e);
  return e;
}

function makeTimeline(): TimelineEntry[] {
  const base = Date.UTC(2026, 7, 14, 9, 0, 0);
  const phases = ["initial_access", "persistence", "collection", "exfiltration", "impact"];
  return Array.from({ length: 12 }, (_, i) => {
    const t = new Date(base + i * 3_600_000).toISOString();
    const verified = i % 3 === 0;
    return {
      entry_id: `mock-entry-${String(i).padStart(2, "0")}`,
      tenant_key: null,
      event_time: t,
      end_time: null,
      event_count: null,
      title: `Mock timeline entry ${i + 1}: ${i % 2 ? "inbox rule created" : "sign-in from relay"}`,
      narrative: i % 4 === 0 ? null : "Synthetic narrative. ".repeat(12),
      phase: phases[i % phases.length],
      status: verified ? "verified" : "proposed",
      supersedes: null,
      created_at: t,
      updated_at: t,
      decided_by: i % 2 ? "agent:triage" : "analyst:carlos",
      decided_at: t,
      on_behalf_of: null,
      review_state: i % 2 ? "pending_review" : "accepted",
      reviewed_by: i % 2 ? null : "analyst:carlos",
      reviewed_at: i % 2 ? null : t,
      review_comment: null,
      evidence: [{ source_table: "signins", record_key: "0055f45e-aefe-4384-87c4-9ef9e6bd9042" }],
    } satisfies TimelineEntry;
  });
}

// ------------------------------------------------------------------------------------------------ helpers

/** Resolves after `ms`, or rejects `interrupted` when `queryCancel` names this id first. */
async function interruptible<T>(queryId: unknown, ms: number, value: () => T): Promise<T> {
  const id = typeof queryId === "string" ? queryId : "";
  if (ms <= 0) return value();
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      running.delete(id);
      resolve(value());
    }, ms);
    running.set(id, (e) => {
      clearTimeout(timer);
      running.delete(id);
      reject(e);
    });
  });
}

const str = (a: Record<string, unknown> | undefined, k: string): string => {
  const v = a?.[k];
  return typeof v === "string" ? v : "";
};

const TOTAL_CAP = 4000;

function sqlRun(a: Record<string, unknown> | undefined): Promise<QueryResult> {
  const sql = str(a, "sql");
  const limit = typeof a?.limit === "number" ? a.limit : 1000;
  const offset = typeof a?.offset === "number" ? a.offset : 0;
  const slow = /slow/i.test(sql);
  // Not DuckDB's parse: good enough for a fake (the real flag ignores ORDER BY in subqueries and comments).
  const ordered = /\border\s+by\b/i.test(sql);
  return interruptible(a?.queryId, slow ? 10_000 : 0, () => {
    if (/\berror\b/i.test(sql)) return fail("invalid", "mock SQL error: syntax error near 'error'");
    if (/select\s+\*|\bwide\b/i.test(sql)) {
      const rows = selectRows([], null);
      return { columns: GEN_COLUMNS, rows: rows.slice(offset, offset + limit), truncated: rows.length > offset + limit, ordered };
    }
    const r = fx.sqlResult();
    return { ...r, rows: r.rows.slice(offset, offset + limit), truncated: r.rows.length > offset + limit, ordered };
  });
}

/** UTF-16 offsets of `token` in `sql`, as the real `sql_check` reports them. */
function mark(sql: string, token: string): { from?: number; to?: number } {
  const at = sql.indexOf(token);
  return at < 0 ? {} : { from: at, to: at + token.length };
}

/**
 * A fake `sql_check`: a non-SELECT or a second statement is `syntax`, the words `FRM` / `findngs` / `rule_idd` stand
 * for a syntax, catalog and binder error, and the word `error` is a syntax error there; anything else is ok.
 */
function sqlCheck(a: Record<string, unknown> | undefined): SqlCheck {
  const sql = str(a, "sql");
  const body = sql.replace(/--[^\n]*/g, "").trim().replace(/;\s*$/, "");
  if (!/^(select|with|from)\b/i.test(body)) {
    return { ok: false, error: { kind: "syntax", message: "query accepts one SELECT statement only: not a SELECT (mock)", suggestions: [] } };
  }
  if (body.includes(";")) {
    return { ok: false, error: { kind: "syntax", message: "query accepts exactly one SELECT statement, got 2", suggestions: [] } };
  }
  const err = sql.search(/\berror\b/i);
  if (err >= 0) {
    return { ok: false, error: { message: "mock syntax error near 'error'", kind: "syntax", from: err, to: err + 5, suggestions: ["select"] } };
  }
  if (/\bFRM\b/.test(sql)) {
    return { ok: false, error: { kind: "syntax", message: 'query accepts one SELECT statement only: syntax error at or near "FRM"', suggestions: [], ...mark(sql, "FRM") } };
  }
  if (sql.includes("findngs")) {
    return { ok: false, error: { kind: "catalog", message: 'Catalog Error: Table with name findngs does not exist!\nDid you mean "findings"?', suggestions: ["findings"], ...mark(sql, "findngs") } };
  }
  if (sql.includes("rule_idd")) {
    return { ok: false, error: { kind: "binder", message: 'Binder Error: Referenced column "rule_idd" not found in FROM clause!\nCandidate bindings: "rule_id"', suggestions: ["rule_id"], ...mark(sql, "rule_idd") } };
  }
  return { ok: true };
}

/** A fake `sql_export_csv`: writes nothing; `slow` in the query waits 10 s so Cancel can be tried. */
function sqlExportCsv(a: Record<string, unknown> | undefined): Promise<SqlExported> {
  const sql = str(a, "sql");
  if (!str(a, "path")) fail("invalid", "no path (mock)");
  return interruptible(a?.queryId, /slow/i.test(sql) ? 10_000 : 0, () => {
    if (/\berror\b/i.test(sql)) return fail("invalid", "mock SQL error: syntax error near 'error'");
    return { rows: GEN_ROWS, capped: false };
  });
}

function browsePage(a: Record<string, unknown> | undefined) {
  const filters = (Array.isArray(a?.filters) ? a.filters : []) as Filter[];
  const sort = (a?.sort ?? null) as Sort | null;
  const offset = typeof a?.offset === "number" ? a.offset : 0;
  const limit = typeof a?.limit === "number" ? a.limit : 100;
  return interruptible(a?.queryId, /slow/i.test(JSON.stringify(filters)) ? 10_000 : 0, () => {
    const matching = selectRows(filters, sort);
    return {
      table: str(a, "table"),
      columns: GEN_COLUMNS,
      rows: matching.slice(offset, offset + limit),
      offset,
      total: Math.min(matching.length, TOTAL_CAP),
      total_capped: matching.length > TOTAL_CAP,
    };
  });
}

function removeFromQueue(match: (q: QueueItem) => boolean, what: string): void {
  const before = queue.length;
  queue = queue.filter((q) => !match(q));
  if (queue.length === before) fail("not_found", `${what} is not in the queue`);
}

// ------------------------------------------------------------------------------------------------ import

const ingestListeners = new Set<(p: IngestProgress) => void>();
let ingestRunning = false;
const cancelledRuns = new Set<string>();
let profiledNow = false;
const closingListeners = new Set<() => void>();
export const mockOnIngestClosing = (f: () => void): (() => void) => {
  closingListeners.add(f);
  return () => void closingListeners.delete(f);
};
// The agent bridge's events: the mock has no bridge; `mockAgentWrote` plays one request (dev tools, tests).
const changedListeners = new Set<(c: CaseChanged) => void>();
const activityListeners = new Set<(a: AgentActivity) => void>();
export const mockOnCaseChanged = (f: (c: CaseChanged) => void): (() => void) => {
  changedListeners.add(f);
  return () => void changedListeners.delete(f);
};
export const mockOnAgentActivity = (f: (a: AgentActivity) => void): (() => void) => {
  activityListeners.add(f);
  return () => void activityListeners.delete(f);
};
/** As if an agent had run `command` through the bridge and changed `kinds`. */
export function mockAgentWrote(agent: string | null, command: string, kinds: string[]) {
  const at = new Date().toISOString();
  activityListeners.forEach((f) => f({ agent, command, at, running: false }));
  if (kinds.length > 0) changedListeners.forEach((f) => f({ kinds }));
}
const emitIngest = (p: IngestProgress) => ingestListeners.forEach((f) => f(p));
export const mockOnIngestProgress = (f: (p: IngestProgress) => void): (() => void) => {
  ingestListeners.add(f);
  return () => void ingestListeners.delete(f);
};

const MOCK_SOURCES: [string, string][] = [
  ["invictus.signins", "UnifiedAuditLog/SignInLogs.csv"],
  ["invictus.ual", "UnifiedAuditLog/UAL-2026-08.csv"],
  ["invictus.mailbox_audit", "Exchange/MailboxAudit.csv"],
  ["invictus.inbox_rules", "Exchange/InboxRules.csv"],
  ["invictus.message_trace", "Exchange/MessageTrace.csv"],
  ["invictus.users", "Users/Users.csv"],
];

/** A fake discovery: `empty` in the path finds nothing, `big` adds a file over the limit. */
function mockDiscovery(path: string): DiscoveryPreview {
  if (/empty/i.test(path)) {
    return { path, collections: [], recognised: 0, unrecognised: 0, too_large: 0, unreadable: 0, max_file_bytes: 1_073_741_824 };
  }
  const files: PreviewFile[] = MOCK_SOURCES.map(([artifact_id, rel_path], i) => ({
    rel_path, artifact_id, derived: false, size: 40_000 * (i + 1), status: "recognised", error: null,
  }));
  files.push({ rel_path: "README.txt", artifact_id: null, derived: false, size: 312, status: "unrecognised", error: null });
  if (/big/i.test(path)) files.push({ rel_path: "UnifiedAuditLog/UAL-huge.csv", artifact_id: "invictus.ual", derived: false, size: 2_400_000_000, status: "too_large", error: null });
  return {
    path,
    collections: [{ tool: "invictus", root: path, tenant_hint: "contoso.example", started_hint: "2026-08-14T09:00:00Z", files }],
    recognised: MOCK_SOURCES.length,
    unrecognised: 1,
    too_large: /big/i.test(path) ? 1 : 0,
    unreadable: 0,
    max_file_bytes: 1_073_741_824,
  };
}

async function mockIngestRun(a: Record<string, unknown> | undefined): Promise<IngestResult> {
  const path = str(a, "path");
  const target = a?.target as IngestTarget;
  const detect = a?.detect !== false;
  if (ingestRunning) fail("invalid", "an import is already running");
  if (target === "open" && info?.read_only_reason) fail("read_only", info.read_only_reason);
  const preview = mockDiscovery(path);
  if (preview.collections.length === 0) fail("invalid", `no Hawk, Microsoft-Extractor-Suite or portal export output found under ${path}`);
  ingestRunning = true;
  const runId = str(a, "runId");
  try {
    emitIngest({ stage: "discover" });
    await nap(80);
    emitIngest({ stage: "collection", index: 1, count: 1, root: path });
    const files = preview.collections[0].files.filter((f) => f.status === "recognised");
    const loaded: typeof files = [];
    for (const [i, f] of files.entries()) {
      if (cancelledRuns.has(runId)) break;
      emitIngest({ stage: "file", collection: 1, collections: 1, index: i + 1, files: preview.collections[0].files.length, rel_path: f.rel_path });
      await nap(250);
      loaded.push(f);
    }
    const cancelled = cancelledRuns.has(runId);
    emitIngest({ stage: "profile" });
    await nap(150);
    if (detect && !cancelled) {
      emitIngest({ stage: "detect" });
      await nap(150);
    }
    const reports = loaded.map((f, i) => ({
      rel_path: f.rel_path, artifact_id: f.artifact_id, status: "parsed", records_read: 1000 * (i + 1) + 3, records_loaded: 1000 * (i + 1),
      records_duplicate: 0, records_error: i === 1 ? 3 : 0, records_collector_lost: 0, warnings: i === 1 ? ["3 records could not be parsed"] : [],
    }));
    const left = files.slice(loaded.length).map((f) => ({ root: path, rel_path: f.rel_path }));
    return {
      case_path: target === "open" ? (info?.path ?? "") : target.new_case,
      cancelled,
      error: null,
      report: { collections: [{ collection_id: 1, tool: "invictus", root: path, files: reports }] },
      files_loaded: loaded.length,
      files_total: preview.collections[0].files.length,
      rows_by_source: reports.map((r) => ({ source: r.artifact_id ?? "unknown", files: 1, rows: r.records_loaded })),
      file_notes: reports.filter((r) => r.warnings.length).map((r) => ({ root: path, rel_path: r.rel_path, status: r.status, notes: ["3 records rejected", ...r.warnings] })),
      not_loaded: left,
      profile_error: null,
      profile_warnings: [],
      detect: detect && !cancelled ? { findings_new: 4, findings_updated: 0, warnings: [] } : null,
      detect_error: null,
    };
  } finally {
    ingestRunning = false;
  }
}

// ------------------------------------------------------------------------------------------------ commands

type Args = Record<string, unknown> | undefined;
const handlers: Record<string, (a: Args) => unknown> = {
  settings_get: () => settings,
  settings_set_analyst: (a) => (settings = { ...settings, analyst: str(a, "name") }),
  case_open: (a) => {
    const path = str(a, "path");
    if (/upgrade/i.test(path) && a?.allowUpgrade !== true) fail("needs_upgrade", "The case is an older schema; upgrade it to open it (mock).");
    info = {
      ...fx.caseInfo(),
      path,
      read_only_reason: /readonly/i.test(path) ? "mock: opened read-only (path contains 'readonly')" : null,
    };
    settings = { ...settings, recent: [path, ...settings.recent.filter((p) => p !== path)].slice(0, 5) };
    return info;
  },
  case_close: () => {
    info = null;
    return null;
  },
  review_queue: () => queue,
  finding_detail: (a) => {
    const d = fx.findingDetail();
    const id = str(a, "findingId");
    d.finding.finding_id = id || d.finding.finding_id;
    d.audit = [...d.audit, ...audit.filter((e) => e.object_id === id)];
    return d;
  },
  review_accept: (a) => {
    removeFromQueue((q) => q.source === "decision" && q.object_type === str(a, "objectType") && q.object_id === str(a, "objectId") && q.decision_seq === a?.decisionSeq, "that decision");
    return auditEntry("review_accept", str(a, "objectType"), str(a, "objectId"), str(a, "comment") || null);
  },
  review_discard: (a) => {
    removeFromQueue((q) => q.source === "decision" && q.object_type === str(a, "objectType") && q.object_id === str(a, "objectId") && q.decision_seq === a?.decisionSeq, "that decision");
    return auditEntry("review_discard", str(a, "objectType"), str(a, "objectId"), str(a, "comment") || null);
  },
  proposal_accept: (a) => {
    removeFromQueue((q) => q.source === "proposal" && q.bundle_sha256 === str(a, "bundleSha256") && q.item_key === str(a, "itemKey"), "that proposal");
    return [auditEntry("proposal_accept", "proposal", str(a, "itemKey"))];
  },
  proposal_discard: (a) => {
    removeFromQueue((q) => q.source === "proposal" && q.bundle_sha256 === str(a, "bundleSha256") && q.item_key === str(a, "itemKey"), "that proposal");
    return auditEntry("proposal_discard", "proposal", str(a, "itemKey"), str(a, "comment") || null);
  },

  timeline_list: () => timeline,
  timeline_propose: (a): EntryWritten => {
    const n = a?.args as NewEntryArgs;
    const now = new Date().toISOString();
    const entry: TimelineEntry = {
      entry_id: `mock-entry-new-${timeline.length}`, tenant_key: n.tenantKey ?? null, event_time: n.eventTime, end_time: null, event_count: null, title: n.title,
      narrative: n.narrative ?? null, phase: n.phase, status: "proposed", supersedes: null, created_at: now, updated_at: now,
      decided_by: `analyst:${settings.analyst ?? "unknown"}`, decided_at: now, on_behalf_of: null, review_state: "accepted",
      reviewed_by: null, reviewed_at: null, review_comment: null,
      evidence: n.evidence.map((e) => {
        const [source_table, ...rest] = e.split(":");
        return { source_table, record_key: rest.join(":") };
      }),
    };
    timeline = [...timeline, entry];
    return { entryId: entry.entry_id, audit: auditEntry("timeline_propose", "timeline_entry", entry.entry_id) };
  },
  timeline_edit: (a): EntryWritten => {
    const id = str(a, "entryId");
    const e = (a?.args ?? {}) as EntryEditArgs;
    const cur = timeline.find((t) => t.entry_id === id) ?? fail("not_found", `timeline entry ${id}`);
    const next: TimelineEntry = {
      ...cur,
      event_time: e.eventTime ?? cur.event_time,
      title: e.title ?? cur.title,
      narrative: e.narrative === undefined ? cur.narrative : e.narrative,
      phase: e.phase ?? cur.phase,
      evidence: e.evidence ? e.evidence.map((x) => { const [s, ...r] = x.split(":"); return { source_table: s, record_key: r.join(":") }; }) : cur.evidence,
      updated_at: new Date().toISOString(),
    };
    timeline = timeline.map((t) => (t.entry_id === id ? next : t));
    return { entryId: id, audit: auditEntry("timeline_edit", "timeline_entry", id) };
  },
  ...eventHandlers({
    fail,
    audit: auditEntry,
    interruptible,
    writable: () => {
      if (info?.read_only_reason) fail("read_only", info.read_only_reason);
      if (!settings.analyst) fail("invalid", "set the analyst name (settings) before making a decision");
    },
    analyst: () => settings.analyst ?? "unknown",
    addEntries: (entries) => {
      timeline = [...timeline, ...entries];
    },
  }),
  timeline_verify: (a) => setStatus(str(a, "entryId"), "verified", null),
  timeline_reject: (a) => setStatus(str(a, "entryId"), "rejected", str(a, "reason") || null),

  accounts_list: () => fx.accounts(),
  devices_list: () => fx.devices().map(withDecision),
  ...deviceStatusHandlers({
    fail,
    audit: auditEntry,
    writable: () => {
      if (info?.read_only_reason) fail("read_only", info.read_only_reason);
      if (!settings.analyst) fail("invalid", "set the analyst name (settings) before making a decision");
    },
    analyst: () => settings.analyst ?? "unknown",
  }),
  export_report: () => null,
  export_timeline_csv: () => null,
  export_workbook: () => null,
  access_report: (a) => {
    const r = fx.accessReport();
    const want = typeof a?.account === "string" ? a.account.toLowerCase() : null;
    if (want === null) return r;
    const hit = r.accounts.find((x) => x.account === want);
    // As the core: an account with nothing attributed gets an empty section with its seven tiles.
    const empty = {
      account: want,
      tenant_key: null,
      scope: [],
      tiles: r.accounts[0].tiles.map((t) => ({
        ...t,
        direct: 0,
        by_time: 0,
        qualifier: null,
        none_seen: false,
        coverage: { status: "none", reason: "The case has no availability record for this source (run sparrow profile)", remediation: null },
      })),
      items: [],
      gaps: [] as string[],
    };
    // The coverage reason of each category, then the gaps Microsoft never logs (the last four of any account's).
    empty.gaps = [
      ...empty.tiles.map((t) => `${ACCESS_TITLES[t.category]}: ${t.coverage.reason}`),
      ...r.accounts[0].gaps.slice(-4),
    ];
    return { ...r, accounts: [hit ?? empty] };
  },
  access_accounts: () => fx.accessReport().accounts.map((x) => x.account),
  export_access_csv: () => null,
  export_access_summary: () => null,

  highlights_get: (a) => highlights.get(str(a, "caseId")) ?? [],
  highlights_set: (a) => {
    const sets = (a?.sets ?? []) as HighlightSet[];
    highlights.set(str(a, "caseId"), sets);
    return sets;
  },
  highlights_clear: (a) => {
    highlights.delete(str(a, "caseId"));
    return null;
  },
  evidence_filter: (a) => ({ table: str(a, "table"), filters: [{ op: "eq", column: "record_key", value: str(a, "key") }] }),
  browse_tables: () => fx.schema().filter((t) => t.kind === "table").map((t) => t.name),
  browse_page: browsePage,
  sql_schema: (a) => {
    const t = str(a, "table");
    return t ? fx.schema().filter((x) => x.name === t) : fx.schema();
  },
  sql_run: sqlRun,
  sql_check: sqlCheck,
  sql_export_csv: sqlExportCsv,
  query_cancel: (a) => {
    running.get(str(a, "queryId"))?.({ kind: "interrupted", message: "query interrupted (mock)" });
    return null;
  },
  indicators_active: () => fx.indicators(),

  ingest_discover: (a) => mockDiscovery(str(a, "path")),
  ingest_run: (a) => mockIngestRun(a),
  ingest_cancel: (a) => {
    cancelledRuns.add(str(a, "runId"));
    return null;
  },
  ingest_unprofiled: () => (/unprofiled/i.test(info?.path ?? "") && !profiledNow ? [1] : []),
  ingest_profile: async () => {
    if (info?.read_only_reason) fail("read_only", info.read_only_reason);
    await nap(300);
    profiledNow = true;
    return { profile_error: null, profile_warnings: [], detect: { findings_new: 2, findings_updated: 0, warnings: [] }, detect_error: null };
  },

  share_export: () => ({ sha256: hex(0xabc), items: 3 }),
  share_preview: () => fx.sharePreview(),
  share_import: (a) => {
    const p = fx.sharePreview();
    if (str(a, "sha256") !== p.sha256) fail("invalid", "the bundle changed since its preview (mock)");
    if (importedBundle) return { ...p.summary, already_imported: true };
    importedBundle = true;
    // The bundle's items land in the review queue as proposals, like the real import.
    const proposals = fx.queue().filter((q) => q.source === "proposal").slice(0, p.summary.new);
    queue = [...queue, ...proposals.map((q, i) => ({ ...q, bundle_sha256: p.sha256, item_key: `${q.source === "proposal" ? q.item_key : ""}#imported${i}` }) as QueueItem)];
    return p.summary;
  },
};

function setStatus(id: string, status: TimelineEntry["status"], reason: string | null): AuditEntry {
  if (!timeline.some((t) => t.entry_id === id)) fail("not_found", `timeline entry ${id}`);
  timeline = timeline.map((t) => (t.entry_id === id ? { ...t, status, updated_at: new Date().toISOString() } : t));
  return auditEntry(status === "verified" ? "timeline_verify" : "timeline_reject", "timeline_entry", id, reason);
}

/** Every command name the mock answers; a test keeps it equal to the names `api.ts` calls. */
export const MOCK_COMMANDS: string[] = Object.keys(handlers).sort();

export async function mockCall<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const h = handlers[cmd];
  if (!h) return fail("internal", `mock backend: unknown command "${cmd}"`);
  await nap(40); // a little latency, so loading states are visible
  return (await h(args)) as T;
}

const MOCK_CASE_PATH = "/cases/synthetic-bec-aitm.duckdb";
export function mockOpen(options?: { directory?: boolean; filters?: { name: string; extensions: string[] }[] }): string {
  if (options?.directory) return "/mock/evidence/invictus-run";
  return options?.filters?.some((f) => f.extensions.includes("json")) ? "/mock/bundle.sparrow-share.json" : MOCK_CASE_PATH;
}
export function mockSave(options?: { defaultPath?: string }): string {
  return `/mock/out/${options?.defaultPath ?? "export.out"}`;
}
