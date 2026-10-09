// DEV ONLY: a fake backend so the UI can be inspected in a plain browser (`npm run dev:mock`). Loaded by a dynamic
// import behind `MOCK_BACKEND`, so a production build holds none of it. All data is synthetic.
import type {
  AuditEntry,
  CaseInfo,
  CmdError,
  CmdErrorKind,
  EntryEditArgs,
  EntryWritten,
  Filter,
  HighlightSet,
  NewEntryArgs,
  Pivot,
  QueryResult,
  QueueItem,
  Settings,
  Sort,
  TimelineEntry,
} from "../api";
import * as fx from "../test/fixtures";
import { GEN_COLUMNS, genObjects, selectRows } from "./generated";

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

function pivot(base: Pivot, cap: unknown): Pivot {
  const n = typeof cap === "number" && cap > 0 ? Math.min(cap, 200) : 200;
  const hostile = genObjects(300).filter((r) => /[<\u202E=]/.test(String(r.user_upn)));
  return {
    sections: [
      ...base.sections,
      { name: "signins (stress)", rows: genObjects(n), total: 1342, truncated: true },
      { name: "hostile values", rows: hostile, total: hostile.length, truncated: false },
    ],
  };
}

function sqlRun(a: Record<string, unknown> | undefined): Promise<QueryResult> {
  const sql = str(a, "sql");
  const limit = typeof a?.limit === "number" ? a.limit : 1000;
  const slow = /slow/i.test(sql);
  return interruptible(a?.queryId, slow ? 10_000 : 0, () => {
    if (/\berror\b/i.test(sql)) return fail("invalid", "mock SQL error: syntax error near 'error'");
    if (/select\s+\*|\bwide\b/i.test(sql)) {
      const rows = selectRows([], null);
      return { columns: GEN_COLUMNS, rows: rows.slice(0, limit), truncated: rows.length > limit };
    }
    return fx.sqlResult();
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
      entry_id: `mock-entry-new-${timeline.length}`, tenant_key: n.tenantKey ?? null, event_time: n.eventTime, title: n.title,
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
  timeline_verify: (a) => setStatus(str(a, "entryId"), "verified", null),
  timeline_reject: (a) => setStatus(str(a, "entryId"), "rejected", str(a, "reason") || null),

  accounts_list: () => fx.accounts(),
  export_report: () => null,
  export_timeline_csv: () => null,
  export_workbook: () => null,

  pivot_ip: (a) => pivot(fx.pivotIp(), a?.cap),
  pivot_user: (a) => pivot(fx.pivotUser(), a?.cap),
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
  query_cancel: (a) => {
    running.get(str(a, "queryId"))?.({ kind: "interrupted", message: "query interrupted (mock)" });
    return null;
  },
  indicators_active: () => fx.indicators(),

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
export function mockOpen(options?: { filters?: { name: string; extensions: string[] }[] }): string {
  return options?.filters?.some((f) => f.extensions.includes("json")) ? "/mock/bundle.sparrow-share.json" : MOCK_CASE_PATH;
}
export function mockSave(options?: { defaultPath?: string }): string {
  return `/mock/out/${options?.defaultPath ?? "export.out"}`;
}
