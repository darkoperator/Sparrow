// The only caller of Tauri's `invoke`. Screens call the typed wrappers added here per command; the JSON shapes are
// the Rust core's serde shapes unchanged. No logic lives in the frontend.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const CMD_ERROR_KINDS = [
  "not_found",
  "invalid",
  "decision",
  "writer_busy",
  "read_only",
  "no_case",
  "needs_upgrade",
  "needs_acknowledge",
  "interrupted",
  "busy",
  "internal",
] as const;

export type CmdErrorKind = (typeof CMD_ERROR_KINDS)[number];

export interface CmdError {
  kind: CmdErrorKind;
  message: string;
}

export function isCmdError(e: unknown): e is CmdError {
  if (typeof e !== "object" || e === null) return false;
  const o = e as Record<string, unknown>;
  return (
    typeof o.kind === "string" &&
    (CMD_ERROR_KINDS as readonly string[]).includes(o.kind) &&
    typeof o.message === "string"
  );
}

/**
 * Runs one backend command. Rejects with a `CmdError` of a known kind only: anything else Tauri or a plugin rejects
 * with (a string, an unknown kind) becomes `internal`, keeping its message when it has one.
 */
export async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    // Dev-only mock backend (`npm run dev:mock`): `__SPARROW_MOCK__` is false in every other build, so the import is dropped.
    if (__SPARROW_MOCK__) return await (await import("./mock/backend")).mockCall<T>(cmd, args);
    return await invoke<T>(cmd, args);
  } catch (e) {
    if (isCmdError(e)) throw e;
    const message =
      typeof e === "object" && e !== null && typeof (e as Record<string, unknown>).message === "string"
        ? ((e as Record<string, unknown>).message as string)
        : String(e);
    const err: CmdError = { kind: "internal", message };
    throw err;
  }
}

// ---------------------------------------------------------------- shapes (the Rust serde shapes unchanged)

export interface Settings {
  analyst: string | null;
  recent: string[];
}

export interface CaseInfo {
  path: string;
  case_id: string;
  schema_version: number;
  audit_ok: boolean;
  read_only_reason: string | null;
  tenants: string[];
  warnings: string[];
}

export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  on_behalf_of: string | null;
  action: string;
  object_type: string;
  object_id: string;
  before: unknown;
  after: unknown;
  reason: string | null;
  prev_hash: string;
  hash: string;
}

/** `sparrow_core::case::review::PendingDecision`. */
export interface PendingDecision {
  object_type: string;
  object_id: string;
  decision_seq: number;
  action: string;
  actor: string;
  on_behalf_of: string | null;
  decided_at: string;
  before: unknown;
  after: unknown;
  reason: string | null;
  account: string | null;
  title: string;
}

/** `sparrow_core::case::share::Item` (tagged by `kind`). */
export type ProposalItem =
  | { kind: "finding"; finding_id: string; status: string; disposition_reason: string | null }
  | {
      kind: "indicator";
      tenant_key: string | null;
      ioc_type: string;
      value: string;
      verdict: string;
      note: string | null;
      active: boolean;
    }
  | {
      kind: "timeline_entry";
      entry_id: string;
      tenant_key: string | null;
      event_time: string;
      title: string;
      narrative: string | null;
      phase: string;
      status: string;
      evidence: string[];
      supersedes: string[];
    }
  | { kind: "note"; target: string; text: string };

/** `sparrow_core::case::share::Proposal`. `classification`: new | agrees | conflict | missing. */
export interface Proposal {
  bundle_sha256: string;
  item_key: string;
  source_analyst: string;
  classification: string;
  state: string;
  item: ProposalItem;
  current: unknown;
}

/** `QueueItem` (serde tag `source`, the payload flattened). */
export type QueueItem = ({ source: "decision" } & PendingDecision) | ({ source: "proposal" } & Proposal);

export interface TimelineRow {
  event_time: string;
  time_tz_assumed: boolean | null;
  source_table: string;
  record_key: string;
  category: string;
  operation: string | null;
  actor_upn: string | null;
  target: string | null;
  ip: string | null;
  ip_country: string | null;
  ip_asn_org: string | null;
  user_agent: string | null;
  summary: string | null;
  source_refs: string[];
  finding_count: number;
  finding_ids: string[];
}

export interface EvidenceRow {
  source_table: string;
  record_key: string;
  role: string;
  event_time: string | null;
  source_refs: string[];
  timeline: TimelineRow | null;
  context: unknown;
}

export interface FindingRow {
  finding_id: string;
  tenant_key: string;
  rule_id: string | null;
  rule_version: number | null;
  severity: string;
  title: string;
  actor_upn: string | null;
  first_seen: string | null;
  last_seen: string | null;
  status: string;
  disposition_reason: string | null;
  created_by: string;
  assigned_to: string | null;
  rule_updated: boolean;
  created_at: string;
  updated_at: string;
  decided_by: string | null;
  decided_at: string | null;
  on_behalf_of: string | null;
  review_state: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_comment: string | null;
  evidence_count: number;
}

export interface Note {
  annotation_id: string;
  object_type: string;
  object_id: string;
  source_table: string | null;
  text: string;
  actor: string;
  on_behalf_of: string | null;
  created_at: string;
}

/** `read::FindingDetail`; `facts` / `facts_unavailable` are flattened in, at most one present. */
export interface FindingDetail {
  finding: FindingRow;
  evidence: EvidenceRow[];
  facts?: unknown;
  facts_unavailable?: string;
  analyst_guidance: string | null;
  notes: Note[];
  audit: AuditEntry[];
}

// ---------------------------------------------------------------- commands

export const settingsGet = () => call<Settings>("settings_get");
export const settingsSetAnalyst = (name: string) => call<Settings>("settings_set_analyst", { name });
export const caseOpen = (path: string, allowUpgrade = false) => call<CaseInfo>("case_open", { path, allowUpgrade });
export const caseClose = () => call<null>("case_close");

export const reviewQueue = () => call<QueueItem[]>("review_queue");
export const findingDetail = (findingId: string) => call<FindingDetail>("finding_detail", { findingId });
export const reviewAccept = (objectType: string, objectId: string, decisionSeq: number, comment?: string) =>
  call<AuditEntry>("review_accept", { objectType, objectId, decisionSeq, comment });
export const reviewDiscard = (objectType: string, objectId: string, decisionSeq: number, comment?: string) =>
  call<AuditEntry>("review_discard", { objectType, objectId, decisionSeq, comment });
export const proposalAccept = (bundleSha256: string, itemKey: string) =>
  call<AuditEntry[]>("proposal_accept", { bundleSha256, itemKey });
export const proposalDiscard = (bundleSha256: string, itemKey: string, comment?: string) =>
  call<AuditEntry>("proposal_discard", { bundleSha256, itemKey, comment });

// ---------------------------------------------------------------- timeline (core serde shapes)

export interface EvidenceRef {
  source_table: string;
  record_key: string;
}

export type EntryStatus = "proposed" | "verified" | "rejected" | "superseded";

export interface TimelineEntry {
  entry_id: string;
  tenant_key: string | null;
  event_time: string;
  /** The end of the span a grouped entry covers (`event_time` is the start); null for a single moment. */
  end_time: string | null;
  /** How many events a grouped entry covers; null when it is not grouped. */
  event_count: number | null;
  title: string;
  narrative: string | null;
  phase: string;
  status: EntryStatus;
  supersedes: string | null;
  created_at: string;
  updated_at: string;
  decided_by: string;
  decided_at: string;
  on_behalf_of: string | null;
  review_state: "pending_review" | "accepted" | "discarded";
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_comment: string | null;
  evidence: EvidenceRef[];
}

export interface NewEntryArgs {
  eventTime: string;
  title: string;
  narrative?: string | null;
  phase: string;
  evidence: string[];
  tenantKey?: string | null;
}

/** An absent field keeps the current value; `narrative: null` clears it; `evidence` replaces the whole list. */
export interface EntryEditArgs {
  eventTime?: string;
  title?: string;
  narrative?: string | null;
  phase?: string;
  evidence?: string[];
}

export interface EntryWritten {
  entryId: string;
  audit: AuditEntry;
}

export const timelineList = () => call<TimelineEntry[]>("timeline_list");
export const timelinePropose = (args: NewEntryArgs) => call<EntryWritten>("timeline_propose", { args });
export const timelineEdit = (entryId: string, args: EntryEditArgs) =>
  call<EntryWritten>("timeline_edit", { entryId, args });
export const timelineVerify = (entryId: string) => call<AuditEntry>("timeline_verify", { entryId });
export const timelineReject = (entryId: string, reason?: string) =>
  call<AuditEntry>("timeline_reject", { entryId, reason });

// ---------------------------------------------------------------- accounts and exports

/** `detect::rule::Stage` (serde snake_case). */
export type Stage =
  | "suspicious_sign_in"
  | "credential_takeover"
  | "persistence"
  | "mail_access"
  | "sending"
  | "consent"
  | "mfa_change";

/** `detect::enrich::accounts::Address`. `reasons` lists why it is worth a look, strongest first. */
export interface Address {
  ip: string;
  reasons: string[];
  tables: string[];
  first_seen: string | null;
  last_seen: string | null;
  asn: number | null;
  asn_org: string | null;
  is_hosting: boolean | null;
  spray_source: boolean;
  in_user_signins: boolean;
}

/** `detect::enrich::accounts::AccountRow`. */
export interface AccountRow {
  tenant_key: string;
  upn: string;
  worst_severity: string;
  finding_count: number;
  by_severity: Record<string, number>;
  stages: Stage[];
  first_suspicious: string | null;
  rules: string[];
  /** First and last sign-in of the account in the case; null when the case holds none. */
  signins_first: string | null;
  signins_last: string | null;
  addresses: Address[];
  addresses_total: number;
  addresses_truncated: boolean;
}

/** `read::AccountPage`; a non-empty `warnings` says why `accounts` may be empty or incomplete. */
export interface AccountPage {
  accounts: AccountRow[];
  total: number;
  truncated: boolean;
  warnings: string[];
}

export const accountsList = (tenant?: string) => call<AccountPage>("accounts_list", { tenant });
export const exportReport = (path: string, reviewedOnly: boolean) =>
  call<null>("export_report", { path, reviewedOnly });
export const exportTimelineCsv = (path: string) => call<null>("export_timeline_csv", { path });
export const exportWorkbook = (path: string) => call<null>("export_workbook", { path });

/** `case::access::Attribution`: how a record is tied to the attacker. Every value but `time` is direct evidence. */
export type Attribution = "session" | "row" | "device" | "ip" | "time";

/** `case::access::Category`, in tile order. */
export type AccessCategory = "mail_read" | "mail_sent" | "attachment" | "file" | "teams" | "copilot" | "other";

export const ACCESS_TITLES: Record<AccessCategory, string> = {
  mail_read: "Emails read",
  mail_sent: "Emails sent",
  attachment: "Attachments",
  file: "SharePoint / OneDrive",
  teams: "Teams",
  copilot: "Copilot",
  other: "Other apps",
};

/** What puts a record or scope value in the access report: an accepted flag, a pending agent flag, or a what-if value. */
export type Basis = "accepted" | "pending" | "adhoc";

/**
 * An Access tab's preview: pending agent flags too, and what-if values (as if flagged malicious and accepted). With
 * `without_accepted`, the case's accepted flags are left out: a device or IP tab's what-if counts its value alone.
 */
export interface PreviewArgs {
  include_pending: boolean;
  adhoc: { kind: "ip" | "ip_prefix" | "session" | "device"; value: string }[];
  without_accepted?: boolean;
}

/** `case::access::Item`: one thing the attacker reached; times are RFC 3339 UTC. */
export interface AccessItem {
  account: string;
  category: AccessCategory;
  attribution: Attribution;
  accessed: string;
  action: string;
  item: string | null;
  location: string | null;
  from: string | null;
  to: string | null;
  size_bytes: number | null;
  item_time: string | null;
  /** The application id; on an "other" record with none, the client the record names. */
  app: string | null;
  /** The name the case's sign-ins or identities give `app`. */
  app_name: string | null;
  ip: string | null;
  session_id: string | null;
  /** The owner of the data when it is not the account (shared or delegated mailbox, send as). */
  owner: string | null;
  note: string | null;
  source: string;
  source_table: string;
  record_key: string;
  basis: Basis;
  /** `<source_table>:<record_key>`, as `sparrow mark flag --row` takes it. */
  row: string;
}

/** `case::access::CategoryCoverage`: an `evidence_availability` status, or `none`. */
export interface AccessCoverage {
  status: string;
  reason: string;
  remediation: string | null;
}

/** `case::access::Tile`. A zero is "none seen" only when `none_seen` is true. */
export interface AccessTile {
  category: AccessCategory;
  direct: number;
  by_time: number;
  qualifier: string | null;
  coverage: AccessCoverage;
  none_seen: boolean;
  /** Of the counts, how many a preview added (pending flags, what-if values); 0 in the reviewed report. */
  pending: number;
  adhoc: number;
}

export interface AccessWindow {
  start: string;
  end: string;
}

/** `case::access::ScopeValue`: a flagged value seen for the account, with the windows of its sightings. */
export interface ScopeValue {
  kind: string;
  value: string;
  windows: AccessWindow[];
  basis: Basis;
}

/** `case::access::AccountAccess`: `tiles` has one entry per category, in tile order. */
export interface AccessAccount {
  account: string;
  tenant_key: string | null;
  scope: ScopeValue[];
  tiles: AccessTile[];
  items: AccessItem[];
  gaps: string[];
}

export interface AccessReport {
  accounts: AccessAccount[];
  /** Malicious flags waiting for review: they attribute nothing until accepted (unless the preview includes them). */
  pending_flags: number;
  /** An item or scope value rests on a pending flag or a what-if value: not the reviewed answer. */
  preview: boolean;
  /** What Microsoft never logs, the same for every account (the accounts' `gaps` hold their own reasons only). */
  never_logged: string[];
}

/**
 * What the attacker reached through `account` (any case), or through every account with accepted malicious flags; with
 * `preview`, also through pending agent flags and what-if values.
 */
export const accessReport = (account?: string | null, preview?: PreviewArgs | null) =>
  call<AccessReport>("access_report", { account: account ?? null, preview: preview ?? null });
/** The reviewed report's seven tiles of `account`, without its items (the account tab's summary line). */
export const accessTiles = (account: string) => call<AccessTile[]>("access_tiles", { account });
/** The accounts the access report lists. */
export const accessAccounts = () => call<string[]>("access_accounts");
/** The access CSV (one row per item) of every account, or of `account`. */
export const exportAccessCsv = (path: string, account?: string | null, preview?: PreviewArgs | null) =>
  call<null>("export_access_csv", { path, account: account ?? null, preview: preview ?? null });
/** The access summary (Markdown) of every account. */
export const exportAccessSummary = (path: string) => call<null>("export_access_summary", { path });

// ---------------------------------------------------------------- highlights (core serde shapes)

export const HIGHLIGHT_COLOURS = ["red", "amber", "green", "blue", "purple"] as const;
export type HighlightColour = (typeof HIGHLIGHT_COLOURS)[number];

/** `column: null` matches any column. `eq` is exact on the raw value; `contains` is a case-insensitive substring. */
export interface HighlightRule {
  column: string | null;
  op: "eq" | "contains";
  value: string;
  colour: HighlightColour;
}

export interface HighlightSet {
  name: string;
  rules: HighlightRule[];
}

// ---------------------------------------------------------------- tables, schema, indicators, highlights

/** `browse::Filter` (serde tag `op`, snake_case). Times are RFC 3339 UTC strings. */
export type Filter =
  | { op: "eq" | "ne"; column: string; value: unknown }
  | { op: "contains"; column: string; value: string }
  | { op: "between"; column: string; low: unknown; high: unknown }
  | { op: "in"; column: string; values: unknown[] }
  | { op: "is_null" | "not_null"; column: string };

export interface Sort {
  column: string;
  descending: boolean;
}

/** `browse::BrowsePage`: `total` counts matching rows up to a cap; `total_capped` says there are more. */
export interface BrowsePage {
  table: string;
  columns: string[];
  rows: unknown[][];
  offset: number;
  total: number;
  total_capped: boolean;
}

/** `db::describe::ColumnInfo`. */
export interface ColumnInfo {
  name: string;
  type: string;
  comment: string | null;
}

/** `db::describe::TableInfo`. `kind`: "table" or "view". */
export interface TableInfo {
  name: string;
  comment: string | null;
  kind: string;
  columns: ColumnInfo[];
}

export interface ActiveIndicator {
  ioc_type: string;
  value: string;
  verdict: string;
}

/** A caller-generated id naming one running query, so `queryCancel` stops that query and no other. */
export function newQueryId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID();
  return `q-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

/** Where an evidence reference opens in the table browser; the backend decides each table's key column. */
export const evidenceFilter = (table: string, key: string) =>
  call<{ table: string; filters: Filter[] }>("evidence_filter", { table, key });

export const browseTables = () => call<string[]>("browse_tables");
export const browsePage = (
  table: string,
  filters: Filter[],
  sort: Sort | null,
  offset: number,
  limit: number,
  queryId: string,
) => call<BrowsePage>("browse_page", { table, filters, sort, offset, limit, queryId });
export const sqlSchema = (table?: string) => call<TableInfo[]>("sql_schema", { table });
/**
 * Interrupts the running `sql_run` / `sql_export_csv` / `browse_page` with this id, if any (any other id: nothing happens); that call
 * then rejects with kind `interrupted`.
 */
export const queryCancel = (queryId: string) => call<null>("query_cancel", { queryId });
export const indicatorsActive = () => call<ActiveIndicator[]>("indicators_active");
export const highlightsGet = (caseId: string) => call<HighlightSet[]>("highlights_get", { caseId });
export const highlightsSet = (caseId: string, sets: HighlightSet[]) =>
  call<HighlightSet[]>("highlights_set", { caseId, sets });
export const highlightsClear = (caseId: string) => call<null>("highlights_clear", { caseId });

// ---------------------------------------------------------------- SQL and share (core serde shapes)

/** `case::query::QueryResult`; each value is DuckDB's `to_json` of the column. */
export interface QueryResult {
  columns: string[];
  rows: unknown[][];
  truncated: boolean;
  /**
   * True when the query's top-level SELECT has an ORDER BY (DuckDB's parse): only then are pages at different
   * offsets slices of one stable order.
   */
  ordered: boolean;
}

/** `case::query::CheckKind`. */
export type SqlCheckKind = "syntax" | "binder" | "catalog" | "other";

/** `case::query::CheckError`. */
export interface SqlCheckError {
  /** DuckDB's message without its `LINE n:` excerpt (the editor marks the place instead). */
  message: string;
  kind: SqlCheckKind;
  /** UTF-16 offsets into the checked text (CodeMirror positions): the offending token; absent without a position. */
  from?: number;
  to?: number;
  /** DuckDB's "Did you mean" / "Candidate bindings" names. */
  suggestions: string[];
}

/** `case::query::Check`. */
export type SqlCheck = { ok: true } | { ok: false; error: SqlCheckError };

/** `case::query::Exported`: data rows written; `capped` when the result had more than 1,000,000 rows. */
export interface SqlExported {
  rows: number;
  capped: boolean;
}

/** `case::share::ImportSummary`. */
export interface ImportSummary {
  bundle_sha256: string;
  analyst: string;
  new: number;
  agrees: number;
  conflicts: number;
  missing: number;
  /**
   * Items stored (for a preview: that would be stored) as `superseded`, because a newer open proposal from the same
   * analyst already covers them. A subset of new + conflicts + missing (an agreeing item is never superseded).
   */
  superseded: number;
  already_imported: boolean;
  rules_only_in_bundle: string[];
  rules_only_here: string[];
}

export interface ShareExported {
  sha256: string;
  items: number;
}

export interface SharePreview {
  sha256: string;
  summary: ImportSummary;
  /** `analyst:<name>`, as in the bundle. */
  analyst: string;
  /** RFC 3339, as in the bundle. */
  exported_at: string;
  items: number;
}

/**
 * `queryId` names this run for `queryCancel` (≤ 64 chars, no control characters; a fresh one per run). `offset`
 * (default 0, ≤ 100,000,000) pages the result: "next 1000" is the same query at offset + 1000.
 */
export const sqlRun = (sql: string, limit: number | undefined, queryId: string, offset?: number) =>
  call<QueryResult>("sql_run", { sql, limit, queryId, offset });
/** Checks one SELECT without running it (binds it on the case); not cancellable. Text over 1 MiB is `invalid`. */
export const sqlCheck = (sql: string) => call<SqlCheck>("sql_check", { sql });
/**
 * Writes the whole result (at most 1,000,000 rows) as CSV at `path`, cancellable with `queryCancel(queryId)`; a
 * failed or cancelled export leaves no file, and the open case or its WAL is refused (`invalid`).
 */
export const sqlExportCsv = (sql: string, path: string, queryId: string) =>
  call<SqlExported>("sql_export_csv", { sql, path, queryId });
/** A saved query as a notebook list shows it (`decided_*` are null for a built-in query). */
export interface QuerySummary {
  query_id: string;
  /** 1-based place in the notebook. */
  position: number;
  /** The first `--` comment line (else the first line). */
  title: string;
  /** `[name]` placeholders still to fill in, without brackets, in order. */
  placeholders: string[];
  /** `agent:<id>` or `analyst:<name>`. */
  decided_by: string | null;
  on_behalf_of: string | null;
  decided_at: string | null;
}

export interface NotebookSummary {
  /** `builtin` for the built-in notebook. */
  notebook_id: string;
  name: string;
  /** Read-only: never saved to, renamed or deleted. */
  builtin: boolean;
  queries: QuerySummary[];
}

export interface SavedQuery extends QuerySummary {
  notebook_id: string;
  sql: string;
}

/** Values from this case in one query of a notebook about to be exported. */
export interface CaseValueHit {
  query_id: string;
  title: string;
  values: string[];
}

/** The built-in notebook first, then the case's by name. */
export const notebookList = () => call<NotebookSummary[]>("notebook_list");
/** `notebook` an id or a name, `query` an id or a 1-based position. */
export const notebookQuery = (notebook: string, query: string) => call<SavedQuery>("notebook_query", { notebook, query });
/** Creates an empty case notebook (the analyst's); its id. */
export const notebookCreate = (name: string) => call<string>("notebook_create", { name });
/** Adds `sql` as the last query of a case notebook; the new query's id. */
export const notebookAddQuery = (notebookId: string, sql: string) => call<string>("notebook_add_query", { notebookId, sql });
/** Save as into a new notebook: the notebook and its first query in one write (a refused query creates nothing). */
export const notebookSaveNew = (name: string, sql: string) =>
  call<{ notebook_id: string; query_id: string }>("notebook_save_new", { name, sql });
export const notebookRename = (notebookId: string, name: string) => call<null>("notebook_rename", { notebookId, name });
export const notebookDelete = (notebookId: string) => call<null>("notebook_delete", { notebookId });
export const notebookDeleteQuery = (queryId: string) => call<null>("notebook_delete_query", { queryId });
/** Moves a case query to `position` (1-based, clamped). */
export const notebookMoveQuery = (queryId: string, position: number) => call<null>("notebook_move_query", { queryId, position });
/** What an export of this notebook would carry out of the case. */
export const notebookCaseValues = (notebookId: string) => call<CaseValueHit[]>("notebook_case_values", { notebookId });
/**
 * Writes the file. The case values are checked again at the write: one not in `accepted` (the values the warning
 * showed; [] when it showed none) is refused (`invalid`), so a query an agent added meanwhile never leaves unseen.
 */
export const notebookExport = (notebookId: string, path: string, accepted: string[]) =>
  call<null>("notebook_export", { notebookId, path, accepted });
/** Imports a notebook file as a new case notebook; its id. */
export const notebookImport = (path: string) => call<string>("notebook_import", { path });
export const shareExport = (path: string) => call<ShareExported>("share_export", { path });
export const sharePreview = (path: string) => call<SharePreview>("share_preview", { path });
/** Refused (`invalid`) when the file's SHA-256 is no longer `sha256`, the one its preview showed. */
export const shareImport = (path: string, sha256: string) => call<ImportSummary>("share_import", { path, sha256 });

// ---------------------------------------------------------------- devices

/** `case::devices::SuspectReason` (serde tag `kind`, snake_case). */
export type SuspectReason =
  | { kind: "indicator"; ip: string; verdict: string }
  | { kind: "finding"; ip: string; finding_id: string; rule_id: string }
  | { kind: "travel_leg"; ip: string; finding_id: string }
  | { kind: "same_name"; name: string; of_device_id: string };

/** `case::devices::DeviceStatus`, in list order. */
export type DeviceStatus =
  | "active_after_removal"
  | "active"
  | "unknown"
  | "not_in_latest_inventory"
  | "disabled"
  | "removed";

/** `case::devices::DeviceSighting`; `event_time` is null for a stored row without a time. */
export interface DeviceSighting {
  tenant_key: string | null;
  device_id: string;
  display_name: string | null;
  os: string | null;
  trust_type: string | null;
  user_upn: string | null;
  ip: string | null;
  event_time: string | null;
  activity: string;
  source_table: string;
  record_key: string;
}

/** `case::devices::OtherIp`. */
export interface OtherIp {
  ip: string;
  asn: number | null;
  asn_org: string | null;
  country_iso: string | null;
  is_hosting: boolean | null;
}

/** `case::devices::LifecycleMark`: the record that sets a lifecycle date. */
export interface LifecycleMark {
  at: string;
  source_table: string;
  record_key: string;
}

/** `case::devices::Lifecycle`. */
export interface Lifecycle {
  status: DeviceStatus;
  registered: LifecycleMark | null;
  removed: LifecycleMark | null;
  disabled: LifecycleMark | null;
  last_active: LifecycleMark | null;
  latest_inventory_at: string | null;
}

/** `case::devices::SuspectDevice`; the list arrives sorted by status, confidence, last active. */
export interface SuspectDevice {
  tenant_key: string | null;
  device_id: string;
  object_id: string | null;
  display_name: string | null;
  os: string | null;
  trust_type: string | null;
  is_compliant: boolean | null;
  is_managed: boolean | null;
  confidence: "high" | "low";
  reasons: SuspectReason[];
  users: string[];
  malicious_ips: string[];
  other_ips: OtherIp[];
  sightings: DeviceSighting[];
  lifecycle: Lifecycle;
  /** The analyst's status of the device (by its id, else its object id), shown next to `lifecycle.status`. */
  analyst: DeviceDecision | null;
  /** The analyst said removed or disabled and the device was active later than that. */
  active_after_analyst_removal: boolean;
}

export const devicesList = (tenant?: string) => call<SuspectDevice[]>("devices_list", { tenant });

/** `case::device_status::AnalystStatus`: what the analyst says of a device. */
export type AnalystDeviceStatus = "removed" | "disabled" | "confirmed_attacker" | "benign";

/** `case::device_status::DeviceDecision`: the live analyst status of one device. */
export interface DeviceDecision {
  device_id: string;
  status: AnalystDeviceStatus;
  note: string | null;
  decided_by: string;
  decided_at: string;
}

/** Set (`status`) or clear (`null`) the analyst's status of a device, with an optional note. Analyst only. */
export const devicesSetAnalystStatus = (deviceId: string, status: AnalystDeviceStatus | null, note: string | null) =>
  call<AuditEntry>("devices_set_analyst_status", { deviceId, status, note });

/** `case::entity::FlaggedCounts`: a pivot row's events by effective flag, by any flag. */
export interface FlaggedCounts {
  malicious: number;
  suspicious: number;
}

// ---------------------------------------------------------------- events grid, entity tabs, marks (core serde shapes)

/** The kind of thing an entity tab is about. */
export type EntityKind = "account" | "ip" | "device" | "session";

/**
 * An entity, the one shape used everywhere: sent as `{kind, value}` with the value in any spelling (the backend
 * normalizes it), and returned in the stored spelling (lower-case account, device and session, normalized IP).
 */
export interface EntityArg {
  kind: EntityKind;
  value: string;
}

/** `case::events::Field`: the filter boxes of the grid. */
export type EventField = "source" | "operation" | "account" | "ip" | "country" | "asn" | "device" | "session" | "tag" | "rule";

export type FlagLevel = "suspicious" | "malicious";
/** `case::events::FlagFilter`. */
export type FlagFilter = "all" | FlagLevel;
/** `case::events::AiFilter`: `marked` has an agent mark, `unreviewed` one no analyst has confirmed. */
export type AiFilter = "all" | "marked" | "unreviewed";

/**
 * What the grid asks for (`cmd::events::EventQueryArgs`). `fields` holds Harrier's filter text per field (comma: OR;
 * `!value` excludes; `*` wildcard; a double-quoted value is literal, `""` one quote: `events/fieldSyntax.ts`); `search` is a raw-text search of every record (it needs a `queryId` on the
 * command); `from` / `to` are inclusive ISO 8601 UTC times.
 */
export interface EventQuery {
  entity?: EntityArg;
  fields: [EventField, string][];
  search?: string;
  from?: string;
  to?: string;
  flag: FlagFilter;
  ai: AiFilter;
}

/** `case::marks::TagRef`: `ai` for an agent's tag that no analyst has confirmed. */
export interface TagRef {
  name: string;
  ai: boolean;
}

/** `case::events::EventRow`. */
export interface EventRow {
  source_table: string;
  record_key: string;
  source: string;
  event_time: string | null;
  time_tz_assumed: boolean | null;
  tenant_key: string | null;
  workload: string | null;
  category: string;
  operation: string | null;
  result: string | null;
  actor_upn: string | null;
  owner_upn: string | null;
  target: string | null;
  ip: string | null;
  ip_prefix: string | null;
  ip_country: string | null;
  asn: number | null;
  asn_org: string | null;
  ip_kind: string | null;
  device_id: string | null;
  device_name: string | null;
  device_object_id: string | null;
  entra_session_id: string | null;
  user_agent: string | null;
  app_id: string | null;
  summary: string | null;
  finding_count: number;
  tags: TagRef[];
  /** Rule ids of the open findings (not closed as false positive or benign) with this event as evidence, sorted. */
  rules: string[];
  /** The strongest of the row's own flag and every standing value flag that matches it. */
  flag: FlagLevel | null;
  /** The flag comes only from an agent's flag that no analyst has confirmed. */
  flag_ai: boolean;
  /**
   * An agent's mark that no analyst has confirmed covers the event: its own flag, a standing flag on a value it carries,
   * or a tag. True even when a stronger confirmed flag hides the pending one (`flag_ai` is then false); Confirm and
   * Remove AI marks act on these events.
   */
  ai_pending: boolean;
  latest_note: string | null;
  note_count: number;
}

/** `case::events::EventsPage`: `total` counts up to a cap; `total_capped` says there are more. */
export interface EventsPage {
  rows: EventRow[];
  offset: number;
  total: number;
  total_capped: boolean;
}

/** `case::events::EventsSummary`; `per_source` is in grid order, sources with no event left out. */
export interface EventsSummary {
  total: number;
  suspicious: number;
  malicious: number;
  per_source: [string, number][];
  /** `message_trace_event` rows the query matches but leaves out unless its Source field names them. */
  hidden_trace_events: number;
}

/** `case::events::FindingMark`: an open finding in the histogram's findings lane. */
export interface FindingMark {
  finding_id: string;
  severity: string;
  first_seen: string;
  last_seen: string;
}

/** `case::events::HistogramGroup`: what the histogram stacks its bars by. */
export type HistogramGroup = "source" | "operation";

/**
 * `case::events::Histogram`. Bucket `i` covers `[start + i * bucket_seconds, start + (i + 1) * bucket_seconds)`; an event
 * exactly at the range end is in the last bucket. `series` is `[name, counts per bucket]`, empty for no rows: by source in
 * grid order; by operation the ten most frequent operations, most first, with every other event (other operations and
 * events with no operation) in `other` (null when there are none, and always null by source).
 */
export interface Histogram {
  start: string;
  bucket_seconds: number;
  group: HistogramGroup;
  series: [string, number[]][];
  other: number[] | null;
  findings: FindingMark[];
}

/** `case::marks::FlagSource`: why a row is flagged (its own flag, or a standing flag on a value it carries). */
export interface FlagSource {
  origin: "row" | "value";
  level: FlagLevel;
  kind: string | null;
  value: string | null;
  scope_kind: string | null;
  scope_value: string | null;
  decided_by: string;
  review_state: string;
}

/** `case::events::EventDetail`; `raw` is the stored evidence record as JSON. */
export interface EventDetail {
  row: EventRow;
  raw: unknown;
  source_refs: string[];
  tags: TagRef[];
  notes: Note[];
  flag: FlagLevel | null;
  flag_sources: FlagSource[];
}

/** `cmd::entity::EntitySummaryView`: the tiles of an entity tab. `entity` is `{kind, value}` in the stored spelling. */
export interface EntitySummary {
  entity: EntityArg;
  first_seen: string | null;
  last_seen: string | null;
  events: number;
  /** The keys `accounts`, `ips`, `countries`, `asns`, `devices`, `sessions`. */
  distinct: Record<string, number>;
  /** Severity to the number of open findings citing the entity's events in range. */
  open_findings: Record<string, number>;
  /** Account tab only: `actor`, `mailbox owner`, `message sender`, `message recipient`. */
  roles_matched: string[];
  ip_intel: Record<string, unknown> | null;
  device: Record<string, unknown> | null;
  /** Device tab: the analyst's status of the device; null for other kinds and when none. */
  analyst_status: DeviceDecision | null;
  active_after_analyst_removal: boolean;
}

/** `case::entity::PivotOf`. `device_changes` is for the device tab only. */
export type PivotOf = "accounts" | "ips" | "devices" | "sessions" | "device_changes";

/** `case::entity::PivotRow`; `extra` holds the columns that depend on the table (see the Rust docs). */
export interface PivotRow {
  value: string;
  label: string | null;
  count: number;
  first_seen: string;
  last_seen: string;
  is_new: boolean;
  /** The standing flag on the value that covers this tab's events (case-wide, or made inside this tab); null if none. */
  flag: PivotFlag | null;
  /** The row's events flagged by any flag (their own, or a standing flag on any of their values); zeros if none. */
  flagged: FlaggedCounts;
  extra: Record<string, unknown>;
}

/** `case::entity::PivotFlag`: the strongest active flag on a pivot row's value. `pending` is an agent's, unreviewed. */
export interface PivotFlag {
  level: FlagLevel;
  pending: boolean;
  /** `case` when a case-wide flag has that level, else `entity` (made inside this tab). */
  scope: "case" | "entity";
}

/** `case::entity::PivotPage`: the first `rows` of `total`. */
export interface PivotPage {
  rows: PivotRow[];
  total: number;
}

/** `case::entity::FindingRef`. */
export interface FindingRef {
  finding_id: string;
  rule_id: string | null;
  title: string;
  severity: string;
  status: string;
  first_seen: string | null;
}

/** `case::coverage::RangeState`: what the case holds of one source over a range. */
export type CoverageState = "covered" | "sampled" | "absent";

/** `case::coverage::SourceState`. `accounts_by_state` is empty for a tenant-wide source (message trace, Entra audit). */
export interface CoverageSource {
  source: string;
  title: string;
  /** The worst over the accounts: absent, then sampled, then covered. */
  state: CoverageState;
  accounts_by_state: Partial<Record<CoverageState, string[]>>;
}

/** One tenant's section of an entity tab's coverage strip. */
export interface TenantCoverage {
  tenant_key: string;
  accounts: string[];
  sources: CoverageSource[];
}

/**
 * `from` / `to`: the UTC days (`YYYY-MM-DD`) judged, even when none of the entity's events fall in them. Null, and no
 * tenants, only when the entity has no events at all. A tenant's `accounts` are those in the entity's events in the range,
 * or in the whole case when none fall in it.
 */
export interface EntityCoverage {
  from: string | null;
  to: string | null;
  tenants: TenantCoverage[];
}

/** `case::marks::RowRef`: the key of an event row. */
export interface RowRef {
  source_table: string;
  record_key: string;
}

/** `case::marks::ValueKind`: what a standing flag on a value matches. */
export type ValueKind = "ip" | "ip_prefix" | "account" | "asn" | "device" | "session";

/** `case::marks::IndicatorChange`: an indicator a Malicious flag added (`created`) or updated. */
export interface IndicatorChange {
  tenant_key: string | null;
  indicator_id: string;
  created: boolean;
}

/** `cmd::marks::ValueFlagged`: the flag's audit row, and the indicators it added or updated (none for most flags). */
export interface ValueFlagged {
  audit: AuditEntry;
  indicators: IndicatorChange[];
}

/** `case::marks::TagInfo`. */
export interface TagInfo {
  name: string;
  count: number;
  agent_unreviewed: number;
}

/** `cmd::timeline::AddEventsArgs`: exactly one of `rows` and `query`. `each` is refused over 200 events. */
export interface AddEventsArgs {
  rows?: RowRef[];
  query?: EventQuery;
  mode: "each" | "group";
  title?: string;
  /** A phase name; without one it comes from the events' categories. */
  phase?: string;
}

/** `cmd::timeline::EventsAdded`. */
export interface EventsAdded {
  entryIds: string[];
  /** One line for a toast. */
  outcome: string;
}

/** The most events `timelineAddEvents` turns into entries one by one. */
export const EACH_MAX = 200;

/**
 * `queryId` names the run for `queryCancel`; it is required (the backend refuses without it) when the query has a raw
 * `search`, and ignored otherwise. A fresh one per run: `newQueryId()`.
 */
export const eventsPage = (query: EventQuery, sort: Sort | null, offset: number, limit: number, queryId?: string) =>
  call<EventsPage>("events_page", { query, sort, offset, limit, queryId });
export const eventsSummary = (query: EventQuery, queryId?: string) =>
  call<EventsSummary>("events_summary", { query, queryId });
export const eventsHistogram = (query: EventQuery, maxBuckets: number, group: HistogramGroup, queryId?: string) =>
  call<Histogram>("events_histogram", { query, maxBuckets, group, queryId });
export const eventsDetail = (sourceTable: string, recordKey: string) =>
  call<EventDetail>("events_detail", { sourceTable, recordKey });
/** Distinct case values of `field` that start with `prefix`, sorted, at most 200. */
export const eventsSuggest = (field: EventField, prefix: string) => call<string[]>("events_suggest", { field, prefix });
/** Writes every event the query matches (not a page) as CSV at `path`; resolves to the rows written. */
export const eventsExportCsv = (query: EventQuery, path: string, queryId?: string) =>
  call<number>("events_export_csv", { query, path, queryId });

/** `case::events::ValueCount` / `FieldValues`: a column filter's list, most events first; `total` counts every value. */
export interface ValueCount {
  value: string;
  count: number;
}
export interface FieldValues {
  values: ValueCount[];
  total: number;
}
/** The most values one `eventsValues` call returns. */
export const VALUES_MAX = 200;
/**
 * The values of `field` with their event counts among the events `query` matches, the field's own filter left out.
 * `prefix` is a case-insensitive start (`*` wildcard); at most `limit` (1 to 200; 0 is refused). `queryId` as for `eventsPage`.
 */
export const eventsValues = (query: EventQuery, field: EventField, prefix: string, limit: number, queryId?: string) =>
  call<FieldValues>("events_values", { query, field, prefix, limit, queryId });

/** `from` / `to`: inclusive ISO 8601 UTC times; either may be omitted. */
export const entitySummary = (entity: EntityArg, from?: string, to?: string) =>
  call<EntitySummary>("entity_summary", { entity, from, to });
/** At most `limit` rows (default 500, at most 5000); `total` is every value the table has. */
export const entityPivot = (entity: EntityArg, of: PivotOf, from?: string, to?: string, limit?: number) =>
  call<PivotPage>("entity_pivot", { entity, of, from, to, limit });
export const entityFindings = (entity: EntityArg, from?: string, to?: string) =>
  call<FindingRef[]>("entity_findings", { entity, from, to });
/** Each source's state over the range, per tenant, for the accounts in the entity's events in it. */
export const entityCoverage = (entity: EntityArg, from?: string, to?: string) =>
  call<EntityCoverage>("entity_coverage", { entity, from, to });

/** Sets (`level`) or clears (`null`) the flag of event rows: one audit row. */
export const marksFlagRows = (rows: RowRef[], level: FlagLevel | null) =>
  call<AuditEntry>("marks_flag_rows", { rows, level });
/** Sets or clears a standing flag on a value; `scope` limits it to one entity's events. */
export const marksFlagValue = (kind: ValueKind, value: string, scope: EntityArg | null, level: FlagLevel | null) =>
  call<ValueFlagged>("marks_flag_value", { kind, value, scope, level });
export const marksTagRows = (rows: RowRef[], tag: string, add: boolean) =>
  call<AuditEntry>("marks_tag_rows", { rows, tag, add });
export const marksListTags = () => call<TagInfo[]>("marks_list_tags");
/**
 * Confirms (`accept`) or removes the agent marks pending on `rows`. This also reviews every pending standing value flag
 * that covers any of the rows, and so changes every row such a flag covers: the UI must warn.
 */
export const marksReview = (rows: RowRef[], accept: boolean) => call<AuditEntry[]>("marks_review", { rows, accept });
/** One note on each row (at most 200 rows); the audit rows come back in row order. */
export const notesAddRows = (rows: RowRef[], text: string) => call<AuditEntry[]>("notes_add_rows", { rows, text });
export const timelineAddEvents = (args: AddEventsArgs) => call<EventsAdded>("timeline_add_events", { args });

// ---------------------------------------------------------------- import (ingest from the window)

/** `cmd::ingest::PreviewFile.status`. */
export type PreviewFileStatus = "recognised" | "unrecognised" | "too_large" | "unreadable";

export interface PreviewFile {
  rel_path: string;
  artifact_id: string | null;
  derived: boolean;
  size: number;
  status: PreviewFileStatus;
  error: string | null;
}

export interface PreviewCollection {
  tool: "hawk" | "invictus" | "portal_export";
  root: string;
  tenant_hint: string | null;
  started_hint: string | null;
  files: PreviewFile[];
}

/** What discovery finds under a folder; nothing is written. */
export interface DiscoveryPreview {
  path: string;
  collections: PreviewCollection[];
  recognised: number;
  unrecognised: number;
  too_large: number;
  unreadable: number;
  max_file_bytes: number;
}

/** Into the open case, or a new case file at this path (which must not exist). */
export type IngestTarget = "open" | { new_case: string };

/** The `ingest-progress` event (serde tag `stage`). */
export type IngestProgress =
  | { stage: "discover" }
  | { stage: "collection"; index: number; count: number; root: string }
  | { stage: "file"; collection: number; collections: number; index: number; files: number; rel_path: string }
  | { stage: "profile" }
  | { stage: "detect" };

/** `ingest::FileReport` (the fields the result card reads). */
export interface IngestFileReport {
  rel_path: string;
  artifact_id: string | null;
  status: string;
  records_read: number;
  records_loaded: number;
  records_duplicate: number;
  records_error: number;
  records_collector_lost: number;
  warnings: string[];
}

export interface IngestResult {
  case_path: string;
  /** Cancel (or closing the window) was asked for: detection did not run, and `not_loaded` lists any file left. */
  cancelled: boolean;
  /** A hard error stopped the import after the files in `report` had committed (they stay loaded and were profiled). */
  error: string | null;
  report: { collections: { collection_id: number; tool: string; root: string; files: IngestFileReport[] }[] };
  files_loaded: number;
  files_total: number;
  rows_by_source: { source: string; files: number; rows: number }[];
  /** Files that failed, had records rejected, or carry warnings. */
  file_notes: { root: string; rel_path: string; status: string; notes: string[] }[];
  not_loaded: { root: string; rel_path: string }[];
  /** The profile step failed after the evidence loaded. */
  profile_error: string | null;
  profile_warnings: string[];
  /** `null` when detection was skipped (asked, or cancelled) or failed (`detect_error`). */
  detect: { findings_new: number; findings_updated: number; warnings: string[] } | null;
  detect_error: string | null;
}

export const ingestDiscover = (path: string) => call<DiscoveryPreview>("ingest_discover", { path });
/**
 * Imports the folder as `sparrow ingest` does (profile, then detection unless `detect` is false), emitting
 * `ingest-progress` (see `onIngestProgress`). `culture` is the CLI's `--culture`. While it runs the open case is held,
 * so every other command waits. Refused (`read_only`) on a read-only case; `invalid` when a case file already exists
 * at the new path or an import already runs.
 */
export const ingestRun = (path: string, target: IngestTarget, culture: string | null, detect: boolean, runId: string) =>
  call<IngestResult>("ingest_run", { path, target, culture, detect, runId });
/**
 * Stops the import `runId` (the id `ingestRun` was given) after the file it is loading; the result says what was left.
 * Safe before the run has started: the run then stops at its first check.
 */
export const ingestCancel = (runId: string) => call<null>("ingest_cancel", { runId });
/** Collections an import loaded but never profiled (the process was killed mid-import): their ids. */
export const ingestUnprofiled = () => call<number[]>("ingest_unprofiled");
/** What `ingestProfile` did (the profile step and detection, as `sparrow profile`). */
export interface ProfileRun {
  profile_error: string | null;
  profile_warnings: string[];
  detect: { findings_new: number; findings_updated: number; warnings: string[] } | null;
  detect_error: string | null;
}
/** "Run profile now": analyst-started; `read_only` on a read-only case. */
export const ingestProfile = (runId: string) => call<ProfileRun>("ingest_profile", { runId });
/** The window asked to close during an import: the backend finishes the current file and the profile, then closes. */
export async function onIngestClosing(handler: () => void): Promise<() => void> {
  if (__SPARROW_MOCK__) return (await import("./mock/backend")).mockOnIngestClosing(handler);
  return listen("ingest-closing", () => handler());
}
/** Calls `handler` with each progress event until the returned function is called. */
export async function onIngestProgress(handler: (p: IngestProgress) => void): Promise<() => void> {
  if (__SPARROW_MOCK__) return (await import("./mock/backend")).mockOnIngestProgress(handler);
  return listen<IngestProgress>("ingest-progress", (e) => handler(e.payload));
}

/** An agent's request through the app's agent bridge (`sparrow` CLI commands run on the open case). */
export interface AgentActivity {
  /** The CLI's `--agent` id, when it gave one. */
  agent: string | null;
  /** The command words, e.g. `mark tag`. */
  command: string;
  /** When it started (`running`) or ended. */
  at: string;
  running: boolean;
}
/** The agent bridge wrote to the case: what changed (`marks`, `notes`, `findings`, `indicators`, `timeline`, `tenant`). */
export interface CaseChanged {
  kinds: string[];
}
/** Calls `handler` after each write through the agent bridge, until the returned function is called. */
export async function onCaseChanged(handler: (c: CaseChanged) => void): Promise<() => void> {
  if (__SPARROW_MOCK__) return (await import("./mock/backend")).mockOnCaseChanged(handler);
  return listen<CaseChanged>("case-changed", (e) => handler(e.payload));
}
/** Calls `handler` when an agent's bridge request starts and ends, until the returned function is called. */
export async function onAgentActivity(handler: (a: AgentActivity) => void): Promise<() => void> {
  if (__SPARROW_MOCK__) return (await import("./mock/backend")).mockOnAgentActivity(handler);
  return listen<AgentActivity>("agent-activity", (e) => handler(e.payload));
}
