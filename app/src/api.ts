// The only caller of Tauri's `invoke`. Screens call the typed wrappers added here per command; the JSON shapes are
// the Rust core's serde shapes unchanged. No logic lives in the frontend.
import { invoke } from "@tauri-apps/api/core";

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
}

export const devicesList = (tenant?: string) => call<SuspectDevice[]>("devices_list", { tenant });

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
export type EventField = "source" | "operation" | "account" | "ip" | "country" | "asn" | "device" | "session" | "tag";

export type FlagLevel = "suspicious" | "malicious";
/** `case::events::FlagFilter`. */
export type FlagFilter = "all" | FlagLevel;
/** `case::events::AiFilter`: `marked` has an agent mark, `unreviewed` one no analyst has confirmed. */
export type AiFilter = "all" | "marked" | "unreviewed";

/**
 * What the grid asks for (`cmd::events::EventQueryArgs`). `fields` holds Harrier's filter text per box (comma: OR;
 * `!value` excludes; `*` wildcard); `search` is a raw-text search of every record (it needs a `queryId` on the
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

/**
 * `case::events::Histogram`. Bucket `i` covers `[start + i * bucket_seconds, start + (i + 1) * bucket_seconds)`; an event
 * exactly at the range end is in the last bucket. `series` is `[source, counts per bucket]`, empty for no rows.
 */
export interface Histogram {
  start: string;
  bucket_seconds: number;
  series: [string, number[]][];
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
  extra: Record<string, unknown>;
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
export const eventsHistogram = (query: EventQuery, maxBuckets: number, queryId?: string) =>
  call<Histogram>("events_histogram", { query, maxBuckets, queryId });
export const eventsDetail = (sourceTable: string, recordKey: string) =>
  call<EventDetail>("events_detail", { sourceTable, recordKey });
/** Distinct case values of `field` that start with `prefix`, sorted, at most 200. */
export const eventsSuggest = (field: EventField, prefix: string) => call<string[]>("events_suggest", { field, prefix });
/** Writes every event the query matches (not a page) as CSV at `path`; resolves to the rows written. */
export const eventsExportCsv = (query: EventQuery, path: string, queryId?: string) =>
  call<number>("events_export_csv", { query, path, queryId });

/** `from` / `to`: inclusive ISO 8601 UTC times; either may be omitted. */
export const entitySummary = (entity: EntityArg, from?: string, to?: string) =>
  call<EntitySummary>("entity_summary", { entity, from, to });
/** At most `limit` rows (default 500, at most 5000); `total` is every value the table has. */
export const entityPivot = (entity: EntityArg, of: PivotOf, from?: string, to?: string, limit?: number) =>
  call<PivotPage>("entity_pivot", { entity, of, from, to, limit });
export const entityFindings = (entity: EntityArg, from?: string, to?: string) =>
  call<FindingRef[]>("entity_findings", { entity, from, to });

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
