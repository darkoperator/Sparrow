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

// ---------------------------------------------------------------- SQL and share (core serde shapes)

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

/** `case::query::QueryResult`; each value is DuckDB's `to_json` of the column. */
export interface QueryResult {
  columns: string[];
  rows: unknown[][];
  truncated: boolean;
}

/** `case::share::ImportSummary`. */
export interface ImportSummary {
  bundle_sha256: string;
  analyst: string;
  new: number;
  agrees: number;
  conflicts: number;
  missing: number;
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
}

export const sqlSchema = (table?: string) => call<TableInfo[]>("sql_schema", { table });
export const sqlRun = (sql: string, limit?: number) => call<QueryResult>("sql_run", { sql, limit });
/** Interrupts the running `sql_run` / `browse_page`, if any; that call then rejects with kind `interrupted`. */
export const queryCancel = () => call<null>("query_cancel");
export const shareExport = (path: string) => call<ShareExported>("share_export", { path });
export const sharePreview = (path: string) => call<SharePreview>("share_preview", { path });
/** Refused (`invalid`) when the file's SHA-256 is no longer `sha256`, the one its preview showed. */
export const shareImport = (path: string, sha256: string) => call<ImportSummary>("share_import", { path, sha256 });
