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

// ---- timeline (core serde shapes) ----

export interface EvidenceRef {
  source_table: string;
  record_key: string;
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

// ---- finding detail (the parts the timeline's evidence picker reads) ----

export interface FindingEvidenceRow {
  source_table: string;
  record_key: string;
  role: string;
  event_time: string | null;
  source_refs: string[];
  context: unknown;
}

export interface FindingDetail {
  finding: { finding_id: string; title: string; [k: string]: unknown };
  evidence: FindingEvidenceRow[];
  [k: string]: unknown;
}

export const findingDetail = (findingId: string) => call<FindingDetail>("finding_detail", { findingId });
