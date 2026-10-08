// Typed access to the recorded command responses (test/fixtures/*.json, recorded from a synthetic case by the
// backend). Each loader checks the shape at runtime, so a change in the Rust serde shapes fails a test here instead of
// being hidden behind a cast. Every call returns a fresh deep copy, safe to edit into a variant.
import caseInfoJson from "./fixtures/case_info.json";
import findingDetailJson from "./fixtures/finding_detail.json";
import queueJson from "./fixtures/queue.json";
import type { CaseInfo, FindingDetail, QueueItem } from "../api";

function need(where: string, o: unknown, keys: string[]): asserts o is Record<string, unknown> {
  if (typeof o !== "object" || o === null) throw new Error(`fixture ${where}: not an object`);
  for (const k of keys) {
    if (!(k in o)) throw new Error(`fixture ${where}: missing key "${k}"`);
  }
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

const DECISION = [
  "object_type", "object_id", "decision_seq", "action", "actor", "on_behalf_of", "decided_at",
  "before", "after", "reason", "account", "title",
];
const PROPOSAL = ["bundle_sha256", "item_key", "source_analyst", "classification", "state", "item", "current"];
const FINDING = [
  "finding_id", "tenant_key", "rule_id", "severity", "title", "actor_upn", "status", "review_state", "evidence_count",
];
const EVIDENCE = ["source_table", "record_key", "role", "event_time", "source_refs", "timeline", "context"];
const AUDIT = ["seq", "ts", "actor", "action", "object_type", "object_id", "before", "after", "reason", "hash"];

export function caseInfo(): CaseInfo {
  const v: unknown = clone(caseInfoJson);
  need("case_info", v, ["path", "case_id", "schema_version", "audit_ok", "read_only_reason", "tenants", "warnings"]);
  return v as unknown as CaseInfo;
}

export function queue(): QueueItem[] {
  const v: unknown = clone(queueJson);
  if (!Array.isArray(v) || v.length === 0) throw new Error("fixture queue: not a non-empty array");
  v.forEach((q: unknown, i) => {
    need(`queue[${i}]`, q, ["source"]);
    if (q.source === "decision") need(`queue[${i}] decision`, q, DECISION);
    else if (q.source === "proposal") need(`queue[${i}] proposal`, q, PROPOSAL);
    else throw new Error(`fixture queue[${i}]: unknown source ${String(q.source)}`);
  });
  return v as QueueItem[];
}

export function findingDetail(): FindingDetail {
  const v: unknown = clone(findingDetailJson);
  need("finding_detail", v, ["finding", "evidence", "analyst_guidance", "notes", "audit"]);
  need("finding_detail.finding", v.finding, FINDING);
  if (!Array.isArray(v.evidence) || v.evidence.length === 0) throw new Error("fixture finding_detail: no evidence");
  v.evidence.forEach((e: unknown, i) => need(`finding_detail.evidence[${i}]`, e, EVIDENCE));
  if (!Array.isArray(v.audit) || v.audit.length === 0) throw new Error("fixture finding_detail: no audit");
  v.audit.forEach((a: unknown, i) => need(`finding_detail.audit[${i}]`, a, AUDIT));
  return v as unknown as FindingDetail;
}
