// Typed access to the recorded command responses (test/fixtures/*.json, recorded from a synthetic case by the
// backend). Each loader checks the shape at runtime, so a change in the Rust serde shapes fails a test here instead of
// being hidden behind a cast. Every call returns a fresh deep copy, safe to edit into a variant.
import caseInfoJson from "./fixtures/case_info.json";
import findingDetailJson from "./fixtures/finding_detail.json";
import queueJson from "./fixtures/queue.json";
import accountsJson from "./fixtures/accounts.json";
import pivotIpJson from "./fixtures/pivot_ip.json";
import pivotUserJson from "./fixtures/pivot_user.json";
import type { AccountPage, CaseInfo, FindingDetail, Pivot, QueueItem } from "../api";

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

const ACCOUNT = [
  "tenant_key", "upn", "worst_severity", "finding_count", "by_severity", "stages", "first_suspicious", "rules",
  "addresses", "addresses_total", "addresses_truncated",
];
const ADDRESS = ["ip", "reasons", "tables", "first_seen", "last_seen", "asn", "asn_org", "is_hosting", "spray_source"];

export function accounts(): AccountPage {
  const v: unknown = clone(accountsJson);
  need("accounts", v, ["accounts", "total", "truncated", "warnings"]);
  if (!Array.isArray(v.accounts) || v.accounts.length === 0) throw new Error("fixture accounts: no accounts");
  if (!Array.isArray(v.warnings)) throw new Error("fixture accounts: warnings is not an array");
  v.accounts.forEach((a: unknown, i) => {
    need(`accounts[${i}]`, a, ACCOUNT);
    if (!Array.isArray(a.addresses)) throw new Error(`fixture accounts[${i}]: addresses is not an array`);
    a.addresses.forEach((x: unknown, j) => need(`accounts[${i}].addresses[${j}]`, x, ADDRESS));
  });
  return v as unknown as AccountPage;
}

const SECTION = ["name", "rows", "total", "truncated"];

function checkPivot(name: string, json: unknown): Pivot {
  const v: unknown = clone(json);
  need(name, v, ["sections"]);
  if (!Array.isArray(v.sections) || v.sections.length === 0) throw new Error(`fixture ${name}: no sections`);
  v.sections.forEach((s: unknown, i) => {
    need(`${name}.sections[${i}]`, s, SECTION);
    if (typeof s.name !== "string") throw new Error(`fixture ${name}.sections[${i}]: name is not a string`);
    if (!Array.isArray(s.rows)) throw new Error(`fixture ${name}.sections[${i}]: rows is not an array`);
    if (typeof s.total !== "number") throw new Error(`fixture ${name}.sections[${i}]: total is not a number`);
    if (typeof s.truncated !== "boolean") throw new Error(`fixture ${name}.sections[${i}]: truncated is not a boolean`);
    if ("unavailable" in s && typeof s.unavailable !== "string") {
      throw new Error(`fixture ${name}.sections[${i}]: unavailable is not a string`);
    }
  });
  return v as unknown as Pivot;
}

/** `read::Pivot` for an IP, recorded from a synthetic case. */
export const pivotIp = (): Pivot => checkPivot("pivot_ip", pivotIpJson);
/** `read::Pivot` for an account (its `addresses` section is the only one that can be `unavailable`). */
export const pivotUser = (): Pivot => checkPivot("pivot_user", pivotUserJson);
