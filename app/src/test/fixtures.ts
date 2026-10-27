// Typed access to the recorded command responses (test/fixtures/*.json, recorded from a synthetic case by the
// backend). Each loader checks the shape at runtime, so a change in the Rust serde shapes fails a test here instead of
// being hidden behind a cast. Every call returns a fresh deep copy, safe to edit into a variant.
import caseInfoJson from "./fixtures/case_info.json";
import findingDetailJson from "./fixtures/finding_detail.json";
import queueJson from "./fixtures/queue.json";
import accountsJson from "./fixtures/accounts.json";
import devicesJson from "./fixtures/devices.json";
import devicesRecordedJson from "./fixtures/devices_recorded.json";
import schemaJson from "./fixtures/schema.json";
import sqlResultJson from "./fixtures/sql_result.json";
import sharePreviewJson from "./fixtures/share_preview.json";
import pivotIpJson from "./fixtures/pivot_ip.json";
import pivotUserJson from "./fixtures/pivot_user.json";
import browsePageJson from "./fixtures/browse_page.json";
import indicatorsJson from "./fixtures/indicators.json";
import type {
  AccountPage,
  ActiveIndicator,
  BrowsePage,
  CaseInfo,
  SuspectDevice,
  FindingDetail,
  Pivot,
  QueryResult,
  QueueItem,
  SharePreview,
  TableInfo,
} from "../api";

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

const BROWSE = ["table", "columns", "rows", "offset", "total", "total_capped"];

/** `browse::BrowsePage` for `signins`, recorded from a synthetic case. */
export function browsePage(): BrowsePage {
  const v: unknown = clone(browsePageJson);
  need("browse_page", v, BROWSE);
  if (!Array.isArray(v.columns) || v.columns.length === 0) throw new Error("fixture browse_page: no columns");
  if (!Array.isArray(v.rows) || v.rows.length === 0) throw new Error("fixture browse_page: no rows");
  v.rows.forEach((r: unknown, i) => {
    if (!Array.isArray(r) || r.length !== (v.columns as unknown[]).length) {
      throw new Error(`fixture browse_page.rows[${i}]: not one value per column`);
    }
  });
  if (typeof v.total !== "number" || typeof v.total_capped !== "boolean") throw new Error("fixture browse_page: bad total");
  return v as unknown as BrowsePage;
}

/** `db::describe::TableInfo[]` of the whole synthetic case. */
export function schema(): TableInfo[] {
  const v: unknown = clone(schemaJson);
  if (!Array.isArray(v) || v.length === 0) throw new Error("fixture schema: not a non-empty array");
  v.forEach((t: unknown, i) => {
    need(`schema[${i}]`, t, ["name", "comment", "kind", "columns"]);
    if (!Array.isArray(t.columns) || t.columns.length === 0) throw new Error(`fixture schema[${i}]: no columns`);
    t.columns.forEach((c: unknown, j) => need(`schema[${i}].columns[${j}]`, c, ["name", "type", "comment"]));
  });
  return v as unknown as TableInfo[];
}

export function indicators(): ActiveIndicator[] {
  const v: unknown = clone(indicatorsJson);
  if (!Array.isArray(v) || v.length === 0) throw new Error("fixture indicators: not a non-empty array");
  v.forEach((x: unknown, i) => need(`indicators[${i}]`, x, ["ioc_type", "value", "verdict"]));
  return v as unknown as ActiveIndicator[];
}

// sql_run and share_preview, recorded by the backend (query::QueryResult, cmd::share::SharePreview with
// share::ImportSummary).

export function sqlResult(): QueryResult {
  const v: unknown = clone(sqlResultJson);
  need("sql_result", v, ["columns", "rows", "truncated", "ordered"]);
  if (!Array.isArray(v.columns) || v.columns.length === 0) throw new Error("fixture sql_result: no columns");
  if (!Array.isArray(v.rows) || v.rows.length === 0) throw new Error("fixture sql_result: no rows");
  const width = v.columns.length;
  v.rows.forEach((r: unknown, i) => {
    if (!Array.isArray(r) || r.length !== width) throw new Error(`fixture sql_result.rows[${i}]: not ${width} values`);
  });
  if (typeof v.truncated !== "boolean") throw new Error("fixture sql_result: truncated is not a boolean");
  return v as unknown as QueryResult;
}

const SUMMARY = [
  "bundle_sha256", "analyst", "new", "agrees", "conflicts", "missing", "superseded", "already_imported",
  "rules_only_in_bundle", "rules_only_here",
];

export function sharePreview(): SharePreview {
  const v: unknown = clone(sharePreviewJson);
  need("share_preview", v, ["sha256", "summary", "analyst", "exported_at", "items"]);
  need("share_preview.summary", v.summary, SUMMARY);
  if (v.summary.bundle_sha256 !== v.sha256) throw new Error("fixture share_preview: summary sha differs from sha256");
  return v as unknown as SharePreview;
}

const DEVICE = [
  "tenant_key", "device_id", "object_id", "display_name", "os", "trust_type", "is_compliant", "is_managed", "confidence",
  "reasons", "users", "malicious_ips", "other_ips", "sightings", "lifecycle",
];
const SIGHTING = [
  "tenant_key", "device_id", "display_name", "os", "trust_type", "user_upn", "ip", "event_time", "activity",
  "source_table", "record_key",
];
const LIFECYCLE = ["status", "registered", "removed", "disabled", "last_active", "latest_inventory_at"];
const OTHER_IP = ["ip", "asn", "asn_org", "country_iso", "is_hosting"];
const MARK = ["at", "source_table", "record_key"];
const STATUSES = ["active_after_removal", "active", "unknown", "not_in_latest_inventory", "disabled", "removed"];
const REASON_FIELDS: Record<string, string[]> = {
  indicator: ["ip", "verdict"],
  finding: ["ip", "finding_id", "rule_id"],
  travel_leg: ["ip", "finding_id"],
  same_name: ["name", "of_device_id"],
};

const isStringOrNull = (v: unknown) => v === null || typeof v === "string";

/** Validates the nested serde shape of a `devices_list` response (enum values, nullable fields, tagged reasons). */
function checkDevices(name: string, json: unknown): SuspectDevice[] {
  const v: unknown = clone(json);
  if (!Array.isArray(v) || v.length === 0) throw new Error(`fixture ${name}: no devices`);
  v.forEach((d: unknown, i) => {
    const at = `${name}[${i}]`;
    need(at, d, DEVICE);
    if (d.confidence !== "high" && d.confidence !== "low") throw new Error(`fixture ${at}: confidence ${String(d.confidence)}`);
    for (const k of ["users", "malicious_ips"] as const) {
      if (!Array.isArray(d[k]) || !d[k].every((x) => typeof x === "string")) throw new Error(`fixture ${at}: ${k} is not a string array`);
    }
    if (!Array.isArray(d.reasons) || d.reasons.length === 0) throw new Error(`fixture ${at}: no reasons`);
    d.reasons.forEach((r: unknown, j) => {
      need(`${at}.reasons[${j}]`, r, ["kind"]);
      const fields = typeof r.kind === "string" ? REASON_FIELDS[r.kind] : undefined;
      if (!fields) throw new Error(`fixture ${at}.reasons[${j}]: kind ${String(r.kind)}`);
      need(`${at}.reasons[${j}]`, r, fields);
    });
    if (!Array.isArray(d.other_ips)) throw new Error(`fixture ${at}: other_ips is not an array`);
    d.other_ips.forEach((o: unknown, j) => need(`${at}.other_ips[${j}]`, o, OTHER_IP));
    need(`${at}.lifecycle`, d.lifecycle, LIFECYCLE);
    const lc = d.lifecycle as Record<string, unknown>;
    if (typeof lc.status !== "string" || !STATUSES.includes(lc.status)) throw new Error(`fixture ${at}: status ${String(lc.status)}`);
    for (const k of ["registered", "removed", "disabled", "last_active"]) {
      if (lc[k] !== null) need(`${at}.lifecycle.${k}`, lc[k], MARK);
    }
    if (!isStringOrNull(lc.latest_inventory_at)) throw new Error(`fixture ${at}: latest_inventory_at`);
    if (!Array.isArray(d.sightings) || d.sightings.length === 0) throw new Error(`fixture ${at}: no sightings`);
    d.sightings.forEach((s: unknown, j) => {
      need(`${at}.sightings[${j}]`, s, SIGHTING);
      if (!isStringOrNull(s.event_time)) throw new Error(`fixture ${at}.sightings[${j}]: event_time`);
      if (typeof s.source_table !== "string" || typeof s.record_key !== "string") throw new Error(`fixture ${at}.sightings[${j}]: source`);
    });
  });
  return v as unknown as SuspectDevice[];
}

/** `case::devices::SuspectDevice` list: synthetic, one device per status the screen distinguishes, in list order. */
export const devices = (): SuspectDevice[] => checkDevices("devices", devicesJson);

/** The `devices_list` response recorded from the synthetic Rust case by the backend recorder. */
export const devicesRecorded = (): SuspectDevice[] => checkDevices("devices_recorded", devicesRecordedJson);
