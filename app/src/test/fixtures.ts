// Typed access to the recorded command responses (test/fixtures/*.json, recorded from a synthetic case by the
// backend). Each loader checks the shape at runtime, so a change in the Rust serde shapes fails a test here instead of
// being hidden behind a cast. Every call returns a fresh deep copy, safe to edit into a variant.
import accessReportJson from "./fixtures/access_report.json";
import caseInfoJson from "./fixtures/case_info.json";
import findingDetailJson from "./fixtures/finding_detail.json";
import queueJson from "./fixtures/queue.json";
import accountsJson from "./fixtures/accounts.json";
import devicesJson from "./fixtures/devices.json";
import devicesRecordedJson from "./fixtures/devices_recorded.json";
import schemaJson from "./fixtures/schema.json";
import sqlResultJson from "./fixtures/sql_result.json";
import sharePreviewJson from "./fixtures/share_preview.json";
import browsePageJson from "./fixtures/browse_page.json";
import indicatorsJson from "./fixtures/indicators.json";
import eventsListJson from "./fixtures/events_list.json";
import eventsPageJson from "./fixtures/events_page.json";
import eventsSummaryJson from "./fixtures/events_summary.json";
import eventsHistogramJson from "./fixtures/events_histogram.json";
import eventsDetailJson from "./fixtures/events_detail.json";
import eventsDetailFlaggedJson from "./fixtures/events_detail_flagged.json";
import eventsSuggestJson from "./fixtures/events_suggest.json";
import entitySummariesJson from "./fixtures/entity_summaries.json";
import entityPivotsJson from "./fixtures/entity_pivots.json";
import entityFindingsJson from "./fixtures/entity_findings.json";
import entityCoverageJson from "./fixtures/entity_coverage.json";
import marksTagsJson from "./fixtures/marks_tags.json";
import timelineAddedJson from "./fixtures/timeline_added.json";
import type {
  AccessCategory,
  AccessReport,
  Attribution,
  Basis,
  AccountPage,
  ActiveIndicator,
  BrowsePage,
  CaseInfo,
  EntityCoverage,
  EntityKind,
  EntitySummary,
  EventDetail,
  EventRow,
  EventsAdded,
  EventsPage,
  EventsSummary,
  FindingRef,
  Histogram,
  PivotOf,
  PivotPage,
  PivotRow,
  SuspectDevice,
  TagInfo,
  FindingDetail,
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
  "signins_first", "signins_last", "addresses", "addresses_total", "addresses_truncated",
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
  "reasons", "users", "malicious_ips", "other_ips", "sightings", "lifecycle", "analyst", "active_after_analyst_removal",
];
const DEVICE_DECISION = ["device_id", "status", "note", "decided_by", "decided_at"];
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
    if (d.analyst !== null) need(`${at}.analyst`, d.analyst, DEVICE_DECISION);
    if (typeof d.active_after_analyst_removal !== "boolean") throw new Error(`fixture ${at}: active_after_analyst_removal`);
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

// ---------------------------------------------------------------- events grid, entity tabs and marks
// Recorded by `record_investigate_fixtures` (crates/sparrow-app/tests/commands.rs) from the synthetic case, after a
// few marks were made: a malicious and two suspicious row flags, an analyst tag, an unreviewed agent tag and agent
// flag, and a note.

const EVENT_ROW = [
  "source_table", "record_key", "source", "event_time", "time_tz_assumed", "tenant_key", "workload", "category",
  "operation", "result", "actor_upn", "owner_upn", "target", "ip", "ip_prefix", "ip_country", "asn", "asn_org",
  "ip_kind", "device_id", "device_name", "device_object_id", "entra_session_id", "user_agent", "app_id", "summary",
  "finding_count", "tags", "rules", "flag", "flag_ai", "ai_pending", "latest_note", "note_count",
];

function checkRow(where: string, r: unknown): EventRow {
  need(where, r, EVENT_ROW);
  if (!Array.isArray(r.tags)) throw new Error(`fixture ${where}: tags is not an array`);
  r.tags.forEach((t: unknown, i) => need(`${where}.tags[${i}]`, t, ["name", "ai"]));
  if (!Array.isArray(r.rules) || r.rules.some((x: unknown) => typeof x !== "string")) throw new Error(`fixture ${where}: rules is not a list of ids`);
  if (r.flag !== null && r.flag !== "suspicious" && r.flag !== "malicious") throw new Error(`fixture ${where}: bad flag`);
  if (typeof r.flag_ai !== "boolean" || typeof r.ai_pending !== "boolean" || typeof r.note_count !== "number") throw new Error(`fixture ${where}: bad marks`);
  return r as unknown as EventRow;
}

/** The mock backend's whole event list: a dozen of the newest events of each source, newest first. */
export function eventsList(): EventRow[] {
  const v: unknown = clone(eventsListJson);
  if (!Array.isArray(v) || v.length === 0) throw new Error("fixture events_list: not a non-empty array");
  return v.map((r: unknown, i) => checkRow(`events_list[${i}]`, r));
}

export function eventsPage(): EventsPage {
  const v: unknown = clone(eventsPageJson);
  need("events_page", v, ["rows", "offset", "total", "total_capped"]);
  if (!Array.isArray(v.rows) || v.rows.length === 0) throw new Error("fixture events_page: no rows");
  v.rows.forEach((r: unknown, i) => checkRow(`events_page.rows[${i}]`, r));
  if (typeof v.total !== "number" || typeof v.total_capped !== "boolean") throw new Error("fixture events_page: bad total");
  return v as unknown as EventsPage;
}

export function eventsSummary(): EventsSummary {
  const v: unknown = clone(eventsSummaryJson);
  need("events_summary", v, ["total", "suspicious", "malicious", "per_source", "hidden_trace_events"]);
  if (!Array.isArray(v.per_source) || v.per_source.length === 0) throw new Error("fixture events_summary: no sources");
  v.per_source.forEach((p: unknown, i) => {
    if (!Array.isArray(p) || p.length !== 2 || typeof p[0] !== "string" || typeof p[1] !== "number") {
      throw new Error(`fixture events_summary.per_source[${i}]: not [source, count]`);
    }
  });
  return v as unknown as EventsSummary;
}

export function eventsHistogram(): Histogram {
  const v: unknown = clone(eventsHistogramJson);
  need("events_histogram", v, ["start", "bucket_seconds", "group", "series", "other", "findings"]);
  if (!Array.isArray(v.series) || v.series.length === 0) throw new Error("fixture events_histogram: no series");
  const widths = new Set<number>();
  v.series.forEach((s: unknown, i) => {
    if (!Array.isArray(s) || s.length !== 2 || typeof s[0] !== "string" || !Array.isArray(s[1])) {
      throw new Error(`fixture events_histogram.series[${i}]: not [source, counts]`);
    }
    widths.add(s[1].length);
  });
  if (widths.size !== 1) throw new Error("fixture events_histogram: series of different lengths");
  if (!Array.isArray(v.findings)) throw new Error("fixture events_histogram: findings is not an array");
  v.findings.forEach((f: unknown, i) => need(`events_histogram.findings[${i}]`, f, ["finding_id", "severity", "first_seen", "last_seen"]));
  return v as unknown as Histogram;
}

function checkDetail(name: string, json: unknown): EventDetail {
  const v: unknown = clone(json);
  need(name, v, ["row", "raw", "source_refs", "tags", "notes", "flag", "flag_sources"]);
  checkRow(`${name}.row`, v.row);
  if (!Array.isArray(v.source_refs) || !Array.isArray(v.notes) || !Array.isArray(v.flag_sources)) {
    throw new Error(`fixture ${name}: source_refs, notes and flag_sources must be arrays`);
  }
  v.flag_sources.forEach((f: unknown, i) =>
    need(`${name}.flag_sources[${i}]`, f, ["origin", "level", "kind", "value", "scope_kind", "scope_value", "decided_by", "review_state"]),
  );
  return v as unknown as EventDetail;
}

/** The detail of an event that carries a note. */
export const eventsDetail = (): EventDetail => checkDetail("events_detail", eventsDetailJson);
/** The detail of an event with a malicious row flag. */
export const eventsDetailFlagged = (): EventDetail => checkDetail("events_detail_flagged", eventsDetailFlaggedJson);

export function eventsSuggest(): string[] {
  const v: unknown = clone(eventsSuggestJson);
  if (!Array.isArray(v) || v.length === 0 || v.some((s) => typeof s !== "string")) throw new Error("fixture events_suggest: not strings");
  return v as string[];
}

const SUMMARY_KEYS = ["entity", "first_seen", "last_seen", "events", "distinct", "open_findings", "roles_matched", "ip_intel", "device"];
const DISTINCT = ["accounts", "ips", "countries", "asns", "devices", "sessions"];

/** `entity_summary` of one entity of each kind (the first of its kind in the synthetic case). */
export function entitySummary(kind: EntityKind): EntitySummary {
  const all: unknown = clone(entitySummariesJson);
  need("entity_summaries", all, ["account", "ip", "device", "session"]);
  const v = all[kind];
  need(`entity_summaries.${kind}`, v, SUMMARY_KEYS);
  need(`entity_summaries.${kind}.distinct`, v.distinct, DISTINCT);
  need(`entity_summaries.${kind}.entity`, v.entity, ["kind", "value"]);
  if (v.entity.kind !== kind) throw new Error(`fixture entity_summaries.${kind}: entity is a ${String(v.entity.kind)}`);
  // The recordings predate the device tab's analyst status; the synthetic case has none.
  return { analyst_status: null, active_after_analyst_removal: false, ...v } as unknown as EntitySummary;
}

function checkPivotRow(where: string, r: unknown): PivotRow {
  need(where, r, ["value", "label", "count", "first_seen", "last_seen", "is_new", "extra"]);
  // The recordings predate the row's `flag` and `flagged`; none of the synthetic case's values is flagged.
  return { flag: null, flagged: { malicious: 0, suspicious: 0 }, ...(r as object) } as unknown as PivotRow;
}

/**
 * `entity_pivot` pages keyed by `of`, recorded for one entity of the right kind (accounts of an IP; the IPs, devices and
 * sessions of an account). The synthetic case has no directory change of a device, so `device_changes` is written by
 * hand after the documented shape: one row per `entra_audit` event.
 */
export function entityPivots(): Record<PivotOf, PivotPage> {
  const all: unknown = clone(entityPivotsJson);
  need("entity_pivots", all, ["accounts", "ips", "devices", "sessions", "device_changes"]);
  const out = {} as Record<PivotOf, PivotPage>;
  for (const of of ["accounts", "ips", "devices", "sessions", "device_changes"] as const) {
    const p = all[of];
    need(`entity_pivots.${of}`, p, ["rows", "total"]);
    if (!Array.isArray(p.rows) || typeof p.total !== "number") throw new Error(`fixture entity_pivots.${of}: bad page`);
    p.rows = p.rows.map((r: unknown, i) => checkPivotRow(`entity_pivots.${of}.rows[${i}]`, r));
    out[of] = p as unknown as PivotPage;
  }
  if (out.device_changes.rows.length === 0) {
    const at = "2026-08-20T09:15:00.000000Z";
    out.device_changes = {
      total: 2,
      rows: [
        {
          value: "Add registered owner to device",
          label: "Add registered owner to device (Succeeded)",
          count: 1,
          first_seen: at,
          last_seen: at,
          is_new: false,
          flag: null,
          flagged: { malicious: 0, suspicious: 0 },
          extra: { source_table: "entra_audit", record_key: "mock-device-change-1", actor: "admin@contoso.example", result: "Succeeded", target: "FRANCES.ROURKE-LAPTOP" },
        },
        {
          value: "Add device",
          label: "Add device (Succeeded)",
          count: 1,
          first_seen: "2026-08-20T09:30:00.000000Z",
          last_seen: "2026-08-20T09:30:00.000000Z",
          is_new: false,
          flag: null,
          flagged: { malicious: 0, suspicious: 0 },
          extra: { source_table: "entra_audit", record_key: "mock-device-change-2", actor: "admin@contoso.example", result: "Succeeded", target: "FRANCES.ROURKE-LAPTOP" },
        },
      ],
    };
  }
  return out;
}

export function entityFindings(): FindingRef[] {
  const v: unknown = clone(entityFindingsJson);
  if (!Array.isArray(v) || v.length === 0) throw new Error("fixture entity_findings: not a non-empty array");
  v.forEach((f: unknown, i) => need(`entity_findings[${i}]`, f, ["finding_id", "rule_id", "title", "severity", "status", "first_seen"]));
  return v as unknown as FindingRef[];
}

export function entityCoverage(): EntityCoverage {
  const v: unknown = clone(entityCoverageJson);
  need("entity_coverage", v, ["from", "to", "tenants"]);
  if (!Array.isArray(v.tenants) || v.tenants.length === 0) throw new Error("fixture entity_coverage: no tenants");
  v.tenants.forEach((t: unknown, i) => {
    need(`entity_coverage.tenants[${i}]`, t, ["tenant_key", "accounts", "sources"]);
    (t.sources as unknown[]).forEach((x, j) => need(`entity_coverage.tenants[${i}].sources[${j}]`, x, ["source", "title", "state", "accounts_by_state"]));
  });
  return v as unknown as EntityCoverage;
}

export function marksTags(): TagInfo[] {
  const v: unknown = clone(marksTagsJson);
  if (!Array.isArray(v) || v.length === 0) throw new Error("fixture marks_tags: not a non-empty array");
  v.forEach((t: unknown, i) => need(`marks_tags[${i}]`, t, ["name", "count", "agent_unreviewed"]));
  return v as unknown as TagInfo[];
}

export function timelineAdded(): EventsAdded {
  const v: unknown = clone(timelineAddedJson);
  need("timeline_added", v, ["entryIds", "outcome"]);
  if (!Array.isArray(v.entryIds) || v.entryIds.length === 0 || typeof v.outcome !== "string") throw new Error("fixture timeline_added: bad shape");
  return v as unknown as EventsAdded;
}

const ACCESS_ORDER: AccessCategory[] = ["mail_read", "mail_sent", "attachment", "file", "teams", "copilot", "other"];
const ATTRIBUTIONS: Attribution[] = ["session", "row", "device", "ip", "time"];
const BASES: Basis[] = ["accepted", "pending", "adhoc"];

/** The recorded access report, checked against the Rust shape (keys, tile order, enum values). */
export function accessReport(): AccessReport {
  const v: unknown = clone(accessReportJson);
  need("access_report", v, ["accounts", "pending_flags", "preview", "never_logged"]);
  if (typeof v.pending_flags !== "number") throw new Error("fixture access_report: pending_flags is not a number");
  if (!Array.isArray(v.accounts) || v.accounts.length === 0) throw new Error("fixture access_report: no accounts");
  v.accounts.forEach((a: unknown, i) => {
    need(`access_report.accounts[${i}]`, a, ["account", "tenant_key", "scope", "tiles", "items", "gaps"]);
    if ((a.tiles as unknown[]).length !== 7) throw new Error(`fixture access_report.accounts[${i}]: not 7 tiles`);
    (a.tiles as unknown[]).forEach((t, j) => {
      need(`access_report.accounts[${i}].tiles[${j}]`, t, ["category", "direct", "by_time", "qualifier", "coverage", "none_seen", "pending", "adhoc"]);
      if (typeof t.pending !== "number" || typeof t.adhoc !== "number") throw new Error(`fixture access_report: tile ${j} preview counts`);
      need(`access_report.accounts[${i}].tiles[${j}].coverage`, t.coverage, ["status", "reason", "remediation"]);
      if (t.category !== ACCESS_ORDER[j]) throw new Error(`fixture access_report: tile ${j} is ${String(t.category)}`);
    });
    (a.scope as unknown[]).forEach((s, j) => {
      need(`access_report.accounts[${i}].scope[${j}]`, s, ["kind", "value", "windows", "basis"]);
      if (!BASES.includes(s.basis as Basis)) throw new Error(`fixture access_report.accounts[${i}].scope[${j}]: unknown basis`);
      (s.windows as unknown[]).forEach((w, k) => need(`access_report.accounts[${i}].scope[${j}].windows[${k}]`, w, ["start", "end"]));
    });
    (a.items as Record<string, unknown>[]).forEach((t, j) => {
      if (!ACCESS_ORDER.includes(t.category as AccessCategory) || !ATTRIBUTIONS.includes(t.attribution as Attribution))
        throw new Error(`fixture access_report.accounts[${i}].items[${j}]: unknown category or attribution`);
      if (!BASES.includes(t.basis as Basis)) throw new Error(`fixture access_report.accounts[${i}].items[${j}]: unknown basis`);
    });
    (a.items as unknown[]).forEach((t, j) => need(`access_report.accounts[${i}].items[${j}]`, t, ["account", "category", "attribution", "accessed", "action", "item", "location", "from", "to", "size_bytes", "item_time", "app", "ip", "session_id", "owner", "note", "source", "source_table", "record_key", "basis", "row"]));
  });
  return v as unknown as AccessReport;
}
