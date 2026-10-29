// DEV ONLY: the mock backend's events grid, entity tabs and marks. It keeps the recorded event list (test/fixtures,
// recorded from a synthetic case by the Rust backend) in memory and answers queries over it with the same rules the
// core has (Harrier filter text, hidden trace events, inclusive ranges, histogram bucket sizes), so a screen can be
// tried by hand and in tests; marks change what the next page shows. All data is synthetic.
import type {
  AddEventsArgs,
  AuditEntry,
  CmdErrorKind,
  EntityArg,
  EntityCoverage,
  EntityKind,
  EntitySummary,
  EventDetail,
  EventField,
  EventQuery,
  EventRow,
  EventsAdded,
  EventsPage,
  EventsSummary,
  FlagLevel,
  Histogram,
  Note,
  PivotFlag,
  PivotOf,
  PivotPage,
  RowRef,
  Sort,
  TagInfo,
  TimelineEntry,
  ValueFlagged,
  ValueKind,
  FieldValues,
} from "../api";
import { parseField, type Term } from "../events/fieldSyntax";
import * as fx from "../test/fixtures";

export interface EventDeps {
  fail: (kind: CmdErrorKind, message: string) => never;
  audit: (action: string, objectType: string, objectId: string, reason?: string | null) => AuditEntry;
  interruptible: <T>(queryId: unknown, ms: number, value: () => T) => Promise<T>;
  /** Throws `read_only` when the open case is read-only. */
  writable: () => void;
  analyst: () => string;
  addEntries: (entries: TimelineEntry[]) => void;
}

type Args = Record<string, unknown> | undefined;

const SOURCES = [
  "ual", "signin_interactive", "signin_noninteractive", "signin_service", "mail_items_accessed", "message_trace",
  "message_trace_event", "entra_audit", "mailbox_audit", "admin_audit", "risk_detection", "azure_activity", "security_alert",
];
const BUCKET_SECONDS = [60, 300, 900, 3_600, 10_800, 21_600, 43_200, 86_400];
const LABEL: Record<EventField, string> = {
  source: "Source", operation: "Operation", account: "Account", ip: "IP", country: "Country", asn: "ASN",
  device: "Device", session: "Session", tag: "Tag",
};
const FIELDS = Object.keys(LABEL) as EventField[];
/** Rows one `notes_add_rows` call writes a note on. */
const MAX_NOTE_ROWS = 200;
const EACH_MAX = 200;
/** What the app layer allows a histogram call to ask for, and what core never exceeds whatever the range. */
const APP_MAX_BUCKETS = 500;
const CORE_MAX_BUCKETS = 2_000;
/** Core's `HISTOGRAM_TOP_OPERATIONS`. */
const TOP_OPERATIONS = 10;
/** Core writes times with six fractional digits (`ts_text`). */
const micros = (ms: number) => new Date(ms).toISOString().replace(/\.(\d{3})Z$/, ".$1000Z");
const SUGGEST_MAX = 200;
const VALUES_MAX = 200;
/** A case-insensitive "starts with", `*` a wildcard. */
const wildcardPrefix = (p: string) => new RegExp(`^${p.split("*").map((x) => x.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}`, "i");

const key = (r: RowRef) => `${r.source_table}:${r.record_key}`;
const lower = (s: string | null | undefined) => (s ?? "").toLowerCase();
const rank = (l: FlagLevel | null) => (l === "malicious" ? 2 : l === "suspicious" ? 1 : 0);

interface ValueFlag {
  kind: ValueKind;
  value: string;
  scope: EntityArg | null;
  level: FlagLevel;
}

export function eventHandlers(deps: EventDeps): Record<string, (a: Args) => unknown> {
  const fail: EventDeps["fail"] = deps.fail;
  // The rows with their own marks only; a standing value flag is applied when a row is read.
  let events: EventRow[] = fx.eventsList();
  let valueFlags: ValueFlag[] = [];
  const notes = new Map<string, Note[]>();
  for (const d of [fx.eventsDetail(), fx.eventsDetailFlagged()]) notes.set(key(d.row), d.notes);

  // -------------------------------------------------------------------------------- query

  const accountsOf = (r: EventRow) => [r.actor_upn, r.owner_upn].map(lower).filter(Boolean);
  const valuesOf = (field: EventField, r: EventRow): string[] => {
    switch (field) {
      case "source": return [r.source];
      case "operation": return r.operation ? [r.operation] : [];
      case "account": return accountsOf(r);
      case "ip": return r.ip ? [lower(r.ip)] : [];
      case "country": return r.ip_country ? [r.ip_country] : [];
      case "asn": return r.asn === null ? [] : [String(r.asn)];
      case "device": return [r.device_id, r.device_object_id, r.device_name].map(lower).filter(Boolean);
      case "session": return r.entra_session_id ? [lower(r.entra_session_id)] : [];
      case "tag": return r.tags.map((t) => lower(t.name));
    }
  };
  const caseFolded = (f: EventField) => f === "account" || f === "device" || f === "session" || f === "tag" || f === "ip";
  const wildcard = (p: string) => new RegExp(`^${p.split("*").map((x) => x.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i");

  /** Harrier's list syntax with quoting (`../events/fieldSyntax`, core's rules); refusals name the field, never match all. */
  function parseList(field: EventField, text: string) {
    if (text.trim() === "") return null;
    const parsed = parseField(text);
    if (!parsed.ok) return fail("invalid", `${LABEL[field]} filter: ${parsed.message}`);
    const make = (t: Term) => {
      const q = caseFolded(field) ? t.text.toLowerCase() : t.text;
      return t.wild ? (v: string) => wildcard(q).test(v) : (v: string) => v === q;
    };
    const inc = parsed.terms.filter((t) => !t.exclude);
    return {
      inc: inc.map(make),
      exc: parsed.terms.filter((t) => t.exclude).map(make),
      names: (n: string) => inc.some((t) => make(t)(n)),
    };
  }

  const entityMatches = (e: EntityArg, r: EventRow): boolean => {
    const v = lower(e.value).trim();
    switch (e.kind) {
      case "account": return accountsOf(r).includes(v);
      case "ip": return lower(r.ip) === v;
      case "device": return lower(r.device_id) === v || lower(r.device_object_id) === v;
      case "session": return lower(r.entra_session_id) === v;
    }
  };

  const valueMatches = (f: ValueFlag, r: EventRow): boolean => {
    if (f.scope && !entityMatches(f.scope, r)) return false;
    switch (f.kind) {
      case "ip": return lower(r.ip) === lower(f.value);
      case "ip_prefix": return r.ip_prefix === f.value;
      case "account": return accountsOf(r).includes(lower(f.value));
      case "asn": return r.asn !== null && String(r.asn) === f.value.replace(/^as/i, "");
      case "device": return [r.device_id, r.device_object_id].map(lower).includes(lower(f.value));
      case "session": return lower(r.entra_session_id) === lower(f.value);
    }
  };

  /** The row as the grid sees it: its own flag and every matching standing flag, the strongest winning. */
  const seen = (r: EventRow): EventRow => {
    let flag = r.flag;
    let ai = r.flag_ai;
    for (const f of valueFlags) {
      if (!valueMatches(f, r)) continue;
      if (rank(f.level) > rank(flag)) {
        flag = f.level;
        ai = false;
      }
    }
    return flag === r.flag && ai === r.flag_ai ? r : { ...r, flag, flag_ai: ai };
  };

  const hasAiMark = (r: EventRow) => r.flag_ai || r.tags.some((t) => t.ai);

  interface Matched { rows: EventRow[]; hiddenTrace: number }

  /** `showHidden`: keep the `message_trace_event` rows even when the Source filter does not name them. */
  function match(q: EventQuery, showHidden = false): Matched {
    if (q === null || typeof q !== "object") fail("invalid", "the query is missing");
    const lists = (q.fields ?? []).map(([f, text]) => {
      if (!FIELDS.includes(f)) fail("invalid", `${String(f)} is not a filter field`);
      return [f, parseList(f, text)] as const;
    });
    const search = q.search === undefined ? null : q.search;
    const needles = search === null ? null : search.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
    if (needles !== null && needles.length === 0) fail("invalid", "search: nothing to look for");
    const from = q.from === undefined ? null : parseTime(q.from);
    const to = q.to === undefined ? null : parseTime(q.to);
    if (q.entity) canonicalEntity(q.entity);
    const source = lists.find(([f]) => f === "source")?.[1] ?? null;
    const traceNamed = source !== null && source.names("message_trace_event");
    let hiddenTrace = 0;
    const rows: EventRow[] = [];
    for (const raw of events) {
      const r = seen(raw);
      if (q.entity && !entityMatches(q.entity, r)) continue;
      if (from !== null || to !== null) {
        const t = r.event_time === null ? null : Date.parse(r.event_time);
        if (t === null || (from !== null && t < from) || (to !== null && t > to)) continue;
      }
      let keep = true;
      for (const [f, list] of lists) {
        if (!list) continue;
        const vals = valuesOf(f, r);
        const inc = list.inc.length === 0 || vals.some((v) => list.inc.some((m) => m(v)));
        const exc = vals.some((v) => list.exc.some((m) => m(v)));
        if (!inc || exc) { keep = false; break; }
      }
      if (!keep) continue;
      if (q.flag !== "all" && r.flag !== q.flag) continue;
      if (q.ai !== "all" && !hasAiMark(r)) continue;
      if (needles && !needles.some((n) => JSON.stringify(r).toLowerCase().includes(n))) continue;
      if (r.source === "message_trace_event" && !traceNamed && !showHidden) { hiddenTrace++; continue; }
      rows.push(r);
    }
    return { rows, hiddenTrace };
  }

  /** A raw search is a cancellable run; without an id the backend refuses it. */
  function run<T>(a: Args, q: EventQuery, value: () => T): Promise<T> {
    const id = a?.queryId;
    if (q?.search !== undefined) {
      if (typeof id !== "string" || id === "") fail("invalid", "a raw-text search needs a query id so that it can be cancelled");
      // Evaluated now so a bad query is refused at once, then held for as long as the (fake) search takes.
      const done = value();
      return deps.interruptible(id, /slow/i.test(q.search) ? 10_000 : 0, () => done);
    }
    return Promise.resolve(value());
  }

  const query = (a: Args): EventQuery => (a?.query ?? null) as EventQuery;

  function parseTime(s: string): number {
    const t = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s) ? Date.parse(s) : NaN;
    if (Number.isNaN(t)) fail("invalid", `${JSON.stringify(s)} is not an RFC 3339 time (for example 2026-03-01T10:00:00Z)`);
    return t;
  }

  function canonicalEntity(e: EntityArg): EntityArg {
    const value = e.value.trim().toLowerCase();
    if (!value) fail("invalid", `an empty ${e.kind} cannot be opened`);
    if (e.kind === "ip" && !/^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]*)$/.test(value)) fail("invalid", `${JSON.stringify(e.value.trim())} is not an IP address`);
    return { kind: e.kind, value };
  }

  const sorted = (rows: EventRow[], sort: Sort | null | undefined): EventRow[] => {
    const col = sort?.column ?? "event_time";
    const desc = sort ? sort.descending : true;
    if (rows.length > 0 && !(col in rows[0])) fail("invalid", `events have no column ${JSON.stringify(col)} to sort by`);
    const val = (r: EventRow) => (r as unknown as Record<string, unknown>)[col] as string | number | null;
    return [...rows].sort((x, y) => {
      const a = val(x), b = val(y);
      if (a === b) return key(x) < key(y) ? -1 : 1;
      if (a === null) return 1;
      if (b === null) return -1;
      return (a < b ? -1 : 1) * (desc ? -1 : 1);
    });
  };

  // -------------------------------------------------------------------------------- reads

  const events_page = (a: Args): Promise<EventsPage> => {
    const q = query(a);
    const offset = typeof a?.offset === "number" ? a.offset : 0;
    const limit = Math.min(typeof a?.limit === "number" ? a.limit : 100, 500);
    return run(a, q, () => {
      const { rows } = match(q);
      return { rows: sorted(rows, a?.sort as Sort | null).slice(offset, offset + limit), offset, total: rows.length, total_capped: false };
    });
  };

  const events_summary = (a: Args): Promise<EventsSummary> => {
    const q = query(a);
    return run(a, q, () => {
      const { rows, hiddenTrace } = match(q);
      const per = new Map<string, number>();
      for (const r of rows) per.set(r.source, (per.get(r.source) ?? 0) + 1);
      return {
        total: rows.length,
        suspicious: rows.filter((r) => r.flag === "suspicious").length,
        malicious: rows.filter((r) => r.flag === "malicious").length,
        per_source: SOURCES.filter((s) => per.has(s)).map((s) => [s, per.get(s)!] as [string, number]),
        hidden_trace_events: hiddenTrace,
      };
    });
  };

  const events_histogram = (a: Args): Promise<Histogram> => {
    const q = query(a);
    const asked = typeof a?.maxBuckets === "number" ? a.maxBuckets : 0;
    if (asked < 1) fail("invalid", "a histogram needs at least 1 bucket");
    // Tauri refuses a missing or unknown grouping before the command runs.
    const group = a?.group;
    if (group !== "source" && group !== "operation") fail("invalid", `unknown histogram grouping ${JSON.stringify(group)}`);
    const max = Math.min(asked, APP_MAX_BUCKETS, CORE_MAX_BUCKETS);
    return run(a, q, () => {
      const timed = match(q).rows.filter((r) => r.event_time !== null);
      // No timed event: core's rule, not the clock: the query's `from`, else its `to`, else the epoch.
      if (timed.length === 0) {
        const at = q.from ?? q.to;
        return { start: at === undefined ? micros(0) : micros(parseTime(at)), bucket_seconds: 60, group, series: [], other: null, findings: [] };
      }
      const times = timed.map((r) => Date.parse(r.event_time!));
      const lo = q.from !== undefined ? parseTime(q.from) : Math.min(...times);
      const hi = q.to !== undefined ? parseTime(q.to) : Math.max(...times);
      const layout = (s: number) => {
        const start = q.from !== undefined ? lo : Math.floor(lo / (s * 1000)) * s * 1000;
        return { start, n: Math.floor((hi - start) / (s * 1000)) + 1 };
      };
      const day = BUCKET_SECONDS[BUCKET_SECONDS.length - 1];
      let size = BUCKET_SECONDS.find((s) => layout(s).n <= max) ?? day;
      if (size === day && layout(day).n > CORE_MAX_BUCKETS) {
        // Past a day: the fewest whole days that fit core's hard cap.
        let days = 2;
        while (layout(days * day).n > CORE_MAX_BUCKETS) days++;
        size = days * day;
      }
      const { start, n } = layout(size);
      const counts = new Map<string, number[]>();
      const unnamed = new Array<number>(n).fill(0);
      for (const r of timed) {
        const i = Math.floor((Date.parse(r.event_time!) - start) / (size * 1000));
        if (i < 0 || i >= n) continue;
        const name = group === "source" ? r.source : r.operation;
        if (name === null) {
          unnamed[i]++;
          continue;
        }
        if (!counts.has(name)) counts.set(name, new Array<number>(n).fill(0));
        counts.get(name)![i]++;
      }
      let series: [string, number[]][];
      let other: number[] | null = null;
      if (group === "source") {
        series = SOURCES.filter((s) => counts.has(s)).map((s) => [s, counts.get(s)!]);
      } else {
        // Core's cut: the ten largest totals, ties by name; the rest and the unnamed are `other`.
        const sum = (c: number[]) => c.reduce((x, y) => x + y, 0);
        const ranked = [...counts].sort(([an, ac], [bn, bc]) => sum(bc) - sum(ac) || (an < bn ? -1 : an > bn ? 1 : 0));
        series = ranked.slice(0, TOP_OPERATIONS);
        for (const [, c] of ranked.slice(TOP_OPERATIONS)) c.forEach((v, i) => (unnamed[i] += v));
        if (unnamed.some((v) => v > 0)) other = unnamed;
      }
      return {
        start: micros(start),
        bucket_seconds: size,
        group,
        series,
        other,
        findings: fx.eventsHistogram().findings.filter((f) => Date.parse(f.last_seen) >= lo && Date.parse(f.first_seen) <= hi),
      };
    });
  };

  const events_detail = (a: Args): EventDetail => {
    const st = str(a, "sourceTable"), rk = str(a, "recordKey");
    if (!events.some((r) => r.source_table === st)) fail("invalid", `${JSON.stringify(st)} is not an event table`);
    const own = events.find((r) => r.source_table === st && r.record_key === rk);
    if (!own) return fail("not_found", `event ${st}:${rk}`);
    const row = seen(own);
    const flag_sources: EventDetail["flag_sources"] = [];
    if (own.flag) {
      flag_sources.push({
        origin: "row", level: own.flag, kind: null, value: null, scope_kind: null, scope_value: null,
        decided_by: own.flag_ai ? "agent:triage" : `analyst:${deps.analyst()}`, review_state: own.flag_ai ? "pending_review" : "accepted",
      });
    }
    for (const f of valueFlags.filter((v) => valueMatches(v, own))) {
      flag_sources.push({
        origin: "value", level: f.level, kind: f.kind, value: f.value, scope_kind: f.scope?.kind ?? null,
        scope_value: f.scope?.value ?? null, decided_by: `analyst:${deps.analyst()}`, review_state: "accepted",
      });
    }
    return {
      row,
      raw: { source_table: st, record_key: rk, ...Object.fromEntries(Object.entries(row).filter(([, v]) => v !== null && typeof v !== "object")) },
      source_refs: [`mock-collection/${st}.json:1`],
      tags: row.tags,
      notes: notes.get(key(row)) ?? [],
      flag: row.flag,
      flag_sources,
    };
  };

  const events_suggest = (a: Args): string[] => {
    const field = str(a, "field") as EventField;
    if (!FIELDS.includes(field)) fail("invalid", `${field} is not a filter field`);
    const p = str(a, "prefix").toLowerCase();
    const found = new Set<string>();
    for (const r of events) {
      const vals = field === "tag" ? r.tags.map((t) => t.name) : field === "account" ? [r.actor_upn, r.owner_upn] : field === "device"
        ? [r.device_id, r.device_object_id, r.device_name] : valuesOf(field, r);
      for (const v of vals) if (v && v.toLowerCase().startsWith(p)) found.add(field === "account" || field === "session" ? v.toLowerCase() : v);
    }
    return [...found].sort().slice(0, SUGGEST_MAX);
  };

  /** Core's `events::values`: the field's own filter left out, Source counting the hidden trace rows, case folded. */
  const events_values = (a: Args): Promise<FieldValues> => {
    const q = query(a);
    const field = str(a, "field") as EventField;
    if (!FIELDS.includes(field)) fail("invalid", `${field} is not a filter field`);
    const asked = typeof a?.limit === "number" ? a.limit : 0;
    if (asked < 1) fail("invalid", "a values list needs a limit of at least 1");
    const limit = Math.min(asked, VALUES_MAX);
    const prefix = wildcardPrefix(str(a, "prefix").trim());
    const rest: EventQuery = { ...q, fields: (q?.fields ?? []).filter(([f]) => f !== field) };
    const folded = field === "account" || field === "device" || field === "session" || field === "tag";
    return run(a, q, () => {
      const groups = new Map<string, { value: string; count: number }>();
      for (const r of match(rest, field === "source").rows) {
        const own = field === "account" ? [...new Set([r.actor_upn, r.owner_upn])]
          : field === "device" ? [r.device_name ?? r.device_id ?? r.device_object_id]
          : field === "tag" ? r.tags.map((t) => t.name)
          : field === "ip" ? [r.ip]
          : valuesOf(field, r);
        for (const v of own) {
          if (!v || v.trim() === "" || !prefix.test(v)) continue;
          const k = folded ? v.toLowerCase() : v;
          const g = groups.get(k);
          if (g) {
            g.count++;
            if (v < g.value) g.value = v;
          } else groups.set(k, { value: v, count: 1 });
        }
      }
      const all = [...groups.values()].sort((x, y) => y.count - x.count || (x.value < y.value ? -1 : x.value > y.value ? 1 : 0));
      return { values: all.slice(0, limit), total: all.length };
    });
  };

  const events_export_csv = (a: Args): Promise<number> => {
    const q = query(a);
    if (!str(a, "path")) fail("invalid", "no path (mock)");
    return run(a, q, () => match(q).rows.length);
  };

  // -------------------------------------------------------------------------------- entity tabs

  const entity = (a: Args): EntityArg => {
    const e = a?.entity as EntityArg | undefined;
    if (!e || !["account", "ip", "device", "session"].includes(e.kind)) fail("invalid", "an entity needs a kind and a value");
    return canonicalEntity(e);
  };
  const range = (a: Args) => {
    const from = typeof a?.from === "string" ? parseTime(a.from) : null;
    const to = typeof a?.to === "string" ? parseTime(a.to) : null;
    return { from, to };
  };
  /** True when the range excludes everything the recorded entity has. */
  const outside = (s: EntitySummary, from: number | null, to: number | null) =>
    s.first_seen !== null && s.last_seen !== null && ((to !== null && to < Date.parse(s.first_seen)) || (from !== null && from > Date.parse(s.last_seen)));

  const entity_summary = (a: Args): EntitySummary => {
    const e = entity(a);
    const { from, to } = range(a);
    const rec = fx.entitySummary(e.kind);
    const stored: EntityArg = e;
    if (outside(rec, from, to)) {
      return {
        ...rec, entity: stored, first_seen: null, last_seen: null, events: 0, roles_matched: [], open_findings: {},
        distinct: Object.fromEntries(Object.keys(rec.distinct).map((k) => [k, 0])),
      };
    }
    return { ...rec, entity: stored };
  };

  const ALLOWED: Record<EntityKind, PivotOf[]> = {
    account: ["ips", "devices", "sessions"],
    ip: ["accounts", "devices", "sessions"],
    device: ["accounts", "ips", "sessions", "device_changes"],
    session: ["accounts", "ips", "devices"],
  };

  const entity_pivot = (a: Args): PivotPage => {
    const e = entity(a);
    const of = str(a, "of") as PivotOf;
    const limit = a?.limit === undefined || a.limit === null ? 500 : (a.limit as number);
    if (limit === 0) fail("invalid", "a pivot needs a limit of at least 1");
    if (!ALLOWED[e.kind].includes(of)) fail("invalid", `a ${e.kind} tab has no ${of} table`);
    const { from, to } = range(a);
    if (outside(fx.entitySummary(e.kind), from, to)) return { rows: [], total: 0 };
    const page = fx.entityPivots()[of];
    const kind = ({ accounts: "account", ips: "ip", devices: "device", sessions: "session" } as Partial<Record<PivotOf, ValueKind>>)[of];
    // The strongest standing flag on the row's value that is case-wide or made inside this tab (the mock's flags are all
    // the analyst's, so none is pending).
    const flagOf = (value: string): PivotFlag | null => {
      const mine = valueFlags.filter(
        (f) => f.kind === kind && lower(f.value) === lower(value) && (f.scope === null || (f.scope.kind === e.kind && lower(f.scope.value) === lower(e.value))),
      );
      const top = mine.reduce<FlagLevel | null>((m, f) => (rank(f.level) > rank(m) ? f.level : m), null);
      if (top === null) return null;
      return { level: top, pending: false, scope: mine.some((f) => f.level === top && f.scope === null) ? "case" : "entity" };
    };
    const rows = page.rows.slice(0, Math.min(limit, 5000)).map((r) => ({ ...r, flag: of === "device_changes" ? null : flagOf(r.value) }));
    return { rows, total: page.total };
  };

  const entity_findings = (a: Args) => {
    const e = entity(a);
    const { from, to } = range(a);
    if (outside(fx.entitySummary(e.kind), from, to)) return [];
    return fx.entityFindings();
  };

  const entity_coverage = (a: Args): EntityCoverage => {
    entity(a);
    const { from, to } = range(a);
    const rec = fx.entityCoverage();
    const day = (ms: number | null, dflt: string | null) => (ms === null ? dflt : new Date(ms).toISOString().slice(0, 10));
    const lo = day(from, rec.from) ?? rec.from;
    const hi = day(to, rec.to) ?? rec.to;
    // Whole days, as the backend: a range that ends before it starts is its first day.
    return { ...rec, from: lo, to: lo !== null && hi !== null && hi < lo ? lo : hi };
  };

  // -------------------------------------------------------------------------------- marks

  const rowsArg = (a: Args, max = 100_000): RowRef[] => {
    const rows = (Array.isArray(a?.rows) ? a.rows : []) as RowRef[];
    const distinct = [...new Map(rows.map((r) => [key(r), r])).values()];
    if (distinct.length === 0) fail("invalid", "no event rows given");
    if (distinct.length > max) fail("invalid", `${distinct.length} event rows in one call; the limit is ${max}`);
    const ghost = distinct.find((r) => !events.some((e) => key(e) === key(r)));
    if (ghost) fail("decision", `unknown event ${key(ghost)}`);
    return distinct;
  };
  const update = (rows: RowRef[], f: (r: EventRow) => EventRow) => {
    const set = new Set(rows.map(key));
    // `ai_pending` follows the row's own pending marks (the mock's standing flags are all the analyst's).
    events = events.map((r) => {
      if (!set.has(key(r))) return r;
      const next = f(r);
      return { ...next, ai_pending: next.flag_ai || next.tags.some((t) => t.ai) };
    });
  };
  const level = (a: Args): FlagLevel | null => {
    const l = a?.level;
    if (l === null || l === undefined) return null;
    if (l !== "suspicious" && l !== "malicious") fail("invalid", `unknown flag level ${JSON.stringify(l)} (suspicious or malicious)`);
    return l;
  };

  const marks_flag_rows = (a: Args): AuditEntry => {
    deps.writable();
    const rows = rowsArg(a);
    const l = level(a);
    update(rows, (r) => ({ ...r, flag: l, flag_ai: false }));
    return deps.audit("flag_rows", "event_flag", `mock-batch-${rows.length}`);
  };

  // The indicators Malicious value flags made (core: one per tenant of the matching events, IP and account only).
  const indicatorIds = new Set<string>();
  const marks_flag_value = (a: Args): ValueFlagged => {
    deps.writable();
    const kind = str(a, "kind") as ValueKind;
    if (!["ip", "ip_prefix", "account", "asn", "device", "session"].includes(kind)) fail("invalid", `unknown flag value kind ${JSON.stringify(kind)}`);
    const value = str(a, "value").trim();
    if (!value) fail("invalid", "a value flag needs a value");
    const scope = a?.scope ? canonicalEntity(a.scope as EntityArg) : null;
    const l = level(a);
    const same = (f: ValueFlag) => f.kind === kind && lower(f.value) === lower(value) && JSON.stringify(f.scope) === JSON.stringify(scope);
    valueFlags = valueFlags.filter((f) => !same(f));
    if (l) valueFlags = [...valueFlags, { kind, value, scope, level: l }];
    const indicators: ValueFlagged["indicators"] = [];
    if (l === "malicious" && (kind === "ip" || kind === "account")) {
      const flag: ValueFlag = { kind, value, scope, level: l };
      const tenants = [...new Set(events.filter((r) => valueMatches(flag, r)).map((r) => r.tenant_key))];
      for (const tenant_key of tenants) {
        const indicator_id = `mock-indicator:${tenant_key ?? "case"}:${kind}:${lower(value)}`;
        indicators.push({ tenant_key, indicator_id, created: !indicatorIds.has(indicator_id) });
        indicatorIds.add(indicator_id);
      }
    }
    return { audit: deps.audit("flag_value", "value_flag", `${kind}:${value}`), indicators };
  };

  const marks_tag_rows = (a: Args): AuditEntry => {
    deps.writable();
    const rows = rowsArg(a);
    const tag = str(a, "tag").trim().toLowerCase();
    if (!tag) fail("invalid", "a tag needs a name");
    if (tag.length > 64) fail("invalid", "a tag name is at most 64 characters");
    const add = a?.add === true;
    update(rows, (r) => ({
      ...r,
      tags: add
        ? r.tags.some((t) => t.name === tag) ? r.tags.map((t) => (t.name === tag ? { name: tag, ai: false } : t)) : [...r.tags, { name: tag, ai: false }]
        : r.tags.filter((t) => t.name !== tag),
    }));
    return deps.audit("tag_rows", "event_tag", tag);
  };

  const marks_list_tags = (): TagInfo[] => {
    const by = new Map<string, TagInfo>();
    for (const r of events) {
      for (const t of r.tags) {
        const cur = by.get(t.name) ?? { name: t.name, count: 0, agent_unreviewed: 0 };
        cur.count++;
        if (t.ai) cur.agent_unreviewed++;
        by.set(t.name, cur);
      }
    }
    return [...by.values()].sort((x, y) => (x.name < y.name ? -1 : 1));
  };

  const marks_review = (a: Args): AuditEntry[] => {
    deps.writable();
    const rows = rowsArg(a);
    const accept = a?.accept === true;
    const out: AuditEntry[] = [];
    const set = new Set(rows.map(key));
    const pendingFlag = events.filter((r) => set.has(key(r)) && r.flag_ai).length;
    const pendingTag = events.filter((r) => set.has(key(r)) && r.tags.some((t) => t.ai)).length;
    update(rows, (r) => ({
      ...r,
      flag: !accept && r.flag_ai ? null : r.flag,
      flag_ai: false,
      tags: accept ? r.tags.map((t) => ({ ...t, ai: false })) : r.tags.filter((t) => !t.ai),
    }));
    if (pendingFlag > 0) out.push(deps.audit(accept ? "review_accept" : "review_discard", "event_flag", "mock-agent-flags"));
    if (pendingTag > 0) out.push(deps.audit(accept ? "review_accept" : "review_discard", "event_tag", "mock-agent-tags"));
    return out;
  };

  const notes_add_rows = (a: Args): AuditEntry[] => {
    deps.writable();
    const text = str(a, "text");
    if (text.trim() === "") fail("decision", "a note must not be empty");
    const rows = rowsArg(a, MAX_NOTE_ROWS);
    const now = new Date().toISOString();
    return rows.map((r) => {
      const entry = deps.audit("add_note", "annotation", `mock-note-${notes.size}`);
      const note: Note = {
        annotation_id: `mock-note-${notes.size}`, object_type: "evidence", object_id: r.record_key, source_table: r.source_table,
        text, actor: `analyst:${deps.analyst()}`, on_behalf_of: null, created_at: now,
      };
      notes.set(key(r), [...(notes.get(key(r)) ?? []), note]);
      update([r], (e) => ({ ...e, note_count: e.note_count + 1, latest_note: text }));
      return entry;
    });
  };

  // -------------------------------------------------------------------------------- add to timeline

  const PHASE_BY_CATEGORY: [string[], string][] = [
    [["auth"], "initial_access"],
    [["audit_tamper"], "defense_evasion"],
    [["mail_rule", "forwarding", "config_change", "app_consent", "app_credential", "mfa_change", "role_change", "permission"], "persistence"],
    [["mail_read", "file_access", "file_download", "ediscovery"], "collection"],
    [["mail_flow", "mail_send", "file_share"], "exfiltration"],
  ];
  const defaultPhase = (cats: string[]) => PHASE_BY_CATEGORY.find(([names]) => cats.some((c) => names.includes(c)))?.[1] ?? "recon";
  const PHASES = ["initial_access", "persistence", "defense_evasion", "recon", "collection", "exfiltration", "impact", "remediation"];
  const iso = (t: string) => t.replace(/\.\d+Z$/, "Z");

  const timeline_add_events = (a: Args): EventsAdded => {
    deps.writable();
    const args = (a?.args ?? {}) as AddEventsArgs;
    if ((args.rows === undefined) === (args.query === undefined)) fail("invalid", "give either rows or a query to add to the timeline, not both and not neither");
    if (args.phase !== undefined && !PHASES.includes(args.phase)) fail("invalid", `unknown phase ${JSON.stringify(args.phase)}`);
    let rows: EventRow[];
    if (args.rows) {
      const refs = rowsArg({ rows: args.rows });
      rows = refs.map((r) => events.find((e) => key(e) === key(r))!);
    } else {
      rows = sorted(match(args.query!).rows, null);
      if (rows.length === 0) fail("invalid", "no event matches the query");
    }
    if (args.mode === "each" && rows.length > EACH_MAX) {
      fail("invalid", `${rows.length} events: one entry per event is limited to ${EACH_MAX}; add them as one grouped entry`);
    }
    const now = new Date().toISOString();
    const title = args.title?.trim() || undefined;
    const base = (r: Partial<TimelineEntry>, id: string): TimelineEntry => ({
      entry_id: id, tenant_key: null, event_time: now, end_time: null, event_count: null, title: "", narrative: null,
      phase: "recon", status: "verified", supersedes: null, created_at: now, updated_at: now, decided_by: `analyst:${deps.analyst()}`,
      decided_at: now, on_behalf_of: null, review_state: "accepted", reviewed_by: `analyst:${deps.analyst()}`, reviewed_at: now,
      review_comment: null, evidence: [], ...r,
    });
    const ev = (r: EventRow): RowRef => ({ source_table: r.source_table, record_key: r.record_key });
    let entries: TimelineEntry[];
    if (args.mode === "each") {
      entries = rows.map((r, i) => {
        if (r.event_time === null) fail("invalid", `event ${key(r)} has no time, so it cannot be an entry of its own (add it in a group)`);
        return base({
          event_time: r.event_time, title: title ?? r.summary ?? r.operation ?? r.source_table,
          phase: args.phase ?? defaultPhase([r.category]), evidence: [ev(r)],
        }, `mock-added-${Date.now()}-${i}`);
      });
    } else {
      const times = rows.filter((r) => r.event_time !== null).map((r) => Date.parse(r.event_time!));
      if (times.length === 0) fail("invalid", "none of these events has a time, so they have no span to group");
      const start = new Date(Math.min(...times)).toISOString();
      const end = new Date(Math.max(...times)).toISOString();
      entries = [base({
        event_time: start, end_time: end, event_count: rows.length,
        title: title ?? `${rows.length} event${rows.length === 1 ? "" : "s"} ${iso(start)} to ${iso(end)}`,
        phase: args.phase ?? defaultPhase([...new Set(rows.map((r) => r.category))]), evidence: rows.map(ev),
      }, `mock-added-${Date.now()}`)];
    }
    deps.addEntries(entries);
    for (const e of entries) deps.audit("create_verified", "timeline_entry", e.entry_id);
    const n = entries.length;
    return {
      entryIds: entries.map((e) => e.entry_id),
      outcome: args.mode === "each"
        ? `Added ${n} timeline ${n === 1 ? "entry" : "entries"}`
        : `Added 1 grouped timeline entry covering ${rows.length} event${rows.length === 1 ? "" : "s"}`,
    };
  };

  return {
    events_page, events_summary, events_histogram, events_detail, events_suggest, events_export_csv, events_values,
    entity_summary, entity_pivot, entity_findings, entity_coverage,
    marks_flag_rows, marks_flag_value, marks_tag_rows, marks_list_tags, marks_review, notes_add_rows,
    timeline_add_events,
  };
}

function str(a: Args, k: string): string {
  const v = a?.[k];
  return typeof v === "string" ? v : "";
}
