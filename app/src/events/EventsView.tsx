// The Events view: filters, summary bar, timeline chart, the grid and the detail panel, over one query. The filter
// boxes hold what the analyst types; Search (or Enter, a summary count, a chart drag, a cell menu) runs it. Results
// are replaced only when a run succeeds, so a cancelled or refused search leaves the previous ones on screen, and
// Export CSV, paging and sorting always act on the query that produced what is shown.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  eventsExportCsv,
  eventsHistogram,
  eventsPage,
  eventsSummary,
  isCmdError,
  newQueryId,
  queryCancel,
  type EntityKind,
  type EventField,
  type EventQuery,
  type EventRow,
  type EventsSummary,
  type Histogram as HistogramData,
  type RowRef,
  type Sort,
} from "../api";
import { save } from "../dialog";
import Grid, { cellText } from "../grid/Grid";
import { loadJson, removeJson, saveJson } from "../grid/gridLayout";
import { useNav } from "../shell/nav";
import type { EntityRef } from "../shell/tabs";
import { displaySafe } from "../text";
import { COLUMN_BY_ID, COLUMNS, DEFAULT_VISIBLE, filterable } from "./columns";
import EventDetail, { TagBadge } from "./EventDetail";
import Filters, { emptyDraft, FIELD_LABEL, FIELDS, type FilterDraft, type FilterErrors } from "./Filters";
import Histogram from "./Histogram";
import SummaryBar from "./SummaryBar";

export interface EventsViewProps {
  /** A fixed scope (an entity tab): only this entity's events, and no way to remove it. */
  entity?: EntityRef;
  /** A removable scope ("Show in Events"): shown as a chip; removing it calls `onClearChip`. */
  chip?: EntityRef & { nonce?: number };
  onClearChip?: () => void;
  /** The applied range changed (undefined: no end). An entity tab narrows its tiles, pivots and findings with it. */
  onRangeChange?: (from?: string, to?: string) => void;
  /**
   * The query whose results are on screen, and how many events it matches (null until a run succeeds). `pending` is
   * true while a newer run is loading: the query and count are then the previous ones, not what the boxes show.
   */
  onQueryChange?: (query: EventQuery | null, count: number | null, pending: boolean) => void;
  /** The most rows paging loads (the backend counts to one million); a smaller number is for tests. */
  maxLoaded?: number;
}

const PAGE = 200;
const MAX_BUCKETS = 120;
const GRID_HEIGHT = 380;
/** The page total is counted up to this; past it paging stops and the analyst is told to narrow the filter. */
const LOAD_MAX = 1_000_000;
const LAYOUT_ID = "events";
const VISIBLE_KEY = `sparrow.grid.visible.v1.${LAYOUT_ID}`;

/** The columns the analyst chose to show, from storage: only known ids, in grid order; anything else is the defaults. */
function loadVisible(): string[] {
  const v = loadJson(VISIBLE_KEY);
  if (!Array.isArray(v)) return DEFAULT_VISIBLE;
  const ids = COLUMNS.map((c) => c.id).filter((id) => v.includes(id));
  return ids.length > 0 ? ids : DEFAULT_VISIBLE;
}

type Range = "from" | "to";

/**
 * A From/To box read as ISO 8601 UTC: `2026-09-10`, `2026-09-10T01:55`, `2026-09-10 01:55:36`, `…Z`, with optional
 * fractions. A date alone means the start of that day for From and its last instant for To. The result is the text sent
 * and shown. Anything with an offset, or not a real date, is refused.
 */
export function parseUtc(text: string, end: Range): { ok: true; value: string | undefined } | { ok: false; message: string } {
  const t = text.trim();
  if (t === "") return { ok: true, value: undefined };
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(\.\d{1,6})?)?)?Z?$/.exec(t);
  const bad = { ok: false as const, message: `${JSON.stringify(t)} is not an ISO 8601 UTC time, like 2026-09-10T01:55:00Z` };
  if (!m) return bad;
  const [, y, mo, d, hh, mi, ss, frac] = m;
  const parts = [Number(y), Number(mo), Number(d), Number(hh ?? 0), Number(mi ?? 0), Number(ss ?? 0)];
  const ms = Date.UTC(parts[0], parts[1] - 1, parts[2], parts[3], parts[4], parts[5]);
  const back = new Date(ms);
  if (back.getUTCFullYear() !== parts[0] || back.getUTCMonth() !== parts[1] - 1 || back.getUTCDate() !== parts[2] || parts[3] > 23 || parts[4] > 59 || parts[5] > 59) {
    return bad;
  }
  const dayOnly = hh === undefined;
  if (dayOnly && end === "to") return { ok: true, value: `${y}-${mo}-${d}T23:59:59.999999Z` };
  const clock = `${hh ?? "00"}:${mi ?? "00"}:${ss ?? "00"}${frac ?? ""}`;
  return { ok: true, value: `${y}-${mo}-${d}T${clock}Z` };
}

function buildQuery(d: FilterDraft, entity: EntityRef | undefined): EventQuery {
  const q: EventQuery = {
    fields: FIELDS.filter((f) => d.fields[f].trim() !== "").map((f) => [f, d.fields[f]] as [EventField, string]),
    flag: d.flag,
    ai: d.ai,
  };
  if (entity) q.entity = { kind: entity.kind, value: entity.value };
  if (d.search.trim() !== "") q.search = d.search;
  if (d.from !== "") q.from = d.from;
  if (d.to !== "") q.to = d.to;
  return q;
}

/** A refusal of one filter box comes back as "<Field> filter: …"; show it under that box. */
function errorsFor(message: string): FilterErrors | null {
  const m = /^(\w+) filter:/.exec(message);
  const field = m && FIELDS.find((f) => FIELD_LABEL[f].toLowerCase() === m[1].toLowerCase());
  if (field) return { [field]: message };
  if (/^search\b/i.test(message)) return { search: message };
  return null;
}

interface Shown {
  /** The boxes as they were when this was run. */
  draft: FilterDraft;
  query: EventQuery;
  sort: Sort | null;
}

export default function EventsView({ entity, chip, onClearChip, onRangeChange, onQueryChange, maxLoaded = LOAD_MAX }: EventsViewProps) {
  const nav = useNav();
  const scope: EntityRef | undefined = entity ?? chip;
  const scopeKind = scope?.kind;
  const scopeValue = scope?.value;
  const scopeNonce = chip?.nonce;

  const [draft, setDraft] = useState<FilterDraft>(emptyDraft);
  const [errors, setErrors] = useState<FilterErrors>({});
  const [notice, setNotice] = useState<{ kind: "error" | "info"; text: string } | null>(null);
  const [rows, setRows] = useState<EventRow[]>([]);
  const [total, setTotal] = useState(0);
  const [capped, setCapped] = useState(false);
  const [summary, setSummary] = useState<EventsSummary | null>(null);
  const [hist, setHist] = useState<HistogramData | null>(null);
  const [shown, setShown] = useState<Shown | null>(null);
  const [running, setRunning] = useState<{ cancellable: boolean } | null>(null);
  const [exporting, setExporting] = useState(false);
  const [selected, setSelected] = useState<RowRef | null>(null);
  const [visibleCols, setVisibleCols] = useState<string[]>(loadVisible);

  // What the run functions read, kept current after each render (an effect, so no ref is written during render).
  const latest = useRef({ draft, shown, onRangeChange, rows, total, maxLoaded });
  useEffect(() => {
    latest.current = { draft, shown, onRangeChange, rows, total, maxLoaded };
  });
  useEffect(() => {
    onQueryChange?.(shown?.query ?? null, summary?.total ?? null, running !== null);
  }, [onQueryChange, shown, summary, running]);
  const token = useRef(0);
  const inflight = useRef<string[]>([]);
  const moreBusy = useRef(false);
  const exportId = useRef<string | null>(null);

  const cancelInflight = useCallback(() => {
    for (const id of inflight.current) void queryCancel(id).catch(() => undefined);
    inflight.current = [];
  }, []);
  /** A fresh id for one call of a query that has a raw search (the backend needs it to be cancellable). */
  const idFor = useCallback((q: EventQuery): string | undefined => {
    if (q.search === undefined) return undefined;
    const id = newQueryId();
    inflight.current.push(id);
    return id;
  }, []);

  const fail = useCallback((e: unknown) => {
    const text = isCmdError(e) ? e.message : String(e);
    if (isCmdError(e) && e.kind === "interrupted") {
      setNotice({ kind: "info", text: "Cancelled. The previous results are still shown." });
      return;
    }
    const mine = isCmdError(e) && e.kind === "invalid" ? errorsFor(text) : null;
    if (mine) setErrors(mine);
    else setNotice({ kind: "error", text });
  }, []);

  /** Run a query: the page, and (unless `pageOnly`) the summary and the chart. Replaces the results only on success. */
  const run = useCallback(
    async (next: FilterDraft, sort: Sort | null, pageOnly: boolean) => {
      const query = buildQuery(next, scopeKind && scopeValue ? { kind: scopeKind, value: scopeValue } : undefined);
      const mine = ++token.current;
      cancelInflight();
      moreBusy.current = false;
      setRunning({ cancellable: query.search !== undefined });
      setNotice(null);
      setErrors({});
      try {
        const [page, sum, h] = await Promise.all([
          eventsPage(query, sort, 0, PAGE, idFor(query)),
          pageOnly ? Promise.resolve(null) : eventsSummary(query, idFor(query)),
          pageOnly ? Promise.resolve(null) : eventsHistogram(query, MAX_BUCKETS, idFor(query)),
        ]);
        if (mine !== token.current) return;
        const before = latest.current.shown?.query;
        setRows(page.rows);
        setTotal(page.total);
        setCapped(page.total_capped);
        if (sum) setSummary(sum);
        if (h) setHist(h);
        setShown({ draft: next, query, sort });
        if (before?.from !== query.from || before?.to !== query.to) latest.current.onRangeChange?.(query.from, query.to);
      } catch (e) {
        if (mine === token.current) fail(e);
      } finally {
        if (mine === token.current) {
          inflight.current = [];
          setRunning(null);
        }
      }
    },
    [scopeKind, scopeValue, cancelInflight, idFor, fail],
  );

  // First load, and again whenever the scope changes ("Show in Events", or the chip removed): the filters in effect
  // stay, the scope changes.
  useEffect(() => {
    void run(latest.current.shown?.draft ?? latest.current.draft, latest.current.shown?.sort ?? null, false);
  }, [run, scopeNonce]);

  /** Run the boxes as typed, plus `patch`. A bad From or To is refused here, under its box, and nothing runs. */
  const apply = (patch: Partial<FilterDraft> = {}) => {
    const next = { ...draft, ...patch };
    const from = parseUtc(next.from, "from");
    const to = parseUtc(next.to, "to");
    const bad: FilterErrors = {};
    if (!from.ok) bad.from = from.message;
    if (!to.ok) bad.to = to.message;
    if (from.ok && to.ok && from.value && to.value && Date.parse(from.value) > Date.parse(to.value)) bad.to = "To is before From";
    setDraft(next);
    if (Object.keys(bad).length > 0) {
      setErrors(bad);
      return;
    }
    const clean = { ...next, from: from.ok ? (from.value ?? "") : "", to: to.ok ? (to.value ?? "") : "" };
    setDraft(clean);
    void run(clean, shown?.sort ?? null, false);
  };

  // Cancel ends the run here and now: its token is void, so an answer that was already on its way is ignored, the
  // spinner stops, and the earlier results stay. The backend is asked to stop too.
  const cancel = () => {
    token.current++;
    cancelInflight();
    moreBusy.current = false;
    setRunning(null);
    setNotice({ kind: "info", text: "Cancelled. The previous results are still shown." });
  };

  const sortBy = (column: string) => {
    if (!shown) return;
    const cur = shown.sort;
    const next: Sort = cur?.column === column ? { column, descending: !cur.descending } : { column, descending: false };
    void run(shown.draft, next, true);
  };

  const loadMore = useCallback(async () => {
    const cur = latest.current;
    if (!cur.shown || moreBusy.current || cur.rows.length >= Math.min(cur.total, cur.maxLoaded)) return;
    moreBusy.current = true;
    const mine = token.current;
    try {
      const page = await eventsPage(cur.shown.query, cur.shown.sort, cur.rows.length, PAGE, idFor(cur.shown.query));
      if (mine === token.current) setRows((r) => [...r, ...page.rows]);
    } catch (e) {
      if (mine === token.current) fail(e);
    } finally {
      if (mine === token.current) moreBusy.current = false;
    }
  }, [idFor, fail]);

  const exportCsv = async () => {
    if (!shown) return;
    const path = await save({ defaultPath: "events.csv", filters: [{ name: "CSV", extensions: ["csv"] }] });
    if (!path) return;
    const id = newQueryId();
    exportId.current = id;
    setExporting(true);
    setNotice(null);
    try {
      const n = await eventsExportCsv(shown.query, path, id);
      setNotice({ kind: "info", text: `Exported ${n.toLocaleString("en-US")} events to ${path}` });
    } catch (e) {
      if (isCmdError(e) && e.kind === "interrupted") setNotice({ kind: "info", text: "Export cancelled. No file was written." });
      else setNotice({ kind: "error", text: isCmdError(e) ? e.message : String(e) });
    } finally {
      exportId.current = null;
      setExporting(false);
    }
  };

  // ------------------------------------------------------------------------------------------------ the grid

  const cols = useMemo(() => COLUMNS.filter((c) => visibleCols.includes(c.id)), [visibleCols]);
  const columnIds = useMemo(() => cols.map((c) => c.id), [cols]);
  const labels = useMemo(() => Object.fromEntries(COLUMNS.map((c) => [c.id, c.label])), []);
  const widths = useMemo(() => Object.fromEntries(COLUMNS.map((c) => [c.id, c.width])), []);
  const gridRows = useMemo(() => rows.map((r) => cols.map((c) => c.text(r))), [rows, cols]);

  const flagClass = (r: EventRow) => {
    const level = r.flag === "malicious" ? "ev-flag-malicious" : r.flag === "suspicious" ? "ev-flag-suspicious" : null;
    return level ? `${level}${r.flag_ai ? " ev-flag-ai" : ""}` : "";
  };

  const cellItems = ({ column, row }: { column: string; value: unknown; row: number }) => {
    const ev = rows[row];
    const col = COLUMN_BY_ID.get(column);
    if (!ev || !col) return [];
    const out: { label: string; run: () => void }[] = [
      { label: "Show details", run: () => setSelected({ source_table: ev.source_table, record_key: ev.record_key }) },
    ];
    const fv = col.filter?.value(ev) ?? null;
    if (col.filter && fv !== null && filterable(fv)) {
      const field = col.filter.field;
      out.push({ label: "Filter by this value", run: () => apply({ fields: { ...draft.fields, [field]: fv } }) });
      out.push({ label: "Exclude this value", run: () => apply({ fields: { ...draft.fields, [field]: `!${fv}` } }) });
    }
    const target = col.entity?.(ev) ?? null;
    if (nav && target) {
      out.push({ label: `Open ${target.kind === "ip" ? "IP" : target.kind} tab`, run: () => nav.openEntity(target) });
    }
    return out;
  };

  const trace = () => {
    const text = draft.fields.source.trim();
    const parts = text.split(",").map((p) => p.trim()).filter((p) => p !== "");
    // A list of only exclusions means "everything but these": adding a name would narrow it to that name alone.
    const next = parts.every((p) => p.startsWith("!")) ? [...parts, "*"] : [...parts, "message_trace_event"];
    apply({ fields: { ...draft.fields, source: next.join(",") } });
  };

  const toggleColumn = (id: string) => {
    const next = visibleCols.includes(id) ? visibleCols.filter((x) => x !== id) : COLUMNS.map((c) => c.id).filter((x) => x === id || visibleCols.includes(x));
    setVisibleCols(next);
    saveJson(VISIBLE_KEY, next);
  };
  const resetColumns = () => {
    removeJson(VISIBLE_KEY);
    setVisibleCols(DEFAULT_VISIBLE);
  };

  // Paging stops at the limit while the backend says there is more: say so instead of just not loading.
  const atLimit = shown !== null && rows.length >= maxLoaded && (capped || total > rows.length);
  const hasRange = (shown?.query.from ?? shown?.query.to) !== undefined;
  const sourceText = shown?.draft.fields.source ?? "";

  return (
    <section className="ev-view" aria-label="Events">
      {chip && !entity && (
        <div className="filter-chip" role="group" aria-label="Scope">
          <span>
            Showing events for {chip.kind} <strong>{displaySafe(chip.value)}</strong>
          </span>
          <button type="button" aria-label={`Remove scope ${displaySafe(chip.value)}`} onClick={onClearChip}>
            ×
          </button>
        </div>
      )}
      <Filters
        draft={draft}
        errors={errors}
        onChange={(p) => setDraft((d) => ({ ...d, ...p }))}
        onApply={apply}
        onClear={() => apply(emptyDraft())}
      />
      {running && (
        <div role="status" className="ev-running">
          <span className="ev-spinner" aria-hidden="true" />
          {running.cancellable ? "Searching…" : "Loading…"}
          {running.cancellable && (
            <button type="button" onClick={cancel}>
              Cancel
            </button>
          )}
        </div>
      )}
      {notice && (
        <div role={notice.kind === "error" ? "alert" : "status"} className="ev-notice">
          {displaySafe(notice.text)}
        </div>
      )}
      <SummaryBar
        summary={summary}
        sourceText={sourceText}
        flag={shown?.draft.flag ?? "all"}
        onAll={() => apply({ flag: "all", fields: { ...draft.fields, source: "" } })}
        onSource={(s) => apply({ fields: { ...draft.fields, source: sourceText.trim() === s ? "" : s } })}
        onFlag={(level) => apply({ flag: shown?.draft.flag === level ? "all" : level })}
        onIncludeTrace={trace}
      />
      <Histogram
        data={hist}
        hasRange={hasRange}
        onRange={(from, to) => apply({ from, to })}
        onReset={() => apply({ from: "", to: "" })}
        onFinding={(id) => nav?.openFinding(id)}
      />
      <div className="ev-toolbar">
        <span className="meta" aria-live="polite">
          {shown ? `${rows.length.toLocaleString("en-US")} of ${total.toLocaleString("en-US")}${capped ? "+" : ""} shown` : ""}
          {atLimit && ` — paging stops here; narrow the filter to see the rest`}
        </span>
        <details className="ev-columns">
          <summary>Columns</summary>
          <ul className="plain">
            {COLUMNS.map((c) => (
              <li key={c.id}>
                <label>
                  <input type="checkbox" checked={visibleCols.includes(c.id)} onChange={() => toggleColumn(c.id)} /> {c.label}
                </label>
              </li>
            ))}
          </ul>
        </details>
        <button type="button" disabled={!shown || exporting} onClick={() => void exportCsv()}>
          Export CSV
        </button>
        {exporting && (
          <button type="button" onClick={() => exportId.current && void queryCancel(exportId.current).catch(() => undefined)}>
            Cancel export
          </button>
        )}
      </div>
      <div className="ev-main">
        <div className="ev-grid">
          <Grid
            columns={columnIds}
            rows={gridRows}
            layoutId={LAYOUT_ID}
            onResetColumns={resetColumns}
            labels={labels}
            widths={widths}
            height={GRID_HEIGHT}
            sort={shown?.sort ?? null}
            onSort={sortBy}
            sortable={(c) => COLUMN_BY_ID.get(c)?.sortable ?? false}
            onNearEnd={() => void loadMore()}
            onRowClick={(_, i) => rows[i] && setSelected({ source_table: rows[i].source_table, record_key: rows[i].record_key })}
            rowClass={(i) => {
              const r = rows[i];
              if (!r) return undefined;
              const sel = selected?.source_table === r.source_table && selected.record_key === r.record_key ? " ev-selected" : "";
              return `${flagClass(r)}${sel}`.trim() || undefined;
            }}
            renderCell={({ column, value, row }) => {
              const r = rows[row];
              if (!r) return undefined;
              if (column === "tags" && r.tags.length > 0) return r.tags.map((t) => <TagBadge key={t.name} tag={t} />);
              if (column === "flag" && r.flag !== null) {
                return <span className={r.flag === "malicious" ? "ev-flagtext ev-flagtext-malicious" : "ev-flagtext ev-flagtext-suspicious"}>{cellText(value)}</span>;
              }
              return undefined;
            }}
            cellItems={cellItems}
          />
        </div>
        {selected && <EventDetail key={`${selected.source_table}:${selected.record_key}`} event={selected} onClose={() => setSelected(null)} />}
      </div>
    </section>
  );
}

export type { EntityKind };
