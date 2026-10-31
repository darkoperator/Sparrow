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
  marksFlagRows,
  marksFlagValue,
  marksListTags,
  marksTagRows,
  newQueryId,
  queryCancel,
  type EntityKind,
  type EventField,
  type EventQuery,
  type EventRow,
  type EventsSummary,
  type FlagLevel,
  type IndicatorChange,
  type Histogram as HistogramData,
  type HistogramGroup,
  type RowRef,
  type Sort,
  type TagInfo,
} from "../api";
import { save } from "../dialog";
import Grid, { cellText } from "../grid/Grid";
import { loadJson, removeJson, saveJson } from "../grid/gridLayout";
import { useFillHeight } from "../grid/useFillHeight";
import AddToTimelineDialog from "../marks/AddToTimelineDialog";
import NoteDialog from "../marks/NoteDialog";
import ReviewMarksDialog from "../marks/ReviewMarksDialog";
import { rowMenu, type RowMenuActions } from "../marks/rowMenu";
import { NewTagDialog } from "../marks/TagMenu";
import { useFocusAnalyst, useNav, useOnDataChanged, useRefreshBadges, useWriteBlocked } from "../shell/nav";
import type { EntityRef } from "../shell/tabs";
import { displaySafe } from "../text";
import Icon from "../ui/Icon";
import "./events.css";
import "../marks/marks.css";
import ColumnFilter, { FilterBadge } from "./ColumnFilter";
import { COLUMN_BY_ID, COLUMN_FIELD, COLUMNS, DEFAULT_VISIBLE } from "./columns";
import EventDetail, { TagBadge } from "./EventDetail";
import { parseField, quoteValue } from "./fieldSyntax";
import Filters, { emptyDraft, FIELD_LABEL, FIELDS, type FilterDraft, type FilterErrors } from "./Filters";
import Histogram, { useHistogramGroup } from "./Histogram";
import SummaryBar from "./SummaryBar";
import { parseUtc } from "./time";

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
  /** Changes when the host wrote marks the grid shows (an entity tab flagging a pivot value): the grid reads again. */
  reloadToken?: number;
  /** The most rows paging loads (the backend counts to one million); a smaller number is for tests. */
  maxLoaded?: number;
}

const PAGE = 200;
const MAX_BUCKETS = 120;
/** Space kept under the grid: the page's bottom padding, plus the selection bar while rows are ticked. */
const BELOW_GRID = 16;
const SELBAR_HEIGHT = 46;

/** The name-like columns read in the UI font (events.png); times, IPs, ids and ASNs stay mono. */
const NAME_COLUMNS: ReadonlySet<string> = new Set(["source", "operation", "actor_upn", "target"]);
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
export { parseUtc };

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

/** A refusal of one field filter comes back as "<Field> filter: …"; it is shown on that column. */
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

/**
 * What the backend says it did to indicators for a flag, worded from its answer: "; IP x added as an indicator",
 * "; indicator updated", both for a value in several tenants, or nothing when it made none.
 */
export function indicatorNote(what: string, changes: IndicatorChange[]): string {
  const made = changes.filter((c) => c.created).length;
  const updated = changes.length - made;
  if (made > 0 && updated > 0) return `; ${what} added as an indicator in ${made === 1 ? "1 tenant" : `${made} tenants`} and updated in ${updated}`;
  if (made > 0) return `; ${what} added as an indicator${made > 1 ? ` in ${made} tenants` : ""}`;
  if (updated > 0) return `; indicator for ${what} updated${updated > 1 ? ` in ${updated} tenants` : ""}`;
  return "";
}

const rowKey = (r: RowRef) => `${r.source_table}\u0000${r.record_key}`;
const TICK = "_tick";
const plural = (n: number, one: string) => (n === 1 ? `1 ${one}` : `${n.toLocaleString("en-US")} ${one}s`);

type Dialog =
  | { kind: "note"; rows: RowRef[] }
  | { kind: "timeline"; rows: RowRef[] }
  | { kind: "newtag"; rows: RowRef[] }
  | { kind: "review"; accept: boolean; rows: EventRow[] };

export default function EventsView({ entity, chip, onClearChip, onRangeChange, onQueryChange, reloadToken, maxLoaded = LOAD_MAX }: EventsViewProps) {
  const nav = useNav();
  const refreshBadges = useRefreshBadges();
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
  // The chart's colouring. Runs read it through the ref. A toggle with no run pending refetches the chart of the query
  // shown; during a run it only records the choice, and the run, when it lands, fetches its own query's chart again
  // if what it got (or what is shown) is in the other colouring.
  const [histGroup, setHistGroup] = useHistogramGroup();
  const histGroupRef = useRef(histGroup);
  const shownGroup = useRef<HistogramGroup | null>(null);
  /** The token of the run (or reload) still pending, else null. */
  const pendingRun = useRef<number | null>(null);
  const [shown, setShown] = useState<Shown | null>(null);
  const [running, setRunning] = useState<{ cancellable: boolean } | null>(null);
  const [exporting, setExporting] = useState(false);
  const [selected, setSelected] = useState<RowRef | null>(null);
  const [visibleCols, setVisibleCols] = useState<string[]>(loadVisible);
  const [ticked, setTicked] = useState<ReadonlySet<string>>(new Set());
  const [tags, setTags] = useState<TagInfo[]>([]);
  // What an open cell menu acts on besides its own row: the ticks at the moment it opened.
  const [menuTicks, setMenuTicks] = useState<ReadonlySet<string>>(new Set());
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [dialogBusy, setDialogBusy] = useState(false);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [detailVersion, setDetailVersion] = useState(0);

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

  const showChart = useCallback((h: HistogramData) => {
    shownGroup.current = h.group;
    setHist(h);
  }, []);
  /** The chart of `query` in the colouring chosen now; dropped if a run started since (`mine`) or the colouring moved. */
  const fetchChart = useCallback(
    (query: EventQuery, mine: number) => {
      const g = histGroupRef.current;
      eventsHistogram(query, MAX_BUCKETS, g, idFor(query)).then(
        (h) => {
          if (mine === token.current && h.group === histGroupRef.current) showChart(h);
        },
        (e) => {
          if (mine === token.current && histGroupRef.current === g) fail(e);
        },
      );
    },
    [idFor, fail, showChart],
  );
  /**
   * A run's chart, as the run lands: shown if it is in the colouring chosen now. Otherwise (the colouring changed while
   * the run was pending, or a page-only run fetched no chart while the one shown is in the other colouring) the run's
   * own query is fetched again in the colouring chosen now.
   */
  const landChart = useCallback(
    (query: EventQuery, h: HistogramData | null, mine: number) => {
      if (h && h.group === histGroupRef.current) showChart(h);
      else if (h || (shownGroup.current !== null && shownGroup.current !== histGroupRef.current)) fetchChart(query, mine);
    },
    [showChart, fetchChart],
  );

  /** Run a query: the page, and (unless `pageOnly`) the summary and the chart. Replaces the results only on success. */
  const run = useCallback(
    async (next: FilterDraft, sort: Sort | null, pageOnly: boolean) => {
      const query = buildQuery(next, scopeKind && scopeValue ? { kind: scopeKind, value: scopeValue } : undefined);
      const mine = ++token.current;
      pendingRun.current = mine;
      cancelInflight();
      moreBusy.current = false;
      setRunning({ cancellable: query.search !== undefined });
      setNotice(null);
      setErrors({});
      try {
        const [page, sum, h] = await Promise.all([
          eventsPage(query, sort, 0, PAGE, idFor(query)),
          pageOnly ? Promise.resolve(null) : eventsSummary(query, idFor(query)),
          pageOnly ? Promise.resolve(null) : eventsHistogram(query, MAX_BUCKETS, histGroupRef.current, idFor(query)),
        ]);
        if (mine !== token.current) return;
        const before = latest.current.shown?.query;
        setRows(page.rows);
        setTotal(page.total);
        setCapped(page.total_capped);
        if (sum) setSummary(sum);
        landChart(query, h, mine);
        setShown({ draft: next, query, sort });
        // A new query shows other events: ticks on the old ones would act on rows nobody can see. A sort keeps them.
        if (!pageOnly) setTicked(new Set());
        if (before?.from !== query.from || before?.to !== query.to) latest.current.onRangeChange?.(query.from, query.to);
      } catch (e) {
        if (mine === token.current) fail(e);
      } finally {
        if (pendingRun.current === mine) pendingRun.current = null;
        if (mine === token.current) {
          inflight.current = [];
          setRunning(null);
        }
      }
    },
    [scopeKind, scopeValue, cancelInflight, idFor, fail, landChart],
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
    pendingRun.current = null;
    cancelInflight();
    moreBusy.current = false;
    setRunning(null);
    setNotice({ kind: "info", text: "Cancelled. The previous results are still shown." });
  };

  /**
   * Read the shown query again after a write, as many rows as were loaded (the page the analyst scrolled to stays), with
   * the summary and the chart. The ticks stay on the rows that are still there.
   */
  const reload = useCallback(async () => {
    const cur = latest.current;
    if (!cur.shown) return;
    const { query, sort } = cur.shown;
    const want = Math.min(Math.max(cur.rows.length, PAGE), cur.maxLoaded);
    const mine = ++token.current;
    pendingRun.current = mine;
    cancelInflight();
    moreBusy.current = false;
    setRunning({ cancellable: query.search !== undefined });
    try {
      const [first, sum, h] = await Promise.all([
        eventsPage(query, sort, 0, PAGE, idFor(query)),
        eventsSummary(query, idFor(query)),
        eventsHistogram(query, MAX_BUCKETS, histGroupRef.current, idFor(query)),
      ]);
      let all = first.rows;
      while (all.length < want && all.length < first.total) {
        const page = await eventsPage(query, sort, all.length, PAGE, idFor(query));
        if (mine !== token.current) return;
        if (page.rows.length === 0) break;
        all = [...all, ...page.rows];
      }
      if (mine !== token.current) return;
      setRows(all);
      setTotal(first.total);
      setCapped(first.total_capped);
      setSummary(sum);
      landChart(query, h, mine);
      const here = new Set(all.map(rowKey));
      setTicked((t) => new Set([...t].filter((k) => here.has(k))));
    } catch (e) {
      if (mine === token.current) fail(e);
    } finally {
      if (pendingRun.current === mine) pendingRun.current = null;
      if (mine === token.current) {
        inflight.current = [];
        setRunning(null);
      }
    }
  }, [cancelInflight, idFor, fail, landChart]);

  /** A new colouring. No run pending: the chart of the query shown, refetched alone. A run pending: see `landChart`. */
  const chooseHistGroup = useCallback(
    (g: HistogramGroup) => {
      histGroupRef.current = g;
      setHistGroup(g);
      const query = latest.current.shown?.query;
      if (query && pendingRun.current === null) fetchChart(query, token.current);
    },
    [setHistGroup, fetchChart],
  );

  const loadTags = useCallback(() => {
    marksListTags().then(setTags, () => undefined);
  }, []);
  useEffect(() => {
    loadTags();
  }, [loadTags]);

  /** After a successful write: say what happened, then read everything the write may have changed again. */
  const wrote = useCallback(
    (message: string) => {
      setNotice({ kind: "info", text: message });
      refreshBadges();
      setDetailVersion((v) => v + 1);
      loadTags();
      void reload();
    },
    [refreshBadges, loadTags, reload],
  );
  // An agent wrote through the bridge: read again like after the analyst's own write, keeping filters and range.
  useOnDataChanged(() => {
    setDetailVersion((v) => v + 1);
    loadTags();
    void reload();
  });
  // The host asks for a re-read (not on mount: the first run loads).
  const seenToken = useRef(reloadToken);
  useEffect(() => {
    if (seenToken.current === reloadToken) return;
    seenToken.current = reloadToken;
    setDetailVersion((v) => v + 1);
    void reload();
  }, [reloadToken, reload]);
  const attempt = useCallback(
    async <T,>(job: () => Promise<T>, message: string | ((done: T) => string)) => {
      try {
        const done = await job();
        wrote(typeof message === "function" ? message(done) : message);
      } catch (e) {
        setNotice({ kind: "error", text: isCmdError(e) ? e.message : String(e) });
      }
    },
    [wrote],
  );

  // Why writes are off (read-only case, or no analyst name), shown on every disabled write item.
  const readOnly = useWriteBlocked();
  const focusAnalyst = useFocusAnalyst();
  const tickedRows = useMemo(() => rows.filter((r) => ticked.has(rowKey(r))), [rows, ticked]);
  const gridBox = useRef<HTMLDivElement>(null);
  const gridHeight = useFillHeight(gridBox, BELOW_GRID + (tickedRows.length > 0 ? SELBAR_HEIGHT : 0));
  // Events with an agent mark waiting for review, whether or not it is the flag shown (a stronger confirmed flag hides it).
  const aiRows = useMemo(() => tickedRows.filter((r) => r.ai_pending), [tickedRows]);
  const toggleTick = (r: EventRow) =>
    setTicked((t) => {
      const next = new Set(t);
      if (!next.delete(rowKey(r))) next.add(rowKey(r));
      return next;
    });
  const closeDialog = () => {
    setDialog(null);
    setDialogBusy(false);
    setDialogError(null);
  };
  const dialogDone = (message: string) => {
    closeDialog();
    wrote(message);
  };

  const act: RowMenuActions = {
    showDetails: (r) => setSelected(r),
    filter: (field, value, exclude) => apply({ fields: { ...draft.fields, [field]: `${exclude ? "!" : ""}${quoteValue(value)}` } }),
    openEntity: (e) => nav?.openEntity(e),
    flagRows: (refs, level: FlagLevel | null) =>
      void attempt(
        () => marksFlagRows(refs, level),
        level === null ? `Cleared the flag on ${plural(refs.length, "event")}` : `Flagged ${plural(refs.length, "event")} ${level}`,
      ),
    flagValue: (kind, value, scope, level, what) =>
      void attempt(
        () => marksFlagValue(kind, value, scope, level),
        (done) => {
          const where = scope ? ` in this ${scope.kind === "account" ? "user" : scope.kind === "ip" ? "IP" : scope.kind}` : "";
          if (level === null) return `Cleared the flag on ${what}${where}; flags set on single events stay`;
          return `Flagged every event with ${what}${where} ${level}, including later imports${indicatorNote(what, done.indicators)}`;
        },
      ),
    tagRows: (refs, tag, add) =>
      void attempt(
        () => marksTagRows(refs, tag, add),
        add ? `Tagged ${plural(refs.length, "event")} “${tag}”` : `Removed tag “${tag}” from ${plural(refs.length, "event")}`,
      ),
    newTag: (refs) => setDialog({ kind: "newtag", rows: refs }),
    addNote: (refs) => setDialog({ kind: "note", rows: refs }),
    addToTimeline: (refs) => setDialog({ kind: "timeline", rows: refs }),
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
  const columnIds = useMemo(() => [TICK, ...cols.map((c) => c.id)], [cols]);
  const labels = useMemo(() => ({ [TICK]: "✓", ...Object.fromEntries(COLUMNS.map((c) => [c.id, c.label])) }), []);
  const widths = useMemo(() => ({ [TICK]: 34, ...Object.fromEntries(COLUMNS.map((c) => [c.id, c.width])) }), []);
  const gridRows = useMemo(() => rows.map((r) => ["", ...cols.map((c) => c.text(r))]), [rows, cols]);

  const flagClass = (r: EventRow) => {
    const level = r.flag === "malicious" ? "ev-flag-malicious" : r.flag === "suspicious" ? "ev-flag-suspicious" : null;
    return level ? `${level}${r.flag_ai ? " ev-flag-ai" : ""}` : "";
  };

  const cellItems = ({ column, row }: { column: string; value: unknown; row: number }) => {
    const ev = rows[row];
    if (!ev) return [];
    // The ticked rows as they were when the menu opened, read from the rows as they are now (a tag toggle updates them).
    const targets = rows.filter((r) => menuTicks.has(rowKey(r)));
    return rowMenu({ column, row: ev, ticked: targets }, { entity, readOnly, focusAnalyst, tags, canOpen: nav !== null, act });
  };

  const trace = () => {
    const text = draft.fields.source.trim();
    const parsed = parseField(text);
    // A list of only exclusions means "everything but these": adding a name would narrow it to that name alone.
    const add = !parsed.ok || parsed.terms.every((t) => t.exclude) ? "*" : "message_trace_event";
    apply({ fields: { ...draft.fields, source: text === "" ? add : `${text},${add}` } });
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
  // A field filter in effect whose column is hidden still narrows the grid: say so, with a way out.
  const hiddenFiltered = FIELDS.filter((f) => draft.fields[f].trim() !== "" && !cols.some((c) => COLUMN_FIELD[c.id] === f));

  const headerPanel = (column: string, close: () => void) => {
    const field = COLUMN_FIELD[column];
    if (!field) return null;
    const query = shown?.query ?? buildQuery(draft, scopeKind && scopeValue ? { kind: scopeKind, value: scopeValue } : undefined);
    return (
      <ColumnFilter
        key={column}
        field={field}
        label={COLUMN_BY_ID.get(column)?.label ?? FIELD_LABEL[field]}
        text={draft.fields[field]}
        error={errors[field]}
        query={query}
        onApply={(text) => apply({ fields: { ...draft.fields, [field]: text } })}
        onClose={close}
      />
    );
  };
  const headerBadge = (column: string) => {
    const field = COLUMN_FIELD[column];
    if (!field || (draft.fields[field].trim() === "" && !errors[field])) return null;
    return <FilterBadge label={COLUMN_BY_ID.get(column)?.label ?? FIELD_LABEL[field]} text={draft.fields[field]} error={errors[field]} />;
  };

  return (
    <section className="ev-view" aria-label="Events">
      <div className="ev-left">
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
      <SummaryBar
        summary={summary}
        sourceText={sourceText}
        flag={shown?.draft.flag ?? "all"}
        onAll={() => apply({ flag: "all", fields: { ...draft.fields, source: "" } })}
        onSource={(s) => apply({ fields: { ...draft.fields, source: sourceText.trim() === s ? "" : s } })}
        onFlag={(level) => apply({ flag: shown?.draft.flag === level ? "all" : level })}
        onIncludeTrace={trace}
      />
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
      <Histogram
        data={hist}
        group={histGroup}
        onGroup={chooseHistGroup}
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
        {hiddenFiltered.length > 0 && (
          <span className="ev-hiddenfilter" role="status">
            Filtered on hidden {hiddenFiltered.length === 1 ? "column" : "columns"}: {hiddenFiltered.map((f) => FIELD_LABEL[f]).join(", ")}
            <button
              type="button"
              className="link"
              onClick={() => apply({ fields: { ...draft.fields, ...Object.fromEntries(hiddenFiltered.map((f) => [f, ""])) } })}
            >
              Clear
            </button>
          </span>
        )}
        <details className="ev-columns">
          <summary className="btn">Columns</summary>
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
        <button type="button" className="btn" disabled={!shown || exporting} onClick={() => void exportCsv()}>
          <Icon name="download" size={13} />
          Export CSV
        </button>
        {exporting && (
          <button type="button" onClick={() => exportId.current && void queryCancel(exportId.current).catch(() => undefined)}>
            Cancel export
          </button>
        )}
        {/* The Events window only (not an entity tab's grid): the whole case, whatever the filters here. */}
        {!entity && (
          <button type="button" className="btn" disabled={!nav} onClick={() => nav?.openAccess({ access: "case", value: "" })}>
            <Icon name="flag" size={13} />
            Access (all malicious)
          </button>
        )}
      </div>
      <div className="ev-main">
        <div className="ev-grid" ref={gridBox}>
          <Grid
            columns={columnIds}
            rows={gridRows}
            layoutId={LAYOUT_ID}
            pinnedFirst={TICK}
            rowId={(i) => (rows[i] ? rowKey(rows[i]) : undefined)}
            onMenuOpen={() => setMenuTicks(ticked)}
            onResetColumns={resetColumns}
            labels={labels}
            widths={widths}
            height={gridHeight}
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
              if (column === TICK) {
                return (
                  <span className="ev-tickcell">
                    <input
                      type="checkbox"
                      aria-label="Select event"
                      checked={ticked.has(rowKey(r))}
                      onClick={(e) => e.stopPropagation()}
                      onChange={() => toggleTick(r)}
                    />
                  </span>
                );
              }
              if (NAME_COLUMNS.has(column)) return <span className="ev-name">{cellText(value)}</span>;
              if (column === "tags" && r.tags.length > 0) return r.tags.map((t) => <TagBadge key={t.name} tag={t} />);
              if (column === "rules" && r.rules.length > 0) {
                return r.rules.map((id) => <span key={id} className="tag ev-tag ev-rule" title="A rule whose open finding has this event as evidence">{displaySafe(id)}</span>);
              }
              if (column === "flag" && r.flag !== null) {
                return <span className={r.flag === "malicious" ? "ev-flagtext ev-flagtext-malicious" : "ev-flagtext ev-flagtext-suspicious"}>{cellText(value)}</span>;
              }
              return undefined;
            }}
            cellItems={cellItems}
            headerPanel={headerPanel}
            headerBadge={headerBadge}
          />
        </div>
      </div>
      {tickedRows.length > 0 && (
        <div className="ev-selbar" role="group" aria-label="Selection">
          <span className="meta" aria-live="polite">
            {plural(tickedRows.length, "event")} selected — right-click to act
            {aiRows.length > 0 && ` · ${aiRows.length.toLocaleString("en-US")} with AI marks`}
          </span>
          <button type="button" onClick={() => setTicked(new Set(rows.map(rowKey)))}>
            Select all shown
          </button>
          <button type="button" onClick={() => setTicked(new Set())}>
            Clear selection
          </button>
          <button
            type="button"
            disabled={readOnly !== null || aiRows.length === 0}
            title={readOnly ?? (aiRows.length === 0 ? "None of the selected events has an AI mark waiting for review" : "Make the agent's flags and tags on the selected events yours")}
            onClick={() => setDialog({ kind: "review", accept: true, rows: aiRows })}
          >
            Confirm AI marks
          </button>
          <button
            type="button"
            disabled={readOnly !== null || aiRows.length === 0}
            title={readOnly ?? (aiRows.length === 0 ? "None of the selected events has an AI mark waiting for review" : "Take the agent's flags and tags off the selected events")}
            onClick={() => setDialog({ kind: "review", accept: false, rows: aiRows })}
          >
            Remove AI marks
          </button>
        </div>
      )}
      {dialog?.kind === "note" && <NoteDialog rows={dialog.rows} onClose={closeDialog} onDone={dialogDone} />}
      {dialog?.kind === "timeline" && <AddToTimelineDialog rows={dialog.rows} onClose={closeDialog} onDone={dialogDone} />}
      {dialog?.kind === "review" && <ReviewMarksDialog accept={dialog.accept} rows={dialog.rows} onClose={closeDialog} onDone={dialogDone} />}
      {dialog?.kind === "newtag" && (
        <NewTagDialog
          count={dialog.rows.length}
          existing={tags.map((t) => t.name)}
          busy={dialogBusy}
          error={dialogError}
          onClose={closeDialog}
          onAdd={(name) => {
            const refs = dialog.rows;
            setDialogBusy(true);
            setDialogError(null);
            marksTagRows(refs, name, true).then(
              () => dialogDone(`Tagged ${plural(refs.length, "event")} “${name}”`),
              (e: unknown) => {
                setDialogError(isCmdError(e) ? e.message : String(e));
                setDialogBusy(false);
              },
            );
          }}
        />
      )}
      </div>
      {selected && (
        <EventDetail
          key={`${selected.source_table}:${selected.record_key}`}
          event={selected}
          onClose={() => setSelected(null)}
          readOnly={readOnly}
          tagNames={tags.map((t) => t.name)}
          version={detailVersion}
          onChanged={wrote}
        />
      )}
    </section>
  );
}

export type { EntityKind };
