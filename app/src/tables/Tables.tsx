import { useCallback, useEffect, useRef, useState } from "react";
import {
  browsePage,
  browseTables,
  isCmdError,
  newQueryId,
  queryCancel,
  sqlSchema,
  type ColumnInfo,
  type Filter,
  type Sort,
} from "../api";
import { parseUtc } from "../events/time";
import DateRangeFilter from "../grid/DateRangeFilter";
import Grid, { ROW_HEIGHT, type Cell } from "../grid/Grid";
import { useFillHeight } from "../grid/useFillHeight";
import { displaySafe } from "../text";
import Icon from "../ui/Icon";
import { columnKind } from "./columnKind";
import ColumnQuickFilter from "./ColumnQuickFilter";
import FilterBuilder, { FilterChips } from "./FilterBuilder";
import RowDetail from "./RowDetail";
import "./tables.css";

export interface TableRequest {
  table: string;
  filters: Filter[];
}

const PAGE = 500;
const OPEN_FROM = "0001-01-01T00:00:00Z";
const OPEN_TO = "9999-12-31T23:59:59Z";
/** Space kept under the grid: the screen's bottom padding. */
const TABLES_BOTTOM_PAD = 20;

interface Spec {
  table: string;
  filters: Filter[];
  sort: Sort | null;
}

const message = (e: unknown) => (isCmdError(e) ? e.message : String(e));

/**
 * The table browser: pick a table or view, filter and sort on the server, page on demand while scrolling, open a row
 * in full. Everything is the backend's: this screen holds the filter list, the sort and the pages loaded so far.
 */
export default function Tables({ initial }: { initial?: TableRequest }) {
  const [tables, setTables] = useState<string[]>([]);
  const [spec, setSpec] = useState<Spec | null>(initial ? { ...initial, sort: null } : null);
  const [columnInfo, setColumnInfo] = useState<ColumnInfo[]>([]);
  const [columns, setColumns] = useState<string[]>([]);
  const [rows, setRows] = useState<Cell[][]>([]);
  const [total, setTotal] = useState(0);
  const [capped, setCapped] = useState(false);
  const [more, setMore] = useState(false);
  const [loading, setLoading] = useState(initial !== undefined);
  const [error, setError] = useState<string | null>(null);
  const [cancelled, setCancelled] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);
  const [gridKey, setGridKey] = useState(0); // a new spec shows a fresh grid, scrolled to the top

  const gen = useRef(0); // bumped by every new spec: older responses are dropped
  const inflight = useRef(false);
  const queryId = useRef<string | null>(null);
  const loaded = useRef(0); // rows held, readable from callbacks without stale closures
  const hasMore = useRef(false); // false once a short page (or a full count) says there is nothing after it
  const stalled = useRef(false); // after an error or a cancel, scrolling does not retry by itself

  const schemaFor = useRef(0);

  /** Stops the page request in flight, if any (its answer is dropped by the generation guard). */
  const cancelInflight = useCallback(() => {
    if (inflight.current && queryId.current) void queryCancel(queryId.current).catch(() => {});
    inflight.current = false;
  }, []);

  /** Fetches the page at `offset` for `s`. A first page (offset 0) replaces the rows, a later one appends. */
  const fetchPage = useCallback((s: Spec, offset: number, mine: number) => {
    const id = newQueryId();
    queryId.current = id;
    inflight.current = true;
    return browsePage(s.table, s.filters, s.sort, offset, PAGE, id).then(
      (p) => {
        if (mine !== gen.current) return;
        inflight.current = false;
        setLoading(false);
        setColumns(p.columns);
        setTotal(p.total);
        setCapped(p.total_capped);
        // A full page may have more after it: always when the count was capped, else while rows are missing.
        const next = p.rows.length === PAGE && (p.total_capped || p.offset + p.rows.length < p.total);
        hasMore.current = next;
        setMore(next);
        if (p.offset === 0) {
          loaded.current = p.rows.length;
          setRows(p.rows);
        } else {
          loaded.current += p.rows.length;
          setRows((r) => [...r, ...p.rows]);
        }
      },
      (e: unknown) => {
        if (mine !== gen.current) return;
        inflight.current = false;
        setLoading(false);
        stalled.current = true;
        if (isCmdError(e) && e.kind === "interrupted") setCancelled(true);
        else setError(message(e));
      },
    );
  }, []);

  /** Starts over with a new table, filter list or sort. */
  const begin = (s: Spec) => {
    cancelInflight();
    const mine = ++gen.current;
    stalled.current = false;
    loaded.current = 0;
    setSpec(s);
    setRows([]);
    setTotal(0);
    setCapped(false);
    setMore(false);
    hasMore.current = false;
    setError(null);
    setCancelled(false);
    setSelected(null);
    setGridKey((k) => k + 1);
    setLoading(true);
    void fetchPage(s, 0, mine);
  };

  useEffect(() => {
    let live = true;
    browseTables().then(
      (t) => live && setTables(t),
      (e: unknown) => live && setError(message(e)),
    );
    if (initial) {
      void fetchPage({ ...initial, sort: null }, 0, gen.current);
      const mine = ++schemaFor.current;
      sqlSchema(initial.table).then(
        (info) => live && mine === schemaFor.current && setColumnInfo(info[0]?.columns ?? []),
        (e: unknown) => live && mine === schemaFor.current && setError(message(e)),
      );
    }
    return () => {
      live = false;
      // Leaving the screen: stop the page being read and drop its answer.
      // A counter, not a DOM node: the current value is what is wanted here.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      gen.current++;
      cancelInflight();
    };
    // Runs once per mount; the shell remounts this screen (key) for a new request.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const pickTable = (table: string) => {
    if (table === "") return;
    setColumnInfo([]);
    const mine = ++schemaFor.current;
    sqlSchema(table).then(
      (info) => mine === schemaFor.current && setColumnInfo(info[0]?.columns ?? []),
      (e: unknown) => mine === schemaFor.current && setError(message(e)),
    );
    begin({ table, filters: [], sort: null });
  };

  const addFilter = (f: Filter) => spec && begin({ ...spec, filters: [...spec.filters, f] });
  const removeFilter = (i: number) => spec && begin({ ...spec, filters: spec.filters.filter((_, j) => j !== i) });

  const onSort = (column: string) => {
    if (!spec) return;
    const cur = spec.sort;
    const next: Sort | null =
      cur?.column !== column ? { column, descending: false } : cur.descending ? null : { column, descending: true };
    begin({ ...spec, sort: next });
  };

  const loadMore = useCallback(() => {
    if (!spec || inflight.current || stalled.current || loaded.current === 0 || !hasMore.current) return;
    setLoading(true);
    void fetchPage(spec, loaded.current, gen.current);
  }, [spec, fetchPage]);

  const retry = () => {
    if (!spec) return;
    stalled.current = false;
    setError(null);
    setCancelled(false);
    setLoading(true);
    void fetchPage(spec, loaded.current, gen.current);
  };

  const cancel = () => {
    if (queryId.current) void queryCancel(queryId.current).catch(() => {});
  };

  const onFilterCell = (column: string, value: Cell) => {
    if (value === null || value === undefined) addFilter({ op: "is_null", column });
    else addFilter({ op: "eq", column, value });
  };

  const clearColumn = (column: string) => spec && begin({ ...spec, filters: spec.filters.filter((f) => f.column !== column) });
  /** A date range replaces the column's earlier range. An open end is the far end of the time the column can hold. */
  const applyRange = (info: ColumnInfo, from: string | undefined, to: string | undefined) => {
    if (!spec) return;
    const rest = spec.filters.filter((f) => !(f.column === info.name && f.op === "between"));
    if (!from && !to) return begin({ ...spec, filters: rest });
    const low = from ?? OPEN_FROM;
    const high = to ?? OPEN_TO;
    const day = columnKind(info.type) === "date";
    begin({ ...spec, filters: [...rest, { op: "between", column: info.name, low: day ? low.slice(0, 10) : low, high: day ? high.slice(0, 10) : high }] });
  };
  const headerPanel = (column: string, close: () => void) => {
    const info = columnInfo.find((c) => c.name === column);
    if (!info || !spec) return null;
    const on = spec.filters.filter((f) => f.column === column);
    const kind = columnKind(info.type);
    if (kind !== "time" && kind !== "date") {
      return <ColumnQuickFilter key={column} column={info} active={on.length > 0} onAdd={addFilter} onClear={() => clearColumn(column)} onClose={close} />;
    }
    const range = on.find((f) => f.op === "between");
    const end = (v: unknown, which: "from" | "to", open: string) => {
      if (typeof v !== "string" || v === open) return undefined;
      const r = parseUtc(v, which);
      return r.ok ? r.value : undefined;
    };
    return (
      <DateRangeFilter
        key={column}
        label={column}
        from={range && end(range.low, "from", OPEN_FROM)}
        to={range && end(range.high, "to", OPEN_TO)}
        onApply={(from, to) => applyRange(info, from, to)}
        onClose={close}
      />
    );
  };
  const panelLabel = (column: string) => {
    const kind = columnKind(columnInfo.find((c) => c.name === column)?.type ?? "");
    return kind === "time" || kind === "date" ? "Filter by date…" : "Filter this column…";
  };
  const headerBadge = (column: string) =>
    spec?.filters.some((f) => f.column === column) ? (
      <span className="grid-badge colf-badge" role="img" aria-label={`${displaySafe(column)} is filtered`} title={`${displaySafe(column)} is filtered`}>
        <Icon name="filter" size={12} />
      </span>
    ) : null;

  const gridBox = useRef<HTMLDivElement>(null);
  const gridHeight = useFillHeight(gridBox, TABLES_BOTTOM_PAD);
  const detailRow = selected === null ? undefined : rows[selected];

  return (
    <section className="tables">
      <header className="tbl-head">
        <h2>Tables</h2>
        <label className="tbl-pick">
          Table{" "}
          <select className="mono" value={spec?.table ?? ""} onChange={(e) => pickTable(e.target.value)}>
            <option value="">Choose a table…</option>
            {tables.map((t) => (
              <option key={t} value={t}>
                {displaySafe(t)}
              </option>
            ))}
          </select>
        </label>
      </header>
      {spec && (columnInfo.length > 0 || spec.filters.length > 0) && (
        <div className="card tbl-filters">
          {columnInfo.length > 0 && <FilterBuilder key={spec.table} columns={columnInfo} onAdd={addFilter} />}
          {spec.filters.length > 0 && <FilterChips filters={spec.filters} onRemove={removeFilter} />}
        </div>
      )}
      {error && <div role="alert">{displaySafe(error)}</div>}
      {cancelled && <p role="status">Query cancelled.</p>}
      {loading && (
        <p role="status">
          Loading… <button onClick={cancel}>Cancel</button>
        </p>
      )}
      {spec && (!loading || rows.length > 0) && !error && !cancelled && (
        <p className="meta tbl-total" data-testid="total">
          {capped ? "≥ " : ""}
          {total.toLocaleString("en-US")} {total === 1 ? "row" : "rows"}
          {(rows.length < total || capped) && ` · ${rows.length.toLocaleString("en-US")} loaded`}
        </p>
      )}
      {(error || cancelled) && rows.length > 0 && more && <button className="tbl-more" onClick={retry}>Load more</button>}
      {spec && rows.length > 0 && (
        <div ref={gridBox} className={detailRow ? "tables-layout tables-layout-detail" : "tables-layout"}>
          <Grid
            key={gridKey}
            layoutId={`table:${spec.table}`}
            columns={columns}
            rows={rows}
            height={gridHeight}
            sort={spec.sort}
            onSort={onSort}
            onNearEnd={more ? loadMore : undefined}
            onRowClick={(_, i) => setSelected(i)}
            cellActions={{ onFilter: onFilterCell }}
            headerPanel={headerPanel}
            headerBadge={headerBadge}
            panelLabel={panelLabel}
          />
          {detailRow && <RowDetail columns={columns} row={detailRow} maxHeight={gridHeight + ROW_HEIGHT} />}
        </div>
      )}
      {spec && !loading && !error && !cancelled && rows.length === 0 && <p className="tbl-empty">No rows match.</p>}
    </section>
  );
}
