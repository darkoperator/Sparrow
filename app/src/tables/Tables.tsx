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
import Grid, { type Cell } from "../grid/Grid";
import { displaySafe } from "../text";
import FilterBuilder, { FilterChips } from "./FilterBuilder";
import RowDetail from "./RowDetail";
import "./tables.css";

export interface TableRequest {
  table: string;
  filters: Filter[];
}

const PAGE = 500;

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
        <div className="tables-layout">
          <Grid
            key={gridKey}
            layoutId={`table:${spec.table}`}
            columns={columns}
            rows={rows}
            height={360}
            sort={spec.sort}
            onSort={onSort}
            onNearEnd={more ? loadMore : undefined}
            onRowClick={(_, i) => setSelected(i)}
            cellActions={{ onFilter: onFilterCell }}
          />
          {selected !== null && rows[selected] && <RowDetail columns={columns} row={rows[selected]} />}
        </div>
      )}
      {spec && !loading && !error && !cancelled && rows.length === 0 && <p className="tbl-empty">No rows match.</p>}
    </section>
  );
}
