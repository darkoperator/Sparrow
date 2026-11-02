import { useEffect, useMemo, useRef, useState } from "react";
import {
  isCmdError,
  newQueryId,
  queryCancel,
  sqlCheck,
  sqlExportCsv,
  sqlRun,
  sqlSchema,
  type QueryResult,
  type TableInfo,
} from "../api";
import { save } from "../dialog";
import { useColumnView, ViewNote, type ViewColumn } from "../grid/columnView";
import Grid from "../grid/Grid";
import { displaySafe, displaySafeMultiline } from "../text";
import Icon from "../ui/Icon";
import { identifier } from "./completion";
import NotebookPanel from "./NotebookPanel";
import SchemaSidebar from "./SchemaSidebar";
import SqlEditor, { type CheckNote, type SqlEditorHandle } from "./SqlEditor";
import "./sql.css";

// The backend clamps to 10000 as well; the default matches `sql_run`'s.
const LIMITS = [100, 1000, 5000, 10000] as const;
const DEFAULT_LIMIT = 1000;
const EXPORT_CAP = 1_000_000;

/** The pages loaded so far for one Run: `sql` is what ran (later pages re-run exactly that text). */
interface Loaded {
  sql: string;
  limit: number;
  columns: string[];
  rows: unknown[][];
  /** The latest page's `truncated`. */
  truncated: boolean;
  ordered: boolean;
  /** Rows in the latest page: a page shorter than the limit was the last. */
  lastPage: number;
  pages: number;
}

type Outcome = { kind: "result"; loaded: Loaded } | { kind: "error"; message: string } | { kind: "cancelled" };

const SIDE_TABS = ["notebook", "schema"] as const;
type Side = (typeof SIDE_TABS)[number];

const rowCount = (n: number) => (n === 1 ? "1 row" : `${n.toLocaleString("en-US")} rows`);
const message = (e: unknown) => (isCmdError(e) ? e.message : String(e));
const interrupted = (e: unknown) => isCmdError(e) && e.kind === "interrupted";

/**
 * Read-only SQL: one SELECT run by the backend (`sql_run`, the CLI's `query` limits and refusals), the result in the
 * shared grid, and a schema sidebar. Refusals are shown as the backend words them.
 */
export default function Sql() {
  const [sql, setSql] = useState("");
  const [limit, setLimit] = useState<number>(DEFAULT_LIMIT);
  const [tables, setTables] = useState<TableInfo[]>([]);
  const [schemaError, setSchemaError] = useState<string | null>(null);
  const [checkError, setCheckError] = useState<CheckNote | null>(null);
  const [running, setRunning] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [pageNote, setPageNote] = useState<{ alert: boolean; text: string } | null>(null);
  const [exportNote, setExportNote] = useState<{ alert: boolean; text: string } | null>(null);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const [side, setSide] = useState<Side>("notebook");
  // The side tabs as a tab list: arrows, Home and End move between them (and select), Tab leaves the list.
  const sideKey = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    const i = SIDE_TABS.indexOf(side);
    const to =
      e.key === "ArrowRight" ? (i + 1) % SIDE_TABS.length
      : e.key === "ArrowLeft" ? (i + SIDE_TABS.length - 1) % SIDE_TABS.length
      : e.key === "Home" ? 0
      : e.key === "End" ? SIDE_TABS.length - 1
      : null;
    if (to === null) return;
    e.preventDefault();
    setSide(SIDE_TABS[to]);
    document.getElementById(`sql-tab-${SIDE_TABS[to]}`)?.focus();
  };
  const editor = useRef<SqlEditorHandle>(null);
  // A query still running when the screen goes away is cancelled, and its late outcome ignored: the backend holds
  // the case for it, and nothing would show its result.
  const mounted = useRef(true);
  // The id of the run in flight: Cancel and leaving the screen cancel that run only.
  const activeId = useRef<string | null>(null);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (activeId.current !== null) queryCancel(activeId.current).catch(() => {});
    };
  }, []);

  useEffect(() => {
    let live = true;
    sqlSchema().then(
      (t) => live && setTables(t),
      (e: unknown) => live && setSchemaError(message(e)),
    );
    return () => {
      live = false;
    };
  }, []);

  // One operation at a time. The slot is taken synchronously (state would lag a keypress) and, for the export,
  // before the save dialog opens; `busy` mirrors it for rendering.
  const slot = useRef(false);
  const busy = running || exporting;

  const run = async () => {
    editor.current?.closeCompletion();
    if (slot.current || sql.trim() === "") return;
    slot.current = true;
    const id = newQueryId();
    activeId.current = id;
    setRunning(true);
    setOutcome(null);
    setPageNote(null);
    setExportNote(null);
    setCancelError(null);
    let next: Outcome;
    try {
      const r = await sqlRun(sql, limit, id, 0);
      next = {
        kind: "result",
        loaded: {
          sql,
          limit,
          columns: r.columns,
          rows: r.rows,
          truncated: r.truncated,
          ordered: r.ordered,
          lastPage: r.rows.length,
          pages: 1,
        },
      };
    } catch (e) {
      next = interrupted(e) ? { kind: "cancelled" } : { kind: "error", message: message(e) };
    }
    if (activeId.current === id) activeId.current = null;
    slot.current = false;
    if (!mounted.current) return;
    setOutcome(next);
    setRunning(false);
  };

  const loadMore = async (loaded: Loaded) => {
    if (slot.current) return;
    slot.current = true;
    const id = newQueryId();
    activeId.current = id;
    setRunning(true);
    setPageNote(null);
    setCancelError(null);
    let page: QueryResult | null = null;
    let note: { alert: boolean; text: string } | null = null;
    try {
      page = await sqlRun(loaded.sql, loaded.limit, id, loaded.rows.length);
    } catch (e) {
      note = interrupted(e) ? { alert: false, text: "Query cancelled." } : { alert: true, text: message(e) };
    }
    if (activeId.current === id) activeId.current = null;
    slot.current = false;
    if (!mounted.current) return;
    if (page !== null) {
      const p = page;
      setOutcome({
        kind: "result",
        loaded: {
          ...loaded,
          rows: [...loaded.rows, ...p.rows],
          truncated: p.truncated,
          lastPage: p.rows.length,
          pages: loaded.pages + 1,
        },
      });
    }
    setPageNote(note);
    setRunning(false);
  };

  const exportCsv = async () => {
    if (slot.current || sql.trim() === "") return;
    slot.current = true;
    const text = sql;
    setExporting(true);
    setExportNote(null);
    setCancelError(null);
    const id = newQueryId();
    let note: { alert: boolean; text: string } | null;
    try {
      const path = await save({ defaultPath: "sparrow-query.csv", filters: [{ name: "CSV", extensions: ["csv"] }] });
      if (path === null || !mounted.current) {
        slot.current = false;
        if (mounted.current) setExporting(false);
        return;
      }
      activeId.current = id;
      const r = await sqlExportCsv(text, path, id);
      note = {
        alert: false,
        text:
          `${r.rows.toLocaleString("en-US")} ${r.rows === 1 ? "row" : "rows"} written` +
          (r.capped ? ` (capped at ${EXPORT_CAP.toLocaleString("en-US")})` : ""),
      };
    } catch (e) {
      note = interrupted(e) ? { alert: false, text: "Export cancelled." } : { alert: true, text: message(e) };
    }
    if (activeId.current === id) activeId.current = null;
    slot.current = false;
    if (!mounted.current) return;
    setExportNote(note);
    setExporting(false);
  };

  const cancel = async () => {
    if (activeId.current === null) return;
    try {
      await queryCancel(activeId.current);
    } catch (e) {
      if (mounted.current) setCancelError(message(e));
    }
  };

  const loaded = outcome?.kind === "result" ? outcome.loaded : null;
  const hasMore = loaded !== null && loaded.lastPage >= loaded.limit;

  return (
    <div className="sql-screen">
      <div className="sql-side">
        <div className="sql-side-tabs" role="tablist" aria-label="Side panel">
          {SIDE_TABS.map((t) => (
            <button
              key={t}
              type="button"
              role="tab"
              id={`sql-tab-${t}`}
              aria-selected={side === t}
              aria-controls={`sql-panel-${t}`}
              tabIndex={side === t ? 0 : -1}
              className={side === t ? "sql-side-tab is-active" : "sql-side-tab"}
              onClick={() => setSide(t)}
              onKeyDown={sideKey}
            >
              {t === "notebook" ? "Notebook" : "Schema"}
            </button>
          ))}
        </div>
        <div role="tabpanel" id="sql-panel-notebook" aria-labelledby="sql-tab-notebook" hidden={side !== "notebook"}>
          <NotebookPanel editorText={sql} onLoad={(text) => editor.current?.setText(text)} />
        </div>
        <div role="tabpanel" id="sql-panel-schema" aria-labelledby="sql-tab-schema" hidden={side !== "schema"}>
          <div className="label sql-side-head">Schema · read-only</div>
          {schemaError !== null && <p role="alert">{displaySafe(schemaError)}</p>}
          <SchemaSidebar tables={tables} onInsert={(name) => editor.current?.insert(identifier(name))} />
        </div>
      </div>
      <section className="sql-main">
        <SqlEditor
          ref={editor}
          tables={tables}
          onChange={setSql}
          onRun={() => void run()}
          check={sqlCheck}
          onCheckNote={setCheckError}
        />
        {checkError !== null && (
          <p role="alert" className="prose">
            {checkError.unavailable && "SQL check unavailable: "}
            {displaySafeMultiline(checkError.text)}
          </p>
        )}
        <div className="sql-actions sql-runbar">
          <button className="btn-primary" disabled={busy || sql.trim() === ""} onClick={() => void run()}>
            Run
          </button>
          {busy && <button onClick={() => void cancel()}>Cancel</button>}
          <label className="sql-limit">
            Row limit{" "}
            <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
              {LIMITS.map((l) => (
                <option key={l} value={l}>
                  {l.toLocaleString("en-US")}
                </option>
              ))}
            </select>
          </label>
          <button className="btn-ghost" disabled={busy || sql.trim() === ""} onClick={() => void exportCsv()}>
            Export CSV…
          </button>
          {busy && <span className="meta">{exporting ? "Exporting…" : "Running…"}</span>}
          <span className="sql-hint">Cmd/Ctrl+Enter runs</span>
        </div>
        <p className="meta sql-note">
          <Icon name="alert" size={12} />
          Leaving this screen cancels a running query.
        </p>
        {cancelError !== null && <p role="alert">{displaySafe(cancelError)}</p>}
        {exportNote !== null &&
          (exportNote.alert ? (
            <p role="alert" className="prose">
              {displaySafeMultiline(exportNote.text)}
            </p>
          ) : (
            <p role="status">{displaySafe(exportNote.text)}</p>
          ))}
        {outcome?.kind === "cancelled" && <p role="status">Query cancelled.</p>}
        {outcome?.kind === "error" && (
          <p role="alert" className="prose">
            {displaySafeMultiline(outcome.message)}
          </p>
        )}
        {loaded !== null && (
          <>
            <div className="sql-results-head">
              <h3>Results</h3>
            </div>
            <p className="meta sql-count">
              {rowCount(loaded.rows.length)}
              {loaded.truncated &&
                loaded.pages === 1 &&
                ` — showing the first ${loaded.limit.toLocaleString("en-US")} rows; the query returned more.` +
                  ` Load next ${loaded.limit.toLocaleString("en-US")}, raise the limit, or narrow the query.`}
            </p>
            <div className="sql-actions">
              <button disabled={busy || !hasMore} onClick={() => void loadMore(loaded)}>
                Load next {loaded.limit.toLocaleString("en-US")}
              </button>
              {loaded.ordered === false && (hasMore || loaded.pages > 1) && (
                <span className="meta">No ORDER BY — pages may overlap or skip rows.</span>
              )}
            </div>
            {pageNote !== null &&
              (pageNote.alert ? (
                <p role="alert" className="prose">
                  {displaySafeMultiline(pageNote.text)}
                </p>
              ) : (
                <p role="status">{displaySafe(pageNote.text)}</p>
              ))}
            <LoadedGrid key={loaded.sql} columns={loaded.columns} rows={loaded.rows} />
          </>
        )}
      </section>
    </div>
  );
}

/** The results so far, sorted and filtered by column in memory; the query itself is untouched. */
function LoadedGrid({ columns, rows }: { columns: string[]; rows: unknown[][] }) {
  const defs = useMemo<ViewColumn<unknown[]>[]>(() => columns.map((id, i) => ({ id, label: id, value: (r) => r[i] })), [columns]);
  const view = useColumnView(rows, defs);
  return (
    <>
      <ViewNote view={view} />
      <Grid
        columns={columns}
        rows={view.rows}
        height={420}
        sort={view.sort}
        onSort={view.onSort}
        headerPanel={view.panel}
        headerBadge={view.badge}
        panelLabel={view.panelLabel}
      />
    </>
  );
}
