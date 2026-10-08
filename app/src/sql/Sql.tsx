import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import { isCmdError, newQueryId, queryCancel, sqlRun, sqlSchema, type QueryResult, type TableInfo } from "../api";
import Grid from "../grid/Grid";
import { displaySafe, displaySafeMultiline } from "../text";
import SchemaSidebar from "./SchemaSidebar";

// The backend clamps to 10000 as well; the default matches `sql_run`'s.
const LIMITS = [100, 1000, 5000, 10000] as const;
const DEFAULT_LIMIT = 1000;

type Outcome =
  | { kind: "result"; result: QueryResult; limit: number }
  | { kind: "error"; message: string }
  | { kind: "cancelled" };

/** An identifier as typed into the editor: bare when plain, else double-quoted. Editor convenience only. */
function identifier(name: string): string {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) ? name : `"${name.replace(/"/g, '""')}"`;
}

const rowCount = (n: number) => (n === 1 ? "1 row" : `${n.toLocaleString("en-US")} rows`);
const message = (e: unknown) => (isCmdError(e) ? e.message : String(e));

/**
 * Read-only SQL: one SELECT run by the backend (`sql_run`, the CLI's `query` limits and refusals), the result in the
 * shared grid, and a schema sidebar. Refusals are shown as the backend words them.
 */
export default function Sql() {
  const [sql, setSql] = useState("");
  const [limit, setLimit] = useState<number>(DEFAULT_LIMIT);
  const [tables, setTables] = useState<TableInfo[]>([]);
  const [schemaError, setSchemaError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const editor = useRef<HTMLTextAreaElement>(null);
  // Where to put the cursor after an insert, applied once the new text is rendered.
  const cursor = useRef<number | null>(null);
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

  useLayoutEffect(() => {
    if (cursor.current !== null && editor.current) {
      editor.current.setSelectionRange(cursor.current, cursor.current);
      editor.current.focus();
      cursor.current = null;
    }
  }, [sql]);

  const run = async () => {
    if (running || sql.trim() === "") return;
    const id = newQueryId();
    activeId.current = id;
    setRunning(true);
    setOutcome(null);
    setCancelError(null);
    let next: Outcome;
    try {
      next = { kind: "result", result: await sqlRun(sql, limit, id), limit };
    } catch (e) {
      const cancelled = isCmdError(e) && e.kind === "interrupted";
      next = cancelled ? { kind: "cancelled" } : { kind: "error", message: message(e) };
    }
    activeId.current = null;
    if (!mounted.current) return;
    setOutcome(next);
    setRunning(false);
  };

  const cancel = async () => {
    if (activeId.current === null) return;
    try {
      await queryCancel(activeId.current);
    } catch (e) {
      if (mounted.current) setCancelError(message(e));
    }
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      void run();
    }
  };

  const insert = (name: string) => {
    const text = identifier(name);
    const el = editor.current;
    const start = el?.selectionStart ?? sql.length;
    const end = el?.selectionEnd ?? sql.length;
    cursor.current = start + text.length;
    setSql(sql.slice(0, start) + text + sql.slice(end));
  };

  return (
    <div className="sql-screen">
      <div>
        {schemaError !== null && <p role="alert">{displaySafe(schemaError)}</p>}
        <SchemaSidebar tables={tables} onInsert={insert} />
      </div>
      <section className="sql-main">
        <textarea
          ref={editor}
          aria-label="SQL"
          className="sql-editor"
          rows={8}
          spellCheck={false}
          value={sql}
          onChange={(e) => setSql(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="SELECT … (one read-only statement; Cmd/Ctrl+Enter runs it)"
        />
        <div className="sql-actions">
          <button disabled={running || sql.trim() === ""} onClick={() => void run()}>
            Run
          </button>
          {running && <button onClick={() => void cancel()}>Cancel</button>}
          <label>
            Row limit{" "}
            <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
              {LIMITS.map((l) => (
                <option key={l} value={l}>
                  {l.toLocaleString("en-US")}
                </option>
              ))}
            </select>
          </label>
          {running && <span className="meta">Running…</span>}
        </div>
        <p className="meta">Leaving this screen cancels a running query.</p>
        {cancelError !== null && <p role="alert">{displaySafe(cancelError)}</p>}
        {outcome?.kind === "cancelled" && <p role="status">Query cancelled.</p>}
        {outcome?.kind === "error" && (
          <p role="alert" className="prose">
            {displaySafeMultiline(outcome.message)}
          </p>
        )}
        {outcome?.kind === "result" && (
          <>
            <p className="meta">
              {rowCount(outcome.result.rows.length)}
              {outcome.result.truncated &&
                ` — showing the first ${outcome.limit.toLocaleString("en-US")} rows; the query returned more.` +
                  " Raise the limit or narrow the query."}
            </p>
            <Grid columns={outcome.result.columns} rows={outcome.result.rows} height={420} />
          </>
        )}
      </section>
    </div>
  );
}
