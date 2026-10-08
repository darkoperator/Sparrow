import { useCallback, useEffect, useRef, useState } from "react";
import { isCmdError, pivotIp, pivotUser, type Pivot as PivotData, type PivotSection } from "../api";
import Grid, { type Cell } from "../grid/Grid";
import { displaySafe } from "../text";
import type { PivotKind } from "../value";

export interface PivotRequest {
  kind: PivotKind;
  value: string;
}

const DEFAULT_CAP = 200;
const MAX_CAP = 1000;
const count = (n: number) => n.toLocaleString("en-US");

/** A section's rows are JSON objects: the columns are the keys in first-seen order, presentation only. */
function tabulate(rows: unknown[]): { columns: string[]; cells: Cell[][] } {
  const columns: string[] = [];
  const objects = rows.map((r) => (typeof r === "object" && r !== null && !Array.isArray(r) ? (r as Record<string, unknown>) : { value: r }));
  for (const o of objects) {
    for (const k of Object.keys(o)) if (!columns.includes(k)) columns.push(k);
  }
  return { columns, cells: objects.map((o) => columns.map((c) => o[c] ?? null)) };
}

function Section({ s, cap, onRaise }: { s: PivotSection; cap: number; onRaise: () => void }) {
  const { columns, cells } = tabulate(s.rows);
  return (
    <details className="pivot-section" open={s.rows.length > 0 || s.unavailable !== undefined}>
      <summary>
        {displaySafe(s.name)} ({count(s.total)})
      </summary>
      {s.unavailable !== undefined ? (
        <p role="status">{displaySafe(s.unavailable)}</p>
      ) : (
        <>
          {s.truncated && (
            <p className="meta">
              showing {count(s.rows.length)} of {count(s.total)}
              {cap < MAX_CAP ? (
                <>
                  {" — "}
                  <button className="link" onClick={onRaise}>
                    Raise the cap
                  </button>
                </>
              ) : (
                " — the maximum cap"
              )}
            </p>
          )}
          <Grid columns={columns} rows={cells} height={Math.min(320, 26 * (cells.length + 1))} />
        </>
      )}
    </details>
  );
}

/**
 * Everything the case knows about one IP or account, section by section. The host (the shell) passes the request
 * that opened the screen; the form re-runs it with another value. Validation is the backend's: its error is shown.
 */
export default function Pivot({ initial }: { initial?: PivotRequest }) {
  const [kind, setKind] = useState<PivotKind>(initial?.kind ?? "ip");
  const [value, setValue] = useState(initial?.value ?? "");
  const [cap, setCap] = useState(DEFAULT_CAP);
  const [shown, setShown] = useState<PivotRequest | null>(initial ?? null);
  const [data, setData] = useState<PivotData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(initial !== undefined);
  const latest = useRef(0);

  // Starts a request and settles the screen when it answers; a slower, older answer is dropped.
  const load = useCallback((req: PivotRequest, useCap: number) => {
    const mine = ++latest.current;
    return (req.kind === "ip" ? pivotIp : pivotUser)(req.value, useCap).then(
      (d) => {
        if (mine !== latest.current) return;
        setData(d);
        setError(null);
        setLoading(false);
      },
      (e: unknown) => {
        if (mine !== latest.current) return;
        setData(null);
        setError(isCmdError(e) ? e.message : String(e));
        setLoading(false);
      },
    );
  }, []);

  const run = (req: PivotRequest, useCap: number) => {
    setLoading(true);
    setError(null);
    setData(null);
    setShown(req);
    void load(req, useCap);
  };

  useEffect(() => {
    // The shell remounts this screen (key) for a new request; only the first one is loaded here.
    if (initial) void load(initial, DEFAULT_CAP);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setCap(DEFAULT_CAP);
    run({ kind, value }, DEFAULT_CAP);
  };

  return (
    <section className="pivot">
      <h2>Pivot</h2>
      <form onSubmit={submit} className="pivot-form">
        <label>
          Pivot on{" "}
          <select value={kind} onChange={(e) => setKind(e.target.value as PivotKind)}>
            <option value="ip">IP address</option>
            <option value="account">Account</option>
          </select>
        </label>{" "}
        <label>
          Value <input value={value} onChange={(e) => setValue(e.target.value)} size={40} />
        </label>{" "}
        <button type="submit" disabled={value.trim() === ""}>
          Pivot
        </button>
      </form>
      {error && <div role="alert">{displaySafe(error)}</div>}
      {loading && <p>Loading…</p>}
      {shown && data && !error && (
        <>
          <p className="meta">
            {shown.kind === "ip" ? "IP" : "Account"} {displaySafe(shown.value)}
          </p>
          {data.sections.map((s) => (
            <Section
              key={s.name}
              s={s}
              cap={cap}
              onRaise={() => {
                setCap(MAX_CAP);
                run(shown, MAX_CAP);
              }}
            />
          ))}
        </>
      )}
    </section>
  );
}
