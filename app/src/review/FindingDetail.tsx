import { useEffect, useMemo, useState } from "react";
import { findingDetail, isCmdError, type FindingDetail as Detail } from "../api";
import Grid from "../grid/Grid";
import { useNav } from "../shell/nav";
import { displaySafe, displaySafeMultiline } from "../text";

const EVIDENCE_COLUMNS = ["time", "table", "key", "role", "summary", "context"];

/** One finding in full: evidence rows, facts, rule guidance, notes and the audit history. All text is shown as text. */
export default function FindingDetail({ findingId }: { findingId: string }) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const nav = useNav();

  useEffect(() => {
    let current = true;
    findingDetail(findingId).then(
      (d) => {
        if (!current) return;
        setDetail(d);
        setError(null);
      },
      (e: unknown) => {
        if (!current) return;
        setDetail(null);
        setError(isCmdError(e) ? e.message : String(e));
      },
    );
    return () => {
      current = false;
    };
  }, [findingId]);

  const rows = useMemo(
    () =>
      (detail?.evidence ?? []).map((e) => [
        e.event_time,
        e.source_table,
        e.record_key,
        e.role,
        e.timeline?.summary ?? null,
        e.context,
      ]),
    [detail],
  );

  if (error) return <div role="alert">{displaySafe(error)}</div>;
  if (!detail) return <p>Loading…</p>;
  const f = detail.finding;
  return (
    <div className="finding-detail">
      <p className="meta">
        {displaySafe(
          `${f.finding_id} · ${f.severity} · ${f.status}${f.rule_id ? ` · ${f.rule_id}` : ""}${
            f.actor_upn ? ` · ${f.actor_upn}` : ""
          }`,
        )}
        {nav && f.actor_upn && (
          <>
            {" "}
            <button
              className="link"
              aria-label={`Open account tab ${displaySafe(f.actor_upn)}`}
              onClick={() => nav.openEntity({ kind: "account", value: f.actor_upn! })}
            >
              Open tab
            </button>
          </>
        )}
      </p>
      {detail.analyst_guidance && (
        <section>
          <h4>Guidance</h4>
          <p className="prose">{displaySafeMultiline(detail.analyst_guidance)}</p>
        </section>
      )}
      <section>
        <h4>Evidence ({detail.evidence.length})</h4>
        <Grid columns={EVIDENCE_COLUMNS} rows={rows} layoutId="finding-evidence" height={220} />
      </section>
      <section>
        <h4>Facts</h4>
        {detail.facts_unavailable !== undefined ? (
          <p>{displaySafe(detail.facts_unavailable)}</p>
        ) : detail.facts !== undefined ? (
          <pre className="prose">{displaySafeMultiline(JSON.stringify(detail.facts, null, 2))}</pre>
        ) : (
          <p>None for this rule.</p>
        )}
      </section>
      <section>
        <h4>Notes</h4>
        {detail.notes.length === 0 ? (
          <p>No notes.</p>
        ) : (
          <ul>
            {detail.notes.map((n) => (
              <li key={n.annotation_id}>
                {n.actor.startsWith("agent:") && <span className="tag">agent note</span>}{" "}
                <span className="meta">{displaySafe(`${n.actor} · ${n.created_at}`)}</span>
                <p className="prose">{displaySafeMultiline(n.text)}</p>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h4>History</h4>
        <ol data-testid="history">
          {detail.audit.map((a) => (
            <li key={a.seq}>
              {displaySafe(`#${a.seq} ${a.ts} ${a.actor}${a.on_behalf_of ? ` for ${a.on_behalf_of}` : ""} ${a.action}`)}
              {a.reason && <div className="reason">{displaySafe(a.reason)}</div>}
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}
