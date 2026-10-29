// The detail pane for any queue item. Findings keep the full finding detail; every other item shows its own fields
// in full, as text. Nothing here interprets a value.
import { useState, type ReactNode } from "react";
import { evidenceFilter, isCmdError, type QueueItem } from "../api";
import { useNav } from "../shell/nav";
import { displaySafe, displaySafeMultiline } from "../text";
import { entityKindFor } from "../value";
import Diff from "./Diff";
import FindingDetail from "./FindingDetail";

type Rec = Record<string, unknown>;

const isRec = (v: unknown): v is Rec => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | null => (v === null || v === undefined ? null : typeof v === "string" ? v : JSON.stringify(v));

function Fields({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="detail-fields">
      {rows
        .filter(([, v]) => v !== null && v !== undefined && v !== "")
        .map(([k, v]) => (
          <div key={k} style={{ display: "contents" }}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
    </dl>
  );
}

const text = (v: unknown): ReactNode => {
  const s = str(v);
  return s === null ? null : <span className="prose">{displaySafeMultiline(s)}</span>;
};

function EntityButton({ value }: { value: string }) {
  const nav = useNav();
  const kind = nav ? entityKindFor("", value) : null;
  if (!nav || !kind) return null;
  return (
    <button
      className="link"
      aria-label={`Open ${kind === "ip" ? "IP" : kind} tab ${displaySafe(value)}`}
      onClick={() => nav.openEntity({ kind, value })}
    >
      {kind === "ip" ? "Open IP tab" : "Open account tab"}
    </button>
  );
}

/** An evidence ref is "table:record_key"; the backend resolves its key column, then the link opens that table. */
function EvidenceRefs({ refs }: { refs: string[] }) {
  const nav = useNav();
  const [error, setError] = useState<string | null>(null);
  if (refs.length === 0) return null;
  const open = (table: string, key: string) => {
    setError(null);
    evidenceFilter(table, key).then(
      (t) => nav?.openTable(t.table, t.filters),
      (e: unknown) => setError(isCmdError(e) ? e.message : String(e)),
    );
  };
  return (
    <>
      {error && <div role="alert">{displaySafe(error)}</div>}
      <ul className="plain card rq-card rq-refs">
        {refs.map((r) => {
          const at = r.indexOf(":");
          return (
            <li key={r}>
              {nav && at > 0 ? (
                <button className="link" onClick={() => open(r.slice(0, at), r.slice(at + 1))}>
                  {displaySafe(r)}
                </button>
              ) : (
                displaySafe(r)
              )}
            </li>
          );
        })}
      </ul>
    </>
  );
}

function IndicatorFields({ o }: { o: Rec }) {
  const value = str(o.value);
  return (
    <Fields
      rows={[
        ["Type", text(o.type ?? o.ioc_type)],
        [
          "Value",
          value === null ? null : (
            <>
              {text(value)} <EntityButton value={value} />
            </>
          ),
        ],
        ["Verdict", text(o.verdict)],
        ["Note", text(o.note)],
        ["Tenant", text(o.tenant_key)],
      ]}
    />
  );
}

function TimelineFields({ o }: { o: Rec }) {
  const evidence = Array.isArray(o.evidence) ? o.evidence.filter((e): e is string => typeof e === "string") : [];
  return (
    <>
      <Fields
        rows={[
          ["Time", text(o.event_time)],
          ["Phase", text(o.phase)],
          ["Title", text(o.title)],
          ["Narrative", text(o.narrative)],
          ["Status", text(o.status)],
          ["Tenant", text(o.tenant_key)],
        ]}
      />
      {evidence.length > 0 && (
        <>
          <h4>Evidence</h4>
          <EvidenceRefs refs={evidence} />
        </>
      )}
    </>
  );
}

/** The finding a queue item is about, if it is about one. */
export function findingIdOf(q: QueueItem): string | null {
  if (q.source === "decision") return q.object_type === "finding" ? q.object_id : null;
  return q.item.kind === "finding" ? q.item.finding_id : null;
}

export default function QueueItemDetail({ item }: { item: QueueItem }) {
  const findingId = findingIdOf(item);
  if (item.source === "decision") {
    // The object as it will be once accepted; a removal has only its `before`.
    const o = isRec(item.after) ? item.after : isRec(item.before) ? item.before : {};
    return (
      <div className="queue-item-detail">
        <Fields
          rows={[
            ["Object", displaySafe(`${item.object_type} ${item.object_id}`)],
            ["Action", displaySafe(item.action)],
            ["Actor", displaySafe(item.actor)],
            ["On behalf of", item.on_behalf_of ? displaySafe(item.on_behalf_of) : null],
            ["Decided", displaySafe(item.decided_at)],
            ["Reason", text(item.reason)],
          ]}
        />
        {item.object_type === "indicator" && <IndicatorFields o={o} />}
        {item.object_type === "timeline_entry" && <TimelineFields o={o} />}
        <h4>Change</h4>
        <div className="card rq-card">
          <Diff before={item.before} after={item.after} />
        </div>
        {findingId !== null && <FindingDetail findingId={findingId} />}
      </div>
    );
  }
  const p = item.item;
  return (
    <div className="queue-item-detail">
      <Fields
        rows={[
          ["From", displaySafe(item.source_analyst)],
          ["Classification", displaySafe(item.classification)],
          ["State", displaySafe(item.state)],
        ]}
      />
      {p.kind === "indicator" && <IndicatorFields o={p as unknown as Rec} />}
      {p.kind === "timeline_entry" && <TimelineFields o={p as unknown as Rec} />}
      {p.kind === "note" && <Fields rows={[["Target", text(p.target)], ["Text", text(p.text)]]} />}
      {p.kind !== "finding" && (
        <>
          <h4>Current value</h4>
          {item.current === null || item.current === undefined ? (
            <p className="card rq-card">None: this item is new to the case.</p>
          ) : (
            <pre className="prose card rq-card">{displaySafeMultiline(JSON.stringify(item.current, null, 2))}</pre>
          )}
        </>
      )}
      <h4>Change</h4>
      <div className="card rq-card">
        <Diff before={item.current} after={item.item} />
      </div>
      {findingId !== null && <FindingDetail findingId={findingId} />}
    </div>
  );
}
