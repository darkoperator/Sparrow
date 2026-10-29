// The panel beside the grid for one event: its main fields, the flag and where it comes from, tags, notes, the
// source file and line, and the raw record (collapsed). Account, IP, device and session values open entity tabs.
// Everything is rendered as text.
import { useEffect, useState, type ReactNode } from "react";
import { eventsDetail, isCmdError, type EntityArg, type EventDetail as Detail, type RowRef, type TagRef } from "../api";
import { useNav } from "../shell/nav";
import { displaySafe, displaySafeMultiline } from "../text";
import { deviceKey, isoSeconds } from "./columns";

const MIN_WIDTH = 280;
const MAX_WIDTH = 900;

export function TagBadge({ tag }: { tag: TagRef }) {
  return (
    <span className={tag.ai ? "tag ev-tag ev-tag-ai" : "tag ev-tag"} title={tag.ai ? "Added by an agent; not yet confirmed" : undefined}>
      {displaySafe(tag.name)}
      {tag.ai && <span className="ev-ai-badge">AI</span>}
    </span>
  );
}

function Value({ entity, children }: { entity: EntityArg | null; children: ReactNode }) {
  const nav = useNav();
  if (!entity || !nav) return <>{children}</>;
  return (
    <button type="button" className="link" title={`Open ${entity.kind} tab`} onClick={() => nav.openEntity(entity)}>
      {children}
    </button>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  );
}

interface Props {
  event: RowRef;
  onClose: () => void;
}

export default function EventDetail({ event, onClose }: Props) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [width, setWidth] = useState(420);

  useEffect(() => {
    // One panel per event (the parent keys it), so it starts empty; nothing to reset here.
    let live = true;
    eventsDetail(event.source_table, event.record_key).then(
      (d) => live && setDetail(d),
      (e: unknown) => live && setError(isCmdError(e) ? e.message : String(e)),
    );
    return () => {
      live = false;
    };
  }, [event.source_table, event.record_key]);

  // The panel is resized by dragging its left edge; the width is clamped, and the keyboard can do the same.
  const startResize = (e: React.MouseEvent) => {
    e.preventDefault();
    const x0 = e.clientX;
    const w0 = width;
    const move = (m: MouseEvent) => setWidth(Math.min(Math.max(w0 + (x0 - m.clientX), MIN_WIDTH), MAX_WIDTH));
    const up = () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  };

  const r = detail?.row;
  return (
    <aside className="ev-detail" aria-label="Event detail" style={{ width }}>
      <div
        className="ev-detail-edge"
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize detail panel"
        aria-valuemin={MIN_WIDTH}
        aria-valuemax={MAX_WIDTH}
        aria-valuenow={width}
        tabIndex={0}
        onMouseDown={startResize}
        onKeyDown={(e) => {
          if (e.key === "ArrowLeft") setWidth((w) => Math.min(w + 20, MAX_WIDTH));
          if (e.key === "ArrowRight") setWidth((w) => Math.max(w - 20, MIN_WIDTH));
        }}
      />
      <div className="ev-detail-body">
        <div className="ev-detail-head">
          <strong>{r ? displaySafe(r.operation ?? r.source) : "Event"}</strong>
          <button type="button" onClick={onClose} aria-label="Close detail">
            ×
          </button>
        </div>
        {error && <div role="alert">{displaySafe(error)}</div>}
        {!error && !detail && <p className="meta">Loading…</p>}
        {detail && r && (
          <>
            <dl className="detail-fields">
              <Field label="Time (UTC)">
                {r.event_time === null ? "—" : displaySafe(isoSeconds(r.event_time))}
                {r.time_tz_assumed ? " (zone assumed UTC)" : ""}
              </Field>
              <Field label="Source">{displaySafe(r.source)}</Field>
              <Field label="Category">{displaySafe(r.category)}</Field>
              {r.operation && <Field label="Operation">{displaySafe(r.operation)}</Field>}
              {r.result && <Field label="Result">{displaySafe(r.result)}</Field>}
              {r.actor_upn && (
                <Field label="Account">
                  <Value entity={{ kind: "account", value: r.actor_upn }}>{displaySafe(r.actor_upn)}</Value>
                </Field>
              )}
              {r.owner_upn && (
                <Field label="Mailbox owner">
                  <Value entity={{ kind: "account", value: r.owner_upn }}>{displaySafe(r.owner_upn)}</Value>
                </Field>
              )}
              {r.target && <Field label="Target">{displaySafe(r.target)}</Field>}
              {r.ip && (
                <Field label="IP">
                  <Value entity={{ kind: "ip", value: r.ip }}>{displaySafe(r.ip)}</Value>
                  {r.ip_country ? ` ${displaySafe(r.ip_country)}` : ""}
                  {r.asn !== null ? ` AS${r.asn}` : ""}
                  {r.asn_org ? ` ${displaySafe(r.asn_org)}` : ""}
                  {r.ip_kind ? ` · ${displaySafe(r.ip_kind)}` : ""}
                </Field>
              )}
              {(r.device_name ?? deviceKey(r)) && (
                <Field label="Device">
                  {(() => {
                    const id = deviceKey(r);
                    return (
                      <Value entity={id ? { kind: "device", value: id } : null}>{displaySafe(r.device_name ?? id ?? "")}</Value>
                    );
                  })()}
                </Field>
              )}
              {r.entra_session_id && (
                <Field label="Entra session">
                  <Value entity={{ kind: "session", value: r.entra_session_id }}>{displaySafe(r.entra_session_id)}</Value>
                </Field>
              )}
              {r.user_agent && <Field label="User agent">{displaySafe(r.user_agent)}</Field>}
              {r.app_id && <Field label="App">{displaySafe(r.app_id)}</Field>}
              {r.summary && <Field label="Summary">{displaySafe(r.summary)}</Field>}
              <Field label="Record">{displaySafe(`${r.source_table}:${r.record_key}`)}</Field>
            </dl>
            <h4>Flag</h4>
            {detail.flag === null ? (
              <p className="meta">Not flagged.</p>
            ) : (
              <ul className="plain">
                <li>
                  <strong>{detail.flag === "malicious" ? "Malicious" : "Suspicious"}</strong>
                </li>
                {detail.flag_sources.map((f, i) => (
                  <li key={i} className="meta">
                    {displaySafe(
                      `${f.level} · ${
                        f.origin === "row"
                          ? "set on this event"
                          : `every event with ${f.kind ?? "value"} ${f.value ?? ""}${f.scope_kind ? ` in ${f.scope_kind} ${f.scope_value ?? ""}` : ""}`
                      } · ${f.decided_by} · ${f.review_state}`,
                    )}
                  </li>
                ))}
              </ul>
            )}
            <h4>Tags</h4>
            {detail.tags.length === 0 ? (
              <p className="meta">No tags.</p>
            ) : (
              <p>
                {detail.tags.map((t) => (
                  <TagBadge key={t.name} tag={t} />
                ))}
              </p>
            )}
            <h4>Notes</h4>
            {detail.notes.length === 0 ? (
              <p className="meta">No notes.</p>
            ) : (
              <ul className="plain">
                {detail.notes.map((n) => (
                  <li key={n.annotation_id}>
                    <div className="prose">{displaySafeMultiline(n.text)}</div>
                    <div className="meta">
                      {displaySafe(`${n.actor}${n.on_behalf_of ? ` for ${n.on_behalf_of}` : ""} · ${isoSeconds(n.created_at)}`)}
                    </div>
                  </li>
                ))}
              </ul>
            )}
            <h4>Source</h4>
            {detail.source_refs.length === 0 ? (
              <p className="meta">No source reference.</p>
            ) : (
              <ul className="plain">
                {detail.source_refs.map((s) => (
                  <li key={s}>{displaySafe(s)}</li>
                ))}
              </ul>
            )}
            <details>
              <summary>Raw record</summary>
              <pre className="prose">{displaySafeMultiline(JSON.stringify(detail.raw, null, 2) ?? "")}</pre>
            </details>
          </>
        )}
      </div>
    </aside>
  );
}
