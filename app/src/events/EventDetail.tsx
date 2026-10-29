// The panel beside the grid for one event: its main fields, the flag and where it comes from, tags, notes, the
// source file and line, and the raw record (collapsed). Account, IP, device and session values open entity tabs.
// Everything is rendered as text.
import { useEffect, useId, useState, type ReactNode } from "react";
import {
  eventsDetail,
  isCmdError,
  marksFlagRows,
  marksFlagValue,
  marksTagRows,
  type EntityArg,
  type EntityKind,
  type EventDetail as Detail,
  type FlagLevel,
  type FlagSource,
  type RowRef,
  type TagRef,
  type ValueKind,
} from "../api";
import AddToTimelineDialog from "../marks/AddToTimelineDialog";
import NoteDialog from "../marks/NoteDialog";
import { useNav } from "../shell/nav";
import { displaySafe, displaySafeMultiline } from "../text";
import Icon, { type IconName } from "../ui/Icon";
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

function Value({ entity, full, describedBy, children }: { entity: EntityArg | null; full: string; describedBy: string; children: ReactNode }) {
  const nav = useNav();
  if (!entity || !nav) return <span title={full}>{children}</span>;
  return (
    <button type="button" className="link" title={`${full} — open ${entity.kind} tab`} aria-describedby={describedBy} onClick={() => nav.openEntity(entity)}>
      {children}
    </button>
  );
}

interface TabRow {
  label: string;
  icon: IconName;
  value: string;
  meta?: string;
  entity: EntityArg | null;
}

/** Pretty-printed JSON with the key, string, number and keyword colours; every piece stays a text node. */
const JSON_TOKEN = /("(?:[^"\\\n]|\\.)*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b/g;
function JsonText({ text }: { text: string }) {
  const out: ReactNode[] = [];
  let at = 0;
  for (const m of text.matchAll(JSON_TOKEN)) {
    const i = m.index ?? 0;
    if (i > at) out.push(text.slice(at, i));
    const cls = m[1] !== undefined ? (m[2] !== undefined ? "syn-key" : "syn-str") : m[3] !== undefined ? "syn-num" : "syn-kw";
    out.push(
      <span key={i} className={cls}>
        {m[1] !== undefined ? m[1] : m[0]}
      </span>,
    );
    if (m[2] !== undefined) out.push(m[2]);
    at = i + m[0].length;
  }
  if (at < text.length) out.push(text.slice(at));
  return <>{out}</>;
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
  /** Why the analyst cannot write (a read-only case, or no analyst name), or null. */
  readOnly?: string | null;
  /** The case's tag names, offered when adding one. */
  tagNames?: string[];
  /** Changes when something was written elsewhere: the panel reads the event again, keeping what it shows meanwhile. */
  version?: number;
  /** Something was written here: the host reloads its grid and says `message`. */
  onChanged?: (message: string) => void;
}

const KINDS: readonly string[] = ["ip", "ip_prefix", "account", "asn", "device", "session"];
const ENTITY_KINDS: readonly string[] = ["account", "ip", "device", "session"];

/** Where a standing flag stops, when it was made inside an entity tab. */
function scopeOf(f: FlagSource): { kind: EntityKind; value: string } | null {
  return f.scope_kind && f.scope_value && ENTITY_KINDS.includes(f.scope_kind) ? { kind: f.scope_kind as EntityKind, value: f.scope_value } : null;
}

export default function EventDetail({ event, onClose, readOnly = null, tagNames = [], version = 0, onChanged }: Props) {
  const panelId = useId();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [width, setWidth] = useState(420);
  const [dialog, setDialog] = useState<"note" | "timeline" | null>(null);
  const [writeError, setWriteError] = useState<string | null>(null);
  const [newTag, setNewTag] = useState("");

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
  }, [event.source_table, event.record_key, version]);

  const write = async (job: () => Promise<unknown>, message: string) => {
    setWriteError(null);
    try {
      await job();
      onChanged?.(message);
    } catch (e) {
      setWriteError(isCmdError(e) ? e.message : String(e));
    }
  };
  const setFlag = (level: FlagLevel | null) =>
    write(() => marksFlagRows([event], level), level === null ? "Flag cleared" : `Flagged ${level}`);
  const clearSource = (f: FlagSource) =>
    f.origin === "row" || !f.kind || !f.value || !KINDS.includes(f.kind)
      ? setFlag(null)
      : write(() => marksFlagValue(f.kind as ValueKind, f.value!, scopeOf(f), null), `Cleared the flag on ${f.kind} ${f.value}`);
  const off = readOnly ?? undefined;

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
  const eventTitle = r ? [r.operation ?? r.source, r.actor_upn ? `by ${r.actor_upn}` : null, r.ip ? `from ${r.ip}` : null].filter(Boolean).join(" ") : "";
  const tabRows: TabRow[] = [];
  if (r) {
    if (r.actor_upn) tabRows.push({ label: "Account", icon: "user", value: r.actor_upn, entity: { kind: "account", value: r.actor_upn } });
    if (r.owner_upn) tabRows.push({ label: "Mailbox owner", icon: "user", value: r.owner_upn, entity: { kind: "account", value: r.owner_upn } });
    if (r.ip) {
      const where = [r.ip_country, r.asn !== null ? `AS${r.asn}` : null, r.asn_org, r.ip_kind].filter((x): x is string => !!x).map(displaySafe).join(" · ");
      tabRows.push({ label: "IP", icon: "globe", value: r.ip, meta: where, entity: { kind: "ip", value: r.ip } });
    }
    const dev = deviceKey(r);
    if (r.device_name ?? dev) tabRows.push({ label: "Device", icon: "monitor", value: r.device_name ?? dev ?? "", entity: dev ? { kind: "device", value: dev } : null });
    if (r.entra_session_id) tabRows.push({ label: "Entra session", icon: "key", value: r.entra_session_id, entity: { kind: "session", value: r.entra_session_id } });
  }
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
          <span className="label">Event detail</span>
          <button type="button" className="ev-close" onClick={onClose} aria-label="Close detail">
            <Icon name="x" size={16} />
          </button>
        </div>
        <h3 className="ev-detail-title">{r ? displaySafe(r.operation ?? r.source) : "Event"}</h3>
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
              {r.target && <Field label="Target">{displaySafe(r.target)}</Field>}
              {r.user_agent && <Field label="User agent">{displaySafe(r.user_agent)}</Field>}
              {r.app_id && <Field label="App">{displaySafe(r.app_id)}</Field>}
              {r.summary && <Field label="Summary">{displaySafe(r.summary)}</Field>}
              <Field label="Record">{displaySafe(`${r.source_table}:${r.record_key}`)}</Field>
            </dl>
            {tabRows.length > 0 && (
              <section aria-label="Open a tab" className="ev-tabs">
                <div className="label">Open a tab</div>
                {tabRows.map((t, i) => (
                  <div key={`${t.label}:${t.value}`} className="ev-tabrow">
                    <Icon name={t.icon} size={14} />
                    <span id={`${panelId}-tab-${i}`} className="ev-tablabel">
                      {t.label}
                    </span>
                    <Value entity={t.entity} full={displaySafe(t.value)} describedBy={`${panelId}-tab-${i}`}>
                      {displaySafe(t.value)}
                    </Value>
                    {t.meta && <span className="ev-tabmeta">{t.meta}</span>}
                    {t.entity && <Icon name="external" size={13} />}
                  </div>
                ))}
              </section>
            )}
            {writeError && <div role="alert">{displaySafe(writeError)}</div>}
            <h4 className="label">Flag</h4>
            {detail.flag === null ? (
              <p className="meta">Not flagged.</p>
            ) : (
              <ul className="plain">
                <li>
                  <strong className={detail.flag === "malicious" ? "pill pill-mal" : "pill pill-sus"}>
                    {detail.flag === "malicious" ? "Malicious" : "Suspicious"}
                  </strong>
                </li>
                {detail.flag_sources.map((f, i) => (
                  <li key={i} className="ev-detail-flag">
                    <span className="meta">
                      {displaySafe(
                        `${f.level} · ${
                          f.origin === "row"
                            ? "set on this event"
                            : `every event with ${f.kind ?? "value"} ${f.value ?? ""}${f.scope_kind ? ` in ${f.scope_kind} ${f.scope_value ?? ""}` : ""}, incl. later imports`
                        } · ${f.decided_by} · ${f.review_state}`,
                      )}
                    </span>
                    <button
                      type="button"
                      disabled={readOnly !== null}
                      title={off ?? (f.origin === "row" ? "Clear the flag set on this event" : "Clear this flag from every event it covers; flags set on single events stay")}
                      onClick={() => void clearSource(f)}
                    >
                      {f.origin === "row" ? "Clear" : "Clear for all"}
                    </button>
                  </li>
                ))}
              </ul>
            )}
            <div className="ev-detail-actions" role="group" aria-label="Flag this event">
              <button type="button" disabled={readOnly !== null} title={off} onClick={() => void setFlag("suspicious")}>
                Flag suspicious
              </button>
              <button type="button" disabled={readOnly !== null} title={off} onClick={() => void setFlag("malicious")}>
                Flag malicious
              </button>
            </div>
            <h4 className="label">Tags</h4>
            {detail.tags.length === 0 ? (
              <p className="meta">No tags.</p>
            ) : (
              <p>
                {detail.tags.map((t) => (
                  <span key={t.name}>
                    <TagBadge tag={t} />
                    <button
                      type="button"
                      className="link"
                      aria-label={`Remove tag ${displaySafe(t.name)}`}
                      disabled={readOnly !== null}
                      title={off ?? "Remove this tag from the event"}
                      onClick={() => void write(() => marksTagRows([event], t.name, false), `Removed tag ${t.name}`)}
                    >
                      ×
                    </button>
                  </span>
                ))}
              </p>
            )}
            <form
              className="ev-detail-actions"
              onSubmit={(e) => {
                e.preventDefault();
                const name = newTag.trim();
                if (name === "") return;
                setNewTag("");
                void write(() => marksTagRows([event], name, true), `Tagged ${name}`);
              }}
            >
              <input
                aria-label="New tag"
                list="detail-tag-names"
                value={newTag}
                disabled={readOnly !== null}
                title={off}
                onChange={(e) => setNewTag(e.target.value)}
              />
              <datalist id="detail-tag-names">
                {tagNames.map((t) => (
                  <option key={t} value={t} />
                ))}
              </datalist>
              <button type="submit" disabled={readOnly !== null || newTag.trim() === ""} title={off}>
                Add tag
              </button>
            </form>
            <h4 className="label">Notes</h4>
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
            <h4 className="label">Source</h4>
            {detail.source_refs.length === 0 ? (
              <p className="meta">No source reference.</p>
            ) : (
              <ul className="plain">
                {detail.source_refs.map((s) => (
                  <li key={s}>{displaySafe(s)}</li>
                ))}
              </ul>
            )}
            <details className="ev-raw">
              <summary className="label">Raw record</summary>
              <pre className="prose">
                <JsonText text={displaySafeMultiline(JSON.stringify(detail.raw, null, 2) ?? "")} />
              </pre>
            </details>
          </>
        )}
      </div>
      {detail && r && (
        <div className="ev-detail-foot">
          <button type="button" className="btn" disabled={readOnly !== null} title={off} onClick={() => setDialog("note")}>
            <Icon name="note" size={13} />
            Add note…
          </button>
          <button type="button" className="btn btn-primary" disabled={readOnly !== null} title={off} onClick={() => setDialog("timeline")}>
            <Icon name="plus" size={13} />
            Add to timeline…
          </button>
        </div>
      )}
      {dialog === "note" && (
        <NoteDialog
          rows={[event]}
          onClose={() => setDialog(null)}
          onDone={(m) => {
            setDialog(null);
            onChanged?.(m);
          }}
        />
      )}
      {dialog === "timeline" && (
        <AddToTimelineDialog
          rows={[event]}
          defaultTitle={eventTitle}
          onClose={() => setDialog(null)}
          onDone={(m) => {
            setDialog(null);
            onChanged?.(m);
          }}
        />
      )}
    </aside>
  );
}
