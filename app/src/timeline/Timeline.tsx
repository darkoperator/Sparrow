import { useEffect, useState } from "react";
import {
  isCmdError,
  timelineEdit,
  timelineList,
  timelinePropose,
  timelineReject,
  timelineVerify,
  type EntryEditArgs,
  type NewEntryArgs,
  type TimelineEntry,
} from "../api";
import { useRefreshBadges } from "../shell/nav";
import { displaySafe } from "../text";
import Icon from "../ui/Icon";
import { EntryEditor, PHASES, phaseLabel } from "./EntryEditor";
import "./timeline.css";

/** The status pill's colour; the status text is always shown in it. An agent's pending decision is AI-violet. */
function statusTone(e: TimelineEntry): string {
  if (e.review_state === "pending_review") return "ai";
  const tones: Record<string, string> = { verified: "ok", proposed: "proposed", rejected: "mal" };
  return tones[e.status] ?? "muted";
}

const count = new Intl.NumberFormat("en-US");

type Editing = TimelineEntry | "new" | null;

/**
 * The timeline screen: entries grouped by phase, in time order, with the analyst's add / edit / verify / reject.
 * Self-contained (loads its own entries); the shell passes `readOnly` for a case that opened read-only.
 */
export function Timeline({ readOnly = false }: { readOnly?: boolean }) {
  const [entries, setEntries] = useState<TimelineEntry[] | null>(null);
  const [version, setVersion] = useState(0);
  const [clientView, setClientView] = useState(false);
  const [showSuperseded, setShowSuperseded] = useState(false);
  const [editing, setEditing] = useState<Editing>(null);
  const [rejecting, setRejecting] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    timelineList().then(
      (list) => {
        if (live) setEntries(list);
      },
      (e: unknown) => {
        if (live) setError(isCmdError(e) ? e.message : String(e));
      },
    );
    return () => {
      live = false;
    };
  }, [version]);

  const refreshBadges = useRefreshBadges();
  const reload = () => {
    setVersion((v) => v + 1);
    refreshBadges();
  };

  /**
   * Runs a write; a refusal is shown and the entries reloaded (what the analyst saw may have changed). Returns null
   * on success, else the refusal's kind.
   */
  async function write(action: () => Promise<string | void>): Promise<string | null> {
    setError(null);
    setNotice(null);
    try {
      const msg = await action();
      if (msg) setNotice(msg);
      reload();
      return null;
    } catch (e) {
      setError(isCmdError(e) ? e.message : String(e));
      reload();
      return isCmdError(e) ? e.kind : "internal";
    }
  }

  async function save(args: NewEntryArgs | EntryEditArgs) {
    const target = editing;
    const failed = await write(async () => {
      if (target === "new") {
        await timelinePropose(args as NewEntryArgs);
      } else if (target) {
        const res = await timelineEdit(target.entry_id, args as EntryEditArgs);
        if (res.entryId !== target.entry_id) {
          return `Saved as a new proposed entry ${res.entryId}; it replaces ${target.entry_id} once verified.`;
        }
      }
    });
    // A core refusal (the entry changed, or has a pending agent decision) closes the form: the reloaded table is
    // the truth and a retry starts from it. A malformed argument keeps the form open for correction.
    if (failed === null || failed === "decision") setEditing(null);
  }

  async function reject(id: string) {
    const failed = await write(async () => {
      await timelineReject(id, reason);
    });
    if (failed === null) {
      setRejecting(null);
      setReason("");
    }
  }

  const visible = (entries ?? []).filter((e) => {
    if (clientView) return e.status === "verified";
    return showSuperseded || e.status !== "superseded";
  });
  // Core's timestamps are fixed-width UTC text, so text order is time order; the entry id breaks ties.
  const byTime = (a: TimelineEntry, b: TimelineEntry) =>
    a.event_time < b.event_time ? -1 : a.event_time > b.event_time ? 1 : a.entry_id < b.entry_id ? -1 : 1;
  const groups = PHASES.map((p) => ({
    phase: p,
    entries: visible.filter((e) => e.phase === p).sort(byTime),
  })).filter((g) => g.entries.length > 0);

  // The header's summary and the phase rail describe the entries on screen (after the view toggles).
  const verified = visible.filter((e) => e.status === "verified").length;
  const proposed = visible.filter((e) => e.status === "proposed").length;
  const agent = visible.filter((e) => e.review_state === "pending_review").length;
  const starts = visible.map((e) => e.event_time).sort();
  const ends = visible.map((e) => e.end_time ?? e.event_time).sort();

  return (
    <section aria-label="Timeline" className="timeline">
      <div className="tl-head">
        <div className="tl-heading">
          <h2>Timeline</h2>
          {entries !== null && (
            <p className="tl-summary">
              {`${visible.length} ${visible.length === 1 ? "entry" : "entries"} · ${verified} verified · ${proposed} proposed`}
              {agent > 0 && ` · ${agent} pending agent review`}
              {starts.length > 0 && (
                <>
                  {" · "}
                  <span className="mono">{displaySafe(`${starts[0]} → ${ends[ends.length - 1]}`)}</span>
                </>
              )}
            </p>
          )}
        </div>
        <div className="tl-controls">
          <label className="tl-toggle">
            <input type="checkbox" checked={clientView} onChange={(e) => setClientView(e.target.checked)} />
            Client view (verified only)
          </label>
          <label className="tl-toggle">
            <input
              type="checkbox"
              checked={showSuperseded}
              disabled={clientView}
              onChange={(e) => setShowSuperseded(e.target.checked)}
            />
            Show superseded
          </label>
          <button type="button" className="btn btn-primary" disabled={readOnly} onClick={() => setEditing("new")}>
            <Icon name="plus" size={13} />
            Add entry
          </button>
        </div>
      </div>
      {groups.length > 0 && (
        <ol className="tl-rail" aria-label="Phases">
          {groups.map((g) => (
            <li key={g.phase} className={`tl-phase-${g.phase}`} style={{ flexGrow: g.entries.length }}>
              {`${phaseLabel(g.phase)} · ${g.entries.length}`}
            </li>
          ))}
        </ol>
      )}
      {error && <p role="alert">{displaySafe(error)}</p>}
      {notice && <p role="status">{displaySafe(notice)}</p>}
      {editing && (
        <EntryEditor
          key={editing === "new" ? "new" : editing.entry_id}
          {...(editing === "new"
            ? { onSubmit: save }
            : { entry: editing, onSubmit: save })}
          readOnly={readOnly}
          onCancel={() => setEditing(null)}
        />
      )}
      {entries === null && !error && <p className="tl-empty">Loading…</p>}
      {entries !== null && groups.length === 0 && <p className="tl-empty">No timeline entries to show.</p>}
      {groups.map((g) => (
        <section key={g.phase} aria-label={phaseLabel(g.phase)} className="tl-group">
          <h3>
            <span className={`tl-phase tl-phase-${g.phase}`}>{phaseLabel(g.phase)}</span>
          </h3>
          <div className="table-scroll">
          <table className="tl-table">
            <thead>
              <tr>
                <th>Time (UTC)</th>
                <th>Title</th>
                <th>Status</th>
                <th>Evidence</th>
                <th>Decided by</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {g.entries.map((e) => (
                <tr
                  key={e.entry_id}
                  data-entry={e.entry_id}
                  className={e.review_state === "pending_review" ? "tl-row-agent" : undefined}
                >
                  <td className="tl-time">
                    <div>{displaySafe(e.event_time)}</div>
                    {e.end_time && <div className="tl-end">{displaySafe(`→ ${e.end_time}`)}</div>}
                  </td>
                  <td className="tl-title">
                    <div>{displaySafe(e.title)}</div>
                    {e.narrative && (
                      <div className="tl-sub" title={displaySafe(e.narrative)}>
                        {displaySafe(e.narrative)}
                      </div>
                    )}
                  </td>
                  <td>
                    <span data-status={e.status} className={`pill tl-status tl-status-${statusTone(e)}`}>
                      {e.status}
                    </span>
                    {e.review_state === "pending_review" && (
                      <span className="tl-agent">{" (agent decision, pending review)"}</span>
                    )}
                  </td>
                  <td className="tl-evidence">
                    {e.event_count !== null && (
                      <div className="tl-count">{`${count.format(e.event_count)} ${e.event_count === 1 ? "event" : "events"}`}</div>
                    )}
                    <ul>
                      {e.evidence.map((r) => (
                        <li key={`${r.source_table}:${r.record_key}`} title={displaySafe(`${r.source_table}:${r.record_key}`)}>
                          <code>{displaySafe(`${r.source_table}:${r.record_key}`)}</code>
                        </li>
                      ))}
                    </ul>
                  </td>
                  <td className="tl-by" title={displaySafe(e.decided_by)}>
                    {displaySafe(e.decided_by)}
                  </td>
                  <td className="tl-actions">
                    {(e.status === "proposed" || e.status === "verified") && (
                      <>
                        <button
                          type="button"
                          className="btn btn-ghost"
                          disabled={readOnly}
                          aria-label={`Edit ${displaySafe(e.title)}`}
                          onClick={() => setEditing(e)}
                        >
                          Edit
                        </button>{" "}
                        <button
                          type="button"
                          className="btn btn-ghost tl-reject"
                          disabled={readOnly}
                          aria-label={`Reject ${displaySafe(e.title)}`}
                          onClick={() => {
                            setRejecting(e.entry_id);
                            setReason("");
                          }}
                        >
                          <Icon name="x" size={12} />
                          Reject
                        </button>{" "}
                      </>
                    )}
                    {e.status === "proposed" && (
                      <button
                        type="button"
                        className="btn btn-ghost tl-verify"
                        disabled={readOnly}
                        aria-label={`Verify ${displaySafe(e.title)}`}
                        onClick={() => void write(async () => void (await timelineVerify(e.entry_id)))}
                      >
                        <Icon name="check" size={12} />
                        Verify
                      </button>
                    )}
                    {rejecting === e.entry_id && (
                      <form
                        className="tl-reject-form"
                        onSubmit={(ev) => {
                          ev.preventDefault();
                          if (!readOnly) void reject(e.entry_id);
                        }}
                      >
                        <label>
                          Reason for rejecting
                          <input value={reason} onChange={(ev) => setReason(ev.target.value)} />
                        </label>
                        <button type="submit" className="btn btn-primary" disabled={readOnly || reason.trim() === ""}>
                          Confirm reject
                        </button>
                        <button type="button" onClick={() => setRejecting(null)}>
                          Cancel
                        </button>
                      </form>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </section>
      ))}
    </section>
  );
}
