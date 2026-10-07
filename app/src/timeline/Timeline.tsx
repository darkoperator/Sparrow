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
import { displaySafe } from "../text";
import { EntryEditor, PHASES, phaseLabel } from "./EntryEditor";

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

  const reload = () => setVersion((v) => v + 1);

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

  return (
    <section aria-label="Timeline">
      <h2>Timeline</h2>
      <div>
        <label>
          <input type="checkbox" checked={clientView} onChange={(e) => setClientView(e.target.checked)} />
          Client view (verified only)
        </label>{" "}
        <label>
          <input
            type="checkbox"
            checked={showSuperseded}
            disabled={clientView}
            onChange={(e) => setShowSuperseded(e.target.checked)}
          />
          Show superseded
        </label>{" "}
        <button type="button" disabled={readOnly} onClick={() => setEditing("new")}>
          Add entry
        </button>
      </div>
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
      {entries === null && !error && <p>Loading…</p>}
      {entries !== null && groups.length === 0 && <p>No timeline entries to show.</p>}
      {groups.map((g) => (
        <section key={g.phase} aria-label={phaseLabel(g.phase)}>
          <h3>{phaseLabel(g.phase)}</h3>
          <table>
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
                <tr key={e.entry_id} data-entry={e.entry_id}>
                  <td>{displaySafe(e.event_time)}</td>
                  <td>
                    <div>{displaySafe(e.title)}</div>
                    {e.narrative && <div>{displaySafe(e.narrative)}</div>}
                  </td>
                  <td>
                    <span data-status={e.status}>{e.status}</span>
                    {e.review_state === "pending_review" && " (agent decision, pending review)"}
                  </td>
                  <td>
                    <ul>
                      {e.evidence.map((r) => (
                        <li key={`${r.source_table}:${r.record_key}`}>
                          <code>{displaySafe(`${r.source_table}:${r.record_key}`)}</code>
                        </li>
                      ))}
                    </ul>
                  </td>
                  <td>{displaySafe(e.decided_by)}</td>
                  <td>
                    {(e.status === "proposed" || e.status === "verified") && (
                      <>
                        <button
                          type="button"
                          disabled={readOnly}
                          aria-label={`Edit ${displaySafe(e.title)}`}
                          onClick={() => setEditing(e)}
                        >
                          Edit
                        </button>{" "}
                        <button
                          type="button"
                          disabled={readOnly}
                          aria-label={`Reject ${displaySafe(e.title)}`}
                          onClick={() => {
                            setRejecting(e.entry_id);
                            setReason("");
                          }}
                        >
                          Reject
                        </button>{" "}
                      </>
                    )}
                    {e.status === "proposed" && (
                      <button
                        type="button"
                        disabled={readOnly}
                        aria-label={`Verify ${displaySafe(e.title)}`}
                        onClick={() => void write(async () => void (await timelineVerify(e.entry_id)))}
                      >
                        Verify
                      </button>
                    )}
                    {rejecting === e.entry_id && (
                      <form
                        onSubmit={(ev) => {
                          ev.preventDefault();
                          if (!readOnly) void reject(e.entry_id);
                        }}
                      >
                        <label>
                          Reason for rejecting
                          <input value={reason} onChange={(ev) => setReason(ev.target.value)} />
                        </label>
                        <button type="submit" disabled={readOnly || reason.trim() === ""}>
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
        </section>
      ))}
    </section>
  );
}
