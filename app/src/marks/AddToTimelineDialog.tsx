// Add events to the timeline: events picked in the grid (one entry per event, at most 200, or one grouped entry), or
// every event a query matches (one grouped entry: an entity tab's "+ Timeline (group)"). The analyst's own entries are
// created and verified in one step by the backend. Phase blank means "from the events' categories".
import { useState } from "react";
import { EACH_MAX, isCmdError, timelineAddEvents, type AddEventsArgs, type EventQuery, type RowRef } from "../api";
import { displaySafe } from "../text";
import { PHASES, phaseLabel } from "../timeline/EntryEditor";

export default function AddToTimelineDialog({
  rows,
  query,
  count,
  defaultTitle = "",
  onDone,
  onClose,
}: {
  /** The events picked in the grid. Exactly one of `rows` and `query`. */
  rows?: RowRef[];
  /** Every event this query matches, as one grouped entry; `count` is how many (null when not known). */
  query?: EventQuery;
  count?: number | null;
  /** Offered in the title box (the caller knows the event); blank leaves the title to the backend. */
  defaultTitle?: string;
  onDone: (outcome: string) => void;
  onClose: () => void;
}) {
  const n = rows ? rows.length : (count ?? 0);
  const eachBlocked = n > EACH_MAX ? `One entry per event is limited to ${EACH_MAX}; ${n} are selected` : undefined;
  const [mode, setMode] = useState<"each" | "group">(query === undefined && eachBlocked === undefined ? "each" : "group");
  const [title, setTitle] = useState(defaultTitle);
  const [phase, setPhase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const args: AddEventsArgs = query ? { query, mode: "group" } : { rows, mode };
      if (title.trim() !== "") args.title = title.trim();
      if (phase !== "") args.phase = phase;
      onDone((await timelineAddEvents(args)).outcome);
    } catch (e) {
      setError(isCmdError(e) ? e.message : String(e));
      setBusy(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Add to timeline"
      className="entity-dialog mark-dialog"
      onKeyDown={(e) => {
        if (e.key === "Escape") onClose();
      }}
    >
      <h4>
        Add {query ? (count === null || count === undefined ? "these events" : `${count} events`) : n === 1 ? "this event" : `${n} events`} to the
        timeline{query ? " as one entry" : ""}
      </h4>
      {query === undefined && n > 1 && (
        <fieldset>
          <legend>Entries</legend>
          <label>
            <input
              type="radio"
              name="timeline-mode"
              checked={mode === "each"}
              disabled={eachBlocked !== undefined}
              title={eachBlocked}
              onChange={() => setMode("each")}
            />{" "}
            One entry per event (max {EACH_MAX})
          </label>
          {eachBlocked && <span className="meta">{eachBlocked}</span>}
          <label>
            <input type="radio" name="timeline-mode" checked={mode === "group"} onChange={() => setMode("group")} /> One grouped entry
          </label>
        </fieldset>
      )}
      <label>
        Title
        <input autoFocus value={title} placeholder="Leave blank to describe the events" onChange={(e) => setTitle(e.target.value)} />
      </label>
      <label>
        Phase
        <select value={phase} onChange={(e) => setPhase(e.target.value)}>
          <option value="">Choose from the events</option>
          {PHASES.map((p) => (
            <option key={p} value={p}>
              {phaseLabel(p)}
            </option>
          ))}
        </select>
      </label>
      {error && <p role="alert">{displaySafe(error)}</p>}
      <div className="entity-dialog-buttons">
        <button type="button" disabled={busy} onClick={() => void submit()}>
          Add to timeline
        </button>
        <button type="button" onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}
