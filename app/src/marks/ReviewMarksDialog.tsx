// Confirm or remove the agent marks pending on the ticked events. Reviewing also reviews every pending standing flag
// on a value that covers any of them, which changes every event that flag covers: the dialog finds those flags first
// (from each flagged event's detail) and says so before the analyst decides.
import { useEffect, useState } from "react";
import { eventsDetail, isCmdError, marksReview, type EventRow, type FlagSource, type RowRef } from "../api";
import { displaySafe } from "../text";

/** Events whose detail is read to find value flags; past this the warning is general. */
export const SCAN_MAX = 50;

/** `every event with ip 192.0.2.5 in account jdoe@…` */
export function describeValueFlag(f: FlagSource): string {
  const scope = f.scope_kind ? ` in ${f.scope_kind} ${f.scope_value ?? ""}` : "";
  return `every event with ${f.kind ?? "value"} ${f.value ?? ""}${scope}`;
}

export default function ReviewMarksDialog({
  accept,
  rows,
  onDone,
  onClose,
}: {
  accept: boolean;
  /** The ticked events with an agent mark waiting for review (`ai_pending`). */
  rows: EventRow[];
  onDone: (message: string) => void;
  onClose: () => void;
}) {
  // Any of them may be covered by an agent's standing flag, even one hidden under a stronger confirmed flag.
  const flagged = rows;
  const scan = flagged.slice(0, SCAN_MAX);
  const [found, setFound] = useState<string[] | null>(scan.length === 0 ? [] : null);
  const [scanFailed, setScanFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (scan.length === 0) return;
    let live = true;
    Promise.all(scan.map((r) => eventsDetail(r.source_table, r.record_key))).then(
      (details) => {
        if (!live) return;
        const all = details.flatMap((d) => d.flag_sources.filter((f) => f.origin === "value" && f.review_state.startsWith("pending")));
        setFound([...new Set(all.map(describeValueFlag))]);
      },
      () => {
        if (!live) return;
        setScanFailed(true);
        setFound([]);
      },
    );
    return () => {
      live = false;
    };
    // The dialog is opened for one selection; it is remounted for another.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const verb = accept ? "Confirm" : "Remove";
  const n = rows.length;
  const submit = async () => {
    setBusy(true);
    setError(null);
    const refs: RowRef[] = rows.map((r) => ({ source_table: r.source_table, record_key: r.record_key }));
    try {
      const done = await marksReview(refs, accept);
      onDone(
        done.length === 0
          ? "No AI marks were waiting on those events"
          : `${accept ? "Confirmed" : "Removed"} the AI marks on ${n === 1 ? "1 event" : `${n} events`}`,
      );
    } catch (e) {
      setError(isCmdError(e) ? e.message : String(e));
      setBusy(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`${verb} AI marks`}
      className="entity-dialog mark-dialog"
      onKeyDown={(e) => {
        if (e.key === "Escape") onClose();
      }}
    >
      <h4>
        {verb} the AI marks on {n === 1 ? "this event" : `${n} events`}?
      </h4>
      <p>
        {accept
          ? "The flags and tags an agent added become yours, confirmed."
          : "The flags and tags an agent added are taken off. Where an agent's flag replaced an earlier one, the earlier one comes back."}
      </p>
      {found === null && <p className="meta">Checking for flags on values…</p>}
      {found !== null && (found.length > 0 || scanFailed || flagged.length > SCAN_MAX) && (
        <div role="alert">
          <strong>This reaches beyond the ticked events.</strong> An agent flagged a value, and {accept ? "confirming" : "removing"} that flag
          changes every event it covers, not only the ticked ones:
          {found.length > 0 && (
            <ul>
              {found.map((f) => (
                <li key={f}>{displaySafe(f)}</li>
              ))}
            </ul>
          )}
          {(scanFailed || flagged.length > SCAN_MAX) && (
            <p>
              {scanFailed ? "The flags could not be listed." : `Only the first ${SCAN_MAX} events were checked.`} Other events with a value
              flagged by an agent may be affected too.
            </p>
          )}
        </div>
      )}
      {error && <p role="alert">{displaySafe(error)}</p>}
      <div className="entity-dialog-buttons">
        <button type="button" disabled={busy || found === null} onClick={() => void submit()}>
          {verb} AI marks
        </button>
        <button type="button" onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}
