import { useState } from "react";
import { findingDetail, isCmdError, type EvidenceRow } from "../api";
import { displaySafe } from "../text";

/** Adds `<table>:<record_key>` references taken from the evidence rows of a finding. */
export function EvidencePicker({ existing, onAdd }: { existing: string[]; onAdd: (ref: string) => void }) {
  const [findingId, setFindingId] = useState("");
  const [rows, setRows] = useState<EvidenceRow[] | null>(null);
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setError(null);
    try {
      const d = await findingDetail(findingId.trim());
      setRows(d.evidence);
      setTitle(d.finding.title);
    } catch (e) {
      setRows(null);
      setError(isCmdError(e) ? e.message : String(e));
    }
  }

  return (
    <fieldset>
      <legend>Evidence from a finding</legend>
      <label>
        Finding id
        <input value={findingId} onChange={(e) => setFindingId(e.target.value)} />
      </label>
      <button type="button" onClick={() => void load()} disabled={findingId.trim() === ""}>
        Load evidence
      </button>
      {error && <p role="alert">{displaySafe(error)}</p>}
      {rows && (
        <>
          <p>{displaySafe(title)}</p>
          {rows.length === 0 && <p>This finding has no evidence rows.</p>}
          <ul className="tl-refs">
            {rows.map((r) => {
              const ref = `${r.source_table}:${r.record_key}`;
              return (
                <li key={ref}>
                  <code title={displaySafe(ref)}>{displaySafe(ref)}</code> {displaySafe(r.role)}
                  {r.event_time ? ` ${displaySafe(r.event_time)}` : ""}{" "}
                  <button
                    type="button"
                    className="btn btn-ghost"
                    aria-label={`Add ${displaySafe(ref)}`}
                    disabled={existing.includes(ref)}
                    onClick={() => onAdd(ref)}
                  >
                    {existing.includes(ref) ? "Added" : "Add"}
                  </button>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </fieldset>
  );
}
