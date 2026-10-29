// Add one note to each of the given events (`annotations`, append-only). The backend takes at most 200 rows.
import { useState } from "react";
import { isCmdError, notesAddRows, type RowRef } from "../api";
import { displaySafe } from "../text";

export default function NoteDialog({
  rows,
  onDone,
  onClose,
}: {
  rows: RowRef[];
  /** The note was added; the text is for the confirmation. */
  onDone: (message: string) => void;
  onClose: () => void;
}) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await notesAddRows(rows, text.trim());
      onDone(rows.length === 1 ? "Note added" : `Note added to ${rows.length} events`);
    } catch (e) {
      setError(isCmdError(e) ? e.message : String(e));
      setBusy(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Add note"
      className="entity-dialog mark-dialog"
      onKeyDown={(e) => {
        if (e.key === "Escape") onClose();
      }}
    >
      <h4>{rows.length === 1 ? "Add a note to this event" : `Add the same note to ${rows.length} events`}</h4>
      <label>
        Note
        <textarea autoFocus value={text} onChange={(e) => setText(e.target.value)} />
      </label>
      {error && <p role="alert">{displaySafe(error)}</p>}
      <div className="entity-dialog-buttons">
        <button type="button" disabled={busy || text.trim() === ""} onClick={() => void submit()}>
          Add note
        </button>
        <button type="button" onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}
