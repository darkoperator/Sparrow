import { useState } from "react";
import { isCmdError, settingsSetAnalyst, type Settings } from "../api";
import { displaySafe } from "../text";

/** Asks for the analyst's name once; it is stored in the app settings and sent with every write. */
export default function AnalystPrompt({ onSaved }: { onSaved: (s: Settings) => void }) {
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    try {
      onSaved(await settingsSetAnalyst(name.trim()));
      setError(null);
    } catch (e) {
      setError(isCmdError(e) ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="banner analyst-prompt"
      onSubmit={(ev) => {
        ev.preventDefault();
        void save();
      }}
    >
      <label>
        Analyst name <input value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" />
      </label>{" "}
      <button type="submit" disabled={busy || name.trim() === ""}>
        Save name
      </button>
      <span> Decisions you make are recorded under this name; set it before you accept or discard anything.</span>
      {error && <div role="alert">{displaySafe(error)}</div>}
    </form>
  );
}
