import { useState } from "react";
import type { EntryEditArgs, NewEntryArgs, TimelineEntry } from "../api";
import { displaySafe } from "../text";
import { EvidencePicker } from "./EvidencePicker";

export const PHASES = [
  "initial_access",
  "persistence",
  "defense_evasion",
  "recon",
  "collection",
  "exfiltration",
  "impact",
  "remediation",
] as const;

export const phaseLabel = (p: string) => p.replace(/_/g, " ");

/** Whether `displaySafe` would change the text, ignoring the newlines an ordinary narrative has. */
function hidden(s: string, allowNewlines: boolean) {
  const t = allowNewlines ? s.replace(/\n/g, "") : s;
  return displaySafe(t) !== t;
}

function sameList(a: string[], b: string[]) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

const refText = (r: { source_table: string; record_key: string }) => `${r.source_table}:${r.record_key}`;

type Props = { readOnly?: boolean; onCancel: () => void } & (
  | { entry: TimelineEntry; onSubmit: (args: EntryEditArgs) => void | Promise<void> }
  | { entry?: undefined; onSubmit: (args: NewEntryArgs) => void | Promise<void> }
);

function HiddenNotice({ what, onReplace }: { what: string; onReplace: () => void }) {
  return (
    <p role="note">
      This {what} contains hidden control or direction characters, shown escaped.{" "}
      <button type="button" aria-label={`Replace ${what}`} onClick={onReplace}>
        Replace
      </button>
    </p>
  );
}

/** The add / edit form. An edit sends only the fields the analyst changed. Times are UTC, RFC 3339. */
export function EntryEditor(props: Props) {
  const { entry, readOnly, onCancel } = props;
  const original = entry?.evidence.map(refText) ?? [];
  const [time, setTime] = useState(entry?.event_time ?? "");
  const [title, setTitle] = useState(entry?.title ?? "");
  const [narrative, setNarrative] = useState(entry?.narrative ?? "");
  const [phase, setPhase] = useState(entry?.phase ?? "initial_access");
  const [evidence, setEvidence] = useState<string[]>(original);
  const [manual, setManual] = useState("");
  const [busy, setBusy] = useState(false);
  // A stored value with hidden control or direction characters is never put in an editable field (the escaped form
  // would be saved back as literal text): it is shown escaped, read-only, until the analyst replaces it.
  const [titleReplaced, setTitleReplaced] = useState(false);
  const [narrativeReplaced, setNarrativeReplaced] = useState(false);
  const titleLocked = !!entry && !titleReplaced && hidden(entry.title, false);
  const narrativeLocked = !!entry && !narrativeReplaced && hidden(entry.narrative ?? "", true);

  const addRef = (ref: string) => setEvidence((cur) => (cur.includes(ref) ? cur : [...cur, ref]));

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      if (props.entry) {
        const args: EntryEditArgs = {};
        if (time !== props.entry.event_time) args.eventTime = time;
        if (title !== props.entry.title) args.title = title;
        if (narrative !== (props.entry.narrative ?? "")) args.narrative = narrative === "" ? null : narrative;
        if (phase !== props.entry.phase) args.phase = phase;
        if (!sameList(evidence, original)) args.evidence = evidence;
        await props.onSubmit(args);
      } else {
        await props.onSubmit({
          eventTime: time,
          title,
          narrative: narrative === "" ? null : narrative,
          phase,
          evidence,
        });
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} aria-label={entry ? "Edit entry" : "Add entry"}>
      <h3>{entry ? "Edit entry" : "Add entry"}</h3>
      {entry?.status === "verified" && (
        <p>This entry is verified. Saving creates a proposed successor that replaces it once it is verified.</p>
      )}
      <label>
        Time (UTC, RFC 3339)
        <input value={time} placeholder="2026-03-01T10:00:00Z" onChange={(e) => setTime(e.target.value)} />
      </label>
      <label>
        Title
        {titleLocked ? (
          <input value={displaySafe(title)} readOnly />
        ) : (
          <input value={title} onChange={(e) => setTitle(e.target.value)} />
        )}
      </label>
      {titleLocked && (
        <HiddenNotice
          onReplace={() => {
            setTitle("");
            setTitleReplaced(true);
          }}
          what="title"
        />
      )}
      <label>
        Narrative
        {narrativeLocked ? (
          <textarea value={displaySafe(narrative)} readOnly />
        ) : (
          <textarea value={narrative} onChange={(e) => setNarrative(e.target.value)} />
        )}
      </label>
      {narrativeLocked && (
        <HiddenNotice
          onReplace={() => {
            setNarrative("");
            setNarrativeReplaced(true);
          }}
          what="narrative"
        />
      )}
      <label>
        Phase
        <select value={phase} onChange={(e) => setPhase(e.target.value)}>
          {PHASES.map((p) => (
            <option key={p} value={p}>
              {phaseLabel(p)}
            </option>
          ))}
        </select>
      </label>
      <fieldset>
        <legend>Evidence</legend>
        {evidence.length === 0 && <p>No evidence yet; a verified entry needs at least one row.</p>}
        <ul>
          {evidence.map((r) => (
            <li key={r}>
              <code>{displaySafe(r)}</code>{" "}
              <button
                type="button"
                aria-label={`Remove ${displaySafe(r)}`}
                onClick={() => setEvidence((cur) => cur.filter((x) => x !== r))}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
        <label>
          Add a reference (table:key)
          <input value={manual} onChange={(e) => setManual(e.target.value)} />
        </label>
        <button
          type="button"
          disabled={manual.trim() === ""}
          onClick={() => {
            addRef(manual.trim());
            setManual("");
          }}
        >
          Add reference
        </button>
        <EvidencePicker existing={evidence} onAdd={addRef} />
      </fieldset>
      <button type="submit" disabled={readOnly || busy}>
        Save
      </button>
      <button type="button" onClick={onCancel}>
        Cancel
      </button>
    </form>
  );
}
