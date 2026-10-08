import { useState } from "react";
import { HIGHLIGHT_COLOURS, type HighlightColour, type HighlightRule, type HighlightSet } from "../api";
import { displaySafe } from "../text";
import { useHighlights } from "./useHighlights";

/** A rule as one line: "any column eq value". The value is the analyst's or copied from a cell; always escaped. */
export function ruleText(r: HighlightRule): string {
  return `${r.column ?? "any column"} ${r.op === "eq" ? "equals" : "contains"} ${r.value}`;
}

/**
 * The highlight sets of the open case: named sets of rules, switched on and off here, plus the built-in "Highlight
 * indicators" set. Sets live in the app's local settings (not in the case, not shared); "Clear" removes them all.
 */
export default function Highlights() {
  const hl = useHighlights();
  const [setName, setSetName] = useState("");
  const [column, setColumn] = useState("");
  const [op, setOp] = useState<"eq" | "contains">("eq");
  const [value, setValue] = useState("");
  const [colour, setColour] = useState<HighlightColour>("amber");
  const [confirmClear, setConfirmClear] = useState(false);

  if (!hl) return <p>Open a case to manage highlights.</p>;

  const addRule = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = setName.trim();
    if (name === "" || value === "") return;
    const rule: HighlightRule = { column: column.trim() === "" ? null : column.trim(), op, value, colour };
    const ok = await hl.update((current) =>
      current.some((s) => s.name === name)
        ? current.map((s) => (s.name === name ? { ...s, rules: [...s.rules, rule] } : s))
        : [...current, { name, rules: [rule] }],
    );
    if (ok) setValue("");
  };

  const removeRule = (set: HighlightSet, i: number) =>
    void hl.update((current) =>
      current.flatMap((s) => {
        if (s.name !== set.name) return [s];
        const rules = s.rules.filter((_, j) => j !== i);
        return rules.length > 0 ? [{ ...s, rules }] : [];
      }),
    );

  const removeSet = (set: HighlightSet) => void hl.update((current) => current.filter((s) => s.name !== set.name));

  return (
    <section className="highlights">
      <h2>Highlights</h2>
      <p className="meta">
        Kept on this computer for this case only: not in the case, not audited, not shared in bundles.
      </p>
      {hl.error && <div role="alert">{displaySafe(hl.error)}</div>}

      <h3>Sets</h3>
      <ul className="plain">
        <li>
          <label>
            <input type="checkbox" checked={hl.indicatorsOn} onChange={(e) => hl.setIndicatorsOn(e.target.checked)} />{" "}
            Highlight indicators
          </label>{" "}
          <span className="meta">
            {hl.indicators.length} active malicious or suspicious {hl.indicators.length === 1 ? "indicator" : "indicators"}
          </span>
        </li>
        {hl.sets.map((s) => (
          <li key={s.name}>
            <label>
              <input type="checkbox" checked={!hl.off.has(s.name)} onChange={() => hl.toggleSet(s.name)} />{" "}
              <strong>{displaySafe(s.name)}</strong>
            </label>{" "}
            <button aria-label={`Remove set ${displaySafe(s.name)}`} onClick={() => removeSet(s)}>
              Remove set
            </button>
            <ul>
              {s.rules.map((r, i) => (
                <li key={i}>
                  <span className={`swatch hl-${r.colour}`} aria-hidden="true" />
                  <span>{displaySafe(ruleText(r))}</span> <span className="meta">({r.colour})</span>{" "}
                  <button aria-label={`Remove rule ${displaySafe(ruleText(r))}`} onClick={() => removeRule(s, i)}>
                    ×
                  </button>
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
      {hl.sets.length === 0 && <p>No highlight sets for this case.</p>}

      <h3>Add a rule</h3>
      <form onSubmit={(e) => void addRule(e)}>
        <label>
          Set <input list="highlight-sets" value={setName} onChange={(e) => setSetName(e.target.value)} />
        </label>
        <datalist id="highlight-sets">
          {hl.sets.map((s) => (
            <option key={s.name} value={s.name} />
          ))}
        </datalist>{" "}
        <label>
          Column (empty = any){" "}
          <input value={column} onChange={(e) => setColumn(e.target.value)} />
        </label>{" "}
        <label>
          Match{" "}
          <select value={op} onChange={(e) => setOp(e.target.value as "eq" | "contains")}>
            <option value="eq">equals</option>
            <option value="contains">contains</option>
          </select>
        </label>{" "}
        <label>
          Value <input value={value} onChange={(e) => setValue(e.target.value)} />
        </label>{" "}
        <label>
          Colour{" "}
          <select value={colour} onChange={(e) => setColour(e.target.value as HighlightColour)}>
            {HIGHLIGHT_COLOURS.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </label>{" "}
        <button type="submit" disabled={setName.trim() === "" || value === ""}>
          Add rule
        </button>
      </form>

      <h3>Clear</h3>
      {confirmClear ? (
        <p>
          Remove every highlight set for this case?{" "}
          <button
            onClick={() => {
              void hl.clear().then(() => setConfirmClear(false));
            }}
          >
            Yes, clear them
          </button>{" "}
          <button onClick={() => setConfirmClear(false)}>Keep them</button>
        </p>
      ) : (
        <button onClick={() => setConfirmClear(true)} disabled={hl.sets.length === 0}>
          Clear highlights for this case
        </button>
      )}
    </section>
  );
}
