// The filter rows of the Events grid: raw-text search, one box per field in Harrier's syntax (comma: any of; `*`:
// wildcard; `!`: exclude), a From/To range in ISO 8601 UTC, the flag toggle and the agent-mark filter. Nothing here
// parses the text: it goes to the backend as typed, and a refusal comes back as an `errors` entry under its box.
import { useEffect, useId, useState } from "react";
import { eventsSuggest, type AiFilter, type EventField, type FlagFilter } from "../api";
import Icon from "../ui/Icon";
import { displaySafe } from "../text";

export const FIELD_LABEL: Record<EventField, string> = {
  source: "Source",
  operation: "Operation",
  account: "Account",
  ip: "IP",
  country: "Country",
  asn: "ASN",
  device: "Device",
  session: "Session",
  tag: "Tag",
};
export const FIELDS = Object.keys(FIELD_LABEL) as EventField[];

/** What the boxes hold: the text as typed, applied together by Search or Enter. */
export interface FilterDraft {
  fields: Record<EventField, string>;
  search: string;
  from: string;
  to: string;
  flag: FlagFilter;
  ai: AiFilter;
}

export const emptyDraft = (): FilterDraft => ({
  fields: Object.fromEntries(FIELDS.map((f) => [f, ""])) as Record<EventField, string>,
  search: "",
  from: "",
  to: "",
  flag: "all",
  ai: "all",
});

/** A message under one box: a field, the raw search, or the range ends. */
export type FilterErrors = Partial<Record<EventField | "search" | "from" | "to", string>>;

interface Props {
  draft: FilterDraft;
  errors: FilterErrors;
  /** Edit the text of the boxes (nothing runs). */
  onChange: (patch: Partial<FilterDraft>) => void;
  /** Run the query now, with the boxes as they are plus `patch`. */
  onApply: (patch?: Partial<FilterDraft>) => void;
  onClear: () => void;
}

const SUGGEST_DELAY_MS = 150;

/** The part of a list box being typed: what is before it (kept), and the word itself without a leading `!`. */
export function splitLastToken(text: string): { head: string; bang: string; prefix: string } {
  const at = text.lastIndexOf(",");
  const head = text.slice(0, at + 1);
  const rest = text.slice(at + 1);
  const lead = rest.length - rest.trimStart().length;
  const word = rest.slice(lead);
  const bang = word.startsWith("!") ? "!" : "";
  return { head: head + rest.slice(0, lead), bang, prefix: word.slice(bang.length) };
}

function FieldBox({
  field,
  value,
  error,
  onChange,
}: {
  field: EventField;
  value: string;
  error?: string;
  onChange: (text: string) => void;
}) {
  const id = useId();
  // The suggestions are for one text; once the text moves on they are not offered until the next answer arrives.
  const [suggested, setSuggested] = useState<{ text: string; options: string[] }>({ text: "", options: [] });
  const options = suggested.text === value ? suggested.options : [];
  useEffect(() => {
    const { head, bang, prefix } = splitLastToken(value);
    // A wildcard word is a pattern, not a prefix to complete; nothing typed yet has too many answers to be useful.
    if (prefix === "" || prefix.includes("*")) return;
    let live = true;
    const t = setTimeout(() => {
      eventsSuggest(field, prefix).then(
        (found) => live && setSuggested({ text: value, options: found.map((v) => head + bang + v) }),
        () => live && setSuggested({ text: value, options: [] }),
      );
    }, SUGGEST_DELAY_MS);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [field, value]);
  return (
    <div className="ev-field">
      <label htmlFor={`${id}-in`} className="label">{FIELD_LABEL[field]}</label>
      <input
        id={`${id}-in`}
        className="mono"
        value={value}
        list={options.length > 0 ? `${id}-list` : undefined}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${id}-err` : undefined}
        autoComplete="off"
        spellCheck={false}
        onChange={(e) => onChange(e.target.value)}
      />
      {options.length > 0 && (
        <datalist id={`${id}-list`}>
          {options.map((o) => (
            <option key={o} value={o} />
          ))}
        </datalist>
      )}
      {error && (
        <div id={`${id}-err`} role="alert" className="ev-error">
          {displaySafe(error)}
        </div>
      )}
    </div>
  );
}

const FLAGS: { id: FlagFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "suspicious", label: "Suspicious" },
  { id: "malicious", label: "Malicious" },
];

export default function Filters({ draft, errors, onChange, onApply, onClear }: Props) {
  return (
    <form
      className="ev-filters"
      aria-label="Event filters"
      onSubmit={(e) => {
        e.preventDefault();
        onApply();
      }}
    >
      <div className="ev-row ev-searchrow">
        <div className="ev-field ev-search">
          <label htmlFor="ev-search" className="sr-only">
            Search text
          </label>
          <span className="ev-searchbox">
            <Icon name="search" size={14} />
            <input
              id="ev-search"
              className="mono"
              value={draft.search}
              placeholder="any text in the raw record; comma: any of"
              aria-invalid={errors.search ? true : undefined}
              onChange={(e) => onChange({ search: e.target.value })}
            />
          </span>
          {errors.search && (
            <div role="alert" className="ev-error">
              {displaySafe(errors.search)}
            </div>
          )}
        </div>
        <div className="ev-actions">
          <button type="submit" className="btn btn-primary">
            Search
          </button>
          <button type="button" className="btn btn-ghost" onClick={onClear}>
            Clear filters
          </button>
        </div>
      </div>
      <div className="ev-row ev-fields">
        {FIELDS.map((f) => (
          <FieldBox key={f} field={f} value={draft.fields[f]} error={errors[f]} onChange={(text) => onChange({ fields: { ...draft.fields, [f]: text } })} />
        ))}
      </div>
      <div className="ev-row">
        <div className="ev-field">
          <label htmlFor="ev-from" className="label">From (UTC)</label>
          <input
            id="ev-from"
            className="mono"
            value={draft.from}
            placeholder="2026-09-10T00:00:00Z"
            spellCheck={false}
            aria-invalid={errors.from ? true : undefined}
            onChange={(e) => onChange({ from: e.target.value })}
          />
          {errors.from && (
            <div role="alert" className="ev-error">
              {displaySafe(errors.from)}
            </div>
          )}
        </div>
        <div className="ev-field">
          <label htmlFor="ev-to" className="label">To (UTC)</label>
          <input
            id="ev-to"
            className="mono"
            value={draft.to}
            placeholder="2026-09-11T00:00:00Z"
            spellCheck={false}
            aria-invalid={errors.to ? true : undefined}
            onChange={(e) => onChange({ to: e.target.value })}
          />
          {errors.to && (
            <div role="alert" className="ev-error">
              {displaySafe(errors.to)}
            </div>
          )}
        </div>
        <div className="ev-field" role="group" aria-label="Show">
          <span className="ev-label label">Show</span>
          <span className="ev-toggle">
            {FLAGS.map((f) => (
              <button key={f.id} type="button" aria-pressed={draft.flag === f.id} onClick={() => onApply({ flag: f.id })}>
                {f.label}
              </button>
            ))}
          </span>
        </div>
        <div className="ev-field">
          <label htmlFor="ev-ai" className="label">Agent marks</label>
          <select id="ev-ai" value={draft.ai} onChange={(e) => onApply({ ai: e.target.value as AiFilter })}>
            <option value="all">All events</option>
            <option value="marked">Agent-marked</option>
            <option value="unreviewed">Unreviewed agent marks</option>
          </select>
        </div>
      </div>
    </form>
  );
}
