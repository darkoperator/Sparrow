// The Events filter card: one row with the raw-text search, a From/To range in ISO 8601 UTC, the flag toggle, the
// agent-mark filter, Search and Clear all. The field filters (Harrier's syntax: comma, any of; `*`, wildcard; `!`,
// exclude) live in the grid's column titles (`ColumnFilter.tsx`) but are held here, in `FilterDraft.fields`. Nothing
// here parses the text: it goes to the backend as written, and a refusal comes back as an `errors` entry.
import { type AiFilter, type EventField, type FlagFilter } from "../api";
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
  rule: "Rule",
};
export const FIELDS = Object.keys(FIELD_LABEL) as EventField[];

/** What the filters hold: the text as written, applied together by Search, Enter or a column filter's Apply. */
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

/** A refusal of one filter: a field (shown on its column), the raw search, or the range ends. */
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
        <div className="ev-field ev-time">
          <label htmlFor="ev-from" className="sr-only">From (UTC)</label>
          <input
            id="ev-from"
            className="mono"
            value={draft.from}
            placeholder="From (UTC)"
            title="From (UTC), inclusive: 2026-09-10 or 2026-09-10T00:00:00Z"
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
        <div className="ev-field ev-time">
          <label htmlFor="ev-to" className="sr-only">To (UTC)</label>
          <input
            id="ev-to"
            className="mono"
            value={draft.to}
            placeholder="To (UTC)"
            title="To (UTC), inclusive: 2026-09-11 or 2026-09-11T00:00:00Z"
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
        <div className="ev-field ev-inline" role="group" aria-label="Show">
          <span className="ev-toggle">
            {FLAGS.map((f) => (
              <button key={f.id} type="button" aria-pressed={draft.flag === f.id} onClick={() => onApply({ flag: f.id })}>
                {f.label}
              </button>
            ))}
          </span>
        </div>
        <div className="ev-field ev-inline">
          <label htmlFor="ev-ai" className="sr-only">Agent marks</label>
          <select id="ev-ai" value={draft.ai} title="Agent marks" onChange={(e) => onApply({ ai: e.target.value as AiFilter })}>
            <option value="all">All events</option>
            <option value="marked">Agent-marked</option>
            <option value="unreviewed">Unreviewed agent marks</option>
          </select>
        </div>
        <div className="ev-actions">
          <button type="submit" className="btn btn-primary">
            Search
          </button>
          <button type="button" className="btn btn-ghost" onClick={onClear}>
            Clear all
          </button>
        </div>
      </div>
    </form>
  );
}
