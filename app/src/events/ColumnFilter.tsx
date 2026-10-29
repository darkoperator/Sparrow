// A column's filter in the Events grid's header popover: the column's values with their event counts under every other
// filter, tick boxes (any of), an Exclude switch (none of), a pattern box for what ticking cannot say, Apply and Clear.
// It writes the field's text syntax (`fieldSyntax.ts`), quoting ticked values, so the backend parses what it always
// has. Answers for an older query or search text are dropped, and a superseded raw-search count is cancelled.
import { useEffect, useId, useRef, useState } from "react";
import { eventsValues, isCmdError, newQueryId, queryCancel, VALUES_MAX, type EventField, type EventQuery, type FieldValues } from "../api";
import { displaySafe } from "../text";
import Icon from "../ui/Icon";
import { buildField, splitField } from "./fieldSyntax";

/** The fields whose values read in the UI font (names); the rest are ids, addresses and codes, in mono. */
const NAME_FIELDS: ReadonlySet<EventField> = new Set(["source", "operation", "account", "tag"]);
const FIND_DELAY_MS = 200;

export interface ColumnFilterProps {
  field: EventField;
  /** The column's title. */
  label: string;
  /** The field's text in effect. */
  text: string;
  /** The backend's refusal of that text, if any. */
  error?: string;
  /** The query on screen: the values are counted under it, this field's own filter left out by the backend. */
  query: EventQuery;
  /** Apply this field text (blank: no filter on the field). */
  onApply: (text: string) => void;
  onClose: () => void;
}

/** How a value reads in the list: an ASN with its `AS`. */
const shown = (field: EventField, v: string) => (field === "asn" ? `AS${v}` : v);

export default function ColumnFilter({ field, label, text, error, query, onApply, onClose }: ColumnFilterProps) {
  const id = useId();
  const start = splitField(text);
  const [ticked, setTicked] = useState<string[]>(start.values);
  const [exclude, setExclude] = useState(start.exclude);
  const [pattern, setPattern] = useState(start.pattern);
  const [find, setFind] = useState("");
  const [prefix, setPrefix] = useState("");
  const [list, setList] = useState<{ key: string; data: FieldValues } | null>(null);
  const [failed, setFailed] = useState<{ key: string; message: string } | null>(null);
  const findBox = useRef<HTMLInputElement>(null);

  useEffect(() => {
    findBox.current?.focus();
  }, []);
  useEffect(() => {
    const t = setTimeout(() => setPrefix(find.trim()), FIND_DELAY_MS);
    return () => clearTimeout(t);
  }, [find]);

  // One answer per (query, prefix): a newer key makes every older answer stale, whenever it arrives.
  const key = JSON.stringify([query, field, prefix]);
  useEffect(() => {
    let live = true;
    const qid = query.search !== undefined ? newQueryId() : undefined;
    eventsValues(query, field, prefix, VALUES_MAX, qid).then(
      (data) => live && setList({ key, data }),
      (e: unknown) => {
        if (!live || (isCmdError(e) && e.kind === "interrupted")) return;
        setFailed({ key, message: isCmdError(e) ? e.message : String(e) });
      },
    );
    return () => {
      live = false;
      if (qid) void queryCancel(qid).catch(() => undefined);
    };
    // `key` stands for query, field and prefix.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  const current = list?.key === key ? list.data : null;
  const problem = failed?.key === key ? failed.message : null;
  const counts = new Map((current?.values ?? []).map((v) => [v.value, v.count]));
  // Ticked values stay on top even when the list (top 200, or the find text) leaves them out.
  const rows = [
    ...ticked.map((value) => ({ value, count: counts.get(value) })),
    ...(current?.values ?? []).filter((v) => !ticked.includes(v.value)),
  ];
  const toggle = (v: string) => setTicked((t) => (t.includes(v) ? t.filter((x) => x !== v) : [...t, v]));
  const apply = () => {
    onApply(buildField(ticked, exclude, pattern));
    onClose();
  };
  const mono = NAME_FIELDS.has(field) ? "" : " mono";

  return (
    <div className="colf" aria-label={`Filter ${label}`} role="group">
      <div className="colf-head">
        <Icon name="filter" size={13} />
        <span className="label">Filter {displaySafe(label)}</span>
      </div>
      {error && (
        <div role="alert" className="colf-error">
          {displaySafe(error)}
        </div>
      )}
      <label htmlFor={`${id}-find`} className="sr-only">
        Find a value
      </label>
      <span className="colf-find">
        <Icon name="search" size={13} />
        <input
          ref={findBox}
          id={`${id}-find`}
          className={mono.trim()}
          value={find}
          placeholder="Find a value (* wildcard)"
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => setFind(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") e.preventDefault();
          }}
        />
      </span>
      <ul className="colf-values plain" aria-label={`${label} values`} aria-busy={current === null && problem === null}>
        {rows.map((r) => {
          const text = displaySafe(shown(field, r.value));
          return (
            <li key={r.value}>
              <label title={text}>
                <input type="checkbox" aria-label={text} checked={ticked.includes(r.value)} onChange={() => toggle(r.value)} />
                <span className={`colf-value${mono}`}>{text}</span>
                <span className="colf-count">{r.count === undefined ? "" : r.count.toLocaleString("en-US")}</span>
              </label>
            </li>
          );
        })}
      </ul>
      {current === null && problem === null && (
        <p className="colf-meta" role="status">
          Counting…
        </p>
      )}
      {problem && (
        <p className="colf-meta colf-problem" role="status">
          {displaySafe(problem)}
        </p>
      )}
      {current && current.values.length === 0 && <p className="colf-meta">No values{prefix ? " start with that" : ""}.</p>}
      {current && current.total > current.values.length && (
        <p className="colf-meta">
          Showing {current.values.length.toLocaleString("en-US")} of {current.total.toLocaleString("en-US")}
        </p>
      )}
      <label className="colf-switch">
        <input type="checkbox" role="switch" checked={exclude} onChange={(e) => setExclude(e.target.checked)} />
        Exclude the ticked values
      </label>
      <label htmlFor={`${id}-pat`} className="label">
        Pattern
      </label>
      <input
        id={`${id}-pat`}
        className="mono colf-pattern"
        value={pattern}
        placeholder="*@contoso.example, !admin*"
        autoComplete="off"
        spellCheck={false}
        title={'* wildcard; comma: any of; ! excludes; "a,b" in double quotes is one literal value ("" is a quote)'}
        onChange={(e) => setPattern(e.target.value)}
        onKeyDown={(e) => {
          if (e.key !== "Enter") return;
          e.preventDefault();
          apply();
        }}
      />
      <div className="colf-actions">
        <button type="button" className="btn btn-primary" onClick={apply}>
          Apply
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={text.trim() === ""}
          onClick={() => {
            onApply("");
            onClose();
          }}
        >
          Clear filter
        </button>
      </div>
    </div>
  );
}

/** The filter icon a filtered column's title carries: its hover lists the filter; red when the backend refused it. */
export function FilterBadge({ label, text, error }: { label: string; text: string; error?: string }) {
  const title = displaySafe(error ? `${label} filter refused: ${error}` : `${label} filter: ${text}`);
  return (
    <span className={error ? "grid-badge colf-badge colf-badge-error" : "grid-badge colf-badge"} role="img" aria-label={title} title={title}>
      <Icon name={error ? "alert" : "filter"} size={12} />
    </span>
  );
}
