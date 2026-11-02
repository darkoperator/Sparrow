// A date column's filter: a From and a To, each a date picker and an optional 24-hour time, all UTC. A date alone means
// the whole day (`parseUtc`). The host decides what the range filters: loaded rows, or a query on the backend.
import { useEffect, useId, useRef, useState } from "react";
import { parseUtc } from "../events/time";
import { displaySafe } from "../text";
import Icon from "../ui/Icon";
import "../events/events.css";

/** A canonical UTC time as the boxes show it; a whole day (its first or last instant) has no time. */
function boxes(value: string | undefined, end: "from" | "to") {
  if (!value) return { day: "", clock: "" };
  const whole = value.endsWith(end === "from" ? "T00:00:00Z" : "T23:59:59.999999Z");
  return { day: value.slice(0, 10), clock: whole ? "" : value.slice(11, 16) };
}

export interface DateRangeFilterProps {
  label: string;
  /** The range in effect: canonical UTC text, as `parseUtc` gives it. */
  from?: string;
  to?: string;
  onApply: (from: string | undefined, to: string | undefined) => void;
  onClose: () => void;
}

export default function DateRangeFilter({ label, from, to, onApply, onClose }: DateRangeFilterProps) {
  const id = useId();
  const [start, setStart] = useState(() => boxes(from, "from"));
  const [end, setEnd] = useState(() => boxes(to, "to"));
  const [problem, setProblem] = useState<string | null>(null);
  const form = useRef<HTMLFormElement>(null);
  const first = useRef<HTMLInputElement>(null);
  // An empty date is not focused (WebKit would show today's date in it, greyed, like a value): the panel takes focus instead.
  useEffect(() => {
    if (first.current?.value) first.current.focus();
    else form.current?.focus();
  }, []);

  const read = (b: { day: string; clock: string }, which: "from" | "to") => {
    const text = b.clock.trim() === "" ? b.day : `${b.day}T${b.clock.trim().padStart(5, "0")}`;
    return parseUtc(text, which);
  };
  const apply = () => {
    if ((start.clock.trim() !== "" && start.day === "") || (end.clock.trim() !== "" && end.day === "")) {
      setProblem("A time needs a date");
      return;
    }
    const a = read(start, "from");
    const b = read(end, "to");
    if (!a.ok || !b.ok) {
      setProblem("Time is HH:MM, 00:00 to 23:59 (UTC)");
      return;
    }
    if (a.value && b.value && Date.parse(a.value) > Date.parse(b.value)) {
      setProblem("To is before From");
      return;
    }
    onApply(a.value, b.value);
    onClose();
  };
  const row = (name: string, value: { day: string; clock: string }, set: (v: { day: string; clock: string }) => void, ref?: React.Ref<HTMLInputElement>) => (
    <div className="colf-date">
      <label htmlFor={`${id}-${name}`}>{`${name} date (UTC)`}</label>
      <span className="ev-picker-date">
        <input
          ref={ref}
          id={`${id}-${name}`}
          type="date"
          className={value.day === "" ? "ev-picker-empty" : undefined}
          value={value.day}
          onChange={(e) => set({ ...value, day: e.target.value })}
        />
        {value.day === "" && (
          <span className="ev-picker-none" aria-hidden="true">
            No date yet
          </span>
        )}
      </span>
      <input
        type="text"
        inputMode="numeric"
        aria-label={`${name} time (UTC)`}
        placeholder="HH:MM"
        spellCheck={false}
        value={value.clock}
        onChange={(e) => set({ ...value, clock: e.target.value })}
      />
    </div>
  );

  return (
    <form
      ref={form}
      tabIndex={-1}
      className="colf"
      role="group"
      aria-label={`Filter ${label}`}
      onSubmit={(e) => {
        e.preventDefault();
        apply();
      }}
    >
      <div className="colf-head">
        <Icon name="calendar" size={13} />
        <span className="label">Filter {displaySafe(label)}</span>
      </div>
      {row("From", start, setStart, first)}
      {row("To", end, setEnd)}
      {problem ? (
        <p role="alert" className="colf-meta colf-problem">
          {problem}
        </p>
      ) : (
        <p className="colf-meta">Either end can stay empty. A date with no time is the whole day.</p>
      )}
      <div className="colf-actions">
        <button type="submit" className="btn btn-primary">
          Apply
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={!from && !to}
          onClick={() => {
            onApply(undefined, undefined);
            onClose();
          }}
        >
          Clear filter
        </button>
      </div>
    </form>
  );
}
