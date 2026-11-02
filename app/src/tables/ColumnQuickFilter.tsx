// A table column's filter in the grid's header popover: contains (text) or equals (a number), or empty and not empty. It
// writes the same `Filter` as the builder above the grid, so the backend applies it and it shows as a chip. Date columns
// use `DateRangeFilter` instead.
import { useEffect, useRef, useState } from "react";
import type { ColumnInfo, Filter } from "../api";
import { displaySafe } from "../text";
import Icon from "../ui/Icon";
import { columnKind, typedValue } from "./columnKind";
import "../events/events.css";

export default function ColumnQuickFilter({
  column,
  active,
  onAdd,
  onClear,
  onClose,
}: {
  column: ColumnInfo;
  /** Whether a filter on this column is in effect. */
  active: boolean;
  onAdd: (f: Filter) => void;
  onClear: () => void;
  onClose: () => void;
}) {
  const number = columnKind(column.type) === "number";
  const [text, setText] = useState("");
  const box = useRef<HTMLInputElement>(null);
  useEffect(() => {
    box.current?.focus();
  }, []);
  const value = number ? typedValue("number", text) : text.trim() === "" ? null : text;
  const add = (f: Filter) => {
    onAdd(f);
    onClose();
  };
  return (
    <form
      className="colf"
      role="group"
      aria-label={`Filter ${column.name}`}
      onSubmit={(e) => {
        e.preventDefault();
        if (value === null) return;
        add(number ? { op: "eq", column: column.name, value } : { op: "contains", column: column.name, value: text });
      }}
    >
      <div className="colf-head">
        <Icon name="filter" size={13} />
        <span className="label">Filter {displaySafe(column.name)}</span>
      </div>
      <label className="label">
        {number ? "Equals" : "Contains"}
        <input ref={box} className="colf-pattern" autoComplete="off" spellCheck={false} value={text} onChange={(e) => setText(e.target.value)} />
      </label>
      <div className="colf-actions">
        <button type="submit" className="btn btn-primary" disabled={value === null}>
          Apply
        </button>
        <button type="button" className="btn btn-ghost" onClick={() => add({ op: "is_null", column: column.name })}>
          Empty
        </button>
        <button type="button" className="btn btn-ghost" onClick={() => add({ op: "not_null", column: column.name })}>
          Not empty
        </button>
      </div>
      {active && (
        <button
          type="button"
          className="btn btn-ghost"
          onClick={() => {
            onClear();
            onClose();
          }}
        >
          Clear filters on this column
        </button>
      )}
    </form>
  );
}
