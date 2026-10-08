import { useState } from "react";
import type { ColumnInfo, Filter } from "../api";
import { displaySafe } from "../text";
import { rawText } from "../value";
import { columnKind, typedValue, type ColumnKind } from "./columnKind";

type Op = Filter["op"];

const OP_LABEL: Record<Op, string> = {
  eq: "equals",
  ne: "does not equal",
  contains: "contains",
  between: "is between",
  in: "is in list",
  is_null: "is empty",
  not_null: "is not empty",
};

const OPS: Record<ColumnKind, Op[]> = {
  text: ["eq", "ne", "contains", "in", "is_null", "not_null"],
  number: ["eq", "ne", "between", "in", "is_null", "not_null"],
  time: ["eq", "ne", "between", "is_null", "not_null"],
  date: ["eq", "ne", "between", "is_null", "not_null"],
};

const INPUT_TYPE: Record<ColumnKind, string> = { text: "text", number: "text", time: "datetime-local", date: "date" };

/** One filter as a short line for its chip. Text is escaped by the caller's `displaySafe`. */
export function describeFilter(f: Filter): string {
  switch (f.op) {
    case "between":
      return `${f.column} ${OP_LABEL.between} ${rawText(f.low)} and ${rawText(f.high)}`;
    case "in":
      return `${f.column} ${OP_LABEL.in} (${f.values.map(rawText).join(", ")})`;
    case "is_null":
    case "not_null":
      return `${f.column} ${OP_LABEL[f.op]}`;
    default:
      return `${f.column} ${OP_LABEL[f.op]} ${rawText(f.value)}`;
  }
}

export function FilterChips({ filters, onRemove }: { filters: Filter[]; onRemove: (index: number) => void }) {
  return (
    <ul className="plain filter-chips" aria-label="Filters">
      {filters.map((f, i) => (
        <li key={i} className="filter-chip">
          <span>{displaySafe(describeFilter(f))}</span>
          <button aria-label={`Remove filter ${displaySafe(describeFilter(f))}`} onClick={() => onRemove(i)}>
            ×
          </button>
        </li>
      ))}
    </ul>
  );
}

/** Builds one typed `Filter` for a column of the table; times are entered and sent as UTC. */
export default function FilterBuilder({ columns, onAdd }: { columns: ColumnInfo[]; onAdd: (f: Filter) => void }) {
  const [column, setColumn] = useState(columns[0]?.name ?? "");
  const [op, setOp] = useState<Op>("eq");
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [list, setList] = useState("");

  const info = columns.find((c) => c.name === column) ?? columns[0];
  const kind = info ? columnKind(info.type) : "text";
  const ops = OPS[kind];
  const effectiveOp: Op = ops.includes(op) ? op : ops[0];
  const utc = kind === "time" ? " (UTC)" : "";
  const inputType = INPUT_TYPE[kind];

  const build = (): Filter | null => {
    if (!info) return null;
    const col = info.name;
    if (effectiveOp === "is_null" || effectiveOp === "not_null") return { op: effectiveOp, column: col };
    if (effectiveOp === "contains") return a === "" ? null : { op: "contains", column: col, value: a };
    if (effectiveOp === "in") {
      const items = list.split("\n").filter((l) => l.trim() !== "").map((l) => typedValue(kind, l));
      return items.length === 0 || items.includes(null) ? null : { op: "in", column: col, values: items };
    }
    if (effectiveOp === "between") {
      const low = typedValue(kind, a);
      const high = typedValue(kind, b);
      return low === null || high === null ? null : { op: "between", column: col, low, high };
    }
    const value = typedValue(kind, a);
    return value === null ? null : { op: effectiveOp, column: col, value };
  };
  const filter = build();

  const add = (e: React.FormEvent) => {
    e.preventDefault();
    if (!filter) return;
    onAdd(filter);
    setA("");
    setB("");
    setList("");
  };

  return (
    <form className="filter-builder" onSubmit={add}>
      <label>
        Column{" "}
        <select value={info?.name ?? ""} onChange={(e) => setColumn(e.target.value)}>
          {columns.map((c) => (
            <option key={c.name} value={c.name}>
              {displaySafe(c.name)}
            </option>
          ))}
        </select>
      </label>{" "}
      <label>
        Operator{" "}
        <select value={effectiveOp} onChange={(e) => setOp(e.target.value as Op)}>
          {ops.map((o) => (
            <option key={o} value={o}>
              {OP_LABEL[o]}
            </option>
          ))}
        </select>
      </label>{" "}
      {effectiveOp === "between" ? (
        <>
          <label>
            {`From${utc}`} <input type={inputType} step={kind === "time" ? 1 : undefined} value={a} onChange={(e) => setA(e.target.value)} />
          </label>{" "}
          <label>
            {`To${utc}`} <input type={inputType} step={kind === "time" ? 1 : undefined} value={b} onChange={(e) => setB(e.target.value)} />
          </label>
        </>
      ) : effectiveOp === "in" ? (
        <label>
          Values (one per line){" "}
          <textarea rows={3} value={list} onChange={(e) => setList(e.target.value)} />
        </label>
      ) : effectiveOp === "is_null" || effectiveOp === "not_null" ? null : (
        <label>
          {`Value${utc}`}{" "}
          <input
            type={effectiveOp === "contains" ? "text" : inputType}
            step={kind === "time" && effectiveOp !== "contains" ? 1 : undefined}
            value={a}
            onChange={(e) => setA(e.target.value)}
          />
        </label>
      )}{" "}
      <button type="submit" disabled={filter === null}>
        Add filter
      </button>
    </form>
  );
}
