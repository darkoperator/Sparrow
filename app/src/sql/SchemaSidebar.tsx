import { useState } from "react";
import type { TableInfo } from "../api";
import { displaySafe } from "../text";

interface Props {
  tables: TableInfo[];
  /** Insert this table or column name into the editor. */
  onInsert: (name: string) => void;
}

/** The case's tables and views (`sql_schema`), each expandable to its columns with types and comments. */
export default function SchemaSidebar({ tables, onInsert }: Props) {
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());
  const toggle = (name: string) => {
    const next = new Set(open);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    setOpen(next);
  };

  return (
    <aside className="schema-sidebar" aria-label="Schema">
      <ul className="plain">
        {tables.map((t) => {
          const shown = open.has(t.name);
          return (
            <li key={t.name}>
              <button
                className="link"
                aria-expanded={shown}
                aria-label={`${shown ? "Hide" : "Show"} columns of ${t.name}`}
                onClick={() => toggle(t.name)}
              >
                {shown ? "▾" : "▸"}
              </button>{" "}
              <button
                className="link"
                title={t.comment === null ? undefined : displaySafe(t.comment)}
                onClick={() => onInsert(t.name)}
              >
                {displaySafe(t.name)}
              </button>{" "}
              <span className="tag">{displaySafe(t.kind)}</span>
              {shown && (
                <ul className="plain schema-columns" aria-label={`Columns of ${t.name}`}>
                  {t.columns.map((c) => (
                    <li key={c.name}>
                      <button className="link" onClick={() => onInsert(c.name)}>
                        {displaySafe(c.name)}
                      </button>{" "}
                      <span className="meta">{displaySafe(c.type)}</span>
                      {c.comment !== null && <div className="meta">{displaySafe(c.comment)}</div>}
                    </li>
                  ))}
                </ul>
              )}
            </li>
          );
        })}
      </ul>
    </aside>
  );
}
