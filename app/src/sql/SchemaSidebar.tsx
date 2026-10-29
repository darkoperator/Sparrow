import { useState } from "react";
import type { TableInfo } from "../api";
import { displaySafe } from "../text";
import Icon from "../ui/Icon";

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
      <ul className="plain schema-tables">
        {tables.map((t) => {
          const shown = open.has(t.name);
          return (
            <li key={t.name} className="schema-table">
              <div className="schema-table-row">
              <button
                className="schema-toggle"
                aria-expanded={shown}
                aria-label={`${shown ? "Hide" : "Show"} columns of ${t.name}`}
                onClick={() => toggle(t.name)}
              >
                <Icon name={shown ? "chevron-down" : "chevron-right"} size={12} />
              </button>{" "}
              <button
                className="schema-name mono"
                title={displaySafe(t.comment === null ? t.name : `${t.name} — ${t.comment}`)}
                onClick={() => onInsert(t.name)}
              >
                {displaySafe(t.name)}
              </button>{" "}
              <span className="schema-kind">{displaySafe(t.kind)}</span>
              </div>
              {shown && (
                <ul className="plain schema-columns" aria-label={`Columns of ${t.name}`}>
                  {t.columns.map((c) => (
                    <li key={c.name} className="schema-column">
                      <button className="schema-name mono" title={displaySafe(c.name)} onClick={() => onInsert(c.name)}>
                        {displaySafe(c.name)}
                      </button>{" "}
                      <span className="schema-type mono">{displaySafe(c.type)}</span>
                      {c.comment !== null && <div className="schema-comment">{displaySafe(c.comment)}</div>}
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
