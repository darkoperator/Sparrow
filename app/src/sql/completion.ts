import type { Completion, CompletionContext, CompletionResult, CompletionSource } from "@codemirror/autocomplete";
import type { TableInfo } from "../api";

/** An identifier as typed into the editor: bare when plain, else double-quoted. Editor convenience only. */
export function identifier(name: string): string {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) ? name : `"${name.replace(/"/g, '""')}"`;
}

/**
 * Completions from the schema the sidebar loaded: tables and views, and columns with their types in the detail.
 * After `table.` only that table's columns are offered.
 */
export function schemaCompletions(tables: readonly TableInfo[]): CompletionSource {
  const tableOptions: Completion[] = tables.map((t) => ({
    label: t.name,
    apply: identifier(t.name),
    type: "class",
    detail: t.kind,
    info: t.comment ?? undefined,
  }));
  const column = (t: TableInfo, c: TableInfo["columns"][number], qualified: boolean): Completion => ({
    label: c.name,
    apply: identifier(c.name),
    type: "property",
    detail: qualified ? c.type : `${c.type} · ${t.name}`,
    info: c.comment ?? undefined,
  });
  const all: Completion[] = [];
  const seen = new Set<string>();
  for (const t of tables)
    for (const c of t.columns)
      if (!seen.has(c.name)) {
        seen.add(c.name);
        all.push(column(t, c, false));
      }
  return (context: CompletionContext): CompletionResult | null => {
    const word = context.matchBefore(/(?:[A-Za-z_][A-Za-z0-9_]*\.)?[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*\.|/);
    if (!word || (word.from === word.to && !context.explicit)) return null;
    const dot = word.text.indexOf(".");
    if (dot >= 0) {
      const table = tables.find((t) => t.name.toLowerCase() === word.text.slice(0, dot).toLowerCase());
      if (!table) return null;
      return { from: word.from + dot + 1, options: table.columns.map((c) => column(table, c, true)), validFor: /^\w*$/ };
    }
    return { from: word.from, options: [...tableOptions, ...all], validFor: /^\w*$/ };
  };
}
