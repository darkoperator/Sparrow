import type { Completion, CompletionContext, CompletionResult, CompletionSource } from "@codemirror/autocomplete";
import { keywordCompletionSource, PostgreSQL } from "@codemirror/lang-sql";
import { syntaxTree } from "@codemirror/language";
import type { TableInfo } from "../api";

/** An identifier as typed into the editor: bare when plain, else double-quoted. Editor convenience only. */
export function identifier(name: string): string {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) ? name : `"${name.replace(/"/g, '""')}"`;
}

type Position =
  /** Inside a string literal, a comment or a quoted identifier: no completion. */
  | { kind: "none" }
  | { kind: "plain"; from: number }
  /** After `qualifier.`: `table` is the last qualifier part, unquoted. */
  | { kind: "qualified"; table: string; from: number };

const NO_COMPLETION = new Set(["String", "LineComment", "BlockComment", "QuotedIdentifier"]);

/** Where the cursor is, from the syntax tree (so strings and comments are never mistaken for code). */
function positionOf(context: CompletionContext): Position {
  const { state, pos } = context;
  const node = syntaxTree(state).resolveInner(pos, -1);
  if (NO_COMPLETION.has(node.name) && pos > node.from) return { kind: "none" };
  const composite = node.name === "CompositeIdentifier" ? node : node.parent?.name === "CompositeIdentifier" ? node.parent : null;
  if (composite === null) {
    const word = context.matchBefore(/[A-Za-z_][A-Za-z0-9_]*/);
    return { kind: "plain", from: word ? word.from : pos };
  }
  // The parser splits `"a""b"` into two quoted identifiers; take them back into the composite.
  let start = composite.from;
  for (let prev = composite.prevSibling; prev && prev.name === "QuotedIdentifier" && prev.to === start; prev = prev.prevSibling) {
    start = prev.from;
  }
  const text = state.sliceDoc(start, pos);
  const parts: string[] = text.match(/"(?:[^"]|"")*"|[A-Za-z_][A-Za-z0-9_]*|\./g) ?? [];
  const lastDot = parts.lastIndexOf(".");
  if (lastDot < 1) {
    const word = context.matchBefore(/[A-Za-z_][A-Za-z0-9_]*/);
    return { kind: "plain", from: word ? word.from : pos };
  }
  const q = parts[lastDot - 1];
  const table = q.startsWith('"') ? q.slice(1, -1).replace(/""/g, '"') : q;
  const partial = parts.slice(lastDot + 1).join("");
  return { kind: "qualified", table, from: pos - partial.length };
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
    const at = positionOf(context);
    if (at.kind === "none") return null;
    if (at.kind === "qualified") {
      const table = tables.find((t) => t.name.toLowerCase() === at.table.toLowerCase());
      if (!table) return null;
      return { from: at.from, options: table.columns.map((c) => column(table, c, true)), validFor: /^\w*$/ };
    }
    if (at.from === context.pos && !context.explicit) return null;
    return { from: at.from, options: [...tableOptions, ...all], validFor: /^\w*$/ };
  };
}

/** SQL keywords, except right after a `qualifier.`, where only that table's columns make sense. */
export function keywordCompletions(): CompletionSource {
  const keywords = keywordCompletionSource(PostgreSQL, true);
  return (context) => {
    if (positionOf(context).kind !== "plain") return null;
    return keywords(context);
  };
}
