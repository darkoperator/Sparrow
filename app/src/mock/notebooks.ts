// DEV ONLY: the mock backend's SQL notebooks, kept in memory: the built-in notebook (read-only) and the case's, as
// the core keeps them (positions 1..n, unique names, Built-in reserved). All data is synthetic.
import type { CaseValueHit, CmdErrorKind, NotebookSummary, QuerySummary, SavedQuery } from "../api";
import * as fx from "../test/fixtures";

interface Deps {
  fail: (kind: CmdErrorKind, message: string) => never;
  /** Refuses a write on a read-only case or without an analyst name. */
  writable: () => void;
  analyst: () => string;
}

type Stored = { id: string; name: string; queries: SavedQuery[] };

const builtin = (): Stored => {
  const nb = fx.notebooks()[0];
  return { id: nb.notebook_id, name: nb.name, queries: nb.queries.map((q) => fx.savedQuery(nb.notebook_id, q.query_id)) };
};
const notebooks: Stored[] = [];
let seq = 0;

/** `[name]` placeholders as the core finds them: in code, strings and quoted identifiers, never in comments. */
export function placeholders(sql: string): string[] {
  const out: string[] = [];
  let state: "code" | "str" | "ident" | "line" | "block" = "code";
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    const next = sql[i + 1];
    if (state === "line") {
      if (c === "\n") state = "code";
      continue;
    }
    if (state === "block") {
      if (c === "*" && next === "/") {
        state = "code";
        i++;
      }
      continue;
    }
    if (c === "[") {
      const m = /^\[([A-Za-z][A-Za-z0-9_]*)\]/.exec(sql.slice(i));
      if (m) {
        if (!out.includes(m[1])) out.push(m[1]);
        i += m[0].length - 1;
        continue;
      }
    }
    if (state === "code") {
      if (c === "'") state = "str";
      else if (c === '"') state = "ident";
      else if (c === "-" && next === "-") {
        state = "line";
        i++;
      } else if (c === "/" && next === "*") {
        state = "block";
        i++;
      }
    } else if (state === "str" && c === "'") {
      if (next === "'") i++;
      else state = "code";
    } else if (state === "ident" && c === '"') {
      if (next === '"') i++;
      else state = "code";
    }
  }
  return out;
}

/** Values the mock case holds, as the core's export check looks them up (lower case). */
const caseValues = () =>
  new Set(
    fx.eventsList().flatMap((r) => [r.actor_upn, r.owner_upn, r.ip, r.device_id].filter((v): v is string => !!v).map((v) => v.toLowerCase())),
  );

const title = (sql: string) => {
  const first = sql.split("\n").map((l) => l.trim()).find((l) => l !== "") ?? "";
  return first.startsWith("--") ? first.slice(2).trim() || "(untitled)" : first.slice(0, 80) || "(untitled)";
};
const renumber = (nb: Stored) => nb.queries.forEach((q, i) => (q.position = i + 1));
const summary = (nb: Stored): NotebookSummary => ({
  notebook_id: nb.id,
  name: nb.name,
  builtin: nb.id === "builtin",
  queries: nb.queries.map(
    (q): QuerySummary => ({
      query_id: q.query_id,
      position: q.position,
      title: q.title,
      placeholders: q.placeholders,
      decided_by: q.decided_by,
      on_behalf_of: q.on_behalf_of,
      decided_at: q.decided_at,
    }),
  ),
});

export function notebookHandlers(deps: Deps): Record<string, (a: Record<string, unknown> | undefined) => unknown> {
  const str = (a: Record<string, unknown> | undefined, k: string) => (typeof a?.[k] === "string" ? (a[k] as string) : "");
  const all = () => [builtin(), ...[...notebooks].sort((x, y) => x.name.toLowerCase().localeCompare(y.name.toLowerCase()))];
  const find = (key: string) =>
    all().find((n) => n.id === key || n.name.toLowerCase() === key.toLowerCase()) ?? deps.fail("decision", `unknown notebook ${key}`);
  const own = (id: string) => {
    if (id === "builtin" || id.startsWith("builtin:") || id.toLowerCase() === "built-in")
      deps.fail("decision", "the built-in notebook cannot be changed");
    return notebooks.find((n) => n.id === id) ?? deps.fail("decision", `unknown notebook ${id}`);
  };
  const ownerOf = (queryId: string) =>
    notebooks.find((n) => n.queries.some((q) => q.query_id === queryId)) ?? own(queryId);
  const checkName = (name: string, except?: string) => {
    if (name.trim() === "") deps.fail("decision", "a notebook name must be one line of text");
    if (name.trim().toLowerCase() === "built-in") deps.fail("decision", "the name Built-in is reserved: the built-in notebook cannot be changed");
    if (notebooks.some((n) => n.id !== except && n.name.toLowerCase() === name.trim().toLowerCase()))
      deps.fail("decision", `a notebook named ${name.trim()} already exists`);
  };
  const create = (name: string) => {
    checkName(name);
    const nb = { id: `mocknb${++seq}`, name: name.trim(), queries: [] };
    notebooks.push(nb);
    return nb;
  };
  const add = (nb: Stored, sql: string) => {
    if (sql.trim() === "") deps.fail("decision", "a query must not be empty");
    const q: SavedQuery = {
      query_id: `mockq${++seq}`,
      position: nb.queries.length + 1,
      title: title(sql),
      placeholders: placeholders(sql),
      decided_by: `analyst:${deps.analyst()}`,
      on_behalf_of: null,
      decided_at: new Date().toISOString(),
      notebook_id: nb.id,
      sql,
    };
    nb.queries.push(q);
    return q.query_id;
  };
  return {
    notebook_list: () => all().map(summary),
    notebook_query: (a) => {
      const nb = find(str(a, "notebook"));
      const key = str(a, "query");
      return nb.queries.find((q) => q.query_id === key || String(q.position) === key) ?? deps.fail("decision", `notebook ${nb.name} has no query ${key}`);
    },
    notebook_create: (a) => {
      deps.writable();
      return create(str(a, "name")).id;
    },
    notebook_add_query: (a) => {
      deps.writable();
      return add(own(str(a, "notebookId")), str(a, "sql"));
    },
    notebook_save_new: (a) => {
      deps.writable();
      const sql = str(a, "sql");
      if (sql.trim() === "") deps.fail("decision", "a query must not be empty");
      const nb = create(str(a, "name"));
      return { notebook_id: nb.id, query_id: add(nb, sql) };
    },
    notebook_rename: (a) => {
      deps.writable();
      const nb = own(str(a, "notebookId"));
      checkName(str(a, "name"), nb.id);
      nb.name = str(a, "name").trim();
      return null;
    },
    notebook_delete: (a) => {
      deps.writable();
      const nb = own(str(a, "notebookId"));
      notebooks.splice(notebooks.indexOf(nb), 1);
      return null;
    },
    notebook_delete_query: (a) => {
      deps.writable();
      const nb = ownerOf(str(a, "queryId"));
      nb.queries = nb.queries.filter((q) => q.query_id !== str(a, "queryId"));
      renumber(nb);
      return null;
    },
    notebook_move_query: (a) => {
      deps.writable();
      const id = str(a, "queryId");
      const nb = ownerOf(id);
      const from = nb.queries.findIndex((q) => q.query_id === id);
      const [q] = nb.queries.splice(from, 1);
      const to = Math.min(Math.max(Number(a?.position ?? 1), 1), nb.queries.length + 1);
      nb.queries.splice(to - 1, 0, q);
      renumber(nb);
      return null;
    },
    // Exact accounts, IPs and devices of the mock case's events (the core also checks domains and ranges).
    notebook_case_values: (a): CaseValueHit[] => {
      const known = caseValues();
      return find(str(a, "notebookId")).queries.flatMap((q) => {
        const tokens = q.sql.toLowerCase().match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|\b\d{1,3}(?:\.\d{1,3}){3}\b|[0-9a-f]{8}-[0-9a-f-]{27}/g) ?? [];
        const values = [...new Set(tokens.filter((t) => known.has(t)))].sort();
        return values.length ? [{ query_id: q.query_id, title: q.title, values }] : [];
      });
    },
    notebook_export: (a) => {
      find(str(a, "notebookId"));
      if (!str(a, "path")) deps.fail("invalid", "no path (mock)");
      return null;
    },
    notebook_import: (a) => {
      deps.writable();
      if (!str(a, "path")) deps.fail("invalid", "no path (mock)");
      let name = "Imported";
      for (let n = 2; notebooks.some((x) => x.name.toLowerCase() === name.toLowerCase()); n++) name = `Imported (${n})`;
      const nb = create(name);
      add(nb, "-- Imported query\nSELECT count(*) AS events FROM events");
      return nb.id;
    },
  };
}
