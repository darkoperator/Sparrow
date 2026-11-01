import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  isCmdError,
  notebookAddQuery,
  notebookCaseValues,
  notebookCreate,
  notebookDelete,
  notebookDeleteQuery,
  notebookExport,
  notebookImport,
  notebookList,
  notebookMoveQuery,
  notebookQuery,
  notebookRename,
  notebookSaveNew,
  type CaseValueHit,
  type NotebookSummary,
  type QuerySummary,
  type SavedQuery,
} from "../api";
import { open, save } from "../dialog";
import { useDataVersion, useWriteTick } from "../shell/nav";
import { displaySafe } from "../text";

const BUILTIN = "builtin";
const NEW = "__new__";

const FILES = [{ name: "SQL notebook", extensions: ["sql"] }];
/** A file name for a notebook: its name without characters a file name cannot hold. */
const fileName = (name: string) => `${name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, "-").trim() || "notebook"}.sql`;

const message = (e: unknown) => (isCmdError(e) ? e.message : String(e));
/** `agent:claude` → `claude`; null for an analyst's own query. */
const agentOf = (q: QuerySummary) => (q.decided_by?.startsWith("agent:") ? q.decided_by.slice("agent:".length) : null);

interface Props {
  /** The editor's text now: what Save as saves, and what loading would replace. */
  editorText: string;
  /** Put a saved query's text in the editor (it does not run). */
  onLoad: (sql: string) => void;
}

/**
 * The SQL screen's notebooks: the built-in notebook (read-only) and the case's. Clicking a query loads it into the
 * editor; Save as adds the editor's text to a case notebook; case notebooks can be reordered, renamed and pruned here.
 * Agents add queries through the CLI: the list reloads when the case changes and never touches the editor.
 */
export default function NotebookPanel({ editorText, onLoad }: Props) {
  const [list, setList] = useState<NotebookSummary[]>([]);
  const [chosen, setChosen] = useState(BUILTIN);
  // The text last loaded or saved, and which query it is: the editor holding exactly this is not unsaved work.
  const [loaded, setLoaded] = useState<{ queryId: string; sql: string } | null>(null);
  const [pending, setPending] = useState<SavedQuery | null>(null);
  const [saving, setSaving] = useState<{ target: string; name: string } | null>(null);
  const [creating, setCreating] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<{ queryId: string; title: string } | "notebook" | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Why the list did not load: kept apart from a write's error, as the next load that succeeds clears only this one.
  const [listError, setListError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  // The case values an export of one notebook found, waiting for Export anyway or Cancel.
  // `at` is the case's data version when checked: once the case changes the warning no longer holds and is not shown.
  const [leaks, setLeaks] = useState<{ notebookId: string; hits: CaseValueHit[]; at: string } | null>(null);
  // The latest editor text and loaded query, for answers that arrive after a wait; a newer pick, notebook choice or
  // export check makes an older one's answer stale.
  const editorNow = useRef(editorText);
  const loadedNow = useRef(loaded);
  const chosenNow = useRef(chosen);
  useLayoutEffect(() => {
    editorNow.current = editorText;
    loadedNow.current = loaded;
    chosenNow.current = chosen;
  });
  const seq = useRef(0);
  const dataVersion = useDataVersion();
  const writeTick = useWriteTick();
  const caseAt = `${dataVersion}.${writeTick}`;
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  /** Shows a freshly loaded list: whatever loaded it, the list did load. */
  const showList = useCallback((l: NotebookSummary[]) => {
    setListError(null);
    setList(l);
    setChosen((c) => (l.some((n) => n.notebook_id === c) ? c : BUILTIN));
    // A deleted query saves the editor's text nowhere any more: it is unsaved work again, and a Replace waiting on it
    // has nothing to load.
    const present = (id: string) => l.some((n) => n.queries.some((x) => x.query_id === id));
    setLoaded((q) => (q && present(q.queryId) ? q : null));
    setPending((p) => (p && present(p.query_id) ? p : null));
  }, []);

  /** Shows a notebook a write just made, before the list reloads with it: its queries arrive with that reload. */
  const showMade = (id: string, name: string) => {
    setList((l) =>
      l.some((n) => n.notebook_id === id) ? l : [...l, { notebook_id: id, name, builtin: false, queries: [] }],
    );
    setChosen(id);
  };

  useEffect(() => {
    let live = true;
    notebookList().then(
      (l) => live && showList(l),
      (e: unknown) => live && setListError(message(e)),
    );
    return () => {
      live = false;
    };
  }, [dataVersion, writeTick, reload, showList]);

  const notebook = list.find((n) => n.notebook_id === chosen) ?? list[0];
  const caseNotebooks = list.filter((n) => !n.builtin);
  /** Whether `text` is work that loading would lose: anything but the loaded query as loaded (an empty editor is not). */
  const isUnsaved = (text: string, base: { sql: string } | null) => (base ? text !== base.sql : text.trim() !== "");

  /** Run a write; on success reload the list and show `done`, on failure show the backend's words. */
  const write = async (f: () => Promise<unknown>, done?: string) => {
    setError(null);
    setNote(null);
    try {
      await f();
    } catch (e) {
      if (mounted.current) setError(message(e));
      return false;
    }
    if (!mounted.current) return false;
    if (done) setNote(done);
    setReload((n) => n + 1);
    return true;
  };

  const load = (q: SavedQuery) => {
    setPending(null);
    setLoaded({ queryId: q.query_id, sql: q.sql });
    onLoad(q.sql);
  };

  const pick = async (q: QuerySummary) => {
    if (!notebook) return;
    setError(null);
    const mine = ++seq.current;
    let full: SavedQuery;
    try {
      full = await notebookQuery(notebook.notebook_id, q.query_id);
    } catch (e) {
      if (mounted.current && mine === seq.current) setError(message(e));
      return;
    }
    if (!mounted.current || mine !== seq.current) return;
    if (isUnsaved(editorNow.current, loadedNow.current)) setPending(full);
    else load(full);
  };

  const choose = (value: string) => {
    seq.current++;
    setDeleting(null);
    setRenaming(null);
    setLeaks(null);
    setPending(null);
    if (value === NEW) setCreating("");
    else {
      setCreating(null);
      setChosen(value);
    }
  };

  const create = async () => {
    const name = creating?.trim() ?? "";
    if (name === "") return;
    let id = "";
    const ok = await write(async () => {
      id = await notebookCreate(name);
    }, `Created ${name}`);
    if (ok) {
      setCreating(null);
      showMade(id, name);
    }
  };

  const saveAs = async () => {
    if (!saving) return;
    const text = editorText;
    const newName = saving.name.trim();
    let target = saving.target;
    let queryId = "";
    const ok = await write(async () => {
      if (target === NEW) {
        const made = await notebookSaveNew(newName, text);
        target = made.notebook_id;
        queryId = made.query_id;
      } else {
        queryId = await notebookAddQuery(target, text);
      }
    });
    if (!ok) return;
    const name = target === saving.target ? (list.find((n) => n.notebook_id === target)?.name ?? "") : newName;
    setNote(`Saved to ${name}`);
    setSaving(null);
    if (target === saving.target) setChosen(target);
    else showMade(target, name);
    setLoaded({ queryId, sql: text });
  };

  const openSaveAs = () => {
    setError(null);
    setSaving({ target: caseNotebooks[0]?.notebook_id ?? NEW, name: "" });
  };

  const rename = async () => {
    if (!notebook || renaming === null || renaming.trim() === "") return;
    const name = renaming.trim();
    if (await write(() => notebookRename(notebook.notebook_id, name), `Renamed to ${name}`)) setRenaming(null);
  };

  const confirmDelete = async () => {
    if (!notebook || deleting === null) return;
    const gone = deleting === "notebook" ? notebook.queries.map((q) => q.query_id) : [deleting.queryId];
    const ok =
      deleting === "notebook"
        ? await write(() => notebookDelete(notebook.notebook_id), `Deleted ${notebook.name}`)
        : await write(() => notebookDeleteQuery(deleting.queryId));
    if (!ok) return;
    setDeleting(null);
    // Known gone now, before the list reloads: the editor's text is unsaved work again.
    setLoaded((q) => (q && gone.includes(q.queryId) ? null : q));
    setPending((p) => (p && gone.includes(p.query_id) ? null : p));
  };

  /** Writes the file; `accepted` are the case values the analyst saw and accepted (the backend refuses any other). */
  const writeFile = async (nb: NotebookSummary, accepted: string[]) => {
    setLeaks(null);
    const path = await save({ defaultPath: fileName(nb.name), filters: FILES });
    if (!path || !mounted.current) return;
    await write(() => notebookExport(nb.notebook_id, path, accepted), `Exported ${nb.name} to ${path}`);
  };

  const exportNotebook = async () => {
    if (!notebook) return;
    setError(null);
    setNote(null);
    setLeaks(null);
    const mine = ++seq.current;
    const id = notebook.notebook_id;
    let hits: CaseValueHit[];
    try {
      hits = await notebookCaseValues(id);
    } catch (e) {
      if (mounted.current && mine === seq.current) setError(message(e));
      return;
    }
    // A newer action or another notebook chosen meanwhile: this check is for what is no longer shown.
    if (!mounted.current || mine !== seq.current || chosenNow.current !== id) return;
    if (hits.length > 0) setLeaks({ notebookId: id, hits, at: caseAt });
    else await writeFile(notebook, []);
  };

  const importNotebook = async () => {
    setError(null);
    setNote(null);
    const path = await open({ filters: FILES });
    if (typeof path !== "string" || !mounted.current) return;
    let id: string;
    let fresh: NotebookSummary[];
    try {
      id = await notebookImport(path);
      fresh = await notebookList();
    } catch (e) {
      if (mounted.current) setError(message(e));
      return;
    }
    if (!mounted.current) return;
    showList(fresh);
    setChosen(id);
    setNote(`Imported as ${fresh.find((n) => n.notebook_id === id)?.name ?? "a new notebook"}`);
  };

  const saveDisabled =
    !saving || editorText.trim() === "" || (saving.target === NEW && saving.name.trim() === "");

  return (
    <div className="notebook-panel">
      <div className="notebook-picker">
        <select
          className="input"
          aria-label="Notebook"
          value={creating !== null ? NEW : (notebook?.notebook_id ?? BUILTIN)}
          onChange={(e) => choose(e.target.value)}
        >
          {list.map((n) => (
            <option key={n.notebook_id} value={n.notebook_id}>
              {displaySafe(n.name)}
            </option>
          ))}
          <option value={NEW}>New notebook…</option>
        </select>
        {notebook && !notebook.builtin && creating === null && (
          <>
            <button type="button" className="btn btn-ghost btn-small" onClick={() => setRenaming(notebook.name)}>
              Rename notebook
            </button>
            <button type="button" className="btn btn-ghost btn-small" onClick={() => setDeleting("notebook")}>
              Delete notebook
            </button>
          </>
        )}
      </div>

      {creating !== null && (
        <form
          className="notebook-form"
          onSubmit={(e) => {
            e.preventDefault();
            void create();
          }}
        >
          <input
            className="input"
            aria-label="New notebook name"
            value={creating}
            autoFocus
            onChange={(e) => setCreating(e.target.value)}
          />
          <button type="submit" className="btn btn-small" disabled={creating.trim() === ""}>
            Create
          </button>
          <button type="button" className="btn btn-ghost btn-small" onClick={() => setCreating(null)}>
            Cancel
          </button>
        </form>
      )}

      {renaming !== null && (
        <form
          className="notebook-form"
          onSubmit={(e) => {
            e.preventDefault();
            void rename();
          }}
        >
          <input
            className="input"
            aria-label="Notebook name"
            value={renaming}
            autoFocus
            onChange={(e) => setRenaming(e.target.value)}
          />
          <button type="submit" className="btn btn-small" disabled={renaming.trim() === ""}>
            Rename
          </button>
          <button type="button" className="btn btn-ghost btn-small" onClick={() => setRenaming(null)}>
            Cancel
          </button>
        </form>
      )}

      {deleting !== null && notebook && (
        <div className="notebook-confirm" role="group" aria-label="Confirm delete">
          <span>
            {deleting === "notebook"
              ? `Delete notebook "${displaySafe(notebook.name)}" and its ${notebook.queries.length} ${
                  notebook.queries.length === 1 ? "query" : "queries"
                }?`
              : `Delete "${displaySafe(deleting.title)}"?`}
          </span>
          <button type="button" className="btn btn-small" onClick={() => void confirmDelete()}>
            Delete
          </button>
          <button type="button" className="btn btn-ghost btn-small" onClick={() => setDeleting(null)}>
            Cancel
          </button>
        </div>
      )}

      {pending !== null && (
        <div className="notebook-confirm" role="group" aria-label="Replace the editor's text">
          <span>Replace the editor's text?</span>
          <button type="button" className="btn btn-small" onClick={() => load(pending)}>
            Replace
          </button>
          <button type="button" className="btn btn-ghost btn-small" onClick={() => setPending(null)}>
            Keep editing
          </button>
        </div>
      )}

      {leaks !== null && notebook && leaks.notebookId === notebook.notebook_id && leaks.at === caseAt && (
        <div className="notebook-confirm" role="group" aria-label="Case values in the export">
          <span>These queries contain values from this case:</span>
          <ul className="notebook-leaks">
            {leaks.hits.map((h) => (
              <li key={h.query_id}>{displaySafe(`${h.title}: ${h.values.join(", ")}`)}</li>
            ))}
          </ul>
          <button type="button" className="btn btn-small" onClick={() => void writeFile(notebook, [...new Set(leaks.hits.flatMap((h) => h.values))])}>
            Export anyway
          </button>
          <button type="button" className="btn btn-ghost btn-small" onClick={() => setLeaks(null)}>
            Cancel
          </button>
        </div>
      )}

      {[listError, error].map(
        (e, i) =>
          e !== null && (
            <p key={i} role="alert" className="notebook-error">
              {displaySafe(e)}
            </p>
          ),
      )}
      {note !== null && <p className="notebook-note">{displaySafe(note)}</p>}

      <ol className="notebook-queries">
        {notebook?.queries.map((q, i) => {
          const agent = agentOf(q);
          const edited = loaded?.queryId === q.query_id && editorText !== loaded.sql;
          const last = i === notebook.queries.length - 1;
          return (
            <li key={q.query_id} className={loaded?.queryId === q.query_id ? "notebook-row is-loaded" : "notebook-row"}>
              <button type="button" className="notebook-load" onClick={() => void pick(q)}>
                <span className="notebook-title">{displaySafe(q.title)}</span>
                {q.placeholders.map((p) => (
                  <span key={p} className="chip notebook-placeholder">
                    [{displaySafe(p)}]
                  </span>
                ))}
              </button>
              {(agent !== null || edited) && (
                <span className="notebook-meta">
                  {agent !== null && <span>by {displaySafe(agent)}</span>}
                  {edited && <span className="notebook-edited">edited</span>}
                </span>
              )}
              {!notebook.builtin && (
                <span className="notebook-row-actions">
                  {i > 0 && (
                    <button
                      type="button"
                      className="btn btn-ghost btn-small"
                      aria-label={`Move "${q.title}" up`}
                      onClick={() => void write(() => notebookMoveQuery(q.query_id, q.position - 1))}
                    >
                      ↑
                    </button>
                  )}
                  {!last && (
                    <button
                      type="button"
                      className="btn btn-ghost btn-small"
                      aria-label={`Move "${q.title}" down`}
                      onClick={() => void write(() => notebookMoveQuery(q.query_id, q.position + 1))}
                    >
                      ↓
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn btn-ghost btn-small"
                    aria-label={`Delete "${q.title}"`}
                    onClick={() => setDeleting({ queryId: q.query_id, title: q.title })}
                  >
                    ×
                  </button>
                </span>
              )}
            </li>
          );
        })}
      </ol>
      {notebook && notebook.queries.length === 0 && (
        <p className="notebook-empty">No queries yet. Write one in the editor and use Save as.</p>
      )}

      <div className="notebook-files">
        <button type="button" className="btn btn-ghost btn-small" disabled={!notebook} onClick={() => void exportNotebook()}>
          Export…
        </button>
        <button type="button" className="btn btn-ghost btn-small" onClick={() => void importNotebook()}>
          Import…
        </button>
      </div>
      <div className="notebook-save">
        {saving === null ? (
          <button type="button" className="btn btn-small" disabled={editorText.trim() === ""} onClick={openSaveAs}>
            Save as…
          </button>
        ) : (
          <form
            className="notebook-form"
            onSubmit={(e) => {
              e.preventDefault();
              void saveAs();
            }}
          >
            <select
              className="input"
              aria-label="Save to"
              value={saving.target}
              onChange={(e) => setSaving({ ...saving, target: e.target.value })}
            >
              {caseNotebooks.map((n) => (
                <option key={n.notebook_id} value={n.notebook_id}>
                  {displaySafe(n.name)}
                </option>
              ))}
              <option value={NEW}>New notebook…</option>
            </select>
            {saving.target === NEW && (
              <input
                className="input"
                aria-label="New notebook name"
                value={saving.name}
                onChange={(e) => setSaving({ ...saving, name: e.target.value })}
              />
            )}
            <button type="submit" className="btn btn-primary btn-small" disabled={saveDisabled}>
              Save
            </button>
            <button type="button" className="btn btn-ghost btn-small" onClick={() => setSaving(null)}>
              Cancel
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
