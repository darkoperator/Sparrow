import { autocompletion, closeCompletion } from "@codemirror/autocomplete";
import { PostgreSQL, sql } from "@codemirror/lang-sql";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { linter, lintGutter, type Action, type Diagnostic } from "@codemirror/lint";
import { Compartment, EditorState, Prec } from "@codemirror/state";
import { EditorView, keymap, placeholder, tooltips } from "@codemirror/view";
import { basicSetup } from "codemirror";
import { tags as t } from "@lezer/highlight";
import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";
import type { SqlCheck, TableInfo } from "../api";
import { keywordCompletions, schemaCompletions } from "./completion";

export interface SqlEditorHandle {
  /** Replace the selection with this text and put the cursor after it. */
  insert: (text: string) => void;
  /** Close the completion popup, if open. */
  closeCompletion: () => void;
}

/** What the check says outside the editor: the check itself refused, or an error with no position to mark. */
export interface CheckNote {
  unavailable: boolean;
  text: string;
}

interface Props {
  tables: readonly TableInfo[];
  onChange: (text: string) => void;
  onRun: () => void;
  /** `sql_check`; a rejection is the check itself being refused, reported through `onCheckNote`. */
  check: (text: string) => Promise<SqlCheck>;
  onCheckNote: (note: CheckNote | null) => void;
}

const LINT_DELAY_MS = 500;

// The console theme: every colour is a theme.css token, so the editor matches the rest of the app.
const theme = EditorView.theme(
  {
    "&": {
      color: "var(--text)",
      backgroundColor: "var(--bg)",
      border: "1px solid var(--line-strong)",
      borderRadius: "8px",
      fontSize: "13px",
    },
    "&.cm-focused": { outline: "2px solid var(--accent)", outlineOffset: "1px" },
    ".cm-scroller": { fontFamily: "var(--font-mono)", lineHeight: "20px", minHeight: "10em", maxHeight: "24em" },
    ".cm-content": { caretColor: "var(--accent)", padding: "10px 0" },
    ".cm-cursor, .cm-dropCursor": { borderLeftColor: "var(--accent)" },
    "&.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, .cm-selectionBackground, ::selection": {
      backgroundColor: "var(--accent-soft)",
    },
    ".cm-activeLine": { backgroundColor: "transparent" },
    ".cm-gutters": { backgroundColor: "transparent", color: "var(--faint)", border: "0" },
    ".cm-activeLineGutter": { backgroundColor: "transparent", color: "var(--muted)" },
    ".cm-placeholder": { color: "var(--faint)" },
    ".cm-matchingBracket, &.cm-focused .cm-matchingBracket": { backgroundColor: "var(--raised-2)", outline: "0" },
    ".cm-tooltip": {
      backgroundColor: "var(--card)",
      color: "var(--text)",
      border: "1px solid var(--line-strong)",
      borderRadius: "6px",
      boxShadow: "var(--shadow-pop)",
    },
    ".cm-tooltip-autocomplete > ul": { fontFamily: "var(--font-mono)", fontSize: "12px" },
    ".cm-tooltip-autocomplete > ul > li[aria-selected]": { backgroundColor: "var(--accent-soft)", color: "var(--text)" },
    ".cm-completionDetail": { color: "var(--faint)" },
    ".cm-diagnostic-error": { borderLeftColor: "var(--mal)" },
    ".cm-lintRange-error": { backgroundImage: "none", textDecoration: "underline wavy var(--mal)" },
  },
  { dark: true },
);

// Syntax colours from the design's syntax tokens.
const highlight = HighlightStyle.define([
  { tag: [t.keyword, t.operatorKeyword, t.bool, t.null], color: "var(--syn-kw)" },
  { tag: [t.string, t.special(t.string)], color: "var(--syn-str)" },
  { tag: [t.number, t.atom], color: "var(--syn-num)" },
  { tag: [t.standard(t.name), t.typeName, t.function(t.variableName)], color: "var(--syn-key)" },
  { tag: [t.comment, t.lineComment, t.blockComment], color: "var(--faint)", fontStyle: "italic" },
  { tag: [t.name, t.propertyName, t.operator, t.punctuation], color: "var(--text)" },
]);

/** CodeMirror 6 SQL editor: keywords, schema completion, and `sql_check` error marks with quick-fixes. */
const SqlEditor = forwardRef<SqlEditorHandle, Props>(function SqlEditor(props, ref) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const completion = useRef(new Compartment());
  // The latest props, read by the long-lived editor extensions.
  const latest = useRef(props);
  latest.current = props;
  // Only the newest check's result applies.
  const checkSeq = useRef(0);

  useImperativeHandle(ref, () => ({
    closeCompletion() {
      if (view.current) closeCompletion(view.current);
    },
    insert(text) {
      const v = view.current;
      if (!v) return;
      const { from, to } = v.state.selection.main;
      v.dispatch({ changes: { from, to, insert: text }, selection: { anchor: from + text.length }, userEvent: "input" });
      v.focus();
    },
  }));

  useEffect(() => {
    const source = async (v: EditorView): Promise<Diagnostic[]> => {
      const text = v.state.doc.toString();
      const seq = ++checkSeq.current;
      if (text.trim() === "") {
        latest.current.onCheckNote(null);
        return [];
      }
      let result: SqlCheck;
      try {
        result = await latest.current.check(text);
      } catch (e) {
        if (seq === checkSeq.current) {
          const m = typeof e === "object" && e !== null && "message" in e ? String((e as { message: unknown }).message) : String(e);
          latest.current.onCheckNote({ unavailable: true, text: m });
        }
        return [];
      }
      if (seq !== checkSeq.current) return [];
      latest.current.onCheckNote(null);
      if (result.ok) return [];
      const { error } = result;
      const len = v.state.doc.length;
      const { from, to } = error;
      if (from === undefined || !Number.isInteger(from) || from < 0 || from > len) {
        // Nothing to mark: say it as text, without quick-fixes (they would replace a range we do not know).
        const hint = error.suggestions.length > 0 ? `\nDid you mean: ${error.suggestions.join(", ")}` : "";
        latest.current.onCheckNote({ unavailable: false, text: error.message + hint });
        return [];
      }
      const end = to !== undefined && Number.isInteger(to) ? Math.min(Math.max(to, from), len) : Math.min(from + 1, len);
      const actions: Action[] = error.suggestions.map((s) => ({
        name: s,
        apply: (view, f, t) => view.dispatch({ changes: { from: f, to: t, insert: s } }),
      }));
      return [{ from, to: end, severity: "error", message: error.message, actions }];
    };

    const runKey = (): boolean => {
      latest.current.onRun();
      return true;
    };
    const seq = checkSeq;
    const state = EditorState.create({
      doc: "",
      extensions: [
        basicSetup,
        sql({ dialect: PostgreSQL, upperCaseKeywords: true }),
        completion.current.of(autocompletion({ override: [keywordCompletions()] })),
        linter(source, { delay: LINT_DELAY_MS }),
        lintGutter(),
        // Tooltips live in <body>, fixed: a first-line tooltip is not clipped by the editor or the window top and
        // flips below when there is no room above.
        tooltips({ parent: document.body, position: "fixed" }),
        theme,
        syntaxHighlighting(highlight),
        placeholder("SELECT … (one read-only statement; Cmd/Ctrl+Enter runs it)"),
        Prec.highest(keymap.of([
            { key: "Ctrl-Enter", run: runKey, preventDefault: true },
            { key: "Meta-Enter", run: runKey, preventDefault: true },
          ])),
        EditorView.contentAttributes.of({ "aria-label": "SQL" }),
        EditorView.updateListener.of((u) => {
          if (u.docChanged) {
            // Whatever a check was about to say concerns the old text.
            seq.current++;
            latest.current.onCheckNote(null);
            latest.current.onChange(u.state.doc.toString());
          }
        }),
      ],
    });
    const v = new EditorView({ state, parent: host.current! });
    view.current = v;
    return () => {
      seq.current++;
      v.destroy();
      view.current = null;
    };
  }, []);

  useEffect(() => {
    view.current?.dispatch({
      effects: completion.current.reconfigure(
        autocompletion({ override: [schemaCompletions(props.tables), keywordCompletions()] }),
      ),
    });
  }, [props.tables]);

  return <div ref={host} className="sql-editor" />;
});

export default SqlEditor;
