import { EditorView } from "@codemirror/view";
import { CompletionContext } from "@codemirror/autocomplete";
import { EditorState } from "@codemirror/state";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { schema as schemaFixture, sqlResult as sqlResultFixture } from "../test/fixtures";
import type { QueryResult } from "../api";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  sqlSchema: vi.fn(),
  sqlRun: vi.fn(),
  queryCancel: vi.fn(),
  sqlCheck: vi.fn(),
  sqlExportCsv: vi.fn(),
}));
vi.mock("../dialog", () => ({ save: vi.fn(), open: vi.fn() }));

import * as api from "../api";
import * as dialog from "../dialog";
import { schemaCompletions } from "./completion";
import Sql from "./Sql";

const m = {
  schema: vi.mocked(api.sqlSchema),
  run: vi.mocked(api.sqlRun),
  cancel: vi.mocked(api.queryCancel),
  check: vi.mocked(api.sqlCheck),
  exportCsv: vi.mocked(api.sqlExportCsv),
  save: vi.mocked(dialog.save),
};
let result: QueryResult;

beforeEach(() => {
  for (const f of Object.values(m)) f.mockReset();
  result = sqlResultFixture();
  m.schema.mockResolvedValue(schemaFixture());
  m.run.mockImplementation(async () => result);
  m.cancel.mockResolvedValue(null);
  m.check.mockResolvedValue({ ok: true });
  m.save.mockResolvedValue("/out/q.csv");
});

async function setup() {
  const user = userEvent.setup();
  render(<Sql />);
  await screen.findByRole("button", { name: "signins" });
  return user;
}

const QUERY = "SELECT user_upn, ip, count(*) n FROM signins GROUP BY ALL";
const content = () => screen.getByRole("textbox", { name: "SQL" });
const view = () => EditorView.findFromDOM(content().closest(".cm-editor") as HTMLElement)!;
const text = () => view().state.doc.toString();
/** Replace the whole document, as typing would (CodeMirror reads its own DOM, which jsdom cannot type into). */
const typeSql = (t: string, cursor = t.length) =>
  act(() => view().dispatch({ changes: { from: 0, to: view().state.doc.length, insert: t }, selection: { anchor: cursor } }));
const cmdEnter = () => fireEvent.keyDown(content(), { key: "Enter", metaKey: true });

describe("Sql", () => {
  it("runs the typed query with the default limit, then the chosen one", async () => {
    const user = await setup();
    expect(screen.getByRole("button", { name: "Run" })).toBeDisabled();
    await typeSql(QUERY);
    await user.click(screen.getByRole("button", { name: "Run" }));
    expect(m.run).toHaveBeenLastCalledWith(QUERY, 1000, expect.any(String), 0);
    // The result is shown in the grid, every recorded row.
    const table = await screen.findByRole("table");
    expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(result.columns);
    const first = String(result.rows[0][0]);
    const same = result.rows.filter((r) => String(r[0]) === first).length;
    expect(within(table).getAllByText(first)).toHaveLength(same);
    expect(screen.getByText(`${result.rows.length} rows`)).toBeInTheDocument();
    expect(screen.queryByText(/raise the limit/i)).toBeNull();

    await user.selectOptions(screen.getByRole("combobox", { name: "Row limit" }), "10000");
    await user.click(screen.getByRole("button", { name: "Run" }));
    expect(m.run).toHaveBeenLastCalledWith(QUERY, 10000, expect.any(String), 0);
    expect(m.run).toHaveBeenCalledTimes(2);
    // A fresh query id per run.
    const [a, b] = m.run.mock.calls.map((c) => c[2]);
    expect(a).toBeTruthy();
    expect(a).not.toBe(b);
  });

  it("offers no limit above 10000", async () => {
    await setup();
    const values = within(screen.getByRole("combobox", { name: "Row limit" }))
      .getAllByRole("option")
      .map((o) => Number((o as HTMLOptionElement).value));
    expect(values.length).toBeGreaterThan(1);
    expect(Math.max(...values)).toBe(10000);
    expect((screen.getByRole("combobox", { name: "Row limit" }) as HTMLSelectElement).value).toBe("1000");
  });

  it("Cmd+Enter and Ctrl+Enter run the query; plain Enter does not", async () => {
    const user = await setup();
    await typeSql("SELECT 1");
    // Plain Enter is the editor's: a new line, no run.
    await user.type(content(), "{Enter}");
    expect(m.run).not.toHaveBeenCalled();
    expect(text()).toContain("\n");
    cmdEnter();
    expect(m.run).toHaveBeenCalledTimes(1);
    expect(m.run).toHaveBeenLastCalledWith(text(), 1000, expect.any(String), 0);
    await screen.findByRole("table");
    fireEvent.keyDown(content(), { key: "Enter", ctrlKey: true });
    expect(m.run).toHaveBeenCalledTimes(2);
  });

  it("says when the result was truncated at the limit", async () => {
    result = { ...result, truncated: true };
    const user = await setup();
    await typeSql("SELECT * FROM signins");
    await user.click(screen.getByRole("button", { name: "Run" }));
    expect(await screen.findByText(/first 1,000 rows.*raise the limit/i)).toBeInTheDocument();
  });

  it("Cancel interrupts the running query and says it was cancelled", async () => {
    let reject: (e: unknown) => void = () => {};
    m.run.mockImplementation(() => new Promise<QueryResult>((_, rj) => (reject = rj)));
    const user = await setup();
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
    await typeSql("SELECT count(*) FROM range(10000000000)");
    await user.click(screen.getByRole("button", { name: "Run" }));
    expect(screen.getByRole("button", { name: "Run" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    // Cancel names the running query, nothing else.
    expect(m.cancel).toHaveBeenCalledExactlyOnceWith(m.run.mock.calls[0][2]);
    await act(async () => reject({ kind: "interrupted", message: "INTERRUPT Error: Interrupted!" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Query cancelled.");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
    expect(screen.getByRole("button", { name: "Run" })).toBeEnabled();
  });

  it("leaving the screen while a query runs cancels it and ignores the late result", async () => {
    let resolve: (r: QueryResult) => void = () => {};
    m.run.mockImplementation(() => new Promise<QueryResult>((rs) => (resolve = rs)));
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const user = userEvent.setup();
    const view = render(<Sql />);
    await screen.findByRole("button", { name: "signins" });
    expect(screen.getByText("Leaving this screen cancels a running query.")).toBeInTheDocument();
    await typeSql("SELECT count(*) FROM range(10000000000)");
    await user.click(screen.getByRole("button", { name: "Run" }));
    expect(m.cancel).not.toHaveBeenCalled();
    view.unmount();
    expect(m.cancel).toHaveBeenCalledExactlyOnceWith(m.run.mock.calls[0][2]);
    await act(async () => resolve(result));
    expect(errors).not.toHaveBeenCalled();
    errors.mockRestore();
  });

  it("leaving the screen with no query running cancels nothing", async () => {
    const user = await setup();
    await typeSql("SELECT 1");
    await user.click(screen.getByRole("button", { name: "Run" }));
    await screen.findByRole("table");
    cleanup();
    expect(m.cancel).not.toHaveBeenCalled();
  });

  it("shows the backend's refusal verbatim, escaped, and clears the old result", async () => {
    const user = await setup();
    await typeSql("SELECT 1");
    await user.click(screen.getByRole("button", { name: "Run" }));
    await screen.findByRole("table");
    const message = "query accepts one SELECT statement only: <b>DELETE</b>‮ FROM x";
    m.run.mockRejectedValue({ kind: "invalid", message });
    await user.click(screen.getByRole("button", { name: "Run" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("query accepts one SELECT statement only: <b>DELETE</b>\\u{202E} FROM x");
    expect(alert.querySelector("b")).toBeNull();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("the schema sidebar lists tables and views with their columns, types and comments", async () => {
    const user = await setup();
    const tables = schemaFixture();
    for (const t of tables) expect(screen.getByRole("button", { name: t.name })).toBeInTheDocument();
    const views = tables.filter((t) => t.kind === "view").length;
    expect(views).toBeGreaterThan(0);
    expect(screen.getAllByText("view")).toHaveLength(views);
    expect(screen.queryByRole("button", { name: "user_upn" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "Show columns of signins" }));
    const signins = tables.find((t) => t.name === "signins")!;
    const cols = screen.getByRole("list", { name: "Columns of signins" });
    for (const c of signins.columns) expect(within(cols).getByRole("button", { name: c.name })).toBeInTheDocument();
    const upn = signins.columns.find((c) => c.name === "user_upn")!;
    expect(upn.comment).toBeTruthy();
    expect(within(cols).getByText(upn.comment!)).toBeInTheDocument();
    const tz = signins.columns.filter((c) => c.type === "TIMESTAMP WITH TIME ZONE").length;
    expect(tz).toBeGreaterThan(0);
    expect(within(cols).getAllByText("TIMESTAMP WITH TIME ZONE")).toHaveLength(tz);
  });

  it("clicking a table or column name inserts it at the cursor", async () => {
    const user = await setup();
    await typeSql("SELECT  FROM ");
    await user.click(screen.getByRole("button", { name: "signins" }));
    expect(text()).toBe("SELECT  FROM signins");
    // Put the cursor after "SELECT " and insert a column there.
    act(() => view().dispatch({ selection: { anchor: 7 } }));
    await user.click(screen.getByRole("button", { name: "Show columns of signins" }));
    await user.click(screen.getByRole("button", { name: "user_upn" }));
    expect(text()).toBe("SELECT user_upn FROM signins");
  });

  it("a name that is not a plain identifier is inserted quoted", async () => {
    m.schema.mockResolvedValue([
      {
        name: "signins",
        comment: null,
        kind: "table",
        columns: [{ name: 'odd "col"', type: "VARCHAR", comment: null }],
      },
    ]);
    const user = await setup();
    await user.click(screen.getByRole("button", { name: "Show columns of signins" }));
    await user.click(screen.getByRole("button", { name: 'odd "col"' }));
    expect(text()).toBe('"odd ""col"""');
  });

  it("a schema error is shown, and the editor still works", async () => {
    m.schema.mockRejectedValue({ kind: "read_only", message: "SQL needs a writable case" });
    render(<Sql />);
    expect(await screen.findByRole("alert")).toHaveTextContent("SQL needs a writable case");
    await typeSql("SELECT 1");
    expect(screen.getByRole("button", { name: "Run" })).toBeEnabled();
  });

  describe("completion", () => {
    const source = () => schemaCompletions(schemaFixture());
    const complete = async (doc: string, explicit = true) => {
      const state = EditorState.create({ doc });
      return source()(new CompletionContext(state, doc.length, explicit));
    };

    it("lists a table with its kind and its columns with their types", async () => {
      const tables = schemaFixture();
      const signins = tables.find((t) => t.name === "signins")!;
      const r = (await complete("SELECT * FROM sig"))!;
      expect(r.from).toBe("SELECT * FROM ".length);
      const table = r.options.find((o) => o.label === "signins")!;
      expect(table.detail).toBe(signins.kind);
      const upn = signins.columns.find((c) => c.name === "user_upn")!;
      const col = r.options.find((o) => o.label === "user_upn")!;
      expect(col.detail).toContain(upn.type);
      expect(signins.columns.length).toBeGreaterThan(1);
    });

    it("after `table.` offers only that table's columns, with types", async () => {
      const signins = schemaFixture().find((t) => t.name === "signins")!;
      const r = (await complete("SELECT signins.u"))!;
      expect(r.from).toBe("SELECT signins.".length);
      expect(r.options.map((o) => o.label)).toEqual(signins.columns.map((c) => c.name));
      expect(r.options.map((o) => o.detail)).toEqual(signins.columns.map((c) => c.type));
    });

    it("quotes names that are not plain identifiers when applied", async () => {
      const src = schemaCompletions([
        { name: "t", comment: null, kind: "table", columns: [{ name: "odd col", type: "VARCHAR", comment: null }] },
      ]);
      const r = (await src(new CompletionContext(EditorState.create({ doc: "o" }), 1, true)))!;
      expect(r.options.find((o) => o.label === "odd col")!.apply).toBe('"odd col"');
    });

    it("offers nothing on an unrelated qualifier or an empty implicit position", async () => {
      expect(await complete("SELECT nosuch.x")).toBeNull();
      expect(await complete("SELECT ", false)).toBeNull();
    });
  });

  describe("error marks", () => {
    const BAD = "SELECT frm signins";
    const error = {
      message: 'Parser Error: syntax error at or near "signins"',
      kind: "syntax" as const,
      from: 11,
      to: 18,
      suggestions: ["FROM", "from_unixtime"],
    };
    const marks = () => document.querySelectorAll(".cm-lintRange-error");

    it("checks 500 ms after the last edit and underlines from..to with the message and a fix per suggestion", async () => {
      m.check.mockResolvedValue({ ok: false, error });
      await setup();
      const t0 = Date.now();
      await typeSql(BAD);
      await new Promise((r) => setTimeout(r, 300));
      expect(m.check).not.toHaveBeenCalled();
      await waitFor(() => expect(m.check).toHaveBeenCalledExactlyOnceWith(BAD), { timeout: 3000 });
      expect(Date.now() - t0).toBeGreaterThanOrEqual(450);
      await waitFor(() => expect(marks()).toHaveLength(1));
      expect(marks()[0].textContent).toBe(BAD.slice(error.from, error.to));
      const diags = await import("@codemirror/lint").then((l) => {
        const out: { from: number; to: number; message: string; actions?: readonly { name: string }[] }[] = [];
        l.forEachDiagnostic(view().state, (d, from, to) => out.push({ ...d, from, to }));
        return out;
      });
      expect(diags).toHaveLength(1);
      expect(diags[0]).toMatchObject({ from: 11, to: 18, message: error.message });
      expect(diags[0].actions!.map((a) => a.name)).toEqual(error.suggestions);
    });

    it("a quick-fix replaces exactly the marked range", async () => {
      m.check.mockResolvedValue({ ok: false, error });
      await setup();
      await typeSql(BAD);
      await waitFor(() => expect(marks()).toHaveLength(1), { timeout: 3000 });
      const { forEachDiagnostic } = await import("@codemirror/lint");
      let fix: (() => void) | undefined;
      forEachDiagnostic(view().state, (d, from, to) => {
        fix = () => d.actions![0].apply(view(), from, to);
      });
      act(() => fix!());
      expect(text()).toBe("SELECT frm FROM");
    });

    it("drops a stale check result: only the latest text's answer applies", async () => {
      let first: (v: api.SqlCheck) => void = () => {};
      m.check.mockImplementationOnce(() => new Promise((rs) => (first = rs)));
      m.check.mockResolvedValueOnce({ ok: true });
      await setup();
      await typeSql(BAD);
      await waitFor(() => expect(m.check).toHaveBeenCalledTimes(1), { timeout: 3000 });
      await typeSql("SELECT 1");
      await waitFor(() => expect(m.check).toHaveBeenCalledTimes(2), { timeout: 3000 });
      await act(async () => first({ ok: false, error }));
      expect(m.check).toHaveBeenLastCalledWith("SELECT 1");
      expect(marks()).toHaveLength(0);
    });

    it("does not check an empty editor", async () => {
      await setup();
      await typeSql("   ");
      await new Promise((r) => setTimeout(r, 800));
      expect(m.check).not.toHaveBeenCalled();
    });

    it("a refused check is shown once, as a message and not as a mark", async () => {
      m.check.mockRejectedValue({ kind: "read_only", message: "SQL needs a writable case" });
      await setup();
      await typeSql("SELECT 1");
      const alert = await screen.findByRole("alert", {}, { timeout: 3000 });
      expect(alert).toHaveTextContent("SQL check unavailable: SQL needs a writable case");
      expect(screen.getAllByRole("alert")).toHaveLength(1);
      expect(marks()).toHaveLength(0);
    });
  });

  describe("next page", () => {
    const page = (n: number, start = 0, ordered = true): QueryResult => ({
      columns: ["n"],
      rows: Array.from({ length: n }, (_, i) => [start + i]),
      truncated: false,
      ordered,
    });
    const run = async (user: ReturnType<typeof userEvent.setup>) => {
      await typeSql("SELECT n FROM t");
      await user.selectOptions(screen.getByRole("combobox", { name: "Row limit" }), "100");
      await user.click(screen.getByRole("button", { name: "Run" }));
      await screen.findByText("100 rows");
    };

    it("appends the next page at the loaded offset, and disables on a short page", async () => {
      m.run.mockResolvedValueOnce(page(100)).mockResolvedValueOnce(page(100, 100)).mockResolvedValueOnce(page(30, 200));
      const user = await setup();
      expect(screen.queryByRole("button", { name: /load next/i })).toBeNull();
      await run(user);
      const next = screen.getByRole("button", { name: "Load next 100" });
      expect(next).toBeEnabled();
      await user.click(next);
      await screen.findByText("200 rows");
      expect(m.run).toHaveBeenLastCalledWith("SELECT n FROM t", 100, expect.any(String), 100);
      await user.click(screen.getByRole("button", { name: "Load next 100" }));
      await screen.findByText("230 rows");
      expect(m.run).toHaveBeenLastCalledWith("SELECT n FROM t", 100, expect.any(String), 200);
      expect(screen.getByRole("button", { name: "Load next 100" })).toBeDisabled();
      const ids = m.run.mock.calls.map((c) => c[2]);
      expect(new Set(ids).size).toBe(3);
    });

    it("pages with the SQL that ran, not the edited text", async () => {
      m.run.mockResolvedValueOnce(page(100)).mockResolvedValueOnce(page(5, 100));
      const user = await setup();
      await run(user);
      await typeSql("SELECT 2");
      await user.click(screen.getByRole("button", { name: "Load next 100" }));
      expect(m.run).toHaveBeenLastCalledWith("SELECT n FROM t", 100, expect.any(String), 100);
    });

    it("says so when the query has no ORDER BY, and not when it has", async () => {
      m.run.mockResolvedValueOnce(page(100, 0, false));
      const user = await setup();
      await run(user);
      expect(screen.getByText("No ORDER BY — pages may overlap or skip rows.")).toBeInTheDocument();
      m.run.mockResolvedValueOnce(page(100, 0, true));
      await user.click(screen.getByRole("button", { name: "Run" }));
      await screen.findByText("100 rows");
      expect(screen.queryByText(/No ORDER BY/)).toBeNull();
    });

    it("a new Run starts again at offset 0", async () => {
      m.run.mockResolvedValueOnce(page(100)).mockResolvedValueOnce(page(100, 100)).mockResolvedValueOnce(page(100));
      const user = await setup();
      await run(user);
      await user.click(screen.getByRole("button", { name: "Load next 100" }));
      await screen.findByText("200 rows");
      await user.click(screen.getByRole("button", { name: "Run" }));
      await screen.findByText("100 rows");
      expect(m.run).toHaveBeenLastCalledWith("SELECT n FROM t", 100, expect.any(String), 0);
    });

    it("a failed next page keeps the rows and shows the error", async () => {
      m.run.mockResolvedValueOnce(page(100));
      const user = await setup();
      await run(user);
      m.run.mockRejectedValueOnce({ kind: "invalid", message: "boom" });
      await user.click(screen.getByRole("button", { name: "Load next 100" }));
      expect(await screen.findByRole("alert")).toHaveTextContent("boom");
      expect(screen.getByText("100 rows")).toBeInTheDocument();
    });
  });

  describe("CSV export", () => {
    it("asks for a path (default sparrow-query.csv) and exports the current SQL with a fresh id", async () => {
      m.exportCsv.mockResolvedValue({ rows: 12345, capped: false });
      const user = await setup();
      expect(screen.getByRole("button", { name: "Export CSV…" })).toBeDisabled();
      await typeSql("SELECT 1");
      await user.click(screen.getByRole("button", { name: "Export CSV…" }));
      expect(m.save).toHaveBeenCalledWith(expect.objectContaining({ defaultPath: "sparrow-query.csv" }));
      expect(m.exportCsv).toHaveBeenCalledExactlyOnceWith("SELECT 1", "/out/q.csv", expect.any(String));
      expect(await screen.findByRole("status")).toHaveTextContent("12,345 rows written");
      await user.click(screen.getByRole("button", { name: "Export CSV…" }));
      const [a, b] = m.exportCsv.mock.calls.map((c) => c[2]);
      expect(a).not.toBe(b);
    });

    it("mentions the cap", async () => {
      m.exportCsv.mockResolvedValue({ rows: 1_000_000, capped: true });
      const user = await setup();
      await typeSql("SELECT 1");
      await user.click(screen.getByRole("button", { name: "Export CSV…" }));
      expect(await screen.findByRole("status")).toHaveTextContent("1,000,000 rows written (capped at 1,000,000)");
    });

    it("does nothing when the save dialog is dismissed", async () => {
      m.save.mockResolvedValue(null);
      const user = await setup();
      await typeSql("SELECT 1");
      await user.click(screen.getByRole("button", { name: "Export CSV…" }));
      expect(m.exportCsv).not.toHaveBeenCalled();
    });

    it("Cancel during the export cancels that export only", async () => {
      let reject: (e: unknown) => void = () => {};
      m.exportCsv.mockImplementation(() => new Promise((_, rj) => (reject = rj)));
      const user = await setup();
      await typeSql("SELECT 1");
      await user.click(screen.getByRole("button", { name: "Export CSV…" }));
      await user.click(await screen.findByRole("button", { name: "Cancel" }));
      expect(m.cancel).toHaveBeenCalledExactlyOnceWith(m.exportCsv.mock.calls[0][2]);
      await act(async () => reject({ kind: "interrupted", message: "Interrupted" }));
      expect(await screen.findByRole("status")).toHaveTextContent("Export cancelled.");
      expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
    });

    it("shows a refusal", async () => {
      m.exportCsv.mockRejectedValue({ kind: "invalid", message: "not a SELECT" });
      const user = await setup();
      await typeSql("SELECT 1");
      await user.click(screen.getByRole("button", { name: "Export CSV…" }));
      expect(await screen.findByRole("alert")).toHaveTextContent("not a SELECT");
    });
  });
});
