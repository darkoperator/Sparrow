import { act, cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { schema as schemaFixture, sqlResult as sqlResultFixture } from "../test/fixtures";
import type { QueryResult } from "../api";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  sqlSchema: vi.fn(),
  sqlRun: vi.fn(),
  queryCancel: vi.fn(),
}));

import * as api from "../api";
import Sql from "./Sql";

const m = { schema: vi.mocked(api.sqlSchema), run: vi.mocked(api.sqlRun), cancel: vi.mocked(api.queryCancel) };
let result: QueryResult;

beforeEach(() => {
  for (const f of Object.values(m)) f.mockReset();
  result = sqlResultFixture();
  m.schema.mockResolvedValue(schemaFixture());
  m.run.mockImplementation(async () => result);
  m.cancel.mockResolvedValue(null);
});

async function setup() {
  const user = userEvent.setup();
  render(<Sql />);
  await screen.findByRole("button", { name: "signins" });
  return user;
}

const QUERY = "SELECT user_upn, ip, count(*) n FROM signins GROUP BY ALL";
const editor = () => screen.getByRole("textbox", { name: "SQL" }) as HTMLTextAreaElement;

describe("Sql", () => {
  it("runs the typed query with the default limit, then the chosen one", async () => {
    const user = await setup();
    expect(screen.getByRole("button", { name: "Run" })).toBeDisabled();
    await user.type(editor(), QUERY);
    await user.click(screen.getByRole("button", { name: "Run" }));
    expect(m.run).toHaveBeenLastCalledWith(QUERY, 1000, expect.any(String));
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
    expect(m.run).toHaveBeenLastCalledWith(QUERY, 10000, expect.any(String));
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

  it("Cmd+Enter and Ctrl+Enter run the query; plain Enter adds a line", async () => {
    const user = await setup();
    await user.type(editor(), "SELECT 1{Enter}");
    expect(m.run).not.toHaveBeenCalled();
    expect(editor().value).toBe("SELECT 1\n");
    await user.keyboard("{Meta>}{Enter}{/Meta}");
    expect(m.run).toHaveBeenCalledTimes(1);
    expect(m.run).toHaveBeenLastCalledWith("SELECT 1\n", 1000, expect.any(String));
    await screen.findByRole("table");
    await user.keyboard("{Control>}{Enter}{/Control}");
    expect(m.run).toHaveBeenCalledTimes(2);
  });

  it("says when the result was truncated at the limit", async () => {
    result = { ...result, truncated: true };
    const user = await setup();
    await user.type(editor(), "SELECT * FROM signins");
    await user.click(screen.getByRole("button", { name: "Run" }));
    expect(await screen.findByText(/first 1,000 rows.*raise the limit/i)).toBeInTheDocument();
  });

  it("Cancel interrupts the running query and says it was cancelled", async () => {
    let reject: (e: unknown) => void = () => {};
    m.run.mockImplementation(() => new Promise<QueryResult>((_, rj) => (reject = rj)));
    const user = await setup();
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
    await user.type(editor(), "SELECT count(*) FROM range(10000000000)");
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
    await user.type(editor(), "SELECT count(*) FROM range(10000000000)");
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
    await user.type(editor(), "SELECT 1");
    await user.click(screen.getByRole("button", { name: "Run" }));
    await screen.findByRole("table");
    cleanup();
    expect(m.cancel).not.toHaveBeenCalled();
  });

  it("shows the backend's refusal verbatim, escaped, and clears the old result", async () => {
    const user = await setup();
    await user.type(editor(), "SELECT 1");
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
    await user.type(editor(), "SELECT  FROM ");
    await user.click(screen.getByRole("button", { name: "signins" }));
    expect(editor().value).toBe("SELECT  FROM signins");
    // Put the cursor after "SELECT " and insert a column there.
    editor().setSelectionRange(7, 7);
    await user.click(screen.getByRole("button", { name: "Show columns of signins" }));
    await user.click(screen.getByRole("button", { name: "user_upn" }));
    expect(editor().value).toBe("SELECT user_upn FROM signins");
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
    expect(editor().value).toBe('"odd ""col"""');
  });

  it("a schema error is shown, and the editor still works", async () => {
    m.schema.mockRejectedValue({ kind: "read_only", message: "SQL needs a writable case" });
    const user = userEvent.setup();
    render(<Sql />);
    expect(await screen.findByRole("alert")).toHaveTextContent("SQL needs a writable case");
    await user.type(editor(), "SELECT 1");
    expect(screen.getByRole("button", { name: "Run" })).toBeEnabled();
  });
});
