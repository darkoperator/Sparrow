import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { BrowsePage, CmdError, Filter } from "../api";
import { browsePage as browseFixture, schema } from "../test/fixtures";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  browseTables: vi.fn(),
  browsePage: vi.fn(),
  sqlSchema: vi.fn(),
  queryCancel: vi.fn(),
  highlightsGet: vi.fn(),
  highlightsSet: vi.fn(),
  indicatorsActive: vi.fn(),
}));

import * as api from "../api";
import { HighlightsError, HighlightsProvider } from "../highlights/useHighlights";
import Tables from "./Tables";

const m = {
  tables: vi.mocked(api.browseTables),
  page: vi.mocked(api.browsePage),
  schema: vi.mocked(api.sqlSchema),
  cancel: vi.mocked(api.queryCancel),
};
const hl = {
  get: vi.mocked(api.highlightsGet),
  set: vi.mocked(api.highlightsSet),
  ind: vi.mocked(api.indicatorsActive),
};
const all = schema();

/** A page of `n` synthetic rows starting at `offset`, for a table with two columns. */
function synth(offset: number, total: number, n: number, capped = false): BrowsePage {
  return {
    table: "signins",
    columns: ["name", "n"],
    rows: Array.from({ length: n }, (_, i) => [`row-${offset + i}`, offset + i]),
    offset,
    total,
    total_capped: capped,
  };
}

beforeEach(() => {
  for (const f of [...Object.values(m), ...Object.values(hl)]) f.mockReset();
  m.tables.mockResolvedValue(["ual_events", "signins"]);
  m.schema.mockImplementation(async (t) => all.filter((x) => x.name === t));
  m.cancel.mockResolvedValue(null);
  m.page.mockImplementation(async () => browseFixture());
});

async function pickSignins() {
  const user = userEvent.setup();
  render(<Tables />);
  await screen.findByRole("option", { name: "signins" });
  await user.selectOptions(screen.getByLabelText("Table"), "signins");
  return user;
}
const lastArgs = () => m.page.mock.calls.at(-1)!;
const pick = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const rowLoaded = () => screen.findAllByText(browseFixture().rows[0][0] as string);
const scrollBody = () => document.querySelector(".grid-body")!;

describe("Tables", () => {
  it("lists the tables, loads the first page with server paging and shows the rows", async () => {
    await pickSignins();
    const page = browseFixture();
    await rowLoaded();
    expect(m.schema).toHaveBeenCalledWith("signins");
    const [table, filters, sort, offset, limit, id] = lastArgs();
    expect([table, filters, sort, offset, limit]).toEqual(["signins", [], null, 0, 500]);
    expect(typeof id).toBe("string");
    expect(id.length).toBeGreaterThan(8);
    expect(screen.getByTestId("total")).toHaveTextContent(`${page.total} ${page.total === 1 ? "row" : "rows"}`);
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual(page.columns);
  });

  it("capped_total_is_shown_as_at_least", async () => {
    m.page.mockResolvedValue(synth(0, 1_000_000, 500, true));
    await pickSignins();
    expect(await screen.findByTestId("total")).toHaveTextContent("≥ 1,000,000 rows · 500 loaded");
  });

  it("an uncapped total has no ≥", async () => {
    m.page.mockResolvedValue(synth(0, 1234, 500, false));
    await pickSignins();
    const total = await screen.findByTestId("total");
    expect(total).toHaveTextContent("1,234 rows");
    expect(total.textContent).not.toContain("≥");
  });

  it("a filter built in the builder is sent and shown as a chip; removing it reloads without it", async () => {
    const user = await pickSignins();
    await rowLoaded();
    pick("Column", "asn");
    await user.type(screen.getByLabelText("Value"), "64499");
    await user.click(screen.getByRole("button", { name: "Add filter" }));
    await waitFor(() => expect(lastArgs()[1]).toEqual([{ op: "eq", column: "asn", value: 64499 }]));
    expect(lastArgs()[3]).toBe(0);
    expect(screen.getByText("asn equals 64499")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Remove filter asn equals 64499" }));
    await waitFor(() => expect(lastArgs()[1]).toEqual([]));
    expect(screen.queryByText("asn equals 64499")).toBeNull();
  });

  it("clicking a header sorts ascending, then descending, then off", async () => {
    m.page.mockResolvedValue(synth(0, 3, 3));
    const user = await pickSignins();
    const header = await screen.findByRole("button", { name: "name" });
    await user.click(header);
    await waitFor(() => expect(lastArgs()[2]).toEqual({ column: "name", descending: false }));
    expect(screen.getByRole("columnheader", { name: /name/ })).toHaveAttribute("aria-sort", "ascending");
    await user.click(await screen.findByRole("button", { name: /^name/ }));
    await waitFor(() => expect(lastArgs()[2]).toEqual({ column: "name", descending: true }));
    await user.click(await screen.findByRole("button", { name: /^name/ }));
    await waitFor(() => expect(lastArgs()[2]).toBeNull());
  });

  it("scrolling near the end fetches the next page at offset 500 and appends it", async () => {
    m.page.mockImplementation(async (_t, _f, _s, offset) => synth(offset, 1200, Math.min(500, 1200 - offset)));
    await pickSignins();
    await screen.findByText("row-0");
    expect(m.page).toHaveBeenCalledTimes(1);
    const body = scrollBody();
    Object.defineProperty(body, "scrollTop", { value: 26 * 480, configurable: true, writable: true });
    fireEvent.scroll(body);
    await waitFor(() => expect(m.page).toHaveBeenCalledTimes(2));
    expect(lastArgs().slice(3, 5)).toEqual([500, 500]);
    await waitFor(() => expect(screen.getByTestId("total")).toHaveTextContent("1,200 rows · 1,000 loaded"));
  });

  it("does not fetch again while a page is in flight, nor past the last row", async () => {
    let release!: (p: BrowsePage) => void;
    m.page.mockImplementation(async (_t, _f, _s, offset) => synth(offset, 600, Math.min(500, 600 - offset)));
    await pickSignins();
    await screen.findByText("row-0");
    m.page.mockImplementationOnce(() => new Promise<BrowsePage>((r) => (release = r)));
    const body = scrollBody();
    const scrollTo = (rows: number) => {
      Object.defineProperty(body, "scrollTop", { value: 26 * rows, configurable: true, writable: true });
      fireEvent.scroll(body);
    };
    scrollTo(470);
    await waitFor(() => expect(m.page).toHaveBeenCalledTimes(2));
    // The window moves again while that page is pending: still one request.
    scrollTo(480);
    scrollTo(490);
    expect(m.page).toHaveBeenCalledTimes(2);
    await act(async () => {
      release(synth(500, 600, 100));
    });
    await waitFor(() => expect(screen.getByTestId("total")).toHaveTextContent("600 rows"));
    scrollTo(560);
    scrollTo(590);
    expect(m.page).toHaveBeenCalledTimes(2);
  });

  it("Cancel while a page loads calls query_cancel with that page's id and shows 'cancelled', not an error", async () => {
    let reject!: (e: CmdError) => void;
    m.page.mockImplementation(() => new Promise<BrowsePage>((_, r) => (reject = r)));
    const user = await pickSignins();
    await user.click(await screen.findByRole("button", { name: "Cancel" }));
    const id = lastArgs()[5];
    expect(m.cancel).toHaveBeenCalledExactlyOnceWith(id);
    await act(async () => {
      reject({ kind: "interrupted", message: "the query was cancelled" });
    });
    expect(await screen.findByText("Query cancelled.")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
  });

  it("a new spec cancels the superseded page's query by its id", async () => {
    let first = "";
    m.page.mockImplementationOnce((_t, _f, _s, _o, _l, id) => {
      first = id;
      return new Promise<BrowsePage>(() => {});
    });
    const user = await pickSignins();
    await screen.findByLabelText("Operator");
    expect(first).not.toBe("");
    expect(m.cancel).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText("Value"), "x");
    await user.click(screen.getByRole("button", { name: "Add filter" }));
    expect(m.cancel).toHaveBeenCalledExactlyOnceWith(first);
    expect(lastArgs()[5]).not.toBe(first);
  });

  it("leaving the screen while a page is pending cancels it; a finished page is not cancelled", async () => {
    let id = "";
    m.page.mockImplementationOnce((_t, _f, _s, _o, _l, qid) => {
      id = qid;
      return new Promise<BrowsePage>(() => {});
    });
    const user = userEvent.setup();
    const { unmount } = render(<Tables />);
    await screen.findByRole("option", { name: "signins" });
    await user.selectOptions(screen.getByLabelText("Table"), "signins");
    unmount();
    expect(m.cancel).toHaveBeenCalledExactlyOnceWith(id);

    m.cancel.mockClear();
    render(<Tables initial={{ table: "signins", filters: [] }} />);
    await rowLoaded();
    cleanup();
    expect(m.cancel).not.toHaveBeenCalled();
  });

  it("a capped total keeps paging past the count until a short page", async () => {
    // Capped: `total` is only the cap, so rows loaded == total does not mean the end.
    m.page.mockImplementation(async (_t, _f, _s, offset) => synth(offset, 500, offset === 0 ? 500 : 100, true));
    await pickSignins();
    await screen.findByText("row-0");
    const body = scrollBody();
    const scrollTo = (rows: number) => {
      Object.defineProperty(body, "scrollTop", { value: 26 * rows, configurable: true, writable: true });
      fireEvent.scroll(body);
    };
    scrollTo(480);
    await waitFor(() => expect(m.page).toHaveBeenCalledTimes(2));
    expect(lastArgs().slice(3, 5)).toEqual([500, 500]);
    await waitFor(() => expect(screen.getByTestId("total")).toHaveTextContent("≥ 500 rows · 600 loaded"));
    scrollTo(590);
    scrollTo(595);
    expect(m.page).toHaveBeenCalledTimes(2); // the short page was the last
  });

  it("an empty page ends a capped total too", async () => {
    m.page.mockImplementation(async (_t, _f, _s, offset) => synth(offset, 500, offset === 0 ? 500 : 0, true));
    await pickSignins();
    await screen.findByText("row-0");
    const body = scrollBody();
    Object.defineProperty(body, "scrollTop", { value: 26 * 480, configurable: true, writable: true });
    fireEvent.scroll(body);
    await waitFor(() => expect(m.page).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByTestId("total")).toHaveTextContent("≥ 500 rows · 500 loaded"));
    Object.defineProperty(body, "scrollTop", { value: 26 * 495, configurable: true, writable: true });
    fireEvent.scroll(body);
    expect(m.page).toHaveBeenCalledTimes(2);
  });

  it("the schema of an initial table is under the same guard: A's late schema does not overwrite B's", async () => {
    let releaseA!: (t: typeof all) => void;
    m.schema.mockImplementationOnce(() => new Promise((r) => (releaseA = r)));
    const user = userEvent.setup();
    render(<Tables initial={{ table: "signins", filters: [] }} />);
    await screen.findByRole("option", { name: "ual_events" });
    await user.selectOptions(screen.getByLabelText("Table"), "ual_events");
    const ual = all.find((t) => t.name === "ual_events")!.columns.map((c) => c.name);
    const signinOnly = all.find((t) => t.name === "signins")!.columns.map((c) => c.name).find((c) => !ual.includes(c))!;
    await screen.findByLabelText("Operator");
    await act(async () => {
      releaseA(all.filter((t) => t.name === "signins"));
    });
    const options = Array.from((screen.getByLabelText("Column") as HTMLSelectElement).options).map((o) => o.value);
    expect(options).toEqual(ual);
    expect(options).not.toContain(signinOnly);
  });

  it("a rejected quick highlight from a grid on the Tables screen is shown there", async () => {
    m.page.mockResolvedValue({ table: "t", columns: ["who"], rows: [["alice"]], offset: 0, total: 1, total_capped: false });
    hl.get.mockResolvedValue([]);
    hl.ind.mockResolvedValue([]);
    hl.set.mockRejectedValue({ kind: "invalid", message: "a case can have at most 50 highlight sets" } satisfies CmdError);
    const user = userEvent.setup();
    render(
      <HighlightsProvider caseId="c1">
        <HighlightsError />
        <Tables />
      </HighlightsProvider>,
    );
    await screen.findByRole("option", { name: "signins" });
    await user.selectOptions(screen.getByLabelText("Table"), "signins");
    fireEvent.contextMenu(await screen.findByText("alice"));
    await user.click(screen.getByRole("menuitem", { name: "Highlight this value" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("at most 50 highlight sets");
  });

  it("each page request carries its own query id", async () => {
    const user = await pickSignins();
    await rowLoaded();
    const first = lastArgs()[5];
    await user.click(screen.getByRole("button", { name: browseFixture().columns[0] }));
    await waitFor(() => expect(m.page).toHaveBeenCalledTimes(2));
    expect(lastArgs()[5]).not.toBe(first);
  });

  it("shows a backend error and no rows", async () => {
    m.page.mockRejectedValue({ kind: "invalid", message: "no such column: nope" } satisfies CmdError);
    await pickSignins();
    expect(await screen.findByRole("alert")).toHaveTextContent("no such column: nope");
    expect(screen.queryByTestId("total")).toBeNull();
  });

  it("drops a slow answer for an earlier filter", async () => {
    const user = userEvent.setup();
    let releaseFirst!: (p: BrowsePage) => void;
    m.page.mockImplementationOnce(() => new Promise<BrowsePage>((r) => (releaseFirst = r)));
    render(<Tables />);
    await screen.findByRole("option", { name: "signins" });
    await user.selectOptions(screen.getByLabelText("Table"), "signins");
    await screen.findByLabelText("Operator");
    await user.type(screen.getByLabelText("Value"), "x");
    await user.click(screen.getByRole("button", { name: "Add filter" }));
    await rowLoaded();
    await act(async () => {
      releaseFirst(synth(0, 1, 1));
    });
    expect(screen.queryByText("row-0")).toBeNull();
  });

  it("opening a row shows every column in a detail pane, JSON text pretty-printed and escaped", async () => {
    m.page.mockResolvedValue({
      table: "t",
      columns: ["id", "raw"],
      rows: [["k1", '{"a":1,"b":["<img src=x>","x‮y"]}']],
      offset: 0,
      total: 1,
      total_capped: false,
    });
    const user = await pickSignins();
    await user.click(await screen.findByText("k1"));
    const pane = screen.getByLabelText("Row detail");
    expect(within(pane).getByText("raw")).toBeInTheDocument();
    const pre = pane.querySelectorAll("pre")[1];
    expect(pre.textContent).toBe('{\n  "a": 1,\n  "b": [\n    "<img src=x>",\n    "x\\u{202E}y"\n  ]\n}');
    expect(pane.querySelector("img")).toBeNull();
  });

  it("'Filter by this value' on a cell adds an eq filter; on an empty cell an 'is empty' filter", async () => {
    m.page.mockResolvedValue({
      table: "t",
      columns: ["who", "note"],
      rows: [["alice", null]],
      offset: 0,
      total: 1,
      total_capped: false,
    });
    const user = await pickSignins();
    fireEvent.contextMenu(await screen.findByText("alice"));
    await user.click(screen.getByRole("menuitem", { name: "Filter by this value" }));
    await waitFor(() => expect(lastArgs()[1]).toEqual([{ op: "eq", column: "who", value: "alice" }]));
    await screen.findByText("alice");
    const cells = screen.getAllByRole("cell");
    fireEvent.contextMenu(cells[1]);
    await user.click(screen.getByRole("menuitem", { name: "Filter by this value" }));
    await waitFor(() =>
      expect(lastArgs()[1]).toEqual([
        { op: "eq", column: "who", value: "alice" },
        { op: "is_null", column: "note" },
      ] satisfies Filter[]),
    );
  });

  it("opens on a requested table and filters (from a pivot or another screen)", async () => {
    const filters: Filter[] = [{ op: "eq", column: "ip", value: "192.0.2.2" }];
    render(<Tables initial={{ table: "signins", filters }} />);
    await rowLoaded();
    expect(m.page.mock.calls[0].slice(0, 5)).toEqual(["signins", filters, null, 0, 500]);
    expect(await screen.findByText("ip equals 192.0.2.2")).toBeInTheDocument();
    expect(m.schema).toHaveBeenCalledWith("signins");
  });

  it("says when no row matches", async () => {
    m.page.mockResolvedValue({ ...synth(0, 0, 0) });
    await pickSignins();
    expect(await screen.findByText("No rows match.")).toBeInTheDocument();
  });
});
