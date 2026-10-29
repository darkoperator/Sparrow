import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Grid from "./Grid";
import { columnKeys, readLayout } from "./gridLayout";

const COLUMNS = ["a", "b", "c"];
const ROWS = [["a1", "b1", "c1"], ["a2", "b2", "c2"]];
const KEY = "sparrow.grid.layout.v1.test";

const headers = () => screen.getAllByRole("columnheader").map((h) => h.textContent!.replace(/Resize .*$/, "").replace(/[ ▲▼]+$/, ""));
const header = (name: string) => screen.getByRole("columnheader", { name: new RegExp(`^${name}`) });
const firstRow = () => within(screen.getAllByRole("row")[1]).getAllByRole("cell").map((c) => c.textContent);
const template = () => (screen.getAllByRole("row")[0] as HTMLElement).style.gridTemplateColumns;
const stored = () => JSON.parse(localStorage.getItem(KEY) ?? "null");
const drag = (from: string, to: string) => {
  fireEvent.dragStart(header(from));
  fireEvent.dragOver(header(to));
  fireEvent.drop(header(to));
  fireEvent.dragEnd(header(from));
};
const grid = (props: Partial<React.ComponentProps<typeof Grid>> = {}) => (
  <Grid columns={COLUMNS} rows={ROWS} layoutId="test" {...props} />
);

beforeEach(() => localStorage.clear());
afterEach(() => vi.restoreAllMocks());

describe("Grid column layout", () => {
  it("dragging a header reorders the columns and their cells; rightwards lands after the target, leftwards before", () => {
    render(grid());
    expect(headers()).toEqual(["a", "b", "c"]);
    drag("a", "b");
    expect(headers()).toEqual(["b", "a", "c"]);
    expect(firstRow()).toEqual(["b1", "a1", "c1"]);
    drag("c", "b");
    expect(headers()).toEqual(["c", "b", "a"]);
    expect(firstRow()).toEqual(["c1", "b1", "a1"]);
    // A drop on itself, or a drag that never started, changes nothing.
    drag("b", "b");
    fireEvent.drop(header("a"));
    expect(headers()).toEqual(["c", "b", "a"]);
  });

  it("still reports the source row and the column name after a reorder", async () => {
    const onRowClick = vi.fn();
    const onSort = vi.fn();
    render(grid({ onRowClick, onSort }));
    drag("a", "c");
    const user = userEvent.setup();
    await user.click(screen.getByText("b2"));
    expect(onRowClick).toHaveBeenCalledExactlyOnceWith(["a2", "b2", "c2"], 1);
    await user.click(screen.getByRole("button", { name: /^a/ }));
    expect(onSort).toHaveBeenCalledExactlyOnceWith("a");
  });

  it("the header menu moves a column by one and resets the layout", async () => {
    const user = userEvent.setup();
    const onResetColumns = vi.fn();
    render(grid({ onResetColumns }));
    fireEvent.contextMenu(header("b"));
    await user.click(screen.getByRole("menuitem", { name: "Move column right" }));
    expect(headers()).toEqual(["a", "c", "b"]);
    fireEvent.contextMenu(header("a"));
    // The first column cannot move left; the last cannot move right.
    expect(screen.queryByRole("menuitem", { name: "Move column left" })).toBeNull();
    fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
    fireEvent.contextMenu(header("b"));
    expect(screen.queryByRole("menuitem", { name: "Move column right" })).toBeNull();
    await user.click(screen.getByRole("menuitem", { name: "Move column left" }));
    expect(headers()).toEqual(["a", "b", "c"]);
    drag("a", "c");
    fireEvent.contextMenu(header("b"));
    await user.click(screen.getByRole("menuitem", { name: "Reset columns" }));
    expect(headers()).toEqual(["a", "b", "c"]);
    expect(onResetColumns).toHaveBeenCalledOnce();
  });

  it("remembers the order per grid and restores it on the next mount, and a reset forgets it", async () => {
    const first = render(grid());
    drag("a", "c");
    first.unmount(); // a pending save is written when the grid goes away
    expect(stored()).toEqual({ order: ["b", "c", "a"], widths: {} });
    const again = render(grid());
    expect(headers()).toEqual(["b", "c", "a"]);
    expect(firstRow()).toEqual(["b1", "c1", "a1"]);
    again.unmount();
    // Another grid id has its own layout.
    const other = render(grid({ layoutId: "other" }));
    expect(headers()).toEqual(["a", "b", "c"]);
    other.unmount();
    render(grid());
    fireEvent.contextMenu(header("b"));
    await userEvent.setup().click(screen.getByRole("menuitem", { name: "Reset columns" }));
    expect(headers()).toEqual(["a", "b", "c"]);
    await waitFor(() => expect(localStorage.getItem(KEY)).toBeNull());
  });

  it("resizing a column sets its width, saves it after a pause, and the width comes back", async () => {
    const first = render(grid({ widths: { a: 100 } }));
    expect(template()).toBe("100px 180px 180px");
    fireEvent.mouseDown(screen.getByRole("separator", { name: "Resize a" }), { clientX: 100 });
    fireEvent.mouseMove(document, { clientX: 160 });
    fireEvent.mouseUp(document, { clientX: 160 });
    expect(template()).toBe("160px 180px 180px");
    // Not written on every move: after a short pause.
    expect(localStorage.getItem(KEY)).toBeNull();
    await waitFor(() => expect(stored()).toEqual({ order: [], widths: { a: 160 } }));
    first.unmount();
    render(grid({ widths: { a: 100 } }));
    expect(template()).toBe("160px 180px 180px");
  });

  it("a width follows its column when the columns are reordered", () => {
    render(grid());
    fireEvent.mouseDown(screen.getByRole("separator", { name: "Resize b" }), { clientX: 0 });
    fireEvent.mouseMove(document, { clientX: 40 });
    fireEvent.mouseUp(document);
    expect(template()).toBe("180px 220px 180px");
    drag("b", "a");
    expect(headers()).toEqual(["b", "a", "c"]);
    expect(template()).toBe("220px 180px 180px");
  });

  it("pressing a resize handle does not start a column drag, and a header press does", () => {
    render(grid());
    fireEvent.mouseDown(screen.getByRole("separator", { name: "Resize a" }));
    expect(fireEvent.dragStart(header("a"))).toBe(false); // default prevented
    fireEvent.mouseUp(window);
    expect(fireEvent.dragStart(header("a"))).toBe(true);
  });

  it("writes nothing on open, and nothing at all without a layout id", async () => {
    const set = vi.spyOn(Storage.prototype, "setItem");
    const one = render(grid());
    one.unmount();
    expect(set).not.toHaveBeenCalled();
    render(grid({ layoutId: undefined }));
    drag("a", "c");
    expect(headers()).toEqual(["b", "c", "a"]);
    await new Promise((r) => setTimeout(r, 400));
    expect(set).not.toHaveBeenCalled();
  });

  it("falls back to the defaults for junk in storage", () => {
    for (const junk of ["not json", "null", "[]", '"x"', '{"order":"abc","widths":[1]}', '{"order":[1,null,{}],"widths":{"a":"wide","b":-5,"c":null}}']) {
      localStorage.setItem(KEY, junk);
      const { unmount } = render(grid());
      expect(headers()).toEqual(["a", "b", "c"]);
      expect(template()).toBe("180px 180px 180px");
      unmount();
    }
  });

  it("ignores saved columns that no longer exist, repeats and extremes, and puts new columns last", () => {
    localStorage.setItem(KEY, JSON.stringify({ order: ["gone", "c", "c", "a"], widths: { b: 99999, c: 1 } }));
    render(grid());
    expect(headers()).toEqual(["c", "a", "b"]);
    expect(template()).toBe("60px 180px 2000px");
  });

  it("works with storage that throws, in memory", async () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    const set = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("full");
    });
    vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    const view = render(grid());
    expect(headers()).toEqual(["a", "b", "c"]);
    drag("a", "c");
    expect(headers()).toEqual(["b", "c", "a"]);
    await waitFor(() => expect(set).toHaveBeenCalled());
    expect(headers()).toEqual(["b", "c", "a"]);
    fireEvent.contextMenu(header("b"));
    await userEvent.setup().click(screen.getByRole("menuitem", { name: "Reset columns" }));
    expect(headers()).toEqual(["a", "b", "c"]);
    view.unmount();
  });

  it("repeated column names are kept apart", () => {
    expect(columnKeys(["id", "x", "id", "id"])).toEqual(["id", "x", "id#2", "id#3"]);
    render(<Grid columns={["id", "id"]} rows={[["first", "second"]]} layoutId="test" />);
    const heads = screen.getAllByRole("columnheader");
    fireEvent.dragStart(heads[0]);
    fireEvent.dragOver(heads[1]);
    fireEvent.drop(heads[1]);
    expect(firstRow()).toEqual(["second", "first"]);
  });

  it("an empty grid keeps its header and Reset columns", async () => {
    localStorage.setItem(KEY, JSON.stringify({ order: ["c", "a", "b"], widths: { a: 300 } }));
    const onResetColumns = vi.fn();
    render(grid({ rows: [], onResetColumns }));
    expect(headers()).toEqual(["c", "a", "b"]);
    expect(screen.getByText("No rows.")).toBeInTheDocument();
    fireEvent.contextMenu(header("a"));
    await userEvent.setup().click(screen.getByRole("menuitem", { name: "Reset columns" }));
    expect(headers()).toEqual(["a", "b", "c"]);
    expect(onResetColumns).toHaveBeenCalledOnce();
    await waitFor(() => expect(localStorage.getItem(KEY)).toBeNull());
  });

  it("a layout id change saves the old layout at once and writes nothing for the new one", async () => {
    const set = vi.spyOn(Storage.prototype, "setItem");
    localStorage.setItem("sparrow.grid.layout.v1.two", JSON.stringify({ order: ["b", "a", "c"], widths: {} }));
    set.mockClear();
    const view = render(grid({ layoutId: "one" }));
    drag("a", "c");
    expect(localStorage.getItem(KEY.replace("test", "one"))).toBeNull(); // still pending
    view.rerender(grid({ layoutId: "two" }));
    // The old layout is saved on the switch, not lost with the timer.
    expect(JSON.parse(localStorage.getItem(KEY.replace("test", "one"))!)).toEqual({ order: ["b", "c", "a"], widths: {} });
    // The new id shows its own saved layout and is left as it was.
    expect(headers()).toEqual(["b", "a", "c"]);
    await new Promise((r) => setTimeout(r, 400));
    expect(set.mock.calls.map((c) => c[0])).toEqual(["sparrow.grid.layout.v1.one"]);
    // An edit after the switch belongs to the new id.
    drag("b", "c");
    view.unmount();
    expect(JSON.parse(localStorage.getItem(KEY.replace("test", "two"))!).order).toEqual(["a", "c", "b"]);
    expect(JSON.parse(localStorage.getItem(KEY.replace("test", "one"))!).order).toEqual(["b", "c", "a"]);
  });

  it("readLayout gives the defaults with no id", () => {
    expect(readLayout(undefined)).toEqual({ order: [], widths: {} });
  });
});
