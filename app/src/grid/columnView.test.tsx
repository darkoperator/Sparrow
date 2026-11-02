import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { compareValues, instant, kindOf, useColumnView, useViewHeaders, ViewNote, type ViewColumn } from "./columnView";
import CellMenu from "./CellMenu";

interface Row {
  name: string | null;
  n: number;
  at: string | null;
}

const COLS: ViewColumn<Row>[] = [
  { id: "name", label: "Name", value: (r) => r.name },
  { id: "n", label: "N", value: (r) => r.n },
  { id: "at", label: "At", value: (r) => r.at },
];

const ROWS: Row[] = [
  { name: "beta", n: 10, at: "2026-06-29T20:50:28.000000Z" },
  { name: "Alpha", n: 9, at: "2026-06-30T01:00:00.000000Z" },
  { name: null, n: 100, at: null },
];

function Table() {
  const view = useColumnView(ROWS, COLS);
  const { header, popover } = useViewHeaders(view, COLS);
  return (
    <>
      <ViewNote view={view} />
      <table>
        <thead>
          <tr>{COLS.map((c) => header(c.id))}</tr>
        </thead>
        <tbody>
          {view.rows.map((r, i) => (
            <tr key={i} data-testid="row">
              <td>{r.name ?? "none"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {popover}
    </>
  );
}

const names = () => screen.getAllByTestId("row").map((r) => r.textContent);

describe("column view helpers", () => {
  it("reads times as UTC, with or without an offset", () => {
    expect(instant("2026-06-29")).toBe(Date.UTC(2026, 5, 29));
    expect(instant("2026-06-29 01:00:00")).toBe(Date.UTC(2026, 5, 29, 1));
    expect(instant("2026-06-29T01:00:00.123456Z")).toBe(Date.UTC(2026, 5, 29, 1, 0, 0, 123));
    expect(instant("2026-06-29 03:00:00+02")).toBe(Date.UTC(2026, 5, 29, 1));
    expect(instant("not a date")).toBeNull();
    expect(instant(12)).toBeNull();
  });
  it("works out a column's kind from its values, ignoring empties", () => {
    expect(kindOf(["2026-06-29T01:00:00Z", null])).toBe("date");
    expect(kindOf([1, 2, null])).toBe("number");
    expect(kindOf(["2026-06-29", "x"])).toBe("text");
    expect(kindOf([null])).toBe("text");
  });
  it("sorts empties last in both directions", () => {
    expect(compareValues(null, "a", "text", false)).toBe(1);
    expect(compareValues(null, "a", "text", true)).toBe(1);
    expect(compareValues(2, 10, "number", false)).toBeLessThan(0);
  });
});

describe("a table through the column view", () => {
  it("sorts by a header click: ascending, descending, then back to the given order", () => {
    render(<Table />);
    const name = screen.getByRole("button", { name: "Name" });
    fireEvent.click(name);
    expect(names()).toEqual(["Alpha", "beta", "none"]);
    expect(screen.getByRole("columnheader", { name: /Name/ })).toHaveAttribute("aria-sort", "ascending");
    fireEvent.click(name);
    expect(names()).toEqual(["beta", "Alpha", "none"]);
    fireEvent.click(name);
    expect(names()).toEqual(["beta", "Alpha", "none"]);
    expect(screen.getByRole("columnheader", { name: /Name/ })).toHaveAttribute("aria-sort", "none");
  });
  it("sorts numbers as numbers", () => {
    render(<Table />);
    fireEvent.click(screen.getByRole("button", { name: "N" }));
    expect(names()).toEqual(["Alpha", "beta", "none"]);
  });
  it("filters by a ticked value from a right-click, says so, and clears", () => {
    render(<Table />);
    fireEvent.contextMenu(screen.getByRole("columnheader", { name: /Name/ }));
    const panel = screen.getByRole("group", { name: "Filter Name" });
    fireEvent.click(within(panel).getByRole("checkbox", { name: "Alpha" }));
    fireEvent.click(within(panel).getByRole("button", { name: "Apply" }));
    expect(names()).toEqual(["Alpha"]);
    expect(screen.getByRole("status")).toHaveTextContent("Showing 1 of 3");
    expect(screen.getByRole("img", { name: "Name is filtered" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(names()).toHaveLength(3);
  });
  it("excludes the ticked values, and matches contains ignoring case", () => {
    render(<Table />);
    fireEvent.contextMenu(screen.getByRole("columnheader", { name: /Name/ }));
    let panel = screen.getByRole("group", { name: "Filter Name" });
    fireEvent.click(within(panel).getByRole("checkbox", { name: "Alpha" }));
    fireEvent.click(within(panel).getByRole("switch"));
    fireEvent.click(within(panel).getByRole("button", { name: "Apply" }));
    expect(names()).toEqual(["beta", "none"]);
    fireEvent.contextMenu(screen.getByRole("columnheader", { name: /Name/ }));
    panel = screen.getByRole("group", { name: "Filter Name" });
    fireEvent.click(within(panel).getByRole("button", { name: "Clear filter" }));
    fireEvent.contextMenu(screen.getByRole("columnheader", { name: /Name/ }));
    panel = screen.getByRole("group", { name: "Filter Name" });
    fireEvent.change(within(panel).getByRole("textbox", { name: "Contains" }), { target: { value: "ALP" } });
    fireEvent.click(within(panel).getByRole("button", { name: "Apply" }));
    expect(names()).toEqual(["Alpha"]);
  });
  it("offers date pickers on a date column, a date alone being the whole day and empties left out", () => {
    render(<Table />);
    fireEvent.contextMenu(screen.getByRole("columnheader", { name: /At/ }));
    const panel = screen.getByRole("group", { name: "Filter At" });
    const to = within(panel).getByLabelText("To date (UTC)");
    expect(to).toHaveAttribute("type", "date");
    fireEvent.change(to, { target: { value: "2026-06-29" } });
    fireEvent.click(within(panel).getByRole("button", { name: "Apply" }));
    expect(names()).toEqual(["beta"]);
  });
  it("refuses a range that ends before it starts", () => {
    render(<Table />);
    fireEvent.contextMenu(screen.getByRole("columnheader", { name: /At/ }));
    const panel = screen.getByRole("group", { name: "Filter At" });
    fireEvent.change(within(panel).getByLabelText("From date (UTC)"), { target: { value: "2026-07-01" } });
    fireEvent.change(within(panel).getByLabelText("To date (UTC)"), { target: { value: "2026-06-01" } });
    fireEvent.click(within(panel).getByRole("button", { name: "Apply" }));
    expect(within(panel).getByRole("alert")).toHaveTextContent("To is before From");
  });
});

describe("menus over neighbouring panes", () => {
  it("a cell menu sits on the document body, outside whatever clips or covers the table", () => {
    const { container } = render(<CellMenu x={10} y={10} items={[{ label: "Copy" }]} onClose={() => {}} />);
    const menu = screen.getByRole("menu");
    expect(container.contains(menu)).toBe(false);
    expect(menu.closest(".cell-menu-root")?.parentElement).toBe(document.body);
  });
});
