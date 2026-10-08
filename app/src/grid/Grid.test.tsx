import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { NavContext } from "../shell/nav";
import type { HighlightRule } from "../api";
import Grid from "./Grid";

describe("Grid", () => {
  it("renders headers and cells as text through displaySafe", () => {
    render(<Grid columns={["when", "what"]} rows={[["2026-03-01", "<img src=x>‮"], ["2026-03-02", null]]} />);
    expect(screen.getByText("when")).toBeInTheDocument();
    expect(screen.getByText("<img src=x>\\u{202E}")).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText("2026-03-02")).toBeInTheDocument();
  });
  it("escapes hostile column headers, keeping the raw name for filters and highlights", async () => {
    const onFilter = vi.fn();
    const hostile = ["safe\u202ereversed", "<b>x</b>"];
    render(
      <Grid
        columns={hostile}
        rows={[["v1", "v2"]]}
        cellActions={{ onFilter }}
        highlights={[{ column: hostile[0], op: "eq", value: "v1", colour: "red" }]}
      />,
    );
    expect(screen.getByText("safe\\u{202E}reversed")).toBeInTheDocument();
    expect(screen.getByText("<b>x</b>")).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
    expect(screen.getByText("v1").closest('[role="row"]')).toHaveClass("hl-red");
    fireEvent.contextMenu(screen.getByText("v1"));
    await userEvent.setup().click(screen.getByRole("menuitem", { name: "Filter by this value" }));
    expect(onFilter).toHaveBeenCalledExactlyOnceWith(hostile[0], "v1");
  });
  it("stringifies objects and numbers", () => {
    render(<Grid columns={["n", "o"]} rows={[[42, { a: 1 }]]} />);
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText('{"a":1}')).toBeInTheDocument();
  });
  it("calls onRowClick with the row and its index", async () => {
    const onRowClick = vi.fn();
    render(<Grid columns={["a"]} rows={[["x"], ["y"]]} onRowClick={onRowClick} />);
    await userEvent.setup().click(screen.getByText("y"));
    expect(onRowClick).toHaveBeenCalledWith(["y"], 1);
  });
  it("renders a window of a large row set, not every row", () => {
    const rows = Array.from({ length: 5000 }, (_, i) => [`row-${i}`]);
    render(<Grid columns={["a"]} rows={rows} height={200} />);
    expect(screen.getByText("row-0")).toBeInTheDocument();
    expect(screen.queryByText("row-4999")).toBeNull();
    const rendered = document.querySelectorAll('[data-row]').length;
    expect(rendered).toBeGreaterThan(0);
    expect(rendered).toBeLessThan(100);
  });
  it("says so when there are no rows", () => {
    render(<Grid columns={["a"]} rows={[]} />);
    expect(screen.getByText("No rows.")).toBeInTheDocument();
  });
});

describe("Grid cell actions", () => {
  const rows = [
    ["203.0.113.1", "marlowe.rhodes@contoso.example", "plain text"],
    ["2001:db8::1", "x", "<b>hi</b>\u202e"],
  ];
  const columns = ["ip", "who", "note"];
  const openMenu = (text: string) => {
    fireEvent.contextMenu(screen.getByText(text));
    return screen.getByRole("menu");
  };
  const withNav = (ui: React.ReactElement, openPivot = vi.fn()) => (
    <NavContext.Provider value={{ openPivot }}>{ui}</NavContext.Provider>
  );

  it("offers Pivot on IP only for an IP value, Pivot on account only for an account-shaped one", () => {
    render(withNav(<Grid columns={columns} rows={rows} />));
    let menu = openMenu("203.0.113.1");
    expect(within(menu).getByRole("menuitem", { name: "Pivot on IP 203.0.113.1" })).toBeInTheDocument();
    expect(within(menu).queryByRole("menuitem", { name: /Pivot on account/ })).toBeNull();
    fireEvent.keyDown(menu, { key: "Escape" });
    menu = openMenu("marlowe.rhodes@contoso.example");
    expect(within(menu).getByRole("menuitem", { name: "Pivot on account marlowe.rhodes@contoso.example" })).toBeInTheDocument();
    expect(within(menu).queryByRole("menuitem", { name: /Pivot on IP/ })).toBeNull();
    fireEvent.keyDown(menu, { key: "Escape" });
    menu = openMenu("plain text");
    expect(within(menu).queryByRole("menuitem", { name: /Pivot/ })).toBeNull();
    expect(within(menu).getByRole("menuitem", { name: "Copy" })).toBeInTheDocument();
  });

  it("hides the pivot actions outside a shell, and Filter/Highlight unless the host supports them", () => {
    render(<Grid columns={columns} rows={rows} />);
    const menu = openMenu("203.0.113.1");
    expect(within(menu).getAllByRole("menuitem").map((i) => i.textContent)).toEqual(["Copy"]);
  });

  it("Pivot calls the shell with the kind and the raw value, and closes the menu", async () => {
    const openPivot = vi.fn();
    render(withNav(<Grid columns={columns} rows={rows} />, openPivot));
    openMenu("2001:db8::1");
    await userEvent.setup().click(screen.getByRole("menuitem", { name: "Pivot on IP 2001:db8::1" }));
    expect(openPivot).toHaveBeenCalledExactlyOnceWith("ip", "2001:db8::1");
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("Filter and Highlight call the host with the column name and the raw value", async () => {
    const onFilter = vi.fn();
    const onHighlight = vi.fn();
    render(<Grid columns={columns} rows={rows} cellActions={{ onFilter, onHighlight }} />);
    const user = userEvent.setup();
    openMenu("plain text");
    await user.click(screen.getByRole("menuitem", { name: "Filter by this value" }));
    expect(onFilter).toHaveBeenCalledExactlyOnceWith("note", "plain text");
    openMenu("plain text");
    await user.click(screen.getByRole("menuitem", { name: "Highlight this value" }));
    expect(onHighlight).toHaveBeenCalledExactlyOnceWith("note", "plain text");
  });

  it("Copy writes the RAW value to the clipboard", async () => {
    const user = userEvent.setup();
    const write = vi.spyOn(navigator.clipboard, "writeText");
    render(<Grid columns={columns} rows={rows} />);
    openMenu("<b>hi</b>\\u{202E}");
    await user.click(screen.getByRole("menuitem", { name: "Copy" }));
    expect(write).toHaveBeenCalledExactlyOnceWith("<b>hi</b>\u202e");
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("Enter on a focused cell opens its menu; Escape closes it", async () => {
    const user = userEvent.setup();
    render(withNav(<Grid columns={columns} rows={rows} />));
    screen.getByText("203.0.113.1").focus();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("menuitem", { name: "Pivot on IP 203.0.113.1" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("does not open the row click when the menu opens", () => {
    const onRowClick = vi.fn();
    render(<Grid columns={columns} rows={rows} onRowClick={onRowClick} />);
    openMenu("plain text");
    expect(onRowClick).not.toHaveBeenCalled();
  });
});

describe("Grid highlights", () => {
  const columns = ["ip", "note"];
  const rows = [["203.0.113.1", "alpha"], ["198.51.100.7", "Beta <b>"], ["192.0.2.9", "gamma"]];
  const rowOf = (text: string) => screen.getByText(text).closest('[role="row"]')!;
  const rule = (r: Partial<HighlightRule>): HighlightRule => ({ column: null, op: "eq", value: "x", colour: "red", ...r });

  it("colours exactly the rows a rule matches, by the raw cell value", () => {
    render(<Grid columns={columns} rows={rows} highlights={[rule({ value: "203.0.113.1" })]} />);
    expect(rowOf("203.0.113.1")).toHaveClass("hl-red");
    expect(rowOf("198.51.100.7")).not.toHaveClass("hl-red");
    expect(rowOf("192.0.2.9")).not.toHaveClass("hl-red");
  });
  it("eq is exact; contains is a case-insensitive substring", () => {
    render(
      <Grid
        columns={columns}
        rows={rows}
        highlights={[rule({ op: "eq", value: "alph" }), rule({ column: "note", op: "contains", value: "BETA", colour: "blue" })]}
      />,
    );
    expect(rowOf("alpha")).not.toHaveClass("hl-red");
    expect(rowOf("Beta <b>")).toHaveClass("hl-blue");
  });
  it("a rule with a column looks only at that column; null looks at every column", () => {
    render(
      <Grid
        columns={columns}
        rows={rows}
        highlights={[rule({ column: "ip", op: "contains", value: "gamma" }), rule({ column: null, op: "contains", value: "ALPHA", colour: "green" })]}
      />,
    );
    expect(rowOf("gamma")).not.toHaveClass("hl-red");
    expect(rowOf("alpha")).toHaveClass("hl-green");
  });
  it("the first matching rule decides the colour", () => {
    render(<Grid columns={columns} rows={rows} highlights={[rule({ value: "alpha", colour: "amber" }), rule({ value: "alpha", colour: "red" })]} />);
    expect(rowOf("alpha")).toHaveClass("hl-amber");
    expect(rowOf("alpha")).not.toHaveClass("hl-red");
  });
  it("a colour that is not in the palette adds no class and no style", () => {
    const bad = rule({ value: "alpha", colour: 'red" onmouseover="x' as never });
    render(<Grid columns={columns} rows={rows} highlights={[bad]} />);
    const row = rowOf("alpha");
    expect(row.className).toBe("grid-row");
    expect(row.getAttribute("onmouseover")).toBeNull();
    expect(row.getAttribute("style")).not.toMatch(/red|color/i);
  });
  it("never sets an inline colour from data", () => {
    render(<Grid columns={columns} rows={rows} highlights={[rule({ value: "alpha" })]} />);
    expect(rowOf("alpha").getAttribute("style")).not.toMatch(/background|color/i);
  });
});

