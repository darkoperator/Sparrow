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
  const withNav = (ui: React.ReactElement, openEntity = vi.fn()) => (
    <NavContext.Provider value={{ openEntity, openTable: vi.fn(), showInEvents: vi.fn() }}>{ui}</NavContext.Provider>
  );

  it("offers an IP tab only for an IP value, an account tab only for an account-shaped one", () => {
    render(withNav(<Grid columns={columns} rows={rows} />));
    let menu = openMenu("203.0.113.1");
    expect(within(menu).getByRole("menuitem", { name: "Open IP tab" })).toBeInTheDocument();
    expect(within(menu).queryByRole("menuitem", { name: /Open account tab/ })).toBeNull();
    fireEvent.keyDown(menu, { key: "Escape" });
    menu = openMenu("marlowe.rhodes@contoso.example");
    expect(within(menu).getByRole("menuitem", { name: "Open account tab" })).toBeInTheDocument();
    expect(within(menu).queryByRole("menuitem", { name: /Open IP tab/ })).toBeNull();
    fireEvent.keyDown(menu, { key: "Escape" });
    menu = openMenu("plain text");
    expect(within(menu).queryByRole("menuitem", { name: /Open .* tab/ })).toBeNull();
    expect(within(menu).getByRole("menuitem", { name: "Copy" })).toBeInTheDocument();
  });

  it("hides the tab actions outside a shell, and Filter/Highlight unless the host supports them", () => {
    render(<Grid columns={columns} rows={rows} />);
    const menu = openMenu("203.0.113.1");
    expect(within(menu).getAllByRole("menuitem").map((i) => i.textContent)).toEqual(["Copy", "Show full value"]);
  });

  it("Open tab calls the shell with the kind and the raw value, and closes the menu", async () => {
    const openEntity = vi.fn();
    render(withNav(<Grid columns={columns} rows={rows} />, openEntity));
    openMenu("2001:db8::1");
    await userEvent.setup().click(screen.getByRole("menuitem", { name: "Open IP tab" }));
    expect(openEntity).toHaveBeenCalledExactlyOnceWith({ kind: "ip", value: "2001:db8::1" });
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
    expect(screen.getByRole("menuitem", { name: "Open IP tab" })).toBeInTheDocument();
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


describe("Grid layout", () => {
  it("header and body share one scroll container, and the header is sticky", () => {
    render(<Grid columns={["a", "b"]} rows={[["x", "y"]]} />);
    const scroller = document.querySelector(".grid-scroll") as HTMLElement;
    expect(scroller).not.toBeNull();
    const header = screen.getByText("a").closest(".grid-head") as HTMLElement;
    expect(scroller.contains(header)).toBe(true);
    expect(header).toHaveClass("grid-head-sticky");
    expect(scroller.contains(screen.getByText("x"))).toBe(true);
  });
  it("the grid container is bounded and scrolls inside itself", () => {
    render(<Grid columns={["a"]} rows={[["x"]]} />);
    const grid = document.querySelector(".grid") as HTMLElement;
    expect(grid).toHaveClass("grid-bounded");
    expect(grid.querySelector(".grid-scroll")).not.toBeNull();
  });
  it("dragging a header edge resizes that column for header and rows", () => {
    render(<Grid columns={["a", "b"]} rows={[["x", "y"]]} />);
    const head = document.querySelector(".grid-head") as HTMLElement;
    const row = screen.getByText("x").closest('[role="row"]') as HTMLElement;
    const before = head.style.gridTemplateColumns;
    expect(before).toBe("180px 180px");
    const handle = screen.getAllByRole("separator")[0];
    fireEvent.mouseDown(handle, { clientX: 100 });
    fireEvent.mouseMove(document, { clientX: 160 });
    fireEvent.mouseUp(document, { clientX: 160 });
    expect(head.style.gridTemplateColumns).toBe("240px 180px");
    expect(row.style.gridTemplateColumns).toBe("240px 180px");
  });
});

describe("Grid value viewer", () => {
  const long = "line one\nline two <b>x</b>‮" + "z".repeat(300);
  it("double-click opens a dialog with the complete value, escaped, and the column name", async () => {
    render(<Grid columns={["note"]} rows={[[long]]} />);
    fireEvent.doubleClick(screen.getByRole("cell"));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("note")).toBeInTheDocument();
    const body = dialog.querySelector("pre") as HTMLElement;
    expect(body.textContent).toBe("line one\nline two <b>x</b>\\u{202E}" + "z".repeat(300));
    expect(dialog.querySelector("b")).toBeNull();
  });
  it("pretty-prints objects and JSON text", () => {
    render(<Grid columns={["o", "s"]} rows={[[{ a: 1, b: [2] }, '{"k":"v"}']]} />);
    const cells = screen.getAllByRole("cell");
    fireEvent.doubleClick(cells[0]);
    expect(screen.getByRole("dialog").querySelector("pre")!.textContent).toBe(JSON.stringify({ a: 1, b: [2] }, null, 2));
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    fireEvent.doubleClick(cells[1]);
    expect(screen.getByRole("dialog").querySelector("pre")!.textContent).toBe('{\n  "k": "v"\n}');
  });
  it("Copy copies the raw value, not the escaped one", async () => {
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
    render(<Grid columns={["note"]} rows={[[long]]} />);
    fireEvent.doubleClick(screen.getByRole("cell"));
    await user.click(screen.getByRole("button", { name: "Copy" }));
    expect(writeText).toHaveBeenCalledExactlyOnceWith(long);
  });
  it("Escape closes it and focus returns to the cell", () => {
    render(<Grid columns={["note"]} rows={[["v"]]} />);
    const cell = screen.getByRole("cell");
    cell.focus();
    fireEvent.doubleClick(cell);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(cell).toHaveFocus();
  });
  it("the cell menu offers Show full value", async () => {
    render(<Grid columns={["note"]} rows={[["v"]]} />);
    fireEvent.contextMenu(screen.getByRole("cell"));
    await userEvent.setup().click(screen.getByRole("menuitem", { name: "Show full value" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });
});

describe("Grid keyboard navigation", () => {
  const many = Array.from({ length: 300 }, (_, i) => [`r${i}-a`, `r${i}-b`]);
  // jsdom has no layout: give the scroller its sizes, and make scrollTo set scrollTop and raise the scroll event the
  // virtualizer listens to.
  const withScrollTo = () => {
    const proto = HTMLElement.prototype as unknown as { scrollTo?: unknown };
    const saved = proto.scrollTo;
    const heights = Object.defineProperties(HTMLElement.prototype, {
      scrollHeight: { configurable: true, get: () => 26 * 301 },
      clientHeight: { configurable: true, get: () => 226 },
    });
    void heights;
    proto.scrollTo = function (this: HTMLElement, o: { top?: number }) {
      Object.defineProperty(this, "scrollTop", { value: o.top ?? 0, configurable: true, writable: true });
      this.dispatchEvent(new Event("scroll"));
    };
    return () => {
      proto.scrollTo = saved;
      delete (HTMLElement.prototype as unknown as Record<string, unknown>).scrollHeight;
      delete (HTMLElement.prototype as unknown as Record<string, unknown>).clientHeight;
    };
  };
  it("has one tab stop, and arrows move between cells", async () => {
    render(<Grid columns={["a", "b"]} rows={many} height={200} />);
    expect(screen.getAllByRole("cell").filter((c) => c.tabIndex === 0)).toHaveLength(1);
    const user = userEvent.setup();
    screen.getByText("r0-a").focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByText("r0-b")).toHaveFocus();
    await user.keyboard("{ArrowDown}");
    expect(screen.getByText("r1-b")).toHaveFocus();
    await user.keyboard("{ArrowLeft}{ArrowUp}");
    expect(screen.getByText("r0-a")).toHaveFocus();
    expect(screen.getAllByRole("cell").filter((c) => c.tabIndex === 0)).toHaveLength(1);
  });
  it("moving past the rendered window scrolls to the row and focuses it", async () => {
    const restore = withScrollTo();
    try {
      render(<Grid columns={["a", "b"]} rows={many} height={200} />);
      expect(screen.queryByText("r132-a")).toBeNull();
      screen.getByText("r0-a").focus();
      const user = userEvent.setup();
      // PageDown steps (6 rows each at this height) until the target row is far beyond the initial window.
      for (let i = 0; i < 22; i++) await user.keyboard("{PageDown}");
      const cell = await screen.findByText("r132-a");
      await vi.waitFor(() => expect(cell).toHaveFocus());
    } finally {
      restore();
    }
  });
  it("when the active row scrolls out of the window, a visible cell becomes the tab stop", async () => {
    const restore = withScrollTo();
    try {
      render(
        <>
          <button>before</button>
          <Grid columns={["a", "b"]} rows={many} height={200} />
        </>,
      );
      const scroller = document.querySelector(".grid-scroll") as HTMLElement;
      expect(screen.getByText("r0-a")).toHaveAttribute("tabindex", "0");
      scroller.scrollTo({ top: 26 * 200 });
      await vi.waitFor(() => expect(screen.queryByText("r0-a")).toBeNull());
      const stops = screen.getAllByRole("cell").filter((c) => c.tabIndex === 0);
      expect(stops).toHaveLength(1);
      screen.getByRole("button", { name: "before" }).focus();
      await userEvent.setup().tab();
      const row = Number(document.activeElement?.closest("[data-row]")?.getAttribute("data-row"));
      expect(document.activeElement).toBe(stops[0]);
      expect(row).toBeGreaterThan(150);
    } finally {
      restore();
    }
  });
  it("Tab leaves the grid instead of walking cells", async () => {
    render(
      <>
        <Grid columns={["a", "b"]} rows={many} height={200} />
        <button>after</button>
      </>,
    );
    screen.getByText("r0-a").focus();
    await userEvent.setup().tab();
    expect(screen.getByRole("button", { name: "after" })).toHaveFocus();
  });
});

describe("Grid value viewer focus", () => {
  it("Tab and Shift+Tab stay inside the dialog; Escape still closes after tabbing", async () => {
    const user = userEvent.setup();
    render(
      <>
        <button>outside</button>
        <Grid columns={["note"]} rows={[["v"]]} />
      </>,
    );
    const cell = screen.getByRole("cell");
    cell.focus();
    fireEvent.doubleClick(cell);
    const dialog = screen.getByRole("dialog");
    for (let i = 0; i < 5; i++) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
    for (let i = 0; i < 5; i++) {
      await user.tab({ shift: true });
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
    await user.tab();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(cell).toHaveFocus();
  });
  it("focus returns to the cell when closed with the Close button", async () => {
    const user = userEvent.setup();
    render(<Grid columns={["note"]} rows={[["v"]]} />);
    const cell = screen.getByRole("cell");
    cell.focus();
    fireEvent.doubleClick(cell);
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(cell).toHaveFocus();
  });
});

describe("Grid cell menu: entity tabs by column", () => {
  const guid = "4F1C0000-1111-2222-3333-44449A2E5555";
  const columns = ["entra_session_id", "device_id", "other", "actor_upn"];
  const rows = [[guid, guid, guid, "JDoe@Contoso.example"]];
  const openMenuAt = (n: number) => {
    fireEvent.contextMenu(screen.getAllByText(guid)[n]);
    return screen.getByRole("menu");
  };
  const wrap = (openEntity = vi.fn()) => (
    <NavContext.Provider value={{ openEntity, openTable: vi.fn(), showInEvents: vi.fn() }}>
      <Grid columns={columns} rows={rows} />
    </NavContext.Provider>
  );

  it("an entra_session_id cell offers Open session tab and passes the raw value", async () => {
    const openEntity = vi.fn();
    render(wrap(openEntity));
    const menu = openMenuAt(0);
    expect(within(menu).getAllByRole("menuitem").map((i) => i.textContent)).toEqual([
      "Copy",
      "Show full value",
      "Open session tab",
    ]);
    await userEvent.setup().click(within(menu).getByRole("menuitem", { name: "Open session tab" }));
    expect(openEntity).toHaveBeenCalledExactlyOnceWith({ kind: "session", value: guid });
  });

  it("a device_id cell offers Open device tab; a GUID in another column offers none", () => {
    render(wrap());
    let menu = openMenuAt(1);
    expect(within(menu).getByRole("menuitem", { name: "Open device tab" })).toBeInTheDocument();
    fireEvent.keyDown(menu, { key: "Escape" });
    menu = openMenuAt(2);
    expect(within(menu).queryByRole("menuitem", { name: /Open .* tab/ })).toBeNull();
  });

  it("an actor_upn cell offers Open account tab", () => {
    render(wrap());
    fireEvent.contextMenu(screen.getByText("JDoe@Contoso.example"));
    expect(within(screen.getByRole("menu")).getByRole("menuitem", { name: "Open account tab" })).toBeInTheDocument();
  });
});
