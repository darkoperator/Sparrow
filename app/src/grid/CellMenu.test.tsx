import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import CellMenu, { type MenuItem } from "./CellMenu";

function setup() {
  const run = { a: vi.fn(), sus: vi.fn(), mal: vi.fn(), off: vi.fn() };
  const onClose = vi.fn();
  const items: MenuItem[] = [
    { label: "Copy", run: run.a },
    {
      label: "Flag this event",
      items: [
        { label: "Suspicious", run: run.sus },
        { label: "Malicious", run: run.mal },
      ],
    },
    { label: "Add note…", run: run.off, disabled: "Read-only case" },
  ];
  render(<CellMenu x={10} y={10} items={items} onClose={onClose} />);
  return { run, onClose, user: userEvent.setup() };
}
const focused = () => document.activeElement?.textContent ?? "";

describe("CellMenu", () => {
  it("keyboard_navigation_in_submenus", async () => {
    const { run, onClose, user } = setup();
    // The first item has the focus; arrows move and wrap.
    expect(focused()).toBe("Copy");
    await user.keyboard("{ArrowDown}");
    expect(focused()).toBe("Flag this event▸");
    // → opens the submenu and focuses its first item; ↑↓ wrap inside it only.
    await user.keyboard("{ArrowRight}");
    expect(screen.getAllByRole("menu")).toHaveLength(2);
    expect(focused()).toBe("Suspicious");
    await user.keyboard("{ArrowDown}");
    expect(focused()).toBe("Malicious");
    await user.keyboard("{ArrowDown}");
    expect(focused()).toBe("Suspicious");
    await user.keyboard("{ArrowUp}");
    expect(focused()).toBe("Malicious");
    // ← closes the submenu and returns to its parent item.
    await user.keyboard("{ArrowLeft}");
    expect(screen.getAllByRole("menu")).toHaveLength(1);
    expect(focused()).toBe("Flag this event▸");
    // Enter opens it; Escape closes only the submenu; a second Escape closes the menu.
    await user.keyboard("{Enter}");
    expect(focused()).toBe("Suspicious");
    await user.keyboard("{Escape}");
    expect(screen.getAllByRole("menu")).toHaveLength(1);
    expect(focused()).toBe("Flag this event▸");
    expect(onClose).not.toHaveBeenCalled();
    // Space opens it too.
    await user.keyboard(" ");
    expect(focused()).toBe("Suspicious");
    await user.keyboard("{Escape}");
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(run.sus).not.toHaveBeenCalled();
  });

  it("enter_on_a_submenu_item_runs_it_and_closes_the_menu", async () => {
    const { run, onClose, user } = setup();
    await user.keyboard("{ArrowDown}{ArrowRight}{ArrowDown}{Enter}");
    expect(run.mal).toHaveBeenCalledTimes(1);
    expect(run.sus).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("a_disabled_item_shows_its_reason_and_does_nothing", async () => {
    const { run, onClose, user } = setup();
    const off = screen.getByRole("menuitem", { name: "Add note…" });
    expect(off).toHaveAttribute("aria-disabled", "true");
    expect(off).toHaveAttribute("title", "Read-only case");
    await user.click(off);
    expect(run.off).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("hover_and_click_open_a_submenu_and_a_click_elsewhere_closes_the_menu", async () => {
    const { run, onClose, user } = setup();
    await user.hover(screen.getByRole("menuitem", { name: "Flag this event" }));
    expect(screen.getByRole("menuitem", { name: "Malicious" })).toBeInTheDocument();
    await user.click(screen.getByRole("menuitem", { name: "Suspicious" }));
    expect(run.sus).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
    onClose.mockClear();
    await user.click(document.body);
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
