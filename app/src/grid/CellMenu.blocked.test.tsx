// With no analyst name every write item is disabled: the menu says why on the item itself, and choosing one takes the
// analyst to the name prompt instead of doing nothing.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { EventRow } from "../api";
import { pivotMenu, rowMenu } from "../marks/rowMenu";
import { writeBlockedReason } from "../shell/nav";
// @ts-expect-error the app has no node typings; Vitest runs in node and its CSS imports come back empty
import { readFileSync } from "node:fs";
import CellMenu, { type MenuItem } from "./CellMenu";

const WHY = writeBlockedReason(null, null)!;
const act = {
  showDetails: vi.fn(), filter: vi.fn(), openEntity: vi.fn(), flagRows: vi.fn(), flagValue: vi.fn(), tagRows: vi.fn(),
  newTag: vi.fn(), addNote: vi.fn(), addToTimeline: vi.fn(),
};
const ev = (i: number) => ({ source_table: "ual", record_key: `k${i}`, ip: "192.0.2.5", tags: [] }) as unknown as EventRow;
const ticked = Array.from({ length: 600 }, (_, i) => ev(i));

function menus(focusAnalyst: () => void): [string, MenuItem[]][] {
  return [
    ["the 600 ticked events menu", rowMenu({ column: "operation", row: ticked[0], ticked }, { readOnly: WHY, focusAnalyst, tags: [], canOpen: false, act })],
    ["the pivot menu", pivotMenu("ips", "192.0.2.5", { readOnly: WHY, focusAnalyst, act })],
  ];
}

describe("a menu with no analyst name", () => {
  it("shows the reason on each blocked item and describes the item with it", () => {
    for (const [, items] of menus(() => {})) {
      const { unmount } = render(<CellMenu x={10} y={10} items={items} onClose={() => {}} />);
      const blocked = items.filter((i) => i.disabled !== undefined);
      expect(blocked.length).toBeGreaterThan(0);
      expect(screen.getAllByText(WHY)).toHaveLength(blocked.length);
      for (const it of blocked) {
        const el = screen.getByRole("menuitem", { name: it.label });
        expect(el).toHaveAttribute("aria-disabled", "true");
        expect(el).toHaveAccessibleDescription(WHY);
      }
      unmount();
    }
  });

  for (const how of ["click", "Enter", "ArrowRight"]) {
    it(`choosing a blocked item with ${how} opens no submenu, closes the menu and focuses the analyst name`, async () => {
      const focus = vi.fn();
      for (const [, set] of menus(focus)) {
        focus.mockClear();
        const onClose = vi.fn();
        const user = userEvent.setup();
        const { unmount } = render(<CellMenu x={10} y={10} items={set} onClose={onClose} />);
        const first = set.find((i) => i.items && i.disabled !== undefined)!;
        const el = screen.getByRole("menuitem", { name: first.label });
        if (how === "click") await user.click(el);
        else {
          el.focus();
          await user.keyboard(`{${how}}`);
        }
        expect(screen.getAllByRole("menu")).toHaveLength(1);
        expect(onClose).toHaveBeenCalledTimes(1);
        await waitFor(() => expect(focus).toHaveBeenCalledTimes(1));
        unmount();
      }
    });
  }

  it("a blocked item without a way to fix it (a read-only case) just does nothing", async () => {
    const onClose = vi.fn();
    const items = rowMenu({ column: "operation", row: ticked[0], ticked }, { readOnly: "Read-only case: x", tags: [], canOpen: false, act });
    render(<CellMenu x={10} y={10} items={items} onClose={onClose} />);
    await userEvent.setup().click(screen.getByRole("menuitem", { name: /^Flag 600/ }));
    expect(screen.getAllByRole("menu")).toHaveLength(1);
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getAllByText("Read-only case: x").length).toBeGreaterThan(0);
  });

  it("the reason is full strength: only the label and the arrow of a disabled item dim", () => {
    const gridCss: string = readFileSync("src/grid/grid.css", "utf8"); // Vitest runs from the app folder
    expect(gridCss).toContain(".cell-menu-reason");
    const rule = (sel: string) => gridCss.split("\n").filter((l: string) => l.startsWith(sel)).join("\n");
    // The whole-button opacity is what made the reason faint.
    expect(rule('.cell-menu button[aria-disabled="true"] {')).not.toMatch(/opacity/);
    expect(rule('.cell-menu button[aria-disabled="true"] .cell-menu-label')).toMatch(/opacity: 0\.5/);
    expect(rule(".cell-menu-reason")).toMatch(/color: var\(--text-2\)/);
    expect(rule(".cell-menu-reason")).not.toMatch(/opacity/);
    render(<CellMenu x={10} y={10} items={[{ label: "Add note…", disabled: WHY }]} onClose={() => {}} />);
    const reason = screen.getByText(WHY);
    expect(reason).toHaveClass("cell-menu-reason");
    expect(reason.closest(".cell-menu-label")).toBeNull();
  });
});
