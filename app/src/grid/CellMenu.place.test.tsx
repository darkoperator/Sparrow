// Where a menu and its submenus go: inside the window whatever the click position, capped at the window height with
// their own scroll, and never inside a scrolling parent (a fixed submenu is not clipped by it). jsdom has no layout, so
// the boxes are faked: a menu is 200px wide and 28px per item plus 12px of padding, an item sits at its place in it.
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EventRow } from "../api";
import { pivotMenu, rowMenu } from "../marks/rowMenu";
import CellMenu, { type MenuItem } from "./CellMenu";

const ROW = 28;
const rect = (left: number, top: number, width: number, height: number): DOMRect =>
  ({ left, top, width, height, right: left + width, bottom: top + height, x: left, y: top, toJSON: () => ({}) }) as DOMRect;

/** The menu's own box: where its inline style puts it, as tall as its items (capped by its max-height). */
function menuBox(el: HTMLElement): DOMRect {
  const left = parseFloat(el.style.left) || 0;
  const top = parseFloat(el.style.top) || 0;
  const cap = el.style.maxHeight ? parseFloat(el.style.maxHeight) : Infinity;
  const h = Math.min(el.querySelectorAll(":scope > .cell-menu-row").length * ROW + 12, cap);
  return rect(left, top, 200, h);
}

beforeEach(() => {
  Object.defineProperty(window, "innerWidth", { configurable: true, value: 1024 });
  Object.defineProperty(window, "innerHeight", { configurable: true, value: 300 });
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (this: HTMLElement) {
    if (this.classList.contains("cell-menu-root")) return menuBox(this.querySelector<HTMLElement>(":scope > .cell-menu")!);
    if (this.classList.contains("cell-menu")) return menuBox(this);
    const list = this.closest<HTMLElement>(".cell-menu");
    if (list && this.getAttribute("role")?.startsWith("menuitem")) {
      const at = [...list.querySelectorAll(":scope > .cell-menu-row")].indexOf(this.parentElement!);
      const box = menuBox(list);
      return rect(box.left, box.top + 6 + at * ROW, 200, ROW);
    }
    return rect(0, 0, 0, 0);
  });
});
afterEach(() => vi.restoreAllMocks());

const many = (n: number, prefix = "Item"): MenuItem[] => Array.from({ length: n }, (_, i) => ({ label: `${prefix} ${i}`, run: () => {} }));
const sub = (n: number): MenuItem => ({ label: "Flag", items: many(n, "Level") });
const menus = () => screen.getAllByRole("menu");
const px = (el: HTMLElement, prop: "left" | "top" | "maxHeight") => parseFloat(el.style[prop]);

describe("CellMenu placement", () => {
  it("a_menu_opened_low_opens_upward_to_stay_inside_the_window", () => {
    // 5 items are 152px tall; at y=250 only 50px are left below the pointer.
    render(<CellMenu x={20} y={250} items={many(5)} onClose={() => {}} />);
    const top = px(menus()[0], "top");
    expect(top).toBe(250 - 152);
    expect(top + 152).toBeLessThanOrEqual(300);
  });

  it("a_menu_taller_than_the_window_is_capped_at_the_window_height_and_scrolls", () => {
    // 40 items are 1132px tall; the window is 300px, with an 8px margin each side.
    render(<CellMenu x={20} y={120} items={many(40)} onClose={() => {}} />);
    const m = menus()[0];
    expect(px(m, "maxHeight")).toBe(300 - 16);
    expect(px(m, "top")).toBe(8);
    expect(m.style.overflowY).toBe("auto");
  });

  it("a_menu_opened_at_the_right_edge_shifts_left_into_the_window", () => {
    render(<CellMenu x={1000} y={20} items={many(3)} onClose={() => {}} />);
    expect(px(menus()[0], "left")).toBe(1024 - 200 - 8);
  });

  it("a_menu_that_fits_stays_where_it_was_opened", () => {
    render(<CellMenu x={40} y={30} items={many(3)} onClose={() => {}} />);
    expect(px(menus()[0], "left")).toBe(40);
    expect(px(menus()[0], "top")).toBe(30);
  });

  it("a_submenu_is_fixed_beside_its_item_and_shifts_up_to_stay_inside_the_window", async () => {
    const user = userEvent.setup();
    // 3 items open upward from y=150 (top 54); the last, "Flag", sits at 54+6+56=116..144 and its 4-item submenu is 124px
    // tall: at the item's top (-5px) it would end at 235, which fits, so push the window in to force the shift.
    Object.defineProperty(window, "innerHeight", { configurable: true, value: 200 });
    render(<CellMenu x={20} y={60} items={[...many(2), sub(4)]} onClose={() => {}} />);
    await user.hover(screen.getByRole("menuitem", { name: "Flag" }));
    const [root, submenu] = menus();
    expect(submenu.style.position).toBe("fixed");
    expect(root.contains(submenu)).toBe(true);
    const top = px(submenu, "top");
    expect(top).toBeGreaterThanOrEqual(8);
    expect(top + 124).toBeLessThanOrEqual(200 - 8);
    expect(px(submenu, "left")).toBe(px(root, "left") + 200);
  });

  it("a_submenu_that_does_not_fit_on_the_right_opens_to_the_left", async () => {
    const user = userEvent.setup();
    render(<CellMenu x={700} y={20} items={[sub(2)]} onClose={() => {}} />);
    await user.hover(screen.getByRole("menuitem", { name: "Flag" }));
    const [root, submenu] = menus();
    // 700+200 leaves 124px on the right, the submenu is 200 wide.
    expect(px(submenu, "left")).toBe(px(root, "left") - 200);
  });

  it("a_submenu_taller_than_the_window_is_capped_and_scrolls", async () => {
    const user = userEvent.setup();
    render(<CellMenu x={20} y={20} items={[{ label: "Tag", items: many(40, "Tag") }]} onClose={() => {}} />);
    await user.hover(screen.getByRole("menuitem", { name: "Tag" }));
    const submenu = menus()[1];
    expect(px(submenu, "maxHeight")).toBe(300 - 16);
    expect(px(submenu, "top")).toBe(8);
    expect(submenu.style.overflowY).toBe("auto");
  });
});

describe("every submenu item opens its submenu", () => {
  const ev = (): EventRow => ({ source_table: "ual", record_key: "k", ip: "192.0.2.5", ip_prefix: "192.0.2.0/24" }) as unknown as EventRow;
  const act = {
    showDetails: vi.fn(), filter: vi.fn(), openEntity: vi.fn(), flagRows: vi.fn(), flagValue: vi.fn(), tagRows: vi.fn(),
    newTag: vi.fn(), addNote: vi.fn(), addToTimeline: vi.fn(),
  };
  const ticked = Array.from({ length: 600 }, (_, i) => ({ ...ev(), record_key: `k${i}`, tags: [] }) as unknown as EventRow);
  const cases: [string, MenuItem[]][] = [
    ["the pivot row menu", pivotMenu("ips", "192.0.2.5", { entity: { kind: "account", value: "a@contoso.example" }, readOnly: null, act })],
    [
      "the menu of 600 ticked events",
      rowMenu(
        { column: "operation", row: ticked[0], ticked },
        { readOnly: null, tags: [{ name: "bec", count: 3 }] as never, canOpen: false, act },
      ),
    ],
  ];

  for (const [name, items] of cases) {
    const parents = items.filter((i) => i.items);
    it(`${name}: hover, click, ArrowRight and Enter each open it, inside the window`, async () => {
      expect(parents.length).toBeGreaterThan(0);
      for (const how of ["hover", "click", "ArrowRight", "Enter"]) {
        const user = userEvent.setup();
        const { unmount } = render(<CellMenu x={20} y={20} items={items} onClose={() => {}} />);
        for (const p of parents) {
          const item = screen.getByRole("menuitem", { name: p.label });
          if (how === "hover") await user.hover(item);
          else if (how === "click") await user.click(item);
          else {
            item.focus();
            await user.keyboard(`{${how}}`);
          }
          const open = menus().filter((m) => m.classList.contains("cell-submenu"));
          expect(open, `${how} on ${p.label}`).toHaveLength(1);
          expect(open[0].style.position).toBe("fixed");
          expect(px(open[0], "top") + (open[0].getBoundingClientRect().height || 0)).toBeLessThanOrEqual(300 - 8);
          await user.keyboard("{Escape}");
          expect(menus()).toHaveLength(1);
        }
        unmount();
      }
    });
  }
});
