import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { EventRow, TagInfo } from "../api";
import CellMenu from "../grid/CellMenu";
import * as fx from "../test/fixtures";
import { tagItems } from "./TagMenu";

const base = fx.eventsList()[0];
const row = (key: string, tags: string[]): EventRow => ({ ...base, record_key: key, tags: tags.map((name) => ({ name, ai: false })) });
const info = (names: string[]): TagInfo[] => names.map((name) => ({ name, count: 1, agent_unreviewed: 0 }));
const ref = (r: EventRow) => ({ source_table: r.source_table, record_key: r.record_key });

function act() {
  return { tagRows: vi.fn(), newTag: vi.fn() };
}

describe("tag menu", () => {
  it("tag_menu_tristate_and_filter_box", async () => {
    // Over the three selected events: beta is on all of them, alpha on two, gamma on none.
    const rows = [row("a", ["alpha", "beta"]), row("b", ["alpha", "beta"]), row("c", ["beta"])];
    const a = act();
    const items = tagItems(info(["gamma", "beta", "alpha"]), rows, a);
    expect(items.map((i) => [i.label, i.checked])).toEqual([
      ["alpha", "mixed"],
      ["beta", true],
      ["gamma", false],
      ["New tag…", undefined],
    ]);
    expect(items[3].pinned).toBe(true);
    // All carry it: the click removes it. Mixed or none: it is added.
    items[1].run!();
    expect(a.tagRows).toHaveBeenLastCalledWith(rows.map(ref), "beta", false);
    items[0].run!();
    expect(a.tagRows).toHaveBeenLastCalledWith(rows.map(ref), "alpha", true);
    items[2].run!();
    expect(a.tagRows).toHaveBeenLastCalledWith(rows.map(ref), "gamma", true);
    items[3].run!();
    expect(a.newTag).toHaveBeenCalledWith(rows.map(ref));

    // Rendered: ticks show as checked / mixed / unchecked.
    const user = userEvent.setup();
    const { unmount } = render(<CellMenu x={0} y={0} onClose={() => undefined} items={[{ label: "Tag 3 ticked events", filter: true, items }]} />);
    await user.click(screen.getByRole("menuitem", { name: "Tag 3 ticked events" }));
    expect(screen.getByRole("menuitemcheckbox", { name: "alpha" })).toHaveAttribute("aria-checked", "mixed");
    expect(screen.getByRole("menuitemcheckbox", { name: "beta" })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByRole("menuitemcheckbox", { name: "gamma" })).toHaveAttribute("aria-checked", "false");
    // Twelve tags or fewer: no filter box.
    expect(screen.queryByRole("searchbox")).not.toBeInTheDocument();
    unmount();

    // Thirteen tags: a filter box above them; "New tag…" stays whatever is typed.
    const names = Array.from({ length: 13 }, (_, i) => `tag-${String(i).padStart(2, "0")}`);
    const many = tagItems(info(names), [row("a", [])], act());
    render(<CellMenu x={0} y={0} onClose={() => undefined} items={[{ label: "Tag this event", filter: true, items: many }]} />);
    await user.click(screen.getByRole("menuitem", { name: "Tag this event" }));
    const box = screen.getByRole("searchbox", { name: "Filter" });
    expect(box).toHaveFocus();
    expect(screen.getAllByRole("menuitemcheckbox")).toHaveLength(13);
    await user.type(box, "TAG-1");
    expect(screen.getAllByRole("menuitemcheckbox").map((e) => e.textContent)).toEqual(["tag-10", "tag-11", "tag-12"]);
    expect(screen.getByRole("menuitem", { name: "New tag…" })).toBeInTheDocument();
    await user.clear(box);
    await user.type(box, "zzz");
    expect(screen.queryAllByRole("menuitemcheckbox")).toHaveLength(0);
    expect(screen.getByRole("menuitem", { name: "New tag…" })).toBeInTheDocument();
    // ↓ from the box moves to the first item left.
    await user.keyboard("{ArrowDown}");
    expect(document.activeElement?.textContent).toBe("New tag…");
  });

  it("exactly_twelve_tags_show_no_filter_box", async () => {
    const names = Array.from({ length: 12 }, (_, i) => `t${i}`);
    render(<CellMenu x={0} y={0} onClose={() => undefined} items={[{ label: "Tag this event", filter: true, items: tagItems(info(names), [row("a", [])], act()) }]} />);
    await userEvent.setup().click(screen.getByRole("menuitem", { name: "Tag this event" }));
    expect(screen.getAllByRole("menuitemcheckbox")).toHaveLength(12);
    expect(screen.queryByRole("searchbox")).not.toBeInTheDocument();
  });
});
