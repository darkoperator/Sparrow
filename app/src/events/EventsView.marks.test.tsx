import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  calls: [] as { cmd: string; args: Record<string, unknown> | undefined }[],
  override: {} as Record<string, (args: Record<string, unknown> | undefined) => unknown>,
}));
vi.mock("@tauri-apps/api/core", () => ({
  invoke: async (cmd: string, args?: Record<string, unknown>) => {
    h.calls.push({ cmd, args });
    if (h.override[cmd]) return h.override[cmd](args);
    return (await import("../mock/backend")).mockCall(cmd, args);
  },
}));
vi.mock("../dialog", () => ({ save: vi.fn(), open: vi.fn() }));

import type { EventDetail as Detail, EventQuery, EventRow, RowRef } from "../api";
import { NavContext, RefreshBadgesContext, WriteBlockedContext, type Nav } from "../shell/nav";
import EventsView, { indicatorNote, type EventsViewProps } from "./EventsView";
import { DEFAULT_VISIBLE } from "./columns";

// The mock backend keeps its marks between calls, so each test starts from a fresh one.
let mockCall: typeof import("../mock/backend").mockCall;
const COLS = ["_tick", ...DEFAULT_VISIBLE];
const ALL: EventQuery = { fields: [], flag: "all", ai: "all" };
const refOf = (r: EventRow): RowRef => ({ source_table: r.source_table, record_key: r.record_key });
const callsOf = (cmd: string) => h.calls.filter((c) => c.cmd === cmd);
const shown = (a: number, b: number) => screen.findByText(`${a} of ${b} shown`);
const dataRows = () => screen.getAllByRole("row").slice(1);
const cell = (row: number, col: string) => within(dataRows()[row]).getAllByRole("cell")[COLS.indexOf(col)];
const tick = async (user: ReturnType<typeof userEvent.setup>, row: number) =>
  user.click(within(dataRows()[row]).getByRole("checkbox", { name: "Select event" }));
const menu = (name: string) => screen.getByRole("menuitem", { name });

let all: EventRow[];
const badges = vi.fn();
const nav = (): Nav => ({ openEntity: vi.fn(), openTable: vi.fn(), showInEvents: vi.fn(), openFinding: vi.fn() });

const WRITE_BLOCKED = "Read-only case: the case file is older than this version";

function view(props: EventsViewProps & { writeBlocked?: string } = {}) {
  const { writeBlocked, ...rest } = props;
  const n = nav();
  render(
    <NavContext.Provider value={n}>
      <RefreshBadgesContext.Provider value={badges}>
        <WriteBlockedContext.Provider value={writeBlocked ?? null}>
          <EventsView {...rest} />
        </WriteBlockedContext.Provider>
      </RefreshBadgesContext.Provider>
    </NavContext.Provider>,
  );
  return n;
}

beforeEach(async () => {
  h.calls.length = 0;
  for (const k of Object.keys(h.override)) delete h.override[k];
  badges.mockReset();
  localStorage.clear();
  vi.resetModules();
  mockCall = (await import("../mock/backend")).mockCall;
  await mockCall("case_open", { path: "/x.duckdb", allowUpgrade: false });
  all = (await mockCall<{ rows: EventRow[] }>("events_page", { query: ALL, sort: null, offset: 0, limit: 500 })).rows;
});

describe("EventsView marking", () => {
  it("flag_one_event_from_its_menu_reloads_the_grid_and_refreshes_the_badges", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    const target = all[5];
    expect(target.flag).toBeNull();
    const pages = callsOf("events_page").length;
    const sums = callsOf("events_summary").length;
    fireEvent.contextMenu(cell(5, "event_time"));
    await user.click(menu("Flag this event"));
    await user.click(menu("Malicious"));
    await screen.findByText("Flagged 1 event malicious");
    expect(callsOf("marks_flag_rows").map((c) => c.args)).toEqual([{ rows: [refOf(target)], level: "malicious" }]);
    expect(badges).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(dataRows()[5]).toHaveClass("ev-flag-malicious"));
    // The grid and the counts were read again; the box stays as it was.
    expect(callsOf("events_page").length).toBeGreaterThan(pages);
    expect(callsOf("events_summary").length).toBeGreaterThan(sums);
    expect(screen.getByText("81 of 81 shown")).toBeInTheDocument();
    // Clearing it again.
    fireEvent.contextMenu(cell(5, "event_time"));
    await user.click(menu("Flag this event"));
    await user.click(menu("Clear flag on this event"));
    await screen.findByText("Cleared the flag on 1 event");
    await waitFor(() => expect(dataRows()[5]).not.toHaveClass("ev-flag-malicious"));
    expect(badges).toHaveBeenCalledTimes(2);
  });

  it("a_reload_after_a_write_keeps_the_filters_and_the_loaded_page", async () => {
    const user = userEvent.setup();
    // 450 events in pages: a write after the analyst scrolled to the second page reads both pages again.
    const total = 450;
    const synth = (i: number): EventRow => ({ ...all[5], record_key: `synthetic-${String(i).padStart(4, "0")}`, flag: null, flag_ai: false, tags: [] });
    h.override.marks_flag_rows = () => ({});
    h.override.events_page = (a) => {
      const offset = a!.offset as number;
      const limit = a!.limit as number;
      return { rows: Array.from({ length: Math.min(limit, total - offset) }, (_, i) => synth(offset + i)), offset, total, total_capped: false };
    };
    view();
    await shown(200, total);
    await user.type(within(screen.getByRole("form", { name: "Event filters" })).getByLabelText("Account"), "wren*");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(callsOf("events_page").at(-1)!.args!.query).toMatchObject({ fields: [["account", "wren*"]] }));
    await waitFor(() => expect(screen.queryByText("Loading…")).not.toBeInTheDocument());
    await shown(200, total);
    const scroller = document.querySelector<HTMLElement>(".grid-scroll")!;
    scroller.scrollTop = 33 * 190;
    fireEvent.scroll(scroller);
    await shown(400, total);
    h.calls.length = 0;
    fireEvent.contextMenu(cell(0, "event_time"));
    await user.click(menu("Flag this event"));
    await user.click(menu("Suspicious"));
    await screen.findByText("Flagged 1 event suspicious");
    await waitFor(() => expect(callsOf("events_page").length).toBeGreaterThan(1));
    await shown(400, total);
    // The same query each time, read from the start up to the rows that were loaded.
    const pages = callsOf("events_page").map((c) => [c.args!.offset, c.args!.limit]);
    expect(pages).toEqual([[0, 200], [200, 200]]);
    for (const c of [...callsOf("events_page"), ...callsOf("events_summary"), ...callsOf("events_histogram")]) {
      expect((c.args!.query as EventQuery).fields).toEqual([["account", "wren*"]]);
    }
  });

  it("flag_every_event_with_an_ip_is_a_standing_flag_and_malicious_says_it_is_an_indicator", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    const row = 3;
    const ip = all[row].ip!;
    expect(ip).toBe("192.0.2.12");
    fireEvent.contextMenu(cell(row, "ip"));
    await user.click(menu("Flag every event from this IP (incl. later imports)"));
    await user.click(menu("Malicious (adds or updates an indicator)"));
    await screen.findByText(`Flagged every event with IP ${ip} malicious, including later imports; IP ${ip} added as an indicator`);
    expect(callsOf("marks_flag_value").map((c) => c.args)).toEqual([{ kind: "ip", value: ip, scope: null, level: "malicious" }]);
    expect(callsOf("marks_flag_rows")).toHaveLength(0);
    expect(badges).toHaveBeenCalledTimes(1);
    // Every loaded event with that IP shows flagged, and the count agrees with the backend.
    const want = all.filter((r) => r.ip === ip).length;
    expect(want).toBeGreaterThan(1);
    // (The grid draws only the rows in view.)
    await waitFor(() => {
      const drawn = dataRows().length;
      expect(drawn).toBeGreaterThan(10);
      expect(document.querySelectorAll(".grid-row.ev-flag-malicious").length).toBe(
        all.slice(0, drawn).filter((r) => r.ip === ip || r.flag === "malicious").length,
      );
    });
    expect((await mockCall<{ malicious: number }>("events_summary", { query: ALL })).malicious).toBe(
      all.filter((r) => r.ip === ip || r.flag === "malicious").length,
    );
  });

  it("the_indicator_wording_follows_what_the_backend_says_it_did", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    const ip = all[3].ip!;
    const flagIp = async () => {
      fireEvent.contextMenu(cell(3, "ip"));
      await user.click(menu("Flag every event from this IP (incl. later imports)"));
      await user.click(menu("Malicious (adds or updates an indicator)"));
    };
    const base = `Flagged every event with IP ${ip} malicious, including later imports`;
    // Added (the real mock says so), then flagged again after a clear: updated.
    await flagIp();
    await screen.findByText(`${base}; IP ${ip} added as an indicator`);
    fireEvent.contextMenu(cell(3, "ip"));
    await user.click(menu("Flag every event from this IP (incl. later imports)"));
    await user.click(menu("Clear this flag (flags set on single events stay)"));
    await screen.findByText(`Cleared the flag on IP ${ip}; flags set on single events stay`);
    await flagIp();
    await screen.findByText(`${base}; indicator for IP ${ip} updated`);
    // The backend made none (no tenant): the message does not mention indicators at all.
    h.override.marks_flag_value = async (a) => {
      const r = await mockCall<{ audit: unknown }>("marks_flag_value", a);
      return { audit: r.audit, indicators: [] };
    };
    await flagIp();
    await screen.findByText(base);
    expect(screen.queryByText(/indicator/)).not.toBeInTheDocument();
    // The wording itself.
    const c = (created: boolean) => ({ tenant_key: null, indicator_id: "i", created });
    expect(indicatorNote("IP x", [])).toBe("");
    expect(indicatorNote("IP x", [c(true), c(true)])).toBe("; IP x added as an indicator in 2 tenants");
    expect(indicatorNote("IP x", [c(false), c(false)])).toBe("; indicator for IP x updated in 2 tenants");
    expect(indicatorNote("IP x", [c(true), c(false)])).toBe("; IP x added as an indicator in 1 tenant and updated in 1");
  });

  it("flagging_the_tabs_own_value_sends_no_scope_and_says_nothing_about_a_tab", async () => {
    const user = userEvent.setup();
    const ip = all[0].ip!;
    view({ entity: { kind: "ip", value: ip } });
    await screen.findByText(/of \d+ shown/);
    fireEvent.contextMenu(cell(0, "ip"));
    await user.click(menu("Flag every event from this IP (incl. later imports)"));
    await user.click(menu("Suspicious"));
    await screen.findByText(`Flagged every event with IP ${ip} suspicious, including later imports`);
    expect(callsOf("marks_flag_value")[0].args).toEqual({ kind: "ip", value: ip, scope: null, level: "suspicious" });
    // Its network is another value: scoped to the tab.
    fireEvent.contextMenu(cell(0, "ip"));
    await user.click(menu(`Flag every event from its /24 ${all[0].ip_prefix} in this IP (incl. later imports)`));
    await user.click(menu("Suspicious"));
    await waitFor(() => expect(callsOf("marks_flag_value")).toHaveLength(2));
    expect(callsOf("marks_flag_value")[1].args).toMatchObject({ kind: "ip_prefix", scope: { kind: "ip", value: ip } });
  });

  it("the_tag_submenu_stays_open_and_updates_in_place_after_a_toggle", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    // Row 5 has no tags; phish-lure is in the case (rows 3 and 4 carry it).
    fireEvent.contextMenu(cell(5, "event_time"));
    await user.click(menu("Tag this event"));
    const lure = () => screen.getByRole("menuitemcheckbox", { name: "phish-lure" });
    expect(lure()).toHaveAttribute("aria-checked", "false");
    await user.click(lure());
    await screen.findByText("Tagged 1 event “phish-lure”");
    // The menu is still there, and the same item now shows the tag as on.
    await waitFor(() => expect(lure()).toHaveAttribute("aria-checked", "true"));
    expect(screen.getAllByRole("menu")).toHaveLength(2);
    expect(callsOf("marks_tag_rows")).toHaveLength(1);
    // Toggled back off in the same open menu.
    await user.click(lure());
    await waitFor(() => expect(lure()).toHaveAttribute("aria-checked", "false"));
    expect(callsOf("marks_tag_rows").map((c) => c.args!.add)).toEqual([true, false]);
    expect(screen.getAllByRole("menu")).toHaveLength(2);
    // Escape closes the submenu, then the menu.
    await user.keyboard("{Escape}{Escape}");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("value_flags_inside_an_entity_tab_carry_the_tab_as_scope_and_say_so", async () => {
    const user = userEvent.setup();
    const who = all[3].actor_upn!;
    view({ entity: { kind: "account", value: who } });
    await screen.findByText(/of \d+ shown/);
    fireEvent.contextMenu(cell(0, "ip"));
    await user.click(menu("Flag every event from this IP in this user (incl. later imports)"));
    await user.click(menu("Suspicious"));
    await screen.findByText(/^Flagged every event with IP 192\.0\.2\.\d+ in this user suspicious, including later imports$/);
    const call = callsOf("marks_flag_value")[0].args!;
    expect(call.scope).toEqual({ kind: "account", value: who });
    expect(call.level).toBe("suspicious");
    // A suspicious flag makes no indicator, and the message does not claim one.
    expect(screen.queryByText(/indicator/)).not.toBeInTheDocument();
  });

  it("a_flag_on_an_asn_or_device_makes_no_indicator_claim", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    fireEvent.contextMenu(cell(0, "asn"));
    await user.click(menu("Flag every event in AS64496 (incl. later imports)"));
    await user.click(menu("Malicious"));
    await screen.findByText("Flagged every event with AS64496 malicious, including later imports");
    expect(screen.queryByText(/indicator/)).not.toBeInTheDocument();
  });

  it("ticked_rows_are_acted_on_together_and_the_ticks_survive_the_reload", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    await tick(user, 1);
    await tick(user, 2);
    expect(await screen.findByText("2 events selected — right-click to act")).toBeInTheDocument();
    // Right-click on a ticked row: both. On another row: that row alone.
    fireEvent.contextMenu(cell(2, "event_time"));
    await user.click(menu("Tag 2 ticked events"));
    await user.click(menu("New tag…"));
    const dlg = screen.getByRole("dialog", { name: "New tag" });
    await user.type(within(dlg).getByLabelText("Tag name"), "relay-wave");
    await user.click(within(dlg).getByRole("button", { name: "Add tag" }));
    await screen.findByText("Tagged 2 events “relay-wave”");
    expect(callsOf("marks_tag_rows").map((c) => c.args)).toEqual([{ rows: [refOf(all[1]), refOf(all[2])], tag: "relay-wave", add: true }]);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await waitFor(() => expect(within(dataRows()[1]).getByText("relay-wave")).toBeInTheDocument());
    expect(screen.getByText("2 events selected — right-click to act")).toBeInTheDocument();
    // The tag is now a checked item for the same selection, and clicking it removes it from both.
    fireEvent.contextMenu(cell(1, "event_time"));
    await user.click(menu("Tag 2 ticked events"));
    expect(screen.getByRole("menuitemcheckbox", { name: "relay-wave" })).toHaveAttribute("aria-checked", "true");
    await user.click(screen.getByRole("menuitemcheckbox", { name: "relay-wave" }));
    await screen.findByText("Removed tag “relay-wave” from 2 events");
    expect(callsOf("marks_tag_rows").at(-1)!.args).toEqual({ rows: [refOf(all[1]), refOf(all[2])], tag: "relay-wave", add: false });
    // Another row alone.
    fireEvent.contextMenu(cell(4, "event_time"));
    expect(menu("Flag this event")).toBeInTheDocument();
    fireEvent.keyDown(screen.getByRole("menuitem", { name: "Flag this event" }), { key: "Escape" });
    await user.click(screen.getByRole("button", { name: "Clear selection" }));
    expect(screen.queryByText(/selected — right-click/)).not.toBeInTheDocument();
  });

  it("a_new_search_clears_the_ticks_but_a_sort_keeps_them", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    await tick(user, 0);
    await screen.findByText("1 event selected — right-click to act");
    await user.click(screen.getByRole("button", { name: /^Source/ }));
    await waitFor(() => expect(callsOf("events_page").length).toBeGreaterThan(1));
    expect(screen.getByText("1 event selected — right-click to act")).toBeInTheDocument();
    await user.type(within(screen.getByRole("form", { name: "Event filters" })).getByLabelText("Country"), "US");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(screen.queryByText(/selected — right-click/)).not.toBeInTheDocument());
  });

  it("add_a_note_for_the_ticked_rows", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    await tick(user, 0);
    await tick(user, 5);
    fireEvent.contextMenu(cell(0, "tags"));
    await user.click(menu("Add note to 2 events…"));
    const dlg = screen.getByRole("dialog", { name: "Add note" });
    expect(within(dlg).getByRole("button", { name: "Add note" })).toBeDisabled();
    await user.type(within(dlg).getByLabelText("Note"), "  seen in the relay wave ");
    await user.click(within(dlg).getByRole("button", { name: "Add note" }));
    await screen.findByText("Note added to 2 events");
    expect(callsOf("notes_add_rows").map((c) => c.args)).toEqual([{ rows: [refOf(all[0]), refOf(all[5])], text: "seen in the relay wave" }]);
    await waitFor(() => expect(within(dataRows()[0]).getByText("seen in the relay wave")).toBeInTheDocument());
    expect(badges).toHaveBeenCalledTimes(1);
  });

  it("add_events_to_the_timeline_as_one_grouped_entry", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    await tick(user, 0);
    await tick(user, 1);
    await tick(user, 2);
    fireEvent.contextMenu(cell(1, "flag"));
    await user.click(menu("Add 3 events to timeline…"));
    const dlg = screen.getByRole("dialog", { name: "Add to timeline" });
    await user.click(within(dlg).getByRole("radio", { name: "One grouped entry" }));
    await user.type(within(dlg).getByLabelText("Title"), "Relay sends");
    await user.click(within(dlg).getByRole("button", { name: "Add to timeline" }));
    await waitFor(() => expect(callsOf("timeline_add_events")).toHaveLength(1));
    expect(callsOf("timeline_add_events")[0].args).toEqual({ args: { rows: [refOf(all[0]), refOf(all[1]), refOf(all[2])], mode: "group", title: "Relay sends" } });
    await screen.findByText(/timeline/i, { selector: "[role=status]" });
    expect(badges).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("a_refused_write_is_shown_and_the_menu_closes_without_reloading", async () => {
    const user = userEvent.setup();
    h.override.marks_flag_rows = () => {
      throw { kind: "read_only", message: "This case is open read-only" };
    };
    view();
    await shown(81, 81);
    const pages = callsOf("events_page").length;
    fireEvent.contextMenu(cell(5, "event_time"));
    await user.click(menu("Flag this event"));
    await user.click(menu("Suspicious"));
    expect(await screen.findByRole("alert")).toHaveTextContent("This case is open read-only");
    expect(callsOf("events_page")).toHaveLength(pages);
    expect(badges).not.toHaveBeenCalled();
  });

  it("read_only_disables_every_write_with_the_reason", async () => {
    const user = userEvent.setup();
    view({ writeBlocked: WRITE_BLOCKED });
    await shown(81, 81);
    await tick(user, 7);
    fireEvent.contextMenu(cell(7, "event_time"));
    for (const name of ["Flag this event", "Tag this event", "Add note…", "Add to timeline…"]) {
      expect(menu(name), name).toHaveAttribute("aria-disabled", "true");
      expect(menu(name), name).toHaveAttribute("title", WRITE_BLOCKED);
    }
    await user.click(menu("Flag this event"));
    expect(screen.queryByRole("menuitem", { name: "Suspicious" })).not.toBeInTheDocument();
    fireEvent.keyDown(menu("Flag this event"), { key: "Escape" });
    fireEvent.contextMenu(cell(7, "ip"));
    expect(menu("Flag every event from this IP (incl. later imports)")).toHaveAttribute("title", WRITE_BLOCKED);
    expect(menu("Filter by this value")).not.toHaveAttribute("aria-disabled");
    fireEvent.keyDown(menu("Show details"), { key: "Escape" });
    // The footer buttons too, even with an AI mark selected.
    expect(all[7].flag_ai).toBe(true);
    for (const name of ["Confirm AI marks", "Remove AI marks"]) {
      expect(screen.getByRole("button", { name })).toBeDisabled();
      expect(screen.getByRole("button", { name })).toHaveAttribute("title", WRITE_BLOCKED);
    }
    expect(callsOf("marks_flag_rows")).toHaveLength(0);
  });
});

describe("an open cell menu", () => {
  it("closes_when_the_grid_changes_under_it_so_no_action_reaches_the_replacement_row", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    await tick(user, 5);
    fireEvent.contextMenu(cell(5, "event_time"));
    await user.click(menu("Flag this event"));
    expect(screen.getByRole("menuitem", { name: "Malicious" })).toBeInTheDocument();
    // The next run answers with the same events in the opposite order (a sort or a reload would do the same), while
    // the menu is open. A form submit is not a mousedown, so only the rows change.
    const pageOf = async (a: Record<string, unknown> | undefined) => mockCall<{ rows: EventRow[] }>("events_page", a);
    h.override.events_page = async (a) => {
      const p = await pageOf(a);
      return { ...p, rows: [...p.rows].reverse() };
    };
    fireEvent.submit(screen.getByRole("form", { name: "Event filters" }));
    await waitFor(() => expect(dataRows()[0].textContent).not.toBe(""));
    await waitFor(() => expect(screen.queryByRole("menu")).not.toBeInTheDocument());
    expect(callsOf("marks_flag_rows")).toHaveLength(0);
    // The ticks were cleared with the new query, and a new menu on the row now at that index targets that row alone.
    expect(screen.queryByText(/selected — right-click/)).not.toBeInTheDocument();
    const replacement = (await pageOf({ query: ALL, sort: null, offset: 0, limit: 500 })).rows.reverse()[5];
    expect(replacement.record_key).not.toBe(all[5].record_key);
    fireEvent.contextMenu(cell(5, "event_time"));
    await user.click(menu("Flag this event"));
    await user.click(menu("Malicious"));
    await waitFor(() => expect(callsOf("marks_flag_rows")).toHaveLength(1));
    expect(callsOf("marks_flag_rows")[0].args).toEqual({ rows: [refOf(replacement)], level: "malicious" });
    await screen.findByText("Flagged 1 event malicious");
    await waitFor(() => expect(badges).toHaveBeenCalledTimes(1));
  });

  it("a_menu_keeps_the_selection_it_had_when_it_opened", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    await tick(user, 1);
    await tick(user, 2);
    fireEvent.contextMenu(cell(1, "event_time"));
    // Ticks changing while the menu is open do not change what it acts on.
    fireEvent.click(within(dataRows()[4]).getByRole("checkbox", { name: "Select event" }));
    await user.click(menu("Flag 2 ticked events"));
    await user.click(menu("Malicious"));
    await waitFor(() => expect(callsOf("marks_flag_rows")).toHaveLength(1));
    expect(callsOf("marks_flag_rows")[0].args).toEqual({ rows: [refOf(all[1]), refOf(all[2])], level: "malicious" });
    await screen.findByText("Flagged 2 events malicious");
    await waitFor(() => expect(badges).toHaveBeenCalledTimes(1));
  });
});

describe("confirm and remove AI marks", () => {
  it("confirm_and_remove_ai_marks_footer", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    // all[6] has an agent tag, all[7] an agent flag (pending); all[5] has no AI mark.
    expect(all[6].tags.some((t) => t.ai)).toBe(true);
    expect(all[7].flag_ai).toBe(true);
    await tick(user, 5);
    // Nothing AI selected yet: both buttons are disabled and say why.
    for (const name of ["Confirm AI marks", "Remove AI marks"]) {
      expect(screen.getByRole("button", { name })).toBeDisabled();
      expect(screen.getByRole("button", { name })).toHaveAttribute("title", "None of the selected events has an AI mark waiting for review");
    }
    await tick(user, 6);
    await tick(user, 7);
    expect(screen.getByText("3 events selected — right-click to act · 2 with AI marks")).toBeInTheDocument();
    // The flag at row 7 is a plain row flag by an agent: no value flag is involved, so no warning.
    await user.click(screen.getByRole("button", { name: "Confirm AI marks" }));
    const dlg = await screen.findByRole("dialog", { name: "Confirm AI marks" });
    await waitFor(() => expect(within(dlg).getByRole("button", { name: "Confirm AI marks" })).toBeEnabled());
    expect(within(dlg).queryByRole("alert")).not.toBeInTheDocument();
    // Both events are checked for standing flags: either may be covered by one.
    expect(callsOf("events_detail").map((c) => c.args)).toEqual([
      { sourceTable: all[6].source_table, recordKey: all[6].record_key },
      { sourceTable: all[7].source_table, recordKey: all[7].record_key },
    ]);
    await user.click(within(dlg).getByRole("button", { name: "Confirm AI marks" }));
    await screen.findByText("Confirmed the AI marks on 2 events");
    // Only the two rows that carry an AI mark are sent.
    expect(callsOf("marks_review").map((c) => c.args)).toEqual([{ rows: [refOf(all[6]), refOf(all[7])], accept: true }]);
    expect(badges).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(within(dataRows()[6]).getByText("ai:relay")).toBeInTheDocument());
    await waitFor(() => expect(dataRows()[7]).not.toHaveClass("ev-flag-ai"));
    // They are confirmed now: nothing left to confirm or remove.
    expect(screen.getByText("3 events selected — right-click to act")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove AI marks" })).toBeDisabled();
  });

  it("removing_ai_marks_asks_first_and_warns_when_a_value_flag_covers_more_than_the_selection", async () => {
    const user = userEvent.setup();
    // The agent flagged the IP of row 7, not the row: reviewing it reaches every event with that IP.
    h.override.events_detail = async (a) => {
      const d = await mockCall<Detail>("events_detail", a);
      return {
        ...d,
        flag_sources: [
          { origin: "value", level: "suspicious", kind: "ip", value: "192.0.2.13", scope_kind: null, scope_value: null, decided_by: "agent:triage", review_state: "pending_review" },
          { origin: "value", level: "malicious", kind: "account", value: "ada@contoso.example", scope_kind: "session", scope_value: "s-1", decided_by: "agent:triage", review_state: "pending_review" },
          { origin: "value", level: "suspicious", kind: "asn", value: "64496", scope_kind: null, scope_value: null, decided_by: "analyst:carlos", review_state: "accepted" },
        ],
      };
    };
    view();
    await shown(81, 81);
    await tick(user, 7);
    await user.click(screen.getByRole("button", { name: "Remove AI marks" }));
    const dlg = await screen.findByRole("dialog", { name: "Remove AI marks" });
    const warn = await within(dlg).findByRole("alert");
    expect(warn).toHaveTextContent("This reaches beyond the ticked events.");
    // The pending ones are listed; the analyst's own accepted flag is not.
    expect(within(warn).getAllByRole("listitem").map((l) => l.textContent)).toEqual([
      "every event with ip 192.0.2.13",
      "every event with account ada@contoso.example in session s-1",
    ]);
    // Cancel changes nothing.
    await user.click(within(dlg).getByRole("button", { name: "Cancel" }));
    expect(callsOf("marks_review")).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: "Remove AI marks" }));
    const again = await screen.findByRole("dialog", { name: "Remove AI marks" });
    await within(again).findByRole("alert");
    await user.click(within(again).getByRole("button", { name: "Remove AI marks" }));
    await screen.findByText("Removed the AI marks on 1 event");
    expect(callsOf("marks_review").map((c) => c.args)).toEqual([{ rows: [refOf(all[7])], accept: false }]);
    await waitFor(() => expect(dataRows()[7]).not.toHaveClass("ev-flag-suspicious"));
  });

  it("a_pending_agent_flag_hidden_under_a_stronger_confirmed_one_is_still_reviewable", async () => {
    const user = userEvent.setup();
    h.override.events_detail = async (a) => {
      const d = await mockCall<Detail>("events_detail", a);
      return {
        ...d,
        flag_sources: [
          { origin: "value", level: "suspicious", kind: "ip", value: "192.0.2.13", scope_kind: null, scope_value: null, decided_by: "agent:triage", review_state: "pending_review" },
          { origin: "value", level: "malicious", kind: "asn", value: "64496", scope_kind: null, scope_value: null, decided_by: "analyst:carlos", review_state: "accepted" },
        ],
      };
    };
    view();
    await shown(81, 81);
    expect(all[7].flag_ai).toBe(true);
    // The analyst confirms Malicious on that event's IP: the effective flag is now a confirmed Malicious one.
    fireEvent.contextMenu(cell(7, "ip"));
    await user.click(menu("Flag every event from this IP (incl. later imports)"));
    await user.click(menu("Malicious (adds or updates an indicator)"));
    await screen.findByText(/^Flagged every event with IP 192\.0\.2\.13 malicious/);
    await waitFor(() => expect(dataRows()[7]).toHaveClass("ev-flag-malicious"));
    expect(dataRows()[7]).not.toHaveClass("ev-flag-ai");
    const now = (await mockCall<{ rows: EventRow[] }>("events_page", { query: ALL, sort: null, offset: 0, limit: 500 })).rows[7];
    expect([now.flag, now.flag_ai, now.ai_pending]).toEqual(["malicious", false, true]);
    // Its pending agent mark is still there to review.
    await tick(user, 7);
    expect(await screen.findByText("1 event selected — right-click to act · 1 with AI marks")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove AI marks" })).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Remove AI marks" }));
    const dlg = await screen.findByRole("dialog", { name: "Remove AI marks" });
    const warn = await within(dlg).findByRole("alert");
    expect(within(warn).getAllByRole("listitem").map((l) => l.textContent)).toEqual(["every event with ip 192.0.2.13"]);
    await user.click(within(dlg).getByRole("button", { name: "Remove AI marks" }));
    await screen.findByText("Removed the AI marks on 1 event");
    expect(callsOf("marks_review").map((c) => c.args)).toEqual([{ rows: [refOf(all[7])], accept: false }]);
  });

  it("the_dialog_says_so_when_it_could_not_look_for_value_flags", async () => {
    const user = userEvent.setup();
    h.override.events_detail = () => {
      throw { kind: "not_found", message: "gone" };
    };
    view();
    await shown(81, 81);
    await tick(user, 7);
    await user.click(screen.getByRole("button", { name: "Confirm AI marks" }));
    const warn = await screen.findByRole("alert");
    expect(warn).toHaveTextContent("The flags could not be listed.");
    expect(within(screen.getByRole("dialog")).getByRole("button", { name: "Confirm AI marks" })).toBeEnabled();
  });
});

describe("detail panel marking", () => {
  it("the_detail_panel_shows_where_a_flag_comes_from_and_clears_a_standing_flag", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    // A standing flag on an IP, then the panel of an event with that IP.
    const ip = all[3].ip!;
    fireEvent.contextMenu(cell(3, "ip"));
    await user.click(menu("Flag every event from this IP (incl. later imports)"));
    await user.click(menu("Suspicious"));
    await screen.findByText(/^Flagged every event with IP /);
    await waitFor(() => expect(dataRows()[3]).toHaveClass("ev-flag-suspicious"));
    await user.click(cell(3, "operation"));
    const panel = await screen.findByRole("complementary", { name: "Event detail" });
    expect(await within(panel).findByText(`suspicious · every event with ip ${ip}, incl. later imports · analyst:carlos · accepted`)).toBeInTheDocument();
    h.calls.length = 0;
    await user.click(within(panel).getByRole("button", { name: "Clear for all" }));
    await screen.findByText(`Cleared the flag on ip ${ip}`);
    expect(callsOf("marks_flag_value").map((c) => c.args)).toEqual([{ kind: "ip", value: ip, scope: null, level: null }]);
    await waitFor(() => expect(dataRows()[3]).not.toHaveClass("ev-flag-suspicious"));
    // The panel read the event again and no longer shows the flag.
    await waitFor(() => expect(within(screen.getByRole("complementary", { name: "Event detail" })).getByText("Not flagged.")).toBeInTheDocument());
  });

  it("the_panel_flags_tags_and_notes_one_event", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    await user.click(cell(5, "operation"));
    const panel = await screen.findByRole("complementary", { name: "Event detail" });
    await within(panel).findByText("Not flagged.");
    await user.click(within(panel).getByRole("button", { name: "Flag malicious" }));
    await screen.findByText("Flagged malicious");
    expect(callsOf("marks_flag_rows").at(-1)!.args).toEqual({ rows: [refOf(all[5])], level: "malicious" });
    await within(screen.getByRole("complementary", { name: "Event detail" })).findByText("set on this event", { exact: false });
    await user.click(within(screen.getByRole("complementary", { name: "Event detail" })).getByRole("button", { name: "Clear" }));
    await screen.findByText("Flag cleared");
    expect(callsOf("marks_flag_rows").at(-1)!.args).toEqual({ rows: [refOf(all[5])], level: null });
    // Tag, then remove it.
    const p2 = screen.getByRole("complementary", { name: "Event detail" });
    await user.type(within(p2).getByLabelText("New tag"), " lure ");
    await user.click(within(p2).getByRole("button", { name: "Add tag" }));
    await screen.findByText("Tagged lure");
    expect(callsOf("marks_tag_rows").at(-1)!.args).toEqual({ rows: [refOf(all[5])], tag: "lure", add: true });
    await user.click(await within(screen.getByRole("complementary", { name: "Event detail" })).findByRole("button", { name: "Remove tag lure" }));
    await screen.findByText("Removed tag lure");
    // Note and timeline for this one event.
    await user.click(within(screen.getByRole("complementary", { name: "Event detail" })).getByRole("button", { name: "Add note…" }));
    await user.type(within(screen.getByRole("dialog", { name: "Add note" })).getByLabelText("Note"), "checked");
    await user.click(within(screen.getByRole("dialog", { name: "Add note" })).getByRole("button", { name: "Add note" }));
    await screen.findByText("Note added");
    expect(callsOf("notes_add_rows").at(-1)!.args).toEqual({ rows: [refOf(all[5])], text: "checked" });
    await waitFor(() => expect(within(screen.getByRole("complementary", { name: "Event detail" })).getByText("checked")).toBeInTheDocument());
    await user.click(within(screen.getByRole("complementary", { name: "Event detail" })).getByRole("button", { name: "Add to timeline…" }));
    const dlg = screen.getByRole("dialog", { name: "Add to timeline" });
    expect(within(dlg).queryByRole("radio")).not.toBeInTheDocument();
    expect(within(dlg).getByLabelText("Title")).toHaveValue(`${all[5].operation} by ${all[5].actor_upn} from ${all[5].ip}`);
    await user.click(within(dlg).getByRole("button", { name: "Add to timeline" }));
    await waitFor(() => expect(callsOf("timeline_add_events")).toHaveLength(1));
    expect(callsOf("timeline_add_events")[0].args).toEqual({ args: { rows: [refOf(all[5])], mode: "each", title: `${all[5].operation} by ${all[5].actor_upn} from ${all[5].ip}` } });
  });

  it("the_panel_disables_its_writes_in_a_read_only_case", async () => {
    const user = userEvent.setup();
    view({ writeBlocked: WRITE_BLOCKED });
    await shown(81, 81);
    await user.click(cell(5, "operation"));
    const panel = await screen.findByRole("complementary", { name: "Event detail" });
    await within(panel).findByText("Not flagged.");
    for (const name of ["Flag suspicious", "Flag malicious", "Add tag", "Add note…", "Add to timeline…"]) {
      expect(within(panel).getByRole("button", { name }), name).toBeDisabled();
    }
    expect(within(panel).getByLabelText("New tag")).toBeDisabled();
    expect(within(panel).getByRole("button", { name: "Add note…" })).toHaveAttribute("title", WRITE_BLOCKED);
  });
});
