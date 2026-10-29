import { describe, expect, it, vi } from "vitest";
import type { EventRow } from "../api";
import type { MenuItem } from "../grid/CellMenu";
import * as fx from "../test/fixtures";
import { NOTE_MAX, rowMenu, targetsOf, type RowMenuActions, type RowMenuContext } from "./rowMenu";

const base = fx.eventsList()[0];
const ev = (over: Partial<EventRow> = {}): EventRow => ({
  ...base,
  record_key: "k1",
  actor_upn: "jdoe@contoso.example",
  owner_upn: null,
  ip: "192.0.2.26",
  ip_prefix: "192.0.2.0/24",
  asn: 64496,
  device_id: null,
  device_name: null,
  device_object_id: null,
  entra_session_id: null,
  tags: [],
  flag: null,
  flag_ai: false,
  ...over,
});
const ref = (r: EventRow) => ({ source_table: r.source_table, record_key: r.record_key });

function actions(): RowMenuActions {
  return {
    showDetails: vi.fn(),
    filter: vi.fn(),
    openEntity: vi.fn(),
    flagRows: vi.fn(),
    flagValue: vi.fn(),
    tagRows: vi.fn(),
    newTag: vi.fn(),
    addNote: vi.fn(),
    addToTimeline: vi.fn(),
  };
}
const ctx = (over: Partial<RowMenuContext> = {}): RowMenuContext => ({ readOnly: null, tags: [], canOpen: true, act: actions(), ...over });
const labels = (items: MenuItem[]) => items.map((i) => i.label);
const find = (items: MenuItem[], label: string) => {
  const it = items.find((i) => i.label === label);
  if (!it) throw new Error(`no item ${label}: ${labels(items).join(" | ")}`);
  return it;
};

describe("rowMenu", () => {
  it("event_cells_offer_flag_tag_note_and_timeline_for_the_event", () => {
    // Time, Tags, Notes and Flag cells (and any other cell that is not a value) act on the event.
    for (const column of ["event_time", "tags", "notes", "flag", "_tick", "target"]) {
      const c = ctx();
      const r = ev();
      const items = rowMenu({ column, row: r, ticked: [] }, c);
      expect(labels(items), column).toEqual(["Show details", "Flag this event", "Tag this event", "Add note…", "Add to timeline…"]);
      expect(labels(find(items, "Flag this event").items!)).toEqual(["Suspicious", "Malicious", "Clear flag on this event"]);
      find(find(items, "Flag this event").items!, "Malicious").run!();
      expect(c.act.flagRows).toHaveBeenCalledWith([ref(r)], "malicious");
      find(find(items, "Flag this event").items!, "Clear flag on this event").run!();
      expect(c.act.flagRows).toHaveBeenLastCalledWith([ref(r)], null);
      find(items, "Add note…").run!();
      expect(c.act.addNote).toHaveBeenCalledWith([ref(r)]);
      find(items, "Add to timeline…").run!();
      expect(c.act.addToTimeline).toHaveBeenCalledWith([ref(r)]);
      find(items, "Show details").run!();
      expect(c.act.showDetails).toHaveBeenCalledWith(ref(r));
    }
  });

  it("a_filterable_event_cell_also_offers_filter_and_exclude", () => {
    const c = ctx();
    const r = ev({ ip_country: "US" });
    const items = rowMenu({ column: "ip_country", row: r, ticked: [] }, c);
    expect(labels(items)).toEqual(["Show details", "Filter by this value", "Exclude this value", "Flag this event", "Tag this event", "Add note…", "Add to timeline…"]);
    find(items, "Exclude this value").run!();
    expect(c.act.filter).toHaveBeenCalledWith("country", "US", true);
    find(items, "Filter by this value").run!();
    expect(c.act.filter).toHaveBeenLastCalledWith("country", "US", false);
  });

  it("the_menu_acts_on_the_ticked_rows_only_when_the_clicked_row_is_one_of_them", () => {
    const a = ev({ record_key: "a" });
    const b = ev({ record_key: "b" });
    const other = ev({ record_key: "z" });
    const c = ctx();
    const onTicked = rowMenu({ column: "event_time", row: b, ticked: [a, b] }, c);
    expect(labels(onTicked)).toEqual(["Show details", "Flag 2 ticked events", "Tag 2 ticked events", "Add note to 2 events…", "Add 2 events to timeline…"]);
    find(find(onTicked, "Flag 2 ticked events").items!, "Suspicious").run!();
    expect(c.act.flagRows).toHaveBeenCalledWith([ref(a), ref(b)], "suspicious");
    find(onTicked, "Add note to 2 events…").run!();
    expect(c.act.addNote).toHaveBeenCalledWith([ref(a), ref(b)]);
    // A click on a row that is not ticked acts on that row alone.
    const elsewhere = rowMenu({ column: "event_time", row: other, ticked: [a, b] }, c);
    expect(labels(elsewhere)).toEqual(["Show details", "Flag this event", "Tag this event", "Add note…", "Add to timeline…"]);
    find(find(elsewhere, "Flag this event").items!, "Malicious").run!();
    expect(c.act.flagRows).toHaveBeenLastCalledWith([ref(other)], "malicious");
    expect(targetsOf({ row: other, ticked: [a, b] })).toEqual([other]);
  });

  it("notes_are_refused_over_the_row_limit_but_the_rest_still_works", () => {
    const ticked = Array.from({ length: NOTE_MAX + 1 }, (_, i) => ev({ record_key: `r${i}` }));
    const items = rowMenu({ column: "event_time", row: ticked[0], ticked }, ctx());
    expect(find(items, `Add note to ${NOTE_MAX + 1} events…`).disabled).toBe(`Notes go on at most 200 events at once; ${NOTE_MAX + 1} are ticked`);
    expect(find(items, `Tag ${NOTE_MAX + 1} ticked events`).disabled).toBeUndefined();
    const ok = Array.from({ length: NOTE_MAX }, (_, i) => ev({ record_key: `r${i}` }));
    expect(find(rowMenu({ column: "event_time", row: ok[0], ticked: ok }, ctx()), `Add note to ${NOTE_MAX} events…`).disabled).toBeUndefined();
  });

  it("ip_cell_flags_this_ip_or_its_network_as_a_standing_flag", () => {
    const c = ctx();
    const r = ev();
    const items = rowMenu({ column: "ip", row: r, ticked: [r] }, c);
    expect(labels(items)).toEqual([
      "Show details",
      "Filter by this value",
      "Exclude this value",
      "Open IP tab",
      "Flag every event from this IP (incl. later imports)",
      "Flag every event from its /24 192.0.2.0/24 (incl. later imports)",
    ]);
    const ip = find(items, "Flag every event from this IP (incl. later imports)");
    expect(labels(ip.items!)).toEqual(["Suspicious", "Malicious (adds or updates an indicator)", "Clear this flag (flags set on single events stay)"]);
    find(ip.items!, "Malicious (adds or updates an indicator)").run!();
    expect(c.act.flagValue).toHaveBeenCalledWith("ip", "192.0.2.26", null, "malicious", "IP 192.0.2.26");
    find(ip.items!, "Suspicious").run!();
    expect(c.act.flagValue).toHaveBeenLastCalledWith("ip", "192.0.2.26", null, "suspicious", "IP 192.0.2.26");
    find(ip.items!, "Clear this flag (flags set on single events stay)").run!();
    expect(c.act.flagValue).toHaveBeenLastCalledWith("ip", "192.0.2.26", null, null, "IP 192.0.2.26");
    // The network: Malicious says nothing about indicators because core makes none for a network.
    const net = find(items, "Flag every event from its /24 192.0.2.0/24 (incl. later imports)");
    expect(labels(net.items!)).toEqual(["Suspicious", "Malicious", "Clear this flag (flags set on single events stay)"]);
    find(net.items!, "Malicious").run!();
    expect(c.act.flagValue).toHaveBeenLastCalledWith("ip_prefix", "192.0.2.26", null, "malicious", "network 192.0.2.0/24");
    find(items, "Open IP tab").run!();
    expect(c.act.openEntity).toHaveBeenCalledWith({ kind: "ip", value: "192.0.2.26" });
  });

  it("an_ipv6_cell_offers_its_48_and_an_event_without_a_network_only_the_ip", () => {
    const six = rowMenu({ column: "ip", row: ev({ ip: "2001:db8::1", ip_prefix: "2001:db8::/48" }), ticked: [] }, ctx());
    expect(labels(six).slice(-2)).toEqual([
      "Flag every event from this IP (incl. later imports)",
      "Flag every event from its /48 2001:db8::/48 (incl. later imports)",
    ]);
    const bare = rowMenu({ column: "ip", row: ev({ ip_prefix: null }), ticked: [] }, ctx());
    expect(labels(bare).slice(-1)).toEqual(["Flag every event from this IP (incl. later imports)"]);
    // No IP at all: nothing to flag by value, so the cell falls back to the event's own actions.
    expect(labels(rowMenu({ column: "ip", row: ev({ ip: null, ip_prefix: null }), ticked: [] }, ctx()))).toEqual([
      "Show details",
      "Flag this event",
      "Tag this event",
      "Add note…",
      "Add to timeline…",
    ]);
  });

  it("account_asn_device_and_session_cells_flag_every_event_with_the_value", () => {
    const r = ev({ actor_upn: "JDoe@Contoso.example", owner_upn: "boss@contoso.example", device_id: "dev-1", device_name: "LAPTOP-1", entra_session_id: "sess-1" });
    const cases: [string, string, string[], [string, string, string]][] = [
      [
        "actor_upn",
        "Flag every event with this account (incl. later imports)",
        ["Show details", "Filter by this value", "Exclude this value", "Open account tab"],
        ["account", "JDoe@Contoso.example", "account jdoe@contoso.example"],
      ],
      [
        "owner_upn",
        "Flag every event with this account (incl. later imports)",
        ["Show details", "Open account tab"],
        ["account", "boss@contoso.example", "account boss@contoso.example"],
      ],
      ["asn", "Flag every event in AS64496 (incl. later imports)", ["Show details", "Filter by this value", "Exclude this value"], ["asn", "64496", "AS64496"]],
      [
        "device_name",
        "Flag every event with this device (incl. later imports)",
        ["Show details", "Filter by this value", "Exclude this value", "Open device tab"],
        ["device", "dev-1", "device dev-1"],
      ],
      [
        "entra_session_id",
        "Flag every event with this Entra session (incl. later imports)",
        ["Show details", "Filter by this value", "Exclude this value", "Open session tab"],
        ["session", "sess-1", "Entra session sess-1"],
      ],
    ];
    for (const [column, label, before, [kind, value, what]] of cases) {
      const c = ctx();
      const items = rowMenu({ column, row: r, ticked: [] }, c);
      expect(labels(items), column).toEqual([...before, label]);
      const flag = find(items, label);
      // No indicator is promised for these: only an IP or an account makes one.
      expect(labels(flag.items!).slice(0, 2)).toEqual(column === "actor_upn" || column === "owner_upn" ? ["Suspicious", "Malicious (adds or updates an indicator)"] : ["Suspicious", "Malicious"]);
      flag.items![0].run!();
      expect(c.act.flagValue, column).toHaveBeenCalledWith(kind, value, null, "suspicious", what);
    }
  });

  it("inside_an_entity_tab_value_flags_are_limited_to_that_entity", () => {
    const c = ctx({ entity: { kind: "session", value: "sess-9" } });
    const items = rowMenu({ column: "ip", row: ev(), ticked: [] }, c);
    const label = "Flag every event from this IP in this session (incl. later imports)";
    expect(labels(items)).toContain(label);
    expect(labels(items)).toContain("Flag every event from its /24 192.0.2.0/24 in this session (incl. later imports)");
    find(find(items, label).items!, "Suspicious").run!();
    expect(c.act.flagValue).toHaveBeenCalledWith("ip", "192.0.2.26", { kind: "session", value: "sess-9" }, "suspicious", "IP 192.0.2.26");
    for (const [kind, word] of [["account", "user"], ["ip", "IP"], ["device", "device"], ["session", "session"]] as const) {
      const m = rowMenu({ column: "asn", row: ev(), ticked: [] }, ctx({ entity: { kind, value: "x" } }));
      expect(labels(m).at(-1)).toBe(`Flag every event in AS64496 in this ${word} (incl. later imports)`);
    }
  });

  it("the_tabs_own_value_is_flagged_without_a_scope_and_without_in_this_in_the_label", () => {
    // IP tab on 192.0.2.26: its IP cell flags the IP itself; its network is a different value, so it keeps the scope.
    const ipTab = ctx({ entity: { kind: "ip", value: "192.0.2.26" } });
    const ip = rowMenu({ column: "ip", row: ev(), ticked: [] }, ipTab);
    expect(labels(ip).slice(-2)).toEqual([
      "Flag every event from this IP (incl. later imports)",
      "Flag every event from its /24 192.0.2.0/24 in this IP (incl. later imports)",
    ]);
    find(find(ip, "Flag every event from this IP (incl. later imports)").items!, "Suspicious").run!();
    expect(ipTab.act.flagValue).toHaveBeenCalledWith("ip", "192.0.2.26", null, "suspicious", "IP 192.0.2.26");
    find(find(ip, "Flag every event from its /24 192.0.2.0/24 in this IP (incl. later imports)").items!, "Suspicious").run!();
    expect(ipTab.act.flagValue).toHaveBeenLastCalledWith("ip_prefix", "192.0.2.26", { kind: "ip", value: "192.0.2.26" }, "suspicious", "network 192.0.2.0/24");
    // User tab: the account cell (in any spelling, or as mailbox owner) is the tab's own value; the IP cell is another.
    const userTab = ctx({ entity: { kind: "account", value: "jdoe@contoso.example" } });
    const r = ev({ actor_upn: "JDoe@Contoso.example", owner_upn: "JDOE@contoso.example" });
    for (const column of ["actor_upn", "owner_upn"]) {
      const acct = rowMenu({ column, row: r, ticked: [] }, userTab);
      expect(labels(acct).at(-1), column).toBe("Flag every event with this account (incl. later imports)");
      acct.at(-1)!.items![0].run!();
      expect(userTab.act.flagValue).toHaveBeenLastCalledWith("account", r[column === "actor_upn" ? "actor_upn" : "owner_upn"], null, "suspicious", expect.stringMatching(/^account /));
    }
    expect(labels(rowMenu({ column: "ip", row: r, ticked: [] }, userTab)).at(-2)).toBe("Flag every event from this IP in this user (incl. later imports)");
    // Another account's cell in that tab keeps the scope.
    const other = rowMenu({ column: "actor_upn", row: ev({ actor_upn: "other@contoso.example" }), ticked: [] }, userTab);
    expect(labels(other).at(-1)).toBe("Flag every event with this account in this user (incl. later imports)");
    // The same text under another kind is not the tab's value: an ASN in an IP tab, a session id in a device tab.
    const asn = rowMenu({ column: "asn", row: ev(), ticked: [] }, ctx({ entity: { kind: "ip", value: "64496" } }));
    expect(labels(asn).at(-1)).toBe("Flag every event in AS64496 in this IP (incl. later imports)");
  });

  it("a_read_only_case_disables_every_write_item_with_the_reason_and_keeps_reading_ones", () => {
    const why = "Read-only case, or the analyst name is not set";
    const time = rowMenu({ column: "event_time", row: ev(), ticked: [] }, ctx({ readOnly: why }));
    expect(time.map((i) => [i.label, i.disabled])).toEqual([
      ["Show details", undefined],
      ["Flag this event", why],
      ["Tag this event", why],
      ["Add note…", why],
      ["Add to timeline…", why],
    ]);
    const ip = rowMenu({ column: "ip", row: ev(), ticked: [] }, ctx({ readOnly: why }));
    expect(ip.map((i) => [i.label, i.disabled])).toEqual([
      ["Show details", undefined],
      ["Filter by this value", undefined],
      ["Exclude this value", undefined],
      ["Open IP tab", undefined],
      ["Flag every event from this IP (incl. later imports)", why],
      ["Flag every event from its /24 192.0.2.0/24 (incl. later imports)", why],
    ]);
  });

  it("open_tab_items_need_a_shell", () => {
    expect(labels(rowMenu({ column: "ip", row: ev(), ticked: [] }, ctx({ canOpen: false })))).not.toContain("Open IP tab");
  });
});
