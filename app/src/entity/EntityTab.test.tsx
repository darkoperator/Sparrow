import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  calls: [] as { cmd: string; args: Record<string, unknown> | undefined }[],
  override: {} as Record<string, (args: Record<string, unknown> | undefined) => unknown>,
}));
// The app's one door to the backend goes to the mock backend, recording each call; a test can answer a command itself.
vi.mock("@tauri-apps/api/core", () => ({
  invoke: async (cmd: string, args?: Record<string, unknown>) => {
    h.calls.push({ cmd, args });
    if (h.override[cmd]) return h.override[cmd](args);
    return (await import("../mock/backend")).mockCall(cmd, args);
  },
}));
vi.mock("../dialog", () => ({ save: vi.fn(), open: vi.fn() }));

import type { EventQuery } from "../api";
import { mockCall } from "../mock/backend";
import { NavContext, RefreshBadgesContext, WriteBlockedContext, type Nav } from "../shell/nav";
import type { EntityRef } from "../shell/tabs";
import EntityTab from "./EntityTab";

const nav = (): Nav => ({ openEntity: vi.fn(), openTable: vi.fn(), showInEvents: vi.fn(), openFinding: vi.fn() });

function view(entity: EntityRef, opts: { writeBlocked?: string; n?: Nav; refresh?: () => void } = {}) {
  const n = opts.n ?? nav();
  const refresh = opts.refresh ?? vi.fn();
  const out = render(
    <NavContext.Provider value={n}>
      <RefreshBadgesContext.Provider value={refresh}>
        <WriteBlockedContext.Provider value={opts.writeBlocked ?? null}>
          <EntityTab entity={entity} />
        </WriteBlockedContext.Provider>
      </RefreshBadgesContext.Provider>
    </NavContext.Provider>,
  );
  return { ...out, nav: n, refresh };
}

const ACCOUNT: EntityRef = { kind: "account", value: "frances.rourke@contoso.example" };
// An account that has events in the mock case (the tiles come from the recorded summary whatever the value).
const ADMIN: EntityRef = { kind: "account", value: "admin@contoso.example" };
const IP: EntityRef = { kind: "ip", value: "192.0.2.19" };
const DEVICE: EntityRef = { kind: "device", value: "7d5f6b6a-b999-43da-820e-ac7acb6ae7e7" };
const SESSION: EntityRef = { kind: "session", value: "335fd402-004e-44c5-84f3-b052ee70de8c" };

const callsOf = (cmd: string) => h.calls.filter((c) => c.cmd === cmd);
const lastQuery = (cmd = "events_page") => callsOf(cmd).at(-1)!.args!.query as EventQuery;
/** The tiles as `label: value` text, in order. */
function tileTexts(): string[] {
  const dl = screen.getByLabelText("Summary tiles");
  return within(dl)
    .getAllByRole("group")
    .map((g) => `${g.getAttribute("aria-label")}: ${g.querySelector("dd")!.textContent}`);
}
const pivot = (name: string) => within(screen.getByRole("region", { name }));
const filterBox = (name: string) => within(screen.getByRole("form", { name: "Event filters" })).getByLabelText(name);

beforeEach(async () => {
  h.calls.length = 0;
  for (const k of Object.keys(h.override)) delete h.override[k];
  localStorage.clear();
  await mockCall("case_open", { path: "/x.duckdb", allowUpgrade: false });
});

describe("EntityTab", () => {
  it("tiles_per_kind_exact", async () => {
    // account: counts from the summary, the open findings worst first, and the roles that matched
    const a = view(ACCOUNT);
    await waitFor(() => expect(tileTexts()).toContain("First seen: 2026-08-01T00:42:39Z"));
    expect(tileTexts()).toEqual([
      "First seen: 2026-08-01T00:42:39Z",
      "Last seen: 2026-09-09T17:16:32Z",
      "Events: 917",
      "IPs: 85",
      "Countries: 8",
      "ASNs: 9",
      "Devices: 1",
      "Sessions: 46",
      "Open findings: high 1 · medium 2",
    ]);
    expect(screen.getByText("Events matched as: actor, mailbox owner, message sender, message recipient")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 3 })).toHaveTextContent("User frances.rourke@contoso.example");
    expect(PIVOT_TITLES()).toEqual(["IPs", "Devices", "Sessions"]);
    a.unmount();

    // ip: ip_intel as country, ASN and kind; no roles line
    const b = view(IP);
    await waitFor(() => expect(tileTexts()).toContain("Country: AU · Australia"));
    expect(tileTexts()).toEqual([
      "First seen: 2026-08-03T00:32:02Z",
      "Last seen: 2026-09-09T17:16:32Z",
      "Events: 663",
      "Accounts: 17",
      "Devices: 1",
      "Sessions: 27",
      "Country: AU · Australia",
      "ASN: AS64499 · Documentation ISP 4",
      "Kind: —",
      "Open findings: 0",
    ]);
    expect(screen.queryByText(/Events matched as/)).not.toBeInTheDocument();
    expect(PIVOT_TITLES()).toEqual(["Accounts", "Sessions", "Devices"]);
    b.unmount();

    // device: OS, trust type, compliant and managed from the sign-in device
    const c = view(DEVICE);
    await waitFor(() => expect(tileTexts()).toContain("OS: Windows 11"));
    expect(tileTexts()).toEqual([
      "First seen: 2026-08-12T00:22:04Z",
      "Last seen: 2026-09-09T07:51:48Z",
      "Events: 104",
      "Accounts: 1",
      "IPs: 4",
      "Sessions: 34",
      "OS: Windows 11",
      "Trust type: Azure AD joined",
      "Compliant: yes",
      "Managed: yes",
      "Open findings: 0",
    ]);
    expect(PIVOT_TITLES()).toEqual(["Accounts", "Sessions", "IPs", "Device changes"]);
    c.unmount();

    // session
    view(SESSION);
    await waitFor(() => expect(tileTexts()).toContain("First seen: 2026-09-07T14:09:20Z"));
    expect(tileTexts()).toEqual([
      "First seen: 2026-09-07T14:09:20Z",
      "Last seen: 2026-09-07T22:12:37Z",
      "Events: 15",
      "Accounts: 1",
      "IPs: 1",
      "Countries: 1",
      "Devices: 0",
      "Open findings: 0",
    ]);
    expect(PIVOT_TITLES()).toEqual(["IPs", "Accounts", "Devices"]);
  });

  it("device_missing_fields_and_ip_kind_show_a_dash_not_a_guess", async () => {
    h.override.entity_summary = async (args) => {
      const s = await mockCall<Record<string, unknown>>("entity_summary", args);
      return { ...s, device: { device_id: "x", is_compliant: null, is_managed: false } };
    };
    view(DEVICE);
    await waitFor(() => expect(tileTexts()).toContain("Managed: no"));
    expect(tileTexts()).toEqual(
      expect.arrayContaining(["OS: —", "Trust type: —", "Compliant: —", "Managed: no"]),
    );
  });

  it("pivot_row_opens_entity_tab", async () => {
    const user = userEvent.setup();
    const { nav: n } = view(ACCOUNT);
    await user.click(await pivot("IPs").findByRole("row", { name: "Open ip 192.0.2.20" }));
    expect(n.openEntity).toHaveBeenLastCalledWith({ kind: "ip", value: "192.0.2.20" });
    await user.click(await pivot("Devices").findByRole("row", { name: "Open device 7d5f6b6a-b999-43da-820e-ac7acb6ae7e7" }));
    expect(n.openEntity).toHaveBeenLastCalledWith({ kind: "device", value: "7d5f6b6a-b999-43da-820e-ac7acb6ae7e7" });
    await user.click(await pivot("Sessions").findByRole("row", { name: "Open session 895bd3f0-60ee-4f29-9599-97de834bb852" }));
    expect(n.openEntity).toHaveBeenLastCalledWith({ kind: "session", value: "895bd3f0-60ee-4f29-9599-97de834bb852" });
    expect(n.openEntity).toHaveBeenCalledTimes(3);
  });

  it("pivot_row_opens_with_the_keyboard", async () => {
    const user = userEvent.setup();
    const { nav: n } = view(IP);
    const row = await pivot("Accounts").findByRole("row", { name: "Open account ollie.carter@contoso.example" });
    row.focus();
    await user.keyboard("{Enter}");
    expect(n.openEntity).toHaveBeenCalledWith({ kind: "account", value: "ollie.carter@contoso.example" });
  });

  it("new_badge_shown", async () => {
    view(ACCOUNT);
    const ips = pivot("IPs");
    // Fixture: of the 25 IP rows shown, 24 are new; the first-seen day of 192.0.2.20 equals the entity's.
    const row20 = await ips.findByRole("row", { name: "Open ip 192.0.2.20" });
    expect(within(row20).queryByText("new")).not.toBeInTheDocument();
    const row19 = ips.getByRole("row", { name: "Open ip 192.0.2.19" });
    expect(within(row19).getByText("new")).toBeInTheDocument();
    expect(ips.getAllByText("new")).toHaveLength(24);
    // Sessions: all 25 shown are new; Devices: its one row is
    expect(pivot("Sessions").getAllByText("new")).toHaveLength(25);
    expect(pivot("Devices").getAllByText("new")).toHaveLength(1);
  });

  it("pivot_shows_n_of_total_only_when_cut", async () => {
    view(ACCOUNT);
    await pivot("IPs").findByRole("row", { name: "Open ip 192.0.2.20" });
    expect(screen.getByRole("heading", { name: /^IPs/ })).toHaveTextContent("IPs · showing 25 of 85");
    expect(screen.getByRole("heading", { name: /^Sessions/ })).toHaveTextContent("Sessions · showing 25 of 46");
    // Devices has its single row of 1: not cut
    expect(screen.getByRole("heading", { name: "Devices" })).not.toHaveTextContent("showing");
  });

  it("device_tab_lists_device_changes_separately_and_they_open_nothing", async () => {
    h.override.entity_pivot = async (args) => {
      if (args?.of !== "device_changes") return mockCall("entity_pivot", args);
      return {
        total: 1,
        rows: [
          {
            value: "Add registered users to device",
            label: "Device registered by a user",
            count: 1,
            first_seen: "2026-08-12T00:22:04.000000Z",
            last_seen: "2026-08-12T00:22:04.000000Z",
            is_new: false,
            extra: { actor: "admin@contoso.example", result: "success", record_key: "k1", source_table: "directory_audits" },
          },
        ],
      };
    };
    const user = userEvent.setup();
    const { nav: n } = view(DEVICE);
    const changes = pivot("Device changes");
    expect(await changes.findByText("Add registered users to device")).toBeInTheDocument();
    expect(changes.getByText("Device registered by a user")).toBeInTheDocument();
    expect(changes.getByText("admin@contoso.example")).toBeInTheDocument();
    expect(changes.getByText("2026-08-12T00:22:04Z")).toBeInTheDocument();
    await user.click(changes.getByText("Add registered users to device"));
    expect(n.openEntity).not.toHaveBeenCalled();
    expect(changes.queryByRole("row", { name: /^Open/ })).not.toBeInTheDocument();
  });

  it("findings_listed_and_click_opens_finding", async () => {
    const user = userEvent.setup();
    const { nav: n } = view(ACCOUNT);
    const findings = within(await screen.findByRole("region", { name: "Findings" }));
    await user.click((await findings.findAllByText("Risky Entra sign-in"))[0]);
    expect(n.openFinding).toHaveBeenCalledWith("20309ce49aeb83a9");
    expect(findings.getAllByText(/SPW-HAWK-012 · new · 2026-08-21T09:12:00Z/).length).toBeGreaterThan(0);
  });

  it("range_change_requeries_tiles_pivots_findings", async () => {
    const user = userEvent.setup();
    view(ACCOUNT);
    await waitFor(() => expect(tileTexts()).toContain("Events: 917"));
    // First load: no range anywhere
    for (const cmd of ["entity_summary", "entity_findings"]) {
      expect(callsOf(cmd)).toHaveLength(1);
      expect(callsOf(cmd)[0].args).toMatchObject({ entity: ACCOUNT });
      expect(callsOf(cmd)[0].args!.from).toBeUndefined();
    }
    expect(callsOf("entity_pivot").map((c) => c.args!.of)).toEqual(["ips", "devices", "sessions"]);

    // The range chosen on the tab's own grid (a range outside the entity's events: the backend answers with zeros)
    await user.type(filterBox("From (UTC)"), "2027-01-01T00:00:00Z");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(callsOf("entity_summary")).toHaveLength(2));
    for (const cmd of ["entity_summary", "entity_findings"]) {
      expect(callsOf(cmd)).toHaveLength(2);
      expect(callsOf(cmd)[1].args).toMatchObject({ from: "2027-01-01T00:00:00Z" });
      expect(callsOf(cmd)[1].args!.to).toBeUndefined();
    }
    expect(callsOf("entity_pivot")).toHaveLength(6);
    expect(callsOf("entity_pivot").slice(3).map((c) => [c.args!.of, c.args!.from])).toEqual([
      ["ips", "2027-01-01T00:00:00Z"],
      ["devices", "2027-01-01T00:00:00Z"],
      ["sessions", "2027-01-01T00:00:00Z"],
    ]);
    // What the narrower range returned is what shows
    await waitFor(() => expect(tileTexts()).toContain("Events: 0"));
    expect(tileTexts()).toContain("First seen: —");
    expect(tileTexts()).toContain("Open findings: 0");
    await waitFor(() => expect(screen.getAllByText("None in this range.")).toHaveLength(4));

    // Reset range: the whole case again
    await user.click(screen.getByRole("button", { name: "Reset range" }));
    await waitFor(() => expect(callsOf("entity_summary")).toHaveLength(3));
    expect(callsOf("entity_summary")[2].args!.from).toBeUndefined();
    await waitFor(() => expect(tileTexts()).toContain("Events: 917"));
  });

  it("an_answer_for_an_older_range_is_dropped", async () => {
    // The first summary answers late with a stale count; the second (narrower range) answers at once.
    let release: (v: unknown) => void = () => undefined;
    let n = 0;
    h.override.entity_summary = async (args) => {
      n += 1;
      if (n === 1) {
        const stale = await mockCall<Record<string, unknown>>("entity_summary", args);
        return new Promise((r) => {
          release = () => r({ ...stale, events: 111_111 });
        });
      }
      return mockCall("entity_summary", args);
    };
    const user = userEvent.setup();
    view(ACCOUNT);
    await waitFor(() => expect(callsOf("entity_summary")).toHaveLength(1));
    await user.type(filterBox("From (UTC)"), "2027-01-01");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(tileTexts()).toContain("Events: 0"));
    release(null);
    await new Promise((r) => setTimeout(r, 20));
    expect(tileTexts()).toContain("Events: 0");
    expect(tileTexts()).not.toContain("Events: 111,111");
  });

  it("group_to_timeline_sends_query", async () => {
    const user = userEvent.setup();
    const { refresh } = view(ADMIN);
    await waitFor(() => expect(tileTexts()).toContain("Events: 917"));
    const button = screen.getByRole("button", { name: "+ Timeline (group)" });
    await waitFor(() => expect(button).toBeEnabled());
    const count = (await mockCall<{ total: number }>("events_summary", { query: lastQuery("events_summary") })).total;
    expect(count).toBeGreaterThan(0);
    await user.click(button);
    const dialog = screen.getByRole("dialog", { name: "Add to timeline" });
    expect(within(dialog).getByLabelText("Title")).toHaveValue(`account admin@contoso.example: ${count} events`);
    expect(within(dialog).getByLabelText("Phase")).toHaveValue("");
    await user.click(within(dialog).getByRole("button", { name: "Add to timeline" }));

    await waitFor(() => expect(callsOf("timeline_add_events")).toHaveLength(1));
    // The tab's current query: the entity scope plus whatever the boxes and range hold (nothing here); no rows, no phase.
    expect(callsOf("timeline_add_events")[0].args).toEqual({
      args: {
        query: { entity: ADMIN, fields: [], flag: "all", ai: "all" },
        mode: "group",
        title: `account admin@contoso.example: ${count} events`,
      },
    });
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(screen.getByRole("status")).toHaveTextContent(/^Added/);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("group_to_timeline_uses_the_filters_range_title_and_phase_in_effect", async () => {
    const user = userEvent.setup();
    const { refresh } = view(ADMIN);
    await waitFor(() => expect(callsOf("events_summary")).toHaveLength(1));
    // The Operation filter is in its column's popover; its Apply runs the From typed before it too.
    await user.type(filterBox("From (UTC)"), "2026-08-01");
    fireEvent.contextMenu(screen.getByRole("columnheader", { name: /^Operation/ }));
    const pop = await screen.findByRole("dialog", { name: "Operation column" });
    await user.type(within(pop).getByLabelText("Pattern"), "MailItemsAccessed");
    await user.click(within(pop).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(callsOf("events_summary")).toHaveLength(2));
    const q = lastQuery("events_summary");
    expect(q.fields).toEqual([["operation", "MailItemsAccessed"]]);
    expect(q.from).toBe("2026-08-01T00:00:00Z");
    const count = (await mockCall<{ total: number }>("events_summary", { query: q })).total;
    expect(count).toBeGreaterThan(0);
    await waitFor(() => expect(screen.getByRole("button", { name: "+ Timeline (group)" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "+ Timeline (group)" }));
    const dialog = screen.getByRole("dialog", { name: "Add to timeline" });
    expect(within(dialog).getByLabelText("Title")).toHaveValue(`account admin@contoso.example: ${count} events`);
    await user.clear(within(dialog).getByLabelText("Title"));
    await user.type(within(dialog).getByLabelText("Title"), "Mail reads after Aug 1");
    await user.selectOptions(within(dialog).getByLabelText("Phase"), "collection");
    await user.click(within(dialog).getByRole("button", { name: "Add to timeline" }));
    await waitFor(() => expect(callsOf("timeline_add_events")).toHaveLength(1));
    expect(callsOf("timeline_add_events")[0].args).toEqual({
      args: { query: q, mode: "group", title: "Mail reads after Aug 1", phase: "collection" },
    });
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
  });

  it("group_to_timeline_shows_the_backends_refusal_and_keeps_the_dialog", async () => {
    h.override.timeline_add_events = async () => {
      throw { kind: "invalid", message: "250000 events: a grouped entry is limited to 100000" };
    };
    const user = userEvent.setup();
    const { refresh } = view(ADMIN);
    const button = screen.getByRole("button", { name: "+ Timeline (group)" });
    await waitFor(() => expect(button).toBeEnabled());
    await user.click(button);
    await user.click(screen.getByRole("button", { name: "Add to timeline" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("250000 events: a grouped entry is limited to 100000");
    expect(screen.getByRole("dialog", { name: "Add to timeline" })).toBeInTheDocument();
    expect(refresh).not.toHaveBeenCalled();
    // Cancel closes it, with nothing added
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(callsOf("timeline_add_events")).toHaveLength(1);
  });

  it("group_to_timeline_disabled_with_a_reason_when_read_only_or_nothing_matches", async () => {
    const a = view(ADMIN, { writeBlocked: "Read-only case: the case file is older than this version" });
    await waitFor(() => expect(callsOf("events_summary")).toHaveLength(1));
    const button = screen.getByRole("button", { name: "+ Timeline (group)" });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("title", "Read-only case: the case file is older than this version");
    a.unmount();

    h.override.events_summary = async (args) => {
      const s = await mockCall<Record<string, unknown>>("events_summary", args);
      return { ...s, total: 0 };
    };
    view(ADMIN);
    await waitFor(() => expect(screen.getByRole("button", { name: "+ Timeline (group)" })).toHaveAttribute("title", "No events match this tab's filters"));
    expect(screen.getByRole("button", { name: "+ Timeline (group)" })).toBeDisabled();
  });

  it("group_to_timeline_is_disabled_while_a_new_grid_query_is_pending", async () => {
    const user = userEvent.setup();
    view(ADMIN);
    const button = () => screen.getByRole("button", { name: "+ Timeline (group)" });
    await waitFor(() => expect(button()).toBeEnabled());
    // The next run's summary is held: the boxes show the new range, the grid still shows the old results.
    let release: () => void = () => undefined;
    const held = new Promise<void>((r) => (release = r));
    h.override.events_summary = async (args) => {
      await held;
      return mockCall("events_summary", args);
    };
    await user.type(filterBox("From (UTC)"), "2026-08-01");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(button()).toBeDisabled());
    expect(button()).toHaveAttribute("title", "Wait for the events to finish loading");
    await user.click(button());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(callsOf("timeline_add_events")).toHaveLength(0);
    // Answered: enabled again, and the dialog now holds the query that was applied (with the range).
    release();
    await waitFor(() => expect(button()).toBeEnabled());
    await user.click(button());
    const dialog = screen.getByRole("dialog", { name: "Add to timeline" });
    await user.click(within(dialog).getByRole("button", { name: "Add to timeline" }));
    await waitFor(() => expect(callsOf("timeline_add_events")).toHaveLength(1));
    expect((callsOf("timeline_add_events")[0].args!.args as { query: EventQuery }).query.from).toBe("2026-08-01T00:00:00Z");
  });

  it("a_range_change_shows_tiles_pivots_and_findings_as_loading_until_each_answers", async () => {
    const user = userEvent.setup();
    view(ACCOUNT);
    await waitFor(() => expect(tileTexts()).toContain("Events: 917"));
    await pivot("IPs").findByRole("row", { name: "Open ip 192.0.2.20" });
    await within(screen.getByRole("region", { name: "Findings" })).findAllByText("Risky Entra sign-in");
    // Hold the next answers of the summary, the IP pivot and the findings.
    const gates: Record<string, () => void> = {};
    const gate = (cmd: string) => {
      const p = new Promise<void>((r) => (gates[cmd] = r));
      h.override[cmd] = async (args) => {
        const first = args?.of === undefined || args.of === "ips";
        if (first) await p;
        delete h.override[cmd];
        return mockCall(cmd, args);
      };
    };
    gate("entity_summary");
    gate("entity_pivot");
    gate("entity_findings");
    await user.type(filterBox("From (UTC)"), "2027-01-01");
    await user.click(screen.getByRole("button", { name: "Search" }));
    // Nothing from the old range stays on screen.
    await waitFor(() => expect(screen.queryByLabelText("Summary tiles")).not.toBeInTheDocument());
    expect(screen.queryByRole("row", { name: "Open ip 192.0.2.20" })).not.toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Findings" })).queryByText("Risky Entra sign-in")).not.toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Findings" })).getByText("Loading…")).toBeInTheDocument();
    expect(pivot("IPs").getByText("Loading…")).toBeInTheDocument();
    expect(screen.getAllByText("Loading…").length).toBeGreaterThanOrEqual(3);
    // The pivots that answered at once show; the held ones fill in when they answer, for the new range.
    await waitFor(() => expect(pivot("Devices").getByText("None in this range.")).toBeInTheDocument());
    gates.entity_pivot();
    gates.entity_findings();
    gates.entity_summary();
    await waitFor(() => expect(pivot("IPs").getByText("None in this range.")).toBeInTheDocument());
    await waitFor(() => expect(tileTexts()).toContain("Events: 0"));
    expect(within(screen.getByRole("region", { name: "Findings" })).getByText("None in this range.")).toBeInTheDocument();
  });

  it("late_pivot_and_findings_answers_for_an_older_range_are_dropped", async () => {
    // The first range's IP pivot and findings answer only after the second range's.
    const gates: (() => void)[] = [];
    const late = (cmd: string, isIps: (a?: Record<string, unknown>) => boolean) => {
      let n = 0;
      h.override[cmd] = async (args) => {
        n += 1;
        if (n === 1 && isIps(args)) {
          const old = await mockCall(cmd, args);
          return new Promise((r) => gates.push(() => r(old)));
        }
        return mockCall(cmd, { ...args, from: args?.from ?? undefined });
      };
    };
    late("entity_pivot", (a) => a?.of === "ips");
    late("entity_findings", () => true);
    const user = userEvent.setup();
    view(ACCOUNT);
    await waitFor(() => expect(callsOf("entity_findings")).toHaveLength(1));
    await user.type(filterBox("From (UTC)"), "2027-01-01");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(pivot("IPs").getByText("None in this range.")).toBeInTheDocument());
    await waitFor(() => expect(within(screen.getByRole("region", { name: "Findings" })).getByText("None in this range.")).toBeInTheDocument());
    gates.forEach((g) => g());
    await new Promise((r) => setTimeout(r, 30));
    expect(pivot("IPs").getByText("None in this range.")).toBeInTheDocument();
    expect(pivot("IPs").queryByRole("row", { name: /^Open ip/ })).not.toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Findings" })).getByText("None in this range.")).toBeInTheDocument();
    expect(gates).toHaveLength(2);
  });

  it("show_in_events_sets_chip", async () => {
    const user = userEvent.setup();
    const { nav: n } = view(IP);
    await user.click(screen.getByRole("button", { name: "Show in Events" }));
    expect(n.showInEvents).toHaveBeenCalledWith(IP);
    expect(n.showInEvents).toHaveBeenCalledTimes(1);
  });

  it("copy_puts_the_value_on_the_clipboard", async () => {
    const user = userEvent.setup();
    view(IP);
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    await user.click(screen.getByRole("button", { name: "Copy" }));
    expect(writeText).toHaveBeenCalledWith("192.0.2.19");
    expect(await screen.findByText("Copied 192.0.2.19")).toBeInTheDocument();
  });

  it("the_events_grid_is_scoped_to_the_entity", async () => {
    view(SESSION);
    await waitFor(() => expect(callsOf("events_page")).toHaveLength(1));
    expect(lastQuery().entity).toEqual(SESSION);
    expect(screen.queryByRole("group", { name: "Scope" })).not.toBeInTheDocument();
  });

  it("coverage_strip_shows_under_the_tiles_and_asks_for_the_tabs_entity", async () => {
    view(ACCOUNT);
    const strip = await screen.findByRole("region", { name: "Coverage warning" });
    expect(callsOf("entity_coverage")).toHaveLength(1);
    expect(callsOf("entity_coverage")[0].args).toMatchObject({ entity: ACCOUNT });
    expect(callsOf("entity_coverage")[0].args!.from).toBeUndefined();
    expect(within(strip).getAllByRole("listitem").map((li) => li.textContent)).toEqual([
      "Unified audit log in this range is sampled (capped export)",
      "MailItemsAccessed in this range has no data",
      "Mailbox audit log (legacy) in this range has no data",
    ]);
    // Under the tiles, before the pivot tables.
    const tiles = screen.getByLabelText("Summary tiles");
    expect(tiles.compareDocumentPosition(strip) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(strip.compareDocumentPosition(screen.getByRole("region", { name: "Findings" })) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("coverage_strip_is_absent_when_everything_is_covered", async () => {
    h.override.entity_coverage = async (args) => {
      const c = await mockCall<{ tenants: { sources: { state: string; accounts_by_state: Record<string, string[]> }[] }[] }>("entity_coverage", args);
      for (const t of c.tenants) for (const s of t.sources) { s.state = "covered"; s.accounts_by_state = {}; }
      return c;
    };
    view(ACCOUNT);
    await waitFor(() => expect(callsOf("entity_coverage")).toHaveLength(1));
    await waitFor(() => expect(tileTexts()).toContain("Events: 917"));
    expect(screen.queryByRole("region", { name: "Coverage warning" })).not.toBeInTheDocument();
  });

  it("coverage_requeries_with_the_range_and_drops_a_stale_answer", async () => {
    // The first answer comes late and says everything is absent; the narrower range answers at once with the fixture.
    let release: (v: unknown) => void = () => undefined;
    let n = 0;
    h.override.entity_coverage = async (args) => {
      n += 1;
      if (n === 1) {
        return new Promise((r) => {
          release = () => r({ from: "2026-08-01", to: "2026-09-09", tenants: [{ tenant_key: "late", accounts: [], sources: [{ source: "ual", title: "STALE", state: "absent", accounts_by_state: {} }] }] });
        });
      }
      return mockCall("entity_coverage", args);
    };
    const user = userEvent.setup();
    view(ACCOUNT);
    await waitFor(() => expect(callsOf("entity_coverage")).toHaveLength(1));
    await user.type(filterBox("From (UTC)"), "2026-08-15T00:00:00Z");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(callsOf("entity_coverage")).toHaveLength(2));
    expect(callsOf("entity_coverage")[1].args).toMatchObject({ entity: ACCOUNT, from: "2026-08-15T00:00:00Z" });
    await screen.findByText("Unified audit log in this range is sampled (capped export)");
    release(null);
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText("STALE in this range has no data")).not.toBeInTheDocument();
    expect(screen.getByText("Unified audit log in this range is sampled (capped export)")).toBeInTheDocument();
    // A range with none of the entity's events: the strip is still there, for those days.
    await user.clear(filterBox("From (UTC)"));
    await user.type(filterBox("From (UTC)"), "2027-01-01T00:00:00Z");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(callsOf("entity_coverage")).toHaveLength(3));
    await waitFor(() => expect(tileTexts()).toContain("Events: 0"));
    const strip = await screen.findByRole("region", { name: "Coverage warning" });
    expect(within(strip).getByText("Evidence coverage 2027-01-01 to 2027-01-01 (UTC days)")).toBeInTheDocument();
    expect(within(strip).getByText("Unified audit log in this range is sampled (capped export)")).toBeInTheDocument();
  });

  it("hostile_values_render_as_text", async () => {
    h.override.entity_pivot = async (args) => {
      const page = await mockCall<{ rows: Record<string, unknown>[]; total: number }>("entity_pivot", args);
      return { total: 1, rows: [{ ...page.rows[0], value: "<img src=x onerror=alert(1)>", label: null }].slice(0, 1) };
    };
    const { container } = view(SESSION);
    await waitFor(() => expect(container.textContent).toContain("<img src=x onerror=alert(1)>"));
    expect(container.querySelector("img")).toBeNull();
  });
});

/** The titles of the pivot tables on screen, in order (the Findings box is not one). */
function PIVOT_TITLES(): string[] {
  return screen
    .getAllByRole("heading", { level: 4 })
    .map((hd) => hd.firstChild?.textContent ?? "")
    .filter((t) => ["Accounts", "IPs", "Devices", "Sessions", "Device changes"].includes(t));
}
