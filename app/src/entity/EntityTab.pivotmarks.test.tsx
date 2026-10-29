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

import { NavContext, RefreshBadgesContext, WriteBlockedContext, type Nav } from "../shell/nav";
import type { EntityRef } from "../shell/tabs";
import EntityTab from "./EntityTab";

const nav = (): Nav => ({ openEntity: vi.fn(), openTable: vi.fn(), showInEvents: vi.fn(), openFinding: vi.fn() });

function view(entity: EntityRef, opts: { writeBlocked?: string } = {}) {
  const n = nav();
  const refresh = vi.fn();
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
const IP: EntityRef = { kind: "ip", value: "192.0.2.19" };
const DEVICE: EntityRef = { kind: "device", value: "7d5f6b6a-b999-43da-820e-ac7acb6ae7e7" };
const callsOf = (cmd: string) => h.calls.filter((c) => c.cmd === cmd);
const pivot = (name: string) => within(screen.getByRole("region", { name }));

// A fresh mock backend per test: value flags would otherwise carry over from one test to the next.
const mockCall = async <T,>(cmd: string, args?: Record<string, unknown>): Promise<T> => (await import("../mock/backend")).mockCall<T>(cmd, args);

beforeEach(async () => {
  vi.resetModules();
  h.calls.length = 0;
  for (const k of Object.keys(h.override)) delete h.override[k];
  localStorage.clear();
  await mockCall("case_open", { path: "/x.duckdb", allowUpgrade: false });
});

const IP_ROW = "Open ip 192.0.2.20";

/** Right-click the row, open the flag submenu whose label starts with `label`, and return the menu. */
async function openFlag(user: ReturnType<typeof userEvent.setup>, row: HTMLElement, label: RegExp) {
  fireEvent.contextMenu(row);
  await user.click(await screen.findByRole("menuitem", { name: label }));
}

describe("pivot marking", () => {
  it("flags_a_pivot_value_in_the_whole_case_and_reloads_the_tab", async () => {
    const user = userEvent.setup();
    const { refresh } = view(ACCOUNT);
    const row = await pivot("IPs").findByRole("row", { name: IP_ROW });
    expect(within(row).queryByText("Malicious")).toBeNull();
    const before = { pivot: callsOf("entity_pivot").length, summary: callsOf("entity_summary").length, page: callsOf("events_page").length };
    await openFlag(user, row, /^Flag every event from IP 192\.0\.2\.20 in the whole case/);
    await user.click(screen.getByRole("menuitem", { name: "Malicious (adds or updates an indicator)" }));
    await waitFor(() => expect(callsOf("marks_flag_value")).toHaveLength(1));
    expect(callsOf("marks_flag_value")[0].args).toEqual({ kind: "ip", value: "192.0.2.20", scope: null, level: "malicious" });
    expect(await screen.findByText(/^Flagged every event with IP 192\.0\.2\.20 malicious, including later imports/)).toBeInTheDocument();
    // The pill comes from the reloaded pivot, and tiles, pivots and the grid read again.
    const again = await pivot("IPs").findByRole("row", { name: IP_ROW });
    expect(await within(again).findByText("Malicious")).toHaveAttribute("title", "Malicious flag on this value for every event in the case");
    expect(callsOf("entity_pivot").length).toBeGreaterThan(before.pivot);
    expect(callsOf("entity_summary").length).toBeGreaterThan(before.summary);
    await waitFor(() => expect(callsOf("events_page").length).toBeGreaterThan(before.page));
    expect(refresh).toHaveBeenCalled();
  });

  it("flags_only_the_tabs_events_with_the_tab_as_scope", async () => {
    const user = userEvent.setup();
    view(ACCOUNT);
    const row = await pivot("IPs").findByRole("row", { name: IP_ROW });
    await openFlag(user, row, /^Flag every event from IP 192\.0\.2\.20 in this user/);
    await user.click(screen.getByRole("menuitem", { name: "Suspicious" }));
    await waitFor(() => expect(callsOf("marks_flag_value")).toHaveLength(1));
    expect(callsOf("marks_flag_value")[0].args).toEqual({
      kind: "ip",
      value: "192.0.2.20",
      scope: { kind: "account", value: ACCOUNT.value },
      level: "suspicious",
    });
    const pill = await within(await pivot("IPs").findByRole("row", { name: IP_ROW })).findByText("Suspicious");
    expect(pill).toHaveAttribute("title", "Suspicious flag on this value for only the events of this user");
  });

  it("clearing_removes_the_pill", async () => {
    const user = userEvent.setup();
    view(ACCOUNT);
    const row = await pivot("IPs").findByRole("row", { name: IP_ROW });
    await openFlag(user, row, /in the whole case/);
    await user.click(screen.getByRole("menuitem", { name: "Suspicious" }));
    await within(await pivot("IPs").findByRole("row", { name: IP_ROW })).findByText("Suspicious");
    await openFlag(user, await pivot("IPs").findByRole("row", { name: IP_ROW }), /in the whole case/);
    await user.click(screen.getByRole("menuitem", { name: /^Clear this flag/ }));
    await waitFor(() => expect(within(pivot("IPs").getByRole("row", { name: IP_ROW })).queryByText("Suspicious")).toBeNull());
    expect(callsOf("marks_flag_value").at(-1)!.args).toMatchObject({ level: null, scope: null });
  });

  it("each_table_flags_its_own_kind", async () => {
    const user = userEvent.setup();
    view(IP);
    const acct = await pivot("Accounts").findAllByRole("row", { name: /^Open account / });
    await openFlag(user, acct[0], /^Flag every event with account .* in the whole case/);
    await user.click(screen.getByRole("menuitem", { name: "Malicious (adds or updates an indicator)" }));
    await waitFor(() => expect(callsOf("marks_flag_value")).toHaveLength(1));
    expect(callsOf("marks_flag_value")[0].args).toMatchObject({ kind: "account", scope: null, level: "malicious" });
    const sess = await pivot("Sessions").findAllByRole("row", { name: /^Open session / });
    await openFlag(user, sess[0], /^Flag every event with Entra session .* in this IP/);
    await user.click(screen.getByRole("menuitem", { name: "Malicious" }));
    await waitFor(() => expect(callsOf("marks_flag_value")).toHaveLength(2));
    expect(callsOf("marks_flag_value")[1].args).toMatchObject({ kind: "session", scope: { kind: "ip", value: IP.value }, level: "malicious" });
  });

  it("a_device_row_flags_a_device", async () => {
    const user = userEvent.setup();
    view(ACCOUNT);
    const row = await pivot("Devices").findByRole("row", { name: `Open device ${DEVICE.value}` });
    await openFlag(user, row, /^Flag every event with device .* in the whole case/);
    await user.click(screen.getByRole("menuitem", { name: "Malicious" }));
    await waitFor(() => expect(callsOf("marks_flag_value")[0]?.args).toMatchObject({ kind: "device", value: DEVICE.value, scope: null }));
  });

  it("the_menu_key_and_shift_f10_open_the_same_menu", async () => {
    const user = userEvent.setup();
    view(ACCOUNT);
    const row = await pivot("IPs").findByRole("row", { name: IP_ROW });
    row.focus();
    await user.keyboard("{ContextMenu}");
    expect(await screen.findByRole("menuitem", { name: /in the whole case/ })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("menu")).toBeNull());
    expect(row).toHaveFocus();
    row.focus();
    await user.keyboard("{Shift>}{F10}{/Shift}");
    expect(await screen.findByRole("menuitem", { name: /in this user/ })).toBeInTheDocument();
  });

  it("is_disabled_with_the_reason_when_writes_are_blocked", async () => {
    const user = userEvent.setup();
    const why = "Read-only case: opened from a bundle";
    view(ACCOUNT, { writeBlocked: why });
    const row = await pivot("IPs").findByRole("row", { name: IP_ROW });
    fireEvent.contextMenu(row);
    const item = await screen.findByRole("menuitem", { name: /in the whole case/ });
    expect(item).toHaveAttribute("aria-disabled", "true");
    expect(item).toHaveAttribute("title", why);
    await user.click(item);
    expect(screen.queryByRole("menuitem", { name: "Malicious (adds or updates an indicator)" })).toBeNull();
    expect(callsOf("marks_flag_value")).toHaveLength(0);
  });

  it("device_changes_rows_have_no_menu", async () => {
    view(DEVICE);
    const rows = await pivot("Device changes").findAllByRole("row");
    fireEvent.contextMenu(rows[1]);
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("a_long_account_shows_in_full_in_the_menu_and_the_toast", async () => {
    const user = userEvent.setup();
    const upn = `${"very.long.mailbox.name.".repeat(3)}x@contoso.example`;
    expect(upn.length).toBeGreaterThan(60);
    h.override.entity_pivot = async (args) => {
      const page = await mockCall<{ rows: Record<string, unknown>[]; total: number }>("entity_pivot", args);
      return { total: 1, rows: [{ ...page.rows[0], value: upn, label: null }] };
    };
    h.override.marks_flag_value = async () => ({ audit: {}, indicators: [] });
    view(IP);
    const row = await pivot("Accounts").findByRole("row", { name: `Open account ${upn}` });
    await openFlag(user, row, new RegExp(`account ${upn.replace(/\./g, "\\.")} in the whole case`));
    await user.click(screen.getByRole("menuitem", { name: "Malicious (adds or updates an indicator)" }));
    expect(await screen.findByText(`Flagged every event with account ${upn} malicious, including later imports`)).toBeInTheDocument();
    expect(callsOf("marks_flag_value")[0].args).toMatchObject({ kind: "account", value: upn });
  });

  it("a_full_length_ipv6_address_shows_in_full_in_the_menu_and_the_toast_and_focus_returns_to_the_row", async () => {
    const user = userEvent.setup();
    const v6 = "2001:0db8:abcd:0012:0000:0000:0000:0001";
    h.override.entity_pivot = async (args) => {
      const page = await mockCall<{ rows: Record<string, unknown>[]; total: number }>("entity_pivot", args);
      return { total: 1, rows: [{ ...page.rows[0], value: v6, label: null }] };
    };
    h.override.marks_flag_value = async () => ({ audit: {}, indicators: [] });
    view(ACCOUNT);
    const row = await pivot("IPs").findByRole("row", { name: `Open ip ${v6}` });
    await openFlag(user, row, new RegExp(`from IP ${v6} in the whole case`));
    await user.click(screen.getByRole("menuitem", { name: "Suspicious" }));
    expect(await screen.findByText(`Flagged every event with IP ${v6} suspicious, including later imports`)).toBeInTheDocument();
    expect(callsOf("marks_flag_value")[0].args).toEqual({ kind: "ip", value: v6, scope: null, level: "suspicious" });
    // After an action the focus is back on the row that opened the menu.
    expect(screen.queryByRole("menu")).toBeNull();
    expect(pivot("IPs").getByRole("row", { name: `Open ip ${v6}` })).toHaveFocus();
  });

  it("an_agents_unreviewed_flag_shows_as_pending_in_the_pill", async () => {
    h.override.entity_pivot = async (args) => {
      const page = await mockCall<{ rows: Record<string, unknown>[]; total: number }>("entity_pivot", args);
      return { ...page, rows: page.rows.map((r, i) => (i === 0 ? { ...r, flag: { level: "malicious", pending: true, scope: "entity" } } : r)) };
    };
    view(ACCOUNT);
    const pill = await pivot("IPs").findByText("Malicious · agent");
    expect(pill).toHaveAttribute("title", "Malicious flag on this value for only the events of this user; set by an agent, not yet reviewed");
    expect(pill).toHaveClass("pill-mal");
  });
});
