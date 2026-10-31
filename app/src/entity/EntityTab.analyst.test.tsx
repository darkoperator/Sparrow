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

import type { PivotPage } from "../api";
import { NavContext, RefreshBadgesContext, WriteBlockedContext, type Nav } from "../shell/nav";
import type { EntityRef } from "../shell/tabs";
import { entityPivots } from "../test/fixtures";
import EntityTab from "./EntityTab";
import { flaggedText, flaggedTitle } from "./PivotTable";

const nav = (): Nav => ({ openEntity: vi.fn(), openTable: vi.fn(), showInEvents: vi.fn(), openFinding: vi.fn(), openAccess: vi.fn() });

function view(entity: EntityRef, writeBlocked: string | null = null) {
  return render(
    <NavContext.Provider value={nav()}>
      <RefreshBadgesContext.Provider value={vi.fn()}>
        <WriteBlockedContext.Provider value={writeBlocked}>
          <EntityTab entity={entity} />
        </WriteBlockedContext.Provider>
      </RefreshBadgesContext.Provider>
    </NavContext.Provider>,
  );
}

const ACCOUNT: EntityRef = { kind: "account", value: "frances.rourke@contoso.example" };
const DEVICE: EntityRef = { kind: "device", value: "7d5f6b6a-b999-43da-820e-ac7acb6ae7e7" };
const callsOf = (cmd: string) => h.calls.filter((c) => c.cmd === cmd);
const header = () => screen.getByRole("banner");

beforeEach(async () => {
  vi.resetModules();
  h.calls.length = 0;
  for (const k of Object.keys(h.override)) delete h.override[k];
  localStorage.clear();
  await (await import("../mock/backend")).mockCall("case_open", { path: "/x.duckdb", allowUpgrade: false });
});

describe("device tab: analyst status", () => {
  it("shows none, sets Confirmed attacker from the header button, and the reloaded summary shows it", async () => {
    const user = userEvent.setup();
    view(DEVICE);
    const status = await screen.findByLabelText("Analyst status");
    expect(within(status).getByText("—")).toBeInTheDocument();
    await user.click(within(header()).getByRole("button", { name: "Analyst status ▾" }));
    await user.click(await screen.findByRole("menuitem", { name: "Set analyst status" }));
    await user.click(screen.getByRole("menuitem", { name: "Confirmed attacker…" }));
    const dialog = await screen.findByRole("dialog", { name: "Set analyst status" });
    expect(dialog).toHaveTextContent(`Set device ${DEVICE.value} to Confirmed attacker`);
    const summaries = callsOf("entity_summary").length;
    await user.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(callsOf("devices_set_analyst_status")).toHaveLength(1));
    expect(callsOf("devices_set_analyst_status")[0].args).toEqual({ deviceId: DEVICE.value, status: "confirmed_attacker", note: null });
    expect(await screen.findByText(`Device ${DEVICE.value}: analyst status Confirmed attacker`)).toBeInTheDocument();
    await waitFor(() => expect(callsOf("entity_summary").length).toBeGreaterThan(summaries));
    const pill = await within(await screen.findByLabelText("Analyst status")).findByTestId("analyst-status");
    expect(pill).toHaveTextContent("Confirmed attacker");
    expect(pill.getAttribute("title")).toMatch(/^Analyst status: Confirmed attacker, set by analyst:carlos at /);
  });

  it("right-clicking the header opens the same menu; Shift+F10 too; the warning shows after a removal", async () => {
    const user = userEvent.setup();
    // The device's last event is after the decision: the backend says it was active after the removal.
    h.override.entity_summary = async (a) => {
      const real = await (await import("../mock/backend")).mockCall<Record<string, unknown>>("entity_summary", a);
      return {
        ...real,
        analyst_status: { device_id: DEVICE.value, status: "removed", note: "wiped", decided_by: "analyst:carlos", decided_at: "2026-08-01T00:00:00.000000Z" },
        active_after_analyst_removal: true,
      };
    };
    view(DEVICE);
    const status = await screen.findByLabelText("Analyst status");
    await waitFor(() => expect(within(status).getByTestId("analyst-status")).toHaveTextContent("Removed"));
    expect(within(status).getByTestId("analyst-warning")).toHaveTextContent("active after your removal");
    fireEvent.contextMenu(within(header()).getByText(DEVICE.value));
    expect(await screen.findByRole("menuitem", { name: "Set analyst status" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    within(header()).getByRole("button", { name: "Copy" }).focus();
    await user.keyboard("{Shift>}{F10}{/Shift}");
    await user.click(await screen.findByRole("menuitem", { name: "Set analyst status" }));
    await user.click(screen.getByRole("menuitem", { name: "Clear" }));
    await waitFor(() => expect(callsOf("devices_set_analyst_status")).toHaveLength(1));
    expect(callsOf("devices_set_analyst_status")[0].args).toEqual({ deviceId: DEVICE.value, status: null, note: null });
  });

  it("is disabled with the write reason when writes are off; other kinds of tab have no analyst status", async () => {
    const user = userEvent.setup();
    const { unmount } = view(DEVICE, "The case is open read-only");
    await user.click(await within(header()).findByRole("button", { name: "Analyst status ▾" }));
    expect(await screen.findByRole("menuitem", { name: "Set analyst status" })).toHaveAttribute("title", "The case is open read-only");
    unmount();
    view(ACCOUNT);
    await screen.findByRole("region", { name: "IPs" });
    expect(within(header()).queryByRole("button", { name: "Analyst status ▾" })).toBeNull();
    expect(screen.queryByLabelText("Analyst status")).toBeNull();
    fireEvent.contextMenu(within(header()).getByText(ACCOUNT.value));
    expect(screen.queryByRole("menuitem", { name: "Set analyst status" })).toBeNull();
  });
});

describe("pivot rows: events flagged by any flag", () => {
  it("shows each row's flagged events as a second line of its Count cell, with a hover that tells it from a flag on the value", async () => {
    const page: PivotPage = entityPivots().ips;
    h.override.entity_pivot = (a) => {
      if (a?.of !== "ips") return { rows: [], total: 0 };
      const rows = page.rows.map((r, i) => ({
        ...r,
        flagged: i === 0 ? { malicious: 312, suspicious: 4 } : i === 1 ? { malicious: 0, suspicious: 2 } : { malicious: 0, suspicious: 0 },
      }));
      return { rows, total: page.total };
    };
    view(ACCOUNT);
    const ips = within(await screen.findByRole("region", { name: "IPs" }));
    // No separate column: the counts are a second line of the Count cell, so the card does not scroll sideways.
    const heads = ips.getAllByRole("columnheader").map((c) => c.textContent);
    expect(heads).not.toContain("Flagged");
    expect(heads).toContain("Count");
    const rows = (await ips.findAllByRole("row")).slice(1);
    const count = (row: HTMLElement) => row.querySelector("td.entity-count")!;
    const line = (row: HTMLElement) => count(row).querySelector(".entity-flagged");
    expect(count(rows[0])).toHaveTextContent(`${page.rows[0].count.toLocaleString("en-US")}312 malicious · 4 suspicious`);
    expect(line(rows[0])).toHaveTextContent("312 malicious · 4 suspicious");
    expect(line(rows[0])).toHaveClass("entity-flagged-mal");
    expect(line(rows[0])!.getAttribute("title")).toBe(
      "312 malicious · 4 suspicious: events of this user with this IP that are flagged, by any flag (their own, or a flag on any of their values, such as a device or session). The pill says whether this IP itself is flagged.",
    );
    expect(line(rows[1])).toHaveTextContent("2 suspicious");
    expect(line(rows[1])).toHaveClass("entity-flagged-sus");
    // A row with no flagged event has no second line: just its count.
    expect(line(rows[2])).toBeNull();
    expect(count(rows[2])).toHaveTextContent(new RegExp(`^${page.rows[2].count.toLocaleString("en-US")}$`));
    // ASN / kind is capped (ellipsis) so Count stays in view; its full text is the cell's title.
    const asnIdx = heads.indexOf("ASN / kind");
    expect(ips.getAllByRole("columnheader")[asnIdx]).toHaveClass("entity-col-narrow");
    const asnCell = within(rows[0]).getAllByRole("cell")[asnIdx];
    expect(asnCell).toHaveClass("entity-col-narrow");
    expect(asnCell.getAttribute("title")).toBe(asnCell.textContent);
    expect(asnCell.textContent).toMatch(/^AS\d+ · /);
    // The value itself carries no flag: no pill, while the counts show its flagged events.
    expect(within(rows[0]).queryByText("Malicious")).toBeNull();
  });

  it("formats the counts", () => {
    expect(flaggedText({ malicious: 1234, suspicious: 0 })).toBe("1,234 malicious");
    expect(flaggedText({ malicious: 0, suspicious: 0 })).toBe("—");
    expect(flaggedTitle("sessions", { malicious: 0, suspicious: 0 }, "device")).toMatch(/^None: events of this device with this session /);
  });
});
