import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  calls: [] as { cmd: string; args: Record<string, unknown> | undefined }[],
}));
// The app's one door to the backend goes to the mock backend, recording each call.
vi.mock("@tauri-apps/api/core", () => ({
  invoke: async (cmd: string, args?: Record<string, unknown>) => {
    h.calls.push({ cmd, args });
    return (await import("../mock/backend")).mockCall(cmd, args);
  },
}));
vi.mock("../dialog", () => ({ save: vi.fn(), open: vi.fn() }));

import { WriteBlockedContext } from "../shell/nav";
import { devices as devicesFixture } from "../test/fixtures";
import Devices from "./Devices";

const callsOf = (cmd: string) => h.calls.filter((c) => c.cmd === cmd);
const list = devicesFixture();
// The fixture's first device: active after removal, with the analyst's Removed and a sighting after it.
const A = list[0];
// The second: unknown, the analyst says confirmed attacker, no note.
const B = list[1];
// The removed device has no analyst status.
const D = list.find((d) => d.lifecycle.status === "removed")!;

function view(writeBlocked: string | null = null) {
  return render(
    <WriteBlockedContext.Provider value={writeBlocked}>
      <Devices />
    </WriteBlockedContext.Provider>,
  );
}

const rowOf = async (id: string) => {
  const table = await screen.findByRole("table", { name: "Devices to contain" });
  return within(table).getAllByRole("row").find((r) => r.textContent?.includes(id))!;
};

beforeEach(async () => {
  vi.resetModules();
  h.calls.length = 0;
  const { mockCall } = await import("../mock/backend");
  await mockCall("case_open", { path: "/x.duckdb", allowUpgrade: false });
});

describe("analyst device status", () => {
  it("shows the Analyst column next to Status: pill, note on hover, and the warning after a removal", async () => {
    expect(A.analyst?.status).toBe("removed");
    expect(A.active_after_analyst_removal).toBe(true);
    view();
    const table = await screen.findByRole("table", { name: "Devices to contain" });
    const heads = within(table).getAllByRole("columnheader").map((c) => c.textContent);
    expect(heads.slice(0, 3)).toEqual(["Status", "Analyst", "Device"]);
    const a = await rowOf(A.device_id);
    // The computed status stays, the analyst's sits next to it.
    expect(within(a).getByTestId("status")).toHaveAttribute("data-status", "active_after_removal");
    const pill = within(a).getByTestId("analyst-status");
    expect(pill).toHaveAttribute("data-status", "removed");
    expect(pill).toHaveTextContent("Removed");
    expect(pill).toHaveAttribute("title", "Analyst status: Removed, set by analyst:carlos at 2026-03-02T10:00:00.000000Z · Note: Wiped by IT; ticket INC-0042");
    expect(within(a).getByTestId("analyst-warning")).toHaveTextContent("Warning: active after your removal");
    const b = await rowOf(B.device_id);
    expect(within(b).getByTestId("analyst-status")).toHaveTextContent("Confirmed attacker");
    expect(within(b).queryByTestId("analyst-warning")).toBeNull();
    const d = await rowOf(D.device_id);
    expect(within(d).queryByTestId("analyst-status")).toBeNull();
    expect(within(d).getByText("—")).toBeInTheDocument();
  });

  it("right-click → Set analyst status → Disabled with a note: saved, audited by the backend, and the list reloads", async () => {
    const user = userEvent.setup();
    view();
    fireEvent.contextMenu(await rowOf(D.device_id));
    await user.click(await screen.findByRole("menuitem", { name: "Set analyst status" }));
    // Clear is off: the device has no status yet.
    expect(screen.getByRole("menuitem", { name: "Clear" })).toHaveAttribute("title", "This device has no analyst status");
    await user.click(screen.getByRole("menuitem", { name: "Disabled…" }));
    const dialog = await screen.findByRole("dialog", { name: "Set analyst status" });
    await user.type(within(dialog).getByRole("textbox", { name: "Note (optional)" }), "  disabled in Entra  ");
    const lists = callsOf("devices_list").length;
    await user.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(callsOf("devices_set_analyst_status")).toHaveLength(1));
    expect(callsOf("devices_set_analyst_status")[0].args).toEqual({ deviceId: D.device_id, status: "disabled", note: "disabled in Entra" });
    expect(await screen.findByRole("status")).toHaveTextContent(`Device ${D.device_id}: analyst status Disabled`);
    await waitFor(() => expect(callsOf("devices_list").length).toBe(lists + 1));
    const pill = await waitFor(async () => within(await rowOf(D.device_id)).getByTestId("analyst-status"));
    expect(pill).toHaveTextContent("Disabled");
    expect(pill.getAttribute("title")).toMatch(/· Note: disabled in Entra$/);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("Clear clears at once; the current status is marked and its note kept when chosen again", async () => {
    const user = userEvent.setup();
    view();
    fireEvent.contextMenu(await rowOf(A.device_id));
    await user.click(await screen.findByRole("menuitem", { name: "Set analyst status" }));
    // Choosing the current status again opens the dialog with its note.
    await user.click(screen.getByRole("menuitem", { name: "Removed (current)…" }));
    const dialog = await screen.findByRole("dialog", { name: "Set analyst status" });
    expect(within(dialog).getByRole("textbox", { name: "Note (optional)" })).toHaveValue("Wiped by IT; ticket INC-0042");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(callsOf("devices_set_analyst_status")).toHaveLength(0);
    // B is a confirmed attacker: make it benign, then clear it.
    fireEvent.contextMenu(await rowOf(B.device_id));
    await user.click(await screen.findByRole("menuitem", { name: "Set analyst status" }));
    await user.click(screen.getByRole("menuitem", { name: "Benign…" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(within(screen.getByRole("status")).getByText(/analyst status Benign/)).toBeInTheDocument());
    fireEvent.contextMenu(await rowOf(B.device_id));
    await user.click(await screen.findByRole("menuitem", { name: "Set analyst status" }));
    await user.click(screen.getByRole("menuitem", { name: "Clear" }));
    await waitFor(() => expect(callsOf("devices_set_analyst_status")).toHaveLength(2));
    expect(callsOf("devices_set_analyst_status")[1].args).toEqual({ deviceId: B.device_id, status: null, note: null });
    expect(await screen.findByText(`Device ${B.device_id}: analyst status cleared`)).toBeInTheDocument();
  });

  it("the keyboard opens the menu (Shift+F10 on the device's button)", async () => {
    const user = userEvent.setup();
    view();
    const row = await rowOf(D.device_id);
    within(row).getByRole("button", { name: new RegExp(D.device_id) }).focus();
    await user.keyboard("{Shift>}{F10}{/Shift}");
    expect(await screen.findByRole("menuitem", { name: "Set analyst status" })).toBeInTheDocument();
  });

  it("is disabled with the write reason on a read-only case, and sends nothing", async () => {
    const user = userEvent.setup();
    view("The case is open read-only");
    fireEvent.contextMenu(await rowOf(D.device_id));
    const item = await screen.findByRole("menuitem", { name: "Set analyst status" });
    expect(item).toHaveAttribute("title", "The case is open read-only");
    await user.click(item);
    expect(screen.queryByRole("menuitem", { name: "Disabled…" })).toBeNull();
    expect(callsOf("devices_set_analyst_status")).toHaveLength(0);
  });
});
