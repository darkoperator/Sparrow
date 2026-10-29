import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { devices as devicesFixture } from "../test/fixtures";
import { NavContext, type Nav } from "../shell/nav";
import type { SuspectDevice } from "../api";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  devicesList: vi.fn(),
  evidenceFilter: vi.fn(),
}));

import * as api from "../api";
import Devices from "./Devices";

let list: SuspectDevice[];
beforeEach(() => {
  list = devicesFixture();
  vi.mocked(api.devicesList).mockReset();
  vi.mocked(api.devicesList).mockImplementation(async () => list);
  vi.mocked(api.evidenceFilter).mockReset();
});

const rowsOf = async () => {
  const table = await screen.findByRole("table", { name: "Devices to contain" });
  return within(table).getAllByRole("row").slice(1);
};

describe("Devices", () => {
  it("lists the high-confidence devices in the backend's order, status first, and hides the low ones", async () => {
    render(<Devices />);
    const rows = await rowsOf();
    const high = list.filter((d) => d.confidence === "high");
    expect(list.length - high.length).toBeGreaterThan(0);
    expect(high.map((d) => d.lifecycle.status)).toEqual(["active_after_removal", "unknown", "removed"]);
    expect(rows).toHaveLength(high.length);
    rows.forEach((row, i) => {
      expect(within(row).getByTestId("status")).toHaveAttribute("data-status", high[i].lifecycle.status);
      expect(within(row).getByRole("button", { name: new RegExp(high[i].device_id) })).toBeInTheDocument();
    });
    // The low-confidence device is behind the toggle, which says how many there are.
    expect(screen.queryByText(new RegExp(list.find((d) => d.confidence === "low")!.device_id))).toBeNull();
    expect(await screen.findByRole("button", { name: "Show 1 low-confidence devices" })).toBeInTheDocument();
  });

  it("the toggle reveals the low-confidence devices in the same list order, marked, and hides them again", async () => {
    const user = userEvent.setup();
    render(<Devices />);
    await rowsOf();
    await user.click(await screen.findByRole("button", { name: "Show 1 low-confidence devices" }));
    const rows = await rowsOf();
    expect(rows.map((r) => within(r).getByTestId("status").getAttribute("data-status"))).toEqual(
      list.map((d) => d.lifecycle.status),
    );
    const low = rows[list.findIndex((d) => d.confidence === "low")];
    expect(within(low).getByText(/low confidence/)).toBeInTheDocument();
    expect(within(rows[0]).queryByText(/low confidence/)).toBeNull();
    await user.click(screen.getByRole("button", { name: "Hide 1 low-confidence devices" }));
    expect(await rowsOf()).toHaveLength(list.length - 1);
  });

  it("with only low-confidence devices the toggle is above an explanation and no table", async () => {
    const user = userEvent.setup();
    list = list.filter((d) => d.confidence === "low");
    render(<Devices />);
    expect(await screen.findByText("No high-confidence device was seen on a malicious IP.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Show 1 low-confidence devices" }));
    expect(await rowsOf()).toHaveLength(1);
  });

  it("marks a device seen after its removal with a cue that does not depend on colour", async () => {
    render(<Devices />);
    const rows = await rowsOf();
    const badge = within(rows[0]).getByTestId("status");
    // A warning sign in the text, a screen-reader warning, and the style class that adds weight and a border.
    expect(badge).toHaveTextContent("⚠");
    expect(badge).toHaveTextContent("Warning: Active after removal");
    expect(badge).toHaveClass("status-alert");
    expect(within(rows[0]).getByText(/containment did not hold/)).toBeInTheDocument();
    // No other status carries the cue.
    for (const row of rows.slice(1)) {
      const other = within(row).getByTestId("status");
      expect(other).not.toHaveTextContent("⚠");
      expect(other).not.toHaveTextContent("Warning:");
      expect(other).not.toHaveClass("status-alert");
    }
  });

  it("tells the analyst to treat an unknown device as active", async () => {
    const user = userEvent.setup();
    render(<Devices />);
    await user.click(await screen.findByRole("button", { name: /Show 1 low-confidence/ }));
    const rows = await rowsOf();
    for (const [i, d] of list.entries()) {
      const note = within(rows[i]).queryByText(/treat as active/);
      const expected = d.lifecycle.status === "unknown" || d.lifecycle.status === "not_in_latest_inventory";
      expect(note !== null, d.lifecycle.status).toBe(expected);
    }
  });

  it("clicking a device lists its sightings in time order with the malicious IPs marked", async () => {
    const user = userEvent.setup();
    render(<Devices />);
    const rows = await rowsOf();
    const d = list[0];
    await user.click(within(rows[0]).getByRole("button", { name: new RegExp(d.device_id) }));
    const detail = await screen.findByRole("region", { name: `Sightings of ${d.device_id}` });
    const items = within(within(detail).getByRole("list", { name: "Sightings" })).getAllByRole("listitem");
    expect(items).toHaveLength(d.sightings.length);
    expect(items[0]).toHaveTextContent("2026-03-01T08:00:00");
    expect(items[1]).toHaveTextContent("2026-03-05T09:00:00");
    expect(items[2]).toHaveTextContent("no time");
    // The malicious address is marked; the other one is not.
    expect(within(items[0]).getByText("malicious")).toBeInTheDocument();
    expect(within(items[1]).queryByText("malicious")).toBeNull();
    // Lifecycle evidence is named.
    expect(within(detail).getByText(/removed 2026-03-02T09:00:00/)).toBeInTheDocument();
  });

  it("a sighting opens its evidence row in the table browser", async () => {
    const user = userEvent.setup();
    const nav: Nav = { openEntity: vi.fn(), openTable: vi.fn(), showInEvents: vi.fn() };
    vi.mocked(api.evidenceFilter).mockResolvedValue({
      table: "signins",
      filters: [{ op: "eq", column: "record_key", value: "si-0003" }],
    });
    render(
      <NavContext.Provider value={nav}>
        <Devices />
      </NavContext.Provider>,
    );
    const rows = await rowsOf();
    await user.click(within(rows[0]).getByRole("button", { name: new RegExp(list[0].device_id) }));
    const detail = await screen.findByRole("region", { name: `Sightings of ${list[0].device_id}` });
    await user.click(within(detail).getByRole("button", { name: "signins:si-0003" }));
    expect(api.evidenceFilter).toHaveBeenCalledExactlyOnceWith("signins", "si-0003");
    expect(nav.openTable).toHaveBeenCalledExactlyOnceWith("signins", [
      { op: "eq", column: "record_key", value: "si-0003" },
    ]);
  });

  it("shows an error from the backend", async () => {
    vi.mocked(api.devicesList).mockRejectedValue({ kind: "no_case", message: "no case is open" });
    render(<Devices />);
    expect(await screen.findByRole("alert")).toHaveTextContent("no case is open");
  });

  it("says what to do when no device was seen on a malicious IP", async () => {
    list = [];
    render(<Devices />);
    expect(
      await screen.findByText("No device was seen on a malicious IP. Mark IPs malicious with an indicator, or run detection."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
  });
});
