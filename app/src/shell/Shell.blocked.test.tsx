// The whole interaction with no analyst name, in a mounted shell with the real Events screen and entity tab: choose a
// blocked menu item, and the menu is gone and the real analyst-name input has the focus.
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ override: {} as Record<string, (args: Record<string, unknown> | undefined) => unknown> }));
vi.mock("@tauri-apps/api/core", () => ({
  invoke: async (cmd: string, args?: Record<string, unknown>) => {
    if (h.override[cmd]) return h.override[cmd](args);
    return (await import("../mock/backend")).mockCall(cmd, args);
  },
}));
vi.mock("@tauri-apps/api/event", () => ({ listen: async () => () => {} }));
vi.mock("../dialog", () => ({ save: vi.fn(), open: vi.fn() }));

import EntityTab from "../entity/EntityTab";
import EventsView from "../events/EventsView";
import Shell from "./Shell";

const WHY = "The analyst name is not set: enter it to make changes";

beforeEach(() => {
  vi.resetModules();
  localStorage.clear();
  h.override.settings_get = () => ({ analyst: null, recent: ["/synthetic/case.duckdb"] });
});

async function openCase(user: ReturnType<typeof userEvent.setup>) {
  render(<Shell entityTab={(e) => <EntityTab entity={e} />} screens={{ events: () => <EventsView /> }} />);
  await user.click(await screen.findByRole("button", { name: "/synthetic/case.duckdb" }));
  await screen.findByText("81 of 81 shown");
}
const analystInput = () => screen.getByLabelText("Analyst name");
const dataRows = () => screen.getAllByRole("row").slice(1);

describe("a blocked menu item in a mounted shell", () => {
  it("ticked rows: choosing 'Flag N ticked events' closes the menu and focuses the analyst name", async () => {
    const user = userEvent.setup();
    await openCase(user);
    for (const r of dataRows().slice(0, 3)) await user.click(within(r).getByRole("checkbox", { name: "Select event" }));
    fireEvent.contextMenu(within(dataRows()[0]).getAllByRole("cell")[2]);
    const item = await screen.findByRole("menuitem", { name: /^Flag 3 ticked events/ });
    expect(item).toHaveAccessibleDescription(WHY);
    await user.click(item);
    await waitFor(() => expect(analystInput()).toHaveFocus());
    expect(screen.queryByRole("menu")).toBeNull();
    expect(analystInput()).toHaveClass("analyst-flash");
  });

  it("pivot row: choosing the value flag closes the menu and focuses the analyst name", async () => {
    const user = userEvent.setup();
    await openCase(user);
    // The IP cell's menu opens the IP's tab.
    const ipCell = within(dataRows()[0]).getAllByRole("cell").find((c) => /^192\.0\.2\.\d+$/.test(c.textContent ?? ""))!;
    fireEvent.contextMenu(ipCell);
    await user.click(await screen.findByRole("menuitem", { name: "Open IP tab" }));
    const pivot = await screen.findByRole("region", { name: "Accounts" });
    const row = await within(pivot).findAllByRole("row").then((r) => r[1]);
    fireEvent.contextMenu(row);
    const item = await screen.findByRole("menuitem", { name: /^Flag every event with account .* in the whole case/ });
    expect(item).toHaveAccessibleDescription(WHY);
    await user.click(item);
    await waitFor(() => expect(analystInput()).toHaveFocus());
    expect(screen.queryByRole("menu")).toBeNull();
  });
});
