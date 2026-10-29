import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

import type { EventQuery, EventRow, FieldValues } from "../api";
import { mockCall } from "../mock/backend";
import { NavContext, type Nav } from "../shell/nav";
import * as fx from "../test/fixtures";
import ColumnFilter from "./ColumnFilter";
import EventsView from "./EventsView";
import { parseField } from "./fieldSyntax";

const callsOf = (cmd: string) => h.calls.filter((c) => c.cmd === cmd);
const lastQuery = () => callsOf("events_page").at(-1)!.args!.query as EventQuery;
const shown = (a: number, b: number) => screen.findByText(`${a} of ${b} shown`);
const header = (label: string) => screen.getByRole("columnheader", { name: new RegExp(`^${label}`) });
const nav = (): Nav => ({ openEntity: vi.fn(), openTable: vi.fn(), showInEvents: vi.fn(), openFinding: vi.fn() });
const ALL: EventQuery = { fields: [], flag: "all", ai: "all" };

async function openFilter(label: string) {
  fireEvent.contextMenu(header(label));
  return screen.findByRole("dialog", { name: `${label} column` });
}
function events() {
  return render(
    <NavContext.Provider value={nav()}>
      <EventsView />
    </NavContext.Provider>,
  );
}

beforeEach(async () => {
  h.calls.length = 0;
  for (const k of Object.keys(h.override)) delete h.override[k];
  localStorage.clear();
  await mockCall("case_open", { path: "/x.duckdb", allowUpgrade: false });
});

describe("column filters in the Events grid", () => {
  it("the nine field boxes are gone; the filter card keeps one row", async () => {
    events();
    await shown(81, 81);
    const form = screen.getByRole("form", { name: "Event filters" });
    for (const label of ["Source", "Operation", "Account", "IP", "Country", "ASN", "Device", "Session", "Tag"]) {
      expect(within(form).queryByLabelText(label)).not.toBeInTheDocument();
    }
    expect(form.querySelectorAll(".ev-row")).toHaveLength(1);
    for (const label of ["Search text", "From (UTC)", "To (UTC)", "Agent marks"]) expect(within(form).getByLabelText(label)).toBeInTheDocument();
    expect(within(form).getByRole("group", { name: "Show" })).toBeInTheDocument();
    expect(within(form).getByRole("button", { name: "Clear all" })).toBeInTheDocument();
  });

  it("lists the values with counts, sends two ticks as a list, Exclude as !a,!b, and Clear removes it", async () => {
    const user = userEvent.setup();
    events();
    await shown(81, 81);
    const pop = await openFilter("Source");
    // The values with their event counts, from the backend, under the query on screen.
    const ual = await within(pop).findByRole("checkbox", { name: "ual" });
    expect(ual.closest("label")).toHaveTextContent(/^ual12$/);
    const asked = callsOf("events_values").at(-1)!.args!;
    expect(asked).toMatchObject({ field: "source", prefix: "", limit: 200, query: ALL });
    // The search box asks for values that start with its text.
    await user.type(within(pop).getByLabelText("Find a value"), "sign");
    await waitFor(() => expect(callsOf("events_values").at(-1)!.args!.prefix).toBe("sign"));
    const names = async () => (await within(pop).findAllByRole("checkbox")).filter((c) => c.getAttribute("role") !== "switch");
    await waitFor(async () => expect((await names()).map((c) => c.getAttribute("aria-label"))).toEqual(["signin_interactive", "signin_noninteractive"]));
    await user.click(within(pop).getByRole("checkbox", { name: "signin_noninteractive" }));
    await user.click(within(pop).getByRole("checkbox", { name: "signin_interactive" }));
    await user.click(within(pop).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(lastQuery().fields).toEqual([["source", "signin_noninteractive,signin_interactive"]]));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    // The title carries a filter icon whose hover lists the filter.
    const icon = screen.getByRole("img", { name: "Source filter: signin_noninteractive,signin_interactive" });
    expect(header("Source")).toContainElement(icon);
    expect(icon).toHaveAttribute("title", "Source filter: signin_noninteractive,signin_interactive");
    // Reopened: the ticks are back, and Exclude turns them into exclusions.
    const again = await openFilter("Source");
    expect(within(again).getByRole("checkbox", { name: "signin_interactive" })).toBeChecked();
    await user.click(within(again).getByRole("switch", { name: "Exclude the ticked values" }));
    await user.click(within(again).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(lastQuery().fields).toEqual([["source", "!signin_noninteractive,!signin_interactive"]]));
    // Clear filter takes the field out of the query and the icon off the title.
    const third = await openFilter("Source");
    expect(within(third).getByRole("switch", { name: "Exclude the ticked values" })).toBeChecked();
    await user.click(within(third).getByRole("button", { name: "Clear filter" }));
    await waitFor(() => expect(lastQuery().fields).toEqual([]));
    expect(screen.queryByRole("img", { name: /^Source filter/ })).not.toBeInTheDocument();
  });

  it("the pattern box adds what ticking cannot say; other filters apply to the counts, its own does not", async () => {
    const user = userEvent.setup();
    events();
    await shown(81, 81);
    const country = await openFilter("Country");
    await user.click(await within(country).findByRole("checkbox", { name: "US" }));
    await user.click(within(country).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(lastQuery().fields).toEqual([["country", "US"]]));
    const acc = await openFilter("Account");
    // Opened while the Country run was loading: it counts again once that query is the one on screen.
    await waitFor(() => expect(callsOf("events_values").at(-1)!.args!.query).toEqual({ fields: [["country", "US"]], flag: "all", ai: "all" }));
    const pattern = within(acc).getByLabelText("Pattern");
    await user.type(pattern, "skyler*");
    await user.click(await within(acc).findByRole("checkbox", { name: "admin@contoso.example" }));
    await user.click(within(acc).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(lastQuery().fields).toEqual([["account", "admin@contoso.example,skyler*"], ["country", "US"]]));
    // Reopened at once, while the account run is still loading: the first count is for the query still on screen and
    // is held back here until after the next one, so a stale answer arriving last is what this checks.
    const both: EventQuery = { fields: [["account", "admin@contoso.example,skyler*"], ["country", "US"]], flag: "all", ai: "all" };
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    h.override.events_values = async (a) => {
      const q = a!.query as EventQuery;
      if (a!.field === "country" && !q.fields.some(([f]) => f === "account")) {
        await gate;
        return { values: [{ value: "STALE", count: 99 }], total: 1 } satisfies FieldValues;
      }
      return mockCall("events_values", a);
    };
    const before = callsOf("events_values").length;
    const again = await openFilter("Country");
    // The count under the account filter, its own left to the backend to ignore.
    await waitFor(() => expect(callsOf("events_values").some((c) => c.args!.field === "country" && JSON.stringify(c.args!.query) === JSON.stringify(both))).toBe(true));
    const want = await mockCall<FieldValues>("events_values", { query: both, field: "country", prefix: "", limit: 200 });
    expect(want.values.length).toBeGreaterThan(0);
    const listed = () =>
      within(again).queryAllByRole("checkbox").filter((c) => c.getAttribute("role") !== "switch").map((c) => [c.getAttribute("aria-label"), c.closest("label")!.textContent]);
    const expected = want.values.map((v) => [v.value, `${v.value}${v.count}`]);
    await waitFor(() => expect(listed()).toEqual(expected));
    // The older count was asked for (and is still held back) before the newer one answered.
    const since = callsOf("events_values").slice(before);
    expect(since.some((c) => c.args!.field === "country" && !(c.args!.query as EventQuery).fields.some(([f]) => f === "account"))).toBe(true);
    release();
    await act(async () => {
      await new Promise((r) => setTimeout(r, 30));
    });
    expect(listed()).toEqual(expected);
    expect(within(again).queryByRole("checkbox", { name: "STALE" })).not.toBeInTheDocument();
  });

  it("a ticked value with a comma, a star, a leading ! or quotes is sent quoted, and the syntax reads it back as that value", async () => {
    const user = userEvent.setup();
    const hostile = ['Send, "now"*', "!Set-Mailbox", "*"];
    const real = mockCall;
    h.override.events_values = async (a) =>
      a!.field === "operation" ? ({ values: hostile.map((value, i) => ({ value, count: i + 1 })), total: 3 } satisfies FieldValues) : real("events_values", a);
    events();
    await shown(81, 81);
    const pop = await openFilter("Operation");
    for (const v of hostile) await user.click(await within(pop).findByRole("checkbox", { name: v }));
    await user.click(within(pop).getByRole("button", { name: "Apply" }));
    const text = '"Send, ""now""*","!Set-Mailbox","*"';
    await waitFor(() => expect(lastQuery().fields).toEqual([["operation", text]]));
    expect(parseField(text)).toEqual({ ok: true, terms: hostile.map((v) => ({ text: v, exclude: false, wild: false })) });
    // The mock reads it the same way: none of the recorded operations is one of those values, so nothing matches
    // (unquoted, `*` alone would match every row).
    await shown(0, 0);
  });

  it("a 60-character account and an IPv6 value show in full in the hover and in the list", async () => {
    const upn = `${"u".repeat(48)}@contoso.example`;
    h.override.events_values = () => ({ values: [{ value: upn, count: 2 }, { value: "2001:db8:abcd:12::1", count: 1 }], total: 2 });
    render(<ColumnFilter field="account" label="Account" text="" query={ALL} onApply={vi.fn()} onClose={vi.fn()} />);
    const box = await screen.findByRole("checkbox", { name: upn });
    expect(box.closest("label")).toHaveAttribute("title", upn);
    expect(screen.getByText(upn)).toBeInTheDocument();
  });

  it("shows 'showing 200 of N' when the list is cut", async () => {
    h.override.events_values = () => ({ values: Array.from({ length: 200 }, (_, i) => ({ value: `v${i}`, count: 1 })), total: 1234 });
    render(<ColumnFilter field="operation" label="Operation" text="" query={ALL} onApply={vi.fn()} onClose={vi.fn()} />);
    expect(await screen.findByText("Showing 200 of 1,234")).toBeInTheDocument();
  });

  it("an answer for an older query never replaces the newer one's list", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    h.override.events_values = async (a) => {
      const q = a!.query as EventQuery;
      if (q.fields.length === 0) {
        await gate;
        return { values: [{ value: "stale", count: 9 }], total: 1 };
      }
      return { values: [{ value: "fresh", count: 1 }], total: 1 };
    };
    const props = { field: "operation" as const, label: "Operation", text: "", onApply: vi.fn(), onClose: vi.fn() };
    const { rerender } = render(<ColumnFilter {...props} query={ALL} />);
    // Another filter changed while the first count was still running.
    rerender(<ColumnFilter {...props} query={{ ...ALL, fields: [["country", "US"]] }} />);
    expect(await screen.findByRole("checkbox", { name: "fresh" })).toBeInTheDocument();
    release();
    await act(async () => {
      await new Promise((r) => setTimeout(r, 30));
    });
    expect(screen.getByRole("checkbox", { name: "fresh" })).toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: "stale" })).not.toBeInTheDocument();
  });

  it("with a raw search the count has a query id, and a superseded or closed count is cancelled", async () => {
    const q: EventQuery = { ...ALL, search: "slow" };
    const props = { field: "operation" as const, label: "Operation", text: "", onApply: vi.fn(), onClose: vi.fn() };
    const { rerender, unmount } = render(<ColumnFilter {...props} query={q} />);
    await waitFor(() => expect(callsOf("events_values")).toHaveLength(1));
    const first = callsOf("events_values")[0].args!.queryId as string;
    expect(typeof first).toBe("string");
    rerender(<ColumnFilter {...props} query={{ ...q, search: "slower" }} />);
    await waitFor(() => expect(callsOf("query_cancel").map((c) => c.args!.queryId)).toEqual([first]));
    const second = callsOf("events_values")[1].args!.queryId as string;
    unmount();
    await waitFor(() => expect(callsOf("query_cancel").map((c) => c.args!.queryId)).toEqual([first, second]));
  });

  it("shows the backend's refusal of this field and keeps the text in the pattern box", async () => {
    render(<ColumnFilter field="ip" label="IP" text="!" error="IP filter: a '!' needs a value after it (like !value)" query={ALL} onApply={vi.fn()} onClose={vi.fn()} />);
    expect(screen.getByRole("alert")).toHaveTextContent("IP filter: a '!' needs a value after it (like !value)");
    expect(screen.getByLabelText("Pattern")).toHaveValue("!");
  });

  it("columns without a filter field keep the plain column menu", async () => {
    events();
    await shown(81, 81);
    fireEvent.contextMenu(header("Time"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Reset columns" })).toBeInTheDocument();
  });

  it("the column items stay below the filter, and Escape closes the popover back to the title", async () => {
    const user = userEvent.setup();
    events();
    await shown(81, 81);
    const pop = await openFilter("IP");
    expect(within(pop).getByRole("menuitem", { name: "Move column left" })).toBeInTheDocument();
    expect(within(pop).getByLabelText("Find a value")).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("a filter on a hidden column is said, and can be cleared", async () => {
    const user = userEvent.setup();
    const rows: EventRow[] = fx.eventsList();
    expect(rows.length).toBeGreaterThan(0);
    events();
    await shown(81, 81);
    const pop = await openFilter("Country");
    await user.click(await within(pop).findByRole("checkbox", { name: "US" }));
    await user.click(within(pop).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(lastQuery().fields).toEqual([["country", "US"]]));
    await user.click(screen.getByText("Columns"));
    await user.click(screen.getByRole("checkbox", { name: "Country" }));
    const note = screen.getByText(/^Filtered on hidden column: Country/);
    await user.click(within(note).getByRole("button", { name: "Clear" }));
    await waitFor(() => expect(lastQuery().fields).toEqual([]));
  });
});
