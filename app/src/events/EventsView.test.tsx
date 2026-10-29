import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
const save = vi.hoisted(() => vi.fn());
vi.mock("../dialog", () => ({ save: (...a: unknown[]) => save(...a), open: vi.fn() }));

import { mockCall } from "../mock/backend";
import type { EventQuery, EventRow, EventsSummary, Histogram as Hist } from "../api";
import { NavContext, type Nav } from "../shell/nav";
import * as fx from "../test/fixtures";
import EventsView, { parseUtc } from "./EventsView";
import { isoJustBefore, isoZ } from "./Histogram";

const nav = (): Nav => ({ openEntity: vi.fn(), openTable: vi.fn(), showInEvents: vi.fn(), openFinding: vi.fn() });

function view(ui = <EventsView />, n: Nav = nav()) {
  const out = render(<NavContext.Provider value={n}>{ui}</NavContext.Provider>);
  return { ...out, nav: n };
}
const shown = (a: number, b: number) => screen.findByText(`${a} of ${b} shown`);
const callsOf = (cmd: string) => h.calls.filter((c) => c.cmd === cmd);
const lastQuery = (cmd = "events_page") => callsOf(cmd).at(-1)!.args!.query as EventQuery;
/** A filter box by its label (the Columns menu has checkboxes with the same names). */
const box = (name: string) => within(screen.getByRole("form", { name: "Event filters" })).getByLabelText(name);
const header = (label: string) => screen.getByRole("columnheader", { name: new RegExp(`^${label}`) });
/** Open a column's filter popover with a right-click on its title. */
async function openFilter(label: string) {
  fireEvent.contextMenu(header(label));
  return screen.findByRole("dialog", { name: `${label} column` });
}
/** Set a column filter to `text` through its pattern box (no value ticked) and apply it, with `{Enter}` if asked. */
async function filterColumn(user: ReturnType<typeof userEvent.setup>, label: string, text: string, enter = false) {
  const pop = await openFilter(label);
  for (const c of within(pop).queryAllByRole("checkbox", { checked: true })) {
    if (c.getAttribute("role") !== "switch") await user.click(c);
  }
  const pattern = within(pop).getByLabelText("Pattern");
  await user.clear(pattern);
  await user.type(pattern, enter ? `${text}{Enter}` : text);
  if (!enter) await user.click(within(pop).getByRole("button", { name: "Apply" }));
}
/** The filter icon on a column's title, by its hover text. */
const badge = (name: string | RegExp) => screen.getByRole("img", { name });
const summary = () => within(screen.getByRole("group", { name: "Summary" }));
const dataRows = () => screen.getAllByRole("row").slice(1);

beforeEach(async () => {
  h.calls.length = 0;
  for (const k of Object.keys(h.override)) delete h.override[k];
  save.mockReset();
  localStorage.clear();
  await mockCall("case_open", { path: "/x.duckdb", allowUpgrade: false });
});

describe("EventsView", () => {
  it("filters_send_harrier_text_unchanged", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    await filterColumn(user, "Account", " !wren*, skyler sanders ");
    // A value ticked in the list.
    const country = await openFilter("Country");
    await user.click(await within(country).findByRole("checkbox", { name: "US" }));
    await user.click(within(country).getByRole("button", { name: "Apply" }));
    await user.type(box("Search text"), "Send");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(lastQuery().fields).toHaveLength(2));
    // As written (the pattern trimmed), blanks left out; the same query goes to the page, the summary and the chart.
    const expected: EventQuery = {
      fields: [
        ["account", "!wren*, skyler sanders"],
        ["country", "US"],
      ],
      search: "Send",
      flag: "all",
      ai: "all",
    };
    expect(lastQuery()).toEqual(expected);
    expect(lastQuery("events_summary")).toEqual(expected);
    expect(lastQuery("events_histogram")).toEqual(expected);
    // A raw search is cancellable: each call has its own id.
    const ids = ["events_page", "events_summary", "events_histogram"].map((c) => callsOf(c).at(-1)!.args!.queryId);
    expect(new Set(ids).size).toBe(3);
    expect(ids.every((i) => typeof i === "string" && i !== "")).toBe(true);
  });

  it("backend_filter_error_shown_on_its_column", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    await filterColumn(user, "IP", "!");
    // A red icon on the column, its hover the backend's message; the popover shows it as an alert.
    const icon = await screen.findByRole("img", { name: /^IP filter refused: IP filter: a '!' needs a value/ });
    expect(icon).toHaveClass("colf-badge-error");
    expect(header("IP")).toContainElement(icon);
    const pop = await openFilter("IP");
    expect(within(pop).getByRole("alert")).toHaveTextContent(/^IP filter: a '!' needs a value/);
    expect(within(pop).getByLabelText("Pattern")).toHaveValue("!");
    // Nothing else changed: the earlier results stay.
    expect(screen.getByText("81 of 81 shown")).toBeInTheDocument();
    // A different field's message goes to its own column only.
    await user.click(within(pop).getByRole("button", { name: "Clear filter" }));
    await shown(81, 81);
    await filterColumn(user, "Tags", ",,");
    expect(await screen.findByRole("img", { name: /^Tags filter refused: Tag filter: / })).toBeInTheDocument();
    expect(screen.queryByRole("img", { name: /^IP filter/ })).not.toBeInTheDocument();
  });

  it("histogram_drag_sets_from_to_and_reset_clears", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    // jsdom has no layout: the chart falls back to 800px wide and its left edge is 0.
    const geometry = async (q: EventQuery) => {
      const hist = await mockCall<Hist>("events_histogram", { query: q, maxBuckets: 120, group: "operation" });
      const band = (800 - 44 - 12) / hist.series[0][1].length;
      return { t0: Date.parse(hist.start), ms: hist.bucket_seconds * 1000, x: (i: number) => 44 + band * i + band / 2 };
    };
    let { t0, ms, x } = await geometry({ fields: [], flag: "all", ai: "all" });
    const plot = () => screen.getByTestId("histogram-plot");
    // Drag over buckets 2 to 4.
    fireEvent.mouseDown(plot(), { clientX: x(2), button: 0 });
    fireEvent.mouseMove(window, { clientX: x(3) });
    fireEvent.mouseUp(window, { clientX: x(4) });
    const from = isoZ(t0 + 2 * ms);
    const to = isoJustBefore(t0 + 5 * ms);
    await waitFor(() => expect(box("From (UTC)")).toHaveValue(from));
    expect(box("To (UTC)")).toHaveValue(to);
    await waitFor(() => expect(lastQuery().from).toBe(from));
    expect(lastQuery().to).toBe(to);
    const want = await mockCall<{ total: number }>("events_page", { query: lastQuery(), sort: null, offset: 0, limit: 500 });
    await shown(want.total, want.total);
    // The chart is drawn again for the new range; a click, narrower than anything, takes one whole bucket and still returns rows.
    ({ t0, ms, x } = await geometry(lastQuery()));
    await waitFor(() => expect(screen.getAllByTestId("histogram-plot")).toHaveLength(1));
    fireEvent.mouseDown(plot(), { clientX: x(0), button: 0 });
    fireEvent.mouseUp(window, { clientX: x(0) });
    await waitFor(() => expect(lastQuery().from).toBe(isoZ(t0)));
    expect(lastQuery().to).toBe(isoJustBefore(t0 + ms));
    await screen.findByText(/^\d+ of \d+ shown$/);
    expect(dataRows().length).toBeGreaterThan(0);
    // Reset range clears both ends and the query.
    await user.click(screen.getByRole("button", { name: "Reset range" }));
    await waitFor(() => expect(lastQuery().from).toBeUndefined());
    expect(lastQuery().to).toBeUndefined();
    expect(box("From (UTC)")).toHaveValue("");
    expect(box("To (UTC)")).toHaveValue("");
    await waitFor(() => expect(screen.queryByRole("button", { name: "Reset range" })).not.toBeInTheDocument());
    await shown(81, 81);
    // Double-click on the chart resets too.
    ({ x } = await geometry({ fields: [], flag: "all", ai: "all" }));
    fireEvent.mouseDown(plot(), { clientX: x(1), button: 0 });
    fireEvent.mouseUp(window, { clientX: x(1) });
    await waitFor(() => expect(lastQuery().from).toBeDefined());
    fireEvent.doubleClick(plot());
    await waitFor(() => expect(lastQuery().from).toBeUndefined());
  });

  it("summary_click_filters_source", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    await user.click(await within(await screen.findByRole("group", { name: "Summary" })).findByRole("button", { name: /^ual 12$/ }));
    await shown(12, 12);
    expect(badge("Source filter: ual")).toBeInTheDocument();
    expect(lastQuery().fields).toEqual([["source", "ual"]]);
    expect(lastQuery("events_summary").fields).toEqual([["source", "ual"]]);
    // Again: back off.
    await user.click(summary().getByRole("button", { name: /^ual 12$/ }));
    await shown(81, 81);
    expect(screen.queryByRole("img", { name: /^Source filter/ })).not.toBeInTheDocument();
    // A flag count sets the flag filter; the total clears everything.
    await user.click(screen.getByRole("button", { name: /3 suspicious/ }));
    await shown(3, 3);
    expect(lastQuery().flag).toBe("suspicious");
    await user.click(screen.getByRole("button", { name: /81 events|3 events/ }));
    await shown(81, 81);
    expect(lastQuery().flag).toBe("all");
  });

  it("message_trace_events_hidden_until_named", async () => {
    const user = userEvent.setup();
    const real = (q: EventQuery) => mockCall<EventsSummary>("events_summary", { query: q });
    h.override.events_summary = async (a) => ({ ...(await real(a!.query as EventQuery)), hidden_trace_events: 5 });
    view();
    const hidden = await screen.findByRole("button", { name: "5 message trace events hidden — include" });
    expect(hidden).toHaveClass("ev-count-hidden");
    // The query never names them on its own.
    expect(lastQuery().fields).toEqual([]);
    await user.click(hidden);
    await waitFor(() => expect(lastQuery().fields).toEqual([["source", "*"]]));
    // With a source already named, the trace events are added to the list.
    await filterColumn(user, "Source", "ual");
    await user.click(await screen.findByRole("button", { name: /message trace events hidden/ }));
    await waitFor(() => expect(lastQuery().fields).toEqual([["source", "ual,message_trace_event"]]));
    // A list of only exclusions means "everything but": a name would narrow it, so a wildcard is added.
    await filterColumn(user, "Source", "!ual");
    await user.click(await screen.findByRole("button", { name: /message trace events hidden/ }));
    await waitFor(() => expect(lastQuery().fields).toEqual([["source", "!ual,*"]]));
  });

  it("detail_value_click_opens_entity_tab", async () => {
    const user = userEvent.setup();
    const { nav: n } = view();
    await shown(81, 81);
    await user.click(within(dataRows()[0]).getByText("2026-09-10T01:55:36Z"));
    const panel = await screen.findByRole("complementary", { name: "Event detail" });
    await within(panel).findByText("Time (UTC)");
    await user.click(within(panel).getByRole("button", { name: "192.0.2.26" }));
    expect(n.openEntity).toHaveBeenCalledWith({ kind: "ip", value: "192.0.2.26" });
    await user.click(within(panel).getByRole("button", { name: "skyler sanders" }));
    expect(n.openEntity).toHaveBeenLastCalledWith({ kind: "account", value: "skyler sanders" });
    await user.click(within(panel).getByRole("button", { name: "admin@contoso.example" }));
    expect(n.openEntity).toHaveBeenLastCalledWith({ kind: "account", value: "admin@contoso.example" });
    // Raw JSON is collapsed; the panel closes.
    expect(within(panel).getByText("Raw record").closest("details")).not.toHaveAttribute("open");
    await user.click(within(panel).getByRole("button", { name: "Close detail" }));
    expect(screen.queryByRole("complementary", { name: "Event detail" })).not.toBeInTheDocument();
  });

  it("export_calls_backend_with_current_query", async () => {
    const user = userEvent.setup();
    save.mockResolvedValue("/out/events.csv");
    view();
    await shown(81, 81);
    await filterColumn(user, "Account", "skyler*");
    await waitFor(() => expect(lastQuery().fields).toEqual([["account", "skyler*"]]));
    // Typed but not applied (the popover closed with Escape): not part of what is shown, so not part of the export.
    const op = await openFilter("Operation");
    await user.type(within(op).getByLabelText("Pattern"), "Send{Escape}");
    expect(screen.queryByRole("dialog", { name: "Operation column" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Export CSV" }));
    await screen.findByText(/Exported \d+ events to \/out\/events\.csv/);
    expect(save).toHaveBeenCalledWith({ defaultPath: "events.csv", filters: [{ name: "CSV", extensions: ["csv"] }] });
    const c = callsOf("events_export_csv");
    expect(c).toHaveLength(1);
    expect(c[0].args).toMatchObject({
      query: { fields: [["account", "skyler*"]], flag: "all", ai: "all" },
      path: "/out/events.csv",
    });
    expect(typeof c[0].args!.queryId).toBe("string");
    // A cancelled dialog exports nothing.
    save.mockResolvedValue(null);
    await user.click(screen.getByRole("button", { name: "Export CSV" }));
    expect(callsOf("events_export_csv")).toHaveLength(1);
  });

  it("flag_colours_and_ai_tag_badge_render", async () => {
    const user = userEvent.setup();
    const { container } = view();
    await shown(81, 81);
    const top = dataRows();
    // Newest rows: one malicious, then suspicious ones (see the recorded list).
    expect(top[0]).toHaveClass("ev-flag-malicious");
    expect(top[0]).toHaveTextContent("Malicious");
    expect(top[1]).toHaveClass("ev-flag-suspicious");
    expect(container.querySelectorAll(".ev-flag-malicious")).toHaveLength(1);
    // Agent marks: filter to them. One row carries an unconfirmed agent flag, one an agent tag.
    await user.selectOptions(box("Agent marks"), "marked");
    await shown(2, 2);
    const aiRows = dataRows();
    expect(aiRows).toHaveLength(2);
    const flagged = aiRows.filter((r) => r.classList.contains("ev-flag-ai"));
    expect(flagged).toHaveLength(1);
    expect(flagged[0]).toHaveClass("ev-flag-suspicious");
    expect(flagged[0]).toHaveTextContent("Suspicious (AI)");
    const tagged = aiRows.find((r) => r.querySelector(".ev-tag-ai"))!;
    const badge = tagged.querySelector(".ev-tag-ai")!;
    expect(badge).toHaveTextContent("ai:relay");
    expect(within(badge as HTMLElement).getByText("AI")).toBeInTheDocument();
    expect(tagged).not.toHaveClass("ev-flag-ai");
    // An analyst tag is plain: no dashed style, no badge.
    await user.selectOptions(box("Agent marks"), "all");
    const tags = await openFilter("Tags");
    await user.click(await within(tags).findByRole("checkbox", { name: "phish-lure" }));
    await user.click(within(tags).getByRole("button", { name: "Apply" }));
    await screen.findByText(/2 of 2 shown/);
    expect(lastQuery().fields).toEqual([["tag", "phish-lure"]]);
    const plain = dataRows()[0].querySelector(".ev-tag")!;
    expect(plain).toHaveTextContent("phish-lure");
    expect(plain).not.toHaveClass("ev-tag-ai");
    expect(within(plain as HTMLElement).queryByText("AI")).not.toBeInTheDocument();
  });

  it("a_search_shows_a_spinner_and_cancel_keeps_the_previous_results", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    await user.type(box("Search text"), "slow");
    await user.click(screen.getByRole("button", { name: "Search" }));
    const status = await screen.findByText("Searching…");
    expect(status.closest("[role=status]")).toBeInTheDocument();
    const ids = ["events_page", "events_summary", "events_histogram"].map((c) => callsOf(c).at(-1)!.args!.queryId as string);
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await screen.findByText("Cancelled. The previous results are still shown.");
    expect(screen.queryByText("Searching…")).not.toBeInTheDocument();
    expect(callsOf("query_cancel").map((c) => c.args!.queryId).sort()).toEqual([...ids].sort());
    expect(screen.getByText("81 of 81 shown")).toBeInTheDocument();
    // Export and paging still act on the query that produced what is shown: the one with no search.
    save.mockResolvedValue("/out/e.csv");
    await user.click(screen.getByRole("button", { name: "Export CSV" }));
    await screen.findByText(/Exported/);
    expect((callsOf("events_export_csv")[0].args!.query as EventQuery).search).toBeUndefined();
    // A plain query shows no Cancel.
    await user.clear(box("Search text"));
    await user.click(screen.getByRole("button", { name: "Search" }));
    await shown(81, 81);
    expect(screen.queryByRole("button", { name: "Cancel" })).not.toBeInTheDocument();
  });

  it("from_and_to_take_iso_utc_and_refuse_anything_else", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    const before = callsOf("events_page").length;
    await user.type(box("From (UTC)"), "2026-09-10T01:00:00+02:00");
    await user.click(screen.getByRole("button", { name: "Search" }));
    expect(await screen.findByText(/not an ISO 8601 UTC time/)).toHaveAttribute("role", "alert");
    expect(callsOf("events_page")).toHaveLength(before);
    await user.clear(box("From (UTC)"));
    await user.type(box("From (UTC)"), "2026-09-10");
    await user.type(box("To (UTC)"), "2026-09-10");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(lastQuery().from).toBe("2026-09-10T00:00:00Z"));
    expect(lastQuery().to).toBe("2026-09-10T23:59:59.999999Z");
    expect(box("From (UTC)")).toHaveValue("2026-09-10T00:00:00Z");
    // 2026-09-10 has the three newest mailbox rows' day: every row of that day, none after.
    expect(await screen.findByText(/^\d+ of \d+ shown$/)).toBeInTheDocument();
    await user.clear(box("To (UTC)"));
    await user.type(box("To (UTC)"), "2026-09-09");
    await user.click(screen.getByRole("button", { name: "Search" }));
    expect(await screen.findByText("To is before From")).toBeInTheDocument();
  });

  it("sorting_reloads_only_the_page_and_keeps_the_applied_query", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    await user.type(box("Search text"), "typed but not applied");
    const sums = callsOf("events_summary").length;
    await user.click(screen.getByRole("button", { name: /^Time/ }));
    await waitFor(() => expect(callsOf("events_page").at(-1)!.args!.sort).toEqual({ column: "event_time", descending: false }));
    expect(callsOf("events_summary")).toHaveLength(sums);
    expect(lastQuery().fields).toEqual([]);
    expect(lastQuery().search).toBeUndefined();
    await waitFor(() => expect(screen.getByRole("columnheader", { name: /^Time/ })).toHaveAttribute("aria-sort", "ascending"));
    await user.click(screen.getByRole("button", { name: /^Time/ }));
    await waitFor(() => expect(callsOf("events_page").at(-1)!.args!.sort).toEqual({ column: "event_time", descending: true }));
    // Tags, notes and flag cannot be sorted: their headers are plain text.
    expect(screen.queryByRole("button", { name: /^Tags/ })).not.toBeInTheDocument();
  });

  it("the cell_menu_filters_and_opens_tabs", async () => {
    const user = userEvent.setup();
    const { nav: n } = view();
    await shown(81, 81);
    const cell = within(dataRows()[0]).getByText("192.0.2.26");
    fireEvent.contextMenu(cell);
    await user.click(screen.getByRole("menuitem", { name: "Open IP tab" }));
    expect(n.openEntity).toHaveBeenCalledWith({ kind: "ip", value: "192.0.2.26" });
    fireEvent.contextMenu(within(dataRows()[0]).getByText("192.0.2.26"));
    await user.click(screen.getByRole("menuitem", { name: "Filter by this value" }));
    await waitFor(() => expect(lastQuery().fields).toEqual([["ip", "192.0.2.26"]]));
    expect(badge("IP filter: 192.0.2.26")).toBeInTheDocument();
    // Act on the filtered rows only once they are on screen: a menu opened on a row the reload replaces closes.
    await waitFor(() => expect(dataRows().every((r) => within(r).queryByText("192.0.2.26"))).toBe(true));
    fireEvent.contextMenu(within(dataRows()[0]).getByText("Send"));
    await user.click(screen.getByRole("menuitem", { name: "Exclude this value" }));
    await waitFor(() => expect(lastQuery().fields).toEqual([["operation", "!Send"], ["ip", "192.0.2.26"]]));
    await waitFor(() => expect(screen.queryByText("Loading…")).not.toBeInTheDocument());
    await waitFor(() => expect(dataRows().some((r) => within(r).queryByText("Send"))).toBe(false));
    // The keyboard can reach the details too.
    fireEvent.contextMenu(within(dataRows()[0]).getByText("192.0.2.26"));
    await user.click(screen.getByRole("menuitem", { name: "Show details" }));
    expect(await screen.findByRole("complementary", { name: "Event detail" }, { timeout: 3000 })).toBeInTheDocument();
  });

  it("a_finding_marker_opens_the_finding", async () => {
    const user = userEvent.setup();
    const { nav: n } = view();
    await shown(81, 81);
    const markers = await screen.findAllByRole("button", { name: /^Open finding / });
    expect(markers).toHaveLength(fx.eventsHistogram().findings.length);
    await user.click(markers[0]);
    expect(n.openFinding).toHaveBeenCalledWith(fx.eventsHistogram().findings[0].finding_id);
    markers[1].focus();
    await user.keyboard("{Enter}");
    expect(n.openFinding).toHaveBeenLastCalledWith(fx.eventsHistogram().findings[1].finding_id);
  });

  it("histogram_colours_by_operation_and_the_toggle_refetches_the_chart_alone", async () => {
    const user = userEvent.setup();
    const { container, unmount } = view();
    await shown(81, 81);
    // Operation is the default: the call asks for it and the legend names ten operations and Other.
    expect(callsOf("events_histogram").map((c) => c.args!.group)).toEqual(["operation"]);
    const legend = () => screen.getByRole("group", { name: /in the chart$/ });
    expect(legend()).toHaveAccessibleName("Operations in the chart");
    const entries = within(legend()).getAllByRole("button");
    expect(entries.map((b) => b.textContent)).toEqual([
      "SignInSucceeded 22", "MessageTrace 12", "Send 11", "MoveToDeletedItems 6", "Add member to group 3", "Update 3",
      "Add member to role 2", "Change user license 2", "MailItemsAccessed 2", "SignInFailed 2", "Other 16",
    ]);
    expect(entries.at(-1)).toHaveAttribute("title", "Other operations");
    expect(screen.getByRole("button", { name: "Colour by operation" })).toHaveAttribute("aria-pressed", "true");
    // Hiding Other takes its bars out.
    const before = container.querySelectorAll("svg.ev-chart rect").length;
    await user.click(entries.at(-1)!);
    expect(entries.at(-1)).toHaveAttribute("aria-pressed", "false");
    expect(container.querySelectorAll("svg.ev-chart rect").length).toBeLessThan(before);
    // Source: one histogram call for the query shown; the page and the summary are not run again.
    const counts = () => ["events_page", "events_summary", "events_histogram"].map((c) => callsOf(c).length);
    const [pages, sums] = counts();
    await user.click(screen.getByRole("button", { name: "Colour by source" }));
    await waitFor(() => expect(legend()).toHaveAccessibleName("Sources in the chart"));
    expect(counts()).toEqual([pages, sums, 2]);
    expect(callsOf("events_histogram")[1].args).toEqual({ ...callsOf("events_histogram")[0].args, group: "source" });
    expect(screen.getByRole("button", { name: "Colour by source" })).toHaveAttribute("aria-pressed", "true");
    // Every legend entry starts shown again, and the choice is remembered on this computer.
    expect(within(legend()).getAllByRole("button").every((b) => b.getAttribute("aria-pressed") === "true")).toBe(true);
    expect(localStorage.getItem("sparrow.events.histogram.group")).toBe("source");
    unmount();
    h.calls.length = 0;
    view();
    await shown(81, 81);
    expect(callsOf("events_histogram").map((c) => c.args!.group)).toEqual(["source"]);
  });

  it("histogram_toggle_during_a_run_charts_the_new_query_in_the_new_colouring", async () => {
    const user = userEvent.setup();
    // Storage refuses everything: the toggle still works for this session.
    const get = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("denied");
    });
    const set = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("denied");
    });
    try {
      view();
      await shown(81, 81);
      const first = callsOf("events_histogram")[0].args!;
      expect(first.group).toBe("operation");
      // Query B (a raw search) is run; its chart answers only when released, one gate per colouring.
      const gates: Record<string, () => void> = {};
      const held = (g: string) => new Promise<void>((r) => (gates[g] = r));
      const waits = { operation: held("operation"), source: held("source") };
      h.override.events_histogram = async (a) => {
        if ((a!.query as EventQuery).search === "Send") await waits[a!.group as "operation" | "source"];
        return (await import("../mock/backend")).mockCall("events_histogram", a);
      };
      await user.type(box("Search text"), "Send");
      await user.click(screen.getByRole("button", { name: "Search" }));
      await waitFor(() => expect(callsOf("events_histogram")).toHaveLength(2));
      // The toggle while B is pending only records the choice: no chart of the shown query A is asked for.
      await user.click(screen.getByRole("button", { name: "Colour by source" }));
      expect(screen.getByRole("button", { name: "Colour by source" })).toHaveAttribute("aria-pressed", "true");
      expect(callsOf("events_histogram")).toHaveLength(2);
      // The chart A in operations no longer matches the choice: it keeps its place but shows as loading.
      expect(screen.getByText("Loading…")).toBeInTheDocument();
      expect(screen.queryByRole("group", { name: /in the chart$/ })).toBeNull();
      // B lands with its by-operation chart: the grid shows B, and B is fetched again by source; still loading.
      gates.operation();
      const queryB = { ...(first.query as EventQuery), search: "Send" };
      await waitFor(() => expect(callsOf("events_histogram")).toHaveLength(3));
      expect(callsOf("events_histogram")[2].args).toMatchObject({ query: queryB, group: "source" });
      expect(callsOf("events_histogram").every((c) => c.args!.group === "operation" || (c.args!.query as EventQuery).search === "Send")).toBe(true);
      const totalB = (await mockCall<EventsSummary>("events_summary", { query: queryB, queryId: "t-1" })).total;
      await shown(totalB, totalB);
      expect(screen.getByText("Loading…")).toBeInTheDocument();
      // Its source chart: B's events, by source.
      gates.source();
      const legend = await screen.findByRole("group", { name: "Sources in the chart" });
      const sum = within(legend)
        .getAllByRole("button")
        .reduce((a, b) => a + Number(b.textContent!.split(" ").at(-1)), 0);
      expect(sum).toBe(totalB);
      expect(totalB).toBeLessThan(81);
      expect(screen.queryByText("Loading…")).toBeNull();
    } finally {
      get.mockRestore();
      set.mockRestore();
    }
  });

  it("histogram_by_operation_with_only_unnamed_operations_draws_the_other_series", async () => {
    const hist = fx.eventsHistogram();
    const counts = hist.series[0][1];
    const total = counts.reduce((x, y) => x + y, 0);
    h.override.events_histogram = (a) => ({ ...hist, group: a!.group, series: [], other: counts });
    const { container } = view();
    await shown(81, 81);
    const legend = await screen.findByRole("group", { name: "Operations in the chart" });
    expect(within(legend).getAllByRole("button").map((b) => b.textContent)).toEqual([`Other ${total}`]);
    expect(screen.queryByText("No events in this range.")).toBeNull();
    expect(screen.getByRole("img", { name: `Events over time, ${counts.length} bars of 1 day` })).toBeInTheDocument();
    expect(container.querySelectorAll(`svg.ev-chart rect[fill="hsl(0 0% 55%)"]`)).toHaveLength(counts.filter((c) => c > 0).length);
  });

  it("an_operation_named_other_is_not_the_other_series", async () => {
    const hist = fx.eventsHistogram();
    const counts = hist.series[0][1];
    h.override.events_histogram = (a) => ({
      ...hist,
      group: a!.group,
      series: [["Other", counts]],
      other: counts.map((n) => n * 2),
    });
    view();
    await shown(81, 81);
    const total = counts.reduce((x, y) => x + y, 0);
    const entries = within(await screen.findByRole("group", { name: "Operations in the chart" })).getAllByRole("button");
    expect(entries.map((b) => [b.textContent, b.getAttribute("title")])).toEqual([
      [`Other ${total}`, "Other"],
      [`Other ${total * 2}`, "Other operations"],
    ]);
    // Hiding one leaves the other shown.
    await userEvent.setup().click(entries[1]);
    expect(entries.map((b) => b.getAttribute("aria-pressed"))).toEqual(["true", "false"]);
  });

  it("legend_toggles_and_collapse_remember", async () => {
    const user = userEvent.setup();
    const { container, unmount } = view();
    await shown(81, 81);
    // The chart opens coloured by operation; the source legend is one click away.
    await user.click(screen.getByRole("button", { name: "Colour by source" }));
    const ual = await screen.findByRole("button", { name: /^ual 12$/, pressed: true, hidden: false });
    const before = container.querySelectorAll("svg.ev-chart rect").length;
    await user.click(ual);
    expect(ual).toHaveAttribute("aria-pressed", "false");
    expect(container.querySelectorAll("svg.ev-chart rect").length).toBeLessThan(before);
    await user.click(screen.getByRole("button", { name: "▾ Hide timeline" }));
    expect(container.querySelector("svg.ev-chart")).toBeNull();
    unmount();
    view();
    expect(await screen.findByRole("button", { name: "▸ Show timeline" })).toBeInTheDocument();
  });

  it("a_chip_scopes_the_query_and_removing_it_asks_the_host", async () => {
    const user = userEvent.setup();
    const onClear = vi.fn();
    const { rerender } = view(<EventsView chip={{ kind: "ip", value: "192.0.2.26", nonce: 1 }} onClearChip={onClear} />);
    await waitFor(() => expect(lastQuery().entity).toEqual({ kind: "ip", value: "192.0.2.26" }));
    const total = (await mockCall<{ total: number }>("events_page", { query: lastQuery(), sort: null, offset: 0, limit: 1 })).total;
    await shown(total, total);
    await user.click(screen.getByRole("button", { name: "Remove scope 192.0.2.26" }));
    expect(onClear).toHaveBeenCalledOnce();
    rerender(<NavContext.Provider value={nav()}><EventsView onClearChip={onClear} /></NavContext.Provider>);
    await shown(81, 81);
    expect(lastQuery().entity).toBeUndefined();
  });

  it("an_entity_tab_has_a_fixed_scope_and_reports_range_changes", async () => {
    const user = userEvent.setup();
    const onRange = vi.fn();
    view(<EventsView entity={{ kind: "account", value: "admin@contoso.example" }} onRangeChange={onRange} />);
    await waitFor(() => expect(lastQuery().entity).toEqual({ kind: "account", value: "admin@contoso.example" }));
    expect(screen.queryByRole("group", { name: "Scope" })).not.toBeInTheDocument();
    expect(onRange).not.toHaveBeenCalled();
    await user.type(box("From (UTC)"), "2026-09-09T00:00:00Z");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(onRange).toHaveBeenCalledWith("2026-09-09T00:00:00Z", undefined));
    await user.click(screen.getByRole("button", { name: "Reset range" }));
    await waitFor(() => expect(onRange).toHaveBeenLastCalledWith(undefined, undefined));
    expect(onRange).toHaveBeenCalledTimes(2);
  });

  it("hidden_columns_can_be_shown", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    expect(screen.queryByRole("columnheader", { name: /^User agent/ })).not.toBeInTheDocument();
    await user.click(screen.getByText("Columns"));
    await user.click(screen.getByRole("checkbox", { name: "User agent" }));
    expect(screen.getByRole("columnheader", { name: /^User agent/ })).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "Time" }));
    expect(screen.queryByRole("columnheader", { name: /^Time/ })).not.toBeInTheDocument();
  });

  it("hostile_values_are_text_in_the_grid_and_the_detail", async () => {
    const user = userEvent.setup();
    const evil = "<img src=x onerror=alert(1)>\u0007‮";
    const rows = fx.eventsList().slice(0, 3).map((r): EventRow => ({ ...r, operation: evil, latest_note: evil, note_count: 2 }));
    h.override.events_page = () => ({ rows, offset: 0, total: 3, total_capped: false });
    h.override.events_detail = () => ({ ...fx.eventsDetail(), row: rows[0], raw: { x: evil }, notes: [{ ...fx.eventsDetail().notes[0], text: evil }] });
    const { container } = view();
    await shown(3, 3);
    const safe = "<img src=x onerror=alert(1)>\\u{0007}\\u{202E}";
    expect(within(dataRows()[0]).getByText(safe)).toBeInTheDocument();
    expect(within(dataRows()[0]).getByText(`${safe} +1`)).toBeInTheDocument();
    await user.click(within(dataRows()[0]).getByText(safe));
    await screen.findByText("Raw record");
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getAllByText(safe, { exact: false }).length).toBeGreaterThan(1);
  });

  it("hostile_source_names_and_findings_are_text_in_the_chart", async () => {
    const evil = "<img src=x onerror=alert(1)>\u202e";
    const hist = fx.eventsHistogram();
    h.override.events_histogram = (a) => ({
      ...hist,
      group: a!.group,
      series: [[evil, hist.series[0][1]]],
      findings: [{ ...hist.findings[0], finding_id: evil, severity: evil }],
    });
    const { container } = view();
    await shown(81, 81);
    const safe = "<img src=x onerror=alert(1)>\\u{202E}";
    expect(await screen.findByRole("button", { name: new RegExp(`^${safe.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`) })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: `Open finding ${safe} (${safe})` })).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });

  it("cancel ends the run at once: an answer already on its way is ignored, and the spinner stops", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    const late = { rows: fx.eventsList().slice(0, 1), offset: 0, total: 1, total_capped: false };
    const lateSummary = { total: 1, suspicious: 0, malicious: 0, per_source: [["ual", 1]], hidden_trace_events: 0 };
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    h.override.events_page = async (a) => ((a!.query as EventQuery).search ? (await gate, late) : mockCall("events_page", a));
    h.override.events_summary = async (a) => ((a!.query as EventQuery).search ? (await gate, lateSummary) : mockCall("events_summary", a));
    await user.type(box("Search text"), "needle");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await screen.findByText("Searching…");
    const ids = ["events_page", "events_summary", "events_histogram"].map((c) => callsOf(c).at(-1)!.args!.queryId as string);
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    // The spinner is gone before the backend has answered anything.
    expect(screen.queryByText("Searching…")).not.toBeInTheDocument();
    expect(screen.getByText("Cancelled. The previous results are still shown.")).toBeInTheDocument();
    expect(callsOf("query_cancel").map((c) => c.args!.queryId).sort()).toEqual([...ids].sort());
    // The answers arrive successfully after all: they change nothing.
    release();
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(screen.getByText("81 of 81 shown")).toBeInTheDocument();
    expect(summary().getByRole("button", { name: /^81 events$/ })).toBeInTheDocument();
    expect(screen.queryByText("Searching…")).not.toBeInTheDocument();
  });

  it("an older request that resolves after a newer one is ignored", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    const stale = { rows: fx.eventsList().slice(0, 5), offset: 0, total: 5, total_capped: false };
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    h.override.events_page = async (a) => {
      const q = a!.query as EventQuery;
      if (q.fields.some(([, t]) => t === "slow-first")) {
        await gate;
        return stale;
      }
      return mockCall("events_page", a);
    };
    await filterColumn(user, "Account", "slow-first", true);
    await waitFor(() => expect(callsOf("events_page").some((c) => JSON.stringify(c.args).includes("slow-first"))).toBe(true));
    // Search stays available while a run is going: the newer query takes over from the older.
    expect(screen.getByRole("button", { name: "Search" })).toBeEnabled();
    await filterColumn(user, "Account", "skyler*", true);
    await screen.findByText(/^\d+ of \d+ shown$/);
    const want = await mockCall<{ total: number }>("events_page", { query: lastQuery(), sort: null, offset: 0, limit: 1 });
    await shown(want.total, want.total);
    release();
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(screen.getByText(`${want.total} of ${want.total} shown`)).toBeInTheDocument();
    expect(screen.queryByText("5 of 5 shown")).not.toBeInTheDocument();
  });

  it("a failed search keeps the results and says why", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    h.override.events_page = async () => {
      throw { kind: "internal", message: "the search blew up" };
    };
    await user.type(box("Search text"), "needle");
    await user.click(screen.getByRole("button", { name: "Search" }));
    expect(await screen.findByText("the search blew up")).toHaveAttribute("role", "alert");
    expect(screen.getByText("81 of 81 shown")).toBeInTheDocument();
    expect(dataRows().length).toBeGreaterThan(10);
    expect(summary().getByRole("button", { name: /^81 events$/ })).toBeInTheDocument();
    expect(screen.queryByText("Searching…")).not.toBeInTheDocument();
    // Export still acts on the query that is shown (no search).
    save.mockResolvedValue("/out/e.csv");
    h.override.events_page = undefined as never;
    delete h.override.events_page;
    await user.click(screen.getByRole("button", { name: "Export CSV" }));
    await screen.findByText(/Exported/);
    expect((callsOf("events_export_csv")[0].args!.query as EventQuery).search).toBeUndefined();
  });

  it("the summary total is exact; the grid line says M+ only when the page total is capped; paging stops at the limit", async () => {
    const base = fx.eventsList();
    const make = (offset: number, n: number) =>
      Array.from({ length: n }, (_, i): EventRow => ({ ...base[i % base.length], record_key: `k${offset + i}` }));
    h.override.events_page = (a) => {
      const offset = a!.offset as number;
      return { rows: make(offset, 200), offset, total: 1_000_000, total_capped: true };
    };
    h.override.events_summary = () => ({ total: 1_200_000, suspicious: 0, malicious: 0, per_source: [["ual", 1_200_000]], hidden_trace_events: 0 });
    view(<EventsView maxLoaded={400} />);
    await screen.findByRole("group", { name: "Summary" });
    expect(await summary().findByRole("button", { name: "1,200,000 events" })).toBeInTheDocument();
    expect(screen.getByText("200 of 1,000,000+ shown")).toBeInTheDocument();
    expect(screen.queryByText(/paging stops here/)).not.toBeInTheDocument();
    const scrollEnd = () =>
      act(() => {
        const scroller = document.querySelector(".grid-scroll")!;
        scroller.scrollTop = 33 * 190;
        fireEvent.scroll(scroller);
      });
    scrollEnd();
    await screen.findByText(/^400 of 1,000,000\+ shown — paging stops here; narrow the filter to see the rest$/);
    // At the limit nothing more is asked for, however far the analyst scrolls.
    const pages = callsOf("events_page").length;
    scrollEnd();
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(callsOf("events_page")).toHaveLength(pages);
    expect(callsOf("events_page").map((c) => c.args!.offset)).toEqual([0, 200]);
  });

  it("an uncapped total has no plus and no limit line", async () => {
    h.override.events_page = (a) => ({ rows: fx.eventsList().slice(0, 3), offset: a!.offset as number, total: 3, total_capped: false });
    view(<EventsView maxLoaded={3} />);
    expect(await screen.findByText("3 of 3 shown")).toBeInTheDocument();
    expect(screen.queryByText(/paging stops here/)).not.toBeInTheDocument();
  });

  it("Enter in any box sends one request set", async () => {
    const user = userEvent.setup();
    view();
    await shown(81, 81);
    for (const [label, text] of [["Account", "skyler*"], ["Search text", "Send"], ["From (UTC)", "2026-09-09"]] as const) {
      const counts = () => ["events_page", "events_summary", "events_histogram"].map((c) => callsOf(c).length);
      const before = counts();
      const cancels = callsOf("query_cancel").length;
      if (label === "Account") await filterColumn(user, label, text, true);
      else await user.type(box(label), `${text}{Enter}`);
      await waitFor(() => expect(counts()).toEqual(before.map((n) => n + 1)));
      await act(async () => {
        await new Promise((r) => setTimeout(r, 30));
      });
      expect(counts()).toEqual(before.map((n) => n + 1));
      expect(callsOf("query_cancel")).toHaveLength(cancels); // nothing was superseded, so nothing cancelled
    }
  });

  it("more_rows_load_when_the_grid_nears_its_end", async () => {
    const base = fx.eventsList();
    const make = (offset: number, n: number) =>
      Array.from({ length: n }, (_, i): EventRow => ({ ...base[i % base.length], record_key: `k${offset + i}` }));
    h.override.events_page = (a) => {
      const offset = a!.offset as number;
      return { rows: make(offset, Math.min(200, 450 - offset)), offset, total: 450, total_capped: false };
    };
    view();
    await shown(200, 450);
    act(() => {
      const scroller = document.querySelector(".grid-scroll")!;
      scroller.scrollTop = 33 * 190;
      fireEvent.scroll(scroller);
    });
    await waitFor(() => expect(callsOf("events_page").some((c) => c.args!.offset === 200)).toBe(true));
    await shown(400, 450);
  });
});

describe("parseUtc", () => {
  it.each([
    ["", "from", undefined],
    ["  ", "to", undefined],
    ["2026-09-10", "from", "2026-09-10T00:00:00Z"],
    ["2026-09-10", "to", "2026-09-10T23:59:59.999999Z"],
    ["2026-09-10 01:55", "from", "2026-09-10T01:55:00Z"],
    ["2026-09-10T01:55:36Z", "to", "2026-09-10T01:55:36Z"],
    ["2026-09-10T01:55:36.250", "from", "2026-09-10T01:55:36.250Z"],
  ] as const)("reads %j (%s) as %j", (text, end, want) => {
    expect(parseUtc(text, end)).toEqual({ ok: true, value: want });
  });
  it.each(["2026-09-10T01:55:36+02:00", "2026-13-01", "2026-02-30", "2026-09-10T24:00", "yesterday", "2026-09-10T01"])("refuses %j", (text) => {
    expect(parseUtc(text, "from")).toMatchObject({ ok: false });
  });
});
