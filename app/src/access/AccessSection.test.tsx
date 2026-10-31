import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AccessAccount, AccessCategory, AccessItem, AccessReport, AccessTile } from "../api";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  accessReport: vi.fn(),
  exportAccessCsv: vi.fn(),
}));
const dialogSave = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({ save: (...a: unknown[]) => dialogSave(...a) }));

import * as api from "../api";
import AccessSection from "./AccessSection";

const A = "jdoe@contoso.example";
const NEVER = ["Teams chats read in the Teams app are not audited (only Graph reads are)"];
const ORDER: AccessCategory[] = ["mail_read", "mail_sent", "attachment", "file", "teams", "copilot", "other"];

function tile(category: AccessCategory, over: Partial<AccessTile> = {}): AccessTile {
  return {
    category,
    direct: 0,
    by_time: 0,
    qualifier: null,
    coverage: { status: "collected", reason: "collected", remediation: null },
    none_seen: true,
    pending: 0,
    adhoc: 0,
    ...over,
  };
}

function item(over: Partial<AccessItem>): AccessItem {
  return {
    account: A, category: "mail_read", attribution: "ip", accessed: "2026-10-23T16:42:18Z", action: "read",
    item: "Q3 invoices", location: "\\Inbox", from: "ap@vendor.example", to: A, size_bytes: 10, item_time: null,
    app: null, ip: "203.0.113.45", session_id: null, owner: null, note: null, source: "ual_events:MailItemsAccessed",
    source_table: "ual_events", record_key: "r1", basis: "accepted", row: "ual_events:r1", ...over,
  };
}

function account(over: Partial<AccessAccount> = {}): AccessAccount {
  return {
    account: A,
    tenant_key: "contoso",
    scope: [{ kind: "ip", value: "203.0.113.45", basis: "accepted", windows: [{ start: "2026-10-23T16:38:51Z", end: "2026-10-23T17:45:09Z" }] }],
    tiles: ORDER.map((c) => tile(c)),
    items: [],
    gaps: [],
    ...over,
  };
}

function load(a: AccessAccount, pending = 0) {
  const r: AccessReport = { accounts: [a], pending_flags: pending, preview: false, never_logged: NEVER };
  vi.mocked(api.accessReport).mockResolvedValue(r);
}

/** The reviewed answer for the plain request, a preview (one pending item, one what-if scope value) otherwise. */
function loadWithPreview() {
  const reviewed = account({ items: [item({})], tiles: ORDER.map((c) => tile(c, c === "mail_read" ? { direct: 1 } : {})) });
  const preview = account({
    scope: [
      ...reviewed.scope,
      { kind: "ip", value: "198.51.100.7", basis: "adhoc", windows: [{ start: "2026-10-23T18:00:00Z", end: "2026-10-23T19:00:00Z" }] },
    ],
    items: [item({}), item({ record_key: "r2", basis: "pending", item: "Payroll" }), item({ record_key: "r3", basis: "adhoc", item: "Wire" })],
    tiles: ORDER.map((c) => tile(c, c === "mail_read" ? { direct: 3, pending: 1, adhoc: 1 } : {})),
  });
  vi.mocked(api.accessReport).mockImplementation(async (_a, p) =>
    p
      ? { accounts: [preview], pending_flags: 1, preview: true, never_logged: NEVER }
      : { accounts: [reviewed], pending_flags: 1, preview: false, never_logged: NEVER },
  );
}

beforeEach(() => {
  vi.mocked(api.accessReport).mockReset();
  vi.mocked(api.exportAccessCsv).mockReset().mockResolvedValue(null);
  dialogSave.mockReset();
});

describe("AccessSection", () => {
  it("shows_seven_tiles_with_counts", async () => {
    const tiles = ORDER.map((c) => tile(c));
    tiles[0] = tile("mail_read", { direct: 48, by_time: 3, qualifier: "3 folders · 4.1 MB", none_seen: false });
    load(account({ tiles }));
    render(<AccessSection account={A} />);
    const grid = await screen.findByRole("list", { name: "What the attacker reached" });
    const cards = within(grid).getAllByRole("listitem");
    expect(cards.map((c) => c.getAttribute("aria-label"))).toEqual([
      "Emails read", "Emails sent", "Attachments", "SharePoint / OneDrive", "Teams", "Copilot", "Other apps",
    ]);
    expect(cards[0]).toHaveTextContent("48");
    expect(cards[0]).toHaveTextContent("· 3 by time");
    expect(cards[0]).toHaveTextContent("3 folders · 4.1 MB");
    expect(api.accessReport).toHaveBeenCalledWith(A, null);
    expect(screen.getByText("ip 203.0.113.45")).toHaveAttribute("title", "2026-10-23T16:38:51Z to 2026-10-23T17:45:09Z");
  });

  it("marks_time_rows", async () => {
    load(account({ items: [item({ record_key: "r1" }), item({ record_key: "r2", attribution: "time", item: "Board" })] }));
    render(<AccessSection account={A} />);
    const table = await screen.findByRole("table", { name: "Emails read" });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);
    expect(rows[0]).not.toHaveTextContent("by time");
    expect(rows[1]).toHaveTextContent("by time");
  });

  it("none_seen_only_when_covered", async () => {
    const tiles = ORDER.map((c) => tile(c));
    tiles[4] = tile("teams", { none_seen: false, coverage: { status: "partial", reason: "UAL partial: Teams operations of this account may not have been collected", remediation: null } });
    tiles[5] = tile("copilot", { none_seen: false, coverage: { status: "not_licensed", reason: "no licence", remediation: null } });
    // As the core: a reason line per category whose source was not collected, then the never-logged gaps.
    load(account({ tiles, gaps: ["Teams: UAL partial: Teams operations of this account may not have been collected", "Copilot: no licence"] }));
    render(<AccessSection account={A} />);
    const grid = await screen.findByRole("list", { name: "What the attacker reached" });
    const card = (n: string) => within(grid).getByRole("listitem", { name: n });
    expect(card("Emails sent")).toHaveTextContent("none seen");
    expect(card("Teams")).not.toHaveTextContent("none seen");
    expect(card("Teams")).toHaveTextContent("partial");
    expect(card("Copilot")).toHaveTextContent("not licensed");
    const coverage = screen.getByRole("region", { name: "Coverage" });
    expect(coverage).toHaveTextContent("UAL partial: Teams operations of this account may not have been collected");
    expect(coverage).toHaveTextContent("Teams chats read in the Teams app are not audited");
  });

  it("shows_the_note_for_other_peoples_data", async () => {
    load(account({ items: [item({ category: "mail_sent", action: "sent as", owner: "ceo@contoso.example", note: "sent as ceo@contoso.example" })] }));
    render(<AccessSection account={A} />);
    const table = await screen.findByRole("table", { name: "Emails sent" });
    expect(table).toHaveTextContent("sent as ceo@contoso.example");
  });

  it("no_scope_shows_the_message", async () => {
    load(account({ scope: [], items: [] }), 2);
    render(<AccessSection account={A} />);
    expect(await screen.findByText("No malicious sessions or IPs are flagged for this account.")).toBeInTheDocument();
    expect(screen.getByText("2 malicious flags are waiting for review; they count once accepted.")).toBeInTheDocument();
  });

  it("export_csv_saves_this_account", async () => {
    const user = userEvent.setup();
    load(account({ items: [item({})] }));
    dialogSave.mockResolvedValue("/out/jdoe-access.csv");
    render(<AccessSection account={A} />);
    await user.click(await screen.findByRole("button", { name: "Export CSV" }));
    expect(api.exportAccessCsv).toHaveBeenCalledWith("/out/jdoe-access.csv", A, null);
    expect(await screen.findByRole("status")).toHaveTextContent("/out/jdoe-access.csv");
  });

  it("renders_duplicate_looking_rows_each", async () => {
    const twin = item({ category: "copilot", record_key: "c1", item: "Q3.docx", location: null, action: "Read" });
    load(account({ items: [twin, { ...twin }] }));
    render(<AccessSection account={A} />);
    const table = await screen.findByRole("table", { name: "Copilot" });
    expect(within(table).getAllByRole("row").slice(1)).toHaveLength(2);
  });

  it("pages_long_tables", async () => {
    const user = userEvent.setup();
    const many = Array.from({ length: 450 }, (_, n) => item({ record_key: `r${n}` }));
    load(account({ items: many }));
    render(<AccessSection account={A} />);
    const table = await screen.findByRole("table", { name: "Emails read" });
    expect(within(table).getAllByRole("row").slice(1)).toHaveLength(200);
    await user.click(screen.getByRole("button", { name: "Show 200 more of Emails read (250 hidden)" }));
    expect(within(table).getAllByRole("row").slice(1)).toHaveLength(400);
    await user.click(screen.getByRole("button", { name: "Show 50 more of Emails read (50 hidden)" }));
    expect(within(table).getAllByRole("row").slice(1)).toHaveLength(450);
    expect(screen.queryByRole("button", { name: /^Show \d+ more of Emails read/ })).toBeNull();
  });

  it("no_scope_still_shows_tiles_and_coverage", async () => {
    const tiles = ORDER.map((c) => tile(c, { none_seen: false, coverage: { status: "available_not_collected", reason: "run a Purview export", remediation: null } }));
    load(account({ scope: [], items: [], tiles, gaps: ["Emails read: run a Purview export"] }));
    render(<AccessSection account={A} />);
    expect(await screen.findByText("No malicious sessions or IPs are flagged for this account.")).toBeInTheDocument();
    const grid = screen.getByRole("list", { name: "What the attacker reached" });
    expect(within(grid).getByRole("listitem", { name: "Emails read" })).toHaveTextContent("not collected");
    expect(screen.getByRole("region", { name: "Coverage" })).toHaveTextContent("run a Purview export");
  });

  it("mail_tables_show_sent_time_and_size", async () => {
    load(account({ items: [item({ item_time: "2026-10-21T16:17:57Z", size_bytes: 93862 })] }));
    render(<AccessSection account={A} />);
    const table = await screen.findByRole("table", { name: "Emails read" });
    expect(within(table).getByRole("columnheader", { name: "Sent (UTC)" })).toBeInTheDocument();
    expect(table).toHaveTextContent("2026-10-21T16:17:57Z");
    expect(table).toHaveTextContent("91.7 KB");
  });

  it("a_sync_only_tile_is_highlighted", async () => {
    const tiles = ORDER.map((c) => tile(c));
    tiles[0] = tile("mail_read", { qualifier: "1 folder synced", none_seen: false });
    load(account({ tiles }));
    render(<AccessSection account={A} />);
    const grid = await screen.findByRole("list", { name: "What the attacker reached" });
    expect(within(grid).getByRole("listitem", { name: "Emails read" })).toHaveClass("access-tile-hit");
  });

  it("an_export_notice_stays_with_its_account", async () => {
    const user = userEvent.setup();
    load(account({ items: [item({})] }));
    let resolve!: (p: string) => void;
    dialogSave.mockReturnValue(new Promise<string>((r) => (resolve = r)));
    const view = render(<AccessSection account={A} />);
    await user.click(await screen.findByRole("button", { name: "Export CSV" }));
    load(account({ account: "bob@contoso.example", items: [item({})] }));
    view.rerender(<AccessSection account="bob@contoso.example" />);
    resolve("/out/a.csv");
    await screen.findByRole("button", { name: "Export CSV" });
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("preview_toggle_shows_the_banner_and_labels", async () => {
    loadWithPreview();
    const user = userEvent.setup();
    render(<AccessSection account={A} />);
    await screen.findByRole("table", { name: "Emails read" });
    expect(screen.queryByText(/^PREVIEW/)).toBeNull();
    await user.click(screen.getByRole("checkbox", { name: "Include pending agent flags" }));
    expect(api.accessReport).toHaveBeenLastCalledWith(A, { include_pending: true, adhoc: [] });
    const banner = await screen.findByText(/^PREVIEW: includes pending agent flags; not the reviewed answer/);
    // Inside the section, so a screenshot of it carries the banner.
    expect(screen.getByRole("region", { name: "Access" })).toContainElement(banner);
    const rows = within(screen.getByRole("table", { name: "Emails read" })).getAllByRole("row");
    expect(rows[2]).toHaveTextContent("PENDING");
    expect(rows[3]).toHaveTextContent("WHAT-IF");
    expect(rows[1]).not.toHaveTextContent(/PENDING|WHAT-IF/);
    expect(screen.getByRole("listitem", { name: "Emails read" })).toHaveTextContent("1 pending");
    expect(screen.getByRole("listitem", { name: "Emails read" })).toHaveTextContent("1 what-if");
    expect(within(screen.getByRole("list", { name: "Scope" })).getByText(/WHAT-IF ip 198\.51\.100\.7/)).toBeInTheDocument();
    // A table seen on its own (scrolled past the banner) still says so in its heading.
    expect(screen.getByRole("heading", { name: /Emails read \(3\)/ })).toHaveTextContent("PREVIEW");
    // Off again: the reviewed answer, no banner.
    await user.click(screen.getByRole("checkbox", { name: "Include pending agent flags" }));
    expect(api.accessReport).toHaveBeenLastCalledWith(A, null);
    await screen.findByRole("table", { name: "Emails read" });
    expect(screen.queryByText(/^PREVIEW/)).toBeNull();
  });

  it("what_if_value_requests_the_preview", async () => {
    loadWithPreview();
    const user = userEvent.setup();
    render(<AccessSection account={A} />);
    await screen.findByRole("table", { name: "Emails read" });
    await user.selectOptions(screen.getByRole("combobox", { name: "What-if kind" }), "session");
    await user.type(screen.getByRole("textbox", { name: "What if" }), "4f1c8d3e-1111-4222-8333-444455559a2e{Enter}");
    expect(api.accessReport).toHaveBeenLastCalledWith(A, {
      include_pending: false,
      adhoc: [{ kind: "session", value: "4f1c8d3e-1111-4222-8333-444455559a2e" }],
    });
    expect(await screen.findByText(/^PREVIEW: includes what-if session 4f1c8d3e/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Clear what-if" }));
    expect(api.accessReport).toHaveBeenLastCalledWith(A, null);
  });

  it("preview_export_names_the_file_preview", async () => {
    loadWithPreview();
    dialogSave.mockResolvedValue("/out/p.csv");
    const user = userEvent.setup();
    render(<AccessSection account={A} />);
    await screen.findByRole("table", { name: "Emails read" });
    await user.click(screen.getByRole("checkbox", { name: "Include pending agent flags" }));
    await screen.findByText(/^PREVIEW/);
    await user.click(screen.getByRole("button", { name: "Export CSV" }));
    const opts = dialogSave.mock.calls[0][0] as { defaultPath: string };
    expect(opts.defaultPath).toMatch(new RegExp(`^access-${A}-PREVIEW-\\d{4}-\\d{2}-\\d{2}\\.csv$`));
    expect(api.exportAccessCsv).toHaveBeenCalledWith("/out/p.csv", A, { include_pending: true, adhoc: [] });
  });

  it("preview_is_off_when_the_tab_reopens", async () => {
    loadWithPreview();
    const user = userEvent.setup();
    const { unmount } = render(<AccessSection account={A} />);
    await screen.findByRole("table", { name: "Emails read" });
    await user.click(screen.getByRole("checkbox", { name: "Include pending agent flags" }));
    await screen.findByText(/^PREVIEW/);
    unmount();
    render(<AccessSection account={A} />);
    await screen.findByRole("table", { name: "Emails read" });
    expect(screen.getByRole("checkbox", { name: "Include pending agent flags" })).not.toBeChecked();
    expect(screen.queryByText(/^PREVIEW/)).toBeNull();
    expect(api.accessReport).toHaveBeenLastCalledWith(A, null);
  });

  it("shows_the_never_logged_gaps_from_the_report", async () => {
    load(account({ gaps: ["Copilot: no licence"] }));
    render(<AccessSection account={A} />);
    const coverage = await screen.findByRole("region", { name: "Coverage" });
    const lines = within(coverage).getAllByRole("listitem").map((l) => l.textContent);
    expect(lines).toEqual(["Copilot: no licence", NEVER[0]]);
  });
});
