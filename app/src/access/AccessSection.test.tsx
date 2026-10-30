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
const ORDER: AccessCategory[] = ["mail_read", "mail_sent", "attachment", "file", "teams", "copilot", "other"];

function tile(category: AccessCategory, over: Partial<AccessTile> = {}): AccessTile {
  return {
    category,
    direct: 0,
    by_time: 0,
    qualifier: null,
    coverage: { status: "collected", reason: "collected", remediation: null },
    none_seen: true,
    ...over,
  };
}

function item(over: Partial<AccessItem>): AccessItem {
  return {
    account: A, category: "mail_read", attribution: "ip", accessed: "2026-10-23T16:42:18Z", action: "read",
    item: "Q3 invoices", location: "\\Inbox", from: "ap@vendor.example", to: A, size_bytes: 10, item_time: null,
    app: null, ip: "203.0.113.45", session_id: null, owner: null, note: null, source: "ual_events:MailItemsAccessed",
    source_table: "ual_events", record_key: "r1", ...over,
  };
}

function account(over: Partial<AccessAccount> = {}): AccessAccount {
  return {
    account: A,
    tenant_key: "contoso",
    scope: [{ kind: "ip", value: "203.0.113.45", windows: [{ start: "2026-10-23T16:38:51Z", end: "2026-10-23T17:45:09Z" }] }],
    tiles: ORDER.map((c) => tile(c)),
    items: [],
    gaps: ["Teams chats read in the Teams app are not audited (only Graph reads are)"],
    ...over,
  };
}

function load(a: AccessAccount, pending = 0) {
  const r: AccessReport = { accounts: [a], pending_flags: pending };
  vi.mocked(api.accessReport).mockResolvedValue(r);
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
    expect(api.accessReport).toHaveBeenCalledWith(A);
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
    load(account({ tiles, gaps: ["Teams: UAL partial: Teams operations of this account may not have been collected", "Copilot: no licence", "Teams chats read in the Teams app are not audited (only Graph reads are)"] }));
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
    expect(api.exportAccessCsv).toHaveBeenCalledWith("/out/jdoe-access.csv", A);
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
});
