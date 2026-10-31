// The Access tabs that can span accounts: a device or IP what-if, and the whole case.
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  accessReport: vi.fn(),
  exportAccessCsv: vi.fn(),
}));
const dialogSave = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({ save: (...a: unknown[]) => dialogSave(...a) }));

import * as api from "../api";
import { DataVersionContext } from "../shell/nav";
import AccessView from "./AccessView";
import { A, account, item, ORDER, report, tile } from "./testData";

const B = "bob@contoso.example";
const IP = "203.0.113.7";
const WHAT_IF = { include_pending: false, adhoc: [{ kind: "ip", value: IP }], without_accepted: true };
const DAY = /\d{4}-\d{2}-\d{2}/.source;

function two() {
  const a = account({ items: [item({ record_key: "a1", accessed: "2026-10-23T10:00:00Z" })], tiles: ORDER.map((c) => tile(c, c === "mail_read" ? { direct: 1, none_seen: false } : {})) });
  const b = account({
    account: B,
    items: [item({ account: B, record_key: "b1", item: "Bob's mail", accessed: "2026-10-23T11:00:00Z" })],
    tiles: ORDER.map((c) => tile(c, c === "mail_read" ? { direct: 4, none_seen: false } : {})),
  });
  vi.mocked(api.accessReport).mockResolvedValue(report([a, b]));
}

const mailTile = () => screen.getByRole("listitem", { name: "Emails read" });

beforeEach(() => {
  vi.mocked(api.accessReport).mockReset();
  vi.mocked(api.exportAccessCsv).mockReset().mockResolvedValue(null);
  dialogSave.mockReset();
});

describe("AccessView across accounts", () => {
  it("what_if_asks_for_its_value_alone", async () => {
    two();
    render(<AccessView scope={{ kind: "ip", value: IP }} />);
    await screen.findByRole("table", { name: "Emails read" });
    expect(api.accessReport).toHaveBeenCalledWith(null, WHAT_IF);
    expect(screen.getByRole("note")).toHaveTextContent(`WHAT-IF: what IP ${IP} would have reached if it were the attacker; not the reviewed report`);
    expect(screen.queryByRole("checkbox", { name: "Include pending agent flags" })).toBeNull();
    expect(screen.queryByRole("textbox", { name: "What if" })).toBeNull();
  });

  it("merged_tab_shows_an_account_column_and_filter", async () => {
    two();
    render(<AccessView scope={{ kind: "case" }} />);
    const table = await screen.findByRole("table", { name: "Emails read" });
    expect(api.accessReport).toHaveBeenCalledWith(null, null);
    expect(within(table).getByRole("columnheader", { name: "Account" })).toBeInTheDocument();
    const filter = screen.getByRole("combobox", { name: "Account" });
    expect(within(filter).getAllByRole("option").map((o) => o.textContent)).toEqual(["All accounts", A, B]);
    expect(mailTile()).toHaveTextContent("5");
  });

  it("an_account_tab_has_no_account_column", async () => {
    vi.mocked(api.accessReport).mockResolvedValue(report([account({ items: [item({})] })]));
    render(<AccessView scope={{ kind: "account", value: A }} />);
    const table = await screen.findByRole("table", { name: "Emails read" });
    expect(within(table).queryByRole("columnheader", { name: "Account" })).toBeNull();
    expect(screen.queryByRole("combobox", { name: "Account" })).toBeNull();
  });

  it("account_filter_narrows_without_refetching", async () => {
    const user = userEvent.setup();
    const many = Array.from({ length: 450 }, (_, n) => item({ account: B, record_key: `b${n}` }));
    const a = account({ items: [item({ record_key: "a1" })] });
    const b = account({ account: B, items: many, tiles: ORDER.map((c) => tile(c, c === "mail_read" ? { direct: 450, none_seen: false } : {})) });
    vi.mocked(api.accessReport).mockResolvedValue(report([a, b]));
    render(<AccessView scope={{ kind: "case" }} />);
    await screen.findByRole("table", { name: "Emails read" });
    await user.click(screen.getByRole("button", { name: /^Show 200 more/ }));
    const calls = vi.mocked(api.accessReport).mock.calls.length;
    await user.selectOptions(screen.getByRole("combobox", { name: "Account" }), B);
    expect(vi.mocked(api.accessReport).mock.calls.length).toBe(calls);
    const rows = within(screen.getByRole("table", { name: "Emails read" })).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(200);
    expect(rows.every((r) => r.textContent?.includes(B))).toBe(true);
    expect(mailTile()).toHaveTextContent("450");
    expect(screen.getByRole("button", { name: /^Show 200 more/ })).toHaveTextContent("250 hidden");
  });

  it("case_csv_name_and_scope", async () => {
    const user = userEvent.setup();
    two();
    dialogSave.mockResolvedValue("/out/case.csv");
    render(<AccessView scope={{ kind: "case" }} />);
    await screen.findByRole("table", { name: "Emails read" });
    await user.selectOptions(screen.getByRole("combobox", { name: "Account" }), B);
    await user.click(screen.getByRole("button", { name: "Export CSV" }));
    expect((dialogSave.mock.calls[0][0] as { defaultPath: string }).defaultPath).toMatch(new RegExp(`^access-case-${DAY}\\.csv$`));
    // The whole tab, never the filter.
    expect(api.exportAccessCsv).toHaveBeenCalledWith("/out/case.csv", null, null);
  });

  it("what_if_csv_name", async () => {
    const user = userEvent.setup();
    vi.mocked(api.accessReport).mockResolvedValue(report([account({ items: [item({ basis: "adhoc" })] })]));
    dialogSave.mockResolvedValue("/out/d.csv");
    render(<AccessView scope={{ kind: "device", value: "d-1" }} />);
    await screen.findByRole("table", { name: "Emails read" });
    await user.click(screen.getByRole("button", { name: "Export CSV" }));
    expect((dialogSave.mock.calls[0][0] as { defaultPath: string }).defaultPath).toMatch(new RegExp(`^access-device-d-1-WHATIF-${DAY}\\.csv$`));
    expect(api.exportAccessCsv).toHaveBeenCalledWith("/out/d.csv", null, { include_pending: false, adhoc: [{ kind: "device", value: "d-1" }], without_accepted: true });
  });

  it("coverage_disagreement_is_said", async () => {
    const missing = { status: "available_not_collected", reason: "Mailbox audit not collected", remediation: null };
    const a = account();
    const b = account({ account: B, tiles: ORDER.map((c) => tile(c, c === "mail_read" ? { none_seen: false, coverage: missing } : {})) });
    vi.mocked(api.accessReport).mockResolvedValue(report([a, b]));
    render(<AccessView scope={{ kind: "case" }} />);
    expect(await screen.findByRole("listitem", { name: "Emails read" })).toHaveTextContent("not collected for 1 of 2 accounts");
    expect(mailTile()).not.toHaveTextContent("none seen");
  });

  it("empty_what_if", async () => {
    vi.mocked(api.accessReport).mockResolvedValue(report([]));
    render(<AccessView scope={{ kind: "ip", value: IP }} />);
    expect(await screen.findByText(`Nothing found for IP ${IP}.`)).toBeInTheDocument();
  });

  it("empty_case", async () => {
    vi.mocked(api.accessReport).mockResolvedValue(report([]));
    render(<AccessView scope={{ kind: "case" }} />);
    expect(await screen.findByText("No malicious flags are accepted yet.")).toBeInTheDocument();
  });

  it("case_preview_keeps_the_controls", async () => {
    const user = userEvent.setup();
    two();
    render(<AccessView scope={{ kind: "case" }} />);
    await screen.findByRole("table", { name: "Emails read" });
    await user.click(screen.getByRole("checkbox", { name: "Include pending agent flags" }));
    expect(api.accessReport).toHaveBeenLastCalledWith(null, { include_pending: true, adhoc: [] });
  });

  it("a_data_change_hides_the_old_answer_until_the_new_one", async () => {
    two();
    const view = render(
      <DataVersionContext.Provider value={1}>
        <AccessView scope={{ kind: "case" }} />
      </DataVersionContext.Provider>,
    );
    await screen.findByRole("table", { name: "Emails read" });
    let resolve!: (r: ReturnType<typeof report>) => void;
    vi.mocked(api.accessReport).mockReturnValue(new Promise((r) => (resolve = r)));
    view.rerender(
      <DataVersionContext.Provider value={2}>
        <AccessView scope={{ kind: "case" }} />
      </DataVersionContext.Provider>,
    );
    expect(screen.queryByRole("table", { name: "Emails read" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Export CSV" })).toBeNull();
    expect(screen.getByText("Loading…")).toBeInTheDocument();
    await act(async () => resolve(report([account({ items: [item({ item: "Fresh" })] })])));
    expect(await screen.findByText("Fresh")).toBeInTheDocument();
  });

  it("a_filtered_account_that_disappears_resets_the_filter", async () => {
    const user = userEvent.setup();
    two();
    const tree = (v: number) => (
      <DataVersionContext.Provider value={v}>
        <AccessView scope={{ kind: "case" }} />
      </DataVersionContext.Provider>
    );
    const view = render(tree(1));
    await screen.findByRole("table", { name: "Emails read" });
    await user.selectOptions(screen.getByRole("combobox", { name: "Account" }), B);
    // B gone (its flag removed), then back: the filter does not silently come back with it.
    vi.mocked(api.accessReport).mockResolvedValue(report([account({ items: [item({})] }), account({ account: "c@contoso.example", items: [item({ account: "c@contoso.example", record_key: "c1" })] })]));
    view.rerender(tree(2));
    await screen.findByRole("table", { name: "Emails read" });
    two();
    view.rerender(tree(3));
    await screen.findByText("Bob's mail");
    expect(screen.getByRole("combobox", { name: "Account" })).toHaveValue("");
  });
});
