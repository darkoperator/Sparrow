import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { accounts as accountsFixture } from "../test/fixtures";
import { NavContext } from "../shell/nav";
import type { AccountPage } from "../api";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  accountsList: vi.fn(),
  accessAccounts: vi.fn(),
}));

import * as api from "../api";
import Accounts from "./Accounts";

let page: AccountPage;
beforeEach(() => {
  page = accountsFixture();
  vi.mocked(api.accountsList).mockReset();
  vi.mocked(api.accountsList).mockImplementation(async () => page);
  vi.mocked(api.accessAccounts).mockReset();
  vi.mocked(api.accessAccounts).mockResolvedValue([]);
});

describe("Accounts", () => {
  it("lists each account with its severity, stages and addresses", async () => {
    render(<Accounts onSelect={() => {}} />);
    const first = page.accounts[0];
    const row = (await screen.findByRole("button", { name: first.upn })).closest("tr")!;
    expect(within(row).getByText(first.worst_severity)).toBeInTheDocument();
    expect(first.addresses.length).toBeGreaterThan(0);
    expect(within(row).getByText(new RegExp(first.addresses[0].ip.replace(/\./g, "\\.")))).toBeInTheDocument();
    expect(screen.queryByLabelText("Warnings")).toBeNull();
  });

  it("shows each account's sign-in coverage, or that none were collected", async () => {
    const covered = { ...page.accounts[0], signins_first: "2026-08-01T07:00:00.000000Z", signins_last: "2026-08-25T18:30:00.000000Z" };
    const bare = { ...page.accounts[1], signins_first: null, signins_last: null };
    page = { ...page, accounts: [covered, bare] };
    render(<Accounts onSelect={() => {}} />);
    const row1 = (await screen.findByRole("button", { name: covered.upn })).closest("tr")!;
    expect(within(row1).getByText("sign-ins 2026-08-01 07:00:00 to 2026-08-25 18:30:00")).toBeInTheDocument();
    const row2 = screen.getByRole("button", { name: bare.upn }).closest("tr")!;
    expect(within(row2).getByText("no sign-ins collected")).toBeInTheDocument();
  });

  it("shows the warnings above an empty table, never an unexplained empty table", async () => {
    page = { accounts: [], total: 0, truncated: false, warnings: ["account roll-up unavailable: run `sparrow detect`"] };
    render(<Accounts onSelect={() => {}} />);
    const warnings = await screen.findByLabelText("Warnings");
    expect(within(warnings).getByText(/account roll-up unavailable/)).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByText("No accounts have findings.")).toBeNull();
  });

  it("clicking an account hands its UPN to the shell", async () => {
    const onSelect = vi.fn();
    const user = userEvent.setup();
    render(<Accounts onSelect={onSelect} />);
    await user.click(await screen.findByRole("button", { name: page.accounts[0].upn }));
    expect(onSelect).toHaveBeenCalledExactlyOnceWith(page.accounts[0].upn);
  });

  it("inside a shell, offers an entity tab per account and per address with the raw values", async () => {
    const openEntity = vi.fn();
    const user = userEvent.setup();
    render(
      <NavContext.Provider value={{ openEntity, openTable: vi.fn(), showInEvents: vi.fn(), openFinding: vi.fn(), openAccess: vi.fn() }}>
        <Accounts onSelect={() => {}} />
      </NavContext.Provider>,
    );
    const first = page.accounts[0];
    await user.click(await screen.findByRole("button", { name: `Open account tab ${first.upn}` }));
    expect(openEntity).toHaveBeenLastCalledWith({ kind: "account", value: first.upn });
    const row = screen.getByRole("button", { name: first.upn }).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: `Open IP tab ${first.addresses[0].ip}` }));
    expect(openEntity).toHaveBeenLastCalledWith({ kind: "ip", value: first.addresses[0].ip });
  });

  it("offers no entity-tab buttons outside a shell", async () => {
    render(<Accounts onSelect={() => {}} />);
    await screen.findByRole("button", { name: page.accounts[0].upn });
    expect(screen.queryByRole("button", { name: /^Open (account|IP) tab/ })).toBeNull();
  });

  it("badges_flagged_accounts", async () => {
    const [flagged, other] = page.accounts;
    vi.mocked(api.accessAccounts).mockResolvedValue([flagged.upn.toLowerCase()]);
    render(<Accounts onSelect={() => {}} />);
    const row1 = (await screen.findByRole("button", { name: flagged.upn })).closest("tr")!;
    expect(await within(row1).findByText("Malicious")).toHaveAttribute("title", "Accepted malicious flags tie activity to this account: see the Access section of its tab");
    const row2 = screen.getByRole("button", { name: other.upn }).closest("tr")!;
    expect(within(row2).queryByText("Malicious")).toBeNull();
  });

  it("lists the accounts even when the access accounts cannot be read", async () => {
    vi.mocked(api.accessAccounts).mockRejectedValue(new Error("no"));
    render(<Accounts onSelect={() => {}} />);
    expect(await screen.findByRole("button", { name: page.accounts[0].upn })).toBeInTheDocument();
  });
});
