import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { accounts as accountsFixture } from "../test/fixtures";
import type { AccountPage } from "../api";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  accountsList: vi.fn(),
}));

import * as api from "../api";
import Accounts from "./Accounts";

let page: AccountPage;
beforeEach(() => {
  page = accountsFixture();
  vi.mocked(api.accountsList).mockReset();
  vi.mocked(api.accountsList).mockImplementation(async () => page);
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
});
