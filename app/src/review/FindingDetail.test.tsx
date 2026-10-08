import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { findingDetail as detailFixture } from "../test/fixtures";
import { NavContext } from "../shell/nav";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  findingDetail: vi.fn(),
}));

import * as api from "../api";
import FindingDetail from "./FindingDetail";

let detail: ReturnType<typeof detailFixture>;
beforeEach(() => {
  detail = detailFixture();
  vi.mocked(api.findingDetail).mockReset();
  vi.mocked(api.findingDetail).mockImplementation(async () => detail);
});

describe("FindingDetail pivot links", () => {
  it("offers a pivot on the finding's account inside a shell", async () => {
    const upn = detail.finding.actor_upn;
    expect(upn).toBeTruthy();
    const openPivot = vi.fn();
    render(
      <NavContext.Provider value={{ openPivot, openTable: vi.fn() }}>
        <FindingDetail findingId={detail.finding.finding_id} />
      </NavContext.Provider>,
    );
    await userEvent.setup().click(await screen.findByRole("button", { name: `Pivot on account ${upn}` }));
    expect(openPivot).toHaveBeenCalledExactlyOnceWith("account", upn);
  });

  it("offers none outside a shell, or for a finding without an account", async () => {
    render(<FindingDetail findingId={detail.finding.finding_id} />);
    await screen.findByText(/Evidence \(/);
    expect(screen.queryByRole("button", { name: /^Pivot on/ })).toBeNull();
  });

  it("offers none for a finding without an account", async () => {
    detail.finding.actor_upn = null;
    render(
      <NavContext.Provider value={{ openPivot: vi.fn(), openTable: vi.fn() }}>
        <FindingDetail findingId={detail.finding.finding_id} />
      </NavContext.Provider>,
    );
    await screen.findByText(/Evidence \(/);
    expect(screen.queryByRole("button", { name: /^Pivot on/ })).toBeNull();
  });
});
