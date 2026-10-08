import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { pivotIp as pivotFixture, pivotUser as pivotUserFixture } from "../test/fixtures";
import type { CmdError, Pivot as PivotData } from "../api";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  pivotIp: vi.fn(),
  pivotUser: vi.fn(),
}));

import * as api from "../api";
import Pivot from "./Pivot";

const m = { ip: vi.mocked(api.pivotIp), user: vi.mocked(api.pivotUser) };
let data: PivotData;
beforeEach(() => {
  m.ip.mockReset();
  m.user.mockReset();
  data = pivotFixture();
  m.ip.mockImplementation(async () => data);
  m.user.mockImplementation(async () => pivotUserFixture());
});

describe("Pivot", () => {
  it("runs the initial pivot and shows each section as a collapsible block with its rows", async () => {
    render(<Pivot initial={{ kind: "ip", value: "203.0.113.1" }} />);
    expect(m.ip).toHaveBeenCalledWith("203.0.113.1", 200);
    for (const s of data.sections) {
      expect(await screen.findByText(new RegExp(`^${s.name}`))).toBeInTheDocument();
    }
    const timeline = screen.getByText(/^timeline/).closest("details")!;
    expect(timeline).toHaveAttribute("open");
    const first = data.sections.find((x) => x.name === "timeline")!.rows[0] as { record_key: string };
    expect(within(timeline).getByText(first.record_key)).toBeInTheDocument();
    expect(within(timeline).getAllByText("Exchange MailItemsAccessed").length).toBeGreaterThan(0);
    // Columns come from the row objects' keys.
    expect(within(timeline).getByText("record_key")).toBeInTheDocument();
  });

  it("says when a section is truncated, with the full count, and raising the cap re-runs", async () => {
    const user = userEvent.setup();
    render(<Pivot initial={{ kind: "ip", value: "203.0.113.1" }} />);
    const timeline = (await screen.findByText(/^timeline/)).closest("details")!;
    expect(within(timeline).getByText(/showing 20 of 191/)).toBeInTheDocument();
    await user.click(within(timeline).getByRole("button", { name: "Raise the cap" }));
    expect(m.ip).toHaveBeenLastCalledWith("203.0.113.1", 1000);
  });

  it("does not offer a higher cap once at the maximum", async () => {
    const user = userEvent.setup();
    render(<Pivot initial={{ kind: "ip", value: "203.0.113.1" }} />);
    await user.click(await screen.findByRole("button", { name: "Raise the cap" }));
    await screen.findByText(/showing 20 of 191/);
    expect(screen.queryByRole("button", { name: "Raise the cap" })).toBeNull();
  });

  it("shows the reason instead of an empty grid for an unavailable section", async () => {
    // Only pivot_user's addresses section can be unavailable in core (enrichment state).
    const user = pivotUserFixture();
    const addresses = user.sections.find((x) => x.name === "addresses")!;
    addresses.unavailable = "the address enrichment is not current: run `sparrow detect`";
    addresses.rows = [];
    addresses.total = 0;
    m.user.mockImplementation(async () => user);
    render(<Pivot initial={{ kind: "account", value: "marlowe.rhodes@contoso.example" }} />);
    const section = (await screen.findByText(/^addresses/)).closest("details")!;
    expect(within(section).getByText(/address enrichment is not current/)).toBeInTheDocument();
    expect(within(section).queryByText("No rows.")).toBeNull();
    expect(within(section).queryByRole("table")).toBeNull();
  });

  it("clears the old result when a new request starts, and shows the new one when it resolves", async () => {
    let release!: (p: PivotData) => void;
    const user = userEvent.setup();
    render(<Pivot initial={{ kind: "ip", value: "192.0.2.2" }} />);
    await screen.findByText(/^timeline/);
    expect(screen.getByText(/^ip_intel/)).toBeInTheDocument();
    m.ip.mockImplementationOnce(() => new Promise<PivotData>((r) => (release = r)));
    await user.clear(screen.getByLabelText("Value"));
    await user.type(screen.getByLabelText("Value"), "198.51.100.7");
    await user.click(screen.getByRole("button", { name: "Pivot" }));
    // B is pending: A's sections are gone.
    expect(screen.queryByText(/^ip_intel/)).toBeNull();
    expect(screen.queryByText(/^timeline/)).toBeNull();
    await act(async () => {
      release({ sections: [{ name: "b_only", rows: [{ k: "b-row" }], total: 1, truncated: false }] });
    });
    expect(screen.getByText(/^b_only/)).toBeInTheDocument();
    expect(screen.getByText("b-row")).toBeInTheDocument();
    expect(screen.queryByText(/^ip_intel/)).toBeNull();
  });

  it("a section that is really empty says so", async () => {
    render(<Pivot initial={{ kind: "ip", value: "203.0.113.1" }} />);
    const spray = (await screen.findByText(/^spray_source/)).closest("details")!;
    expect(within(spray).getByText("No rows.")).toBeInTheDocument();
  });

  it("pivots an account from the form, with the chosen kind", async () => {
    const user = userEvent.setup();
    render(<Pivot />);
    expect(m.ip).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Pivot" })).toBeDisabled();
    await user.selectOptions(screen.getByLabelText("Pivot on"), "account");
    await user.type(screen.getByLabelText("Value"), "marlowe.rhodes@contoso.example");
    await user.click(screen.getByRole("button", { name: "Pivot" }));
    expect(m.user).toHaveBeenCalledExactlyOnceWith("marlowe.rhodes@contoso.example", 200);
    expect(await screen.findByText(/^timeline/)).toBeInTheDocument();
  });

  it("shows the backend's error for a bad input and no stale sections", async () => {
    m.ip.mockRejectedValue({ kind: "invalid", message: "not an IP address: nope" } satisfies CmdError);
    render(<Pivot initial={{ kind: "ip", value: "nope" }} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("not an IP address: nope");
    expect(screen.queryByText(/^timeline/)).toBeNull();
  });

  it("escapes the typed value and section names in what it echoes", async () => {
    data = { sections: [{ name: "x‮y", rows: [], total: 0, truncated: false }] };
    render(<Pivot initial={{ kind: "ip", value: "a‮b" }} />);
    expect(await screen.findByText(/^x\\u\{202E\}y/)).toBeInTheDocument();
    expect(screen.getByLabelText("Value")).toHaveValue("a‮b");
    expect(screen.getByText(/a\\u\{202E\}b/)).toBeInTheDocument();
  });

  it("ignores a slow earlier response that arrives after a later one", async () => {
    let release!: (p: PivotData) => void;
    m.ip.mockImplementationOnce(() => new Promise<PivotData>((r) => (release = r)));
    const user = userEvent.setup();
    render(<Pivot initial={{ kind: "ip", value: "203.0.113.1" }} />);
    await user.clear(screen.getByLabelText("Value"));
    await user.type(screen.getByLabelText("Value"), "198.51.100.7");
    await user.click(screen.getByRole("button", { name: "Pivot" }));
    await screen.findByText(/^timeline/);
    await act(async () => {
      release({ sections: [{ name: "stale_section", rows: [], total: 0, truncated: false }] });
    });
    expect(screen.queryByText(/^stale_section/)).toBeNull();
  });
});
