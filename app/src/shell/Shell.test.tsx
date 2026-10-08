import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { caseInfo } from "../test/fixtures";
import type { CmdError, Settings } from "../api";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  settingsGet: vi.fn(),
  settingsSetAnalyst: vi.fn(),
  caseOpen: vi.fn(),
  caseClose: vi.fn(),
}));
const dialogOpen = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: (...a: unknown[]) => dialogOpen(...a) }));
// The review screen has its own tests; here it only has to know whether writes are enabled.
vi.mock("../review/ReviewQueue", () => ({
  default: ({ canWrite }: { canWrite: boolean }) => <div>queue canWrite={String(canWrite)}</div>,
}));

import * as api from "../api";
import Shell from "./Shell";

const info = caseInfo();
const m = {
  settings: vi.mocked(api.settingsGet),
  setAnalyst: vi.mocked(api.settingsSetAnalyst),
  open: vi.mocked(api.caseOpen),
  close: vi.mocked(api.caseClose),
};
const withAnalyst: Settings = { analyst: "carlos", recent: ["/synthetic/case-a.duckdb", "/synthetic/old.duckdb"] };

beforeEach(() => {
  for (const f of Object.values(m)) f.mockReset();
  dialogOpen.mockReset();
  m.settings.mockResolvedValue(withAnalyst);
  m.open.mockResolvedValue(info);
  m.close.mockResolvedValue(null);
});

async function openViaDialog() {
  dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
  const user = userEvent.setup();
  render(<Shell />);
  await user.click(await screen.findByRole("button", { name: "Open a case" }));
  return user;
}

describe("Shell", () => {
  it("with no case shows Open and the recent list", async () => {
    render(<Shell />);
    expect(await screen.findByRole("button", { name: "Open a case" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "/synthetic/old.duckdb" })).toBeInTheDocument();
  });

  it("opens the chosen file through the dialog with a .duckdb filter", async () => {
    await openViaDialog();
    expect(dialogOpen).toHaveBeenCalledWith(
      expect.objectContaining({ filters: [{ name: "Sparrow case", extensions: ["duckdb"] }] }),
    );
    expect(m.open).toHaveBeenCalledWith("/synthetic/case-a.duckdb", false);
    expect(await screen.findByText("queue canWrite=true")).toBeInTheDocument();
  });

  it("a cancelled dialog opens nothing", async () => {
    dialogOpen.mockResolvedValue(null);
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    expect(dialogOpen).toHaveBeenCalled();
    expect(m.open).not.toHaveBeenCalled();
  });

  it("opens a recent case", async () => {
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "/synthetic/old.duckdb" }));
    expect(m.open).toHaveBeenCalledWith("/synthetic/old.duckdb", false);
  });

  it("asks for the analyst name before any write is enabled", async () => {
    m.settings.mockResolvedValue({ analyst: null, recent: [] });
    m.setAnalyst.mockResolvedValue({ analyst: "dana", recent: [] });
    const user = await openViaDialog();
    expect(await screen.findByText("queue canWrite=false")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Analyst name"), "dana");
    await user.click(screen.getByRole("button", { name: "Save name" }));
    expect(m.setAnalyst).toHaveBeenCalledWith("dana");
    expect(await screen.findByText("queue canWrite=true")).toBeInTheDocument();
    expect(screen.getByText("Analyst: dana")).toBeInTheDocument();
  });

  it("shows a rejected analyst name", async () => {
    m.settings.mockResolvedValue({ analyst: null, recent: [] });
    m.setAnalyst.mockRejectedValue({
      kind: "invalid",
      message: "an analyst name cannot contain ':'",
    } satisfies CmdError);
    const user = await openViaDialog();
    await user.type(await screen.findByLabelText("Analyst name"), "a:b");
    await user.click(screen.getByRole("button", { name: "Save name" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("an analyst name cannot contain ':'");
    expect(screen.getByText("queue canWrite=false")).toBeInTheDocument();
  });

  it("a read-only case shows the banner with the reason and disables writes", async () => {
    const reason = "the audit chain is broken at seq 3: hash mismatch; run sparrow audit verify --acknowledge";
    m.open.mockResolvedValue({ ...info, audit_ok: false, read_only_reason: reason });
    await openViaDialog();
    expect(await screen.findByRole("status")).toHaveTextContent(reason);
    expect(screen.getByText("queue canWrite=false")).toBeInTheDocument();
  });

  it("needs_upgrade asks first, and confirming reopens with allowUpgrade", async () => {
    m.open.mockRejectedValueOnce({
      kind: "needs_upgrade",
      message: "this case is schema 19; opening upgrades it to 21 in place",
    } satisfies CmdError);
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "/synthetic/old.duckdb" }));
    expect(await screen.findByText(/opening upgrades it to 21 in place/)).toBeInTheDocument();
    expect(m.open).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "Upgrade and open" }));
    expect(m.open).toHaveBeenLastCalledWith("/synthetic/old.duckdb", true);
    expect(await screen.findByText("queue canWrite=true")).toBeInTheDocument();
  });

  it("declining the upgrade leaves nothing open", async () => {
    m.open.mockRejectedValueOnce({ kind: "needs_upgrade", message: "upgrade?" } satisfies CmdError);
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "/synthetic/old.duckdb" }));
    await user.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(m.open).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("upgrade?")).toBeNull();
    expect(screen.getByRole("button", { name: "Open a case" })).toBeInTheDocument();
  });

  it("needs_acknowledge shows the message and offers no way to open", async () => {
    m.open.mockRejectedValue({
      kind: "needs_acknowledge",
      message: "the audit chain is broken and the schema is old; run sparrow audit verify --acknowledge first",
    } satisfies CmdError);
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "/synthetic/old.duckdb" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("run sparrow audit verify --acknowledge first");
    expect(screen.queryByRole("button", { name: "Upgrade and open" })).toBeNull();
    expect(m.open).toHaveBeenCalledTimes(1);
  });

  it("a busy case shows the writer_busy message", async () => {
    m.open.mockRejectedValue({ kind: "writer_busy", message: "case is open by another writer" } satisfies CmdError);
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "/synthetic/old.duckdb" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("case is open by another writer");
    expect(screen.getByRole("button", { name: "Open a case" })).toBeInTheDocument();
  });

  it("navigates: review queue, then placeholders for Timeline and Accounts", async () => {
    const user = await openViaDialog();
    await screen.findByText("queue canWrite=true");
    await user.click(screen.getByRole("button", { name: "Timeline" }));
    expect(screen.getByText("Timeline is not built yet.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Accounts" }));
    expect(screen.getByText("Accounts is not built yet.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review queue" }));
    expect(screen.getByText("queue canWrite=true")).toBeInTheDocument();
  });

  it("closing the case returns to the open screen", async () => {
    const user = await openViaDialog();
    await screen.findByText("queue canWrite=true");
    await user.click(screen.getByRole("button", { name: "Close case" }));
    await waitFor(() => expect(m.close).toHaveBeenCalled());
    expect(await screen.findByRole("button", { name: "Open a case" })).toBeInTheDocument();
  });
});
