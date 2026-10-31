// The way into Access tabs from an entity tab: an account's one-line summary and Open access, a device's or IP's what-if.
import { render, screen } from "@testing-library/react";
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
vi.mock("../dialog", () => ({ save: vi.fn(), open: vi.fn() }));

import { ORDER, tile } from "../access/testData";
import { NavContext, type Nav } from "../shell/nav";
import type { EntityRef } from "../shell/tabs";
import EntityTab from "./EntityTab";

const nav = (): Nav => ({ openEntity: vi.fn(), openTable: vi.fn(), showInEvents: vi.fn(), openFinding: vi.fn(), openAccess: vi.fn() });

function view(entity: EntityRef) {
  const n = nav();
  render(
    <NavContext.Provider value={n}>
      <EntityTab entity={entity} />
    </NavContext.Provider>,
  );
  return n;
}

const ACCOUNT: EntityRef = { kind: "account", value: "frances.rourke@contoso.example" };

beforeEach(() => {
  h.calls.length = 0;
  h.override = {};
});

describe("EntityTab Access entry points", () => {
  it("account_tab_has_a_summary_and_open_access", async () => {
    h.override.access_tiles = () => ORDER.map((c) => tile(c, c === "mail_read" ? { direct: 3 } : c === "file" ? { by_time: 2 } : {}));
    const n = view(ACCOUNT);
    expect(await screen.findByText("3 Emails read · 2 SharePoint / OneDrive")).toBeInTheDocument();
    // The reviewed tiles of this account only, never the whole report with its items.
    expect(h.calls.filter((c) => c.cmd === "access_tiles").at(-1)!.args).toEqual({ account: ACCOUNT.value });
    expect(h.calls.some((c) => c.cmd === "access_report")).toBe(false);
    expect(screen.queryByRole("list", { name: "What the attacker reached" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Open access" }));
    expect(n.openAccess).toHaveBeenCalledWith({ access: "account", value: ACCOUNT.value });
  });

  it("a_synced_only_account_is_not_nothing", async () => {
    h.override.access_tiles = () => ORDER.map((c) => tile(c, c === "mail_read" ? { qualifier: "1 folder synced", none_seen: false } : {}));
    view(ACCOUNT);
    expect(await screen.findByText("Emails read: 1 folder synced")).toBeInTheDocument();
    expect(screen.queryByText("Nothing attributed yet")).toBeNull();
  });

  it("an_account_with_nothing_says_so", async () => {
    h.override.access_tiles = () => ORDER.map((c) => tile(c));
    view(ACCOUNT);
    expect(await screen.findByText("Nothing attributed yet")).toBeInTheDocument();
  });

  it.each([
    ["ip", "192.0.2.19"],
    ["device", "7d5f6b6a-b999-43da-820e-ac7acb6ae7e7"],
  ] as const)("a_%s_tab_opens_a_what_if", async (kind, value) => {
    const n = view({ kind, value });
    await userEvent.click(await screen.findByRole("button", { name: "Access (what-if)" }));
    expect(n.openAccess).toHaveBeenCalledWith({ access: kind, value });
    // The what-if is computed when its tab opens, not here.
    expect(h.calls.some((c) => c.cmd === "access_report")).toBe(false);
  });

  it("a_session_tab_has_no_access_button", async () => {
    view({ kind: "session", value: "335fd402-004e-44c5-84f3-b052ee70de8c" });
    await screen.findByRole("button", { name: "Show in Events" });
    expect(screen.queryByRole("button", { name: "Access (what-if)" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Open access" })).toBeNull();
  });
});
