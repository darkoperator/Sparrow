import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { useState } from "react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { caseInfo } from "../test/fixtures";
import type { CmdError, EntityKind, Settings, TimelineEntry } from "../api";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  settingsGet: vi.fn(),
  settingsSetAnalyst: vi.fn(),
  caseOpen: vi.fn(),
  caseClose: vi.fn(),
  highlightsGet: vi.fn(async () => []),
  indicatorsActive: vi.fn(async () => []),
  reviewQueue: vi.fn(async () => []),
  timelineList: vi.fn(async () => []),
}));
const dialogOpen = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: (...a: unknown[]) => dialogOpen(...a) }));
// The review screen has its own tests; here it only has to know whether writes are enabled.
vi.mock("../review/ReviewQueue", () => ({
  default: ({
    canWrite,
    accountFilter,
    onClearFilter,
  }: {
    canWrite: boolean;
    accountFilter?: string | null;
    onClearFilter?: () => void;
  }) => (
    <div>
      queue canWrite={String(canWrite)}
      {accountFilter != null && <button onClick={onClearFilter}>{`filtered to ${accountFilter}`}</button>}
    </div>
  ),
}));
vi.mock("../tables/Tables", () => ({
  default: ({ initial }: { initial?: { table: string; filters: unknown[] } }) => (
    <div>{initial ? `tables ${initial.table} ${JSON.stringify(initial.filters)}` : "tables empty"}</div>
  ),
}));
vi.mock("../highlights/Highlights", () => ({ default: () => <div>highlights panel</div> }));
vi.mock("./ExportMenu", () => ({ default: () => <button>Export</button> }));

import * as api from "../api";
import Grid from "../grid/Grid";
import { useNav, useRefreshBadges } from "./nav";
import Shell from "./Shell";
import type { EntityRef } from "./tabs";

function Opener({ kind, value }: { kind: EntityKind; value: string }) {
  const nav = useNav();
  return <button onClick={() => nav?.openEntity({ kind, value })}>{`open ${value}`}</button>;
}

/** An entity tab with state of its own, to see that it survives the tab being hidden. */
function EntityBody({ e }: { e: EntityRef }) {
  const [text, setText] = useState("");
  return (
    <label>
      {`filter ${e.kind} ${e.value}`}
      <input value={text} onChange={(ev) => setText(ev.target.value)} />
    </label>
  );
}

const info = caseInfo();
const m = {
  settings: vi.mocked(api.settingsGet),
  setAnalyst: vi.mocked(api.settingsSetAnalyst),
  open: vi.mocked(api.caseOpen),
  close: vi.mocked(api.caseClose),
};
/** The case opens on the Events tab; most tests here are about the review queue. */
async function gotoReview(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("tab", { name: /^Review/ }));
  await screen.findByText(/queue canWrite=/);
}
const withAnalyst: Settings = { analyst: "carlos", recent: ["/synthetic/case-a.duckdb", "/synthetic/old.duckdb"] };

beforeEach(() => {
  try {
    localStorage.clear();
  } catch {
    // the storage-failure test replaces it; nothing to clear then
  }
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
  await gotoReview(user);
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
    await gotoReview(user);
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
    await user.click(screen.getByRole("tab", { name: "Timeline" }));
    expect(screen.getByText("Timeline is not built yet.")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Accounts" }));
    expect(screen.getByText("Accounts is not built yet.")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: /^Review/ }));
    expect(screen.getByText("queue canWrite=true")).toBeInTheDocument();
  });

  it("closing the case returns to the open screen", async () => {
    const user = await openViaDialog();
    await user.click(screen.getByRole("button", { name: "Close case" }));
    await waitFor(() => expect(m.close).toHaveBeenCalled());
    expect(await screen.findByRole("button", { name: "Open a case" })).toBeInTheDocument();
  });

  it("an account chosen on the accounts screen filters the review queue, and clearing lifts it", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    render(
      <Shell
        screens={{
          accounts: (p) => <button onClick={() => p.showAccount("marlowe.rhodes@contoso.example")}>pick account</button>,
        }}
      />,
    );
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await gotoReview(user);
    expect(screen.queryByRole("button", { name: /^filtered to/ })).toBeNull();
    await user.click(screen.getByRole("tab", { name: "Accounts" }));
    await user.click(screen.getByRole("button", { name: "pick account" }));
    // Back on the review queue, filtered.
    const chip = await screen.findByRole("button", { name: "filtered to marlowe.rhodes@contoso.example" });
    await user.click(chip);
    expect(screen.queryByRole("button", { name: /^filtered to/ })).toBeNull();
  });

  it("SQL and Share are in the sidebar; Share's queue link returns to the review queue", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    render(
      <Shell
        screens={{
          sql: () => <p>sql screen</p>,
          share: (p) => <button onClick={p.showQueue}>{`share canWrite=${String(p.canWrite)}`}</button>,
        }}
      />,
    );
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(screen.getByRole("tab", { name: "SQL" }));
    expect(screen.getByText("sql screen")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Share" }));
    await user.click(screen.getByRole("button", { name: "share canWrite=true" }));
    expect(screen.getByText("queue canWrite=true")).toBeInTheDocument();
  });

  it("offers the export menu while a case is open", async () => {
    expect(await (async () => {
      await openViaDialog();
      return screen.findByRole("button", { name: "Export" });
    })()).toBeInTheDocument();
  });

  it("opens on the Events tab and lists the fixed tabs in order", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    const tabs = await screen.findAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual([
      "Events",
      "Review",
      "Timeline",
      "Accounts",
      "Devices",
      "Tables",
      "SQL",
      "Highlights",
      "Share",
    ]);
    expect(screen.getByRole("tab", { name: "Events" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("Events is not built yet.")).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Screens" })).toBeNull();
  });

  it("badges the Review tab with the queue length and the Timeline tab with proposed entries", async () => {
    vi.mocked(api.reviewQueue).mockResolvedValue([{}, {}, {}] as never);
    const entry = (review_state: TimelineEntry["review_state"]) => ({ review_state }) as TimelineEntry;
    vi.mocked(api.timelineList).mockResolvedValue([
      entry("pending_review"),
      entry("accepted"),
      entry("pending_review"),
      entry("discarded"),
    ]);
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    expect(await screen.findByRole("tab", { name: "Review, 3 pending" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Timeline, 2 proposed" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Accounts" })).toBeInTheDocument();
  });

  it("a screen's refresh call re-reads the badges without a tab switch", async () => {
    const queue = vi.mocked(api.reviewQueue);
    queue.mockResolvedValue([{}, {}] as never);
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    function Writer() {
      const refresh = useRefreshBadges();
      return <button onClick={refresh}>wrote</button>;
    }
    render(<Shell screens={{ accounts: () => <Writer /> }} />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(await screen.findByRole("tab", { name: "Accounts" }));
    expect(await screen.findByRole("tab", { name: "Review, 2 pending" })).toBeInTheDocument();
    queue.mockResolvedValue([{}, {}, {}, {}, {}] as never);
    await user.click(screen.getByRole("button", { name: "wrote" }));
    expect(await screen.findByRole("tab", { name: "Review, 5 pending" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Accounts" })).toHaveAttribute("aria-selected", "true");
    queue.mockResolvedValue([]);
  });

  it("a cell menu on an entra_session_id cell offers Open session tab, and choosing it opens that tab", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    const sid = "4F1C0000-1111-2222-3333-44449A2E5555";
    render(
      <Shell
        screens={{
          accounts: () => (
            <Grid columns={["entra_session_id", "note"]} rows={[[sid, "plain"]]} />
          ),
        }}
      />,
    );
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(await screen.findByRole("tab", { name: "Accounts" }));
    fireEvent.contextMenu(screen.getByText(sid));
    await user.click(within(screen.getByRole("menu")).getByRole("menuitem", { name: "Open session tab" }));
    const tab = await screen.findByRole("tab", { name: `session ${sid.toLowerCase()}` });
    expect(tab).toHaveAttribute("aria-selected", "true");
    expect(tab).toHaveTextContent("4f1c…5555");
  });

  it("opening an entity from a screen's context or props adds one tab per canonical value and selects it", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    render(
      <Shell
        screens={{
          accounts: (p) => (
            <>
              <Opener kind="ip" value="2001:DB8::1" />
              <button onClick={() => p.openEntity({ kind: "ip", value: "2001:db8::1" })}>via props</button>
            </>
          ),
        }}
      />,
    );
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(await screen.findByRole("tab", { name: "Accounts" }));
    await user.click(screen.getByRole("button", { name: "open 2001:DB8::1" }));
    expect(screen.getByRole("tab", { name: "IP 2001:db8::1" })).toHaveAttribute("aria-selected", "true");
    await user.click(screen.getByRole("tab", { name: "Accounts" }));
    await user.click(screen.getByRole("button", { name: "via props" }));
    expect(screen.getAllByRole("tab", { name: /^IP / })).toHaveLength(1);
    expect(screen.getByRole("tab", { name: "IP 2001:db8::1" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("region", { name: "ip 2001:db8::1" })).toHaveTextContent("ip 2001:db8::1");
  });

  it("an open entity tab keeps its typed filter text when switching away and back", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    render(
      <Shell
        screens={{ accounts: () => <Opener kind="account" value="JDoe@Contoso.example" /> }}
        entityTab={(e) => <EntityBody e={e} />}
      />,
    );
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(await screen.findByRole("tab", { name: "Accounts" }));
    await user.click(screen.getByRole("button", { name: "open JDoe@Contoso.example" }));
    await user.type(screen.getByLabelText("filter account jdoe@contoso.example"), "mfa*");
    await user.click(screen.getByRole("tab", { name: "Events" }));
    // Hidden, not unmounted.
    expect(screen.getByLabelText("filter account jdoe@contoso.example")).not.toBeVisible();
    expect(screen.getByLabelText("filter account jdoe@contoso.example", { selector: "input" })).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "account jdoe@contoso.example" }));
    expect(screen.getByLabelText("filter account jdoe@contoso.example")).toHaveValue("mfa*");
  });

  it("closes an entity tab with ×, a middle-click and Delete or Backspace, and goes back to the previous tab", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    function Many() {
      const nav = useNav();
      return (
        <>
          {["a", "b", "c", "d"].map((n) => (
            <button key={n} onClick={() => nav?.openEntity({ kind: "account", value: `${n}@contoso.example` })}>
              {`open ${n}`}
            </button>
          ))}
        </>
      );
    }
    render(<Shell screens={{ accounts: () => <Many /> }} />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(await screen.findByRole("tab", { name: "Accounts" }));
    for (const n of ["a", "b", "c", "d"]) {
      await user.click(screen.getByRole("button", { name: `open ${n}` }));
      await user.click(screen.getByRole("tab", { name: "Accounts" }));
    }
    await user.click(screen.getByRole("tab", { name: "account c@contoso.example" }));
    await user.click(screen.getByRole("tab", { name: "account d@contoso.example" }));
    const entityTabs = () => screen.queryAllByRole("tab", { name: /^account / }).map((t) => t.getAttribute("aria-label"));
    expect(entityTabs()).toEqual([
      "account a@contoso.example",
      "account b@contoso.example",
      "account c@contoso.example",
      "account d@contoso.example",
    ]);
    // ×: d is showing; closing it returns to c, which was viewed before.
    await user.click(screen.getByRole("button", { name: "Close account d@contoso.example" }));
    expect(screen.getByRole("tab", { name: "account c@contoso.example" })).toHaveAttribute("aria-selected", "true");
    // Middle-click on c.
    fireEvent(
      screen.getByRole("tab", { name: "account c@contoso.example" }),
      new MouseEvent("auxclick", { bubbles: true, cancelable: true, button: 1 }),
    );
    expect(screen.queryByRole("tab", { name: "account c@contoso.example" })).toBeNull();
    expect(screen.getByRole("tab", { name: "Accounts" })).toHaveAttribute("aria-selected", "true");
    await user.click(screen.getByRole("tab", { name: "account b@contoso.example" }));
    // Delete on the focused tab b, then Backspace on a.
    screen.getByRole("tab", { name: "account b@contoso.example" }).focus();
    await user.keyboard("{Delete}");
    expect(entityTabs()).toEqual(["account a@contoso.example"]);
    expect(screen.getByRole("tab", { name: "Accounts" })).toHaveAttribute("aria-selected", "true");
    await user.click(screen.getByRole("tab", { name: "account a@contoso.example" }));
    screen.getByRole("tab", { name: "account a@contoso.example" }).focus();
    await user.keyboard("{Backspace}");
    expect(entityTabs()).toEqual([]);
    expect(screen.getByRole("tab", { name: "Accounts" })).toHaveAttribute("aria-selected", "true");
    // A fixed tab ignores Delete.
    screen.getByRole("tab", { name: "Accounts" }).focus();
    await user.keyboard("{Delete}");
    expect(screen.getByRole("tab", { name: "Accounts" })).toBeInTheDocument();
  });

  it("an eleventh tab closes the least recently viewed and says so", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    function Eleven() {
      const nav = useNav();
      return (
        <>
          {Array.from({ length: 11 }, (_, i) => (
            <button key={i} onClick={() => nav?.openEntity({ kind: "account", value: `u${i}@contoso.example` })}>
              {`open u${i}`}
            </button>
          ))}
        </>
      );
    }
    render(<Shell screens={{ accounts: () => <Eleven /> }} />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(await screen.findByRole("tab", { name: "Accounts" }));
    for (let i = 0; i < 10; i++) {
      await user.click(screen.getByRole("button", { name: `open u${i}` }));
      await user.click(screen.getByRole("tab", { name: "Accounts" }));
    }
    expect(screen.queryByText(/10 tabs max/)).toBeNull();
    // Look at u0 again, so u1 is now the least recently viewed.
    await user.click(screen.getByRole("tab", { name: "account u0@contoso.example" }));
    await user.click(screen.getByRole("tab", { name: "Accounts" }));
    await user.click(screen.getByRole("button", { name: "open u10" }));
    expect(screen.getByRole("status")).toHaveTextContent("Closed u1@contoso.example (10 tabs max)");
    expect(screen.queryByRole("tab", { name: "account u1@contoso.example" })).toBeNull();
    expect(screen.getByRole("tab", { name: "account u0@contoso.example" })).toBeInTheDocument();
    expect(screen.getAllByRole("tab", { name: /^account / })).toHaveLength(10);
  });

  it("remembers the open tabs and the active entity tab per case, and does not leak them into another case", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    const screens = { accounts: () => <Opener kind="ip" value="203.0.113.9" /> };
    const first = render(<Shell screens={screens} />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(await screen.findByRole("tab", { name: "Accounts" }));
    await user.click(screen.getByRole("button", { name: "open 203.0.113.9" }));
    first.unmount();

    // A new window on the same case reopens on the entity tab that was showing.
    render(<Shell screens={screens} />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    expect(await screen.findByRole("tab", { name: "IP 203.0.113.9" })).toHaveAttribute("aria-selected", "true");

    // Another case starts clean.
    m.open.mockResolvedValue({ ...info, case_id: "another-case" });
    await user.click(screen.getByRole("button", { name: "Close case" }));
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await screen.findByRole("tab", { name: "Events" });
    expect(screen.queryByRole("tab", { name: "IP 203.0.113.9" })).toBeNull();
    expect(screen.getByRole("tab", { name: "Events" })).toHaveAttribute("aria-selected", "true");
  });

  it("reopens a case on the fixed tab that was showing, and on Events if the saved id is unknown", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    const first = render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(await screen.findByRole("tab", { name: "Tables" }));
    expect(screen.getByText("tables empty")).toBeInTheDocument();
    first.unmount();

    const second = render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    expect(await screen.findByRole("tab", { name: "Tables" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("tables empty")).toBeInTheDocument();
    second.unmount();

    const key = `sparrow.tabs.v1.${info.case_id}`;
    localStorage.setItem(key, JSON.stringify({ open: [], active: "no-such-tab", viewed: [] }));
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    expect(await screen.findByRole("tab", { name: "Events" })).toHaveAttribute("aria-selected", "true");
  });

  it("shows hostile entity values as text in the tab and in the eviction toast", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    const hostile = (n: number) => `<img src=x onerror=alert(${n})>\u0007\u202e\u200b@contoso.example`;
    const escaped = (n: number) => `<img src=x onerror=alert(${n})>\\u{0007}\\u{202E}\\u{200B}@contoso.example`;
    function Hostile() {
      const nav = useNav();
      return (
        <>
          {Array.from({ length: 11 }, (_, i) => (
            <button key={i} onClick={() => nav?.openEntity({ kind: "account", value: hostile(i) })}>{`open ${i}`}</button>
          ))}
        </>
      );
    }
    render(<Shell screens={{ accounts: () => <Hostile /> }} />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(await screen.findByRole("tab", { name: "Accounts" }));
    for (let i = 0; i < 11; i++) {
      await user.click(screen.getByRole("button", { name: `open ${i}` }));
      await user.click(screen.getByRole("tab", { name: "Accounts" }));
    }
    // The 11th closed the first; its toast shows the escaped value, as text.
    const toast = screen.getByRole("status");
    expect(toast.textContent).toBe(`Closed ${escaped(0)} (10 tabs max)`);
    expect(toast.querySelector("img")).toBeNull();
    // The tab: label and title are escaped text, no element came out of the value.
    const tab = screen.getByRole("tab", { name: `account ${escaped(1)}` });
    expect(tab).toHaveAttribute("title", `account ${escaped(1)}`);
    expect(tab.textContent).not.toMatch(/[\u0007\u202e\u200b]/);
    expect(tab.querySelector("img")).toBeNull();
    expect(document.querySelector("img")).toBeNull();
    const body = document.querySelector("section");
    expect(body).toHaveAttribute("aria-label", `account ${escaped(1)}`);
    expect(body?.textContent).toBe(`account ${escaped(1)}`);
  });

  it("works with storage that throws, starting on Events", async () => {
    const boom = () => {
      throw new Error("blocked");
    };
    vi.stubGlobal("localStorage", { getItem: boom, setItem: boom, removeItem: boom });
    try {
      dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
      const user = userEvent.setup();
      render(<Shell screens={{ accounts: () => <Opener kind="ip" value="203.0.113.9" /> }} />);
      await user.click(await screen.findByRole("button", { name: "Open a case" }));
      expect(await screen.findByRole("tab", { name: "Events" })).toHaveAttribute("aria-selected", "true");
      await user.click(screen.getByRole("tab", { name: "Accounts" }));
      await user.click(screen.getByRole("button", { name: "open 203.0.113.9" }));
      expect(screen.getByRole("tab", { name: "IP 203.0.113.9" })).toHaveAttribute("aria-selected", "true");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("showInEvents switches to the Events tab and hands it the entity", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    render(
      <Shell
        screens={{
          events: (p) => <p>{p.eventsEntity ? `events limited to ${p.eventsEntity.kind} ${p.eventsEntity.value}` : "events all"}</p>,
          accounts: (p) => (
            <button onClick={() => p.showInEvents({ kind: "ip", value: "203.0.113.9" })}>show in events</button>
          ),
        }}
      />,
    );
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    expect(await screen.findByText("events all")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Accounts" }));
    await user.click(screen.getByRole("button", { name: "show in events" }));
    expect(screen.getByText("events limited to ip 203.0.113.9")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Events" })).toHaveAttribute("aria-selected", "true");
  });

  it("openTable (from the context and from props) switches to the tables screen with the table and filters", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    const f = [{ op: "eq", column: "ip", value: "203.0.113.1" }];
    function TableOpener() {
      const nav = useNav();
      return <button onClick={() => nav?.openTable("signins", f as never)}>open signins</button>;
    }
    render(
      <Shell
        screens={{
          accounts: (p) => (
            <>
              <TableOpener />
              <button onClick={() => p.openTable("ual_events", [])}>via props</button>
            </>
          ),
        }}
      />,
    );
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await gotoReview(user);
    await user.click(screen.getByRole("tab", { name: "Accounts" }));
    await user.click(screen.getByRole("button", { name: "open signins" }));
    expect(screen.getByText(`tables signins ${JSON.stringify(f)}`)).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Tables" })).toHaveAttribute("aria-selected", "true");
    await user.click(screen.getByRole("tab", { name: "Accounts" }));
    await user.click(screen.getByRole("button", { name: "via props" }));
    expect(screen.getByText("tables ual_events []")).toBeInTheDocument();
  });

  it("the Tables and Highlights entries open their screens", async () => {
    const user = await openViaDialog();
    await user.click(screen.getByRole("tab", { name: "Tables" }));
    expect(screen.getByText("tables empty")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Highlights" }));
    expect(screen.getByText("highlights panel")).toBeInTheDocument();
  });
});
