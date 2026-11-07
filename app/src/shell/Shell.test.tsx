import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { useEffect, useState } from "react";
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
  ingestDiscover: vi.fn(),
  ingestRun: vi.fn(),
  ingestCancel: vi.fn(),
  onIngestProgress: vi.fn(async () => () => {}),
  onIngestClosing: vi.fn(async () => () => {}),
  ingestUnprofiled: vi.fn(async () => []),
  caseCollectionStatus: vi.fn(async () => null),
  ingestProfile: vi.fn(),
  onCaseChanged: vi.fn(async () => () => {}),
  onAgentActivity: vi.fn(async () => () => {}),
}));
const dialogOpen = vi.fn();
const dialogSave = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: (...a: unknown[]) => dialogOpen(...a),
  save: (...a: unknown[]) => dialogSave(...a),
}));
// The review screen has its own tests; here it only has to know whether writes are enabled.
vi.mock("../review/ReviewQueue", () => ({
  default: ({
    canWrite,
    accountFilter,
    onClearFilter,
    focusFinding,
  }: {
    canWrite: boolean;
    accountFilter?: string | null;
    onClearFilter?: () => void;
    focusFinding?: { id: string; nonce: number } | null;
  }) => (
    <div>
      queue canWrite={String(canWrite)}
      {focusFinding && <span>{`queue focus ${focusFinding.id} #${focusFinding.nonce}`}</span>}
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
import { useFocusAnalyst, useNav, useOnDataChanged, useRefreshBadges, useWriteBlocked, useWriteTick, writeBlockedReason } from "./nav";
import Shell from "./Shell";
import type { EntityRef } from "./tabs";

function Opener({ kind, value }: { kind: EntityKind; value: string }) {
  const nav = useNav();
  return <button onClick={() => nav?.openEntity({ kind, value })}>{`open ${value}`}</button>;
}

function Finder() {
  const nav = useNav();
  return (
    <>
      {["f-1", "f-2"].map((id) => (
        <button key={id} onClick={() => nav?.openFinding(id)}>{`open finding ${id}`}</button>
      ))}
    </>
  );
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
  dialogSave.mockReset();
  vi.mocked(api.ingestDiscover).mockReset();
  vi.mocked(api.ingestRun).mockReset();
  vi.mocked(api.ingestProfile).mockReset();
  vi.mocked(api.ingestUnprofiled).mockReset().mockResolvedValue([]);
  vi.mocked(api.caseCollectionStatus).mockReset().mockResolvedValue(null);
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
    expect(screen.getByTitle("dana")).toBeInTheDocument();
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

  it("an_analyst_write_bumps_the_write_tick", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    function Writes() {
      const refresh = useRefreshBadges();
      const tick = useWriteTick();
      return <button onClick={refresh}>{`tick ${tick}`}</button>;
    }
    render(<Shell screens={{ accounts: () => <Writes /> }} />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(await screen.findByRole("tab", { name: "Accounts" }));
    const before = Number(screen.getByRole("button", { name: /^tick / }).textContent!.slice(5));
    await user.click(screen.getByRole("button", { name: /^tick / }));
    expect(screen.getByRole("button", { name: `tick ${before + 1}` })).toBeInTheDocument();
  });

  it("nav_open_access_shows_the_tab", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    function AccessOpener() {
      const nav = useNav();
      return (
        <>
          <button onClick={() => nav?.openAccess({ access: "case", value: "" })}>open case access</button>
          <button onClick={() => nav?.openAccess({ access: "ip", value: "203.0.113.7" })}>open ip access</button>
        </>
      );
    }
    render(
      <Shell
        screens={{ accounts: () => <AccessOpener /> }}
        accessTab={(a) => <p>{`access body ${a.access} ${a.value}`}</p>}
      />,
    );
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(await screen.findByRole("tab", { name: "Accounts" }));
    await user.click(screen.getByRole("button", { name: "open case access" }));
    const tab = screen.getByRole("tab", { name: "Access whole case" });
    expect(tab).toHaveAttribute("aria-selected", "true");
    expect(tab).toHaveTextContent("Access · case");
    expect(screen.getByText("access body case")).toBeVisible();
    await user.click(screen.getByRole("tab", { name: "Accounts" }));
    await user.click(screen.getByRole("button", { name: "open ip access" }));
    expect(screen.getByRole("tab", { name: "Access IP 203.0.113.7 (what-if)" })).toHaveTextContent("Access · 203.0.113.7 (what-if)");
    expect(screen.getByText("access body ip 203.0.113.7")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Close Access whole case" }));
    expect(screen.queryByRole("tab", { name: "Access whole case" })).toBeNull();
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

  it("the Events screen stays mounted while another tab shows, so its typed filter survives", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    let mounts = 0;
    function EventsBody() {
      const [text, setText] = useState("");
      useState(() => mounts++);
      return (
        <label>
          events filter
          <input value={text} onChange={(e) => setText(e.target.value)} />
        </label>
      );
    }
    render(<Shell screens={{ events: () => <EventsBody /> }} />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.type(await screen.findByLabelText("events filter"), "wren*");
    await user.click(screen.getByRole("tab", { name: /^Review/ }));
    await screen.findByText(/queue canWrite=/);
    expect(screen.getByLabelText("events filter", { selector: "input" })).not.toBeVisible();
    await user.click(screen.getByRole("tab", { name: "Events" }));
    expect(screen.getByLabelText("events filter")).toHaveValue("wren*");
    expect(screen.getByLabelText("events filter")).toBeVisible();
    expect(mounts).toBe(1);
  });

  it("openFinding switches to Review and hands it the finding, clearing an account filter", async () => {
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    render(
      <Shell
        screens={{
          events: () => <Finder />,
        }}
      />,
    );
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(await screen.findByRole("button", { name: "open finding f-1" }));
    expect(await screen.findByText("queue focus f-1 #1")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /^Review/ })).toHaveAttribute("aria-selected", "true");
    await user.click(screen.getByRole("tab", { name: "Events" }));
    await user.click(screen.getByRole("button", { name: "open finding f-2" }));
    expect(await screen.findByText("queue focus f-2 #2")).toBeInTheDocument();
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

  it("a_blocked_menu_item_sends_the_analyst_to_the_name_prompt_only_when_the_name_is_the_reason", async () => {
    const Probe = () => {
      const focus = useFocusAnalyst();
      return <button onClick={() => focus?.()}>{`focus: ${focus ? "yes" : "none"}`}</button>;
    };
    const screens = { events: () => <Probe /> };
    const open = async () => {
      dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
      render(<Shell screens={screens} />);
      await userEvent.setup().click(await screen.findByRole("button", { name: "Open a case" }));
    };
    // No analyst: the callback moves the focus to the prompt's input and flashes it.
    m.settings.mockResolvedValue({ analyst: null, recent: [] });
    await open();
    await userEvent.setup().click(await screen.findByRole("button", { name: "focus: yes" }));
    const input = screen.getByLabelText("Analyst name");
    expect(input).toHaveFocus();
    expect(input).toHaveClass("analyst-flash");
    cleanup();
    // A read-only case: typing a name would not help, so there is no callback.
    m.settings.mockResolvedValue(withAnalyst);
    m.open.mockResolvedValue({ ...info, audit_ok: false, read_only_reason: "the audit chain is broken at seq 3" });
    await open();
    expect(await screen.findByRole("button", { name: "focus: none" })).toBeInTheDocument();
  });

  it("the_shell_tells_every_screen_why_writes_are_off", async () => {
    const Probe = () => <p>{`blocked: ${String(useWriteBlocked())}`}</p>;
    const screens = { events: () => <Probe /> };
    const open = async () => {
      dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
      render(<Shell screens={screens} />);
      await userEvent.setup().click(await screen.findByRole("button", { name: "Open a case" }));
    };
    // Writable.
    await open();
    expect(await screen.findByText("blocked: null")).toBeInTheDocument();
    cleanup();
    // A read-only case: the case's own reason.
    m.open.mockResolvedValue({ ...info, audit_ok: false, read_only_reason: "the audit chain is broken at seq 3" });
    await open();
    expect(await screen.findByText("blocked: Read-only case: the audit chain is broken at seq 3")).toBeInTheDocument();
    cleanup();
    // No analyst name: that, and nothing about a read-only case.
    m.open.mockResolvedValue(info);
    m.settings.mockResolvedValue({ analyst: null, recent: [] });
    await open();
    expect(await screen.findByText("blocked: The analyst name is not set: enter it to make changes")).toBeInTheDocument();
    cleanup();
    // Both: the case's reason wins, since entering a name would not help.
    expect(writeBlockedReason("old schema", null)).toBe("Read-only case: old schema");
    expect(writeBlockedReason(null, null)).toBe("The analyst name is not set: enter it to make changes");
    expect(writeBlockedReason(null, "dana")).toBeNull();
  });
});

describe("Shell import", () => {
  const preview: api.DiscoveryPreview = {
    path: "/evidence/run-1",
    collections: [
      {
        tool: "invictus",
        root: "/evidence/run-1",
        tenant_hint: null,
        started_hint: null,
        files: [{ rel_path: "SignInLogs.csv", artifact_id: "invictus.signins", derived: false, size: 10, status: "recognised", too_large: false, error: null }],
      },
    ],
    recognised: 1,
    unrecognised: 0,
    too_large: 0,
    unreadable: 0,
    xlsx_max_bytes: 1_073_741_824,
  };
  const result = (case_path: string): api.IngestResult => ({
    case_path,
    cancelled: false,
    error: null,
    report: { collections: [] },
    files_loaded: 1,
    files_total: 1,
    rows_by_source: [{ source: "invictus.signins", files: 1, rows: 10 }],
    file_notes: [],
    not_loaded: [],
    profile_error: null,
    profile_warnings: [],
    detect: { findings_new: 0, findings_updated: 0, warnings: [] },
    detect_error: null,
    incomplete_collection: null,
  });

  it("a new case from a folder opens the case it made", async () => {
    vi.mocked(api.ingestDiscover).mockResolvedValue(preview);
    vi.mocked(api.ingestRun).mockResolvedValue(result("/cases/made.duckdb"));
    dialogOpen.mockResolvedValue("/evidence/run-1");
    dialogSave.mockResolvedValue("/cases/made.duckdb");
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "New case from a folder…" }));
    const dialog = await screen.findByRole("dialog", { name: "New case from a folder" });
    await user.click(within(dialog).getByRole("button", { name: /^Choose a folder/ }));
    await within(dialog).findByRole("region", { name: "Discovery" });
    await user.click(within(dialog).getByRole("button", { name: "Choose where to save…" }));
    await user.click(within(dialog).getByRole("button", { name: "Create the case and import" }));
    expect(api.ingestRun).toHaveBeenCalledWith("/evidence/run-1", { new_case: "/cases/made.duckdb" }, null, true, expect.any(String));
    expect(m.open).not.toHaveBeenCalled();
    await user.click(await within(dialog).findByRole("button", { name: "Open the new case" }));
    expect(m.open).toHaveBeenCalledWith("/cases/made.duckdb", false);
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(await screen.findByRole("button", { name: "Import data…" })).toBeInTheDocument();
  });

  it("closing the new-case dialog without importing opens nothing", async () => {
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "New case from a folder…" }));
    await user.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(m.open).not.toHaveBeenCalled();
  });

  it("importing into the open case reloads the case and every screen when the dialog closes", async () => {
    vi.mocked(api.ingestDiscover).mockResolvedValue(preview);
    vi.mocked(api.ingestRun).mockResolvedValue(result("/synthetic/case-a.duckdb"));
    const mounts = vi.fn();
    function Probe() {
      useEffect(() => mounts(), []);
      return <p>events probe</p>;
    }
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    render(<Shell screens={{ events: () => <Probe /> }} />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await screen.findByText("events probe");
    expect(m.open).toHaveBeenCalledTimes(1);
    expect(mounts).toHaveBeenCalledTimes(1);
    const queueCalls = vi.mocked(api.reviewQueue).mock.calls.length;
    dialogOpen.mockResolvedValue("/evidence/run-1");
    await user.click(screen.getByRole("button", { name: "Import data…" }));
    const dialog = await screen.findByRole("dialog", { name: "Import data into this case" });
    await user.click(within(dialog).getByRole("button", { name: /^Choose a folder/ }));
    await within(dialog).findByRole("region", { name: "Discovery" });
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    expect(api.ingestRun).toHaveBeenCalledWith("/evidence/run-1", "open", null, true, expect.any(String));
    // Nothing reloads while the result is on screen.
    await within(dialog).findByRole("region", { name: "Import result" });
    expect(m.open).toHaveBeenCalledTimes(1);
    await user.click(within(dialog).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(m.open).toHaveBeenCalledTimes(2));
    expect(m.open).toHaveBeenLastCalledWith(info.path, false);
    // The screens were remounted (each loads the new data) and the tab badges were counted again.
    await waitFor(() => expect(mounts).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(vi.mocked(api.reviewQueue).mock.calls.length).toBeGreaterThan(queueCalls));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("closing the dialog without importing reloads nothing", async () => {
    const user = await openViaDialog();
    await user.click(screen.getByRole("button", { name: "Import data…" }));
    await user.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(m.open).toHaveBeenCalledTimes(1);
  });

  it("a read-only case cannot import and the button says why", async () => {
    const reason = "the audit chain is broken at seq 3: hash mismatch";
    m.open.mockResolvedValue({ ...info, audit_ok: false, read_only_reason: reason });
    await openViaDialog();
    const button = screen.getByRole("button", { name: "Import data…" });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("title", `Read-only case: ${reason}`);
  });

  it("importing does not need the analyst name", async () => {
    m.settings.mockResolvedValue({ analyst: null, recent: [] });
    await openViaDialog();
    expect(screen.getByRole("button", { name: "Import data…" })).toBeEnabled();
  });

  it("the shell behind an open import dialog is inert", async () => {
    const user = await openViaDialog();
    const titlebar = screen.getByRole("button", { name: "Import data…" }).closest("[inert]");
    expect(titlebar).toBeNull();
    await user.click(screen.getByRole("button", { name: "Import data…" }));
    const dialog = await screen.findByRole("dialog");
    const background = screen.getByRole("button", { name: "Import data…", hidden: true }).closest("[inert]");
    expect(background).not.toBeNull();
    expect(background).toHaveAttribute("inert");
    expect(background).not.toContainElement(dialog);
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("button", { name: "Import data…" }).closest("[inert]")).toBeNull();
  });

  it("the Open case screen is inert behind the new-case dialog", async () => {
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "New case from a folder…" }));
    const dialog = await screen.findByRole("dialog");
    const open = screen.getByRole("button", { name: "Open a case", hidden: true });
    expect(open.closest("[inert]")).not.toBeNull();
    expect(open.closest("[inert]")).not.toContainElement(dialog);
  });

  it("offers to profile an import that was killed before its profile, and reloads after it", async () => {
    vi.mocked(api.ingestUnprofiled).mockResolvedValueOnce([4]).mockResolvedValue([]);
    vi.mocked(api.ingestProfile).mockResolvedValue({ profile_error: null, profile_warnings: [], detect: null, detect_error: null });
    await openViaDialog();
    const banner = await screen.findByText(/Some imported data was not profiled \(1 collection\)/);
    expect(banner).toBeInTheDocument();
    // Nothing is written on open by itself.
    expect(api.ingestProfile).not.toHaveBeenCalled();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Run profile now" }));
    expect(api.ingestProfile).toHaveBeenCalledWith(expect.any(String));
    await waitFor(() => expect(screen.queryByText(/was not profiled/)).not.toBeInTheDocument());
    expect(await screen.findByText("Profile finished")).toBeInTheDocument();
  });

  it("no profile banner on a read-only case, and it does not even ask", async () => {
    vi.mocked(api.ingestUnprofiled).mockResolvedValue([4]);
    m.open.mockResolvedValue({ ...info, audit_ok: false, read_only_reason: "broken chain" });
    await openViaDialog();
    expect(screen.queryByText(/was not profiled/)).not.toBeInTheDocument();
    expect(api.ingestUnprofiled).not.toHaveBeenCalled();
  });

  it("refreshes_on_case_changed_keeping_filters", async () => {
    let changed: ((c: api.CaseChanged) => void) | null = null;
    vi.mocked(api.onCaseChanged).mockImplementation(async (h) => {
      changed = h;
      return () => {};
    });
    let reloads = 0;
    function Screen() {
      const [text, setText] = useState("");
      useOnDataChanged(() => {
        reloads += 1;
      });
      return (
        <label>
          filter
          <input value={text} onChange={(ev) => setText(ev.target.value)} />
        </label>
      );
    }
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    render(<Shell screens={{ accounts: () => <Screen /> }} />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await user.click(screen.getByRole("tab", { name: "Accounts" }));
    await user.type(screen.getByRole("textbox", { name: "filter" }), "jdoe");
    await waitFor(() => expect(changed).not.toBeNull());
    const queueReads = vi.mocked(api.reviewQueue).mock.calls.length;
    act(() => changed!({ kinds: ["marks"] }));
    await waitFor(() => expect(reloads).toBe(1));
    // The same screen, not a remount: what the analyst typed is still there.
    expect(screen.getByRole("textbox", { name: "filter" })).toHaveValue("jdoe");
    await waitFor(() => expect(vi.mocked(api.reviewQueue).mock.calls.length).toBeGreaterThan(queueReads));
  });

  it("shows the agent chip after a bridge request", async () => {
    let activity: ((a: api.AgentActivity) => void) | null = null;
    vi.mocked(api.onAgentActivity).mockImplementation(async (h) => {
      activity = h;
      return () => {};
    });
    await openViaDialog();
    expect(screen.queryByRole("status", { name: /^Agent/ })).toBeNull();
    await waitFor(() => expect(activity).not.toBeNull());
    act(() => activity!({ agent: "claude", command: "mark tag", at: new Date().toISOString(), running: false }));
    expect(await screen.findByRole("status", { name: "Agent claude" })).toBeInTheDocument();
    // A new session of the same case starts without the old request.
    await userEvent.setup().click(screen.getByRole("button", { name: "Close case" }));
    await userEvent.setup().click(await screen.findByRole("button", { name: "/synthetic/case-a.duckdb" }));
    await screen.findByRole("tab", { name: /^Review/ });
    expect(screen.queryByRole("status", { name: /^Agent/ })).toBeNull();
  });
});

describe("the incomplete-collection banner", () => {
  const status: api.IncompleteCollection = {
    gaps: 2,
    sources: ["ual", "message_trace"],
    span_us: 7_200_000_000,
    text: "Collection incomplete: 2 gaps in Unified Audit Log, Message Trace (2 hours). Re-collect before relying on absence of activity.",
  };

  it("shell_shows_the_collection_banner_when_status_is_set", async () => {
    vi.mocked(api.caseCollectionStatus).mockResolvedValue(status);
    const user = await openViaDialog();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveClass("collection-banner");
    expect(alert).toHaveTextContent(status.text);
    expect(alert).toHaveTextContent(`sparrow coverage --case ${info.path}`);
    expect(within(alert).queryByRole("button", { name: /close|dismiss/i })).not.toBeInTheDocument();
    // Directly under the header, above the tab bar.
    const tabs = screen.getAllByRole("tab")[0];
    expect(alert.compareDocumentPosition(tabs) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await user.click(within(alert).getByRole("button", { name: "Copy" }));
    expect(await navigator.clipboard.readText()).toBe(`sparrow coverage --case ${info.path}`);
  });

  it("no_banner_when_status_is_null", async () => {
    await openViaDialog();
    await waitFor(() => expect(api.caseCollectionStatus).toHaveBeenCalled());
    expect(screen.queryByText(/Collection incomplete/)).not.toBeInTheDocument();
    expect(document.querySelector(".collection-banner")).toBeNull();
  });

  it("banner_refreshes_after_import", async () => {
    vi.mocked(api.caseCollectionStatus).mockResolvedValue(status);
    vi.mocked(api.ingestDiscover).mockResolvedValue({
      collections: [
        {
          root: "/evidence/run-1",
          tool: "invictus",
          files: [{ rel_path: "SignInLogs.csv", artifact_id: "invictus.signins", derived: false, size: 10, status: "recognised", too_large: false, error: null }],
        },
      ],
      recognised: 1,
      unrecognised: 0,
      too_large: 0,
      unreadable: 0,
      xlsx_max_bytes: 1_073_741_824,
    } as api.DiscoveryPreview);
    vi.mocked(api.ingestRun).mockResolvedValue({
      case_path: info.path,
      cancelled: false,
      error: null,
      report: { collections: [] },
      files_loaded: 1,
      files_total: 1,
      rows_by_source: [],
      file_notes: [],
      not_loaded: [],
      profile_error: null,
      profile_warnings: [],
      detect: null,
      detect_error: null,
      incomplete_collection: null,
    });
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await screen.findByText(status.text);
    // The second collection covers the gap: the status is clear after the import.
    vi.mocked(api.caseCollectionStatus).mockResolvedValue(null);
    dialogOpen.mockResolvedValue("/evidence/run-1");
    await user.click(screen.getByRole("button", { name: "Import data…" }));
    const dialog = await screen.findByRole("dialog", { name: "Import data into this case" });
    await user.click(within(dialog).getByRole("button", { name: /^Choose a folder/ }));
    await within(dialog).findByRole("region", { name: "Discovery" });
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await within(dialog).findByRole("region", { name: "Import result" });
    await user.click(within(dialog).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByText(status.text)).not.toBeInTheDocument());
  });

  it("banner_clears_when_the_import_finishes_not_when_the_dialog_closes", async () => {
    vi.mocked(api.caseCollectionStatus).mockResolvedValue(status);
    vi.mocked(api.ingestDiscover).mockResolvedValue({
      collections: [{ root: "/evidence/run-1", tool: "invictus", files: [{ rel_path: "S.csv", artifact_id: "invictus.signins", derived: false, size: 10, status: "recognised", too_large: false, error: null }] }],
      recognised: 1, unrecognised: 0, too_large: 0, unreadable: 0, xlsx_max_bytes: 1_073_741_824,
    } as api.DiscoveryPreview);
    vi.mocked(api.ingestRun).mockResolvedValue({
      case_path: info.path, cancelled: false, error: null, report: { collections: [] }, files_loaded: 1, files_total: 1,
      rows_by_source: [], file_notes: [], not_loaded: [], profile_error: null, profile_warnings: [], detect: null,
      detect_error: null, incomplete_collection: null,
    });
    dialogOpen.mockResolvedValue("/synthetic/case-a.duckdb");
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(await screen.findByRole("button", { name: "Open a case" }));
    await screen.findByText(status.text);
    dialogOpen.mockResolvedValue("/evidence/run-1");
    await user.click(screen.getByRole("button", { name: "Import data…" }));
    const dialog = await screen.findByRole("dialog", { name: "Import data into this case" });
    await user.click(within(dialog).getByRole("button", { name: /^Choose a folder/ }));
    await within(dialog).findByRole("region", { name: "Discovery" });
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await within(dialog).findByRole("region", { name: "Import result" });
    // The result card is still open.
    expect(screen.queryByText(status.text)).not.toBeInTheDocument();
  });

  it("the copied command quotes a path with a space and a quote", async () => {
    vi.mocked(api.caseCollectionStatus).mockResolvedValue(status);
    const odd = "/cases/it's here/case.duckdb";
    m.open.mockResolvedValue({ ...info, path: odd });
    const user = await openViaDialog();
    const alert = await screen.findByRole("alert");
    const quoted = "sparrow coverage --case '/cases/it'\\''s here/case.duckdb'";
    expect(alert).toHaveTextContent(quoted);
    await user.click(within(alert).getByRole("button", { name: "Copy" }));
    expect(await navigator.clipboard.readText()).toBe(quoted);
  });

  it("a failed status query shows an error alert, not a clean case", async () => {
    vi.mocked(api.caseCollectionStatus).mockRejectedValue({ kind: "internal", message: "db is busy" });
    await openViaDialog();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Could not check collection completeness: db is busy");
  });
});
