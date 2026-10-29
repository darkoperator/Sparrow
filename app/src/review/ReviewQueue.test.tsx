import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { findingDetail as detailFixture, queue as queueFixture } from "../test/fixtures";
import type { CmdError, FindingDetail, Proposal, QueueItem } from "../api";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  reviewQueue: vi.fn(),
  evidenceFilter: vi.fn(),
  findingDetail: vi.fn(),
  reviewAccept: vi.fn(),
  reviewDiscard: vi.fn(),
  proposalAccept: vi.fn(),
  proposalDiscard: vi.fn(),
}));

import * as api from "../api";
import { NavContext, RefreshBadgesContext } from "../shell/nav";
import ReviewQueue from "./ReviewQueue";

// The recorded queue: three agent decisions on one account (finding set_status, indicator add_ioc, timeline
// propose_entry) and two open proposals from analyst:ann (bundle SHA below).
const ACCOUNT = "marlowe.rhodes@contoso.example";
const FINDING_ID = "1c8b18eff09c880c";
const FINDING = `item-finding:${FINDING_ID}:1`;
const INDICATOR = "item-indicator:c0138dfabda9ce43:2";
const TIMELINE = "item-timeline_entry:8cf41c6e45bc:3";
const SHA = "7c74996e28f36f5f2aa69e0ce60207310ab0eba0b49a681b361f611756c409e5";
const PROP_A = `item-${SHA}:finding:20309ce49aeb83a9`;
const PROP_B = `item-${SHA}:finding:20de6191e65a2528`;

let queue: QueueItem[];
let detail: FindingDetail;
let audit: FindingDetail["audit"][number];

const m = {
  queue: vi.mocked(api.reviewQueue),
  detail: vi.mocked(api.findingDetail),
  accept: vi.mocked(api.reviewAccept),
  discard: vi.mocked(api.reviewDiscard),
  pAccept: vi.mocked(api.proposalAccept),
  pDiscard: vi.mocked(api.proposalDiscard),
};

beforeEach(() => {
  for (const f of Object.values(m)) f.mockReset();
  queue = queueFixture();
  detail = detailFixture();
  audit = detail.audit[0];
  m.queue.mockImplementation(async () => queue);
  m.detail.mockImplementation(async () => detail);
  m.accept.mockResolvedValue(audit);
  m.discard.mockResolvedValue(audit);
  m.pAccept.mockResolvedValue([audit]);
  m.pDiscard.mockResolvedValue(audit);
});

const proposals = () => queue.filter((q): q is { source: "proposal" } & Proposal => q.source === "proposal");

async function ready(canWrite = true) {
  const user = userEvent.setup();
  render(<ReviewQueue canWrite={canWrite} />);
  await screen.findByTestId(FINDING);
  return user;
}

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

describe("ReviewQueue", () => {
  it("groups queue items by account and shows the diff", async () => {
    await ready();
    const headings = screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent);
    expect(headings).toEqual([ACCOUNT, "Other"]);
    // Only the changed keys, before → after.
    const row = screen.getByTestId(FINDING);
    expect(within(row).getByText("User inbox rule deletes, forwards or redirects mail")).toBeInTheDocument();
    expect(within(row).getByText("set_status")).toBeInTheDocument();
    expect(within(row).getByText(/new → in_review/)).toBeInTheDocument();
    expect(within(row).getByText("review_state")).toBeInTheDocument();
    expect(within(row).queryByText("rule_updated")).toBeNull(); // false → false: unchanged
    expect(within(row).queryByText("assigned_to")).toBeNull(); // null → null: unchanged
    expect(within(row).getByText(/agent:triage on behalf of analyst:carlos/)).toBeInTheDocument();
    expect(within(row).getByText("token replay from a hosting ASN", { selector: ".reason" })).toBeInTheDocument();
    // The indicator and the timeline entry sit in the same account group.
    expect(within(screen.getByTestId(INDICATOR)).getByText("add_ioc")).toBeInTheDocument();
    expect(within(screen.getByTestId(TIMELINE)).getByText("propose_entry")).toBeInTheDocument();
    // A proposal shows who it is from and its classification.
    const prop = screen.getByTestId(PROP_A);
    expect(within(prop).getByText(/from analyst:ann/)).toBeInTheDocument();
    expect(within(prop).getByText("new")).toBeInTheDocument();
  });

  it("puts a decision on another account in its own group", async () => {
    const other = queue[1];
    if (other.source !== "decision") throw new Error("fixture");
    other.account = "second.user@contoso.example";
    await ready();
    const headings = screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent);
    expect(headings).toEqual([ACCOUNT, "second.user@contoso.example", "Other"]);
  });

  it("accept calls review_accept with the item's seq and reloads", async () => {
    const user = await ready();
    await user.click(screen.getByTestId(FINDING));
    await user.type(screen.getByLabelText("Comment"), "looks fine");
    await user.click(screen.getByRole("button", { name: "Accept" }));
    expect(m.accept).toHaveBeenCalledWith("finding", FINDING_ID, 1, "looks fine");
    await waitFor(() => expect(m.queue).toHaveBeenCalledTimes(2));
  });

  it("discard calls review_discard", async () => {
    const user = await ready();
    await user.click(screen.getByTestId(INDICATOR));
    await user.click(screen.getByRole("button", { name: "Discard" }));
    expect(m.discard).toHaveBeenCalledWith("indicator", "c0138dfabda9ce43", 2, undefined);
    await waitFor(() => expect(m.queue).toHaveBeenCalledTimes(2));
  });

  it("stale_accept_reloads_item: a gone item moves the selection to its neighbour", async () => {
    const user = await ready();
    await user.click(screen.getByTestId(FINDING));
    m.accept.mockRejectedValue({ kind: "decision", message: "finding changed since the queue loaded" } satisfies CmdError);
    const reloaded = queue.filter((q) => !(q.source === "decision" && q.object_id === FINDING_ID));
    m.queue.mockImplementation(async () => reloaded);
    await user.click(screen.getByRole("button", { name: "Accept" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("finding changed since the queue loaded");
    await waitFor(() => expect(screen.queryByTestId(FINDING)).toBeNull());
    // The next item (the indicator) is selected now.
    expect(screen.getByTestId(INDICATOR)).toHaveAttribute("aria-selected", "true");
  });

  it("keeps the same object selected when a reload gives it a new decision seq", async () => {
    const user = await ready();
    await user.click(screen.getByTestId(INDICATOR));
    m.accept.mockRejectedValueOnce({ kind: "decision", message: "indicator changed since the queue loaded" });
    // Reload: the same indicator, redecided by the agent (seq 9).
    const redecided = queue.map((q) => (q.source === "decision" && q.object_id === "c0138dfabda9ce43" ? { ...q, decision_seq: 9 } : q));
    m.queue.mockImplementation(async () => redecided);
    await user.click(screen.getByRole("button", { name: "Accept" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("changed since");
    const row = await screen.findByTestId("item-indicator:c0138dfabda9ce43:9");
    expect(row).toHaveAttribute("aria-selected", "true");
    // The next accept sends the new seq, not the stale one.
    m.accept.mockResolvedValue(audit);
    await user.click(screen.getByRole("button", { name: "Accept" }));
    expect(m.accept).toHaveBeenLastCalledWith("indicator", "c0138dfabda9ce43", 9, undefined);
  });

  it("selecting a finding loads its detail: evidence, guidance, notes, history", async () => {
    detail.notes = [
      { annotation_id: "n-1", object_type: "finding", object_id: FINDING_ID, source_table: null, text: "Rule moves mail out", actor: "agent:triage", on_behalf_of: null, created_at: "2026-10-07T23:00:00.000000Z" },
      { annotation_id: "n-2", object_type: "finding", object_id: FINDING_ID, source_table: null, text: "Asked the user", actor: "analyst:carlos", on_behalf_of: null, created_at: "2026-10-07T23:10:00.000000Z" },
    ];
    const user = await ready();
    await user.click(screen.getByTestId(FINDING));
    expect(m.detail).toHaveBeenCalledWith(FINDING_ID);
    expect(await screen.findByText(/is how a BEC actor hides replies/)).toBeInTheDocument();
    // Six recorded evidence rows: two ual_events, four inbox_rules.
    expect(screen.getAllByText("ual_events")).toHaveLength(2);
    expect(screen.getAllByText("inbox_rules")).toHaveLength(4);
    expect(screen.getAllByText("agent note")).toHaveLength(1);
    expect(screen.getByText(/Rule moves mail out/)).toBeInTheDocument();
    expect(screen.getByText(/Asked the user/)).toBeInTheDocument();
    expect(screen.getByTestId("history")).toHaveTextContent("set_status");
  });

  it("a request to show a finding selects its item, or says it is not waiting for review", async () => {
    m.queue.mockImplementation(async () => queue);
    const view = render(<ReviewQueue canWrite focusFinding={{ id: FINDING_ID, nonce: 1 }} />);
    await waitFor(() => expect(screen.getByTestId(FINDING)).toHaveAttribute("aria-selected", "true"));
    expect(m.detail).toHaveBeenCalledWith(FINDING_ID);
    // A finding with no pending item: nothing is selected and the queue says why.
    view.rerender(<ReviewQueue canWrite focusFinding={{ id: "no-such-finding", nonce: 2 }} />);
    expect(await screen.findByText(/Finding no-such-finding is not waiting for review/)).toHaveAttribute("role", "status");
    // The same request again (same nonce) does not fire twice.
    view.rerender(<ReviewQueue canWrite focusFinding={{ id: "no-such-finding", nonce: 2 }} />);
    expect(screen.getAllByText(/is not waiting for review/)).toHaveLength(1);
    // The proposal's finding is found too.
    view.rerender(<ReviewQueue canWrite focusFinding={{ id: "20309ce49aeb83a9", nonce: 3 }} />);
    await waitFor(() => expect(screen.getByTestId(PROP_A)).toHaveAttribute("aria-selected", "true"));
  });

  it("evidence_text_is_rendered_literally", async () => {
    detail.evidence[0].context = { rule_name: "<img src=x onerror=alert(1)>‮" };
    detail.analyst_guidance = "<b>bold</b>";
    const user = await ready();
    await user.click(screen.getByTestId(FINDING));
    expect(await screen.findByText(/<img src=x onerror=alert\(1\)>/)).toBeInTheDocument();
    expect(screen.getByText("<b>bold</b>")).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("b")).toBeNull();
    expect(document.body.textContent).toContain("\\u{202E}");
    expect(document.body.textContent).not.toContain("‮");
  });

  it("read-only case disables every write control", async () => {
    const user = await ready(false);
    await user.click(screen.getByTestId(FINDING));
    expect(screen.getByRole("button", { name: "Accept" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Discard" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Accept all from analyst:ann" })).toBeDisabled();
    await user.click(screen.getByTestId(PROP_A));
    const writes = screen.getAllByRole("button", { name: /^(Accept|Discard)/ });
    expect(writes.length).toBeGreaterThanOrEqual(3);
    for (const b of writes) expect(b).toBeDisabled();
    await user.keyboard("a");
    await user.keyboard("d");
    expect(m.accept).not.toHaveBeenCalled();
    expect(m.discard).not.toHaveBeenCalled();
    expect(m.pAccept).not.toHaveBeenCalled();
    expect(m.pDiscard).not.toHaveBeenCalled();
  });

  it("keyboard j/k/a/d drive the queue but not while typing", async () => {
    const user = await ready();
    await user.keyboard("j");
    expect(screen.getByTestId(FINDING)).toHaveAttribute("aria-selected", "true");
    await user.keyboard("j");
    expect(screen.getByTestId(INDICATOR)).toHaveAttribute("aria-selected", "true");
    await user.keyboard("k");
    expect(screen.getByTestId(FINDING)).toHaveAttribute("aria-selected", "true");
    await user.keyboard("a");
    expect(m.accept).toHaveBeenCalledWith("finding", FINDING_ID, 1, undefined);
    await waitFor(() => expect(m.queue).toHaveBeenCalledTimes(2));
    await user.keyboard("j");
    await user.keyboard("d");
    await waitFor(() => expect(m.discard).toHaveBeenCalledWith("indicator", "c0138dfabda9ce43", 2, undefined));
    expect(m.discard).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(m.queue).toHaveBeenCalledTimes(3));
    // While typing a comment the keys are text, not commands.
    await user.click(screen.getByTestId(FINDING));
    m.accept.mockClear();
    m.discard.mockClear();
    await user.click(screen.getByLabelText("Comment"));
    await user.keyboard("jad");
    expect(screen.getByLabelText("Comment")).toHaveValue("jad");
    expect(m.accept).not.toHaveBeenCalled();
    expect(m.discard).not.toHaveBeenCalled();
  });

  it("accepts a proposal and discards one with a comment", async () => {
    const user = await ready();
    await user.click(screen.getByTestId(PROP_A));
    await user.click(screen.getByRole("button", { name: "Accept" }));
    expect(m.pAccept).toHaveBeenCalledWith(SHA, "finding:20309ce49aeb83a9");
    await waitFor(() => expect(m.queue).toHaveBeenCalledTimes(2));
    await user.click(screen.getByTestId(PROP_B));
    await user.type(screen.getByLabelText("Comment"), "not ours");
    await user.click(screen.getByRole("button", { name: "Discard" }));
    expect(m.pDiscard).toHaveBeenCalledWith(SHA, "finding:20de6191e65a2528", "not ours");
  });

  it("accept all from an analyst stops at the first error", async () => {
    const user = await ready();
    m.pAccept
      .mockResolvedValueOnce([audit])
      .mockRejectedValueOnce({ kind: "decision", message: "finding changed since import" } satisfies CmdError);
    await user.click(screen.getByRole("button", { name: "Accept all from analyst:ann" }));
    await waitFor(() => expect(m.pAccept).toHaveBeenCalledTimes(2));
    expect(m.pAccept.mock.calls[0]).toEqual([SHA, "finding:20309ce49aeb83a9"]);
    expect(m.pAccept.mock.calls[1]).toEqual([SHA, "finding:20de6191e65a2528"]);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("1 of 2");
    expect(alert).toHaveTextContent("finding changed since import");
    await waitFor(() => expect(m.queue).toHaveBeenCalledTimes(2));
  });

  it("accept all skips proposals that cannot be accepted", async () => {
    queue.push({ ...proposals()[0], item_key: "note:ffffffffffffffff", classification: "missing" });
    const user = await ready();
    await user.click(screen.getByRole("button", { name: "Accept all from analyst:ann" }));
    await waitFor(() => expect(m.pAccept).toHaveBeenCalledTimes(2));
    expect(m.pAccept.mock.calls.map((c) => c[1])).not.toContain("note:ffffffffffffffff");
  });

  it("a missing proposal cannot be accepted by button or by the a key; it can be discarded", async () => {
    queue.push({ ...proposals()[0], item_key: "note:ffffffffffffffff", classification: "missing" });
    const user = await ready();
    await user.click(screen.getByTestId(`item-${SHA}:note:ffffffffffffffff`));
    expect(screen.getByRole("button", { name: "Accept" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Discard" })).toBeEnabled();
    await user.keyboard("a");
    expect(m.pAccept).not.toHaveBeenCalled();
    expect(await screen.findByRole("alert")).toHaveTextContent(/cannot be accepted/);
    expect(m.queue).toHaveBeenCalledTimes(1); // refused before anything ran: no reload either
    await user.keyboard("d");
    await waitFor(() => expect(m.pDiscard).toHaveBeenCalledWith(SHA, "note:ffffffffffffffff", undefined));
  });

  it("stays busy through the reload, so a double click acts once", async () => {
    const user = await ready();
    await user.click(screen.getByTestId(FINDING));
    const slow = deferred<FindingDetail["audit"][number]>();
    m.accept.mockReturnValue(slow.promise);
    const reload = deferred<QueueItem[]>();
    const accept = screen.getByRole("button", { name: "Accept" });
    await user.dblClick(accept);
    expect(m.accept).toHaveBeenCalledTimes(1);
    expect(accept).toBeDisabled();
    expect(screen.getByRole("button", { name: "Discard" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Accept all from analyst:ann" })).toBeDisabled();
    // The write finishes; the reload is still pending: still busy, keys do nothing.
    m.queue.mockImplementation(() => reload.promise);
    slow.resolve(audit);
    await waitFor(() => expect(m.queue).toHaveBeenCalledTimes(2));
    expect(accept).toBeDisabled();
    await user.keyboard("d");
    expect(m.discard).not.toHaveBeenCalled();
    reload.resolve(queue);
    await waitFor(() => expect(screen.getByRole("button", { name: "Accept" })).toBeEnabled());
    expect(m.accept).toHaveBeenCalledTimes(1);
  });

  it("shows an empty queue", async () => {
    m.queue.mockResolvedValue([]);
    render(<ReviewQueue canWrite />);
    expect(await screen.findByText("Nothing to review.")).toBeInTheDocument();
  });

  it("shows a queue load error", async () => {
    m.queue.mockRejectedValue({ kind: "no_case", message: "no case is open" } satisfies CmdError);
    render(<ReviewQueue canWrite />);
    expect(await screen.findByRole("alert")).toHaveTextContent("no case is open");
  });

  it("an account filter shows only that account's decisions, case-insensitively, and hides proposals", async () => {
    const user = userEvent.setup();
    const onClear = vi.fn();
    render(<ReviewQueue canWrite accountFilter={ACCOUNT.toUpperCase()} onClearFilter={onClear} />);
    await screen.findByTestId(FINDING);
    const decisions = queue.filter((q) => q.source === "decision" && q.account === ACCOUNT);
    expect(decisions.length).toBeGreaterThan(0);
    expect(screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual([ACCOUNT]);
    expect(screen.queryByTestId(PROP_A)).toBeNull();
    expect(screen.queryByRole("button", { name: /Accept all from/ })).toBeNull();
    expect(screen.getByText(new RegExp(`\\(${decisions.length} of ${queue.length}\\)`))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Show all" }));
    expect(onClear).toHaveBeenCalledOnce();
  });

  it("an account filter that matches nothing says so instead of showing nothing", async () => {
    render(<ReviewQueue canWrite accountFilter="nobody@contoso.example" />);
    expect(await screen.findByText("Nothing to review for this account.")).toBeInTheDocument();
  });

  it("the keyboard only reaches the filtered items", async () => {
    const user = userEvent.setup();
    render(<ReviewQueue canWrite accountFilter={ACCOUNT} />);
    await screen.findByTestId(FINDING);
    await user.keyboard("jjjjjjjj");
    await user.keyboard("a");
    // Whatever is selected after running past the end is a visible decision, never a hidden proposal.
    const calls = [...m.accept.mock.calls, ...m.pAccept.mock.calls];
    expect(calls).toHaveLength(1);
    expect(m.pAccept).not.toHaveBeenCalled();
  });
});

describe("ReviewQueue detail for every item", () => {
  const nav = () => ({ openEntity: vi.fn(), openTable: vi.fn(), showInEvents: vi.fn(), openFinding: vi.fn() });
  async function open(testId: string) {
    const n = nav();
    const user = userEvent.setup();
    render(
      <NavContext.Provider value={n}>
        <ReviewQueue canWrite />
      </NavContext.Provider>,
    );
    await user.click(await screen.findByTestId(testId));
    return { user, n, detail: document.querySelector(".queue-detail") as HTMLElement };
  }

  it("an indicator decision shows its fields and opens a tab on the value", async () => {
    const { user, n, detail } = await open(INDICATOR);
    const d = within(detail);
    expect(d.getByText("upn")).toBeInTheDocument();
    expect(d.getAllByText(ACCOUNT).length).toBeGreaterThan(0);
    expect(d.getByText("suspicious")).toBeInTheDocument();
    expect(d.getByText("account used from the relay")).toBeInTheDocument();
    expect(d.getByText("agent:triage")).toBeInTheDocument();
    await user.click(d.getByRole("button", { name: `Open account tab ${ACCOUNT}` }));
    expect(n.openEntity).toHaveBeenCalledWith({ kind: "account", value: ACCOUNT });
  });

  it("a timeline-entry decision shows its narrative and links each evidence ref to Tables", async () => {
    const { user, n, detail } = await open(TIMELINE);
    const d = within(detail);
    expect(d.getByText("initial_access")).toBeInTheDocument();
    expect(d.getAllByText("Sign-in through the AiTM relay").length).toBeGreaterThan(0);
    expect(d.getByText("session token replayed")).toBeInTheDocument();
    expect(d.getByText("2026-08-21T09:47:00.000000Z")).toBeInTheDocument();
    vi.mocked(api.evidenceFilter).mockResolvedValue({
      table: "ual_events",
      filters: [{ op: "eq", column: "record_id", value: "02a13335-5a42-4ce8-9f05-5b5f0f489146" }],
    });
    await user.click(d.getByRole("button", { name: /ual_events/ }));
    expect(api.evidenceFilter).toHaveBeenCalledWith("ual_events", "02a13335-5a42-4ce8-9f05-5b5f0f489146");
    await vi.waitFor(() =>
      expect(n.openTable).toHaveBeenCalledWith("ual_events", [
        { op: "eq", column: "record_id", value: "02a13335-5a42-4ce8-9f05-5b5f0f489146" },
      ]),
    );
  });

  it("an evidence link whose table cannot be resolved shows the error and opens nothing", async () => {
    const { user, n, detail } = await open(TIMELINE);
    vi.mocked(api.evidenceFilter).mockRejectedValue({ kind: "invalid", message: "unknown evidence table" });
    await user.click(within(detail).getByRole("button", { name: /ual_events/ }));
    expect(await within(detail).findByRole("alert")).toHaveTextContent("unknown evidence table");
    expect(n.openTable).not.toHaveBeenCalled();
  });

  it("a and d do nothing while the value viewer is open", async () => {
    const { user } = await open(FINDING);
    const dialog = document.createElement("div");
    dialog.setAttribute("role", "dialog");
    const btn = document.createElement("button");
    dialog.appendChild(btn);
    document.body.appendChild(dialog);
    btn.focus();
    await user.keyboard("ad");
    dialog.remove();
    expect(m.accept).not.toHaveBeenCalled();
    expect(m.discard).not.toHaveBeenCalled();
    await user.keyboard("d");
    expect(m.discard).toHaveBeenCalledTimes(1);
  });

  it("a non-finding proposal shows the proposed item against the current value in full", async () => {
    const sha = "ab".repeat(32);
    queue.push({
      source: "proposal",
      bundle_sha256: sha,
      item_key: "indicator:k1",
      source_analyst: "analyst:ann",
      classification: "conflict",
      state: "open",
      item: { kind: "indicator", tenant_key: null, ioc_type: "ip", value: "203.0.113.9", verdict: "malicious", note: "relay <b>egress</b>", active: true },
      current: { verdict: "benign", note: "old note" },
    });
    const { detail } = await open(`item-${sha}:indicator:k1`);
    const d = within(detail);
    expect(d.getByText("203.0.113.9")).toBeInTheDocument();
    expect(d.getByText("malicious")).toBeInTheDocument();
    expect(d.getByText("relay <b>egress</b>")).toBeInTheDocument();
    expect(detail.querySelector("b")).toBeNull();
    expect(d.getAllByText(/old note/).length).toBeGreaterThan(0);
    expect(d.getByRole("button", { name: "Open IP tab 203.0.113.9" })).toBeInTheDocument();
  });

  it("a note proposal shows the target and the text", async () => {
    const sha = "cd".repeat(32);
    queue.push({
      source: "proposal",
      bundle_sha256: sha,
      item_key: "note:n1",
      source_analyst: "analyst:ann",
      classification: "new",
      state: "open",
      item: { kind: "note", target: "finding:abc", text: "full note text" },
      current: null,
    });
    const { detail } = await open(`item-${sha}:note:n1`);
    expect(within(detail).getByText("full note text")).toBeInTheDocument();
    expect(within(detail).getByText("finding:abc")).toBeInTheDocument();
  });
});

describe("ReviewQueue tells the shell to refresh its badges", () => {
  async function readyWithRefresh() {
    const refresh = vi.fn();
    const user = userEvent.setup();
    render(
      <RefreshBadgesContext.Provider value={refresh}>
        <ReviewQueue canWrite />
      </RefreshBadgesContext.Provider>,
    );
    await screen.findByTestId(FINDING);
    return { user, refresh };
  }

  it("not on load, once after an accept, once after a discard, once after accept all", async () => {
    const { user, refresh } = await readyWithRefresh();
    expect(refresh).not.toHaveBeenCalled();
    await user.click(screen.getByTestId(FINDING));
    await user.click(screen.getByRole("button", { name: "Accept" }));
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
    await user.click(screen.getByTestId(INDICATOR));
    await user.click(screen.getByRole("button", { name: "Discard" }));
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(2));
    await user.click(screen.getByRole("button", { name: "Accept all from analyst:ann" }));
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(3));
  });

  it("also after a refused write, because the reload may have changed the queue", async () => {
    m.accept.mockRejectedValueOnce({ kind: "decision", message: "changed since" } satisfies CmdError);
    const { user, refresh } = await readyWithRefresh();
    await user.click(screen.getByTestId(FINDING));
    await user.click(screen.getByRole("button", { name: "Accept" }));
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
  });
});
