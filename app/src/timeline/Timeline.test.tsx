import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AuditEntry, FindingDetail, TimelineEntry } from "../api";

const api = vi.hoisted(() => ({
  timelineList: vi.fn(),
  timelinePropose: vi.fn(),
  timelineEdit: vi.fn(),
  timelineVerify: vi.fn(),
  timelineReject: vi.fn(),
  findingDetail: vi.fn(),
}));
vi.mock("../api", async (orig) => ({ ...(await orig<typeof import("../api")>()), ...api }));

import { RefreshBadgesContext } from "../shell/nav";
import { Timeline } from "./Timeline";
import { findingDetail as recordedFindingDetail } from "../test/fixtures";

function entry(over: Partial<TimelineEntry> & { entry_id: string }): TimelineEntry {
  return {
    tenant_key: null,
    event_time: "2026-03-01T10:00:00.000000Z",
    end_time: null,
    event_count: null,
    title: "title " + over.entry_id,
    narrative: null,
    phase: "initial_access",
    status: "proposed",
    supersedes: null,
    created_at: "2026-03-01T10:00:00.000000Z",
    updated_at: "2026-03-01T10:00:00.000000Z",
    decided_by: "analyst:carlos",
    decided_at: "2026-03-01T10:00:00.000000Z",
    on_behalf_of: null,
    review_state: "accepted",
    reviewed_by: "analyst:carlos",
    reviewed_at: "2026-03-01T10:00:00.000000Z",
    review_comment: null,
    evidence: [{ source_table: "signins", record_key: "k1" }],
    ...over,
  };
}

const audit = { seq: 9, action: "x" } as AuditEntry;

const ENTRIES: TimelineEntry[] = [
  entry({ entry_id: "e-late", title: "Mailbox rule created", phase: "persistence", status: "verified", event_time: "2026-03-01T12:00:00.000000Z" }),
  entry({ entry_id: "e-sign2", title: "Second sign-in", status: "verified", event_time: "2026-03-01T10:30:00.000000Z" }),
  entry({ entry_id: "e-sign1", title: "First sign-in", status: "verified", event_time: "2026-03-01T10:00:00.000000Z" }),
  entry({ entry_id: "e-prop", title: "Proposed exfil", phase: "exfiltration", status: "proposed" }),
  entry({ entry_id: "e-rej", title: "Rejected guess", phase: "recon", status: "rejected" }),
  entry({ entry_id: "e-old", title: "Old version", status: "superseded" }),
];

beforeEach(() => {
  for (const m of Object.values(api)) m.mockReset();
  api.timelineList.mockResolvedValue(ENTRIES);
});
afterEach(cleanup);

describe("Timeline", () => {
  it("groups entries by phase in time order and hides superseded ones", async () => {
    render(<Timeline />);
    const initial = await screen.findByRole("region", { name: "initial access" });
    const titles = within(initial)
      .getAllByRole("row")
      .slice(1)
      .map((r) => r.querySelector("td:nth-child(2) div")?.textContent);
    expect(titles).toEqual(["First sign-in", "Second sign-in"]);
    expect(screen.getByRole("region", { name: "persistence" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "recon" })).toBeInTheDocument();
    expect(screen.queryByText("Old version")).not.toBeInTheDocument();
    await userEvent.click(screen.getByLabelText("Show superseded"));
    expect(screen.getByText("Old version")).toBeInTheDocument();
  });

  it("client view shows verified entries only", async () => {
    render(<Timeline />);
    await screen.findByText("Proposed exfil");
    expect(screen.getByText("Rejected guess")).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText(/Client view/));
    expect(screen.queryByText("Proposed exfil")).not.toBeInTheDocument();
    expect(screen.queryByText("Rejected guess")).not.toBeInTheDocument();
    expect(screen.getByText("First sign-in")).toBeInTheDocument();
    expect(screen.getByText("Mailbox rule created")).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "exfiltration" })).not.toBeInTheDocument();
  });

  it("the editor sends only the changed fields", async () => {
    api.timelineEdit.mockResolvedValue({ entryId: "e-prop", audit });
    render(<Timeline />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Proposed exfil" }));
    const form = screen.getByRole("form", { name: "Edit entry" });
    const title = within(form).getByLabelText("Title");
    await userEvent.clear(title);
    await userEvent.type(title, "Exfil via forwarding");
    await userEvent.selectOptions(within(form).getByLabelText("Phase"), "collection");
    await userEvent.click(within(form).getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(api.timelineEdit).toHaveBeenCalledWith("e-prop", { title: "Exfil via forwarding", phase: "collection" }),
    );
    await waitFor(() => expect(api.timelineList).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole("form", { name: "Edit entry" })).not.toBeInTheDocument();
  });

  it("adds a new entry with its evidence and reload", async () => {
    api.timelinePropose.mockResolvedValue({ entryId: "n1", audit });
    render(<Timeline />);
    await userEvent.click(await screen.findByRole("button", { name: "Add entry" }));
    const form = screen.getByRole("form", { name: "Add entry" });
    await userEvent.type(within(form).getByLabelText(/^Time/), "2026-03-02T08:00:00Z");
    await userEvent.type(within(form).getByLabelText("Title"), "Token replayed");
    await userEvent.selectOptions(within(form).getByLabelText("Phase"), "persistence");
    await userEvent.type(within(form).getByLabelText(/Add a reference/), "signins:abc");
    await userEvent.click(within(form).getByRole("button", { name: "Add reference" }));
    await userEvent.click(within(form).getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(api.timelinePropose).toHaveBeenCalledWith({
        eventTime: "2026-03-02T08:00:00Z",
        title: "Token replayed",
        narrative: null,
        phase: "persistence",
        evidence: ["signins:abc"],
      }),
    );
  });

  it("editing a verified entry says a successor was created", async () => {
    api.timelineEdit.mockResolvedValue({ entryId: "e-new", audit });
    render(<Timeline />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Mailbox rule created" }));
    expect(screen.getByText(/creates a proposed successor/)).toBeInTheDocument();
    const form = screen.getByRole("form", { name: "Edit entry" });
    await userEvent.type(within(form).getByLabelText("Narrative"), "more");
    await userEvent.click(within(form).getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("status")).toHaveTextContent(/new proposed entry e-new.*e-late/);
  });

  it("verify calls the command; reject needs a reason", async () => {
    api.timelineVerify.mockResolvedValue(audit);
    api.timelineReject.mockResolvedValue(audit);
    render(<Timeline />);
    await userEvent.click(await screen.findByRole("button", { name: "Verify Proposed exfil" }));
    await waitFor(() => expect(api.timelineVerify).toHaveBeenCalledWith("e-prop"));
    await userEvent.click(screen.getByRole("button", { name: "Reject Proposed exfil" }));
    expect(screen.getByRole("button", { name: "Confirm reject" })).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Reason for rejecting"), "not ours");
    await userEvent.click(screen.getByRole("button", { name: "Confirm reject" }));
    await waitFor(() => expect(api.timelineReject).toHaveBeenCalledWith("e-prop", "not ours"));
  });

  it("a refused edit closes the form, reloads and shows the refusal over the changed entry", async () => {
    api.timelineEdit.mockRejectedValue({ kind: "decision", message: "timeline entry e-prop changed since you loaded it" });
    api.timelineList
      .mockResolvedValueOnce(ENTRIES)
      .mockResolvedValue(
        ENTRIES.map((e) => (e.entry_id === "e-prop" ? { ...e, title: "Changed elsewhere" } : e)),
      );
    render(<Timeline />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Proposed exfil" }));
    const form = screen.getByRole("form", { name: "Edit entry" });
    await userEvent.type(within(form).getByLabelText("Title"), "!");
    await userEvent.click(within(form).getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("changed since you loaded it");
    expect(await screen.findByText("Changed elsewhere")).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "Edit entry" })).not.toBeInTheDocument();
    expect(screen.queryByText("Proposed exfil")).not.toBeInTheDocument();
  });

  it("a malformed argument keeps the form open for correction", async () => {
    api.timelineEdit.mockRejectedValue({ kind: "invalid", message: "not an RFC 3339 time" });
    render(<Timeline />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Proposed exfil" }));
    const form = screen.getByRole("form", { name: "Edit entry" });
    await userEvent.type(within(form).getByLabelText("Title"), "!");
    await userEvent.click(within(form).getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("not an RFC 3339 time");
    expect(screen.getByRole("form", { name: "Edit entry" })).toBeInTheDocument();
  });

  it("an open reject form cannot be confirmed once the case turns read-only", async () => {
    api.timelineReject.mockResolvedValue(audit);
    const { rerender } = render(<Timeline />);
    await userEvent.click(await screen.findByRole("button", { name: "Reject Proposed exfil" }));
    await userEvent.type(screen.getByLabelText("Reason for rejecting"), "not ours");
    expect(screen.getByRole("button", { name: "Confirm reject" })).toBeEnabled();
    rerender(<Timeline readOnly />);
    expect(screen.getByRole("button", { name: "Confirm reject" })).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Reason for rejecting"), "{Enter}");
    expect(api.timelineReject).not.toHaveBeenCalled();
  });

  describe("hidden control and direction characters in the editor", () => {
    const hostile = (over: Partial<TimelineEntry>) =>
      api.timelineList.mockResolvedValue([entry({ entry_id: "h", title: "plain", ...over })]);

    it("shows a hostile title and narrative escaped and read-only, and does not send them", async () => {
      hostile({ title: "evil\u202Etitle", narrative: "line1\nbad\u0000nul" });
      api.timelineEdit.mockResolvedValue({ entryId: "h", audit });
      render(<Timeline />);
      await userEvent.click(await screen.findByRole("button", { name: /^Edit / }));
      const form = screen.getByRole("form", { name: "Edit entry" });
      expect(within(form).getAllByRole("note")).toHaveLength(2);
      expect(within(form).getAllByText(/hidden control or direction characters, shown escaped/)).toHaveLength(2);
      const title = within(form).getByLabelText("Title") as HTMLInputElement;
      const narrative = within(form).getByLabelText("Narrative") as HTMLTextAreaElement;
      expect(title).toHaveAttribute("readonly");
      expect(narrative).toHaveAttribute("readonly");
      expect(title.value).toBe("evil\\u{202E}title");
      expect(narrative.value).toBe("line1\\u{000A}bad\\u{0000}nul");
      // Change something else; the hidden fields are not part of the request.
      await userEvent.selectOptions(within(form).getByLabelText("Phase"), "recon");
      await userEvent.click(within(form).getByRole("button", { name: "Save" }));
      await waitFor(() => expect(api.timelineEdit).toHaveBeenCalledWith("h", { phase: "recon" }));
    });

    it("Replace clears the field for a new value, which is what gets sent", async () => {
      hostile({ title: "evil\u202Etitle", narrative: "bad\u0000nul" });
      api.timelineEdit.mockResolvedValue({ entryId: "h", audit });
      render(<Timeline />);
      await userEvent.click(await screen.findByRole("button", { name: /^Edit / }));
      const form = screen.getByRole("form", { name: "Edit entry" });
      await userEvent.click(within(form).getByRole("button", { name: "Replace title" }));
      await userEvent.click(within(form).getByRole("button", { name: "Replace narrative" }));
      expect(within(form).queryByRole("note")).not.toBeInTheDocument();
      const title = within(form).getByLabelText("Title");
      expect(title).not.toHaveAttribute("readonly");
      expect(title).toHaveValue("");
      await userEvent.type(title, "clean title");
      await userEvent.type(within(form).getByLabelText("Narrative"), "clean narrative");
      await userEvent.click(within(form).getByRole("button", { name: "Save" }));
      await waitFor(() =>
        expect(api.timelineEdit).toHaveBeenCalledWith("h", { title: "clean title", narrative: "clean narrative" }),
      );
    });

    it("an ordinary multi-line narrative stays editable", async () => {
      hostile({ narrative: "line1\nline2" });
      render(<Timeline />);
      await userEvent.click(await screen.findByRole("button", { name: /^Edit / }));
      const form = screen.getByRole("form", { name: "Edit entry" });
      expect(within(form).queryByRole("note")).not.toBeInTheDocument();
      expect(within(form).getByLabelText("Narrative")).not.toHaveAttribute("readonly");
      expect(within(form).getByLabelText("Narrative")).toHaveValue("line1\nline2");
    });
  });

  it("read-only disables every write control", async () => {
    render(<Timeline readOnly />);
    await screen.findByText("Proposed exfil");
    expect(screen.getByRole("button", { name: "Add entry" })).toBeDisabled();
    const writes = screen.getAllByRole("button", { name: /^(Edit|Reject|Verify) / });
    expect(writes.length).toBeGreaterThan(0);
    for (const b of writes) expect(b).toBeDisabled();
  });

  it("renders entry text literally, escaping control and bidi characters", async () => {
    api.timelineList.mockResolvedValue([
      entry({ entry_id: "x", title: "<img src=x onerror=alert(1)>‮", status: "verified" }),
    ]);
    const { container } = render(<Timeline />);
    expect(await screen.findByText("<img src=x onerror=alert(1)>\\u{202E}")).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });

  it("the picker adds signins refs from a finding's evidence", async () => {
    // The recorded detail, with its evidence replaced by two sign-in rows the picker can add.
    const recorded = recordedFindingDetail();
    const row = recorded.evidence[0];
    const detail: FindingDetail = {
      ...recorded,
      finding: { ...recorded.finding, finding_id: "f1" },
      evidence: [
        { ...row, source_table: "signins", record_key: "k-a", role: "trigger" },
        { ...row, source_table: "signins", record_key: "k-b", role: "context" },
      ],
    };
    api.findingDetail.mockResolvedValue(detail);
    api.timelinePropose.mockResolvedValue({ entryId: "n1", audit });
    render(<Timeline />);
    await userEvent.click(await screen.findByRole("button", { name: "Add entry" }));
    const form = screen.getByRole("form", { name: "Add entry" });
    await userEvent.type(within(form).getByLabelText("Finding id"), "f1");
    await userEvent.click(within(form).getByRole("button", { name: "Load evidence" }));
    await userEvent.click(await within(form).findByRole("button", { name: "Add signins:k-b" }));
    expect(api.findingDetail).toHaveBeenCalledWith("f1");
    expect(within(form).getByRole("button", { name: "Add signins:k-b" })).toBeDisabled();
    expect(within(form).getByRole("button", { name: "Remove signins:k-b" })).toBeInTheDocument();
    await userEvent.type(within(form).getByLabelText(/^Time/), "2026-03-02T08:00:00Z");
    await userEvent.type(within(form).getByLabelText("Title"), "t");
    await userEvent.click(within(form).getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(api.timelinePropose).toHaveBeenCalledWith(expect.objectContaining({ evidence: ["signins:k-b"] })),
    );
  });
});

describe("Timeline tells the shell to refresh its badges", () => {
  const withRefresh = () => {
    const refresh = vi.fn();
    render(
      <RefreshBadgesContext.Provider value={refresh}>
        <Timeline />
      </RefreshBadgesContext.Provider>,
    );
    return refresh;
  };

  it("once per verify, reject and propose, and not on load", async () => {
    api.timelineVerify.mockResolvedValue(audit);
    api.timelineReject.mockResolvedValue(audit);
    api.timelinePropose.mockResolvedValue({ entryId: "n1", audit });
    const refresh = withRefresh();
    await userEvent.click(await screen.findByRole("button", { name: "Verify Proposed exfil" }));
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
    await userEvent.click(screen.getByRole("button", { name: "Reject Proposed exfil" }));
    await userEvent.type(screen.getByLabelText("Reason for rejecting"), "not ours");
    await userEvent.click(screen.getByRole("button", { name: "Confirm reject" }));
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(2));
    await userEvent.click(screen.getByRole("button", { name: "Add entry" }));
    const form = screen.getByRole("form", { name: "Add entry" });
    await userEvent.type(within(form).getByLabelText(/^Time/), "2026-03-02T08:00:00Z");
    await userEvent.type(within(form).getByLabelText("Title"), "Token replayed");
    await userEvent.selectOptions(within(form).getByLabelText("Phase"), "persistence");
    await userEvent.type(within(form).getByLabelText(/Add a reference/), "signins:abc");
    await userEvent.click(within(form).getByRole("button", { name: "Add reference" }));
    await userEvent.click(within(form).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(3));
  });
});
