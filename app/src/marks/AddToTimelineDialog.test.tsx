import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AddEventsArgs, RowRef } from "../api";

const h = vi.hoisted(() => ({ calls: [] as AddEventsArgs[], fail: null as string | null }));
vi.mock("@tauri-apps/api/core", () => ({
  invoke: async (cmd: string, args?: { args?: AddEventsArgs }) => {
    if (cmd !== "timeline_add_events") throw new Error(`unexpected ${cmd}`);
    h.calls.push(args!.args!);
    if (h.fail) throw { kind: "invalid", message: h.fail };
    return { entryIds: ["e1"], outcome: "Added 1 entry" };
  },
}));

import AddToTimelineDialog from "./AddToTimelineDialog";

const rows = (n: number): RowRef[] => Array.from({ length: n }, (_, i) => ({ source_table: "ual", record_key: `k${i}` }));
beforeEach(() => {
  h.calls.length = 0;
  h.fail = null;
});

describe("AddToTimelineDialog", () => {
  it("timeline_dialog_each_disabled_over_200", async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    render(<AddToTimelineDialog rows={rows(201)} onClose={() => undefined} onDone={onDone} />);
    const each = screen.getByRole("radio", { name: /One entry per event \(max 200\)/ });
    expect(each).toBeDisabled();
    expect(each).toHaveAttribute("title", "One entry per event is limited to 200; 201 are selected");
    expect(screen.getByRole("radio", { name: "One grouped entry" })).toBeChecked();
    await user.click(screen.getByRole("button", { name: "Add to timeline" }));
    await waitFor(() => expect(onDone).toHaveBeenCalledWith("Added 1 entry"));
    expect(h.calls).toEqual([{ rows: rows(201), mode: "group" }]);
  });

  it("exactly_200_events_may_be_added_one_by_one_with_a_title_and_a_phase", async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    render(<AddToTimelineDialog rows={rows(200)} onClose={() => undefined} onDone={onDone} />);
    const each = screen.getByRole("radio", { name: /One entry per event/ });
    expect(each).toBeEnabled();
    expect(each).toBeChecked();
    await user.type(screen.getByLabelText("Title"), "  Relay sends ");
    await user.selectOptions(screen.getByLabelText("Phase"), "recon");
    await user.click(screen.getByRole("button", { name: "Add to timeline" }));
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(h.calls).toEqual([{ rows: rows(200), mode: "each", title: "Relay sends", phase: "recon" }]);
  });

  it("one_event_has_no_mode_choice_and_a_prefilled_title_and_a_refusal_stays_in_the_dialog", async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    h.fail = "event ual:k0 has no time";
    render(<AddToTimelineDialog rows={rows(1)} defaultTitle="Send by jdoe from 192.0.2.5" onClose={() => undefined} onDone={onDone} />);
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Title")).toHaveValue("Send by jdoe from 192.0.2.5");
    await user.click(screen.getByRole("button", { name: "Add to timeline" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("event ual:k0 has no time");
    expect(onDone).not.toHaveBeenCalled();
    expect(h.calls).toEqual([{ rows: rows(1), mode: "each", title: "Send by jdoe from 192.0.2.5" }]);
    expect(screen.getByRole("button", { name: "Add to timeline" })).toBeEnabled();
  });
});
