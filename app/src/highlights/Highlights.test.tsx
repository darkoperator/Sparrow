import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CmdError, HighlightSet } from "../api";
import Grid from "../grid/Grid";
import { indicators as indicatorsFixture } from "../test/fixtures";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  highlightsGet: vi.fn(),
  highlightsSet: vi.fn(),
  highlightsClear: vi.fn(),
  indicatorsActive: vi.fn(),
}));

import * as api from "../api";
import Highlights from "./Highlights";
import { HighlightsError, HighlightsProvider } from "./useHighlights";

const m = {
  get: vi.mocked(api.highlightsGet),
  set: vi.mocked(api.highlightsSet),
  clear: vi.mocked(api.highlightsClear),
  ind: vi.mocked(api.indicatorsActive),
};
const CASE = "case-1";
const HOSTILE = "<img src=x onerror=alert(1)>‮";
let stored: HighlightSet[];

beforeEach(() => {
  for (const f of Object.values(m)) f.mockReset();
  stored = [];
  m.get.mockImplementation(async () => stored);
  m.set.mockImplementation(async (_c, sets) => (stored = sets));
  m.clear.mockImplementation(async () => {
    stored = [];
    return null;
  });
  m.ind.mockResolvedValue([]);
});

const rowOf = (text: string) => screen.getByText(text).closest('[role="row"]')!;

function Screen() {
  return (
    <>
      <Highlights />
      <Grid columns={["ip", "note"]} rows={[["192.0.2.2", "a"], ["198.51.100.7", "b"], [HOSTILE, "c"]]} />
    </>
  );
}
const renderScreen = () =>
  render(
    <HighlightsProvider caseId={CASE}>
      <Screen />
    </HighlightsProvider>,
  );

describe("Highlights", () => {
  it("hostile_highlight_value_is_shown_escaped_and_matches", async () => {
    stored = [{ name: "Hostile", rules: [{ column: null, op: "eq", value: HOSTILE, colour: "red" }] }];
    renderScreen();
    expect(await screen.findByText("any column equals <img src=x onerror=alert(1)>\\u{202E}")).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    // Matching still works on the RAW value, and the cell itself is escaped too.
    const cell = screen.getByText("<img src=x onerror=alert(1)>\\u{202E}", { selector: ".grid-cell" });
    expect(cell.closest('[role="row"]')).toHaveClass("hl-red");
    expect(rowOf("192.0.2.2")).not.toHaveClass("hl-red");
  });

  it("the indicators set colours the rows holding an active IOC, malicious red and suspicious amber, and can be switched off", async () => {
    const ioc = indicatorsFixture()[0];
    expect(ioc.verdict).toBe("malicious");
    m.ind.mockResolvedValue([ioc, { ioc_type: "ip", value: "198.51.100.7", verdict: "suspicious" }]);
    const user = userEvent.setup();
    renderScreen();
    await waitFor(() => expect(rowOf(ioc.value)).toHaveClass("hl-red"));
    expect(rowOf("198.51.100.7")).toHaveClass("hl-amber");
    expect(screen.getByText("2 active malicious or suspicious indicators")).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "Highlight indicators" }));
    expect(rowOf(ioc.value)).not.toHaveClass("hl-red");
    expect(rowOf("198.51.100.7")).not.toHaveClass("hl-amber");
    expect(m.set).not.toHaveBeenCalled(); // computed, never stored
  });

  it("adding a rule saves the whole list for the case; the new rule colours rows", async () => {
    const user = userEvent.setup();
    renderScreen();
    await screen.findByText("No highlight sets for this case.");
    await user.type(screen.getByLabelText("Set"), "Suspects");
    await user.type(screen.getByLabelText("Column (empty = any)"), "ip");
    await user.type(screen.getByLabelText("Value"), "198.51");
    await user.selectOptions(screen.getByLabelText("Match"), "contains");
    await user.selectOptions(screen.getByLabelText("Colour"), "blue");
    await user.click(screen.getByRole("button", { name: "Add rule" }));
    const expected = [{ name: "Suspects", rules: [{ column: "ip", op: "contains", value: "198.51", colour: "blue" }] }];
    expect(m.set).toHaveBeenCalledExactlyOnceWith(CASE, expected);
    await waitFor(() => expect(rowOf("198.51.100.7")).toHaveClass("hl-blue"));
    expect(rowOf("192.0.2.2")).not.toHaveClass("hl-blue");
    expect(screen.getByText("ip contains 198.51")).toBeInTheDocument();
    // A second rule goes into the same set (the form keeps the set name).
    await user.clear(screen.getByLabelText("Column (empty = any)"));
    await user.type(screen.getByLabelText("Value"), "192.0.2.2");
    await user.click(screen.getByRole("button", { name: "Add rule" }));
    await waitFor(() => expect(m.set).toHaveBeenCalledTimes(2));
    expect(m.set.mock.calls[1][1]).toHaveLength(1);
    expect(m.set.mock.calls[1][1][0].rules).toHaveLength(2);
  });

  it("a set can be switched off without removing it", async () => {
    stored = [{ name: "S", rules: [{ column: null, op: "eq", value: "b", colour: "green" }] }];
    const user = userEvent.setup();
    renderScreen();
    await waitFor(() => expect(rowOf("b")).toHaveClass("hl-green"));
    await user.click(screen.getByRole("checkbox", { name: "S" }));
    expect(rowOf("b")).not.toHaveClass("hl-green");
    expect(screen.getByText("any column equals b")).toBeInTheDocument();
    expect(m.set).not.toHaveBeenCalled();
    await user.click(screen.getByRole("checkbox", { name: "S" }));
    expect(rowOf("b")).toHaveClass("hl-green");
  });

  it("removing the last rule removes the set; removing a set saves without it", async () => {
    stored = [
      { name: "One", rules: [{ column: null, op: "eq", value: "x", colour: "red" }] },
      { name: "Two", rules: [{ column: "ip", op: "eq", value: "y", colour: "red" }] },
    ];
    const user = userEvent.setup();
    renderScreen();
    await user.click(await screen.findByRole("button", { name: "Remove rule any column equals x" }));
    expect(m.set).toHaveBeenLastCalledWith(CASE, [expect.objectContaining({ name: "Two" })]);
    await user.click(await screen.findByRole("button", { name: "Remove set Two" }));
    expect(m.set).toHaveBeenLastCalledWith(CASE, []);
  });

  it("Clear highlights asks first, then clears this case's sets", async () => {
    stored = [{ name: "S", rules: [{ column: null, op: "eq", value: "b", colour: "green" }] }];
    const user = userEvent.setup();
    renderScreen();
    await user.click(await screen.findByRole("button", { name: "Clear highlights for this case" }));
    expect(m.clear).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Keep them" }));
    expect(m.clear).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Clear highlights for this case" }));
    await user.click(screen.getByRole("button", { name: "Yes, clear them" }));
    expect(m.clear).toHaveBeenCalledExactlyOnceWith(CASE);
    expect(await screen.findByText("No highlight sets for this case.")).toBeInTheDocument();
    expect(rowOf("b")).not.toHaveClass("hl-green");
  });

  it("shows the backend's refusal and keeps the sets as they were", async () => {
    m.set.mockRejectedValue({ kind: "invalid", message: "a case can have at most 50 highlight sets" } satisfies CmdError);
    const user = userEvent.setup();
    renderScreen();
    await screen.findByText("No highlight sets for this case.");
    await user.type(screen.getByLabelText("Set"), "S");
    await user.type(screen.getByLabelText("Value"), "v");
    await user.click(screen.getByRole("button", { name: "Add rule" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("at most 50 highlight sets");
    expect(screen.getByText("No highlight sets for this case.")).toBeInTheDocument();
    expect(screen.getByLabelText("Value")).toHaveValue("v");
  });

  it("a grid cell's 'Highlight this value' adds an eq rule on the raw value to the quick set", async () => {
    const user = userEvent.setup();
    renderScreen();
    await screen.findByText("No highlight sets for this case.");
    fireEvent.contextMenu(screen.getByText("198.51.100.7"));
    await user.click(screen.getByRole("menuitem", { name: "Highlight this value" }));
    await waitFor(() =>
      expect(m.set).toHaveBeenCalledExactlyOnceWith(CASE, [
        { name: "Quick highlights", rules: [{ column: "ip", op: "eq", value: "198.51.100.7", colour: "amber" }] },
      ]),
    );
    await waitFor(() => expect(rowOf("198.51.100.7")).toHaveClass("hl-amber"));
  });

  it("loads the case's sets once per case id", async () => {
    renderScreen();
    await screen.findByText("No highlight sets for this case.");
    expect(m.get).toHaveBeenCalledExactlyOnceWith(CASE);
    expect(within(document.body).queryByRole("alert")).toBeNull();
  });

  it("checks the caps before saving: 51 sets, 101 rules, a value over 1 KiB never reach the backend", async () => {
    const user = userEvent.setup();
    stored = Array.from({ length: 50 }, (_, i) => ({ name: `s${i}`, rules: [{ column: null, op: "eq" as const, value: "v", colour: "red" as const }] }));
    stored[0] = { name: "s0", rules: Array.from({ length: 100 }, () => ({ column: null, op: "eq" as const, value: "v", colour: "red" as const })) };
    renderScreen();
    await screen.findByText("s0");
    const add = async (set: string, value: string) => {
      await user.clear(screen.getByLabelText("Set"));
      await user.type(screen.getByLabelText("Set"), set);
      await user.clear(screen.getByLabelText("Value"));
      fireEvent.change(screen.getByLabelText("Value"), { target: { value } });
      await user.click(screen.getByRole("button", { name: "Add rule" }));
    };
    await add("new set", "v");
    expect(await screen.findByRole("alert")).toHaveTextContent("at most 50 highlight sets");
    await add("s0", "v");
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("at most 100 rules"));
    await add("s1", "x".repeat(1025));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("at most 1 KiB"));
    expect(m.set).not.toHaveBeenCalled();
    await add("s1", "é".repeat(512)); // 1024 bytes exactly is allowed
    await waitFor(() => expect(m.set).toHaveBeenCalledTimes(1));
  });

  it("two quick edits are saved one after the other, each on the previous result, and the UI ends on the stored state", async () => {
    let releaseFirst!: () => void;
    const calls: HighlightSet[][] = [];
    m.set.mockImplementation(async (_c, sets) => {
      calls.push(sets);
      if (calls.length === 1) await new Promise<void>((r) => (releaseFirst = r));
      stored = sets;
      return sets;
    });
    const user = userEvent.setup();
    renderScreen();
    await screen.findByText("No highlight sets for this case.");
    fireEvent.contextMenu(screen.getByText("198.51.100.7"));
    await user.click(screen.getByRole("menuitem", { name: "Highlight this value" }));
    fireEvent.contextMenu(screen.getByText("192.0.2.2"));
    await user.click(screen.getByRole("menuitem", { name: "Highlight this value" }));
    // The second change waits for the first; it is not sent on a stale copy.
    await waitFor(() => expect(m.set).toHaveBeenCalledTimes(1));
    expect(calls[0][0].rules).toHaveLength(1);
    await act(async () => {
      releaseFirst();
    });
    await waitFor(() => expect(m.set).toHaveBeenCalledTimes(2));
    expect(calls[1]).toHaveLength(1);
    expect(calls[1][0].rules.map((r) => r.value)).toEqual(["198.51.100.7", "192.0.2.2"]);
    await waitFor(() => expect(rowOf("192.0.2.2")).toHaveClass("hl-amber"));
    expect(rowOf("198.51.100.7")).toHaveClass("hl-amber");
    expect(stored[0].rules).toHaveLength(2);
  });

  it("a failed edit does not poison the next one", async () => {
    m.set.mockRejectedValueOnce({ kind: "internal", message: "disk full" } satisfies CmdError);
    const user = userEvent.setup();
    render(
      <HighlightsProvider caseId={CASE}>
        <HighlightsError />
        <Screen />
      </HighlightsProvider>,
    );
    await screen.findByText("No highlight sets for this case.");
    fireEvent.contextMenu(screen.getByText("198.51.100.7"));
    await user.click(screen.getByRole("menuitem", { name: "Highlight this value" }));
    expect((await screen.findAllByRole("alert"))[0]).toHaveTextContent("disk full");
    fireEvent.contextMenu(screen.getByText("192.0.2.2"));
    await user.click(screen.getByRole("menuitem", { name: "Highlight this value" }));
    await waitFor(() => expect(stored[0]?.rules.map((r) => r.value)).toEqual(["192.0.2.2"]));
  });

  it("changes are refused, not applied to an empty list, when the stored sets could not be loaded", async () => {
    m.get.mockRejectedValue({ kind: "internal", message: "settings unreadable" } satisfies CmdError);
    const user = userEvent.setup();
    renderScreen();
    await screen.findByText("settings unreadable");
    await user.type(screen.getByLabelText("Set"), "S");
    await user.type(screen.getByLabelText("Value"), "v");
    await user.click(screen.getByRole("button", { name: "Add rule" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("cannot be changed"));
    expect(m.set).not.toHaveBeenCalled();
  });
});
