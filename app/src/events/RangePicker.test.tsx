import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import RangePicker from "./RangePicker";

function open(value: string, end: "from" | "to" = "from") {
  const onPick = vi.fn();
  render(<RangePicker end={end} value={value} onPick={onPick} />);
  fireEvent.click(screen.getByRole("button", { name: end === "from" ? "Pick From date" : "Pick To date" }));
  return onPick;
}

const date = (end = "From") => screen.getByLabelText(`${end} date (UTC)`);
const time = (end = "From") => screen.getByLabelText(`${end} time (UTC)`);

describe("RangePicker", () => {
  it("opens_on_the_boxes_value", () => {
    open("2026-10-23T14:30:00Z");
    expect(date()).toHaveValue("2026-10-23");
    expect(time()).toHaveValue("14:30");
  });

  it("date_only_writes_the_day", async () => {
    const onPick = open("");
    fireEvent.change(date(), { target: { value: "2026-10-23" } });
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(onPick).toHaveBeenCalledWith("2026-10-23");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("date_and_time_write_the_minute", async () => {
    const onPick = open("", "to");
    fireEvent.change(date("To"), { target: { value: "2026-10-23" } });
    fireEvent.change(time("To"), { target: { value: "09:05" } });
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(onPick).toHaveBeenCalledWith("2026-10-23T09:05");
  });

  it("an_unreadable_box_opens_empty", () => {
    open("garbage");
    expect(date()).toHaveValue("");
    expect(time()).toHaveValue("");
  });

  it("escape_closes_without_writing", () => {
    const onPick = open("2026-10-23");
    fireEvent.keyDown(date(), { key: "Escape" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(onPick).not.toHaveBeenCalled();
  });

  it("an_empty_date_applies_nothing", async () => {
    const onPick = open("");
    fireEvent.change(time(), { target: { value: "09:05" } });
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(onPick).not.toHaveBeenCalled();
  });

  it("midnight_new_year_is_not_shifted", async () => {
    // A local-time conversion would move this to 2025-12-31 in any zone west of UTC.
    const onPick = open("");
    fireEvent.change(date(), { target: { value: "2026-01-01" } });
    fireEvent.change(time(), { target: { value: "00:00" } });
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(onPick).toHaveBeenCalledWith("2026-01-01T00:00");
  });

  it.each([
    ["from", "2026-10-23T14:30:36Z"],
    ["to", "2026-10-23T14:30:36Z"],
  ] as const)("an_untouched_apply_keeps_a_%s_with_seconds", async (end, value) => {
    const onPick = open(value, end);
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(onPick).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("enter_on_clear_time_clears_the_time", async () => {
    const onPick = open("2026-10-23T14:30:00Z");
    screen.getByRole("button", { name: "Clear time" }).focus();
    await userEvent.keyboard("{Enter}");
    expect(time()).toHaveValue("");
    expect(onPick).not.toHaveBeenCalled();
  });

  it("enter_in_the_date_box_applies", async () => {
    const onPick = open("");
    fireEvent.change(date(), { target: { value: "2026-10-23" } });
    fireEvent.keyDown(date(), { key: "Enter" });
    expect(onPick).toHaveBeenCalledWith("2026-10-23");
  });

  it.each([
    ["to", "2026-10-23T23:59:59.999999Z"],
    ["from", "2026-10-23T00:00:00Z"],
  ] as const)("a_canonical_whole_day_%s_opens_without_a_time", (end, value) => {
    open(value, end);
    expect(date(end === "from" ? "From" : "To")).toHaveValue("2026-10-23");
    expect(time(end === "from" ? "From" : "To")).toHaveValue("");
  });

  it("escape_returns_focus_to_the_button", () => {
    open("2026-10-23");
    fireEvent.keyDown(date(), { key: "Escape" });
    expect(screen.getByRole("button", { name: "Pick From date" })).toHaveFocus();
  });
});
