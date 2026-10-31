import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import AgentChip, { LIT_MS } from "./AgentChip";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("AgentChip", () => {
  it("agent_chip_shows_the_last_request", () => {
    vi.useFakeTimers();
    const at = new Date("2026-10-30T12:00:00Z");
    vi.setSystemTime(at);
    const { rerender } = render(<AgentChip activity={null} />);
    expect(screen.queryByRole("status", { name: /agent/i })).toBeNull();

    rerender(<AgentChip activity={{ agent: "claude", command: "mark tag", at: at.toISOString(), running: true }} />);
    const chip = screen.getByRole("status", { name: /agent/i });
    expect(chip).toHaveTextContent("claude");
    expect(chip).toHaveAttribute("data-lit", "true");
    expect(chip).toHaveAttribute("data-running", "true");
    expect(chip.title).toContain("mark tag");

    rerender(<AgentChip activity={{ agent: "claude", command: "mark tag", at: at.toISOString(), running: false }} />);
    expect(screen.getByRole("status", { name: /agent/i })).toHaveAttribute("data-running", "false");
    expect(screen.getByRole("status", { name: /agent/i })).toHaveAttribute("data-lit", "true");
    // Ten minutes after the last request it dims, and stays as a record of it.
    act(() => {
      vi.advanceTimersByTime(LIT_MS + 1000);
    });
    expect(screen.getByRole("status", { name: /agent/i })).toHaveAttribute("data-lit", "false");
  });

  it("says just Agent without an agent id", () => {
    render(<AgentChip activity={{ agent: null, command: "events", at: new Date().toISOString(), running: false }} />);
    expect(screen.getByRole("status", { name: /agent/i })).toHaveTextContent(/^Agent$/);
  });
});
