import { describe, expect, it } from "vitest";
import type { IngestProgress } from "../api";
import { initialView, nonReading, reduce, secondsLeft, type FileStepEvent, type ImportView } from "./importProgress";

const S = 3_000_000_000;
const file = (index: number): IngestProgress => ({
  stage: "file", collection: 1, collections: 1, index, files: 3, rel_path: `f${index}.csv`, size: S,
  bytes_done_before: (index - 1) * S, bytes_total: 3 * S,
});
const step = (steps: string[], i: number, done: number): IngestProgress => ({
  stage: "file_step", steps, step: i, bytes_done: done, bytes_total: S, records: 0, errors: 0,
});
const CHECKING = ["Checking file"];
const UAL = ["Checking file", "Checking dates", "Loading records", "Saving records"];

/**
 * One file read at an even speed, a pass of it every 10 s, its steps list told late: "Checking file" alone through
 * the hash pass, then the three steps. The overall fraction and time left at every event (every 2.5 s).
 */
function lateSteps(): { overall: number[]; left: (number | null)[] } {
  let v: ImportView = initialView();
  const overall: number[] = [];
  const left: (number | null)[] = [];
  const at = (p: IngestProgress, ms: number) => {
    v = reduce(v, p, ms);
    overall.push(v.overall);
    left.push(secondsLeft(v));
  };
  at(file(1), 0);
  for (let pass = 0; pass < 3; pass++) {
    for (let q = 0; q <= 4; q++) {
      const ms = pass * 10_000 + q * 2_500;
      at(pass === 0 ? step(CHECKING, 0, (S * q) / 4) : step(UAL, pass, (S * q) / 4), ms);
    }
  }
  return { overall, left };
}

describe("import progress fold", () => {
  it("a steps list that grows from one to three does not freeze the overall bar for the rest of the file", () => {
    const { overall } = lateSteps();
    // The events of the last pass ("Loading records"): the bar moves during it, not only at its end.
    const loading = overall.slice(-5);
    expect(loading[2]).toBeGreaterThan(loading[0]);
    expect(loading[3]).toBeGreaterThan(loading[2]);
    expect(overall.every((o, i) => i === 0 || o >= overall[i - 1])).toBe(true);
  });

  it("the time left does not jump when the steps list grows", () => {
    const { left } = lateSteps();
    const shown = left.filter((l): l is number => l !== null);
    expect(shown.length).toBeGreaterThan(5);
    for (let i = 1; i < shown.length; i++) {
      const ratio = Math.max(shown[i], shown[i - 1]) / Math.min(shown[i], shown[i - 1]);
      expect(ratio, `time left ${shown[i - 1]} → ${shown[i]}`).toBeLessThanOrEqual(2);
    }
  });

  it("time left never counts bytes back when the total grows", () => {
    let v = reduce(initialView(), file(1), 0);
    v = reduce(v, step(UAL, 2, S), 10_000);
    const before = secondsLeft(v);
    // A copy expected to be skipped is parsed after all: the total grows, the bytes done stay.
    v = reduce(v, { ...(file(2) as Extract<IngestProgress, { stage: "file" }>), bytes_total: 6 * S }, 10_000);
    expect(v.bytesDone).toBe(S);
    expect(secondsLeft(v)).toBeGreaterThan(before ?? 0);
  });
});

describe("steps that read nothing", () => {
  const at = (i: number) => step(UAL, i, 0) as FileStepEvent;
  it("the merge and the detail sort are told apart from the passes", () => {
    expect(nonReading(at(3))).toBe("saving…");
    expect(nonReading(at(1))).toBeNull();
    expect(nonReading(at(2))).toBeNull();
    expect(nonReading(step(["Checking file", "Grouping messages", "Sorting messages"], 2, 0) as FileStepEvent)).toBe("sorting…");
    expect(nonReading(null)).toBeNull();
  });
  it("a merge step keeps the file's size as its total, so the fold still weighs the file", () => {
    let v = reduce(initialView(), file(1), 0);
    v = reduce(v, step(UAL, 3, 0), 1_000);
    // Three of four steps of a file that is a third of the import.
    expect(v.overall).toBeCloseTo(0.25);
    expect(v.step?.bytes_total).toBe(S);
  });
});
