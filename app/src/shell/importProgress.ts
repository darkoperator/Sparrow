// What the import dialog shows while an import runs, folded from the `ingest-progress` events: the stage, the file
// being loaded and where it is, the overall fraction (never going back), and a time-left estimate.
import type { IngestProgress } from "../api";

export type FileEvent = Extract<IngestProgress, { stage: "file" }>;
export type FileStepEvent = Extract<IngestProgress, { stage: "file_step" }>;

export interface ImportView {
  /** The last stage event (`file_step` events are folded into `step`, not kept here). */
  stage: IngestProgress | null;
  /** The file being handled. */
  file: FileEvent | null;
  /** Where that file is; `null` until its first `file_step` (some files get none: refused before they are read). */
  step: FileStepEvent | null;
  /** Overall fraction shown, in [0, 1]: the largest computed so far, so it never goes back when the total grows. */
  overall: number;
  /** When the first file started (clock ms) and the bytes done then, and the bytes done by the last event: the rate
   * for the time left. */
  since: number | null;
  sinceBytes: number;
  bytesDone: number;
  /** Clock ms of the last event. */
  at: number;
}

export const initialView = (): ImportView => ({ stage: null, file: null, step: null, overall: 0, since: null, sinceBytes: 0, bytesDone: 0, at: 0 });

const clamp01 = (v: number) => (Number.isFinite(v) ? Math.min(1, Math.max(0, v)) : 0);

/** Step 0 of every file, the admission read. */
const CHECKING_FILE = "Checking file";

/**
 * How far through its passes the file is, in [0, 1]: the steps before the current one are done, the current one is
 * `bytes_done / bytes_total` through. Each pass counts the same, so a file read three times fills once, not thrice.
 * A list that is still only "Checking file" counts as two steps: the core tells a file's parser steps from the first
 * event (a file it is only hashing has no others), but the hash pass must never claim the whole file if a list grows.
 */
export function fileFraction(step: FileStepEvent | null): number {
  if (!step || step.steps.length === 0) return 0;
  const within = step.bytes_total > 0 ? clamp01(step.bytes_done / step.bytes_total) : 0;
  const count = step.steps.length === 1 && step.steps[0] === CHECKING_FILE ? 2 : step.steps.length;
  return clamp01((Math.min(step.step, step.steps.length - 1) + within) / count);
}

/** Steps that read nothing (one long statement over what the passes staged): they report only their start and end,
 * so their bar is shown as indeterminate, with what they do instead of a byte count. Name → what the line says. */
const NON_READING_STEPS: Record<string, string> = { "Sorting messages": "sorting…", "Saving records": "saving…" };

/** What the current step is doing when it reads nothing (`"saving…"`), or `null` for a step that reads the file. */
export function nonReading(step: FileStepEvent | null): string | null {
  if (!step) return null;
  return NON_READING_STEPS[step.steps[step.step] ?? ""] ?? null;
}

/** This file's bar: the current pass, `bytes_done / bytes_total`. */
export const passFraction = (step: FileStepEvent | null): number =>
  step && step.bytes_total > 0 ? clamp01(step.bytes_done / step.bytes_total) : 0;

/** Bytes of the import done: the files before this one, and this one's share by its passes. The view keeps the
 * largest so far, so the bar and the time left read the same never-decreasing count. */
function bytesDone(file: FileEvent, step: FileStepEvent | null): number {
  return file.bytes_done_before + fileFraction(step) * file.size;
}

export function reduce(view: ImportView, p: IngestProgress, now: number): ImportView {
  switch (p.stage) {
    case "file": {
      // A new file: its view starts empty, whatever the last one reached.
      const done = bytesDone(p, null);
      return {
        ...view,
        stage: p,
        file: p,
        step: null,
        overall: Math.max(view.overall, p.bytes_total > 0 ? clamp01(done / p.bytes_total) : 0),
        since: view.since ?? now,
        sinceBytes: view.since === null ? done : view.sinceBytes,
        bytesDone: Math.max(view.bytesDone, done),
        at: now,
      };
    }
    case "file_step": {
      if (!view.file) return { ...view, step: p, at: now };
      const done = bytesDone(view.file, p);
      const total = view.file.bytes_total;
      return {
        ...view,
        step: p,
        overall: Math.max(view.overall, total > 0 ? clamp01(done / total) : 0),
        bytesDone: Math.max(view.bytesDone, done),
        at: now,
      };
    }
    default:
      return { ...view, stage: p, at: now };
  }
}

/** Data needed before a time left is shown. */
export const MIN_RATE_MS = 5_000;

/** Seconds left at the overall byte rate so far, or `null` (under 5 s of data, nothing done yet, or no total). */
export function secondsLeft(view: ImportView): number | null {
  if (view.since === null || !view.file) return null;
  const elapsed = view.at - view.since;
  const moved = view.bytesDone - view.sinceBytes;
  const left = view.file.bytes_total - view.bytesDone;
  if (elapsed < MIN_RATE_MS || moved <= 0 || left <= 0) return null;
  return (left * elapsed) / moved / 1000;
}

export function timeLeftText(seconds: number | null): string | null {
  if (seconds === null || !Number.isFinite(seconds)) return null;
  if (seconds < 60) return `~${Math.max(1, Math.round(seconds))} s left`;
  const min = Math.round(seconds / 60);
  if (min < 60) return `~${min} min left`;
  return `~${Math.floor(min / 60)} h ${min % 60} min left`;
}
