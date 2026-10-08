// The highlights every Grid in the app applies: the analyst's named sets for the open case (kept in the app's local
// settings by the backend, never in the case) plus the built-in "Highlight indicators" set computed from the case's
// active IOCs (never stored). Which sets are switched on is session state.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  highlightsClear,
  highlightsGet,
  highlightsSet,
  indicatorsActive,
  isCmdError,
  type ActiveIndicator,
  type HighlightRule,
  type HighlightSet,
} from "../api";
import { displaySafe } from "../text";
import { rawText } from "../value";

/** The set "Highlight this value" in a grid's cell menu adds to. */
export const QUICK_SET = "Quick highlights";

export const MAX_SETS = 50;
export const MAX_RULES = 100;
export const MAX_VALUE_BYTES = 1024;

/** The backend's caps, checked before a save so the analyst gets the answer at once. */
export function capError(sets: HighlightSet[]): string | null {
  if (sets.length > MAX_SETS) return `a case can have at most ${MAX_SETS} highlight sets`;
  for (const s of sets) {
    if (s.rules.length > MAX_RULES) return `a highlight set can have at most ${MAX_RULES} rules`;
    for (const r of s.rules) {
      if (new TextEncoder().encode(r.value).length > MAX_VALUE_BYTES) return "a highlight value can be at most 1 KiB";
    }
  }
  return null;
}

export interface HighlightsApi {
  sets: HighlightSet[];
  /** A set is on unless its name is here. */
  off: ReadonlySet<string>;
  indicatorsOn: boolean;
  indicators: ActiveIndicator[];
  /** Every rule currently in force, in order: stored sets first, then the indicator rules. */
  rules: HighlightRule[];
  error: string | null;
  /**
   * Changes the stored sets. Changes run one at a time and each is computed from the result of the previous save, so
   * two quick edits both survive; a refused or failed change leaves the stored sets as they were. True when saved.
   */
  update: (change: (current: HighlightSet[]) => HighlightSet[]) => Promise<boolean>;
  clear: () => Promise<boolean>;
  toggleSet: (name: string) => void;
  setIndicatorsOn: (on: boolean) => void;
  /** Adds an `eq` rule on the raw cell value to the quick set. */
  highlightValue: (column: string | null, value: unknown) => Promise<boolean>;
}

const HighlightsContext = createContext<HighlightsApi | null>(null);

/** Null outside a provider (a unit test, the case-open screen): grids then colour nothing of their own. */
export const useHighlights = () => useContext(HighlightsContext);

export function indicatorRules(list: ActiveIndicator[]): HighlightRule[] {
  return list.map((i) => ({
    column: null,
    op: "eq",
    value: i.value,
    colour: i.verdict === "malicious" ? "red" : "amber",
  }));
}

const message = (e: unknown) => (isCmdError(e) ? e.message : String(e));

export function HighlightsProvider({ caseId, children }: { caseId: string; children: ReactNode }) {
  const [sets, setSets] = useState<HighlightSet[]>([]);
  const [off, setOff] = useState<ReadonlySet<string>>(new Set());
  const [indicatorsOn, setIndicatorsOn] = useState(true);
  const [indicators, setIndicators] = useState<ActiveIndicator[]>([]);
  const [error, setError] = useState<string | null>(null);
  // The sets as last confirmed by the backend (null until loaded) and the tail of the save queue.
  const confirmed = useRef<HighlightSet[] | null>(null);
  const queue = useRef<Promise<unknown>>(Promise.resolve());

  useEffect(() => {
    let live = true;
    confirmed.current = null;
    queue.current = highlightsGet(caseId).then(
      (s) => {
        confirmed.current = s;
        if (live) setSets(s);
      },
      (e: unknown) => {
        if (live) setError(message(e));
      },
    );
    indicatorsActive().then(
      (i) => live && setIndicators(i),
      (e: unknown) => live && setError(message(e)),
    );
    return () => {
      live = false;
    };
  }, [caseId]);

  /** Runs `work` after every earlier change has finished. */
  const enqueue = useCallback((work: () => Promise<boolean>) => {
    const run = queue.current.then(work);
    queue.current = run.catch(() => false);
    return run;
  }, []);

  const update = useCallback(
    (change: (current: HighlightSet[]) => HighlightSet[]) =>
      enqueue(async () => {
        const base = confirmed.current;
        if (base === null) {
          setError("the highlights could not be loaded, so they cannot be changed");
          return false;
        }
        const next = change(base);
        const tooBig = capError(next);
        if (tooBig) {
          setError(tooBig);
          return false;
        }
        try {
          const saved = await highlightsSet(caseId, next);
          confirmed.current = saved;
          setSets(saved);
          setError(null);
          return true;
        } catch (e) {
          setError(message(e));
          return false;
        }
      }),
    [caseId, enqueue],
  );

  const clear = useCallback(
    () =>
      enqueue(async () => {
        try {
          await highlightsClear(caseId);
          confirmed.current = [];
          setSets([]);
          setError(null);
          return true;
        } catch (e) {
          setError(message(e));
          return false;
        }
      }),
    [caseId, enqueue],
  );

  const toggleSet = useCallback((name: string) => {
    setOff((o) => {
      const n = new Set(o);
      if (!n.delete(name)) n.add(name);
      return n;
    });
  }, []);

  const highlightValue = useCallback(
    (column: string | null, value: unknown) => {
      const rule: HighlightRule = { column, op: "eq", value: rawText(value), colour: "amber" };
      return update((current) =>
        current.some((s) => s.name === QUICK_SET)
          ? current.map((s) => (s.name === QUICK_SET ? { ...s, rules: [...s.rules, rule] } : s))
          : [...current, { name: QUICK_SET, rules: [rule] }],
      );
    },
    [update],
  );

  const rules = useMemo(
    () => [
      ...sets.filter((s) => !off.has(s.name)).flatMap((s) => s.rules),
      ...(indicatorsOn ? indicatorRules(indicators) : []),
    ],
    [sets, off, indicatorsOn, indicators],
  );

  const api = useMemo<HighlightsApi>(
    () => ({ sets, off, indicatorsOn, indicators, rules, error, update, clear, toggleSet, setIndicatorsOn, highlightValue }),
    [sets, off, indicatorsOn, indicators, rules, error, update, clear, toggleSet, highlightValue],
  );
  return <HighlightsContext.Provider value={api}>{children}</HighlightsContext.Provider>;
}

/** The provider's last error where the analyst is working, for actions started from any screen (a grid's menu). */
export function HighlightsError() {
  const hl = useHighlights();
  if (!hl?.error) return null;
  return <div role="alert">{displaySafe(hl.error)}</div>;
}
