// A grid's column layout: the order the analyst dragged the columns into and the widths they resized them to, kept per
// grid in localStorage (every read and write in try/catch; a failure or junk means the defaults). Columns are keyed by
// name (a repeated name gets "#2", "#3"…), so a saved layout survives columns being added, removed or reordered in code.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

export const MIN_WIDTH = 60;
export const MAX_WIDTH = 2000;
const SAVE_DELAY_MS = 250;

export interface SavedLayout {
  /** Column keys in the order shown; keys that no longer exist are ignored, new ones go last. */
  order: string[];
  widths: Record<string, number>;
}

const storageKey = (id: string) => `sparrow.grid.layout.v1.${id}`;
const empty = (): SavedLayout => ({ order: [], widths: {} });

export function loadJson(key: string): unknown {
  try {
    const raw = localStorage.getItem(key);
    return raw === null ? null : JSON.parse(raw);
  } catch {
    return null;
  }
}
export function saveJson(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage unavailable: the layout lasts until the grid is closed */
  }
}
export function removeJson(key: string) {
  try {
    localStorage.removeItem(key);
  } catch {
    /* storage unavailable */
  }
}

export function readLayout(id: string | undefined): SavedLayout {
  if (id === undefined) return empty();
  const v = loadJson(storageKey(id)) as Partial<SavedLayout> | null;
  const order = Array.isArray(v?.order) ? v.order.filter((x): x is string => typeof x === "string") : [];
  const widths: Record<string, number> = {};
  if (v?.widths && typeof v.widths === "object" && !Array.isArray(v.widths)) {
    for (const [k, w] of Object.entries(v.widths)) {
      if (typeof w === "number" && Number.isFinite(w) && w > 0) widths[k] = Math.min(Math.max(w, MIN_WIDTH), MAX_WIDTH);
    }
  }
  return { order, widths };
}

/** Unique keys for column names: the name, or the name with `#n` for its nth repeat. */
export function columnKeys(names: string[]): string[] {
  const seen = new Map<string, number>();
  return names.map((n) => {
    const k = (seen.get(n) ?? 0) + 1;
    seen.set(n, k);
    return k === 1 ? n : `${n}#${k}`;
  });
}

export interface GridLayout {
  /** Display position to source column index. */
  order: number[];
  /** The width of the column at this display position. */
  widthAt: (display: number) => number;
  /** Widths from the table (by display position); only those that differ from what is shown are stored. */
  setWidths: (byDisplay: Record<string, number>) => void;
  /** Move the column at one display position to another (rightwards lands after the target, leftwards before). */
  move: (from: number, to: number) => void;
  /** Whether the layout differs from the defaults. */
  changed: boolean;
  reset: () => void;
}

export function useGridLayout(id: string | undefined, names: string[], defaults: Record<string, number> | undefined, fallbackWidth: number): GridLayout {
  // The saved layout is read once per grid id; a new id (another table in the same grid) loads its own.
  // `edits` counts the analyst's changes, so that loading a layout is not mistaken for one (and not written back).
  const [state, setState] = useState(() => ({ id, layout: readLayout(id), edits: 0 }));
  if (state.id !== id) setState((s) => ({ id, layout: readLayout(id), edits: s.edits }));
  const layout = state.id === id ? state.layout : readLayout(id);
  const setLayout = useCallback(
    (f: (l: SavedLayout) => SavedLayout) =>
      setState((s) => {
        const next = f(s.layout);
        return next === s.layout ? s : { ...s, layout: next, edits: s.edits + 1 };
      }),
    [],
  );

  const keys = useMemo(() => columnKeys(names), [names]);
  const order = useMemo(() => {
    const at = new Map(keys.map((k, i) => [k, i]));
    const out: number[] = [];
    const used = new Set<number>();
    for (const k of layout.order) {
      const i = at.get(k);
      if (i !== undefined && !used.has(i)) {
        out.push(i);
        used.add(i);
      }
    }
    for (let i = 0; i < keys.length; i++) if (!used.has(i)) out.push(i);
    return out;
  }, [keys, layout.order]);

  const widthOf = useCallback(
    (src: number) => {
      const w = layout.widths[keys[src]] ?? defaults?.[names[src]] ?? fallbackWidth;
      return Math.min(Math.max(w, MIN_WIDTH), MAX_WIDTH);
    },
    [layout.widths, keys, names, defaults, fallbackWidth],
  );
  const widthAt = useCallback((display: number) => widthOf(order[display]), [widthOf, order]);

  const setWidths = useCallback(
    (byDisplay: Record<string, number>) => {
      setLayout((l) => {
        const widths = { ...l.widths };
        let same = true;
        for (const [d, w] of Object.entries(byDisplay)) {
          const src = order[Number(d)];
          if (src === undefined || !Number.isFinite(w)) continue;
          const next = Math.min(Math.max(Math.round(w), MIN_WIDTH), MAX_WIDTH);
          if (widths[keys[src]] !== next && widthOf(src) !== next) {
            widths[keys[src]] = next;
            same = false;
          }
        }
        return same ? l : { ...l, widths };
      });
    },
    [setLayout, order, keys, widthOf],
  );

  const move = useCallback(
    (from: number, to: number) => {
      if (from === to || from < 0 || to < 0 || from >= order.length || to >= order.length) return;
      setLayout((l) => {
        const cur = order.map((i) => keys[i]);
        const moved = cur[from];
        const next = cur.filter((_, i) => i !== from);
        next.splice(to, 0, moved);
        return { ...l, order: next };
      });
    },
    [setLayout, order, keys],
  );

  const pending = useRef<{ id: string; layout: SavedLayout } | null>(null);
  const flush = useCallback(() => {
    const p = pending.current;
    pending.current = null;
    if (!p) return;
    // Back to the defaults leaves nothing stored.
    if (p.layout.order.length === 0 && Object.keys(p.layout.widths).length === 0) removeJson(storageKey(p.id));
    else saveJson(storageKey(p.id), p.layout);
  }, []);
  const reset = useCallback(() => {
    if (id !== undefined) removeJson(storageKey(id));
    pending.current = null;
    setLayout(() => empty());
  }, [id, setLayout]);

  // An edit is saved shortly after the last one (a resize is many); the layout of an id that is being left, or of a grid
  // going away, is saved at once. Opening a grid, or switching to another id, writes nothing.
  const { id: stateId, layout: stateLayout, edits } = state;
  useEffect(() => {
    if (edits === 0 || stateId === undefined) return;
    pending.current = { id: stateId, layout: stateLayout };
    const t = setTimeout(flush, SAVE_DELAY_MS);
    return () => clearTimeout(t);
    // Only a new edit saves; `stateId` and `stateLayout` are read as they are at that edit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edits]);
  useEffect(() => flush, [stateId, flush]);

  const changed = layout.order.length > 0 || Object.keys(layout.widths).length > 0;
  return { order, widthAt, setWidths, move, changed, reset };
}
