// Sorting and filtering for a list that is already in memory, by any column: the tables of the Access, Accounts, Devices,
// Timeline and entity screens, and the grids that hold their rows (SQL results, a finding's evidence). A header click
// sorts (ascending, descending, off); a right-click, or the context-menu key, opens the column's filter: the column's
// values with counts and a contains box, or From/To date pickers on a date column. Nothing asks the backend, so a list
// that came in pages is filtered as far as it has loaded. The view is state of the screen and starts over with it.
import { useMemo, useState, type ReactNode } from "react";
import type { Sort } from "../api";
import { displaySafe } from "../text";
import Icon from "../ui/Icon";
import { rawText } from "../value";
import DateRangeFilter from "./DateRangeFilter";
import HeaderPopover from "./HeaderPopover";
import "../events/events.css";

export type ViewKind = "text" | "number" | "date";

export interface ViewColumn<T> {
  id: string;
  label: string;
  /** The value sorted and filtered on; null, undefined and "" are empty, and always sort last. */
  value: (row: T) => unknown;
  /** Worked out from the values when not given. */
  kind?: ViewKind;
  /** What it sorts by, when that is not the value (a severity's rank). */
  sortBy?: (row: T) => number | string | null;
}

type ColumnFilter = { type: "values"; values: string[]; exclude: boolean; contains: string } | { type: "date"; from?: string; to?: string };

const ISO_DATE = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}(?::?\d{2})?)?)?$/;

/** A time text as epoch ms, read as UTC when it names no offset; null when it is not one. */
export function instant(v: unknown): number | null {
  if (typeof v !== "string" || !ISO_DATE.test(v)) return null;
  let t = v.replace(" ", "T");
  if (t.length === 10) t += "T00:00:00Z";
  else if (!/(?:Z|[+-]\d{2}(?::?\d{2})?)$/.test(t)) t += "Z";
  t = t.replace(/([+-]\d{2})$/, "$1:00").replace(/\.(\d{3})\d+/, ".$1");
  const ms = Date.parse(t);
  return Number.isNaN(ms) ? null : ms;
}

const isEmpty = (v: unknown) => v === null || v === undefined || v === "";

/** How a column's values read: every one a time, or every one a number; a column with no values is text. */
export function kindOf(values: unknown[]): ViewKind {
  const some = values.filter((v) => !isEmpty(v));
  if (some.length === 0) return "text";
  if (some.every((v) => instant(v) !== null)) return "date";
  if (some.every((v) => typeof v === "number" || typeof v === "bigint")) return "number";
  return "text";
}

/** Empties last whichever way it sorts; numbers and times by value, text ignoring case. */
export function compareValues(a: unknown, b: unknown, kind: ViewKind, descending: boolean): number {
  if (isEmpty(a) || isEmpty(b)) return isEmpty(a) ? (isEmpty(b) ? 0 : 1) : -1;
  let c: number;
  if (kind === "date") c = (instant(a) ?? 0) - (instant(b) ?? 0);
  else if (typeof a === "number" && typeof b === "number") c = a - b;
  else c = rawText(a).localeCompare(rawText(b), "en-US", { sensitivity: "base", numeric: true });
  return descending ? -c : c;
}

function matches(filter: ColumnFilter, value: unknown): boolean {
  if (filter.type === "date") {
    const at = instant(value);
    if (at === null) return false;
    return (!filter.from || at >= (instant(filter.from) ?? at)) && (!filter.to || at <= (instant(filter.to) ?? at));
  }
  const text = rawText(value);
  const ticked = filter.values.length === 0 || filter.values.includes(text);
  const has = filter.contains === "" || text.toLowerCase().includes(filter.contains.toLowerCase());
  return (filter.exclude ? !ticked || filter.values.length === 0 : ticked) && has;
}

/** Values listed in a column's filter; the find box reaches the rest. */
const LISTED = 200;

function ValuesFilter({
  label,
  values,
  filter,
  onApply,
  onClose,
}: {
  label: string;
  values: unknown[];
  filter: Extract<ColumnFilter, { type: "values" }> | undefined;
  onApply: (f: ColumnFilter | undefined) => void;
  onClose: () => void;
}) {
  const [ticked, setTicked] = useState(filter?.values ?? []);
  const [exclude, setExclude] = useState(filter?.exclude ?? false);
  const [contains, setContains] = useState(filter?.contains ?? "");
  const [find, setFind] = useState("");
  const counts = useMemo(() => {
    const by = new Map<string, number>();
    for (const v of values) {
      const t = rawText(v);
      by.set(t, (by.get(t) ?? 0) + 1);
    }
    return [...by].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }, [values]);
  const needle = find.trim().toLowerCase();
  const found = counts.filter(([v]) => v.toLowerCase().includes(needle));
  const rows = [...ticked.map((v) => [v, counts.find(([c]) => c === v)?.[1] ?? 0] as const), ...found.filter(([v]) => !ticked.includes(v)).slice(0, LISTED)];
  const apply = () => {
    onApply(ticked.length === 0 && contains === "" ? undefined : { type: "values", values: ticked, exclude, contains });
    onClose();
  };
  return (
    <form
      className="colf"
      role="group"
      aria-label={`Filter ${label}`}
      onSubmit={(e) => {
        e.preventDefault();
        apply();
      }}
    >
      <div className="colf-head">
        <Icon name="filter" size={13} />
        <span className="label">Filter {displaySafe(label)}</span>
      </div>
      <span className="colf-find">
        <Icon name="search" size={13} />
        <input autoFocus aria-label="Find a value" placeholder="Find a value" autoComplete="off" spellCheck={false} value={find} onChange={(e) => setFind(e.target.value)} />
      </span>
      <ul className="colf-values plain" aria-label={`${label} values`}>
        {rows.map(([v, n]) => {
          const text = v === "" ? "(empty)" : displaySafe(v);
          return (
            <li key={v}>
              <label title={text}>
                <input
                  type="checkbox"
                  aria-label={text}
                  checked={ticked.includes(v)}
                  onChange={() => setTicked((t) => (t.includes(v) ? t.filter((x) => x !== v) : [...t, v]))}
                />
                <span className="colf-value">{text}</span>
                <span className="colf-count">{n.toLocaleString("en-US")}</span>
              </label>
            </li>
          );
        })}
      </ul>
      {found.length > LISTED && <p className="colf-meta">{`Showing ${LISTED} of ${found.length.toLocaleString("en-US")}; find narrows the list.`}</p>}
      <label className="colf-switch">
        <input type="checkbox" role="switch" checked={exclude} onChange={(e) => setExclude(e.target.checked)} />
        Exclude the ticked values
      </label>
      <label className="label">
        Contains
        <input className="colf-pattern" autoComplete="off" spellCheck={false} value={contains} onChange={(e) => setContains(e.target.value)} />
      </label>
      <div className="colf-actions">
        <button type="submit" className="btn btn-primary">
          Apply
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={filter === undefined}
          onClick={() => {
            onApply(undefined);
            onClose();
          }}
        >
          Clear filter
        </button>
      </div>
    </form>
  );
}

export interface ColumnView<T> {
  rows: T[];
  total: number;
  sort: Sort | null;
  onSort: (id: string) => void;
  /** Whether any column is filtered. */
  filtered: boolean;
  clearFilters: () => void;
  /** A column's filter panel (Grid's `headerPanel`); null for a column the view does not know. */
  panel: (id: string, close: () => void) => ReactNode | null;
  /** The icon a filtered column's title carries (Grid's `headerBadge`). */
  badge: (id: string) => ReactNode | null;
  /** What a right-click on a cell of the column offers (Grid's `panelLabel`). */
  panelLabel: (id: string) => string;
}

export function useColumnView<T>(rows: T[], columns: ViewColumn<T>[]): ColumnView<T> {
  const [sort, setSort] = useState<Sort | null>(null);
  const [filters, setFilters] = useState<Record<string, ColumnFilter>>({});
  const byId = useMemo(() => new Map(columns.map((c) => [c.id, c])), [columns]);
  const kinds = useMemo(() => new Map(columns.map((c) => [c.id, c.kind ?? kindOf(rows.map(c.value))])), [columns, rows]);
  const shown = useMemo(() => {
    const active = Object.entries(filters).flatMap(([id, f]) => {
      const c = byId.get(id);
      return c ? [[c, f] as const] : [];
    });
    const kept = active.length === 0 ? rows : rows.filter((r) => active.every(([c, f]) => matches(f, c.value(r))));
    const c = sort && byId.get(sort.column);
    if (!sort || !c) return kept;
    const key = c.sortBy ?? c.value;
    const kind = c.sortBy ? "number" : (kinds.get(c.id) ?? "text");
    return kept
      .map((r, i) => [r, i] as const)
      .sort(([a, i], [b, j]) => compareValues(key(a), key(b), kind, sort.descending) || i - j)
      .map(([r]) => r);
  }, [rows, filters, sort, byId, kinds]);
  const setFilter = (id: string, f: ColumnFilter | undefined) =>
    setFilters((all) => {
      const next = { ...all };
      if (f) next[id] = f;
      else delete next[id];
      return next;
    });
  return {
    rows: shown,
    total: rows.length,
    sort,
    onSort: (id) =>
      setSort((cur) => (cur?.column !== id ? { column: id, descending: false } : cur.descending ? null : { column: id, descending: true })),
    filtered: Object.keys(filters).some((id) => byId.has(id)),
    clearFilters: () => setFilters({}),
    panel: (id, close) => {
      const c = byId.get(id);
      if (!c) return null;
      const f = filters[id];
      if (kinds.get(id) === "date") {
        const range = f?.type === "date" ? f : undefined;
        return (
          <DateRangeFilter
            key={id}
            label={c.label}
            from={range?.from}
            to={range?.to}
            onApply={(from, to) => setFilter(id, from || to ? { type: "date", from, to } : undefined)}
            onClose={close}
          />
        );
      }
      return <ValuesFilter key={id} label={c.label} values={rows.map(c.value)} filter={f?.type === "values" ? f : undefined} onApply={(n) => setFilter(id, n)} onClose={close} />;
    },
    badge: (id) => {
      const c = byId.get(id);
      return c && filters[id] ? <FilteredIcon label={c.label} /> : null;
    },
    panelLabel: (id) => (kinds.get(id) === "date" ? "Filter by date…" : "Filter this column…"),
  };
}

function FilteredIcon({ label }: { label: string }) {
  const title = `${displaySafe(label)} is filtered`;
  return (
    <span className="grid-badge colf-badge" role="img" aria-label={title} title={title}>
      <Icon name="filter" size={12} />
    </span>
  );
}

/** "Showing 3 of 85", with the way out: a filter can leave no rows, and some screens then hide their headers. */
export function ViewNote<T>({ view }: { view: ColumnView<T> }) {
  if (!view.filtered) return null;
  return (
    <p className="meta view-note" role="status">
      {`Showing ${view.rows.length.toLocaleString("en-US")} of ${view.total.toLocaleString("en-US")}`}{" "}
      <button type="button" className="link" onClick={view.clearFilters}>
        Clear filters
      </button>
    </p>
  );
}

/**
 * A plain table's header row cell that sorts and filters through a view, and the popover it opens. One `useViewHeaders`
 * serves every table of the view (the Timeline's phases).
 */
export function useViewHeaders<T>(view: ColumnView<T>, columns: ViewColumn<T>[]) {
  const [open, setOpen] = useState<{ x: number; y: number; id: string; opener: HTMLElement | null } | null>(null);
  const close = () => {
    open?.opener?.focus();
    setOpen(null);
  };
  const header = (id: string, props?: { className?: string; title?: string }) => {
    const c = columns.find((x) => x.id === id);
    if (!c) return null;
    const sorted = view.sort?.column === id ? (view.sort.descending ? "descending" : "ascending") : undefined;
    return (
      <th
        key={id}
        className={props?.className}
        title={props?.title}
        aria-sort={sorted ?? "none"}
        onContextMenu={(e) => {
          e.preventDefault();
          setOpen({ x: e.clientX, y: e.clientY, id, opener: e.currentTarget.querySelector("button") });
        }}
      >
        <button
          type="button"
          className="grid-sort"
          onClick={() => view.onSort(id)}
          onKeyDown={(e) => {
            if (e.key !== "ContextMenu" && !(e.key === "F10" && e.shiftKey)) return;
            e.preventDefault();
            const b = e.currentTarget.getBoundingClientRect();
            setOpen({ x: b.left, y: b.bottom, id, opener: e.currentTarget });
          }}
        >
          {c.label}
          <span aria-hidden="true">{sorted === "ascending" ? " ▲" : sorted === "descending" ? " ▼" : ""}</span>
        </button>
        {view.badge(id)}
      </th>
    );
  };
  const popover = open && (
    <HeaderPopover x={open.x} y={open.y} label={`${columns.find((c) => c.id === open.id)?.label ?? ""} column`} panel={view.panel(open.id, close)} items={[]} onClose={close} />
  );
  return { header, popover };
}
