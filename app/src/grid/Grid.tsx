// The shared grid: a virtualised table of read-only cells. Every cell is rendered as text through `displaySafe`;
// nothing here interprets cell content. Rows are positional (`unknown[][]`) so the same grid serves evidence, pivot
// sections, the table browser and SQL results.
import { createColumnHelper, flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { HIGHLIGHT_COLOURS, type HighlightRule, type Sort } from "../api";
import { useHighlights } from "../highlights/useHighlights";
import { useNav } from "../shell/nav";
import { displaySafe } from "../text";
import { entityKindFor, rawText } from "../value";
import CellMenu, { type MenuItem } from "./CellMenu";
import { useGridLayout } from "./gridLayout";
import "./grid.css";
import ValueViewer from "./ValueViewer";

export type Cell = unknown;

/** What the host does with a cell value; an action the host does not give is not offered. */
export interface CellActions {
  onFilter?: (column: string, value: Cell) => void;
  onHighlight?: (column: string, value: Cell) => void;
}

/** A cell as the host sees it: the column, its value, and the index of its row in `rows`. */
export interface CellRef {
  column: string;
  value: Cell;
  row: number;
}

export interface GridProps {
  columns: string[];
  rows: Cell[][];
  cellActions?: CellActions;
  /** Column sort: the current sort, and a click on a header. Without `onSort` headers are plain text. */
  sort?: Sort | null;
  onSort?: (column: string) => void;
  /** Called when the visible window comes within a screenful of the last row (the host fetches the next page). */
  onNearEnd?: () => void;
  /** Rows holding a cell that matches a rule get the rule's colour class (the first matching rule wins). */
  highlights?: HighlightRule[];
  onRowClick?: (row: Cell[], index: number) => void;
  /** Header text per column, where it differs from the column name (which stays the key for sorting and rules). */
  labels?: Record<string, string>;
  /** Starting width in px per column; the default applies to the rest. */
  widths?: Record<string, number>;
  /** Which headers sort (with `onSort`); every header does by default. */
  sortable?: (column: string) => boolean;
  /** Content for a cell in place of its text (returned `undefined`: the text). The host passes safe nodes only. */
  renderCell?: (cell: CellRef) => ReactNode | undefined;
  /** An extra class for a row, by its index in `rows`. */
  rowClass?: (row: number) => string | undefined;
  /**
   * The host's own menu items for a cell. When given, they replace the built-in "Filter by this value" and "Open … tab"
   * items (the host knows the real value behind the text); Copy, Show full value and Highlight stay.
   */
  cellItems?: (cell: CellRef) => MenuItem[];
  /**
   * Names this grid's layout: the order the analyst dragged the columns into and their widths are remembered under it
   * (localStorage, per grid). Without one the layout still works but lasts only while the grid is shown.
   */
  layoutId?: string;
  /**
   * The identity of the row at an index (the host's key for its event). A cell menu remembers the identity of the row it
   * was opened on and closes itself when that index later holds another row (a sort, a filter, a reload), so an item can
   * never act on a row the analyst did not right-click.
   */
  rowId?: (row: number) => string | undefined;
  /** A cell menu was opened on this cell (before its items are asked for): the host snapshots what it acts on here. */
  onMenuOpen?: (cell: { column: string; row: number }) => void;
  /**
   * The name of a first column that stays put: not draggable, not resizable (its width is `widths[name]`), left out of
   * the saved layout and untouched by "Reset columns". Ignored when it is not the first column.
   */
  pinnedFirst?: string;
  /** Called after "Reset columns", for a host that keeps more column state (which are shown) to reset it too. */
  onResetColumns?: () => void;
  /**
   * A panel for a column's header popover (a column filter). When it gives one, a right-click (or the context-menu key)
   * on the header opens it above the column items (move, reset); `close` closes the popover. `null`: the plain menu.
   */
  headerPanel?: (column: string, close: () => void) => ReactNode | null;
  /** Shown in a column's header after its title (a filter icon); the host passes safe nodes only. */
  headerBadge?: (column: string) => ReactNode | null;
  /** Height of the scrolling body in px. */
  height?: number;
}

const ROW_HEIGHT = 33;
const DEFAULT_COLUMN_WIDTH = 180;
const MIN_COLUMN_WIDTH = 60;

export function cellText(v: Cell): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return displaySafe(v);
  if (typeof v === "object") return displaySafe(JSON.stringify(v));
  return displaySafe(String(v));
}

/** The palette class for a rule colour; anything outside the palette gets none, so data never picks a class. */
function colourClass(colour: string): string | undefined {
  return (HIGHLIGHT_COLOURS as readonly string[]).includes(colour) ? `hl-${colour}` : undefined;
}

/** Matches on the RAW value, never on what is displayed. */
function ruleMatches(rule: HighlightRule, columns: string[], row: Cell[]): boolean {
  const test = (v: Cell) => {
    const raw = rawText(v);
    return rule.op === "eq" ? raw === rule.value : raw.toLowerCase().includes(rule.value.toLowerCase());
  };
  if (rule.column === null) return row.some(test);
  const at = columns.indexOf(rule.column);
  return at >= 0 && test(row[at]);
}

/**
 * A header's popover: the host's panel above the column items, at a fixed position kept inside the window. Escape or a
 * click elsewhere closes it; the panel takes the focus itself.
 */
function HeaderPopover({
  x,
  y,
  label,
  panel,
  items,
  onClose,
}: {
  x: number;
  y: number;
  label: string;
  panel: ReactNode;
  items: MenuItem[];
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [at, setAt] = useState({ x, y });
  useEffect(() => {
    const away = (e: Event) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [onClose]);
  // Kept inside the window, again whenever the panel changes size (its list loads after it opens).
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const fit = () => {
      const r = el.getBoundingClientRect();
      if (r.width === 0) return;
      const nx = Math.max(4, Math.min(x, window.innerWidth - r.width - 4));
      const ny = Math.max(4, Math.min(y, window.innerHeight - r.height - 4));
      setAt((at) => (at.x === nx && at.y === ny ? at : { x: nx, y: ny }));
    };
    fit();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    return () => ro.disconnect();
  }, [x, y]);
  return (
    <div
      ref={ref}
      role="dialog"
      aria-label={label}
      className="grid-header-pop"
      style={{ position: "fixed", left: at.x, top: at.y }}
      onKeyDown={(e) => {
        if (e.key !== "Escape") return;
        e.stopPropagation();
        onClose();
      }}
    >
      {panel}
      <div role="menu" aria-label="Column" className="grid-header-pop-items">
        {items.map((it) => (
          <button
            key={it.label}
            type="button"
            role="menuitem"
            onClick={() => {
              it.run?.();
              onClose();
            }}
          >
            {it.label}
          </button>
        ))}
      </div>
    </div>
  );
}

interface MenuAt {
  x: number;
  y: number;
  row: number;
  col: number;
  /** The identity of the row when the menu opened (`rowId`). */
  id: string | undefined;
}

const NEAR_END = 40;

export default function Grid({
  columns: srcColumns,
  rows: srcRows,
  cellActions,
  highlights,
  sort,
  onSort,
  onNearEnd,
  onRowClick,
  labels,
  widths,
  sortable,
  renderCell,
  rowClass: hostRowClass,
  cellItems,
  layoutId,
  pinnedFirst,
  rowId,
  onMenuOpen,
  onResetColumns,
  headerPanel,
  headerBadge,
  height = 320,
}: GridProps) {
  const nav = useNav();
  // The analyst's column order: from here on `columns` and `rows` are in the order shown; `srcRows` are as given.
  // A pinned first column is kept out of the layout: `off` is how many leading columns the layout does not know.
  const off = pinnedFirst !== undefined && srcColumns[0] === pinnedFirst ? 1 : 0;
  const movable = useMemo(() => (off ? srcColumns.slice(1) : srcColumns), [off, srcColumns]);
  const layout = useGridLayout(layoutId, movable, widths, DEFAULT_COLUMN_WIDTH);
  const columns = useMemo(() => [...srcColumns.slice(0, off), ...layout.order.map((i) => movable[i])], [off, srcColumns, movable, layout.order]);
  const rows = useMemo(() => {
    const identity = layout.order.every((src, d) => src === d);
    if (identity) return srcRows;
    return srcRows.map((r) => [...r.slice(0, off), ...layout.order.map((i) => r[i + off])]);
  }, [off, layout.order, srcRows]);
  const [headerMenu, setHeaderMenu] = useState<{ x: number; y: number; col: number } | null>(null);
  const dragFrom = useRef<number | null>(null);
  const [dropAt, setDropAt] = useState<number | null>(null);
  // A press on a resize handle must not start a column drag.
  const onHandle = useRef(false);
  // Without a `highlights` prop the grid applies the app's shared highlights, when it is inside a provider.
  const shared = useHighlights();
  const rules = highlights ?? shared?.rules;
  const onHighlight =
    cellActions?.onHighlight ?? (shared ? (column: string, value: Cell) => void shared.highlightValue(column, value) : undefined);
  const [menu, setMenu] = useState<MenuAt | null>(null);
  const opener = useRef<HTMLElement | null>(null);
  const closeHeaderMenu = useCallback(() => {
    setHeaderMenu(null);
    opener.current?.focus();
  }, []);
  const closeMenu = useCallback(() => {
    setMenu(null);
    opener.current?.focus();
  }, []);
  const openMenu = (e: React.SyntheticEvent, rect: { x: number; y: number }, row: number, col: number) => {
    e.preventDefault();
    e.stopPropagation();
    opener.current = e.currentTarget as HTMLElement;
    onMenuOpen?.({ column: columns[col], row });
    setMenu({ ...rect, row, col, id: rowId?.(row) });
  };
  // The row under an open menu changed (another event now sits at its index): close it rather than retarget it.
  if (menu && rowId && rowId(menu.row) !== menu.id) setMenu(null);
  const [viewing, setViewing] = useState<{ row: number; col: number } | null>(null);
  const viewerOpener = useRef<HTMLElement | null>(null);
  const openViewer = (el: HTMLElement, row: number, col: number) => {
    viewerOpener.current = el;
    setViewing({ row, col });
  };
  const restoreViewerFocus = useRef(false);
  const closeViewer = useCallback(() => {
    // Focus goes back once the dialog is gone: while it is mounted it pulls focus back in.
    restoreViewerFocus.current = true;
    setViewing(null);
  }, []);
  useEffect(() => {
    if (viewing === null && restoreViewerFocus.current) {
      restoreViewerFocus.current = false;
      viewerOpener.current?.focus();
    }
  }, [viewing]);
  const items = (m: MenuAt): MenuItem[] => {
    const value = rows[m.row]?.[m.col];
    const column = columns[m.col];
    const out: MenuItem[] = [{ label: "Copy", run: () => void navigator.clipboard.writeText(rawText(value)) }];
    out.push({ label: "Show full value", run: () => openViewer(opener.current ?? document.body, m.row, m.col) });
    if (cellItems) {
      if (onHighlight) out.push({ label: "Highlight this value", run: () => onHighlight(column, value) });
      return [...out, ...cellItems({ column, value, row: m.row })];
    }
    if (cellActions?.onFilter) out.push({ label: "Filter by this value", run: () => cellActions.onFilter!(column, value) });
    if (onHighlight) out.push({ label: "Highlight this value", run: () => onHighlight(column, value) });
    const kind = nav ? entityKindFor(column, value) : null;
    if (nav && kind) out.push({ label: `Open ${kind === "ip" ? "IP" : kind} tab`, run: () => nav.openEntity({ kind, value: rawText(value) }) });
    return out;
  };

  const helper = useMemo(() => createColumnHelper<Cell[]>(), []);
  const defs = useMemo(
    () =>
      columns.map((name, i) =>
        helper.accessor((r) => r[i], {
          id: `${i}`,
          minSize: i < off ? 1 : MIN_COLUMN_WIDTH,
          header: displaySafe(labels?.[name] ?? name),
          cell: (c) => cellText(c.getValue()),
        }),
      ),
    [columns, helper, labels, off],
  );
  const pinnedWidth = off ? (widths?.[columns[0]] ?? DEFAULT_COLUMN_WIDTH) : 0;
  const sizing = useMemo(
    () => Object.fromEntries(columns.map((_, d) => [String(d), d < off ? pinnedWidth : layout.widthAt(d - off)])),
    [columns, layout, off, pinnedWidth],
  );
  // TanStack Table's hook is not memoisable by the React Compiler; the grid does not rely on that.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: rows,
    columns: defs,
    defaultColumn: { size: DEFAULT_COLUMN_WIDTH, minSize: MIN_COLUMN_WIDTH },
    columnResizeMode: "onChange",
    state: { columnSizing: sizing },
    onColumnSizingChange: (u) => {
      const next = typeof u === "function" ? u(sizing) : u;
      layout.setWidths(Object.fromEntries(Object.entries(next).filter(([d]) => Number(d) >= off).map(([d, w]) => [String(Number(d) - off), w])));
    },
    getCoreRowModel: getCoreRowModel(),
  });
  const tableRows = table.getRowModel().rows;
  const scroller = useRef<HTMLDivElement>(null);
  const virt = useVirtualizer({
    count: tableRows.length,
    getScrollElement: () => scroller.current,
    scrollMargin: ROW_HEIGHT,
    scrollPaddingStart: ROW_HEIGHT,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
    initialRect: { width: 800, height },
    // The measured size, or the configured height where the element has no layout (jsdom, a hidden tab).
    observeElementRect: (instance, cb) => {
      const el = instance.scrollElement;
      if (!el) return;
      const report = () => {
        const r = el.getBoundingClientRect();
        cb({ width: r.width || 800, height: r.height || height });
      };
      report();
      if (typeof ResizeObserver === "undefined") return;
      const ro = new ResizeObserver(report);
      ro.observe(el);
      return () => ro.disconnect();
    },
  });
  // Roving tabindex: one cell is the grid's tab stop; arrows move it, scrolling the virtualizer to rows that are not
  // rendered yet and focusing the target once it is.
  const [active, setActive] = useState({ row: 0, col: 0 });
  const activeRow = Math.min(active.row, Math.max(rows.length - 1, 0));
  const activeCol = Math.min(active.col, Math.max(columns.length - 1, 0));
  // When the active row is not mounted (scrolled out of the window), the tab stop moves to the first visible row, so
  // the grid always has exactly one tabbable cell.
  const mounted = virt.getVirtualItems();
  const tabRow = mounted.some((v) => v.index === activeRow) ? activeRow : (virt.range?.startIndex ?? mounted[0]?.index ?? 0);
  const pendingFocus = useRef<{ row: number; col: number } | null>(null);
  const moveTo = (row: number, col: number) => {
    const target = { row: Math.min(Math.max(row, 0), rows.length - 1), col: Math.min(Math.max(col, 0), columns.length - 1) };
    pendingFocus.current = target;
    setActive(target);
    virt.scrollToIndex(target.row, { align: "auto" });
  };
  useEffect(() => {
    const want = pendingFocus.current;
    if (!want) return;
    const el = scroller.current?.querySelector<HTMLElement>(`[data-row="${want.row}"] [data-col="${want.col}"]`);
    if (el) {
      pendingFocus.current = null;
      el.focus();
    }
  });
  const onCellKey = (e: React.KeyboardEvent<HTMLElement>, row: number, col: number) => {
    const page = Math.max(Math.floor(height / ROW_HEIGHT) - 1, 1);
    const to: Record<string, [number, number]> = {
      ArrowDown: [row + 1, col],
      ArrowUp: [row - 1, col],
      ArrowRight: [row, col + 1],
      ArrowLeft: [row, col - 1],
      PageDown: [row + page, col],
      PageUp: [row - page, col],
      Home: [row, 0],
      End: [row, columns.length - 1],
    };
    const next = to[e.key];
    if (next) {
      e.preventDefault();
      moveTo(next[0], next[1]);
      return;
    }
    if (e.key !== "Enter") return;
    const r = e.currentTarget.getBoundingClientRect();
    openMenu(e, { x: r.left, y: r.bottom }, row, col);
  };
  const rowClass = (row: Cell[], index: number) => {
    const hit = rules?.find((r) => ruleMatches(r, columns, row));
    const cls = hit ? colourClass(hit.colour) : undefined;
    return ["grid-row", cls, hostRowClass?.(index)].filter(Boolean).join(" ");
  };
  const lastVisible = virt.getVirtualItems().at(-1)?.index ?? -1;
  useEffect(() => {
    if (onNearEnd && rows.length > 0 && lastVisible >= rows.length - 1 - NEAR_END) onNearEnd();
  }, [onNearEnd, rows.length, lastVisible]);
  const columnSizes = table.getVisibleLeafColumns().map((c) => c.getSize());
  const template = columnSizes.map((w) => `${w}px`).join(" ");
  const totalWidth = columnSizes.reduce((a, b) => a + b, 0);

  return (
    <div className="grid grid-bounded" role="table" aria-rowcount={rows.length}>
      <div ref={scroller} className="grid-scroll" style={{ height: height + ROW_HEIGHT }}>
        <div style={{ width: totalWidth, minWidth: "100%" }}>
          <div className="grid-head grid-head-sticky" role="row" style={{ display: "grid", gridTemplateColumns: template, height: ROW_HEIGHT }}>
            {table.getHeaderGroups()[0].headers.map((h, i) => {
              const sorted = sort?.column === columns[i] ? (sort.descending ? "descending" : "ascending") : undefined;
              return (
                <div
                  key={h.id}
                  role="columnheader"
                  aria-sort={onSort && (sortable?.(columns[i]) ?? true) ? (sorted ?? "none") : undefined}
                  className={dropAt === i ? "grid-cell grid-header grid-drop" : "grid-cell grid-header"}
                  draggable={i >= off}
                  onDragStart={(e) => {
                    if (onHandle.current || i < off) {
                      e.preventDefault();
                      return;
                    }
                    dragFrom.current = i;
                    e.dataTransfer?.setData("text/plain", columns[i]);
                    if (e.dataTransfer) e.dataTransfer.effectAllowed = "move";
                  }}
                  onDragOver={(e) => {
                    if (dragFrom.current === null || i < off) return;
                    e.preventDefault();
                    setDropAt(i);
                  }}
                  onDrop={(e) => {
                    e.preventDefault();
                    const from = dragFrom.current;
                    dragFrom.current = null;
                    setDropAt(null);
                    if (from !== null && i >= off) layout.move(from - off, i - off);
                  }}
                  onDragEnd={() => {
                    dragFrom.current = null;
                    setDropAt(null);
                  }}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    if (i < off) return;
                    opener.current = e.currentTarget;
                    setHeaderMenu({ x: e.clientX, y: e.clientY, col: i });
                  }}
                >
                  {onSort && (sortable?.(columns[i]) ?? true) ? (
                    <button className="grid-sort" onClick={() => onSort(columns[i])}>
                      {flexRender(h.column.columnDef.header, h.getContext())}
                      <span aria-hidden="true">{sorted === "ascending" ? " ▲" : sorted === "descending" ? " ▼" : ""}</span>
                    </button>
                  ) : (
                    flexRender(h.column.columnDef.header, h.getContext())
                  )}
                  {headerBadge?.(columns[i])}
                  {i >= off && (
                    <div
                      role="separator"
                      aria-orientation="vertical"
                      aria-label={`Resize ${displaySafe(columns[i])}`}
                      className="grid-resize"
                      draggable={false}
                      onMouseDown={(e) => {
                        onHandle.current = true;
                        window.addEventListener("mouseup", () => (onHandle.current = false), { once: true });
                        h.getResizeHandler()(e);
                      }}
                      onClick={(e) => e.stopPropagation()}
                    />
                  )}
                </div>
              );
            })}
          </div>
          {rows.length === 0 && <p className="grid-empty">No rows.</p>}
          <div style={{ height: virt.getTotalSize(), position: "relative" }}>
            {virt.getVirtualItems().map((v) => {
              const row = tableRows[v.index];
              return (
                <div
                  key={row.id}
                  role="row"
                  data-row={v.index}
                  className={rowClass(row.original, v.index)}
                  onClick={onRowClick ? () => onRowClick(srcRows[v.index], v.index) : undefined}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: ROW_HEIGHT,
                    transform: `translateY(${v.start - ROW_HEIGHT}px)`,
                    display: "grid",
                    gridTemplateColumns: template,
                    cursor: onRowClick ? "pointer" : undefined,
                  }}
                >
                  {row.getVisibleCells().map((c, col) => (
                    <div
                      key={c.id}
                      role="cell"
                      className="grid-cell"
                      data-col={col}
                      tabIndex={v.index === tabRow && col === activeCol ? 0 : -1}
                      onFocus={() => setActive({ row: v.index, col })}
                      title={cellText(c.getValue())}
                      onContextMenu={(e) => openMenu(e, { x: e.clientX, y: e.clientY }, v.index, col)}
                      onDoubleClick={(e) => openViewer(e.currentTarget, v.index, col)}
                      onKeyDown={(e) => onCellKey(e, v.index, col)}
                    >
                      {renderCell?.({ column: columns[col], value: row.original[col], row: v.index }) ??
                        flexRender(c.column.columnDef.cell, c.getContext())}
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        </div>
      </div>
      {headerMenu &&
        (() => {
          const name = columns[headerMenu.col];
          const columnItems: MenuItem[] = [
            ...(headerMenu.col > off ? [{ label: "Move column left", run: () => layout.move(headerMenu.col - off, headerMenu.col - off - 1) }] : []),
            ...(headerMenu.col < columns.length - 1 ? [{ label: "Move column right", run: () => layout.move(headerMenu.col - off, headerMenu.col - off + 1) }] : []),
            {
              label: "Reset columns",
              run: () => {
                layout.reset();
                onResetColumns?.();
              },
            },
          ];
          const panel = headerPanel?.(name, closeHeaderMenu) ?? null;
          return panel !== null ? (
            <HeaderPopover
              x={headerMenu.x}
              y={headerMenu.y}
              label={`${displaySafe(labels?.[name] ?? name)} column`}
              panel={panel}
              items={columnItems}
              onClose={closeHeaderMenu}
            />
          ) : (
            <CellMenu x={headerMenu.x} y={headerMenu.y} items={columnItems} onClose={closeHeaderMenu} />
          );
        })()}
      {menu && <CellMenu x={menu.x} y={menu.y} items={items(menu)} onClose={closeMenu} />}
      {viewing && <ValueViewer column={columns[viewing.col]} value={rows[viewing.row]?.[viewing.col]} onClose={closeViewer} />}
    </div>
  );
}
