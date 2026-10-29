// The shared grid: a virtualised table of read-only cells. Every cell is rendered as text through `displaySafe`;
// nothing here interprets cell content. Rows are positional (`unknown[][]`) so the same grid serves evidence, pivot
// sections, the table browser and SQL results.
import { createColumnHelper, flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { HIGHLIGHT_COLOURS, type HighlightRule, type Sort } from "../api";
import { useHighlights } from "../highlights/useHighlights";
import { useNav } from "../shell/nav";
import { displaySafe } from "../text";
import { entityKindFor, rawText } from "../value";
import CellMenu, { type MenuItem } from "./CellMenu";
import { useGridLayout } from "./gridLayout";
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
  /** Called after "Reset columns", for a host that keeps more column state (which are shown) to reset it too. */
  onResetColumns?: () => void;
  /** Height of the scrolling body in px. */
  height?: number;
}

const ROW_HEIGHT = 26;
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

interface MenuAt {
  x: number;
  y: number;
  row: number;
  col: number;
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
  onResetColumns,
  height = 320,
}: GridProps) {
  const nav = useNav();
  // The analyst's column order: from here on `columns` and `rows` are in the order shown; `srcRows` are as given.
  const layout = useGridLayout(layoutId, srcColumns, widths, DEFAULT_COLUMN_WIDTH);
  const columns = useMemo(() => layout.order.map((i) => srcColumns[i]), [layout.order, srcColumns]);
  const rows = useMemo(() => {
    const identity = layout.order.every((src, d) => src === d);
    return identity ? srcRows : srcRows.map((r) => layout.order.map((i) => r[i]));
  }, [layout.order, srcRows]);
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
  const closeMenu = useCallback(() => {
    setMenu(null);
    opener.current?.focus();
  }, []);
  const openMenu = (e: React.SyntheticEvent, rect: { x: number; y: number }, row: number, col: number) => {
    e.preventDefault();
    e.stopPropagation();
    opener.current = e.currentTarget as HTMLElement;
    setMenu({ ...rect, row, col });
  };
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
          header: displaySafe(labels?.[name] ?? name),
          cell: (c) => cellText(c.getValue()),
        }),
      ),
    [columns, helper, labels],
  );
  const sizing = useMemo(() => Object.fromEntries(columns.map((_, d) => [String(d), layout.widthAt(d)])), [columns, layout]);
  // TanStack Table's hook is not memoisable by the React Compiler; the grid does not rely on that.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: rows,
    columns: defs,
    defaultColumn: { size: DEFAULT_COLUMN_WIDTH, minSize: MIN_COLUMN_WIDTH },
    columnResizeMode: "onChange",
    state: { columnSizing: sizing },
    onColumnSizingChange: (u) => layout.setWidths(typeof u === "function" ? u(sizing) : u),
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
                  draggable
                  onDragStart={(e) => {
                    if (onHandle.current) {
                      e.preventDefault();
                      return;
                    }
                    dragFrom.current = i;
                    e.dataTransfer?.setData("text/plain", columns[i]);
                    if (e.dataTransfer) e.dataTransfer.effectAllowed = "move";
                  }}
                  onDragOver={(e) => {
                    if (dragFrom.current === null) return;
                    e.preventDefault();
                    setDropAt(i);
                  }}
                  onDrop={(e) => {
                    e.preventDefault();
                    const from = dragFrom.current;
                    dragFrom.current = null;
                    setDropAt(null);
                    if (from !== null) layout.move(from, i);
                  }}
                  onDragEnd={() => {
                    dragFrom.current = null;
                    setDropAt(null);
                  }}
                  onContextMenu={(e) => {
                    e.preventDefault();
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
      {headerMenu && (
        <CellMenu
          x={headerMenu.x}
          y={headerMenu.y}
          items={[
            ...(headerMenu.col > 0 ? [{ label: "Move column left", run: () => layout.move(headerMenu.col, headerMenu.col - 1) }] : []),
            ...(headerMenu.col < columns.length - 1 ? [{ label: "Move column right", run: () => layout.move(headerMenu.col, headerMenu.col + 1) }] : []),
            {
              label: "Reset columns",
              run: () => {
                layout.reset();
                onResetColumns?.();
              },
            },
          ]}
          onClose={() => {
            setHeaderMenu(null);
            opener.current?.focus();
          }}
        />
      )}
      {menu && <CellMenu x={menu.x} y={menu.y} items={items(menu)} onClose={closeMenu} />}
      {viewing && <ValueViewer column={columns[viewing.col]} value={rows[viewing.row]?.[viewing.col]} onClose={closeViewer} />}
    </div>
  );
}
