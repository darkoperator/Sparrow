// The shared grid: a virtualised table of read-only cells. Every cell is rendered as text through `displaySafe`;
// nothing here interprets cell content. Rows are positional (`unknown[][]`) so the same grid serves evidence, pivot
// sections, the table browser and SQL results.
import { createColumnHelper, flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { HIGHLIGHT_COLOURS, type HighlightRule, type Sort } from "../api";
import { useHighlights } from "../highlights/useHighlights";
import { useNav } from "../shell/nav";
import { displaySafe } from "../text";
import { rawText, valueKind } from "../value";
import CellMenu, { type MenuItem } from "./CellMenu";

export type Cell = unknown;

/** What the host does with a cell value; an action the host does not give is not offered. */
export interface CellActions {
  onFilter?: (column: string, value: Cell) => void;
  onHighlight?: (column: string, value: Cell) => void;
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
  /** Height of the scrolling body in px. */
  height?: number;
}

const ROW_HEIGHT = 26;

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
  columns,
  rows,
  cellActions,
  highlights,
  sort,
  onSort,
  onNearEnd,
  onRowClick,
  height = 320,
}: GridProps) {
  const nav = useNav();
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
  const items = (m: MenuAt): MenuItem[] => {
    const value = rows[m.row]?.[m.col];
    const column = columns[m.col];
    const out: MenuItem[] = [{ label: "Copy", run: () => void navigator.clipboard.writeText(rawText(value)) }];
    if (cellActions?.onFilter) out.push({ label: "Filter by this value", run: () => cellActions.onFilter!(column, value) });
    if (onHighlight) out.push({ label: "Highlight this value", run: () => onHighlight(column, value) });
    const kind = nav ? valueKind(value) : null;
    if (nav && kind) {
      const text = rawText(value);
      out.push({
        label: kind === "ip" ? `Pivot on IP ${displaySafe(text)}` : `Pivot on account ${displaySafe(text)}`,
        run: () => nav.openPivot(kind, text),
      });
    }
    return out;
  };

  const helper = useMemo(() => createColumnHelper<Cell[]>(), []);
  const defs = useMemo(
    () => columns.map((name, i) => helper.accessor((r) => r[i], { id: `${i}`, header: displaySafe(name), cell: (c) => cellText(c.getValue()) })),
    [columns, helper],
  );
  // TanStack Table's hook is not memoisable by the React Compiler; the grid does not rely on that.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({ data: rows, columns: defs, getCoreRowModel: getCoreRowModel() });
  const tableRows = table.getRowModel().rows;
  const scroller = useRef<HTMLDivElement>(null);
  const virt = useVirtualizer({
    count: tableRows.length,
    getScrollElement: () => scroller.current,
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
  const rowClass = (row: Cell[]) => {
    const hit = rules?.find((r) => ruleMatches(r, columns, row));
    const cls = hit ? colourClass(hit.colour) : undefined;
    return cls ? `grid-row ${cls}` : "grid-row";
  };
  const lastVisible = virt.getVirtualItems().at(-1)?.index ?? -1;
  useEffect(() => {
    if (onNearEnd && rows.length > 0 && lastVisible >= rows.length - 1 - NEAR_END) onNearEnd();
  }, [onNearEnd, rows.length, lastVisible]);
  const template = `repeat(${Math.max(columns.length, 1)}, minmax(120px, 1fr))`;

  if (rows.length === 0) {
    return <p className="grid-empty">No rows.</p>;
  }
  return (
    <div className="grid" role="table" aria-rowcount={rows.length}>
      <div className="grid-head" role="row" style={{ display: "grid", gridTemplateColumns: template }}>
        {table.getHeaderGroups()[0].headers.map((h, i) => {
          const sorted = sort?.column === columns[i] ? (sort.descending ? "descending" : "ascending") : undefined;
          return (
            <div key={h.id} role="columnheader" aria-sort={onSort ? (sorted ?? "none") : undefined} className="grid-cell grid-header">
              {onSort ? (
                <button className="grid-sort" onClick={() => onSort(columns[i])}>
                  {flexRender(h.column.columnDef.header, h.getContext())}
                  <span aria-hidden="true">{sorted === "ascending" ? " ▲" : sorted === "descending" ? " ▼" : ""}</span>
                </button>
              ) : (
                flexRender(h.column.columnDef.header, h.getContext())
              )}
            </div>
          );
        })}
      </div>
      <div ref={scroller} className="grid-body" style={{ height, overflow: "auto", position: "relative" }}>
        <div style={{ height: virt.getTotalSize(), position: "relative" }}>
          {virt.getVirtualItems().map((v) => {
            const row = tableRows[v.index];
            return (
              <div
                key={row.id}
                role="row"
                data-row={v.index}
                className={rowClass(row.original)}
                onClick={onRowClick ? () => onRowClick(row.original, v.index) : undefined}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: ROW_HEIGHT,
                  transform: `translateY(${v.start}px)`,
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
                    tabIndex={0}
                    title={cellText(c.getValue())}
                    onContextMenu={(e) => openMenu(e, { x: e.clientX, y: e.clientY }, v.index, col)}
                    onKeyDown={(e) => {
                      if (e.key !== "Enter") return;
                      const r = e.currentTarget.getBoundingClientRect();
                      openMenu(e, { x: r.left, y: r.bottom }, v.index, col);
                    }}
                  >
                    {flexRender(c.column.columnDef.cell, c.getContext())}
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </div>
      {menu && <CellMenu x={menu.x} y={menu.y} items={items(menu)} onClose={closeMenu} />}
    </div>
  );
}
