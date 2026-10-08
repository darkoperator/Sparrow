// The shared grid: a virtualised table of read-only cells. Every cell is rendered as text through `displaySafe`;
// nothing here interprets cell content. Rows are positional (`unknown[][]`) so the same grid serves evidence, pivot
// sections, the table browser and SQL results.
import { createColumnHelper, flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useMemo, useRef } from "react";
import { displaySafe } from "../text";

export type Cell = unknown;

export interface GridProps {
  columns: string[];
  rows: Cell[][];
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

export default function Grid({ columns, rows, onRowClick, height = 320 }: GridProps) {
  const helper = useMemo(() => createColumnHelper<Cell[]>(), []);
  const defs = useMemo(
    () => columns.map((name, i) => helper.accessor((r) => r[i], { id: `${i}`, header: name, cell: (c) => cellText(c.getValue()) })),
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
  const template = `repeat(${Math.max(columns.length, 1)}, minmax(120px, 1fr))`;

  if (rows.length === 0) {
    return <p className="grid-empty">No rows.</p>;
  }
  return (
    <div className="grid" role="table" aria-rowcount={rows.length}>
      <div className="grid-head" role="row" style={{ display: "grid", gridTemplateColumns: template }}>
        {table.getHeaderGroups()[0].headers.map((h) => (
          <div key={h.id} role="columnheader" className="grid-cell grid-header">
            {flexRender(h.column.columnDef.header, h.getContext())}
          </div>
        ))}
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
                className="grid-row"
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
                {row.getVisibleCells().map((c) => (
                  <div key={c.id} role="cell" className="grid-cell" title={cellText(c.getValue())}>
                    {flexRender(c.column.columnDef.cell, c.getContext())}
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
