// A column header's popover: the host's panel above the column items, kept inside the window and shown over everything
// (a portal on the body, so no pane beside the table can cover it). Escape or a click elsewhere closes it; the panel
// takes the focus itself.
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import type { MenuItem } from "./CellMenu";

export default function HeaderPopover({
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
  return createPortal(
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
      {items.length > 0 && (
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
      )}
    </div>,
    document.body,
  );
}
