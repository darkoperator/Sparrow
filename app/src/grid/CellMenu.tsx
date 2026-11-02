import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import Icon from "../ui/Icon";

export interface MenuItem {
  label: string;
  /** What a click does. An item with `items` opens them instead. */
  run?: () => void;
  /** A submenu; ArrowRight, Enter, Space or a click opens it, ArrowLeft or Escape closes it. */
  items?: MenuItem[];
  /** Why the item cannot be used now. It is shown as the item's title and the item does nothing. */
  disabled?: string;
  /** On a disabled item: choosing it (click, Enter, ArrowRight) closes the menu and then runs this (a way to fix the reason). */
  blocked?: () => void;
  /** A tick box item: checked, unchecked, or `"mixed"` (some of the selection). */
  checked?: boolean | "mixed";
  /** On a submenu: a filter box above its items once there are more than `FILTER_MIN` of them. */
  filter?: boolean;
  /**
   * A click runs the item and leaves the menu open (a tag toggle): the host builds the items again as its data changes,
   * so the menu shows the new state in place.
   */
  keepOpen?: boolean;
  /** In a filtered submenu the item stays whatever the filter says ("New tag…"). */
  pinned?: boolean;
}

/** A submenu with a filter box shows it above this many items (not counting pinned ones). */
export const FILTER_MIN = 12;

const ITEM = '[role^="menuitem"]';

/** The gap kept between a menu and the window's edge. */
const MARGIN = 8;

/** Where a menu goes: a point (the pointer) for the top menu, the item that opened it for a submenu. */
type At = { x: number; y: number } | { item: HTMLElement };

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(v, hi));

/**
 * The top-left of a menu of `w`x`h` inside a `vw`x`vh` window. The top menu opens at the pointer, and upward from it
 * when there is no room below; a submenu opens beside its item, on the left of it when there is no room on the right,
 * and shifted up when it would run off the bottom. A menu taller than the window is capped by its max-height, so it
 * always fits.
 */
export function placeMenu(at: { x: number; y: number } | { item: DOMRect }, w: number, h: number, vw: number, vh: number) {
  const maxTop = vh - MARGIN - h;
  if ("item" in at) {
    const r = at.item;
    const left = r.right + w + MARGIN <= vw ? r.right : r.left - w >= MARGIN ? r.left - w : clamp(vw - w - MARGIN, MARGIN, vw);
    return { left, top: clamp(r.top - 5, MARGIN, Math.max(MARGIN, maxTop)) };
  }
  const left = clamp(at.x, MARGIN, Math.max(MARGIN, vw - w - MARGIN));
  const top = at.y <= maxTop ? at.y : at.y - h >= MARGIN ? at.y - h : Math.max(MARGIN, maxTop);
  return { left, top };
}

function MenuList({
  items,
  filter,
  onRun,
  onBlocked,
  onBack,
  at,
  className,
  focusTick,
}: {
  items: MenuItem[];
  filter: boolean;
  onRun: (item: MenuItem) => void;
  /** A disabled item with `blocked` was chosen. */
  onBlocked: (item: MenuItem) => void;
  /** Present in a submenu: closes it and gives the focus back to the item that opened it. */
  onBack?: () => void;
  /** Where it opens; it is a fixed box, so a scrolling or clipping parent cannot hide it. */
  at: At;
  className: string;
  /** Changes when the menu is asked to take the focus again (a click on the item that opened it). */
  focusTick: number;
}) {
  const uid = useId();
  const ref = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const buttons = useRef<(HTMLButtonElement | null)[]>([]);
  const [open, setOpen] = useState<number | null>(null);
  /** The item whose submenu is open: the submenu is placed from it. */
  const [opener, setOpener] = useState<HTMLElement | null>(null);
  const [query, setQuery] = useState("");
  const [tick, setTick] = useState(0);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);
  const maxHeight = window.innerHeight - 2 * MARGIN;
  const showFilter = filter && items.filter((i) => !i.pinned).length > FILTER_MIN;
  const needle = query.trim().toLowerCase();
  const shown = showFilter && needle !== "" ? items.filter((i) => i.pinned || i.label.toLowerCase().includes(needle)) : items;

  // Measured after layout and before paint, again when the filter changes how tall it is.
  const anchor = "item" in at ? at.item : null;
  const ax = "item" in at ? 0 : at.x;
  const ay = "item" in at ? 0 : at.y;
  useLayoutEffect(() => {
    const box = ref.current?.getBoundingClientRect();
    if (!box) return;
    const place = anchor ? { item: anchor.getBoundingClientRect() } : { x: ax, y: ay };
    setPos(placeMenu(place, box.width, box.height, window.innerWidth, window.innerHeight));
  }, [anchor, ax, ay, shown.length]);

  useEffect(() => {
    if (input.current) input.current.focus();
    else ref.current?.querySelector<HTMLElement>(`:scope > .cell-menu-row > ${ITEM}`)?.focus();
  }, [focusTick]);

  const live = () => buttons.current.slice(0, shown.length).filter((b): b is HTMLButtonElement => b !== null);
  const focusAt = (i: number) => live()[i]?.focus();
  const openAt = (i: number) => {
    const it = shown[i];
    if (it?.disabled !== undefined) {
      if (it.blocked) onBlocked(it);
      return;
    }
    if (it?.items && it.disabled === undefined) {
      setOpen(i);
      setOpener(buttons.current[i]);
      setTick((t) => t + 1);
    }
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    const els = live();
    const at = els.indexOf(document.activeElement as HTMLButtonElement);
    const typing = document.activeElement === input.current;
    if (e.key === "Escape" || (e.key === "ArrowLeft" && !typing)) {
      // The top menu has nothing to go back to: Escape reaches the wrapper, which closes everything.
      if (!onBack) return;
      e.stopPropagation();
      e.preventDefault();
      onBack?.();
      return;
    }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      e.stopPropagation();
      if (els.length === 0) return;
      const down = e.key === "ArrowDown";
      if (at < 0) focusAt(down ? 0 : els.length - 1);
      else if (!down && at === 0 && input.current) input.current.focus();
      else focusAt(down ? (at + 1) % els.length : (at - 1 + els.length) % els.length);
      return;
    }
    if (typing || at < 0) return;
    if (e.key === "ArrowRight" || e.key === "Enter" || e.key === " ") {
      if (shown[at]?.items || (shown[at]?.disabled !== undefined && shown[at]?.blocked)) {
        e.preventDefault();
        e.stopPropagation();
        openAt(at);
      }
    }
  };

  return (
    <div
      ref={ref}
      role="menu"
      className={className}
      style={{
        position: "fixed",
        left: pos?.left ?? ax,
        top: pos?.top ?? ay,
        maxHeight,
        overflowY: "auto",
        visibility: pos ? undefined : "hidden",
      }}
      onKeyDown={onKeyDown}
      // A submenu stays where it opened: a menu scrolled under it closes it.
      onScroll={() => setOpen(null)}
    >
      {showFilter && (
        <input
          ref={input}
          type="search"
          className="cell-menu-filter"
          aria-label="Filter"
          placeholder="Filter…"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setOpen(null);
          }}
        />
      )}
      {shown.map((it, i) => {
        const role = it.checked !== undefined ? "menuitemcheckbox" : "menuitem";
        return (
          <div key={`${i}:${it.label}`} className="cell-menu-row">
            <button
              ref={(el) => {
                buttons.current[i] = el;
              }}
              type="button"
              role={role}
              aria-checked={it.checked === undefined ? undefined : it.checked === "mixed" ? "mixed" : it.checked}
              aria-haspopup={it.items ? "menu" : undefined}
              aria-expanded={it.items ? open === i : undefined}
              aria-disabled={it.disabled !== undefined ? true : undefined}
              title={it.disabled}
              aria-describedby={it.disabled !== undefined ? `${uid}-${i}` : undefined}
              onMouseEnter={(e) => {
                setOpen(it.items && it.disabled === undefined ? i : null);
                setOpener(e.currentTarget);
              }}
              onClick={() => {
                if (it.disabled !== undefined) return openAt(i);
                if (it.items) openAt(i);
                else onRun(it);
              }}
            >
              {it.checked !== undefined && (
                <span aria-hidden="true" className="cell-menu-check">
                  {it.checked === "mixed" ? "–" : it.checked ? "✓" : ""}
                </span>
              )}
              {it.disabled !== undefined ? (
                <span className="cell-menu-text">
                  <span className="cell-menu-label">{it.label}</span>
                  <small id={`${uid}-${i}`} className="cell-menu-reason" aria-hidden="true">
                    {it.disabled}
                  </small>
                </span>
              ) : (
                it.label
              )}
              {it.items && (
                <span aria-hidden="true" className="cell-menu-arrow">
                  <Icon name="chevron-right" size={14} />
                </span>
              )}
            </button>
            {open === i && opener && it.items && it.disabled === undefined && (
              <MenuList
                items={it.items}
                filter={it.filter === true}
                onRun={onRun}
                onBlocked={onBlocked}
                at={{ item: opener }}
                focusTick={tick}
                className="cell-menu cell-submenu"
                onBack={() => {
                  setOpen(null);
                  focusAt(i);
                }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

/**
 * A context menu at a fixed position, on the document body so that no pane beside the table can cover it. Items are plain buttons; Escape or a click elsewhere closes it, arrows move
 * between items, and an item with `items` opens a submenu to its right. Labels must already be safe text (callers pass
 * them through `displaySafe`).
 */
export default function CellMenu({
  x,
  y,
  items,
  onClose,
}: {
  x: number;
  y: number;
  items: MenuItem[];
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const away = (e: Event) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [onClose]);

  return createPortal(
    <div
      ref={ref}
      className="cell-menu-root"
      onKeyDown={(e) => {
        if (e.key !== "Escape") return;
        e.stopPropagation();
        onClose();
      }}
    >
      <MenuList
        items={items}
        filter={false}
        className="cell-menu"
        at={{ x, y }}
        focusTick={0}
        onRun={(it) => {
          it.run?.();
          if (!it.keepOpen) onClose();
        }}
        onBlocked={(it) => {
          onClose();
          // After the close: the host gives the focus back to what opened the menu, and that must not win.
          window.setTimeout(() => it.blocked?.(), 0);
        }}
        onBack={undefined}
      />
    </div>,
    document.body,
  );
}
