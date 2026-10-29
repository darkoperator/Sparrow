import { useEffect, useLayoutEffect, useRef, useState } from "react";
import Icon from "../ui/Icon";

export interface MenuItem {
  label: string;
  /** What a click does. An item with `items` opens them instead. */
  run?: () => void;
  /** A submenu; ArrowRight, Enter, Space or a click opens it, ArrowLeft or Escape closes it. */
  items?: MenuItem[];
  /** Why the item cannot be used now. It is shown as the item's title and the item does nothing. */
  disabled?: string;
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

function MenuList({
  items,
  filter,
  onRun,
  onBack,
  flip,
  className,
  focusTick,
}: {
  items: MenuItem[];
  filter: boolean;
  onRun: (item: MenuItem) => void;
  /** Present in a submenu: closes it and gives the focus back to the item that opened it. */
  onBack?: () => void;
  flip: boolean;
  className: string;
  /** Changes when the menu is asked to take the focus again (a click on the item that opened it). */
  focusTick: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const buttons = useRef<(HTMLButtonElement | null)[]>([]);
  const [open, setOpen] = useState<number | null>(null);
  const [query, setQuery] = useState("");
  const [tick, setTick] = useState(0);
  // A submenu that would run off the right edge of the window opens to the left of its item instead.
  const [spill, setSpill] = useState(false);
  useLayoutEffect(() => {
    if (onBack && ref.current && ref.current.getBoundingClientRect().right > window.innerWidth) setSpill(true);
  }, [onBack]);
  const showFilter = filter && items.filter((i) => !i.pinned).length > FILTER_MIN;
  const needle = query.trim().toLowerCase();
  const shown = showFilter && needle !== "" ? items.filter((i) => i.pinned || i.label.toLowerCase().includes(needle)) : items;

  useEffect(() => {
    if (input.current) input.current.focus();
    else ref.current?.querySelector<HTMLElement>(`:scope > .cell-menu-row > ${ITEM}`)?.focus();
  }, [focusTick]);

  const live = () => buttons.current.slice(0, shown.length).filter((b): b is HTMLButtonElement => b !== null);
  const focusAt = (i: number) => live()[i]?.focus();
  const openAt = (i: number) => {
    const it = shown[i];
    if (it?.items && it.disabled === undefined) {
      setOpen(i);
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
      if (shown[at]?.items) {
        e.preventDefault();
        e.stopPropagation();
        openAt(at);
      }
    }
  };

  return (
    <div ref={ref} role="menu" className={`${className}${flip || spill ? " cell-menu-flip" : ""}`} onKeyDown={onKeyDown}>
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
              onMouseEnter={() => setOpen(it.items && it.disabled === undefined ? i : null)}
              onClick={() => {
                if (it.disabled !== undefined) return;
                if (it.items) openAt(i);
                else onRun(it);
              }}
            >
              {it.checked !== undefined && (
                <span aria-hidden="true" className="cell-menu-check">
                  {it.checked === "mixed" ? "–" : it.checked ? "✓" : ""}
                </span>
              )}
              {it.label}
              {it.items && (
                <span aria-hidden="true" className="cell-menu-arrow">
                  <Icon name="chevron-right" size={14} />
                </span>
              )}
            </button>
            {open === i && it.items && it.disabled === undefined && (
              <MenuList
                items={it.items}
                filter={it.filter === true}
                onRun={onRun}
                flip={flip}
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
 * A context menu at a fixed position. Items are plain buttons; Escape or a click elsewhere closes it, arrows move
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

  return (
    <div
      ref={ref}
      className="cell-menu-root"
      style={{ position: "fixed", left: x, top: y }}
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
        flip={false}
        focusTick={0}
        onRun={(it) => {
          it.run?.();
          if (!it.keepOpen) onClose();
        }}
        onBack={undefined}
      />
    </div>
  );
}
