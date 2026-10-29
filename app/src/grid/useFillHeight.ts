import { useLayoutEffect, useState, type RefObject } from "react";
import { ROW_HEIGHT } from "./Grid";

/** A grid's smallest body height; it grows to fill the room below its top edge. */
export const GRID_MIN_HEIGHT = 200;

/** The nearest ancestor that scrolls vertically, or null for the window. */
function scrollParent(el: HTMLElement): HTMLElement | null {
  for (let p = el.parentElement; p; p = p.parentElement) {
    const y = getComputedStyle(p).overflowY;
    if (y === "auto" || y === "scroll") return p;
  }
  return null;
}

/**
 * The grid body height that makes the grid end `below` px above the bottom of its scrolling screen (the window where
 * nothing scrolls), never under `GRID_MIN_HEIGHT`. Measured after every render (filters and summaries above the grid
 * change height), on window resize and when the screen itself is resized (a banner appears); an element with no
 * layout (jsdom, a hidden tab) keeps the minimum.
 */
export function useFillHeight(box: RefObject<HTMLElement | null>, below: number): number {
  const [height, setHeight] = useState(GRID_MIN_HEIGHT);
  useLayoutEffect(() => {
    const el = box.current;
    if (!el) return;
    const sp = scrollParent(el);
    const fit = () => {
      const r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) return;
      const room = sp ? sp.clientHeight : window.innerHeight;
      const top = sp ? r.top - sp.getBoundingClientRect().top + sp.scrollTop : r.top + window.scrollY;
      const want = Math.max(GRID_MIN_HEIGHT, Math.floor(room - top - below - ROW_HEIGHT));
      setHeight((h) => (Math.abs(h - want) > 1 ? want : h));
    };
    fit();
    window.addEventListener("resize", fit);
    const ro = sp && typeof ResizeObserver !== "undefined" ? new ResizeObserver(fit) : null;
    if (sp) ro?.observe(sp);
    return () => {
      window.removeEventListener("resize", fit);
      ro?.disconnect();
    };
  });
  return height;
}
