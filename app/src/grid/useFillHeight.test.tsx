import { render } from "@testing-library/react";
import { useRef } from "react";
import { describe, expect, it } from "vitest";
import { ROW_HEIGHT } from "./Grid";
import { GRID_MIN_HEIGHT, useFillHeight } from "./useFillHeight";

function Probe({ below, onHeight }: { below: number; onHeight: (h: number) => void }) {
  const box = useRef<HTMLDivElement>(null);
  onHeight(useFillHeight(box, below));
  return (
    <div data-testid="area" style={{ overflowY: "auto" }}>
      <div data-testid="box" ref={box} />
    </div>
  );
}

/** Gives the screen area `areaHeight` of room and the box `boxTop` px from the area's top edge (the area starts at y 100). */
function layout(area: HTMLElement, box: HTMLElement, areaHeight: number, boxTop: number, scrolled = 0) {
  Object.defineProperty(area, "clientHeight", { configurable: true, value: areaHeight });
  area.scrollTop = scrolled;
  area.getBoundingClientRect = () => ({ top: 100, width: 800, height: areaHeight }) as DOMRect;
  box.getBoundingClientRect = () => ({ top: 100 + boxTop - scrolled, width: 800, height: 50 }) as DOMRect;
}

describe("useFillHeight", () => {
  it("keeps the minimum where nothing has layout", () => {
    let h = 0;
    render(<Probe below={16} onHeight={(v) => (h = v)} />);
    expect(h).toBe(GRID_MIN_HEIGHT);
  });

  it("fills the screen area below the box: its height, minus the box's offset, the space kept under and the header row", () => {
    let h = 0;
    const { getByTestId, rerender } = render(<Probe below={16} onHeight={(v) => (h = v)} />);
    layout(getByTestId("area"), getByTestId("box"), 700, 250);
    rerender(<Probe below={16} onHeight={(v) => (h = v)} />);
    expect(h).toBe(700 - 250 - 16 - ROW_HEIGHT);
  });

  it("measures the box against the area's content, so a scrolled area gives the same height", () => {
    let h = 0;
    const { getByTestId, rerender } = render(<Probe below={20} onHeight={(v) => (h = v)} />);
    layout(getByTestId("area"), getByTestId("box"), 700, 250, 60);
    rerender(<Probe below={20} onHeight={(v) => (h = v)} />);
    expect(h).toBe(700 - 250 - 20 - ROW_HEIGHT);
  });

  it("never goes under the minimum", () => {
    let h = 0;
    const { getByTestId, rerender } = render(<Probe below={16} onHeight={(v) => (h = v)} />);
    layout(getByTestId("area"), getByTestId("box"), 400, 350);
    rerender(<Probe below={16} onHeight={(v) => (h = v)} />);
    expect(h).toBe(GRID_MIN_HEIGHT);
  });
});
