import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import Grid from "./Grid";

describe("Grid", () => {
  it("renders headers and cells as text through displaySafe", () => {
    render(<Grid columns={["when", "what"]} rows={[["2026-03-01", "<img src=x>‮"], ["2026-03-02", null]]} />);
    expect(screen.getByText("when")).toBeInTheDocument();
    expect(screen.getByText("<img src=x>\\u{202E}")).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText("2026-03-02")).toBeInTheDocument();
  });
  it("stringifies objects and numbers", () => {
    render(<Grid columns={["n", "o"]} rows={[[42, { a: 1 }]]} />);
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText('{"a":1}')).toBeInTheDocument();
  });
  it("calls onRowClick with the row and its index", async () => {
    const onRowClick = vi.fn();
    render(<Grid columns={["a"]} rows={[["x"], ["y"]]} onRowClick={onRowClick} />);
    await userEvent.setup().click(screen.getByText("y"));
    expect(onRowClick).toHaveBeenCalledWith(["y"], 1);
  });
  it("renders a window of a large row set, not every row", () => {
    const rows = Array.from({ length: 5000 }, (_, i) => [`row-${i}`]);
    render(<Grid columns={["a"]} rows={rows} height={200} />);
    expect(screen.getByText("row-0")).toBeInTheDocument();
    expect(screen.queryByText("row-4999")).toBeNull();
    const rendered = document.querySelectorAll('[data-row]').length;
    expect(rendered).toBeGreaterThan(0);
    expect(rendered).toBeLessThan(100);
  });
  it("says so when there are no rows", () => {
    render(<Grid columns={["a"]} rows={[]} />);
    expect(screen.getByText("No rows.")).toBeInTheDocument();
  });
});
