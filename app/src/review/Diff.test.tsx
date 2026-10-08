import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Diff from "./Diff";

describe("Diff", () => {
  it("lists only the keys that changed", () => {
    render(<Diff before={{ a: 1, b: "same", c: null }} after={{ a: 2, b: "same", c: "x" }} />);
    expect(screen.getByText("a")).toBeInTheDocument();
    expect(screen.getByText("c")).toBeInTheDocument();
    expect(screen.queryByText("b")).toBeNull();
  });
  it("shows a key added from nothing", () => {
    render(<Diff before={null} after={{ title: "new" }} />);
    expect(screen.getByText("title")).toBeInTheDocument();
    expect(screen.getByText(/∅ → new/)).toBeInTheDocument();
  });
  it("renders values as safe text", () => {
    render(<Diff before={{ t: "a" }} after={{ t: "<i>x</i>‮" }} />);
    expect(screen.getByText(/<i>x<\/i>\\u\{202E\}/)).toBeInTheDocument();
    expect(document.querySelector("i")).toBeNull();
  });
  it("says so when nothing changed", () => {
    render(<Diff before={{ a: 1 }} after={{ a: 1 }} />);
    expect(screen.getByText("no change")).toBeInTheDocument();
  });
});
