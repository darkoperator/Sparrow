import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { Filter } from "../api";
import { schema } from "../test/fixtures";
import FilterBuilder, { FilterChips } from "./FilterBuilder";

const signins = schema().find((t) => t.name === "signins")!.columns;

function setup() {
  const onAdd = vi.fn<(f: Filter) => void>();
  render(<FilterBuilder columns={signins} onAdd={onAdd} />);
  return { onAdd, user: userEvent.setup() };
}
const pick = (label: string, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });

describe("FilterBuilder", () => {
  it("text equals sends the text as typed", async () => {
    const { onAdd, user } = setup();
    pick("Column", "user_upn");
    await user.type(screen.getByLabelText("Value"), "frances.rourke@contoso.example");
    await user.click(screen.getByRole("button", { name: "Add filter" }));
    expect(onAdd).toHaveBeenCalledExactlyOnceWith({ op: "eq", column: "user_upn", value: "frances.rourke@contoso.example" });
  });

  it("a number column sends a number, and refuses text that is not one", async () => {
    const { onAdd, user } = setup();
    pick("Column", "asn");
    await user.type(screen.getByLabelText("Value"), "64x");
    expect(screen.getByRole("button", { name: "Add filter" })).toBeDisabled();
    await user.clear(screen.getByLabelText("Value"));
    await user.type(screen.getByLabelText("Value"), "64499");
    await user.click(screen.getByRole("button", { name: "Add filter" }));
    expect(onAdd).toHaveBeenCalledExactlyOnceWith({ op: "eq", column: "asn", value: 64499 });
  });

  it("a timestamp column: between takes UTC inputs and sends RFC 3339 UTC", async () => {
    const { onAdd, user } = setup();
    pick("Column", "event_time");
    pick("Operator", "between");
    fireEvent.change(screen.getByLabelText("From (UTC)"), { target: { value: "2026-08-17T00:20" } });
    fireEvent.change(screen.getByLabelText("To (UTC)"), { target: { value: "2026-08-17T01:00:05" } });
    await user.click(screen.getByRole("button", { name: "Add filter" }));
    expect(onAdd).toHaveBeenCalledExactlyOnceWith({
      op: "between",
      column: "event_time",
      low: "2026-08-17T00:20:00Z",
      high: "2026-08-17T01:00:05Z",
    });
  });

  it("offers contains and in only where they make sense", () => {
    setup();
    pick("Column", "event_time");
    const ops = (label: string) => Array.from((screen.getByLabelText(label) as HTMLSelectElement).options).map((o) => o.value);
    expect(ops("Operator")).toEqual(["eq", "ne", "between", "is_null", "not_null"]);
    pick("Column", "user_upn");
    expect(ops("Operator")).toEqual(["eq", "ne", "contains", "in", "is_null", "not_null"]);
    pick("Column", "asn");
    expect(ops("Operator")).toEqual(["eq", "ne", "between", "in", "is_null", "not_null"]);
  });

  it("in sends one typed value per line; is empty / is not empty need no value", async () => {
    const { onAdd, user } = setup();
    pick("Column", "asn");
    pick("Operator", "in");
    await user.type(screen.getByLabelText("Values (one per line)"), "64499{Enter}64500{Enter}{Enter}");
    await user.click(screen.getByRole("button", { name: "Add filter" }));
    expect(onAdd).toHaveBeenLastCalledWith({ op: "in", column: "asn", values: [64499, 64500] });
    pick("Operator", "is_null");
    await user.click(screen.getByRole("button", { name: "Add filter" }));
    expect(onAdd).toHaveBeenLastCalledWith({ op: "is_null", column: "asn" });
    pick("Operator", "not_null");
    await user.click(screen.getByRole("button", { name: "Add filter" }));
    expect(onAdd).toHaveBeenLastCalledWith({ op: "not_null", column: "asn" });
  });

  it("contains and ne send the text", async () => {
    const { onAdd, user } = setup();
    pick("Column", "user_agent");
    pick("Operator", "contains");
    await user.type(screen.getByLabelText("Value"), "Chrome/128");
    await user.click(screen.getByRole("button", { name: "Add filter" }));
    expect(onAdd).toHaveBeenLastCalledWith({ op: "contains", column: "user_agent", value: "Chrome/128" });
  });
});

describe("FilterBuilder exact decimals", () => {
  it("sends a DECIMAL(38,18) value verbatim, not rounded through a double", async () => {
    const onAdd = vi.fn<(f: Filter) => void>();
    render(<FilterBuilder columns={[{ name: "amount", type: "DECIMAL(38,18)", comment: null }]} onAdd={onAdd} />);
    await userEvent.setup().type(screen.getByLabelText("Value"), "0.123456789123456789");
    await userEvent.setup().click(screen.getByRole("button", { name: "Add filter" }));
    expect(onAdd).toHaveBeenCalledExactlyOnceWith({ op: "eq", column: "amount", value: "0.123456789123456789" });
  });
});

describe("FilterChips", () => {
  it("shows each filter escaped and removes by index", async () => {
    const onRemove = vi.fn();
    const filters: Filter[] = [
      { op: "eq", column: "user_upn", value: "a‮b<i>" },
      { op: "between", column: "asn", low: 1, high: 2 },
      { op: "in", column: "ip", values: ["1.1.1.1", "2.2.2.2"] },
      { op: "is_null", column: "status" },
    ];
    render(<FilterChips filters={filters} onRemove={onRemove} />);
    expect(screen.getByText("user_upn equals a\\u{202E}b<i>")).toBeInTheDocument();
    expect(document.querySelector("i")).toBeNull();
    expect(screen.getByText("asn is between 1 and 2")).toBeInTheDocument();
    expect(screen.getByText("ip is in list (1.1.1.1, 2.2.2.2)")).toBeInTheDocument();
    expect(screen.getByText("status is empty")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Remove filter asn is between 1 and 2" }));
    expect(onRemove).toHaveBeenCalledExactlyOnceWith(1);
  });
});
