import { describe, expect, it } from "vitest";
import { columnKind, toRfc3339Utc, typedValue } from "./columnKind";

describe("columnKind", () => {
  it("groups catalog types", () => {
    expect(columnKind("BIGINT")).toBe("number");
    expect(columnKind("DOUBLE")).toBe("number");
    expect(columnKind("DECIMAL(18,3)")).toBe("number");
    expect(columnKind("TIMESTAMP WITH TIME ZONE")).toBe("time");
    expect(columnKind("DATE")).toBe("date");
    expect(columnKind("VARCHAR")).toBe("text");
    expect(columnKind("BOOLEAN")).toBe("text");
    expect(columnKind("ENUM('a', 'b')")).toBe("text");
  });
});

describe("typedValue", () => {
  it("reads datetime-local as UTC RFC 3339", () => {
    expect(toRfc3339Utc("2026-08-17T00:20")).toBe("2026-08-17T00:20:00Z");
    expect(toRfc3339Utc("2026-08-17T00:20:25")).toBe("2026-08-17T00:20:25Z");
    expect(typedValue("time", "2026-08-17T00:20")).toBe("2026-08-17T00:20:00Z");
  });
  it("only safe integers are numbers; every other valid decimal or exponent stays its exact text; junk is null", () => {
    expect(typedValue("number", " 64499 ")).toBe(64499);
    expect(typedValue("number", "-7")).toBe(-7);
    expect(typedValue("number", "-1.5")).toBe("-1.5");
    expect(typedValue("number", "0.123456789123456789")).toBe("0.123456789123456789");
    expect(typedValue("number", "1e3")).toBe("1e3");
    expect(typedValue("number", ".5")).toBe(".5");
    expect(typedValue("number", "9007199254740993")).toBe("9007199254740993");
    for (const bad of ["1e", "--1", "1,5", "0x10", "NaN", "Infinity", "1e999"]) expect(typedValue("number", bad), bad).toBeNull();
    expect(typedValue("number", "12abc")).toBeNull();
    expect(typedValue("number", "")).toBeNull();
  });
  it("text and date keep the text untouched", () => {
    expect(typedValue("text", " a b ")).toBe(" a b ");
    expect(typedValue("date", "2026-08-17")).toBe("2026-08-17");
  });
});
