import { describe, expect, it } from "vitest";
import { rawText, valueKind } from "./value";

describe("valueKind", () => {
  it("recognises IPv4 and IPv6 addresses", () => {
    for (const ip of ["203.0.113.1", "0.0.0.0", "255.255.255.255", "2001:db8::1", "::1", "::ffff:192.0.2.1"]) {
      expect(valueKind(ip), ip).toBe("ip");
    }
  });
  it("rejects look-alikes", () => {
    for (const s of ["256.1.1.1", "1.2.3", "1.2.3.4.5", "01.2.3.4x", "2001:db8::g", "::::", "12:34", "host.example"]) {
      expect(valueKind(s), s).toBeNull();
    }
  });
  it("recognises account-shaped values only", () => {
    expect(valueKind("marlowe.rhodes@contoso.example")).toBe("account");
    for (const s of ["a@", "@b", "a b@c", "a@b c", "x@y\u0007", ""]) expect(valueKind(s), s).toBeNull();
    expect(valueKind(`${"a".repeat(320)}@b`)).toBeNull();
  });
  it("is null for non-strings", () => {
    expect(valueKind(42)).toBeNull();
    expect(valueKind(null)).toBeNull();
    expect(valueKind({ ip: "203.0.113.1" })).toBeNull();
  });
});

describe("rawText", () => {
  it("keeps strings untouched and stringifies the rest", () => {
    expect(rawText("a‮b")).toBe("a‮b");
    expect(rawText(null)).toBe("");
    expect(rawText(7)).toBe("7");
    expect(rawText({ a: 1 })).toBe('{"a":1}');
  });
});
