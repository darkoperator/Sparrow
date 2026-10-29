import { describe, expect, it } from "vitest";
import { entityKindFor, rawText } from "./value";

const valueKind = (v: unknown) => entityKindFor("", v);

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

describe("entityKindFor", () => {
  const guid = "4f1c0000-1111-2222-3333-44449a2e5555";
  it("decides by column first", () => {
    expect(entityKindFor("device_id", guid)).toBe("device");
    expect(entityKindFor("entra_session_id", guid)).toBe("session");
    expect(entityKindFor("session", guid)).toBe("session");
    for (const c of ["ip", "client_ip", "from_ip"]) expect(entityKindFor(c, "203.0.113.9"), c).toBe("ip");
    for (const c of ["actor_upn", "owner_upn", "user_upn", "sender", "recipient"]) {
      expect(entityKindFor(c, "a@contoso.example"), c).toBe("account");
    }
  });
  it("gives a GUID in any other column no tab, and a listed column's wrong value none", () => {
    expect(entityKindFor("note", guid)).toBeNull();
    expect(entityKindFor("", guid)).toBeNull();
    expect(entityKindFor("ip", "a@contoso.example")).toBeNull();
    expect(entityKindFor("actor_upn", "203.0.113.9")).toBeNull();
    expect(entityKindFor("device_id", "")).toBeNull();
    expect(entityKindFor("device_id", "x\u0007")).toBeNull();
    expect(entityKindFor("device_id", 42)).toBeNull();
  });
  it("falls back to the value for other columns", () => {
    expect(entityKindFor("whatever", "2001:db8::1")).toBe("ip");
    expect(entityKindFor("whatever", "a@contoso.example")).toBe("account");
    expect(entityKindFor("constructor", "plain")).toBeNull();
  });
});
