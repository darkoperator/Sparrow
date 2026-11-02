import { describe, expect, it } from "vitest";
import { displaySafe, displaySafeMultiline, unwrapLines } from "./text";

describe("displaySafe", () => {
  it("escapes control and bidi characters", () => {
    expect(displaySafe("a\u0000b")).toBe("a\\u{0000}b");
    expect(displaySafe("x‮y")).toBe("x\\u{202E}y");
    expect(displaySafe("line1\nline2")).toBe("line1\\u{000A}line2");
  });
  it("leaves ordinary text alone", () => {
    expect(displaySafe("Inbox rule <b>AP</b> → é\tz")).toBe("Inbox rule <b>AP</b> → é\tz");
  });
});

describe("displaySafeMultiline", () => {
  it("keeps line breaks and escapes everything else", () => {
    expect(displaySafeMultiline("a\r\nb‮c\nd\u0000")).toBe("a\nb\\u{202E}c\nd\\u{0000}");
  });
});

describe("unwrapLines", () => {
  it("joins hard-wrapped lines and keeps blank lines and list items", () => {
    expect(unwrapLines("one\ntwo\n\nthree\r\nfour\n- a\n- b\n")).toBe("one two\n\nthree four\n- a\n- b");
  });
});
