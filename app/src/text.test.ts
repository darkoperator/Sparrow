import { describe, expect, it } from "vitest";
import { displaySafe } from "./text";

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
