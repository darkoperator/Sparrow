import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

import { call, isCmdError } from "./api";

describe("call", () => {
  beforeEach(() => {
    invoke.mockReset();
  });

  it("passes the command and its args to invoke and returns the result", async () => {
    invoke.mockResolvedValue({ ok: 1 });
    await expect(call("case_open", { path: "/c.duckdb" })).resolves.toEqual({ ok: 1 });
    expect(invoke).toHaveBeenCalledWith("case_open", { path: "/c.duckdb" });
  });

  it("rethrows a command error unchanged", async () => {
    invoke.mockRejectedValue({ kind: "writer_busy", message: "busy" });
    await expect(call("case_open")).rejects.toEqual({ kind: "writer_busy", message: "busy" });
  });

  it("turns any other rejection into an internal command error", async () => {
    invoke.mockRejectedValue("command case_x not found");
    await expect(call("case_x")).rejects.toEqual({ kind: "internal", message: "command case_x not found" });
  });

  it("turns an error with an unknown kind into an internal command error", async () => {
    invoke.mockRejectedValue({ kind: "timeout", message: "plugin timed out" });
    await expect(call("case_open")).rejects.toEqual({ kind: "internal", message: "plugin timed out" });
  });
});

describe("isCmdError", () => {
  it("accepts only {kind, message} with string fields", () => {
    expect(isCmdError({ kind: "invalid", message: "m" })).toBe(true);
    expect(isCmdError({ kind: "invalid" })).toBe(false);
    expect(isCmdError({ kind: 1, message: "m" })).toBe(false);
    expect(isCmdError({ kind: "timeout", message: "m" })).toBe(false);
    for (const kind of ["not_found", "invalid", "decision", "writer_busy", "read_only", "no_case", "internal"]) {
      expect(isCmdError({ kind, message: "m" })).toBe(true);
    }
    expect(isCmdError("invalid")).toBe(false);
    expect(isCmdError(null)).toBe(false);
  });
});
