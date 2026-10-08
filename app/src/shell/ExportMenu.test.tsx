import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  exportReport: vi.fn(),
  exportTimelineCsv: vi.fn(),
  exportWorkbook: vi.fn(),
}));
const dialogSave = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({ save: (...a: unknown[]) => dialogSave(...a) }));

import * as api from "../api";
import ExportMenu from "./ExportMenu";

beforeEach(() => {
  dialogSave.mockReset();
  for (const f of [api.exportReport, api.exportTimelineCsv, api.exportWorkbook]) {
    vi.mocked(f).mockReset();
    vi.mocked(f).mockResolvedValue(null);
  }
});

async function menu() {
  const user = userEvent.setup();
  render(<ExportMenu />);
  await user.click(screen.getByRole("button", { name: "Export" }));
  return user;
}

describe("ExportMenu", () => {
  it("passes reviewedOnly (default on) with the chosen path", async () => {
    dialogSave.mockResolvedValue("/out/report.md");
    const user = await menu();
    expect(screen.getByRole("checkbox", { name: "Reviewed only" })).toBeChecked();
    await user.click(screen.getByRole("button", { name: "Report" }));
    expect(api.exportReport).toHaveBeenCalledWith("/out/report.md", true);
    expect(await screen.findByRole("status")).toHaveTextContent("/out/report.md");
  });

  it("passes reviewedOnly false once unchecked", async () => {
    dialogSave.mockResolvedValue("/out/all.md");
    const user = await menu();
    await user.click(screen.getByRole("checkbox", { name: "Reviewed only" }));
    await user.click(screen.getByRole("button", { name: "Report" }));
    expect(api.exportReport).toHaveBeenCalledWith("/out/all.md", false);
  });

  it("exports the timeline CSV and the workbook through their own commands", async () => {
    dialogSave.mockResolvedValueOnce("/out/t.csv").mockResolvedValueOnce("/out/c.xlsx");
    const user = await menu();
    await user.click(screen.getByRole("button", { name: "Timeline CSV" }));
    expect(api.exportTimelineCsv).toHaveBeenCalledWith("/out/t.csv");
    // A successful export closes the menu.
    await user.click(screen.getByRole("button", { name: "Export" }));
    await user.click(screen.getByRole("button", { name: "Workbook" }));
    expect(api.exportWorkbook).toHaveBeenCalledWith("/out/c.xlsx");
  });

  it("a cancelled dialog writes nothing", async () => {
    dialogSave.mockResolvedValue(null);
    const user = await menu();
    await user.click(screen.getByRole("button", { name: "Report" }));
    expect(api.exportReport).not.toHaveBeenCalled();
  });

  it("shows a backend error", async () => {
    dialogSave.mockResolvedValue("/nope/report.md");
    vi.mocked(api.exportReport).mockRejectedValue({ kind: "invalid", message: "the folder /nope does not exist" });
    const user = await menu();
    await user.click(screen.getByRole("button", { name: "Report" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("the folder /nope does not exist");
  });
});
