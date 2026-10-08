import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { sharePreview as previewFixture } from "../test/fixtures";
import type { SharePreview } from "../api";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  shareExport: vi.fn(),
  sharePreview: vi.fn(),
  shareImport: vi.fn(),
}));
const dialogSave = vi.fn();
const dialogOpen = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({
  save: (...a: unknown[]) => dialogSave(...a),
  open: (...a: unknown[]) => dialogOpen(...a),
}));

import * as api from "../api";
import Share from "./Share";

const m = { exp: vi.mocked(api.shareExport), preview: vi.mocked(api.sharePreview), imp: vi.mocked(api.shareImport) };
const SHA = "a3f1c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
let preview: SharePreview;

beforeEach(() => {
  for (const f of Object.values(m)) f.mockReset();
  dialogSave.mockReset();
  dialogOpen.mockReset();
  preview = previewFixture();
  m.exp.mockResolvedValue({ sha256: SHA, items: 7 });
  m.preview.mockImplementation(async () => preview);
  m.imp.mockImplementation(async () => preview.summary);
});

function setup(props: { canImport?: boolean; onShowQueue?: () => void } = {}) {
  const user = userEvent.setup();
  render(<Share canImport={props.canImport ?? true} onShowQueue={props.onShowQueue ?? (() => {})} />);
  return user;
}

async function previewFile(user: ReturnType<typeof userEvent.setup>, path = "/in/ann.sparrow-share.json") {
  dialogOpen.mockResolvedValue(path);
  await user.click(screen.getByRole("button", { name: "Import a bundle…" }));
  return screen.findByRole("region", { name: "Bundle preview" });
}

describe("Share — export", () => {
  it("writes the bundle to the chosen path and shows its item count and SHA-256 with a Copy button", async () => {
    dialogSave.mockResolvedValue("/out/work.sparrow-share.json");
    const user = setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText");
    await user.click(screen.getByRole("button", { name: "Export my work…" }));
    expect(m.exp).toHaveBeenCalledExactlyOnceWith("/out/work.sparrow-share.json");
    const done = await screen.findByRole("region", { name: "Exported bundle" });
    expect(done).toHaveTextContent("/out/work.sparrow-share.json");
    expect(done).toHaveTextContent("7 items");
    expect(within(done).getByText(SHA)).toBeInTheDocument();
    expect(done).toHaveTextContent("Send the SHA separately so the other analyst can check the file");
    await user.click(within(done).getByRole("button", { name: "Copy SHA-256" }));
    expect(writeText).toHaveBeenCalledExactlyOnceWith(SHA);
  });

  it("a cancelled save dialog exports nothing", async () => {
    dialogSave.mockResolvedValue(null);
    const user = setup();
    await user.click(screen.getByRole("button", { name: "Export my work…" }));
    expect(m.exp).not.toHaveBeenCalled();
    expect(screen.queryByRole("region", { name: "Exported bundle" })).toBeNull();
  });

  it("shows an export error", async () => {
    dialogSave.mockResolvedValue("/out/x.json");
    m.exp.mockRejectedValue({ kind: "invalid", message: "refusing to overwrite the case file" });
    const user = setup();
    await user.click(screen.getByRole("button", { name: "Export my work…" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("refusing to overwrite the case file");
    expect(screen.queryByRole("region", { name: "Exported bundle" })).toBeNull();
  });
});

describe("Share — import", () => {
  it("previews the bundle (nothing imported yet): analyst, counts, rule-set difference, SHA", async () => {
    const user = setup();
    const card = await previewFile(user);
    expect(m.preview).toHaveBeenCalledExactlyOnceWith("/in/ann.sparrow-share.json");
    expect(m.imp).not.toHaveBeenCalled();
    const s = preview.summary;
    expect(card).toHaveTextContent(s.analyst);
    expect(within(card).getByText(preview.sha256)).toBeInTheDocument();
    for (const [label, n] of [
      ["New", s.new],
      ["Agrees", s.agrees],
      ["Conflicts", s.conflicts],
      ["Missing here", s.missing],
    ] as const) {
      expect(within(card).getByRole("term", { name: label }).nextElementSibling).toHaveTextContent(String(n));
    }
    expect(within(card).getByText(s.rules_only_in_bundle[0])).toBeInTheDocument();
    expect(card).toHaveTextContent(/rule set differs/i);
  });

  it("Confirm imports the same file with the previewed SHA and links to the queue", async () => {
    const onShowQueue = vi.fn();
    const user = setup({ onShowQueue });
    const card = await previewFile(user);
    await user.click(within(card).getByRole("button", { name: "Confirm import" }));
    expect(m.imp).toHaveBeenCalledExactlyOnceWith("/in/ann.sparrow-share.json", preview.sha256);
    const s = preview.summary;
    const added = s.new + s.conflicts + s.missing;
    expect(await screen.findByRole("status")).toHaveTextContent(`${added} proposals added to the review queue`);
    await user.click(screen.getByRole("button", { name: "Open the review queue" }));
    expect(onShowQueue).toHaveBeenCalledTimes(1);
  });

  it("Cancel stores nothing", async () => {
    const user = setup();
    const card = await previewFile(user);
    await user.click(within(card).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("region", { name: "Bundle preview" })).toBeNull();
    expect(m.imp).not.toHaveBeenCalled();
  });

  it("a file changed since the preview is refused, and nothing claims success", async () => {
    m.imp.mockRejectedValue({ kind: "invalid", message: "the file changed since the preview" });
    const user = setup();
    const card = await previewFile(user);
    await user.click(within(card).getByRole("button", { name: "Confirm import" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("the file changed since the preview");
    expect(screen.queryByText(/added to the review queue/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Open the review queue" })).toBeNull();
    // The stale preview is gone: the analyst previews the file again.
    expect(screen.queryByRole("region", { name: "Bundle preview" })).toBeNull();
  });

  it("an already-imported bundle says so and offers no Confirm", async () => {
    preview.summary.already_imported = true;
    const user = setup();
    const card = await previewFile(user);
    expect(card).toHaveTextContent(/already imported/i);
    expect(within(card).queryByRole("button", { name: "Confirm import" })).toBeNull();
  });

  it("a preview error is shown and nothing is imported", async () => {
    const message = "the bundle's evidence differs: 3 files only in the bundle";
    m.preview.mockRejectedValue({ kind: "invalid", message });
    const user = setup();
    dialogOpen.mockResolvedValue("/in/other.json");
    await user.click(screen.getByRole("button", { name: "Import a bundle…" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("the bundle's evidence differs");
    expect(screen.queryByRole("region", { name: "Bundle preview" })).toBeNull();
    expect(m.imp).not.toHaveBeenCalled();
  });

  it("a cancelled open dialog previews nothing", async () => {
    dialogOpen.mockResolvedValue(null);
    const user = setup();
    await user.click(screen.getByRole("button", { name: "Import a bundle…" }));
    expect(m.preview).not.toHaveBeenCalled();
  });

  it("on a read-only case the preview works but Confirm is disabled", async () => {
    const user = setup({ canImport: false });
    const card = await previewFile(user);
    expect(within(card).getByRole("button", { name: "Confirm import" })).toBeDisabled();
    expect(card).toHaveTextContent(/needs a writable case and an analyst name/i);
  });

  it("bundle text is shown escaped", async () => {
    preview.summary.analyst = "analyst:ann‮<i>x</i>";
    preview.summary.rules_only_here = ["SPR-X\u0007:1"];
    const user = setup();
    const card = await previewFile(user);
    expect(card).toHaveTextContent("analyst:ann\\u{202E}<i>x</i>");
    expect(card.querySelector("i")).toBeNull();
    expect(card).toHaveTextContent("SPR-X\\u{0007}:1");
  });
});
