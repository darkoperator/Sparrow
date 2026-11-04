import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CmdError, DiscoveryPreview, IngestProgress, IngestResult, PreviewFile } from "../api";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  ingestDiscover: vi.fn(),
  ingestRun: vi.fn(),
  ingestCancel: vi.fn(),
  onIngestProgress: vi.fn(),
  onIngestClosing: vi.fn(),
}));
const dialogOpen = vi.fn();
const dialogSave = vi.fn();
vi.mock("../dialog", () => ({
  open: (...a: unknown[]) => dialogOpen(...a),
  save: (...a: unknown[]) => dialogSave(...a),
}));

import * as api from "../api";
import ImportDialog from "./ImportDialog";

const m = {
  discover: vi.mocked(api.ingestDiscover),
  run: vi.mocked(api.ingestRun),
  cancel: vi.mocked(api.ingestCancel),
  listen: vi.mocked(api.onIngestProgress),
  closing: vi.mocked(api.onIngestClosing),
};

const file = (
  rel_path: string,
  status: PreviewFile["status"],
  artifact_id: string | null = "invictus.signins",
  size = 2048,
  too_large = false,
): PreviewFile => ({
  rel_path, artifact_id, derived: false, size, status, too_large, error: null,
});

function previewOf(files: PreviewFile[], extra: Partial<DiscoveryPreview> = {}): DiscoveryPreview {
  const count = (s: PreviewFile["status"]) => files.filter((f) => f.status === s).length;
  return {
    path: "/evidence/run-1",
    collections: [{ tool: "invictus", root: "/evidence/run-1", tenant_hint: "contoso.example", started_hint: null, files }],
    recognised: count("recognised"),
    unrecognised: count("unrecognised"),
    too_large: files.filter((f) => f.too_large).length,
    unreadable: count("unreadable"),
    xlsx_max_bytes: 1_073_741_824,
    ...extra,
  };
}

const FILES = [
  file("UnifiedAuditLog/SignInLogs.csv", "recognised"),
  file("UnifiedAuditLog/UAL.csv", "recognised", "invictus.ual", 5_000_000),
  file("README.txt", "unrecognised", null, 300),
];

function resultOf(extra: Partial<IngestResult> = {}): IngestResult {
  return {
    case_path: "/cases/new.duckdb",
    cancelled: false,
    error: null,
    report: { collections: [] },
    files_loaded: 2,
    files_total: 3,
    rows_by_source: [
      { source: "invictus.signins", files: 1, rows: 1200 },
      { source: "invictus.ual", files: 1, rows: 34000 },
    ],
    file_notes: [{ root: "/evidence/run-1", rel_path: "UnifiedAuditLog/UAL.csv", status: "parsed", notes: ["3 records rejected", "dates were ambiguous"] }],
    not_loaded: [],
    profile_error: null,
    profile_warnings: [],
    detect: { findings_new: 4, findings_updated: 1, warnings: [] },
    detect_error: null,
    ...extra,
  };
}

let emit: (p: IngestProgress) => void = () => {};
let closeNow: () => void = () => {};
const off = vi.fn();
const offClosing = vi.fn();

beforeEach(() => {
  for (const f of Object.values(m)) f.mockReset();
  dialogOpen.mockReset();
  dialogSave.mockReset();
  off.mockReset();
  m.listen.mockImplementation(async (h) => {
    emit = h;
    return off;
  });
  m.cancel.mockResolvedValue(null);
  m.closing.mockImplementation(async (h) => {
    closeNow = h;
    return offClosing;
  });
  dialogOpen.mockResolvedValue("/evidence/run-1");
  m.discover.mockResolvedValue(previewOf(FILES));
});

const onClose = vi.fn();
const onOpenCase = vi.fn();
beforeEach(() => {
  onClose.mockReset();
  onOpenCase.mockReset();
});

async function pickFolder(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: /^Choose a folder/ }));
  await screen.findByRole("region", { name: "Discovery" });
}

describe("ImportDialog preview", () => {
  it("asks for a directory, then shows what discovery found before anything is written", async () => {
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    expect(screen.getByRole("button", { name: "Import" })).toBeDisabled();
    await pickFolder(user);
    expect(dialogOpen).toHaveBeenCalledWith(expect.objectContaining({ directory: true }));
    expect(m.discover).toHaveBeenCalledWith("/evidence/run-1");
    expect(m.run).not.toHaveBeenCalled();
    const region = screen.getByRole("region", { name: "Discovery" });
    expect(within(region).getByRole("status")).toHaveTextContent("1 collection · 2 recognised · 1 not recognised");
    expect(within(region).getByText("UnifiedAuditLog/SignInLogs.csv")).toBeInTheDocument();
    expect(within(region).getAllByText("recognised")).toHaveLength(2);
    expect(within(region).getByText("not recognised", { selector: ".pill" })).toBeInTheDocument();
    expect(within(region).getByText("4.8 MiB")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import" })).toBeEnabled();
  });

  it("a cancelled folder dialog does nothing", async () => {
    dialogOpen.mockResolvedValue(null);
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await user.click(screen.getByRole("button", { name: /^Choose a folder/ }));
    expect(m.discover).not.toHaveBeenCalled();
  });

  it("a folder with nothing recognised says so and cannot be imported", async () => {
    m.discover.mockResolvedValue(previewOf([file("README.txt", "unrecognised", null)]));
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    expect(screen.getByText(/recognises none of the files here/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import" })).toBeDisabled();
    expect(screen.queryByLabelText(/Dates written/)).not.toBeInTheDocument();
  });

  it("a folder with no collection says what was looked for", async () => {
    m.discover.mockResolvedValue({ ...previewOf([]), collections: [] });
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await user.click(screen.getByRole("button", { name: /^Choose a folder/ }));
    expect(await screen.findByText(/no Hawk, Microsoft-Extractor-Suite or portal export output was found/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import" })).toBeDisabled();
  });

  it("a workbook over the XLSX limit is flagged and the limit is explained", async () => {
    m.discover.mockResolvedValue(
      // As the real preview lists it: a workbook over the limit is not read, so it is not classified.
      previewOf([...FILES, file("InteractiveSignins.xlsx", "unrecognised", null, 1_200_000_000, true)]),
    );
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    expect(screen.getByRole("status")).toHaveTextContent("2 recognised · 2 not recognised · 1 over the size limit");
    expect(screen.getByText("over the size limit", { selector: ".pill" })).toBeInTheDocument();
    // Its row shows the size pill, not "not recognised" (only README.txt does).
    expect(screen.getAllByText("not recognised", { selector: ".pill" })).toHaveLength(1);
    expect(screen.getByText(/XLSX workbooks over 1\.0 GiB are not loaded/)).toBeInTheDocument();
  });

  it("big recognised files count as recognised, whatever their size", async () => {
    const big = 3_006_477_107;
    m.discover.mockResolvedValue(
      previewOf([
        file("Aug UAL.csv", "recognised", "portal.ual", big),
        file("July UAL.csv", "recognised", "portal.ual", big),
        file("June UAL.csv", "recognised", "portal.ual", big),
      ]),
    );
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    expect(screen.getByRole("status")).toHaveTextContent("1 collection · 3 recognised · 0 not recognised");
    expect(screen.queryByText(/recognises none/)).not.toBeInTheDocument();
    expect(screen.queryByText("over the size limit", { selector: ".pill" })).not.toBeInTheDocument();
    expect(screen.getAllByText("recognised", { selector: ".pill" })).toHaveLength(3);
    expect(screen.getByRole("button", { name: "Import" })).toBeEnabled();
  });

  it("shows a discovery error and keeps the dialog usable", async () => {
    m.discover.mockRejectedValueOnce({ kind: "invalid", message: "/evidence/run-1 is not a folder" } satisfies CmdError);
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await user.click(screen.getByRole("button", { name: /^Choose a folder/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("is not a folder");
    await user.click(screen.getByRole("button", { name: /^Choose a folder/ }));
    await screen.findByRole("region", { name: "Discovery" });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("prints control and bidi characters of a file name as escapes", async () => {
    m.discover.mockResolvedValue(previewOf([file("evil‮gnp.csv", "recognised")]));
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    expect(screen.getByText("evil\\u{202E}gnp.csv")).toBeInTheDocument();
  });

  it("closing before importing reports no change", async () => {
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalledWith(false);
    onClose.mockReset();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledWith(false);
  });
});

describe("ImportDialog options", () => {
  it("runs into the open case with the chosen culture and detection setting", async () => {
    m.run.mockResolvedValue(resultOf());
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    await user.selectOptions(screen.getByLabelText(/Dates written/), "en-GB");
    await user.click(screen.getByRole("checkbox", { name: /Skip detection/ }));
    await user.click(screen.getByRole("button", { name: "Import" }));
    expect(m.run).toHaveBeenCalledWith("/evidence/run-1", "open", "en-GB", false, expect.any(String));
  });

  it("defaults: culture worked out, detection on", async () => {
    m.run.mockResolvedValue(resultOf());
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Import" }));
    expect(m.run).toHaveBeenCalledWith("/evidence/run-1", "open", null, true, expect.any(String));
  });

  it("a new case needs a save path first, and sends it as the target", async () => {
    m.run.mockResolvedValue(resultOf());
    dialogSave.mockResolvedValue("/cases/new.duckdb");
    const user = userEvent.setup();
    render(<ImportDialog mode="new" onClose={onClose} onOpenCase={onOpenCase} />);
    await pickFolder(user);
    const go = screen.getByRole("button", { name: "Create the case and import" });
    expect(go).toBeDisabled();
    expect(go).toHaveAttribute("title", "Choose where to save the case first");
    await user.click(screen.getByRole("button", { name: "Choose where to save…" }));
    expect(dialogSave).toHaveBeenCalledWith(expect.objectContaining({ filters: [{ name: "Sparrow case", extensions: ["duckdb"] }] }));
    expect(screen.getByText("/cases/new.duckdb")).toBeInTheDocument();
    await user.click(go);
    expect(m.run).toHaveBeenCalledWith("/evidence/run-1", { new_case: "/cases/new.duckdb" }, null, true, expect.any(String));
  });

  it("a cancelled save dialog leaves the path unset", async () => {
    dialogSave.mockResolvedValue(null);
    const user = userEvent.setup();
    render(<ImportDialog mode="new" onClose={onClose} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Choose where to save…" }));
    expect(screen.getByRole("button", { name: "Create the case and import" })).toBeDisabled();
  });
});

describe("ImportDialog progress and result", () => {
  it("shows the stage and file while running, cancels, and reports what was left", async () => {
    let finish: (r: IngestResult) => void = () => {};
    m.run.mockReturnValue(new Promise<IngestResult>((r) => (finish = r)));
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Import" }));
    await waitFor(() => expect(m.run).toHaveBeenCalled());
    expect(screen.getByRole("status")).toHaveTextContent("Looking through the folder");
    emit({ stage: "collection", index: 1, count: 2, root: "/evidence/run-1" });
    expect(await screen.findByText("Collection 1 of 2")).toBeInTheDocument();
    emit({
      stage: "file",
      collection: 1,
      collections: 2,
      index: 2,
      files: 6,
      rel_path: "UnifiedAuditLog/UAL.csv",
      size: 1024,
      bytes_done_before: 2048,
      bytes_total: 8192,
    });
    expect(await screen.findByText("Collection 1 of 2 · Overall: file 2 of 6")).toBeInTheDocument();
    expect(screen.getByText("UnifiedAuditLog/UAL.csv")).toBeInTheDocument();
    // 2048 of 8192 bytes are behind it: a quarter of the import.
    const bar = screen.getByRole("progressbar", { name: "Import progress" });
    expect(bar).toHaveAttribute("aria-valuenow", "25");
    expect(bar).toHaveAttribute("aria-valuemax", "100");
    // While it runs there is no close button, and Escape does nothing.
    expect(screen.queryByRole("button", { name: "Close" })).not.toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(onClose).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(m.cancel).toHaveBeenCalledTimes(1);
    // The Cancel names the run the import was started with.
    expect(m.cancel).toHaveBeenCalledWith(m.run.mock.calls[0][4]);
    expect(screen.getByRole("button", { name: "Stopping…" })).toBeDisabled();
    finish(resultOf({
      cancelled: true,
      files_loaded: 2,
      files_total: 6,
      not_loaded: [{ root: "/evidence/run-1", rel_path: "Exchange/MessageTrace.csv" }],
      detect: null,
    }));
    const card = await screen.findByRole("region", { name: "Import result" });
    expect(within(card).getByRole("status")).toHaveTextContent("Cancelled: 2 of 6 files loaded, 1 not loaded");
    expect(within(card).getByText("Exchange/MessageTrace.csv")).toBeInTheDocument();
    expect(within(card).getByText("Detection did not run (the import was cancelled).")).toBeInTheDocument();
    expect(off).toHaveBeenCalled();
    await user.click(within(card).getByRole("button", { name: "Done" }));
    expect(onClose).toHaveBeenCalledWith(true);
  });

  it("the result card has the rows per source, the notes per file and the new findings", async () => {
    m.run.mockResolvedValue(resultOf());
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Import" }));
    const card = await screen.findByRole("region", { name: "Import result" });
    expect(within(card).getByRole("status")).toHaveTextContent("Imported 2 of 3 files · 35,200 rows");
    const rows = within(within(card).getByRole("table")).getAllByRole("row");
    expect(rows.map((r) => r.textContent)).toEqual([
      "invictus.signins1 file1,200",
      "invictus.ual1 file34,000",
    ]);
    expect(within(card).getByText("3 records rejected")).toBeInTheDocument();
    expect(within(card).getByText("dates were ambiguous")).toBeInTheDocument();
    expect(within(card).getByText("Detection: 4 new findings, 1 updated")).toBeInTheDocument();
    expect(within(card).queryByText("Not loaded")).not.toBeInTheDocument();
  });

  it("says when the profile or detection failed after the evidence loaded", async () => {
    m.run.mockResolvedValue(resultOf({ profile_error: "no tenant found", detect: null, detect_error: "rule X failed" }));
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Import" }));
    const alerts = await screen.findAllByRole("alert");
    expect(alerts[0]).toHaveTextContent("The evidence loaded but the profile step failed: no tenant found");
    expect(alerts[1]).toHaveTextContent("Detection failed: rule X failed");
  });

  it("a skipped detection is stated", async () => {
    m.run.mockResolvedValue(resultOf({ detect: null }));
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Import" }));
    expect(await screen.findByText("Detection was skipped.")).toBeInTheDocument();
  });

  it("a new case offers to open the case that was made", async () => {
    m.run.mockResolvedValue(resultOf());
    dialogSave.mockResolvedValue("/cases/new.duckdb");
    const user = userEvent.setup();
    render(<ImportDialog mode="new" onClose={onClose} onOpenCase={onOpenCase} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Choose where to save…" }));
    await user.click(screen.getByRole("button", { name: "Create the case and import" }));
    await user.click(await screen.findByRole("button", { name: "Open the new case" }));
    expect(onOpenCase).toHaveBeenCalledWith("/cases/new.duckdb");
  });

  it("an import that fails shows the error, stops listening, and still reports a possible change", async () => {
    m.run.mockRejectedValue({ kind: "read_only", message: "the audit chain is broken at seq 3" } satisfies CmdError);
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Import" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("the audit chain is broken at seq 3");
    expect(off).toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledWith(true);
  });
});

describe("ImportDialog hardening", () => {
  it("a Cancel pressed before the run has even been invoked still names its run", async () => {
    // The progress subscription is slow to resolve: the dialog is already showing Cancel.
    let release: (off: () => void) => void = () => {};
    m.listen.mockImplementationOnce(() => new Promise((r) => (release = r)));
    m.run.mockResolvedValue(resultOf({ cancelled: true }));
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Import" }));
    await user.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(m.cancel).toHaveBeenCalledTimes(1);
    expect(m.run).not.toHaveBeenCalled();
    release(off);
    await waitFor(() => expect(m.run).toHaveBeenCalled());
    expect(m.cancel.mock.calls[0][0]).toBe(m.run.mock.calls[0][4]);
    expect(m.run.mock.calls[0][4]).toMatch(/\S+/);
  });

  it("every run gets its own id", async () => {
    m.run.mockResolvedValue(resultOf());
    const user = userEvent.setup();
    const { unmount } = render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Import" }));
    await screen.findByRole("region", { name: "Import result" });
    unmount();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Import" }));
    await waitFor(() => expect(m.run).toHaveBeenCalledTimes(2));
    expect(m.run.mock.calls[0][4]).not.toBe(m.run.mock.calls[1][4]);
  });

  it("a window close during the import says it is stopping and rolling back the file being loaded", async () => {
    m.run.mockReturnValue(new Promise<IngestResult>(() => {}));
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Import" }));
    await waitFor(() => expect(m.run).toHaveBeenCalled());
    closeNow();
    expect(await screen.findByText(/Stopping and rolling back the file being loaded…/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Stopping…" })).toBeDisabled();
  });

  it("a hard error after some files shows the file card with the error, not only a message", async () => {
    m.run.mockResolvedValue(
      resultOf({
        error: "database error: disk full",
        detect: null,
        files_loaded: 2,
        files_total: 6,
        not_loaded: [{ root: "/evidence/run-1", rel_path: "Exchange/MessageTrace.csv" }],
      }),
    );
    const user = userEvent.setup();
    render(<ImportDialog mode="open" onClose={onClose} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Import" }));
    const card = await screen.findByRole("region", { name: "Import result" });
    expect(within(card).getByRole("status")).toHaveTextContent("Stopped by an error: 2 of 6 files loaded, 1 not loaded");
    expect(within(card).getByRole("alert")).toHaveTextContent("database error: disk full");
    expect(within(card).getByText("Exchange/MessageTrace.csv")).toBeInTheDocument();
    expect(within(card).getByText("invictus.ual")).toBeInTheDocument();
    expect(within(card).getByText("Detection did not run (the import stopped on an error).")).toBeInTheDocument();
  });

  it("keeps keyboard focus inside the dialog", async () => {
    const user = userEvent.setup();
    render(
      <>
        <button>behind the dialog</button>
        <ImportDialog mode="open" onClose={onClose} />
      </>,
    );
    const dialog = screen.getByRole("dialog");
    for (let i = 0; i < 8; i++) {
      await user.tab();
      expect(dialog).toContainElement(document.activeElement as HTMLElement);
    }
    for (let i = 0; i < 8; i++) {
      await user.tab({ shift: true });
      expect(dialog).toContainElement(document.activeElement as HTMLElement);
    }
  });
});

describe("ImportDialog in-file progress", () => {
  const GiB = 1024 ** 3;
  const S = Math.round(2.8 * GiB);
  const STEPS = ["Checking file", "Checking dates", "Loading records"];
  const fileEvent = (index: number, extra: Partial<Extract<IngestProgress, { stage: "file" }>> = {}): IngestProgress => ({
    stage: "file",
    collection: 1,
    collections: 1,
    index,
    files: 3,
    rel_path: ["Aug UAL.csv", "July UAL.csv", "June UAL.csv"][index - 1],
    size: S,
    bytes_done_before: (index - 1) * S,
    bytes_total: 3 * S,
    ...extra,
  });
  const stepEvent = (step: number, bytes_done: number, records = 0, errors = 0, bytes_total = S): IngestProgress => ({
    stage: "file_step", steps: STEPS, step, bytes_done, bytes_total, records, errors,
  });

  let now = 0;
  const clock = () => now;

  async function running(user: ReturnType<typeof userEvent.setup>) {
    m.run.mockReturnValue(new Promise<IngestResult>(() => {}));
    render(<ImportDialog mode="open" onClose={onClose} clock={clock} />);
    await pickFolder(user);
    await user.click(screen.getByRole("button", { name: "Import" }));
    await waitFor(() => expect(m.run).toHaveBeenCalled());
  }
  const overall = () => screen.getByRole("progressbar", { name: "Import progress" });
  const thisFile = () => screen.getByRole("progressbar", { name: "This file" });

  beforeEach(() => {
    now = 1_000_000;
  });

  it("shows the overall bar, this file's bar, its steps and its counts", async () => {
    const user = userEvent.setup();
    await running(user);
    emit(fileEvent(1));
    emit(stepEvent(2, Math.round(1.1 * GiB), 412_880, 9));
    expect(await screen.findByText("1.1 of 2.8 GiB · 412,880 records · 9 errors")).toBeInTheDocument();
    expect(screen.getByText("Overall: file 1 of 3")).toBeInTheDocument();
    expect(screen.getByText("8.4 GiB total")).toBeInTheDocument();
    expect(screen.getByText("Aug UAL.csv")).toBeInTheDocument();
    // This file: 1.1 of 2.8 GiB through its last pass. Overall: two of three passes done and 39% of the third,
    // of a file that is a third of the import.
    expect(thisFile()).toHaveAttribute("aria-valuenow", "39");
    expect(thisFile()).toHaveAttribute("aria-valuemin", "0");
    expect(thisFile()).toHaveAttribute("aria-valuemax", "100");
    expect(overall()).toHaveAttribute("aria-valuenow", "26");
    const chips = within(screen.getByRole("list", { name: "Steps" })).getAllByRole("listitem");
    expect(chips.map((c) => c.textContent)).toEqual(["✓ Checking file", "✓ Checking dates", "Loading records"]);
    expect(chips[2]).toHaveAttribute("aria-current", "step");
    expect(chips[0]).not.toHaveAttribute("aria-current");
    expect(screen.getByText("Cancel stops now; this file is rolled back, files already loaded stay.")).toBeInTheDocument();
  });

  it("shows the merge as its own step once the passes are done", async () => {
    const user = userEvent.setup();
    await running(user);
    emit(fileEvent(1));
    const saving = ["Checking file", "Checking dates", "Loading records", "Saving records"];
    emit({ stage: "file_step", steps: saving, step: 3, bytes_done: 0, bytes_total: S, records: 1_388_247, errors: 0 });
    await waitFor(() =>
      expect(within(screen.getByRole("list", { name: "Steps" })).getAllByRole("listitem").map((c) => c.textContent)).toEqual([
        "✓ Checking file",
        "✓ Checking dates",
        "✓ Loading records",
        "Saving records",
      ]),
    );
    const chips = within(screen.getByRole("list", { name: "Steps" })).getAllByRole("listitem");
    expect(chips[3]).toHaveAttribute("aria-current", "step");
    // The merge reads nothing: this file's bar is indeterminate and the line says what it does, not "0 B of".
    expect(thisFile()).toHaveAttribute("aria-valuetext", "Saving records");
    expect(thisFile()).not.toHaveAttribute("aria-valuenow");
    expect(thisFile()).toHaveClass("import-bar-indeterminate");
    expect(screen.getByText("1,388,247 records · saving…")).toBeInTheDocument();
    expect(screen.queryByText(/0 B of/)).not.toBeInTheDocument();
    // Three of four steps of a file that is a third of the import.
    expect(overall()).toHaveAttribute("aria-valuenow", "25");
    // Cancel waits for the statement there.
    expect(
      screen.getByText("Cancel takes effect when saving ends; this file is then rolled back, files already loaded stay."),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Cancel stops now/)).not.toBeInTheDocument();
    // The next file's reading step shows its bytes and bar again.
    emit(fileEvent(2));
    emit(stepEvent(1, Math.round(1.1 * GiB)));
    expect(await screen.findByText("1.1 of 2.8 GiB · 0 records · 0 errors")).toBeInTheDocument();
    expect(thisFile()).toHaveAttribute("aria-valuenow", "39");
    expect(screen.getByText("Cancel stops now; this file is rolled back, files already loaded stay.")).toBeInTheDocument();
  });

  it("shows the detail sort as a step that reads nothing", async () => {
    const user = userEvent.setup();
    await running(user);
    emit(fileEvent(1));
    const detail = ["Checking file", "Grouping messages", "Sorting messages", "Checking dates", "Loading records", "Saving records"];
    emit({ stage: "file_step", steps: detail, step: 2, bytes_done: 0, bytes_total: S, records: 0, errors: 0 });
    expect(await screen.findByText("0 records · sorting…")).toBeInTheDocument();
    expect(thisFile()).toHaveAttribute("aria-valuetext", "Sorting messages");
    expect(thisFile()).not.toHaveAttribute("aria-valuenow");
    expect(
      screen.getByText("Cancel takes effect when sorting ends; this file is then rolled back, files already loaded stay."),
    ).toBeInTheDocument();
  });

  it("Cancel asks the backend at once and says the file is being rolled back", async () => {
    const user = userEvent.setup();
    await running(user);
    emit(fileEvent(1));
    emit(stepEvent(2, Math.round(1.1 * GiB)));
    await user.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(m.cancel).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Stopping and rolling back the file being loaded…")).toBeInTheDocument();
    expect(screen.queryByText(/Cancel stops now/)).not.toBeInTheDocument();
  });

  it("the overall bar never goes back when the import's total grows", async () => {
    const user = userEvent.setup();
    await running(user);
    emit(fileEvent(1));
    emit(stepEvent(2, S));
    await waitFor(() => expect(overall()).toHaveAttribute("aria-valuenow", "33"));
    // A copy expected to be skipped is parsed after all: the total doubles, so the computed fraction is 1/6.
    emit(fileEvent(2, { bytes_done_before: S, bytes_total: 6 * S }));
    await screen.findByText("Overall: file 2 of 3");
    expect(overall()).toHaveAttribute("aria-valuenow", "33");
    emit(stepEvent(0, S / 2));
    expect(overall()).toHaveAttribute("aria-valuenow", "33");
    emit(stepEvent(2, S));
    expect(overall()).toHaveAttribute("aria-valuenow", "33");
    // Once the computed fraction passes the shown one, it moves on.
    emit(fileEvent(3, { bytes_done_before: 3 * S, bytes_total: 6 * S }));
    await waitFor(() => expect(overall()).toHaveAttribute("aria-valuenow", "50"));
  });

  it("a zero total never shows NaN", async () => {
    const user = userEvent.setup();
    await running(user);
    emit(fileEvent(1, { size: 0, bytes_total: 0 }));
    emit(stepEvent(0, 0, 0, 0, 0));
    await screen.findByText("Overall: file 1 of 3");
    expect(overall()).toHaveAttribute("aria-valuenow", "0");
    expect(thisFile()).toHaveAttribute("aria-valuenow", "0");
  });

  it("a new file resets this file's view", async () => {
    const user = userEvent.setup();
    await running(user);
    emit(fileEvent(1));
    emit(stepEvent(2, Math.round(1.1 * GiB), 412_880, 9));
    await screen.findByText("1.1 of 2.8 GiB · 412,880 records · 9 errors");
    // The next file is refused before it is read: no file_step comes for it.
    emit(fileEvent(2));
    await screen.findByText("July UAL.csv");
    expect(screen.queryByText(/412,880 records/)).not.toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Steps" })).not.toBeInTheDocument();
    expect(thisFile()).toHaveAttribute("aria-valuenow", "0");
    // Its own steps replace the old ones, and may grow after the first.
    emit({ stage: "file_step", steps: ["Checking file"], step: 0, bytes_done: 0, bytes_total: S, records: 0, errors: 0 });
    await waitFor(() =>
      expect(within(screen.getByRole("list", { name: "Steps" })).getAllByRole("listitem").map((c) => c.textContent)).toEqual([
        "Checking file",
      ]),
    );
    emit(stepEvent(1, 0));
    await waitFor(() => expect(within(screen.getByRole("list", { name: "Steps" })).getAllByRole("listitem")).toHaveLength(3));
  });

  it("estimates the time left from the overall byte rate, after 5 s of data", async () => {
    const user = userEvent.setup();
    await running(user);
    emit(fileEvent(1));
    emit(stepEvent(0, 0));
    now += 4_000;
    emit(stepEvent(0, S / 2));
    await screen.findByText(/0 records/);
    expect(screen.queryByText(/left$/)).not.toBeInTheDocument();
    // 6 s for a ninth of the import (one of three passes of a third): 48 s to go.
    now += 2_000;
    emit(stepEvent(0, S));
    expect(await screen.findByText("~48 s left")).toBeInTheDocument();
    // 60 s for two thirds of the import: 30 s to go; a minute or more is shown in minutes.
    now += 54_000;
    emit(fileEvent(3));
    expect(await screen.findByText("~30 s left")).toBeInTheDocument();
    now += 1_000;
    emit(fileEvent(3, { bytes_total: 30 * S }));
    expect(await screen.findByText(/^~\d+ min left$/)).toBeInTheDocument();
  });
});
