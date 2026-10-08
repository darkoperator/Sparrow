import { save } from "@tauri-apps/plugin-dialog";
import { useState } from "react";
import { exportReport, exportTimelineCsv, exportWorkbook, isCmdError } from "../api";
import { displaySafe } from "../text";

type Notice = { kind: "error" | "info"; text: string };

/**
 * The export menu: the report (optionally reviewed decisions only), the Timeline Explorer CSV and the workbook.
 * The save dialog picks the path; the backend writes it atomically. Exports only read the case, so they stay
 * available on a read-only one.
 */
export default function ExportMenu() {
  const [open, setOpen] = useState(false);
  const [reviewedOnly, setReviewedOnly] = useState(true);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);

  const run = async (
    what: string,
    defaultPath: string,
    ext: string,
    write: (path: string) => Promise<unknown>,
  ) => {
    setNotice(null);
    try {
      const path = await save({ defaultPath, filters: [{ name: what, extensions: [ext] }] });
      if (typeof path !== "string") return; // cancelled
      setBusy(true);
      await write(path);
      setNotice({ kind: "info", text: `${what} written to ${path}` });
      setOpen(false);
    } catch (e) {
      setNotice({ kind: "error", text: isCmdError(e) ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <span className="export-menu">
      <button aria-expanded={open} onClick={() => setOpen(!open)}>
        Export
      </button>
      {open && (
        <span role="group" aria-label="Export">
          <label>
            <input type="checkbox" checked={reviewedOnly} onChange={(e) => setReviewedOnly(e.target.checked)} />
            Reviewed only
          </label>
          <button
            disabled={busy}
            onClick={() => void run("Report", "report.md", "md", (p) => exportReport(p, reviewedOnly))}
          >
            Report
          </button>
          <button disabled={busy} onClick={() => void run("Timeline CSV", "timeline.csv", "csv", exportTimelineCsv)}>
            Timeline CSV
          </button>
          <button disabled={busy} onClick={() => void run("Workbook", "case.xlsx", "xlsx", exportWorkbook)}>
            Workbook
          </button>
        </span>
      )}
      {notice && <span role={notice.kind === "error" ? "alert" : "status"}>{displaySafe(notice.text)}</span>}
    </span>
  );
}
