import { save } from "../dialog";
import { useState } from "react";
import { exportAccessCsv, exportAccessSummary, exportReport, exportTimelineCsv, exportWorkbook, isCmdError } from "../api";
import { displaySafe } from "../text";
import Icon from "../ui/Icon";

/** Today as `YYYY-MM-DD` (UTC), for dated default file names. */
const today = () => new Date().toISOString().slice(0, 10);

type Notice = { kind: "error" | "info"; text: string };

/**
 * The export menu: the report (optionally reviewed decisions only), the Timeline Explorer CSV, the workbook, and the
 * access report of every account (the CSV for legal, the Markdown summary for the final report).
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
      <button className="btn btn-ghost" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Icon name="upload" size={13} />
        Export
      </button>
      {open && (
        <span role="group" aria-label="Export" className="export-pop">
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
          <button disabled={busy} onClick={() => void run("Access CSV", `access-${today()}.csv`, "csv", (p) => exportAccessCsv(p, null))}>
            Access CSV (all accounts)
          </button>
          <button disabled={busy} onClick={() => void run("Access summary", `access-summary-${today()}.md`, "md", exportAccessSummary)}>
            Access summary (Markdown)
          </button>
        </span>
      )}
      {notice && (
        <span role={notice.kind === "error" ? "alert" : "status"} className="export-notice">
          {displaySafe(notice.text)}
        </span>
      )}
    </span>
  );
}
