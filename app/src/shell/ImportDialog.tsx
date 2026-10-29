// Import from the window: pick a folder, see what discovery found (nothing is written yet), choose the options, run the
// import with progress and a Cancel, then read the result card. "new" makes a new case file; "open" adds to the open case.
import { useEffect, useRef, useState, type KeyboardEvent as ReactKeyEvent } from "react";
import { open, save } from "../dialog";
import {
  ingestCancel,
  ingestDiscover,
  ingestRun,
  isCmdError,
  onIngestClosing,
  onIngestProgress,
  type DiscoveryPreview,
  type IngestProgress,
  type IngestResult,
  type PreviewFile,
} from "../api";
import { displaySafe } from "../text";
import Icon from "../ui/Icon";
import "./import.css";

export type ImportMode = "new" | "open";

interface Props {
  mode: ImportMode;
  /**
   * The dialog closed. `changed` is true when the case may have new data (an import ran, finished or not): the shell then
   * reloads its screens.
   */
  onClose: (changed: boolean) => void;
  /** "new" mode: open the case that was made. */
  onOpenCase?: (path: string) => void;
}

const CASE_FILTER = [{ name: "Sparrow case", extensions: ["duckdb"] }];
const CULTURES: ReadonlyArray<{ value: string; label: string }> = [
  { value: "", label: "Work it out from the data" },
  { value: "en-US", label: "Month first (en-US, 03/04 is 4 March)" },
  { value: "en-GB", label: "Day first (en-GB, 03/04 is 3 April)" },
];
const MAX_ROWS = 100;
/** A fresh id naming one run, so a Cancel reaches that run and no other. */
const newRunId = () =>
  typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `run-${Date.now()}-${Math.random()}`;
const FOCUSABLE = "button:not([disabled]), select:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex='-1'])";
const message = (e: unknown) => (isCmdError(e) ? e.message : String(e));
const n = (v: number) => v.toLocaleString("en-US");

function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = bytes;
  let u = -1;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u += 1;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[u]}`;
}

function stageText(p: IngestProgress | null): string {
  switch (p?.stage) {
    case undefined:
    case "discover":
      return "Looking through the folder…";
    case "collection":
      return `Collection ${p.index} of ${p.count}`;
    case "file":
      return `Loading file ${p.index} of ${p.files}`;
    case "profile":
      return "Profiling the case…";
    case "detect":
      return "Running detection…";
  }
}

export default function ImportDialog({ mode, onClose, onOpenCase }: Props) {
  const [preview, setPreview] = useState<DiscoveryPreview | null>(null);
  const [target, setTarget] = useState<string | null>(null);
  const [culture, setCulture] = useState("");
  const [skipDetect, setSkipDetect] = useState(false);
  const [busy, setBusy] = useState<"discover" | "run" | null>(null);
  const [cancelling, setCancelling] = useState(false);
  // The window is closing: the backend finishes the current file and the profile, then closes it.
  const [closing, setClosing] = useState(false);
  const [progress, setProgress] = useState<IngestProgress | null>(null);
  const [result, setResult] = useState<IngestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Set once an import was started: the case may have changed even when it ended in an error.
  const changed = useRef(false);
  const runId = useRef("");
  const dialog = useRef<HTMLDivElement>(null);

  const running = busy === "run";
  const close = () => onClose(changed.current);

  const chooseFolder = async () => {
    setError(null);
    const chosen = await open({ multiple: false, directory: true });
    if (typeof chosen !== "string") return; // cancelled
    setBusy("discover");
    setPreview(null);
    try {
      setPreview(await ingestDiscover(chosen));
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(null);
    }
  };

  const chooseTarget = async () => {
    const chosen = await save({ defaultPath: "case.duckdb", filters: CASE_FILTER });
    if (typeof chosen === "string") setTarget(chosen);
  };

  const start = async () => {
    if (!preview) return;
    setError(null);
    setProgress(null);
    setCancelling(false);
    setClosing(false);
    setBusy("run");
    changed.current = true;
    // The id exists before anything is awaited, so a Cancel pressed at once still names this run.
    const id = newRunId();
    runId.current = id;
    const offs: Array<() => void> = [];
    try {
      offs.push(await onIngestProgress(setProgress));
      offs.push(
        await onIngestClosing(() => {
          setCancelling(true);
          setClosing(true);
        }),
      );
      const t = mode === "open" ? "open" : { new_case: target ?? "" };
      setResult(await ingestRun(preview.path, t, culture === "" ? null : culture, !skipDetect, id));
    } catch (e) {
      setError(message(e));
    } finally {
      offs.forEach((off) => off());
      setBusy(null);
    }
  };

  const cancel = () => {
    setCancelling(true);
    ingestCancel(runId.current).catch((e: unknown) => setError(message(e)));
  };

  // Keyboard focus stays in the dialog: Tab and Shift+Tab wrap at its ends.
  const trap = (e: ReactKeyEvent<HTMLDivElement>) => {
    if (e.key !== "Tab" || !dialog.current) return;
    const items = [...dialog.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
    if (items.length === 0) {
      e.preventDefault();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const at = document.activeElement;
    if (e.shiftKey && (at === first || !dialog.current.contains(at))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (at === last || !dialog.current.contains(at))) {
      e.preventDefault();
      first.focus();
    }
  };

  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !running) onClose(changed.current);
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [running, onClose]);

  useEffect(() => {
    dialog.current?.querySelector<HTMLElement>(FOCUSABLE)?.focus();
  }, []);

  const title = mode === "new" ? "New case from a folder" : "Import data into this case";
  const nothing = preview !== null && preview.recognised === 0;
  const needsTarget = mode === "new" && target === null;

  return (
    <div className="import-scrim">
      <div ref={dialog} role="dialog" aria-modal="true" aria-label={title} className="import-dialog card" onKeyDown={trap}>
        <header className="import-head">
          <h3>{title}</h3>
          {!running && (
            <button className="btn btn-ghost import-x" aria-label="Close" onClick={close}>
              <Icon name="x" size={14} />
            </button>
          )}
        </header>

        {error !== null && <p role="alert">{displaySafe(error)}</p>}

        {result ? (
          <Result result={result} mode={mode} onClose={close} onOpenCase={onOpenCase} />
        ) : running ? (
          <Running progress={progress} cancelling={cancelling} closing={closing} onCancel={cancel} />
        ) : (
          <>
            <p className="import-hint">
              {mode === "new"
                ? "Pick the folder a collector wrote. Sparrow shows what it finds before anything is written."
                : "Pick the folder a collector wrote. The files are added to the open case; a file already loaded is skipped."}
            </p>
            <div className="import-pick">
              <button className="btn btn-primary" disabled={busy !== null} onClick={() => void chooseFolder()}>
                <Icon name="download" size={13} />
                {preview ? "Choose another folder…" : "Choose a folder…"}
              </button>
              {busy === "discover" && <span className="meta" role="status">Looking through the folder…</span>}
            </div>

            {preview && <Preview preview={preview} />}

            {preview && !nothing && (
              <div className="import-options">
                {mode === "new" && (
                  <div className="import-field">
                    <span className="label">Save the case as</span>
                    <span className="import-target">
                      <button className="btn" onClick={() => void chooseTarget()}>
                        {target === null ? "Choose where to save…" : "Change…"}
                      </button>
                      {target !== null && (
                        <span className="mono import-path" title={displaySafe(target)}>
                          {displaySafe(target)}
                        </span>
                      )}
                    </span>
                  </div>
                )}
                <label className="import-field">
                  <span className="label">Dates written as day/month</span>
                  <select value={culture} onChange={(e) => setCulture(e.target.value)}>
                    {CULTURES.map((c) => (
                      <option key={c.value} value={c.value}>
                        {c.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="import-check">
                  <input type="checkbox" checked={skipDetect} onChange={(e) => setSkipDetect(e.target.checked)} />
                  Skip detection (the profile still runs)
                </label>
              </div>
            )}

            <footer className="import-actions">
              <button className="btn btn-ghost" onClick={close}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                disabled={preview === null || nothing || needsTarget || busy !== null}
                title={needsTarget && !nothing ? "Choose where to save the case first" : undefined}
                onClick={() => void start()}
              >
                {mode === "new" ? "Create the case and import" : "Import"}
              </button>
            </footer>
          </>
        )}
      </div>
    </div>
  );
}

function Preview({ preview }: { preview: DiscoveryPreview }) {
  if (preview.collections.length === 0) {
    return (
      <p role="status" className="import-empty">
        Nothing to import: no Hawk, Microsoft-Extractor-Suite or portal export output was found in{" "}
        <span className="mono">{displaySafe(preview.path)}</span>.
      </p>
    );
  }
  const parts = [
    `${preview.collections.length === 1 ? "1 collection" : `${preview.collections.length} collections`}`,
    `${n(preview.recognised)} recognised`,
    `${n(preview.unrecognised)} not recognised`,
    ...(preview.too_large > 0 ? [`${n(preview.too_large)} over the size limit`] : []),
    ...(preview.unreadable > 0 ? [`${n(preview.unreadable)} unreadable`] : []),
  ];
  return (
    <section aria-label="Discovery" className="import-preview">
      <p className="import-summary" role="status">
        {parts.join(" · ")}
      </p>
      {preview.recognised === 0 && (
        <p className="import-empty">Sparrow recognises none of the files here, so there is nothing to import.</p>
      )}
      {preview.too_large > 0 && (
        <p className="import-note">
          Files over {size(preview.max_file_bytes)} are not loaded; they are listed in the result as errors.
        </p>
      )}
      {preview.collections.map((c) => (
        <div key={c.root} className="import-collection">
          <div className="import-collection-head">
            <span className="pill">{c.tool.replace("_", " ")}</span>
            <span className="mono import-path" title={displaySafe(c.root)}>
              {displaySafe(c.root)}
            </span>
            {c.tenant_hint && <span className="meta">{displaySafe(c.tenant_hint)}</span>}
          </div>
          <ul className="plain import-files">
            {c.files.slice(0, MAX_ROWS).map((f) => (
              <FileRow key={f.rel_path} f={f} />
            ))}
          </ul>
          {c.files.length > MAX_ROWS && <p className="meta">…and {n(c.files.length - MAX_ROWS)} more files</p>}
        </div>
      ))}
    </section>
  );
}

function FileRow({ f }: { f: PreviewFile }) {
  return (
    <li className="import-file">
      <span className="mono import-file-name" title={displaySafe(f.rel_path)}>
        {displaySafe(f.rel_path)}
      </span>
      <span className="mono import-file-source" title={f.artifact_id ?? undefined}>
        {f.artifact_id ? displaySafe(f.artifact_id) : ""}
      </span>
      <span className="mono import-file-size">{size(f.size)}</span>
      {f.status === "recognised" && <span className="pill pill-ok">recognised</span>}
      {f.status === "unrecognised" && <span className="pill">not recognised</span>}
      {f.status === "too_large" && <span className="pill pill-mal">over the size limit</span>}
      {f.status === "unreadable" && (
        <span className="pill pill-mal" title={f.error ? displaySafe(f.error) : undefined}>
          unreadable
        </span>
      )}
    </li>
  );
}

function Running({
  progress,
  cancelling,
  closing,
  onCancel,
}: {
  progress: IngestProgress | null;
  cancelling: boolean;
  closing: boolean;
  onCancel: () => void;
}) {
  const file = progress?.stage === "file" ? progress : null;
  const done = file ? file.index - 1 : null;
  return (
    <div className="import-running">
      <p className="import-stage" role="status">
        {stageText(progress)}
      </p>
      {file && (
        <p className="mono import-current" title={displaySafe(file.rel_path)}>
          {displaySafe(file.rel_path)}
        </p>
      )}
      <div
        className="import-bar"
        role="progressbar"
        aria-label="Import progress"
        aria-valuemin={0}
        aria-valuemax={file ? file.files : 1}
        aria-valuenow={done ?? undefined}
      >
        <span style={{ width: file ? `${Math.round(((done ?? 0) / Math.max(file.files, 1)) * 100)}%` : "0%" }} />
      </div>
      <p className="import-hint">
        {closing
          ? "Finishing the current file…"
          : cancelling
          ? "Stopping after the file being loaded; the files already loaded stay."
          : "The case is busy while this runs. Cancel stops after the file being loaded."}
      </p>
      <footer className="import-actions">
        <button className="btn" disabled={cancelling} onClick={onCancel}>
          {cancelling ? "Stopping…" : "Cancel"}
        </button>
      </footer>
    </div>
  );
}

function Result({
  result,
  mode,
  onClose,
  onOpenCase,
}: {
  result: IngestResult;
  mode: ImportMode;
  onClose: () => void;
  onOpenCase?: (path: string) => void;
}) {
  const totalRows = result.rows_by_source.reduce((sum, s) => sum + s.rows, 0);
  return (
    <section aria-label="Import result" className="import-result">
      <p
        className={`import-verdict ${result.cancelled || result.error !== null ? "import-verdict-warn" : "import-verdict-ok"}`}
        role="status"
      >
        {result.error !== null
          ? `Stopped by an error: ${n(result.files_loaded)} of ${n(result.files_total)} files loaded, ${n(result.not_loaded.length)} not loaded`
          : result.cancelled
          ? `Cancelled: ${n(result.files_loaded)} of ${n(result.files_total)} files loaded, ${n(result.not_loaded.length)} not loaded`
          : `Imported ${n(result.files_loaded)} of ${n(result.files_total)} files`}
        {" · "}
        {n(totalRows)} rows
      </p>

      {result.error !== null && (
        <p role="alert">
          The import stopped on an error: {displaySafe(result.error)}. The files listed as loaded are in the case and
          were profiled; the others were not loaded.
        </p>
      )}

      {result.rows_by_source.length > 0 && (
        <table className="import-sources">
          <caption className="label">Rows per source</caption>
          <tbody>
            {result.rows_by_source.map((s) => (
              <tr key={s.source}>
                <td className="mono">{displaySafe(s.source)}</td>
                <td className="import-num">{s.files === 1 ? "1 file" : `${n(s.files)} files`}</td>
                <td className="import-num mono">{n(s.rows)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {result.file_notes.length > 0 && (
        <div>
          <h4 className="label">Errors and warnings</h4>
          <ul className="plain import-notes">
            {result.file_notes.map((f) => (
              <li key={`${f.root}/${f.rel_path}`}>
                <span className="mono" title={displaySafe(f.rel_path)}>
                  {displaySafe(f.rel_path)}
                </span>{" "}
                <span className="pill">{f.status.replace("_", " ")}</span>
                <ul>
                  {f.notes.map((note) => (
                    <li key={note}>{displaySafe(note)}</li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.not_loaded.length > 0 && (
        <div>
          <h4 className="label">Not loaded</h4>
          <ul className="plain import-notes">
            {result.not_loaded.slice(0, MAX_ROWS).map((f) => (
              <li key={`${f.root}/${f.rel_path}`} className="mono" title={displaySafe(f.rel_path)}>
                {displaySafe(f.rel_path)}
              </li>
            ))}
          </ul>
          {result.not_loaded.length > MAX_ROWS && <p className="meta">…and {n(result.not_loaded.length - MAX_ROWS)} more</p>}
        </div>
      )}

      {result.profile_error !== null && (
        <p role="alert">
          The evidence loaded but the profile step failed: {displaySafe(result.profile_error)}. Run{" "}
          <code>sparrow profile --case …</code> to finish it.
        </p>
      )}
      {result.detect_error !== null && (
        <p role="alert">Detection failed: {displaySafe(result.detect_error)}. Run <code>sparrow profile --case …</code> again.</p>
      )}
      <p className="import-detect">
        {result.detect
          ? `Detection: ${n(result.detect.findings_new)} new findings, ${n(result.detect.findings_updated)} updated`
          : result.detect_error === null
            ? result.error !== null
              ? "Detection did not run (the import stopped on an error)."
              : result.cancelled
              ? "Detection did not run (the import was cancelled)."
              : "Detection was skipped."
            : null}
      </p>
      {[...result.profile_warnings, ...(result.detect?.warnings ?? [])].map((w) => (
        <p key={w} className="meta">
          Warning: {displaySafe(w)}
        </p>
      ))}

      <footer className="import-actions">
        {mode === "new" ? (
          <>
            <button className="btn btn-ghost" onClick={onClose}>
              Close
            </button>
            <button className="btn btn-primary" onClick={() => onOpenCase?.(result.case_path)}>
              Open the new case
            </button>
          </>
        ) : (
          <button className="btn btn-primary" onClick={onClose}>
            Done
          </button>
        )}
      </footer>
    </section>
  );
}
