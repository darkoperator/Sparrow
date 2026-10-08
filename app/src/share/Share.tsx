import { open, save } from "@tauri-apps/plugin-dialog";
import { useState } from "react";
import {
  isCmdError,
  shareExport,
  shareImport,
  sharePreview,
  type ImportSummary,
  type ShareExported,
  type SharePreview,
} from "../api";
import { displaySafe } from "../text";

interface Props {
  /** Importing stores proposals: it needs a writable case and an analyst name. */
  canImport: boolean;
  onShowQueue: () => void;
}

const BUNDLE_FILTER = [{ name: "Sparrow share bundle", extensions: ["json"] }];
const message = (e: unknown) => (isCmdError(e) ? e.message : String(e));

/**
 * Share: export my work as a bundle file (its SHA-256 shown, to send separately), and import another analyst's
 * bundle in two steps: preview (nothing stored), then confirm, which imports the same file only if its SHA-256 is
 * still the one previewed (the backend checks).
 */
export default function Share({ canImport, onShowQueue }: Props) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exported, setExported] = useState<(ShareExported & { path: string }) | null>(null);
  const [preview, setPreview] = useState<(SharePreview & { path: string }) | null>(null);
  const [imported, setImported] = useState<ImportSummary | null>(null);

  const guarded = async (f: () => Promise<void>) => {
    setError(null);
    setBusy(true);
    try {
      await f();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  };

  const doExport = () =>
    guarded(async () => {
      const path = await save({ defaultPath: "work.sparrow-share.json", filters: BUNDLE_FILTER });
      if (typeof path !== "string") return; // cancelled
      setExported(null);
      setExported({ ...(await shareExport(path)), path });
    });

  const doPreview = () =>
    guarded(async () => {
      const path = await open({ multiple: false, directory: false, filters: BUNDLE_FILTER });
      if (typeof path !== "string") return; // cancelled
      setPreview(null);
      setImported(null);
      setPreview({ ...(await sharePreview(path)), path });
    });

  const doImport = (p: SharePreview & { path: string }) =>
    guarded(async () => {
      // Whatever the outcome, this preview is spent: a refusal (the file changed) needs a fresh preview.
      setPreview(null);
      setImported(await shareImport(p.path, p.sha256));
    });

  const copy = (sha: string) => {
    navigator.clipboard.writeText(sha).catch((e: unknown) => setError(`could not copy: ${message(e)}`));
  };

  return (
    <div className="share">
      <section aria-labelledby="share-export">
        <h2 id="share-export">Export my work</h2>
        <p className="meta">
          Your accepted and analyst decisions, as one file another analyst with the same evidence can import.
        </p>
        <button disabled={busy} onClick={() => void doExport()}>
          Export my work…
        </button>
        {exported && (
          <div role="region" aria-label="Exported bundle" className="share-card">
            <p>
              {exported.items === 1 ? "1 item" : `${exported.items} items`} written to{" "}
              <code>{displaySafe(exported.path)}</code>
            </p>
            <p>
              SHA-256: <code className="sha">{exported.sha256}</code>{" "}
              <button onClick={() => copy(exported.sha256)}>Copy SHA-256</button>
            </p>
            <p>Send the SHA separately so the other analyst can check the file.</p>
          </div>
        )}
      </section>

      <section aria-labelledby="share-import">
        <h2 id="share-import">Import a bundle</h2>
        <button disabled={busy} onClick={() => void doPreview()}>
          Import a bundle…
        </button>
        {preview && (
          <PreviewCard
            preview={preview}
            canImport={canImport}
            busy={busy}
            onConfirm={() => void doImport(preview)}
            onCancel={() => setPreview(null)}
          />
        )}
        {imported && (
          <p role="status">
            {added(imported)} proposals added to the review queue
            {imported.agrees > 0 && ` (${imported.agrees} already agree)`}.{" "}
            <button className="link" onClick={onShowQueue}>
              Open the review queue
            </button>
          </p>
        )}
      </section>

      {error !== null && <p role="alert">{displaySafe(error)}</p>}
    </div>
  );
}

// Items that enter the queue as open proposals; agreeing items are stored as `agrees` and need no action.
const added = (s: ImportSummary) => s.new + s.conflicts + s.missing;

function PreviewCard({
  preview,
  canImport,
  busy,
  onConfirm,
  onCancel,
}: {
  preview: SharePreview & { path: string };
  canImport: boolean;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const s = preview.summary;
  const counts: ReadonlyArray<[string, number]> = [
    ["New", s.new],
    ["Agrees", s.agrees],
    ["Conflicts", s.conflicts],
    ["Missing here", s.missing],
  ];
  const rulesDiffer = s.rules_only_in_bundle.length > 0 || s.rules_only_here.length > 0;
  return (
    <div role="region" aria-label="Bundle preview" className="share-card">
      <p>
        From <strong>{displaySafe(s.analyst)}</strong> — <code>{displaySafe(preview.path)}</code>
      </p>
      <p>
        SHA-256: <code className="sha">{preview.sha256}</code>
      </p>
      <p className="meta">Compare it with the SHA the other analyst sent you.</p>
      <dl className="share-counts">
        {counts.map(([label, n], i) => (
          <div key={label}>
            <dt id={`share-count-${i}`} aria-label={label}>
              {label}
            </dt>
            <dd aria-labelledby={`share-count-${i}`}>{n}</dd>
          </div>
        ))}
      </dl>
      {rulesDiffer && (
        <div className="warnings">
          <p>The rule set differs from this case's (a warning; the import still works).</p>
          {s.rules_only_in_bundle.length > 0 && (
            <p>
              Only in the bundle:{" "}
              {s.rules_only_in_bundle.map((r, i) => (
                <span key={r}>
                  {i > 0 && ", "}
                  <code>{displaySafe(r)}</code>
                </span>
              ))}
            </p>
          )}
          {s.rules_only_here.length > 0 && (
            <p>
              Only in this case:{" "}
              {s.rules_only_here.map((r, i) => (
                <span key={r}>
                  {i > 0 && ", "}
                  <code>{displaySafe(r)}</code>
                </span>
              ))}
            </p>
          )}
        </div>
      )}
      {s.already_imported ? (
        <p>This bundle was already imported; importing it again changes nothing.</p>
      ) : (
        <>
          {!canImport && <p className="meta">Importing needs a writable case and an analyst name.</p>}
          <button disabled={busy || !canImport} onClick={onConfirm}>
            Confirm import
          </button>
        </>
      )}
      <button disabled={busy} onClick={onCancel}>
        {s.already_imported ? "Close" : "Cancel"}
      </button>
    </div>
  );
}
