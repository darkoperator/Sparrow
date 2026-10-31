// The Access section of an account tab: what the attacker reached through the account (case::access). Scope chips
// (the accepted malicious flags seen for it and their windows), one tile per category with direct and time-attributed
// counts, the coverage line (so a zero is never read as "nothing accessed" when the data was not there), and one
// table per category. Everything shown is evidence text and goes through displaySafe.
//
// The preview (off by default, reset when the tab reopens): "Include pending agent flags" and a "What if" value (an IP,
// prefix, session or device, as if flagged malicious). While either is on, a banner at the top of the section (inside
// what a screenshot of it captures) says it is not the reviewed answer, and every row, tile part and scope chip that a
// preview added says PENDING or WHAT-IF; the section's CSV then carries the basis column and a PREVIEW file name.
import { useEffect, useState } from "react";
import {
  ACCESS_TITLES,
  accessReport,
  exportAccessCsv,
  isCmdError,
  type AccessAccount,
  type AccessCategory,
  type AccessItem,
  type AccessTile,
  type Basis,
  type PreviewArgs,
} from "../api";
import { save } from "../dialog";
import { isoSeconds } from "../events/columns";
import { displaySafe } from "../text";
import "./access.css";
import { useDataVersion } from "../shell/nav";

const STATUS_LABELS: Record<string, string> = {
  none: "no coverage data",
  not_licensed: "not licensed",
  not_enabled: "not enabled",
  beyond_retention: "beyond retention",
  available_not_collected: "not collected",
};
const statusLabel = (s: string) => STATUS_LABELS[s] ?? s;

/** Something was reached: counted items, or exposure without a count (folders synced as a whole). */
const exposed = (t: AccessTile) => t.direct + t.by_time > 0 || t.qualifier !== null;

/** The line under a tile's count: its qualifier, "none seen", or why a zero proves nothing. */
function tileNote(t: AccessTile): string {
  if (t.qualifier) return t.qualifier;
  if (t.direct + t.by_time > 0) return "";
  return t.none_seen ? "none seen" : statusLabel(t.coverage.status);
}

function windowsText(ws: { start: string; end: string }[]): string {
  return ws.map((w) => `${isoSeconds(w.start)} to ${isoSeconds(w.end)}`).join(", ");
}

const cell = (v: string | null) => (v === null || v === "" ? "—" : displaySafe(v));

/** Recipients shown before "+N more": an all-staff message can list thousands, which would swamp the table. The core joins them with "; ". */
const RECIPIENTS = 3;

function Recipients({ to }: { to: string | null }) {
  const [open, setOpen] = useState(false);
  const all = to === null ? [] : to.split("; ").filter((r) => r !== "");
  if (all.length <= RECIPIENTS) return <>{cell(to)}</>;
  const more = all.length - RECIPIENTS;
  return (
    <>
      {displaySafe((open ? all : all.slice(0, RECIPIENTS)).join("; "))}{" "}
      <button type="button" className="link access-recipients" onClick={() => setOpen(!open)}>
        {open ? "Show fewer recipients" : `+${more} more recipients`}
      </button>
    </>
  );
}

/** The label of what a preview added; nothing for the reviewed answer. */
const BASIS_LABEL: Record<Basis, string | null> = { accepted: null, pending: "PENDING", adhoc: "WHAT-IF" };

function BasisChip({ basis }: { basis: Basis }) {
  const label = BASIS_LABEL[basis];
  return label ? <span className={`access-basis access-basis-${basis}`}>{label}</span> : null;
}

type WhatIfKind = PreviewArgs["adhoc"][number]["kind"];
const WHAT_IF_KINDS: { kind: WhatIfKind; label: string }[] = [
  { kind: "ip", label: "IP" },
  { kind: "ip_prefix", label: "Prefix" },
  { kind: "session", label: "Session" },
  { kind: "device", label: "Device" },
];

/** Bytes as `512 B`, `91.7 KB`, `4.1 MB` (1024-based). */
export function sizeText(n: number | null): string {
  if (n === null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1_048_576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1_048_576).toFixed(1)} MB`;
}

/** Rows shown per table before "Show more": a tenant-wide case can hold tens of thousands of items. */
export const PAGE = 200;

const MAIL: AccessCategory[] = ["mail_read", "mail_sent", "attachment"];

function ItemTable({ category, items, preview }: { category: AccessCategory; items: AccessItem[]; preview: boolean }) {
  const title = ACCESS_TITLES[category];
  const [shown, setShown] = useState(PAGE);
  const mail = MAIL.includes(category);
  const hidden = items.length - shown;
  return (
    <section className="access-table card">
      <h5>
        {title} ({items.length})
        {/* A table seen on its own, scrolled past the banner, still says it is not the reviewed answer. */}
        {preview && <span className="access-basis"> · PREVIEW, not the reviewed answer</span>}
      </h5>
      <div className="table-scroll">
        <table aria-label={title}>
          <thead>
            <tr>
              <th>Accessed (UTC)</th>
              <th>Action</th>
              <th>Item</th>
              <th>Location</th>
              <th>From</th>
              <th>To</th>
              {mail && <th>Sent (UTC)</th>}
              {mail && <th>Size</th>}
              <th>Tied by</th>
            </tr>
          </thead>
          <tbody>
            {items.slice(0, shown).map((i, n) => (
              // The list never reorders; several items can share a record (Copilot resources), so the index is part of the key.
              <tr key={`${i.source_table}:${i.record_key}:${n}`} className={i.attribution === "time" ? "access-time" : undefined}>
                <td className="mono">{isoSeconds(i.accessed)}</td>
                <td>{displaySafe(i.action)}</td>
                <td>
                  {cell(i.item)}
                  {i.note && <div className="meta">{displaySafe(i.note)}</div>}
                </td>
                <td>{cell(i.location)}</td>
                <td>{cell(i.from)}</td>
                <td>
                  <Recipients to={i.to} />
                </td>
                {mail && <td className="mono">{i.item_time ? isoSeconds(i.item_time) : "—"}</td>}
                {mail && <td>{sizeText(i.size_bytes)}</td>}
                <td>
                  {i.attribution === "time" ? <span className="access-bytime">by time</span> : i.attribution}{" "}
                  <BasisChip basis={i.basis} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {hidden > 0 && (
        <button type="button" className="btn btn-ghost access-more" onClick={() => setShown(shown + PAGE)}>
          {`Show ${Math.min(PAGE, hidden)} more of ${title} (${hidden} hidden)`}
        </button>
      )}
    </section>
  );
}

type Notice = { kind: "error" | "info"; text: string; for: string };

export default function AccessSection({ account }: { account: string }) {
  // Keyed by the account it was read for: another account's answer is "loading" until its own arrives.
  type Loaded = { for: string; acc?: AccessAccount; pending?: number; never?: string[]; error?: string };
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const dataVersion = useDataVersion();
  // The preview: component state, so it is off again whenever the tab is reopened.
  const [includePending, setIncludePending] = useState(false);
  const [whatIfKind, setWhatIfKind] = useState<WhatIfKind>("ip");
  const [whatIfText, setWhatIfText] = useState("");
  const [whatIf, setWhatIf] = useState<{ kind: WhatIfKind; value: string } | null>(null);
  const preview: PreviewArgs | null =
    includePending || whatIf ? { include_pending: includePending, adhoc: whatIf ? [whatIf] : [] } : null;
  const previewKey = JSON.stringify(preview);
  // Keyed by the account AND the preview it was read for: a reviewed answer never shows under a preview banner.
  const loadKey = `${account}\u0000${previewKey}`;
  useEffect(() => {
    let live = true;
    const args: PreviewArgs | null = JSON.parse(previewKey);
    accessReport(account, args).then(
      (r) => live && setLoaded({ for: loadKey, acc: r.accounts[0], pending: r.pending_flags, never: r.never_logged }),
      (e: unknown) => live && setLoaded({ for: loadKey, error: isCmdError(e) ? e.message : String(e) }),
    );
    return () => {
      live = false;
    };
  }, [account, previewKey, loadKey, dataVersion]);
  const current = loaded?.for === loadKey ? loaded : null;
  const error = current?.error ?? null;
  const data = current?.acc ? { acc: current.acc, pending: current.pending ?? 0, never: current.never ?? [] } : null;

  // The notice belongs to the account whose export it reports: switching tabs mid-export must not show it on another.
  const exportCsv = async () => {
    const forAccount = account;
    setNotice(null);
    try {
      const day = new Date().toISOString().slice(0, 10);
      const safeName = forAccount.replace(/[^A-Za-z0-9@._-]/g, "_");
      const defaultPath = preview ? `access-${safeName}-PREVIEW-${day}.csv` : `access-${day}.csv`;
      const path = await save({ defaultPath, filters: [{ name: "Access CSV", extensions: ["csv"] }] });
      if (typeof path !== "string") return;
      await exportAccessCsv(path, forAccount, preview);
      setNotice({ kind: "info", text: `Access CSV written to ${path}`, for: forAccount });
    } catch (e) {
      setNotice({ kind: "error", text: isCmdError(e) ? e.message : String(e), for: forAccount });
    }
  };
  const shownNotice = notice?.for === account ? notice : null;

  const pendingLine = (n: number) =>
    n > 0 && (
      <p className="access-pending">
        {includePending
          ? `${n} malicious flags are waiting for review; counted here as PENDING.`
          : `${n} malicious flags are waiting for review; they count once accepted.`}
      </p>
    );

  const bannerParts = [
    ...(includePending ? ["pending agent flags"] : []),
    ...(whatIf ? [`what-if ${whatIf.kind} ${whatIf.value}`] : []),
  ];
  const banner = preview && (
    <p role="note" className="access-preview-banner">
      {displaySafe(`PREVIEW: includes ${bannerParts.join(" and ")}; not the reviewed answer`)}
    </p>
  );
  const applyWhatIf = () => {
    const v = whatIfText.trim();
    setWhatIf(v === "" ? null : { kind: whatIfKind, value: v });
  };
  const controls = (
    <div className="access-preview-controls">
      <label>
        <input type="checkbox" checked={includePending} onChange={(e) => setIncludePending(e.target.checked)} />
        Include pending agent flags
      </label>
      <select aria-label="What-if kind" value={whatIfKind} onChange={(e) => setWhatIfKind(e.target.value as WhatIfKind)}>
        {WHAT_IF_KINDS.map((k) => (
          <option key={k.kind} value={k.kind}>
            {k.label}
          </option>
        ))}
      </select>
      <input
        aria-label="What if"
        placeholder="What if… (an IP, prefix, session or device)"
        value={whatIfText}
        onChange={(e) => setWhatIfText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") applyWhatIf();
        }}
      />
      <button type="button" className="btn btn-ghost" onClick={applyWhatIf}>
        Try
      </button>
      {whatIf && (
        <button
          type="button"
          className="btn btn-ghost"
          onClick={() => {
            setWhatIf(null);
            setWhatIfText("");
          }}
        >
          Clear what-if
        </button>
      )}
    </div>
  );

  if (error)
    return (
      <section className="access card" aria-label="Access">
        {banner}
        {controls}
        <p role="alert">{displaySafe(error)}</p>
      </section>
    );
  if (!data)
    return (
      <section className="access card" aria-label="Access">
        {banner}
        {controls}
        <p className="entity-empty">Loading…</p>
      </section>
    );
  const { acc, pending, never } = data;
  const noScope = acc.scope.length === 0 && acc.items.length === 0;
  const byCategory = (c: AccessCategory) => acc.items.filter((i) => i.category === c);
  return (
    <section className="access card" aria-label="Access">
      {banner}
      <header className="access-head">
        <h4>Access</h4>
        <ul className="access-scope" aria-label="Scope">
          {acc.scope.map((s) => (
            <li key={`${s.kind}:${s.value}`} className="access-chip" title={windowsText(s.windows)}>
              {`${BASIS_LABEL[s.basis] ? `${BASIS_LABEL[s.basis]} ` : ""}${s.kind} ${displaySafe(s.value)}`}
            </li>
          ))}
        </ul>
        {!noScope && (
          <button type="button" className="btn btn-ghost" onClick={() => void exportCsv()}>
            Export CSV
          </button>
        )}
      </header>
      {controls}
      {shownNotice && (
        <p role={shownNotice.kind === "error" ? "alert" : "status"} className="access-notice">
          {displaySafe(shownNotice.text)}
        </p>
      )}
      {noScope && <p className="entity-empty">No malicious sessions or IPs are flagged for this account.</p>}
      {pendingLine(pending)}
      <ul className="access-tiles" aria-label="What the attacker reached">
        {acc.tiles.map((t) => (
          <li key={t.category} aria-label={ACCESS_TITLES[t.category]} className={`access-tile card${exposed(t) ? " access-tile-hit" : ""}`}>
            <span className="access-tile-title">{ACCESS_TITLES[t.category]}</span>
            <span className="access-tile-count">
              {t.direct}
              {t.by_time > 0 && <span className="access-tile-time">{` · ${t.by_time} by time`}</span>}
              {t.pending > 0 && <span className="access-basis access-basis-pending">{` · ${t.pending} pending`}</span>}
              {t.adhoc > 0 && <span className="access-basis access-basis-adhoc">{` · ${t.adhoc} what-if`}</span>}
            </span>
            <span className="access-tile-note">{displaySafe(tileNote(t))}</span>
          </li>
        ))}
      </ul>
      <section className="access-coverage" aria-label="Coverage">
        <p>
          <strong>Coverage:</strong>{" "}
          {acc.tiles.map((t, i) => (
            <span key={t.category} title={displaySafe(t.coverage.reason)}>
              {i > 0 ? " · " : ""}
              {`${ACCESS_TITLES[t.category]} ${t.coverage.status === "collected" ? "✓" : statusLabel(t.coverage.status)}`}
            </span>
          ))}
        </p>
        <ul>
          {/* The account's own gaps, then what Microsoft never logs (listed once by the report). */}
          {[...acc.gaps, ...never.filter((g) => !acc.gaps.includes(g))].map((g) => (
            <li key={g}>{displaySafe(g)}</li>
          ))}
        </ul>
      </section>
      {acc.tiles
        .filter((t) => byCategory(t.category).length > 0)
        .map((t) => (
          <ItemTable key={t.category} category={t.category} items={byCategory(t.category)} preview={preview !== null} />
        ))}
    </section>
  );
}
