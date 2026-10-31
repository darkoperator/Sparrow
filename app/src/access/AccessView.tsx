// An Access tab: what the attacker reached (case::access), for one account, for a device or IP as a what-if (that value
// alone, as if it were the attacker, ignoring the case's other flags), or for the whole case. A tab that can span
// accounts shows one merged list (merge.ts) with an Account column and an Account filter that narrows tiles, tables and
// coverage together without asking the backend again. Scope chips (the malicious flags seen and their windows), one tile
// per category with direct and time-attributed counts, the coverage line (so a zero is never read as "nothing
// accessed" when the data was not there), and one table per category. Everything shown is evidence text and goes
// through displaySafe.
//
// The preview of the account and case tabs (off by default, reset when the tab reopens): "Include pending agent flags"
// and a "What if" value (an IP, prefix, session or device, as if flagged malicious). While either is on, or on a
// what-if tab, a banner at the top (inside what a screenshot of it captures) says it is not the reviewed answer, and
// every row, tile part and scope chip that a preview added says PENDING or WHAT-IF; the CSV then carries the basis
// column and says PREVIEW or WHATIF in its file name. The CSV is the whole tab, never the filter.
import { useEffect, useMemo, useState } from "react";
import {
  ACCESS_TITLES,
  accessReport,
  exportAccessCsv,
  isCmdError,
  type AccessAccount,
  type AccessCategory,
  type AccessItem,
  type AccessReport,
  type AccessTile,
  type Basis,
  type PreviewArgs,
} from "../api";
import { save } from "../dialog";
import { isoSeconds } from "../events/columns";
import { displaySafe } from "../text";
import "./access.css";
import { mergeAccess, type MergedTile } from "./merge";
import { useDataVersion, useWriteTick } from "../shell/nav";

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
function tileNote(t: MergedTile): string {
  if (t.qualifier) return t.qualifier;
  if (t.direct + t.by_time > 0) return "";
  if (t.none_seen) return "none seen";
  return partly(t) ?? statusLabel(t.coverage.status);
}

/** On a merged tile whose accounts disagree: "not collected for 2 of 5 accounts". */
const partly = (t: MergedTile) =>
  t.of > 1 && t.notCollectedFor > 0 && t.notCollectedFor < t.of ? `not collected for ${t.notCollectedFor} of ${t.of} accounts` : null;

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

function ItemTable({ category, items, preview, showAccount }: { category: AccessCategory; items: AccessItem[]; preview: boolean; showAccount: boolean }) {
  const title = ACCESS_TITLES[category];
  const [shown, setShown] = useState(PAGE);
  // Another list (the Account filter changed) starts again at the first page.
  const [shownFor, setShownFor] = useState(items);
  if (shownFor !== items) {
    setShownFor(items);
    setShown(PAGE);
  }
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
              {showAccount && <th>Account</th>}
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
                {showAccount && <td>{displaySafe(i.account)}</td>}
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

/** What an Access tab is for: one account, a device or IP what-if, or the whole case. */
export type AccessScope = { kind: "account"; value: string } | { kind: "ip" | "device"; value: string } | { kind: "case" };

const KIND_NAME = { ip: "IP", device: "device" } as const;

/**
 * The account tab's one line, from the reviewed report: the count per category, or its qualifier when exposure has no
 * count (a folder synced as a whole), so such an account never reads as "Nothing attributed yet".
 */
export function accessSummary(acc: AccessAccount): string {
  const hits = acc.tiles
    .filter(exposed)
    .map((t) => (t.direct + t.by_time > 0 ? `${t.direct + t.by_time} ${ACCESS_TITLES[t.category]}` : `${ACCESS_TITLES[t.category]}: ${t.qualifier}`));
  return hits.length > 0 ? hits.join(" · ") : "Nothing attributed yet";
}

/** The CSV's name: what the tab is, PREVIEW or WHATIF when it is not the reviewed answer, and the UTC day. */
function csvName(scope: AccessScope, preview: boolean): string {
  const day = new Date().toISOString().slice(0, 10);
  const safe = (v: string) => v.replace(/[^A-Za-z0-9@._-]/g, "_");
  if (scope.kind === "case") return preview ? `access-case-PREVIEW-${day}.csv` : `access-case-${day}.csv`;
  if (scope.kind === "account") return `access-${safe(scope.value)}-${preview ? "PREVIEW-" : ""}${day}.csv`;
  return `access-${scope.kind}-${safe(scope.value)}-WHATIF-${day}.csv`;
}

export default function AccessView({ scope }: { scope: AccessScope }) {
  const whatIfTab = scope.kind === "ip" || scope.kind === "device";
  const account = scope.kind === "account" ? scope.value : null;
  const scopeKey = JSON.stringify(scope);
  type Loaded = { for: string; report?: AccessReport; error?: string };
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [only, setOnly] = useState<string | null>(null);
  // An agent's write (the data version) or the analyst's own (the write tick) reads the report again.
  const dataVersion = `${useDataVersion()}.${useWriteTick()}`;
  // The preview: component state, so it is off again whenever the tab is reopened.
  const [includePending, setIncludePending] = useState(false);
  const [whatIfKind, setWhatIfKind] = useState<WhatIfKind>("ip");
  const [whatIfText, setWhatIfText] = useState("");
  const [whatIf, setWhatIf] = useState<{ kind: WhatIfKind; value: string } | null>(null);
  // A what-if tab asks for its own value alone; the others preview only when asked.
  const preview: PreviewArgs | null = whatIfTab
    ? { include_pending: false, adhoc: [{ kind: scope.kind, value: scope.value }], without_accepted: true }
    : includePending || whatIf
      ? { include_pending: includePending, adhoc: whatIf ? [whatIf] : [] }
      : null;
  const previewKey = JSON.stringify(preview);
  // Keyed by the scope, the preview AND the data version it was read for: a reviewed answer never shows under a preview
  // banner, and after a data change the old answer (and its Export) is gone until the new one arrives.
  const loadKey = `${scopeKey}\u0000${previewKey}\u0000${dataVersion}`;
  useEffect(() => {
    let live = true;
    const args: PreviewArgs | null = JSON.parse(previewKey);
    const tab = JSON.parse(scopeKey) as AccessScope;
    accessReport(tab.kind === "account" ? tab.value : null, args).then(
      (r) => live && setLoaded({ for: loadKey, report: r }),
      (e: unknown) => live && setLoaded({ for: loadKey, error: isCmdError(e) ? e.message : String(e) }),
    );
    return () => {
      live = false;
    };
  }, [scopeKey, previewKey, loadKey, dataVersion]);
  const current = loaded?.for === loadKey ? loaded : null;
  const error = current?.error ?? null;
  const report = current?.report ?? null;
  const filter = report && only !== null && report.accounts.some((a) => a.account === only) ? only : null;
  // An account that is no longer in the answer drops the filter for good: it does not come back with the account.
  if (report && only !== null && filter === null) setOnly(null);
  const merged = useMemo(() => (report ? mergeAccess(report, filter) : null), [report, filter]);
  // One list per category, kept while the answer and the filter are the same: a table's paging survives other renders.
  const byCategory = useMemo(() => {
    const by = new Map<AccessCategory, AccessItem[]>();
    for (const i of merged?.items ?? []) {
      const list = by.get(i.category);
      if (list) list.push(i);
      else by.set(i.category, [i]);
    }
    return by;
  }, [merged]);

  // The notice belongs to the tab whose export it reports: switching tabs mid-export must not show it on another.
  const exportCsv = async () => {
    const forTab = scopeKey;
    setNotice(null);
    try {
      const path = await save({ defaultPath: csvName(scope, preview !== null), filters: [{ name: "Access CSV", extensions: ["csv"] }] });
      if (typeof path !== "string") return;
      await exportAccessCsv(path, account, preview);
      setNotice({ kind: "info", text: `Access CSV written to ${path}`, for: forTab });
    } catch (e) {
      setNotice({ kind: "error", text: isCmdError(e) ? e.message : String(e), for: forTab });
    }
  };
  const shownNotice = notice?.for === scopeKey ? notice : null;

  const pendingLine = (n: number) =>
    !whatIfTab &&
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
  const banner = whatIfTab ? (
    <p role="note" className="access-preview-banner">
      {displaySafe(`WHAT-IF: what ${KIND_NAME[scope.kind]} ${scope.value} would have reached if it were the attacker; not the reviewed report`)}
    </p>
  ) : (
    preview && (
      <p role="note" className="access-preview-banner">
        {displaySafe(`PREVIEW: includes ${bannerParts.join(" and ")}; not the reviewed answer`)}
      </p>
    )
  );
  const applyWhatIf = () => {
    const v = whatIfText.trim();
    setWhatIf(v === "" ? null : { kind: whatIfKind, value: v });
  };
  const controls = !whatIfTab && (
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
  if (!report || !merged)
    return (
      <section className="access card" aria-label="Access">
        {banner}
        {controls}
        <p className="entity-empty">Loading…</p>
      </section>
    );
  const several = report.accounts.length > 1;
  const empty = merged.scope.length === 0 && merged.items.length === 0;
  const emptyText =
    scope.kind === "account"
      ? "No malicious sessions or IPs are flagged for this account."
      : scope.kind === "case"
        ? "No malicious flags are accepted yet."
        : `Nothing found for ${KIND_NAME[scope.kind]} ${scope.value}.`;
  return (
    <section className="access card" aria-label="Access">
      {banner}
      <header className="access-head">
        <h4>Access</h4>
        <ul className="access-scope" aria-label="Scope">
          {merged.scope.map((s) => (
            <li key={`${s.kind}:${s.value}:${s.basis}`} className="access-chip" title={windowsText(s.windows)}>
              {`${BASIS_LABEL[s.basis] ? `${BASIS_LABEL[s.basis]} ` : ""}${s.kind} ${displaySafe(s.value)}`}
            </li>
          ))}
        </ul>
        {several && (
          <select aria-label="Account" className="access-account" value={filter ?? ""} onChange={(e) => setOnly(e.target.value === "" ? null : e.target.value)}>
            <option value="">All accounts</option>
            {merged.accounts.map((a) => (
              <option key={a} value={a}>
                {displaySafe(a)}
              </option>
            ))}
          </select>
        )}
        {!empty && (
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
      {empty && <p className="entity-empty">{displaySafe(emptyText)}</p>}
      {pendingLine(report.pending_flags)}
      <ul className="access-tiles" aria-label="What the attacker reached">
        {merged.tiles.map((t) => (
          <li key={t.category} aria-label={ACCESS_TITLES[t.category]} className={`access-tile card${exposed(t) ? " access-tile-hit" : ""}`}>
            <span className="access-tile-title">{ACCESS_TITLES[t.category]}</span>
            <span className="access-tile-count">
              {t.direct}
              {t.by_time > 0 && <span className="access-tile-time">{` · ${t.by_time} by time`}</span>}
              {t.pending > 0 && <span className="access-basis access-basis-pending">{` · ${t.pending} pending`}</span>}
              {t.adhoc > 0 && <span className="access-basis access-basis-adhoc">{` · ${t.adhoc} what-if`}</span>}
            </span>
            <span className="access-tile-note" title={displaySafe(tileNote(t))}>
              {displaySafe(tileNote(t))}
            </span>
          </li>
        ))}
      </ul>
      <section className="access-coverage" aria-label="Coverage">
        <p>
          <strong>Coverage:</strong>{" "}
          {merged.tiles.map((t, i) => (
            <span key={t.category} title={displaySafe(t.coverage.reason)}>
              {i > 0 ? " · " : ""}
              {`${ACCESS_TITLES[t.category]} ${t.coverage.status === "collected" ? "✓" : (partly(t) ?? statusLabel(t.coverage.status))}`}
            </span>
          ))}
        </p>
        <ul>
          {/* Each account's own gaps, then what Microsoft never logs (listed once by the report). */}
          {merged.gaps.map((g) => (
            <li key={g}>{displaySafe(g)}</li>
          ))}
        </ul>
      </section>
      {merged.tiles
        .filter((t) => byCategory.has(t.category))
        .map((t) => (
          <ItemTable key={t.category} category={t.category} items={byCategory.get(t.category)!} preview={preview !== null} showAccount={several} />
        ))}
    </section>
  );
}
