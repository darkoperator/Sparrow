import { useEffect, useState } from "react";
import { accessAccounts, accountsList, isCmdError, type AccountPage, type AccountRow } from "../api";
import { useColumnView, useViewHeaders, ViewNote, type ViewColumn } from "../grid/columnView";
import { useNav } from "../shell/nav";
import { displaySafe } from "../text";
import Icon from "../ui/Icon";
import "./accounts.css";

const STAGE_LABELS: Record<string, string> = {
  suspicious_sign_in: "Suspicious sign-in",
  credential_takeover: "Credential takeover",
  persistence: "Persistence",
  mail_access: "Mail access",
  sending: "Sending",
  consent: "Consent",
  mfa_change: "MFA change",
};

const stageLabel = (s: string) => STAGE_LABELS[s] ?? s;

/** `2026-08-01 07:00:00` in UTC, the form `sparrow accounts` prints; anything that is not a time is shown as given. */
function utc(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toISOString().slice(0, 19).replace("T", " ");
}

function signinCoverage(a: AccountRow): string {
  return a.signins_first && a.signins_last
    ? `sign-ins ${utc(a.signins_first)} to ${utc(a.signins_last)}`
    : "no sign-ins collected";
}

/** Two letters for the avatar, from the UPN's local part ("a.rivera@…" → "AR"). Decoration only. */
function initials(upn: string): string {
  const parts = upn.split("@")[0].split(/[._-]+/).filter((p) => p !== "");
  const letters = parts.length > 1 ? parts[0][0] + parts[1][0] : (parts[0] ?? "").slice(0, 2);
  return letters.toUpperCase();
}

/** The severity's colour class; the severity is always written next to it. */
function sevClass(s: string): string {
  const k = s.toLowerCase();
  if (k === "high" || k === "critical") return "acc-sev-high";
  if (k === "medium") return "acc-sev-medium";
  return "acc-sev-low";
}

function addressText(a: AccountRow["addresses"][number]): string {
  return a.reasons.length > 0 ? `${a.ip} (${a.reasons.join(", ")})` : a.ip;
}

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const NO_ACCOUNTS: AccountRow[] = [];

const ACCOUNT_COLUMNS: ViewColumn<AccountRow>[] = [
  { id: "account", label: "Account", value: (a) => a.upn },
  { id: "severity", label: "Worst severity", value: (a) => a.worst_severity, kind: "text", sortBy: (a) => SEVERITY_RANK[a.worst_severity.toLowerCase()] ?? -1 },
  { id: "findings", label: "Findings", value: (a) => a.finding_count, kind: "number" },
  { id: "stages", label: "Stages", value: (a) => a.stages.map(stageLabel).join(", "), kind: "text" },
  { id: "first", label: "First suspicious", value: (a) => a.first_suspicious, kind: "date" },
  { id: "addresses", label: "Addresses", value: (a) => a.addresses.map((x) => x.ip).join(", "), kind: "text" },
];

/**
 * The account roll-up, the analyst's starting point. Clicking an account hands its UPN to the shell, which filters
 * the review queue to it. A roll-up that is not current arrives with warnings: they are shown above the table.
 */
export default function Accounts({ onSelect }: { onSelect: (upn: string) => void }) {
  const [page, setPage] = useState<AccountPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const nav = useNav();
  // The accounts the access report lists (accepted malicious flags tie activity to them); a failure only hides the badge.
  const [flagged, setFlagged] = useState<Set<string>>(new Set());

  useEffect(() => {
    let live = true;
    accessAccounts().then(
      (a) => live && setFlagged(new Set(a)),
      () => {},
    );
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => {
    let live = true;
    accountsList().then(
      (p) => live && setPage(p),
      (e: unknown) => live && setError(isCmdError(e) ? e.message : String(e)),
    );
    return () => {
      live = false;
    };
  }, []);

  const view = useColumnView(page?.accounts ?? NO_ACCOUNTS, ACCOUNT_COLUMNS);
  const { header, popover } = useViewHeaders(view, ACCOUNT_COLUMNS);

  return (
    <section className="accounts">
      <header className="acc-head">
        <h2>Accounts</h2>
        <p className="acc-sub">Accounts with findings. Click one to see its items in the review queue.</p>
      </header>
      {error && <div role="alert">{displaySafe(error)}</div>}
      {page && page.warnings.length > 0 && (
        <ul className="warnings" aria-label="Warnings">
          {page.warnings.map((w) => (
            <li key={w}>{displaySafe(w)}</li>
          ))}
        </ul>
      )}
      {page && page.truncated && <p className="acc-note">Showing {page.accounts.length} of {page.total} accounts.</p>}
      {page && page.accounts.length === 0 && page.warnings.length === 0 && (
        <p className="acc-empty">No accounts have findings.</p>
      )}
      {page && page.accounts.length > 0 && (
        <div className="table-scroll card acc-card">
        <ViewNote view={view} />
        <table className="acc-table">
          <thead>
            <tr>{ACCOUNT_COLUMNS.map((c) => header(c.id, { className: c.id === "findings" ? "acc-num" : undefined }))}</tr>
          </thead>
          <tbody>
            {view.rows.map((a) => (
              <tr key={`${a.tenant_key}/${a.upn}`} className={`acc-row ${sevClass(a.worst_severity)}`}>
                <td>
                  <div className="acc-account">
                    <span className="acc-avatar" aria-hidden="true">
                      {initials(displaySafe(a.upn))}
                    </span>
                    <div className="acc-who">
                      <div className="acc-upn-line">
                        <button
                          className="link acc-upn"
                          title={`${displaySafe(a.upn)} — show this account's items in the review queue`}
                          onClick={() => onSelect(a.upn)}
                        >
                          {displaySafe(a.upn)}
                        </button>
                        {flagged.has(a.upn.toLowerCase()) && (
                          <span
                            className="tag acc-mal"
                            title="Accepted malicious flags tie activity to this account: see the Access section of its tab"
                          >
                            Malicious
                          </span>
                        )}
                        {nav && (
                          <button
                            className="acc-open"
                            aria-label={`Open account tab ${displaySafe(a.upn)}`}
                            title="Open tab"
                            onClick={() => nav.openEntity({ kind: "account", value: a.upn })}
                          >
                            <Icon name="external" size={12} />
                          </button>
                        )}
                      </div>
                      <div className="meta mono" title={displaySafe(a.tenant_key)}>
                        {displaySafe(a.tenant_key)}
                      </div>
                      <div className="meta" title={displaySafe(signinCoverage(a))}>
                        {displaySafe(signinCoverage(a))}
                      </div>
                    </div>
                  </div>
                </td>
                <td>
                  <span className="pill acc-sev">{displaySafe(a.worst_severity)}</span>
                </td>
                <td className="acc-num">{a.finding_count}</td>
                <td>
                  {a.stages.length > 0 && (
                    <span className="acc-stages">
                      {a.stages.map((s) => (
                        <span key={s} className="acc-stage">
                          {stageLabel(s)}
                        </span>
                      ))}
                    </span>
                  )}
                </td>
                <td className="mono acc-time">{a.first_suspicious ? displaySafe(a.first_suspicious) : ""}</td>
                <td>
                  <ul className="plain acc-addresses">
                    {a.addresses.map((x) => (
                      <li key={x.ip} title={displaySafe(addressText(x))}>
                        <span className="mono">{displaySafe(addressText(x))}</span>
                        {nav && (
                          <>
                            {" "}
                            <button
                              className="acc-open"
                              aria-label={`Open IP tab ${displaySafe(x.ip)}`}
                              title="Open tab"
                              onClick={() => nav.openEntity({ kind: "ip", value: x.ip })}
                            >
                              <Icon name="external" size={12} />
                            </button>
                          </>
                        )}
                      </li>
                    ))}
                  </ul>
                  {a.addresses_total > a.addresses.length && (
                    <div className="meta">+{a.addresses_total - a.addresses.length} more</div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}
      {popover}
      {popover}
    </section>
  );
}
