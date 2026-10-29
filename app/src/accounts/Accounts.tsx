import { useEffect, useState } from "react";
import { accountsList, isCmdError, type AccountPage, type AccountRow } from "../api";
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

/**
 * The account roll-up, the analyst's starting point. Clicking an account hands its UPN to the shell, which filters
 * the review queue to it. A roll-up that is not current arrives with warnings: they are shown above the table.
 */
export default function Accounts({ onSelect }: { onSelect: (upn: string) => void }) {
  const [page, setPage] = useState<AccountPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const nav = useNav();

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
        <table className="acc-table">
          <thead>
            <tr>
              <th>Account</th>
              <th>Worst severity</th>
              <th className="acc-num">Findings</th>
              <th>Stages</th>
              <th>First suspicious</th>
              <th>Addresses</th>
            </tr>
          </thead>
          <tbody>
            {page.accounts.map((a) => (
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
    </section>
  );
}
