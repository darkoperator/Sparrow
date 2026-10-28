import { useEffect, useState } from "react";
import { accountsList, isCmdError, type AccountPage, type AccountRow } from "../api";
import { useNav } from "../shell/nav";
import { displaySafe } from "../text";

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
      <h2>Accounts</h2>
      {error && <div role="alert">{displaySafe(error)}</div>}
      {page && page.warnings.length > 0 && (
        <ul className="warnings" aria-label="Warnings">
          {page.warnings.map((w) => (
            <li key={w}>{displaySafe(w)}</li>
          ))}
        </ul>
      )}
      {page && page.truncated && <p>Showing {page.accounts.length} of {page.total} accounts.</p>}
      {page && page.accounts.length === 0 && page.warnings.length === 0 && <p>No accounts have findings.</p>}
      {page && page.accounts.length > 0 && (
        <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Account</th>
              <th>Worst severity</th>
              <th>Findings</th>
              <th>Stages</th>
              <th>First suspicious</th>
              <th>Addresses</th>
            </tr>
          </thead>
          <tbody>
            {page.accounts.map((a) => (
              <tr key={`${a.tenant_key}/${a.upn}`}>
                <td>
                  <button
                    className="link"
                    title="Show this account's items in the review queue"
                    onClick={() => onSelect(a.upn)}
                  >
                    {displaySafe(a.upn)}
                  </button>
                  {nav && (
                    <button
                      className="link"
                      aria-label={`Pivot on account ${displaySafe(a.upn)}`}
                      onClick={() => nav.openPivot("account", a.upn)}
                    >
                      Pivot
                    </button>
                  )}
                  <div className="meta">{displaySafe(a.tenant_key)}</div>
                  <div className="meta">{displaySafe(signinCoverage(a))}</div>
                </td>
                <td>{displaySafe(a.worst_severity)}</td>
                <td>{a.finding_count}</td>
                <td>{a.stages.map(stageLabel).join(", ")}</td>
                <td>{a.first_suspicious ? displaySafe(a.first_suspicious) : ""}</td>
                <td>
                  <ul className="plain">
                    {a.addresses.map((x) => (
                      <li key={x.ip}>
                        {displaySafe(addressText(x))}
                        {nav && (
                          <>
                            {" "}
                            <button
                              className="link"
                              aria-label={`Pivot on IP ${displaySafe(x.ip)}`}
                              onClick={() => nav.openPivot("ip", x.ip)}
                            >
                              Pivot
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
