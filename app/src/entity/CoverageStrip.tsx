// The coverage strip of an entity tab: for the tab's range and the accounts in its events, which evidence sources are
// sampled (a capped export) or absent. It does not depend on the range holding events: an empty range is where absence
// must not be read as proof. Nothing is shown when every source is covered. Each non-covered source is a sentence;
// its hover lists the accounts per state. Coverage works in whole UTC days, and the hover says so.
import type { CoverageSource, CoverageState, EntityCoverage, TenantCoverage } from "../api";
import { displaySafe } from "../text";

export const CLOSING_LINE = "Absence of an action here is not proof it didn't happen.";

/** One sentence for a source that is not covered; when only some of the accounts judged are in that state, how many. */
export function sentence(s: CoverageSource): string {
  const text =
    s.state === "sampled"
      ? `${s.title} in this range is sampled (capped export)`
      : s.state === "collector_gap"
        ? `${s.title} in this range: collector gap`
        : `${s.title} in this range has no data`;
  const total = Object.values(s.accounts_by_state).reduce((n, list) => n + list.length, 0);
  const some = s.accounts_by_state[s.state]?.length ?? 0;
  return some > 0 && some < total ? `${text} for ${some} of ${total} accounts` : text;
}

const STATES: CoverageState[] = ["collector_gap", "absent", "sampled", "covered"];
const STATE_LABEL: Record<CoverageState, string> = { collector_gap: "Collector gap", absent: "Absent", sampled: "Sampled", covered: "Covered" };
export const COLLECTOR_GAP_HINT = "The collector could not collect this range; re-collect it.";
const TENANT_WIDE = new Set(["message_trace", "entra_audit"]);

function hover(s: CoverageSource, from: string | null, to: string | null): string {
  const lines: string[] = [];
  if (TENANT_WIDE.has(s.source)) {
    lines.push(`Judged for the whole tenant: ${STATE_LABEL[s.state].toLowerCase()}.`);
  } else {
    for (const st of STATES) {
      const accounts = s.accounts_by_state[st];
      if (accounts && accounts.length > 0) lines.push(`${STATE_LABEL[st]}: ${accounts.map(displaySafe).join(", ")}`);
    }
  }
  if (s.state === "collector_gap") lines.push(COLLECTOR_GAP_HINT);
  lines.push(from && to ? `Days are UTC days, ${from} to ${to}, both included.` : "Days are UTC days.");
  return lines.join("\n");
}

function Section({ t, from, to, label }: { t: TenantCoverage; from: string | null; to: string | null; label: boolean }) {
  const open = t.sources.filter((s) => s.state !== "covered");
  if (open.length === 0) return null;
  return (
    <div className="coverage-tenant" role="group" aria-label={label ? `Coverage of tenant ${displaySafe(t.tenant_key)}` : "Coverage"}>
      {label && <span className="coverage-tenant-name">Tenant {displaySafe(t.tenant_key)}</span>}
      <ul className="coverage-chips">
        {open.map((s) => (
          <li key={s.source}>
            <span className={`coverage-chip coverage-${s.state.replace("_", "-")}`} tabIndex={0} title={hover(s, from, to)}>
              {displaySafe(sentence(s))}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function CoverageStrip({ coverage }: { coverage: EntityCoverage | null }) {
  if (!coverage) return null;
  const sections = coverage.tenants.filter((t) => t.sources.some((s) => s.state !== "covered"));
  if (sections.length === 0) return null;
  const many = coverage.tenants.length > 1;
  return (
    <section className="coverage-strip" aria-label="Coverage warning">
      <span className="coverage-head">
        Evidence coverage{coverage.from && coverage.to ? ` ${coverage.from} to ${coverage.to} (UTC days)` : ""}
      </span>
      {sections.map((t) => (
        <Section key={t.tenant_key} t={t} from={coverage.from} to={coverage.to} label={many} />
      ))}
      <p className="coverage-note">{CLOSING_LINE}</p>
    </section>
  );
}
