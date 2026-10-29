// One pivot table of an entity tab: the values the entity's events carry, with a count and when they were first and last
// seen. A row opens that value's own tab. The device-changes table is a list of directory events, not values, so its
// rows do not open anything.
import type { EntityKind, PivotOf, PivotPage, PivotRow } from "../api";
import { isoSeconds } from "../events/columns";
import type { EntityRef } from "../shell/tabs";
import { shortValue } from "../shell/tabs";
import { displaySafe } from "../text";

export const PIVOT_TITLE: Record<PivotOf, string> = {
  accounts: "Accounts",
  ips: "IPs",
  devices: "Devices",
  sessions: "Sessions",
  device_changes: "Device changes",
};

/** The kind of tab a row of this table opens; none for the device-changes list. */
export const PIVOT_OPENS: Record<PivotOf, EntityKind | null> = {
  accounts: "account",
  ips: "ip",
  devices: "device",
  sessions: "session",
  device_changes: null,
};

/** The tables of each kind of tab, in order (the design's per-kind table). */
export const PIVOTS: Record<EntityKind, PivotOf[]> = {
  account: ["ips", "devices", "sessions"],
  ip: ["accounts", "sessions", "devices"],
  device: ["accounts", "sessions", "ips", "device_changes"],
  session: ["ips", "accounts", "devices"],
};

const str = (v: unknown): string => (v === null || v === undefined ? "" : String(v));

interface Col {
  label: string;
  cell: (r: PivotRow) => string;
}

const COLS: Record<PivotOf, Col[]> = {
  accounts: [{ label: "Account", cell: (r) => r.value }],
  ips: [
    { label: "IP", cell: (r) => r.value },
    { label: "Country", cell: (r) => str(r.extra.country) },
    {
      label: "ASN / kind",
      cell: (r) => [r.extra.asn === undefined ? "" : `AS${str(r.extra.asn)}`, str(r.extra.asn_org), str(r.extra.ip_kind)].filter((x) => x).join(" · "),
    },
  ],
  devices: [
    { label: "Device", cell: (r) => r.label ?? r.value },
    { label: "Id", cell: (r) => shortValue(r.value) },
  ],
  sessions: [
    { label: "Session", cell: (r) => shortValue(r.value) },
    { label: "First IP", cell: (r) => str(r.extra.first_ip) },
  ],
  device_changes: [
    { label: "Operation", cell: (r) => r.value },
    { label: "Summary", cell: (r) => r.label ?? "" },
    { label: "By", cell: (r) => str(r.extra.actor) },
    { label: "Result", cell: (r) => str(r.extra.result) },
  ],
};

/** Columns that hold ids rather than names: they render in mono. */
const MONO_COLS = new Set(["IP", "Session", "Id", "First IP"]);

interface Props {
  of: PivotOf;
  /** Null while it loads. */
  page: PivotPage | null;
  error?: string | null;
  onOpen: (e: EntityRef) => void;
}

export default function PivotTable({ of, page, error, onOpen }: Props) {
  const title = PIVOT_TITLE[of];
  const opens = PIVOT_OPENS[of];
  const cols = COLS[of];
  const isChanges = of === "device_changes";
  const top = page ? Math.max(1, ...page.rows.map((r) => r.count)) : 1;
  return (
    <section className="entity-pivot card" aria-label={title}>
      <h4>
        {title}
        {page && page.rows.length < page.total && (
          <span className="entity-cut"> · showing {page.rows.length} of {page.total}</span>
        )}
      </h4>
      {error ? (
        <p role="alert" className="entity-error">{displaySafe(error)}</p>
      ) : !page ? (
        <p className="entity-empty">Loading…</p>
      ) : page.rows.length === 0 ? (
        <p className="entity-empty">None in this range.</p>
      ) : (
        <div className="entity-pivot-scroll">
          <table>
            <thead>
              <tr>
                {cols.map((c) => (
                  <th key={c.label}>{c.label}</th>
                ))}
                <th>{isChanges ? "Events" : "Count"}</th>
                <th>{isChanges ? "Time" : "First seen"}</th>
                {!isChanges && <th>Last seen</th>}
              </tr>
            </thead>
            <tbody>
              {page.rows.map((r, i) => {
                const open = opens ? () => onOpen({ kind: opens, value: r.value }) : undefined;
                return (
                  <tr
                    key={`${r.value}#${i}`}
                    className={open ? "entity-pivot-row" : undefined}
                    tabIndex={open ? 0 : undefined}
                    aria-label={open ? `Open ${opens} ${displaySafe(r.value)}` : undefined}
                    onClick={open}
                    onKeyDown={
                      open
                        ? (e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              open();
                            }
                          }
                        : undefined
                    }
                  >
                    {cols.map((c, ci) => (
                      <td key={c.label} className={MONO_COLS.has(c.label) ? "mono" : undefined} title={displaySafe(c.cell(r))}>
                        {displaySafe(c.cell(r))}
                        {ci === 0 && r.is_new && <span className="entity-new pill pill-new">new</span>}
                      </td>
                    ))}
                    <td className="entity-count">
                      {!isChanges && (
                        <span className="entity-bar" aria-hidden="true">
                          <i style={{ width: `${Math.max(2, Math.round((r.count / top) * 100))}%` }} />
                        </span>
                      )}
                      {r.count.toLocaleString("en-US")}
                    </td>
                    <td className="mono" title={isoSeconds(r.first_seen)}>{isoSeconds(r.first_seen)}</td>
                    {!isChanges && <td className="mono" title={isoSeconds(r.last_seen)}>{isoSeconds(r.last_seen)}</td>}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
