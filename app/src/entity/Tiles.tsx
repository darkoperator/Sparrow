// The summary tiles of an entity tab. Which tiles show depends on the kind (the design's per-kind table); every value
// is text, and times are ISO 8601 UTC.
import type { EntityKind, EntitySummary } from "../api";
import { isoSeconds } from "../events/columns";
import { displaySafe } from "../text";

interface Tile {
  label: string;
  value: string;
  /** Extra text for a hover. */
  title?: string;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

/** Open findings as "high 1 · medium 2", worst first; "0" when there are none. */
export function findingsText(open: Record<string, number>): string {
  const keys = Object.keys(open).filter((k) => open[k] > 0);
  if (keys.length === 0) return "0";
  const rank = (k: string) => (SEVERITY_ORDER.includes(k) ? SEVERITY_ORDER.indexOf(k) : SEVERITY_ORDER.length);
  return keys
    .sort((a, b) => rank(a) - rank(b) || a.localeCompare(b))
    .map((k) => `${k} ${open[k]}`)
    .join(" · ");
}

const num = (n: number | undefined) => (n ?? 0).toLocaleString("en-US");
const text = (v: unknown): string => (v === null || v === undefined || v === "" ? "—" : String(v));
const yesNo = (v: unknown): string => (v === true ? "yes" : v === false ? "no" : "—");

/** The tiles of one kind, in order. Exported so a test can assert them exactly. */
export function tilesFor(kind: EntityKind, s: EntitySummary): Tile[] {
  const d = s.distinct;
  const common: Tile[] = [
    { label: "First seen", value: s.first_seen ? isoSeconds(s.first_seen) : "—" },
    { label: "Last seen", value: s.last_seen ? isoSeconds(s.last_seen) : "—" },
    { label: "Events", value: num(s.events) },
  ];
  const findings: Tile = { label: "Open findings", value: findingsText(s.open_findings) };
  switch (kind) {
    case "account":
      return [
        ...common,
        { label: "IPs", value: num(d.ips) },
        { label: "Countries", value: num(d.countries) },
        { label: "ASNs", value: num(d.asns) },
        { label: "Devices", value: num(d.devices) },
        { label: "Sessions", value: num(d.sessions) },
        findings,
      ];
    case "ip": {
      const i = s.ip_intel;
      const country = i ? [i.country_iso, i.country].filter((x) => x).join(" · ") : "";
      const asn = i ? [i.asn === null || i.asn === undefined ? "" : `AS${String(i.asn)}`, i.asn_org].filter((x) => x).join(" · ") : "";
      return [
        ...common,
        { label: "Accounts", value: num(d.accounts) },
        { label: "Devices", value: num(d.devices) },
        { label: "Sessions", value: num(d.sessions) },
        { label: "Country", value: text(country) },
        { label: "ASN", value: text(asn) },
        { label: "Kind", value: text(i?.ip_kind) },
        findings,
      ];
    }
    case "device": {
      const v = s.device;
      return [
        ...common,
        { label: "Accounts", value: num(d.accounts) },
        { label: "IPs", value: num(d.ips) },
        { label: "Sessions", value: num(d.sessions) },
        { label: "OS", value: text(v?.os) },
        { label: "Trust type", value: text(v?.trust_type) },
        { label: "Compliant", value: yesNo(v?.is_compliant) },
        { label: "Managed", value: yesNo(v?.is_managed) },
        findings,
      ];
    }
    case "session":
      return [
        ...common,
        { label: "Accounts", value: num(d.accounts) },
        { label: "IPs", value: num(d.ips) },
        { label: "Countries", value: num(d.countries) },
        { label: "Devices", value: num(d.devices) },
        findings,
      ];
  }
}

export default function Tiles({ kind, summary }: { kind: EntityKind; summary: EntitySummary }) {
  const tiles = tilesFor(kind, summary);
  return (
    <div>
      <dl className="entity-tiles" aria-label="Summary tiles">
        {tiles.map((t) => (
          <div key={t.label} className="entity-tile" role="group" aria-label={t.label}>
            <dt>{t.label}</dt>
            <dd title={t.title}>{displaySafe(t.value)}</dd>
          </div>
        ))}
      </dl>
      {kind === "account" && summary.roles_matched.length > 0 && (
        <p className="entity-roles">Events matched as: {summary.roles_matched.map(displaySafe).join(", ")}</p>
      )}
    </div>
  );
}
