// What a cell value looks like, for the cell menu only. The backend validates every pivot value again; this just
// decides whether to offer the action.

export type PivotKind = "ip" | "account";

/** The cell's value as the analyst would copy it: strings untouched, everything else its JSON/text form. */
export function rawText(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const IPV4 = new RegExp(`^${OCTET}(?:\\.${OCTET}){3}$`);

function isIp(s: string): boolean {
  if (IPV4.test(s)) return true;
  if (!s.includes(":") || s.length > 45 || !/^[0-9a-fA-F:.]+$/.test(s)) return false;
  try {
    // The URL parser validates an IPv6 literal (compression, group count, embedded IPv4).
    new URL(`http://[${s}]/`);
    return true;
  } catch {
    return false;
  }
}

const ACCOUNT = /^[^\s@]+@[^\s@]+$/;

export function valueKind(v: unknown): PivotKind | null {
  if (typeof v !== "string") return null;
  if (isIp(v)) return "ip";
  if (v.length <= 320 && ACCOUNT.test(v) && !/\p{Cc}/u.test(v)) return "account";
  return null;
}
