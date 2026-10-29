// What a cell value looks like, for the cell menu only. The backend validates every entity value again; this just
// decides whether to offer the action.
import type { EntityKind } from "./api";

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

function isAccount(s: string): boolean {
  return s.length <= 320 && ACCOUNT.test(s) && !/\p{Cc}/u.test(s);
}

/** A device or session id: any short text without control characters (the backend lower-cases it). */
function isOpaqueId(s: string): boolean {
  return s.trim().length > 0 && s.length <= 128 && !/\p{Cc}/u.test(s);
}

const BY_COLUMN: Record<string, EntityKind> = {
  device_id: "device",
  entra_session_id: "session",
  session: "session",
  ip: "ip",
  client_ip: "ip",
  from_ip: "ip",
  actor_upn: "account",
  owner_upn: "account",
  user_upn: "account",
  sender: "account",
  recipient: "account",
};

/**
 * The entity tab a cell can open. The column decides first (a device or session id cannot be told from a GUID in
 * another column by its value, so GUID-looking values elsewhere get no action); a listed column whose value does not
 * fit its kind gets none. Any other column falls back to the value: an IP address or an account name.
 */
export function entityKindFor(column: string, v: unknown): EntityKind | null {
  if (typeof v !== "string") return null;
  const kind = Object.hasOwn(BY_COLUMN, column) ? BY_COLUMN[column] : undefined;
  if (kind === "device" || kind === "session") return isOpaqueId(v) ? kind : null;
  if (kind === "ip") return isIp(v) ? "ip" : null;
  if (kind === "account") return isAccount(v) ? "account" : null;
  if (isIp(v)) return "ip";
  return isAccount(v) ? "account" : null;
}
