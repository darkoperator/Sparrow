// Builders for access-report test data (tests only).
import type { AccessAccount, AccessCategory, AccessItem, AccessReport, AccessTile } from "../api";

export const A = "jdoe@contoso.example";
export const NEVER = ["Teams chats read in the Teams app are not audited (only Graph reads are)"];
export const ORDER: AccessCategory[] = ["mail_read", "mail_sent", "attachment", "file", "teams", "copilot", "other"];

export function tile(category: AccessCategory, over: Partial<AccessTile> = {}): AccessTile {
  return {
    category,
    direct: 0,
    by_time: 0,
    qualifier: null,
    coverage: { status: "collected", reason: "collected", remediation: null },
    none_seen: true,
    pending: 0,
    adhoc: 0,
    ...over,
  };
}

export function item(over: Partial<AccessItem>): AccessItem {
  return {
    account: A, category: "mail_read", attribution: "ip", accessed: "2026-10-23T16:42:18Z", action: "read",
    item: "Q3 invoices", location: "\\Inbox", from: "ap@vendor.example", to: A, size_bytes: 10, item_time: null,
    app: null, app_name: null, ip: "203.0.113.45", session_id: null, owner: null, note: null, source: "ual_events:MailItemsAccessed",
    source_table: "ual_events", record_key: "r1", basis: "accepted", row: "ual_events:r1", ...over,
  };
}

export function account(over: Partial<AccessAccount> = {}): AccessAccount {
  return {
    account: A,
    tenant_key: "contoso",
    scope: [{ kind: "ip", value: "203.0.113.45", basis: "accepted", windows: [{ start: "2026-10-23T16:38:51Z", end: "2026-10-23T17:45:09Z" }] }],
    tiles: ORDER.map((c) => tile(c)),
    items: [],
    gaps: [],
    ...over,
  };
}

export function report(accounts: AccessAccount[], over: Partial<AccessReport> = {}): AccessReport {
  return { accounts, pending_flags: 0, preview: false, never_logged: NEVER, ...over };
}
