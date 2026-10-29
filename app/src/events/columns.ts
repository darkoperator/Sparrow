// The Events grid's columns: label, width, whether it shows by default, what it sorts by, which filter box it feeds
// and which entity tab its value opens. A column's `id` is the grid column key and, when `sortable`, the backend's
// sort column (`case::events` SORTABLE), so a header click sends it unchanged.
import type { EntityArg, EventField, EventRow } from "../api";
import { shortValue } from "../shell/tabs";

export interface EventColumn {
  id: string;
  label: string;
  width: number;
  /** Shown until the analyst hides it. */
  visible: boolean;
  /** The backend can sort by `id`. */
  sortable: boolean;
  /** The text of the cell (also its tooltip and what Copy copies). */
  text: (r: EventRow) => string;
  /** The filter box a "Filter by this value" on this column fills, and the exact value to put in it. */
  filter?: { field: EventField; value: (r: EventRow) => string | null };
  /** The entity tab(s) a value in this column can open. */
  entity?: (r: EventRow) => EntityArg | null;
}

/** `2026-09-10T01:55:36.000000Z` shown as `2026-09-10T01:55:36Z`; anything that is not that shape is returned as is. */
export function isoSeconds(t: string): string {
  return t.replace(/\.\d+Z$/, "Z");
}

const s = (v: string | null | undefined) => v ?? "";

const asnText = (r: EventRow) =>
  [r.asn === null ? "" : `AS${r.asn}`, s(r.asn_org), s(r.ip_kind)].filter((x) => x !== "").join(" · ");

/** The id a device filter and device tab use: the device id, else the Entra object id. */
export const deviceKey = (r: EventRow) => r.device_id ?? r.device_object_id;

export const COLUMNS: EventColumn[] = [
  { id: "event_time", label: "Time", width: 190, visible: true, sortable: true, text: (r) => (r.event_time === null ? "" : isoSeconds(r.event_time)) },
  { id: "source", label: "Source", width: 150, visible: true, sortable: true, text: (r) => r.source, filter: { field: "source", value: (r) => r.source } },
  { id: "operation", label: "Operation", width: 170, visible: true, sortable: true, text: (r) => s(r.operation), filter: { field: "operation", value: (r) => r.operation } },
  {
    id: "actor_upn", label: "Account", width: 200, visible: true, sortable: true, text: (r) => s(r.actor_upn),
    filter: { field: "account", value: (r) => r.actor_upn?.toLowerCase() ?? null },
    entity: (r) => (r.actor_upn ? { kind: "account", value: r.actor_upn } : null),
  },
  { id: "target", label: "Target", width: 190, visible: true, sortable: true, text: (r) => s(r.target) },
  {
    id: "ip", label: "IP", width: 140, visible: true, sortable: true, text: (r) => s(r.ip),
    filter: { field: "ip", value: (r) => r.ip },
    entity: (r) => (r.ip ? { kind: "ip", value: r.ip } : null),
  },
  { id: "ip_country", label: "Country", width: 80, visible: true, sortable: true, text: (r) => s(r.ip_country), filter: { field: "country", value: (r) => r.ip_country } },
  {
    id: "asn", label: "ASN / kind", width: 220, visible: true, sortable: true, text: asnText,
    filter: { field: "asn", value: (r) => (r.asn === null ? null : String(r.asn)) },
  },
  {
    id: "device_name", label: "Device", width: 150, visible: true, sortable: true, text: (r) => r.device_name ?? s(r.device_id),
    filter: { field: "device", value: (r) => deviceKey(r) ?? r.device_name },
    entity: (r) => {
      const id = deviceKey(r);
      return id ? { kind: "device", value: id } : null;
    },
  },
  {
    id: "entra_session_id", label: "Session", width: 130, visible: true, sortable: true, text: (r) => (r.entra_session_id ? shortValue(r.entra_session_id) : ""),
    filter: { field: "session", value: (r) => r.entra_session_id },
    entity: (r) => (r.entra_session_id ? { kind: "session", value: r.entra_session_id } : null),
  },
  { id: "result", label: "Result", width: 100, visible: true, sortable: true, text: (r) => s(r.result) },
  { id: "tags", label: "Tags", width: 170, visible: true, sortable: false, text: (r) => r.tags.map((t) => t.name).join(", ") },
  {
    id: "notes", label: "Notes", width: 200, visible: true, sortable: false,
    text: (r) => (r.latest_note === null ? "" : r.note_count > 1 ? `${r.latest_note} +${r.note_count - 1}` : r.latest_note),
  },
  {
    id: "flag", label: "Flag", width: 110, visible: true, sortable: false,
    text: (r) => (r.flag === null ? "" : `${r.flag === "malicious" ? "Malicious" : "Suspicious"}${r.flag_ai ? " (AI)" : ""}`),
  },
  // Hidden until asked for.
  {
    id: "owner_upn", label: "Mailbox owner", width: 200, visible: false, sortable: true, text: (r) => s(r.owner_upn),
    entity: (r) => (r.owner_upn ? { kind: "account", value: r.owner_upn } : null),
  },
  { id: "user_agent", label: "User agent", width: 240, visible: false, sortable: true, text: (r) => s(r.user_agent) },
  { id: "app_id", label: "App", width: 220, visible: false, sortable: true, text: (r) => s(r.app_id) },
  { id: "category", label: "Category", width: 130, visible: false, sortable: true, text: (r) => r.category },
  { id: "record_key", label: "Record key", width: 260, visible: false, sortable: true, text: (r) => r.record_key },
  { id: "finding_count", label: "Findings", width: 80, visible: false, sortable: false, text: (r) => String(r.finding_count) },
];

export const COLUMN_BY_ID: ReadonlyMap<string, EventColumn> = new Map(COLUMNS.map((c) => [c.id, c]));

export const DEFAULT_VISIBLE: string[] = COLUMNS.filter((c) => c.visible).map((c) => c.id);

/**
 * A value can be sent as the exact text of a filter box only if Harrier's syntax reads it back as that one value: no
 * comma (a list), no `*` (a wildcard), no leading `!` (an exclusion), and not blank after trimming.
 */
export function filterable(value: string): boolean {
  return value.trim() !== "" && !value.includes(",") && !value.includes("*") && !value.trim().startsWith("!");
}
