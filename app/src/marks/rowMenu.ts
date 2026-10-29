// The context menu of an Events grid cell, as data. What a cell offers depends on its column: a value cell (IP,
// account, ASN, device, session) opens its tab, filters, and flags every event with that value (a standing flag); any
// other cell flags, tags, notes or adds to the timeline the event, or the ticked events when it is one of them.
// Write items are disabled, with the reason as their title, in a read-only case.
import type { EntityArg, EventField, EventRow, FlagLevel, PivotOf, RowRef, TagInfo, ValueKind } from "../api";
import type { MenuItem } from "../grid/CellMenu";
import type { EntityRef } from "../shell/tabs";
import { COLUMN_BY_ID, deviceKey, filterable } from "../events/columns";
import { displaySafe } from "../text";
import { tagItems } from "./TagMenu";

/** Notes go on at most this many events in one call. */
export const NOTE_MAX = 200;

/** What the menu items do; the grid supplies these. */
export interface RowMenuActions {
  showDetails: (row: RowRef) => void;
  filter: (field: EventField, value: string, exclude: boolean) => void;
  openEntity: (e: EntityRef) => void;
  flagRows: (rows: RowRef[], level: FlagLevel | null) => void;
  /** `what` names the value for the confirmation, like "IP 192.0.2.5". */
  flagValue: (kind: ValueKind, value: string, scope: EntityArg | null, level: FlagLevel | null, what: string) => void;
  tagRows: (rows: RowRef[], tag: string, add: boolean) => void;
  newTag: (rows: RowRef[]) => void;
  addNote: (rows: RowRef[]) => void;
  addToTimeline: (rows: RowRef[]) => void;
}

export interface RowMenuCell {
  column: string;
  row: EventRow;
  /** The ticked rows. Right-click on a ticked row acts on all of them; on any other row, on that row alone. */
  ticked: EventRow[];
}

export interface RowMenuContext {
  /** The entity tab the grid is in: value flags are then limited to it. */
  entity?: EntityRef;
  /** Why writes are not possible (a read-only case, or no analyst name), or null. */
  readOnly: string | null;
  tags: TagInfo[];
  /** False outside the shell: "Open … tab" is then not offered. */
  canOpen: boolean;
  act: RowMenuActions;
}

const ref = (r: EventRow): RowRef => ({ source_table: r.source_table, record_key: r.record_key });
const same = (a: EventRow, b: EventRow) => a.source_table === b.source_table && a.record_key === b.record_key;
const TAB_NOUN: Record<EntityArg["kind"], string> = { account: "user", ip: "IP", device: "device", session: "session" };

/** The rows a menu on `cell` acts on. */
export function targetsOf(cell: Pick<RowMenuCell, "row" | "ticked">): EventRow[] {
  return cell.ticked.some((t) => same(t, cell.row)) ? cell.ticked : [cell.row];
}

interface ValueSpec {
  kind: ValueKind;
  value: string;
  /** "this IP", for the labels. */
  noun: string;
  /** "IP 192.0.2.5", for the confirmation. */
  what: string;
  /** Malicious also makes the value an indicator (core: IPs and accounts only). */
  indicator: boolean;
}

/** The value flags a value cell offers: none for a column that is not a value or an event that lacks it. */
export function valueSpecs(column: string, r: EventRow): ValueSpec[] {
  switch (column) {
    case "ip": {
      if (!r.ip) return [];
      const out: ValueSpec[] = [{ kind: "ip", value: r.ip, noun: "this IP", what: `IP ${r.ip}`, indicator: true }];
      if (r.ip_prefix) {
        const v6 = r.ip.includes(":");
        out.push({ kind: "ip_prefix", value: r.ip, noun: displaySafe(`its ${v6 ? "/48" : "/24"} ${r.ip_prefix}`), what: `network ${r.ip_prefix}`, indicator: false });
      }
      return out;
    }
    case "actor_upn":
    case "owner_upn": {
      const v = column === "actor_upn" ? r.actor_upn : r.owner_upn;
      return v ? [{ kind: "account", value: v, noun: "this account", what: `account ${v.toLowerCase()}`, indicator: true }] : [];
    }
    case "asn":
      return r.asn === null ? [] : [{ kind: "asn", value: String(r.asn), noun: displaySafe(`AS${r.asn}`), what: `AS${r.asn}`, indicator: false }];
    case "device_name": {
      const id = deviceKey(r);
      return id ? [{ kind: "device", value: id, noun: "this device", what: `device ${id}`, indicator: false }] : [];
    }
    case "entra_session_id":
      return r.entra_session_id
        ? [{ kind: "session", value: r.entra_session_id, noun: "this Entra session", what: `Entra session ${r.entra_session_id}`, indicator: false }]
        : [];
    default:
      return [];
  }
}

/** The value flagged is the tab's own entity: a scope to it would cover the same events, so none is sent. */
function isTabEntity(spec: ValueSpec, entity: EntityRef | undefined): boolean {
  const kind: Partial<Record<ValueKind, EntityArg["kind"]>> = { ip: "ip", account: "account", device: "device", session: "session" };
  return entity !== undefined && kind[spec.kind] === entity.kind && spec.value.trim().toLowerCase() === entity.value.trim().toLowerCase();
}

/** What a value-flag menu needs: the tab it is in, why writes are off, and the flag action. */
export type ValueMenuContext = Pick<RowMenuContext, "entity" | "readOnly"> & { act: Pick<RowMenuActions, "flagValue"> };

/**
 * `Flag every event from this IP in this session (incl. later imports)`, and the three choices under it. `mode` "auto"
 * (the events grid) limits another value to the tab's events; "case" and "entity" (a pivot row) choose the scope.
 */
function valueFlagItem(spec: ValueSpec, ctx: ValueMenuContext, mode: "auto" | "case" | "entity" = "auto"): MenuItem {
  // Another value in an entity tab is limited to the tab's events; the tab's own value is not (same events either way).
  const entity =
    mode === "case" ? undefined : mode === "entity" ? ctx.entity : ctx.entity && !isTabEntity(spec, ctx.entity) ? ctx.entity : undefined;
  const scope: EntityArg | null = entity ? { kind: entity.kind, value: entity.value } : null;
  const where = entity ? ` in this ${TAB_NOUN[entity.kind]}` : mode === "case" ? " in the whole case" : "";
  const word = spec.kind === "ip" || spec.kind === "ip_prefix" ? "from" : spec.kind === "asn" ? "in" : "with";
  const label = `Flag every event ${word} ${spec.noun}${where} (incl. later imports)`;
  const set = (level: FlagLevel | null) => () => ctx.act.flagValue(spec.kind, spec.value, scope, level, spec.what);
  const items: MenuItem[] = [
    { label: "Suspicious", run: set("suspicious") },
    {
      label: spec.indicator ? "Malicious (adds or updates an indicator)" : "Malicious",
      run: set("malicious"),
    },
    { label: `Clear this flag (flags set on single events stay)`, run: set(null) },
  ];
  return ctx.readOnly !== null ? { label, items, disabled: ctx.readOnly } : { label, items };
}

/** Flag, Tag, note and timeline items for `targets`. */
function rowActionItems(targets: EventRow[], ctx: RowMenuContext): MenuItem[] {
  const refs = targets.map(ref);
  const n = targets.length;
  const what = n === 1 ? "this event" : `${n} ticked events`;
  const off = ctx.readOnly ?? undefined;
  const noteOff = off ?? (n > NOTE_MAX ? `Notes go on at most ${NOTE_MAX} events at once; ${n} are ticked` : undefined);
  const w = (item: MenuItem, why: string | undefined): MenuItem => (why === undefined ? item : { ...item, disabled: why });
  return [
    w(
      {
        label: `Flag ${what}`,
        items: [
          { label: "Suspicious", run: () => ctx.act.flagRows(refs, "suspicious") },
          { label: "Malicious", run: () => ctx.act.flagRows(refs, "malicious") },
          { label: `Clear flag on ${what}`, run: () => ctx.act.flagRows(refs, null) },
        ],
      },
      off,
    ),
    w({ label: `Tag ${what}`, filter: true, items: tagItems(ctx.tags, targets, ctx.act) }, off),
    w({ label: n === 1 ? "Add note…" : `Add note to ${n} events…`, run: () => ctx.act.addNote(refs) }, noteOff),
    w({ label: n === 1 ? "Add to timeline…" : `Add ${n} events to timeline…`, run: () => ctx.act.addToTimeline(refs) }, off),
  ];
}

export function rowMenu(cell: RowMenuCell, ctx: RowMenuContext): MenuItem[] {
  const { row, column } = cell;
  const col = COLUMN_BY_ID.get(column);
  const out: MenuItem[] = [{ label: "Show details", run: () => ctx.act.showDetails(ref(row)) }];
  const fv = col?.filter?.value(row) ?? null;
  if (col?.filter && fv !== null && filterable(fv)) {
    const field = col.filter.field;
    out.push({ label: "Filter by this value", run: () => ctx.act.filter(field, fv, false) });
    out.push({ label: "Exclude this value", run: () => ctx.act.filter(field, fv, true) });
  }
  const target = col?.entity?.(row) ?? null;
  if (ctx.canOpen && target) {
    out.push({ label: `Open ${target.kind === "ip" ? "IP" : target.kind} tab`, run: () => ctx.act.openEntity(target) });
  }
  const specs = valueSpecs(column, row);
  if (specs.length > 0) return [...out, ...specs.map((s) => valueFlagItem(s, ctx))];
  return [...out, ...rowActionItems(targetsOf(cell), ctx)];
}

/** The full value in the pivot menus and confirmations: nothing is shortened, only made safe to show. */
const PIVOT_KIND: Partial<Record<PivotOf, { kind: ValueKind; noun: string; indicator: boolean }>> = {
  accounts: { kind: "account", noun: "account", indicator: true },
  ips: { kind: "ip", noun: "IP", indicator: true },
  devices: { kind: "device", noun: "device", indicator: false },
  sessions: { kind: "session", noun: "Entra session", indicator: false },
};

/** Whether the rows of this pivot table can be flagged (the device-changes list is events, not values). */
export const pivotFlaggable = (of: PivotOf): boolean => PIVOT_KIND[of] !== undefined;

/**
 * The menu of a pivot table row: flag every event with the row's value, in the whole case or only in the tab's own
 * events. Empty for the device-changes list.
 */
export function pivotMenu(of: PivotOf, value: string, ctx: ValueMenuContext): MenuItem[] {
  const k = PIVOT_KIND[of];
  if (!k || value === "") return [];
  const shown = displaySafe(value);
  const spec: ValueSpec = { kind: k.kind, value, noun: `${k.noun} ${shown}`, what: `${k.noun} ${shown}`, indicator: k.indicator };
  return [valueFlagItem(spec, ctx, "case"), ...(ctx.entity ? [valueFlagItem(spec, ctx, "entity")] : [])];
}

const TAB_WORD: Record<EntityArg["kind"], string> = { account: "user", ip: "IP", device: "device", session: "session" };

/** The confirmation after a value flag: what was flagged, where, and the indicator it made. */
export function flagValueMessage(
  what: string,
  scope: EntityArg | null,
  level: FlagLevel | null,
  indicatorNote: string,
): string {
  const where = scope ? ` in this ${TAB_WORD[scope.kind]}` : "";
  if (level === null) return `Cleared the flag on ${what}${where}; flags set on single events stay`;
  return `Flagged every event with ${what}${where} ${level}, including later imports${indicatorNote}`;
}
