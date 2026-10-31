// The tab strip's state, as pure functions: the fixed tabs, the open entity and Access tabs (at most ten together,
// least recently viewed closed first), which one is showing, and the per-case persistence.
import type { EntityArg, EntityKind } from "../api";

export type { EntityKind };
/** The same shape as the backend's entity argument. */
export type EntityRef = EntityArg;

export const FIXED_TABS = [
  { id: "events", label: "Events" },
  { id: "review", label: "Review" },
  { id: "timeline", label: "Timeline" },
  { id: "accounts", label: "Accounts" },
  { id: "devices", label: "Devices" },
  { id: "tables", label: "Tables" },
  { id: "sql", label: "SQL" },
  { id: "highlights", label: "Highlights" },
  { id: "share", label: "Share" },
] as const;

export type FixedTab = (typeof FIXED_TABS)[number]["id"];

export const MAX_ENTITY_TABS = 10;

/** An Access tab: an account's, a device's or IP's what-if, or the whole case's (value ""). */
export type AccessRef = { access: "account" | "ip" | "device" | "case"; value: string };
/** A closable tab. */
export type OpenTab = EntityRef | AccessRef;

export interface TabsState {
  /** The open entity and Access tabs, in the order they were opened. Values are canonical. */
  open: OpenTab[];
  active: FixedTab | OpenTab;
  /** Keys of the tabs viewed, oldest first; the last is the active tab. */
  viewed: string[];
}

const KINDS: readonly EntityKind[] = ["account", "ip", "device", "session"];
const ACCESS: readonly AccessRef["access"][] = ["account", "ip", "device", "case"];
const FIXED_IDS: readonly string[] = FIXED_TABS.map((t) => t.id);

export const isAccessRef = (t: FixedTab | OpenTab): t is AccessRef => typeof t !== "string" && "access" in t;
export const isEntityRef = (t: FixedTab | OpenTab): t is EntityRef => typeof t !== "string" && !("access" in t);

export function tabKey(t: FixedTab | OpenTab): string {
  if (typeof t === "string") return t;
  return isAccessRef(t) ? `access:${t.access}:${t.value}` : `${t.kind}:${t.value}`;
}

const V4_MAPPED = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/;

/** Mirrors the backend's `normalize_ip`: no brackets or port, IPv4-mapped as IPv4, IPv6 compressed lower-case. */
function canonicalIp(raw: string): string {
  const s = raw.trim();
  const bracket = /^\[([^\]]*)\]/.exec(s);
  const inner = bracket ? bracket[1] : s;
  const withPort = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(inner);
  const text = withPort ? withPort[1] : inner;
  if (text.includes(":")) {
    try {
      const host = new URL(`http://[${text}]/`).hostname.slice(1, -1).toLowerCase();
      const mapped = V4_MAPPED.exec(host);
      if (mapped) {
        const hi = parseInt(mapped[1], 16);
        const lo = parseInt(mapped[2], 16);
        return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
      }
      return host;
    } catch {
      return text.toLowerCase();
    }
  }
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(text) ? text : text.toLowerCase();
}

const KIND_LABEL: Record<EntityKind, string> = { account: "account", ip: "IP", device: "device", session: "session" };

/** A closable tab's full name, for its accessible name, title and the closing toast: `account x`, `Access IP x (what-if)`. */
export function tabName(t: OpenTab): string {
  if (!isAccessRef(t)) return `${KIND_LABEL[t.kind]} ${t.value}`;
  if (t.access === "case") return "Access whole case";
  return `Access ${KIND_LABEL[t.access]} ${t.value}${t.access === "account" ? "" : " (what-if)"}`;
}

/** What the strip shows for a closable tab: the entity's short value, or `Access · <short value>`. */
export function tabText(t: OpenTab): string {
  if (!isAccessRef(t)) return shortValue(t.value);
  if (t.access === "case") return "Access · case";
  return `Access · ${shortValue(t.value)}${t.access === "account" ? "" : " (what-if)"}`;
}

/** The entity in the backend's stored spelling, so two spellings of one value open one tab. The backend re-checks. */
export function canonical(e: EntityRef): EntityRef {
  return { kind: e.kind, value: e.kind === "ip" ? canonicalIp(e.value) : e.value.trim().toLowerCase() };
}

/** An Access tab in canonical form (its value spelled as its entity's; the case's is ""), or null when it is not one. */
function canonicalAccess(a: AccessRef): AccessRef | null {
  if (!ACCESS.includes(a.access)) return null;
  if (a.access === "case") return { access: "case", value: "" };
  const value = canonical({ kind: a.access, value: a.value }).value;
  return value === "" ? null : { access: a.access, value };
}

export function initialTabs(): TabsState {
  return { open: [], active: "events", viewed: ["events"] };
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** What the strip shows for an entity: a GUID as `4f1c…9a2e`, a long value cut with an ellipsis. */
export function shortValue(value: string): string {
  if (GUID.test(value)) return `${value.slice(0, 4)}…${value.slice(-4)}`;
  return value.length > 28 ? `${value.slice(0, 27)}…` : value;
}

function find(s: TabsState, key: string): FixedTab | OpenTab | undefined {
  if (FIXED_IDS.includes(key)) return key as FixedTab;
  return s.open.find((e) => tabKey(e) === key);
}

function view(s: TabsState, t: FixedTab | OpenTab): TabsState {
  const key = tabKey(t);
  return { ...s, active: t, viewed: [...s.viewed.filter((k) => k !== key), key] };
}

/** Switch to a fixed tab or to an entity tab that is open; anything else changes nothing. */
export function showTab(s: TabsState, t: FixedTab | OpenTab): TabsState {
  const found = find(s, tabKey(t));
  return found === undefined ? s : view(s, found);
}

/**
 * Open an entity tab, or switch to it when it is already open. Opening an eleventh closes the least recently viewed
 * one and returns it. An empty value opens nothing.
 */
export function openEntity(s: TabsState, e: EntityRef): { state: TabsState; closed?: OpenTab } {
  const c = canonical(e);
  if (c.value === "" || !KINDS.includes(c.kind)) return { state: s };
  return open(s, c);
}

/** Open an Access tab, or switch to it: the same rules as an entity tab, sharing the same ten. */
export function openAccess(s: TabsState, a: AccessRef): { state: TabsState; closed?: OpenTab } {
  const c = canonicalAccess(a);
  return c ? open(s, c) : { state: s };
}

function open(s: TabsState, c: OpenTab): { state: TabsState; closed?: OpenTab } {
  const key = tabKey(c);
  const there = s.open.find((o) => tabKey(o) === key);
  if (there) return { state: view(s, there) };
  let open = [...s.open, c];
  let closed: OpenTab | undefined;
  if (open.length > MAX_ENTITY_TABS) {
    const openKeys = new Set(open.map(tabKey));
    const victimKey = s.viewed.find((k) => k !== key && openKeys.has(k)) ?? tabKey(open[0]);
    closed = open.find((o) => tabKey(o) === victimKey);
    open = open.filter((o) => tabKey(o) !== victimKey);
  }
  const base = { ...s, open, viewed: closed ? s.viewed.filter((k) => k !== tabKey(closed!)) : s.viewed };
  return { state: view(base, c), closed };
}

/** Close an entity or Access tab. Closing the active one returns to the tab viewed before it. Fixed tabs cannot be closed. */
export function closeTab(s: TabsState, key: string): TabsState {
  if (!s.open.some((o) => tabKey(o) === key)) return s;
  const open = s.open.filter((o) => tabKey(o) !== key);
  const viewed = s.viewed.filter((k) => k !== key);
  if (tabKey(s.active) !== key) return { ...s, open, viewed };
  const back = find({ ...s, open }, viewed[viewed.length - 1] ?? "events") ?? "events";
  return { open, active: back, viewed: viewed.length > 0 ? viewed : ["events"] };
}

const storageKey = (caseId: string) => `sparrow.tabs.v1.${caseId}`;

/** The tabs saved for this case. Anything unreadable gives the Events tab and no entity tabs. */
export function loadTabs(caseId: string): TabsState {
  try {
    const raw = localStorage.getItem(storageKey(caseId));
    if (!raw) return initialTabs();
    const p: unknown = JSON.parse(raw);
    if (typeof p !== "object" || p === null || !Array.isArray((p as { open?: unknown }).open)) return initialTabs();
    const saved = p as { open: unknown[]; active?: unknown; viewed?: unknown };
    const open: OpenTab[] = [];
    for (const t of saved.open) {
      const e = t as Partial<EntityRef> & Partial<AccessRef> | null;
      if (!e || typeof e.value !== "string") continue;
      let c: OpenTab | null = null;
      // An entry with an `access` property is an Access tab or nothing: never read as the entity its `kind` names.
      if ("access" in e) c = typeof e.access === "string" ? canonicalAccess({ access: e.access, value: e.value }) : null;
      else if (KINDS.includes(e.kind as EntityKind)) {
        const en = canonical({ kind: e.kind as EntityKind, value: e.value });
        c = en.value === "" ? null : en;
      }
      if (!c || open.length >= MAX_ENTITY_TABS || open.some((o) => tabKey(o) === tabKey(c))) continue;
      open.push(c);
    }
    const keys = open.map(tabKey);
    const seen = Array.isArray(saved.viewed)
      ? (saved.viewed as unknown[]).filter(
          (k, i, all): k is string =>
            typeof k === "string" && (keys.includes(k) || FIXED_IDS.includes(k)) && all.indexOf(k) === i,
        )
      : [];
    // Reopen on the tab that was showing; an unknown id, or an entity tab that is no longer open, reopens on Events.
    const fixed = FIXED_IDS.find((id) => id === saved.active) as FixedTab | undefined;
    const active: FixedTab | OpenTab = fixed ?? open.find((o) => tabKey(o) === saved.active) ?? "events";
    const viewed = [...keys.filter((k) => !seen.includes(k)), ...seen.filter((k) => k !== tabKey(active))];
    return { open, active, viewed: [...viewed, tabKey(active)] };
  } catch {
    return initialTabs();
  }
}

export function saveTabs(caseId: string, s: TabsState): void {
  try {
    localStorage.setItem(
      storageKey(caseId),
      JSON.stringify({ open: s.open, active: tabKey(s.active), viewed: s.viewed }),
    );
  } catch {
    // Private window, blocked storage: the tabs are simply not remembered.
  }
}
