// One pivot table of an entity tab: the values the entity's events carry, with a count and when they were first and last
// seen. A row opens that value's own tab. The device-changes table is a list of directory events, not values, so its
// rows do not open anything.
import { useMemo, useState } from "react";
import type { EntityKind, FlaggedCounts, PivotFlag, PivotOf, PivotPage, PivotRow } from "../api";
import { isoSeconds } from "../events/columns";
import CellMenu, { type MenuItem } from "../grid/CellMenu";
import { useColumnView, useViewHeaders, ViewNote, type ViewColumn } from "../grid/columnView";
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
  /** A narrower cap than the default (ellipsis; the full text is the cell's title), so Count stays in view. */
  narrow?: boolean;
}

const COLS: Record<PivotOf, Col[]> = {
  accounts: [{ label: "Account", cell: (r) => r.value }],
  ips: [
    { label: "IP", cell: (r) => r.value },
    { label: "Country", cell: (r) => str(r.extra.country) },
    {
      label: "ASN / kind",
      narrow: true,
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
  /** The items of a row's context menu (right-click, the menu key or Shift+F10); none: the rows have no menu. */
  menu?: (row: PivotRow) => MenuItem[];
  /** The noun the tab's own events are named by in a flag's hover ("IP", "user"). */
  tabNoun?: string;
}

/** The flag pill's text and hover: what level, whether an agent's unreviewed one, and whom it covers. */
export function flagPill(f: PivotFlag, tabNoun = "tab"): { text: string; title: string } {
  const level = f.level === "malicious" ? "Malicious" : "Suspicious";
  const where = f.scope === "case" ? "every event in the case" : `only the events of this ${tabNoun}`;
  return {
    text: f.pending ? `${level} · agent` : level,
    title: `${level} flag on this value for ${where}${f.pending ? "; set by an agent, not yet reviewed" : ""}`,
  };
}

/** What a row's value is, for the hover of its flagged counts. */
const VALUE_NOUN: Record<PivotOf, string> = {
  accounts: "account",
  ips: "IP",
  devices: "device",
  sessions: "session",
  device_changes: "change",
};

/** A row's flagged events: "312 malicious · 4 suspicious", one of them, or "—". */
export function flaggedText(f: FlaggedCounts): string {
  const parts = [
    f.malicious > 0 ? `${f.malicious.toLocaleString("en-US")} malicious` : null,
    f.suspicious > 0 ? `${f.suspicious.toLocaleString("en-US")} suspicious` : null,
  ].filter((p): p is string => p !== null);
  return parts.length > 0 ? parts.join(" · ") : "—";
}

/** The hover of the flagged counts: events flagged by any flag, which is not the same as a flag on this value. */
export function flaggedTitle(of: PivotOf, f: FlaggedCounts, tabNoun = "tab"): string {
  const noun = VALUE_NOUN[of];
  const what = f.malicious + f.suspicious > 0 ? flaggedText(f) : "None";
  return `${what}: events of this ${tabNoun} with this ${noun} that are flagged, by any flag (their own, or a flag on any of their values, such as a device or session). The pill says whether this ${noun} itself is flagged.`;
}

/** A menu opened on one row: the items are built when it opens, so a reload under it cannot change what they act on. */
interface Open {
  x: number;
  y: number;
  items: MenuItem[];
  /** The row that opened it: the focus goes back there when the menu closes. */
  opener: HTMLElement;
}

const NO_ROWS: PivotRow[] = [];

export default function PivotTable({ of, page, error, onOpen, menu, tabNoun }: Props) {
  const [open, setOpen] = useState<Open | null>(null);
  const title = PIVOT_TITLE[of];
  const opens = PIVOT_OPENS[of];
  const cols = COLS[of];
  const isChanges = of === "device_changes";
  const top = page ? Math.max(1, ...page.rows.map((r) => r.count)) : 1;
  const columns = useMemo<ViewColumn<PivotRow>[]>(
    () => [
      ...cols.map((c): ViewColumn<PivotRow> => ({ id: c.label, label: c.label, value: c.cell, kind: "text" })),
      { id: "count", label: isChanges ? "Events" : "Count", value: (r) => r.count, kind: "number" },
      { id: "first", label: isChanges ? "Time" : "First seen", value: (r) => r.first_seen, kind: "date" },
      ...(isChanges ? [] : [{ id: "last", label: "Last seen", value: (r: PivotRow) => r.last_seen, kind: "date" as const }]),
    ],
    [cols, isChanges],
  );
  const view = useColumnView(page?.rows ?? NO_ROWS, columns);
  const { header, popover } = useViewHeaders(view, columns);
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
          <ViewNote view={view} />
          <table>
            <thead>
              <tr>{columns.map((c) => header(c.id, { className: cols.find((x) => x.label === c.id)?.narrow ? "entity-col-narrow" : undefined }))}</tr>
            </thead>
            <tbody>
              {view.rows.map((r, i) => {
                const go = opens ? () => onOpen({ kind: opens, value: r.value }) : undefined;
                const items = menu ? menu(r) : [];
                const pill = r.flag ? flagPill(r.flag, tabNoun) : null;
                return (
                  <tr
                    key={`${r.value}#${i}`}
                    className={go ? "entity-pivot-row" : undefined}
                    tabIndex={go ? 0 : undefined}
                    aria-label={go ? `Open ${opens} ${displaySafe(r.value)}` : undefined}
                    onClick={go}
                    onContextMenu={
                      items.length > 0
                        ? (e) => {
                            e.preventDefault();
                            setOpen({ x: e.clientX, y: e.clientY, items, opener: e.currentTarget });
                          }
                        : undefined
                    }
                    onKeyDown={
                      go
                        ? (e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              go();
                            } else if (items.length > 0 && (e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey))) {
                              e.preventDefault();
                              const b = e.currentTarget.getBoundingClientRect();
                              setOpen({ x: b.left + 24, y: b.bottom, items, opener: e.currentTarget });
                            }
                          }
                        : undefined
                    }
                  >
                    {cols.map((c, ci) => (
                      <td
                        key={c.label}
                        className={[MONO_COLS.has(c.label) ? "mono" : "", c.narrow ? "entity-col-narrow" : ""].filter(Boolean).join(" ") || undefined}
                        title={displaySafe(c.cell(r))}
                      >
                        {ci === 0 && (r.flag || r.is_new) ? (
                          <span className="entity-cellwrap">
                            <span className="entity-val">{displaySafe(c.cell(r))}</span>
                            {r.is_new && <span className="entity-new pill pill-new">new</span>}
                            {pill && r.flag && (
                              <span className={`entity-flag pill ${r.flag.level === "malicious" ? "pill-mal" : "pill-sus"}`} title={pill.title}>
                                {pill.text}
                              </span>
                            )}
                          </span>
                        ) : (
                          displaySafe(c.cell(r))
                        )}
                      </td>
                    ))}
                    <td className="entity-count">
                      {!isChanges && (
                        <span className="entity-bar" aria-hidden="true">
                          <i style={{ width: `${Math.max(2, Math.round((r.count / top) * 100))}%` }} />
                        </span>
                      )}
                      {r.count.toLocaleString("en-US")}
                      {!isChanges && r.flagged.malicious + r.flagged.suspicious > 0 && (
                        <span
                          className={`entity-flagged ${r.flagged.malicious > 0 ? "entity-flagged-mal" : "entity-flagged-sus"}`}
                          title={flaggedTitle(of, r.flagged, tabNoun)}
                        >
                          {flaggedText(r.flagged)}
                        </span>
                      )}
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
      {popover}
      {open && (
        <CellMenu
          x={open.x}
          y={open.y}
          items={open.items}
          onClose={() => {
            open.opener.focus();
            setOpen(null);
          }}
        />
      )}
    </section>
  );
}
