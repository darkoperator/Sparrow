// An entity tab: the header, the summary tiles, the pivot tables, the findings that involve the entity and the Events
// grid scoped to it. What the attacker reached opens in its own Access tab: an account's from its one-line summary, a
// device's or IP's as a what-if from the header. The tiles, pivots and findings follow the range of the tab's own histogram, and nothing outside
// the tab does. The coverage strip sits under the tiles and follows the same range.
import { useCallback, useEffect, useRef, useState } from "react";
import {
  accessReport,
  entityCoverage,
  entityFindings,
  entityPivot,
  entitySummary,
  marksFlagValue,
  isCmdError,
  type AnalystDeviceStatus,
  type EntityKind,
  type EventQuery,
  type EntityCoverage,
  type EntitySummary,
  type FindingRef,
  type PivotOf,
  type PivotPage,
} from "../api";
import { isoSeconds } from "../events/columns";
import Icon, { type IconName } from "../ui/Icon";
import EventsView, { indicatorNote } from "../events/EventsView";
import { flagValueMessage, pivotMenu, type ValueMenuContext } from "../marks/rowMenu";
import { useDataVersion, useFocusAnalyst, useNav, useRefreshBadges, useWriteBlocked, useWriteTick } from "../shell/nav";
import type { EntityRef } from "../shell/tabs";
import { displaySafe } from "../text";
import AddToTimelineDialog from "../marks/AddToTimelineDialog";
import CellMenu, { type MenuItem } from "../grid/CellMenu";
import { AnalystPill, AnalystStatusDialog, analystStatusItem, clearAnalystStatus } from "../devices/analystStatus";
import { accessSummary } from "../access/AccessView";
import CoverageStrip from "./CoverageStrip";
import PivotTable, { PIVOTS } from "./PivotTable";
import Tiles from "./Tiles";
import "./entity.css";

export const KIND_NAME: Record<EntityKind, string> = { account: "User", ip: "IP", device: "Device", session: "Entra session" };
const ICON: Record<EntityKind, IconName> = { account: "user", ip: "globe", device: "monitor", session: "key" };

/** The account's access in one line (the reviewed report's counts) and the way into its Access tab. */
function AccessLine({ account }: { account: string }) {
  const nav = useNav();
  const dataVersion = `${useDataVersion()}.${useWriteTick()}`;
  const [line, setLine] = useState<{ for: string; text: string } | null>(null);
  const key = `${account}\u0000${dataVersion}`;
  useEffect(() => {
    let live = true;
    accessReport(account, null).then(
      (r) => live && setLine({ for: key, text: r.accounts[0] ? accessSummary(r.accounts[0]) : "Nothing attributed yet" }),
      (e: unknown) => live && setLine({ for: key, text: isCmdError(e) ? e.message : String(e) }),
    );
    return () => {
      live = false;
    };
  }, [account, key]);
  return (
    <div className="entity-access card" aria-label="Access">
      <span className="entity-kind">Access</span>
      <span className="entity-access-line">{line?.for === key ? displaySafe(line.text) : "Loading…"}</span>
      <button type="button" className="btn btn-ghost" onClick={() => nav?.openAccess({ access: "account", value: account })} disabled={!nav}>
        Open access
      </button>
    </div>
  );
}

export interface EntityTabProps {
  entity: EntityRef;
}

const errorText = (e: unknown) => (isCmdError(e) ? e.message : String(e));

interface Loaded {
  summary: EntitySummary | null;
  pivots: Partial<Record<PivotOf, PivotPage>>;
  pivotErrors: Partial<Record<PivotOf, string>>;
  findings: FindingRef[] | null;
  coverage: EntityCoverage | null;
  error: string | null;
}
const EMPTY: Loaded = { summary: null, pivots: {}, pivotErrors: {}, findings: null, coverage: null, error: null };

export default function EntityTab({ entity }: EntityTabProps) {
  const writeBlocked = useWriteBlocked();
  const focusAnalyst = useFocusAnalyst();
  const nav = useNav();
  const refreshBadges = useRefreshBadges();
  const { kind, value } = entity;
  const [range, setRange] = useState<{ from?: string; to?: string }>({});
  const [data, setData] = useState<Loaded>(EMPTY);
  const [current, setCurrent] = useState<{ query: EventQuery | null; count: number | null; pending: boolean }>({
    query: null,
    count: null,
    pending: true,
  });
  const [notice, setNotice] = useState<string | null>(null);
  // The query and count the dialog was opened with: what it asks to add is what it says.
  const [adding, setAdding] = useState<{ query: EventQuery; count: number | null } | null>(null);
  const token = useRef(0);
  // Bumped after a pivot flag: the tiles, pivots and findings are read again, and the grid with its query.
  const [reloadN, setReloadN] = useState(0);
  // Device tab: the header's menu (right-click, the menu key, Shift+F10 or the button) and the status dialog it opens.
  const [headMenu, setHeadMenu] = useState<{ x: number; y: number; items: MenuItem[]; opener: HTMLElement } | null>(null);
  const [settingStatus, setSettingStatus] = useState<AnalystDeviceStatus | null>(null);

  // A new range: the old tiles, pivots and findings no longer describe it, so they show as loading until each answers.
  const onRangeChange = useCallback((from?: string, to?: string) => {
    setRange({ from, to });
    setData(EMPTY);
  }, []);
  const onQueryChange = useCallback(
    (query: EventQuery | null, count: number | null, pending: boolean) => setCurrent({ query, count, pending }),
    [],
  );

  // Tiles, pivots and findings: again whenever the range changes. A late answer to an earlier range is dropped.
  const { from, to } = range;
  const dataVersion = useDataVersion();
  useEffect(() => {
    const mine = ++token.current;
    const live = () => mine === token.current;
    const arg = { kind, value };
    entitySummary(arg, from, to).then(
      (summary) => live() && setData((d) => ({ ...d, summary, error: null })),
      (e: unknown) => live() && setData((d) => ({ ...d, error: errorText(e) })),
    );
    entityFindings(arg, from, to).then(
      (findings) => live() && setData((d) => ({ ...d, findings })),
      (e: unknown) => live() && setData((d) => ({ ...d, error: errorText(e) })),
    );
    entityCoverage(arg, from, to).then(
      (coverage) => live() && setData((d) => ({ ...d, coverage })),
      (e: unknown) => live() && setData((d) => ({ ...d, error: errorText(e) })),
    );
    for (const of of PIVOTS[kind]) {
      entityPivot(arg, of, from, to).then(
        (page) => live() && setData((d) => ({ ...d, pivots: { ...d.pivots, [of]: page }, pivotErrors: { ...d.pivotErrors, [of]: undefined } })),
        (e: unknown) => live() && setData((d) => ({ ...d, pivotErrors: { ...d.pivotErrors, [of]: errorText(e) } })),
      );
    }
  }, [kind, value, from, to, reloadN, dataVersion]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setNotice(`Copied ${displaySafe(value)}`);
    } catch {
      setNotice("Could not copy to the clipboard");
    }
  };

  const flagContext: ValueMenuContext = {
    entity,
    readOnly: writeBlocked,
    focusAnalyst,
    act: {
      flagValue: (k, v, scope, level, what) => {
        marksFlagValue(k, v, scope, level).then(
          (done) => {
            setNotice(flagValueMessage(what, scope, level, indicatorNote(what, done.indicators)));
            refreshBadges();
            setReloadN((n) => n + 1);
          },
          (e: unknown) => setData((d) => ({ ...d, error: errorText(e) })),
        );
      },
    },
  };

  const statusDone = (message: string) => {
    setSettingStatus(null);
    setNotice(message);
    setReloadN((n) => n + 1);
  };
  const headItems = (): MenuItem[] => [
    analystStatusItem(
      data.summary?.analyst_status ?? null,
      writeBlocked,
      (s) => setSettingStatus(s),
      () => clearAnalystStatus(value).then(statusDone, (e: unknown) => setData((d) => ({ ...d, error: errorText(e) }))),
    ),
  ];
  const openHeadMenu = (x: number, y: number, opener: HTMLElement) => setHeadMenu({ x, y, items: headItems(), opener });
  const isDevice = kind === "device";

  const noQuery = current.query === null || current.count === 0;
  const groupReason = writeBlocked !== null
    ? writeBlocked
    : current.pending
      ? "Wait for the events to finish loading"
      : noQuery
      ? "No events match this tab's filters"
      : undefined;
  const { summary } = data;

  return (
    <section className="entity-tab" aria-label={`${KIND_NAME[kind]} ${displaySafe(value)}`}>
      <header
        className="entity-head"
        onContextMenu={
          isDevice
            ? (e) => {
                e.preventDefault();
                openHeadMenu(e.clientX, e.clientY, e.target instanceof HTMLElement ? e.target : e.currentTarget);
              }
            : undefined
        }
        onKeyDown={
          isDevice
            ? (e) => {
                if (e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey)) {
                  e.preventDefault();
                  const b = (e.target as HTMLElement).getBoundingClientRect();
                  openHeadMenu(b.left, b.bottom, e.target as HTMLElement);
                }
              }
            : undefined
        }
      >
        <span className={`entity-icon entity-icon-${kind}`} aria-hidden="true">
          <Icon name={ICON[kind]} size={20} />
        </span>
        <h3>
          <span className="entity-kind">{KIND_NAME[kind]}</span> <span className={`entity-value entity-value-${kind}`} title={displaySafe(value)}>{displaySafe(value)}</span>
        </h3>
        {isDevice && summary && (
          <div className="entity-analyst" aria-label="Analyst status">
            <span className="entity-kind">Analyst</span>
            <AnalystPill decision={summary.analyst_status} activeAfter={summary.active_after_analyst_removal} />
          </div>
        )}
        <div className="entity-actions">
          {isDevice && (
            <button
              type="button"
              className="btn btn-ghost"
              aria-haspopup="menu"
              onClick={(e) => {
                const b = e.currentTarget.getBoundingClientRect();
                openHeadMenu(b.left, b.bottom, e.currentTarget);
              }}
            >
              Analyst status ▾
            </button>
          )}
          <button type="button" className="btn btn-ghost" onClick={() => nav?.showInEvents(entity)} disabled={!nav}>
            Show in Events
          </button>
          {(kind === "ip" || kind === "device") && (
            <button type="button" className="btn btn-ghost" onClick={() => nav?.openAccess({ access: kind, value })} disabled={!nav}>
              Access (what-if)
            </button>
          )}
          <button type="button" className="btn btn-ghost" onClick={() => void copy()}>
            Copy
          </button>
          <button type="button" className="btn btn-primary" disabled={groupReason !== undefined} title={groupReason} onClick={() => current.query && setAdding({ query: current.query, count: current.count })}>
            + Timeline (group)
          </button>
        </div>
      </header>
      {notice && (
        <p role="status" className="entity-notice">
          {notice}
        </p>
      )}
      {data.error && <p role="alert" className="entity-error">{displaySafe(data.error)}</p>}
      {summary ? <Tiles kind={kind} summary={summary} /> : !data.error && <p className="entity-empty">Loading…</p>}
      {kind === "account" && <AccessLine account={value} />}
      <div className="entity-coverage">
        <CoverageStrip coverage={data.coverage} />
      </div>
      <div className="entity-pivots">
        {PIVOTS[kind].map((of) => (
          <PivotTable
            key={of}
            of={of}
            page={data.pivots[of] ?? null}
            error={data.pivotErrors[of]}
            onOpen={(e) => nav?.openEntity(e)}
            menu={(r) => pivotMenu(of, r.value, flagContext)}
            tabNoun={KIND_NAME[kind].toLowerCase()}
          />
        ))}
        <section className="entity-pivot entity-findings card" aria-label="Findings">
          <h4>Findings involving this {KIND_NAME[kind].toLowerCase()}</h4>
          {data.findings === null ? (
            <p className="entity-empty">Loading…</p>
          ) : data.findings.length === 0 ? (
            <p className="entity-empty">None in this range.</p>
          ) : (
            <ul>
              {data.findings.map((f) => (
                <li key={f.finding_id} className={`entity-finding entity-finding-${f.severity}`}>
                  <button type="button" className="link" title={displaySafe(f.title)} onClick={() => nav?.openFinding(f.finding_id)} disabled={!nav}>
                    {displaySafe(f.title)}
                  </button>{" "}
                  <span className={`entity-sev entity-sev-${f.severity}`}>{displaySafe(f.severity)}</span>{" "}
                  <span className="entity-meta mono">
                    {f.rule_id ? `${displaySafe(f.rule_id)} · ` : ""}
                    {displaySafe(f.status)}
                    {f.first_seen ? ` · ${isoSeconds(f.first_seen)}` : ""}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
      <EventsView entity={entity} reloadToken={reloadN} onRangeChange={onRangeChange} onQueryChange={onQueryChange} />
      {headMenu && (
        <CellMenu
          x={headMenu.x}
          y={headMenu.y}
          items={headMenu.items}
          onClose={() => {
            headMenu.opener.focus();
            setHeadMenu(null);
          }}
        />
      )}
      {settingStatus && (
        <AnalystStatusDialog
          deviceId={value}
          status={settingStatus}
          current={summary?.analyst_status ?? null}
          onDone={statusDone}
          onClose={() => setSettingStatus(null)}
        />
      )}
      {adding && (
        <AddToTimelineDialog
          query={adding.query}
          count={adding.count}
          defaultTitle={`${entity.kind} ${entity.value}: ${adding.count ?? 0} events`}
          onClose={() => setAdding(null)}
          onDone={(outcome) => {
            setAdding(null);
            setNotice(outcome);
            refreshBadges();
          }}
        />
      )}
    </section>
  );
}
