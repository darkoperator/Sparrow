// An entity tab: the header, the summary tiles, the pivot tables, the findings that involve the entity and the Events
// grid scoped to it. The tiles, pivots and findings follow the range of the tab's own histogram, and nothing outside
// the tab does. The coverage strip sits under the tiles and follows the same range.
import { useCallback, useEffect, useRef, useState } from "react";
import {
  entityCoverage,
  entityFindings,
  entityPivot,
  entitySummary,
  isCmdError,
  type EntityKind,
  type EventQuery,
  type EntityCoverage,
  type EntitySummary,
  type FindingRef,
  type PivotOf,
  type PivotPage,
} from "../api";
import { isoSeconds } from "../events/columns";
import EventsView from "../events/EventsView";
import { useNav, useRefreshBadges, useWriteBlocked } from "../shell/nav";
import type { EntityRef } from "../shell/tabs";
import { displaySafe } from "../text";
import AddToTimelineDialog from "../marks/AddToTimelineDialog";
import CoverageStrip from "./CoverageStrip";
import PivotTable, { PIVOTS } from "./PivotTable";
import Tiles from "./Tiles";

export const KIND_NAME: Record<EntityKind, string> = { account: "User", ip: "IP", device: "Device", session: "Entra session" };
const ICON: Record<EntityKind, string> = { account: "👤", ip: "🌐", device: "💻", session: "🔑" };

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
  }, [kind, value, from, to]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setNotice(`Copied ${displaySafe(value)}`);
    } catch {
      setNotice("Could not copy to the clipboard");
    }
  };

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
      <header className="entity-head">
        <h3>
          <span aria-hidden="true">{ICON[kind]}</span> {KIND_NAME[kind]} <span className="entity-value">{displaySafe(value)}</span>
        </h3>
        <button type="button" onClick={() => nav?.showInEvents(entity)} disabled={!nav}>
          Show in Events
        </button>
        <button type="button" onClick={() => void copy()}>
          Copy
        </button>
        <button type="button" disabled={groupReason !== undefined} title={groupReason} onClick={() => current.query && setAdding({ query: current.query, count: current.count })}>
          + Timeline (group)
        </button>
      </header>
      {notice && (
        <p role="status" className="entity-notice">
          {notice}
        </p>
      )}
      {data.error && <p role="alert">{displaySafe(data.error)}</p>}
      {summary ? <Tiles kind={kind} summary={summary} /> : !data.error && <p>Loading…</p>}
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
          />
        ))}
        <section className="entity-pivot entity-findings" aria-label="Findings">
          <h4>Findings involving this {KIND_NAME[kind].toLowerCase()}</h4>
          {data.findings === null ? (
            <p>Loading…</p>
          ) : data.findings.length === 0 ? (
            <p className="entity-empty">None in this range.</p>
          ) : (
            <ul>
              {data.findings.map((f) => (
                <li key={f.finding_id}>
                  <span className={`entity-sev entity-sev-${f.severity}`}>{displaySafe(f.severity)}</span>{" "}
                  <button type="button" className="link" onClick={() => nav?.openFinding(f.finding_id)} disabled={!nav}>
                    {displaySafe(f.title)}
                  </button>{" "}
                  <span className="entity-meta">
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
      <EventsView entity={entity} onRangeChange={onRangeChange} onQueryChange={onQueryChange} />
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
