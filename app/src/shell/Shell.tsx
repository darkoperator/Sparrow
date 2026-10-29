// The window shell: case opening, the analyst name, the read-only banner and the tab strip. Screens are plugged in
// by name; a screen that is not built yet renders a placeholder. Entity tabs stay mounted while hidden, so each
// keeps its filters, range and page.
import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  caseClose,
  caseOpen,
  isCmdError,
  reviewQueue,
  settingsGet,
  timelineList,
  type CaseInfo,
  type Filter,
  type Settings,
} from "../api";
import Highlights from "../highlights/Highlights";
import { HighlightsError, HighlightsProvider } from "../highlights/useHighlights";
import Tables, { type TableRequest } from "../tables/Tables";
import ReviewQueue from "../review/ReviewQueue";
import { displaySafe } from "../text";
import { BrandMark } from "../ui/Icon";
import AnalystPrompt from "./AnalystPrompt";
import ExportMenu from "./ExportMenu";
import { NavContext, RefreshBadgesContext, WriteBlockedContext, writeBlockedReason } from "./nav";
import OpenCase, { type UpgradePrompt } from "./OpenCase";
import ReadOnlyBanner from "./ReadOnlyBanner";
import "./shell.css";
import TabStrip, { type TabBadges } from "./TabStrip";
import {
  closeTab,
  FIXED_TABS,
  initialTabs,
  isEntityRef,
  loadTabs,
  openEntity as openEntityTab,
  saveTabs,
  showTab,
  tabKey,
  type EntityRef,
  type FixedTab,
  type TabsState,
} from "./tabs";

export type ScreenId = FixedTab;

export interface ScreenProps {
  canWrite: boolean;
  /** Show the review queue filtered to this account. */
  showAccount: (upn: string) => void;
  /** Show the review queue, unfiltered. */
  showQueue: () => void;
  /** Open (or switch to) the tab of an account, IP, device or Entra session. */
  openEntity: (e: EntityRef) => void;
  /** Switch to the Events tab, limited to this entity. */
  showInEvents: (e: EntityRef) => void;
  /** The entity "Show in Events" asked for, if any; `nonce` changes with each request. */
  eventsEntity: (EntityRef & { nonce: number }) | null;
  clearEventsEntity: () => void;
  /** Open the table browser on a table, with these filters applied. */
  openTable: (table: string, filters: Filter[]) => void;
}

interface ShellProps {
  /** Screens built elsewhere, by id; anything missing renders a placeholder. */
  screens?: Partial<Record<Exclude<ScreenId, "review" | "tables" | "highlights">, (p: ScreenProps) => ReactNode>>;
  /** The body of an entity tab; until it is built, a placeholder shows the entity. */
  entityTab?: (e: EntityRef, p: ScreenProps) => ReactNode;
}

const TOAST_MS = 6000;

/** Up to two capitals for the analyst chip: the first letters of the first two words, or the first two letters. */
function initials(name: string): string {
  const words = displaySafe(name).split(/[\s._-]+/).filter(Boolean);
  const letters = words.length > 1 ? words[0][0] + words[1][0] : (words[0] ?? "?").slice(0, 2);
  return letters.toUpperCase();
}

export default function Shell({ screens = {}, entityTab }: ShellProps) {
  const [settings, setSettings] = useState<Settings>({ analyst: null, recent: [] });
  const [info, setInfo] = useState<CaseInfo | null>(null);
  const [tabs, setTabs] = useState<TabsState>(initialTabs);
  const [toast, setToast] = useState<string | null>(null);
  const [badgeTick, setBadgeTick] = useState(0);
  const refreshBadges = useCallback(() => setBadgeTick((n) => n + 1), []);
  const [badges, setBadges] = useState<TabBadges>({ review: 0, timeline: 0 });
  // The entity the Events tab is limited to ("Show in Events"); `nonce` tells the screen a new request came.
  const [eventsEntity, setEventsEntity] = useState<(EntityRef & { nonce: number }) | null>(null);
  // The review queue's account filter lives here: the accounts screen sets it, the queue shows it.
  const [accountFilter, setAccountFilter] = useState<string | null>(null);
  // The finding Review should select ("open this finding"); `nonce` tells the queue a new request came.
  const [findingReq, setFindingReq] = useState<{ id: string; nonce: number } | null>(null);
  const [tableReq, setTableReq] = useState<(TableRequest & { nonce: number }) | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [upgrade, setUpgrade] = useState<UpgradePrompt | null>(null);

  const refreshSettings = useCallback(async () => {
    try {
      setSettings(await settingsGet());
    } catch (e) {
      setError(isCmdError(e) ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    let live = true;
    settingsGet().then(
      (s) => live && setSettings(s),
      (e: unknown) => live && setError(isCmdError(e) ? e.message : String(e)),
    );
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), TOAST_MS);
    return () => clearTimeout(t);
  }, [toast]);

  const caseId = info?.case_id;
  const activeKey = tabKey(tabs.active);
  useEffect(() => {
    if (caseId !== undefined) saveTabs(caseId, tabs);
  }, [caseId, tabs]);

  // The badges: what is waiting for the analyst. Read again whenever the analyst switches tab.
  useEffect(() => {
    if (caseId === undefined) return;
    let live = true;
    Promise.all([reviewQueue(), timelineList()]).then(
      ([queue, entries]) =>
        live && setBadges({ review: queue.length, timeline: entries.filter((x) => x.review_state === "pending_review").length }),
      () => live && setBadges({ review: 0, timeline: 0 }),
    );
    return () => {
      live = false;
    };
  }, [caseId, activeKey, badgeTick]);

  const openCase = async (path: string, allowUpgrade = false) => {
    setError(null);
    setUpgrade(null);
    try {
      const opened = await caseOpen(path, allowUpgrade);
      setTabs(loadTabs(opened.case_id));
      setInfo(opened);
      setAccountFilter(null);
      setEventsEntity(null);
      setFindingReq(null);
      setTableReq(null);
      setToast(null);
      await refreshSettings();
    } catch (e) {
      if (isCmdError(e) && e.kind === "needs_upgrade") {
        setUpgrade({ path, message: e.message });
      } else {
        // needs_acknowledge, writer_busy, not_found, …: the message says what to do; there is nothing to confirm.
        setError(isCmdError(e) ? e.message : String(e));
      }
    }
  };

  const closeCase = async () => {
    try {
      await caseClose();
    } catch (e) {
      setError(isCmdError(e) ? e.message : String(e));
    }
    setInfo(null);
    setTabs(initialTabs());
    setEventsEntity(null);
    setFindingReq(null);
    setTableReq(null);
    setToast(null);
  };

  if (!info) {
    return (
      <OpenCase
        recent={settings.recent}
        error={error}
        upgrade={upgrade}
        onOpen={(p) => void openCase(p)}
        onConfirmUpgrade={() => upgrade && void openCase(upgrade.path, true)}
        onCancelUpgrade={() => {
          setUpgrade(null);
          setError(null);
        }}
      />
    );
  }

  const canWrite = info.read_only_reason === null && settings.analyst !== null;
  const show = (t: FixedTab | EntityRef) => setTabs(showTab(tabs, t));
  const showAccount = (upn: string) => {
    setAccountFilter(upn);
    show("review");
  };
  const showQueue = () => {
    setAccountFilter(null);
    show("review");
  };
  const openEntity = (e: EntityRef) => {
    const { state, closed } = openEntityTab(tabs, e);
    setTabs(state);
    if (closed) setToast(`Closed ${displaySafe(closed.value)} (10 tabs max)`);
  };
  const showInEvents = (e: EntityRef) => {
    setEventsEntity((r) => ({ ...e, nonce: (r?.nonce ?? 0) + 1 }));
    show("events");
  };
  const openFinding = (id: string) => {
    setAccountFilter(null);
    setFindingReq((r) => ({ id, nonce: (r?.nonce ?? 0) + 1 }));
    show("review");
  };
  const openTable = (table: string, filters: Filter[]) => {
    setTableReq((r) => ({ table, filters, nonce: (r?.nonce ?? 0) + 1 }));
    show("tables");
  };
  const screenProps: ScreenProps = {
    canWrite,
    showAccount,
    showQueue,
    openEntity,
    showInEvents,
    eventsEntity,
    clearEventsEntity: () => setEventsEntity(null),
    openTable,
  };
  const screen = isEntityRef(tabs.active) ? null : tabs.active;
  const body = (() => {
    if (screen === "review") {
      return (
        <ReviewQueue
          canWrite={canWrite}
          accountFilter={accountFilter}
          onClearFilter={() => setAccountFilter(null)}
          focusFinding={findingReq}
        />
      );
    }
    if (screen === "tables") return <Tables key={tableReq?.nonce ?? 0} initial={tableReq ?? undefined} />;
    if (screen === "highlights") return <Highlights />;
    if (screen === null) return null;
    // The Events screen stays mounted while hidden (below), so its filters, range and page survive a tab switch.
    if (screen === "events" && screens.events) return null;
    const render = screens[screen];
    if (render) return render(screenProps);
    const label = FIXED_TABS.find((t) => t.id === screen)?.label ?? screen;
    return <p>{label} is not built yet.</p>;
  })();

  return (
    <div className="shell">
      <header className="titlebar">
        <span className="brand">
          <BrandMark />
          <strong>Sparrow</strong>
        </span>
        <span className="titlebar-sep" aria-hidden="true">
          /
        </span>
        <span className="case-name" title={info.path}>
          {displaySafe(info.case_id)}
        </span>
        <span className="titlebar-spacer" />
        {settings.analyst && (
          <span className="analyst-chip" title={displaySafe(settings.analyst)}>
            <span className="analyst-initials" aria-hidden="true">
              {initials(settings.analyst)}
            </span>
            <span className="analyst-name">{displaySafe(settings.analyst)}</span>
            <span className="analyst-role"> · analyst</span>
          </span>
        )}
        <ExportMenu />
        <button className="btn btn-ghost" onClick={() => void closeCase()}>
          Close case
        </button>
      </header>
      {info.read_only_reason !== null && <ReadOnlyBanner reason={info.read_only_reason} />}
      {info.warnings.length > 0 && (
        <ul className="warnings">
          {info.warnings.map((w) => (
            <li key={w}>{displaySafe(w)}</li>
          ))}
        </ul>
      )}
      {settings.analyst === null && <AnalystPrompt onSaved={setSettings} />}
      <TabStrip state={tabs} badges={badges} onShow={show} onClose={(key) => setTabs(closeTab(tabs, key))} />
      {toast && (
        <div role="status" className="toast">
          {toast}
        </div>
      )}
      <div className="layout">
        <HighlightsProvider caseId={info.case_id}>
          <NavContext.Provider value={{ openEntity, openTable, showInEvents, openFinding }}>
            <RefreshBadgesContext.Provider value={refreshBadges}>
            <WriteBlockedContext.Provider value={writeBlockedReason(info.read_only_reason, settings.analyst)}>
            <main>
              {screen !== "highlights" && <HighlightsError />}
              {body}
              {screens.events && (
                <section hidden={screen !== "events"} aria-label="Events">
                  {screens.events(screenProps)}
                </section>
              )}
              {tabs.open.map((e) => (
                <section key={tabKey(e)} hidden={tabKey(e) !== activeKey} aria-label={`${e.kind} ${displaySafe(e.value)}`}>
                  {entityTab ? entityTab(e, screenProps) : <p>{`${e.kind} ${displaySafe(e.value)}`}</p>}
                </section>
              ))}
            </main>
            </WriteBlockedContext.Provider>
            </RefreshBadgesContext.Provider>
          </NavContext.Provider>
        </HighlightsProvider>
      </div>
    </div>
  );
}
