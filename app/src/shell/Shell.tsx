// The window shell: case opening, the analyst name, the read-only banner and the tab strip. Screens are plugged in
// by name; a screen that is not built yet renders a placeholder. Entity tabs stay mounted while hidden, so each
// keeps its filters, range and page.
import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  caseClose,
  caseOpen,
  ingestProfile,
  ingestUnprofiled,
  isCmdError,
  onAgentActivity,
  onCaseChanged,
  reviewQueue,
  settingsGet,
  timelineList,
  type AgentActivity,
  type CaseInfo,
  type Filter,
  type Settings,
} from "../api";
import Highlights from "../highlights/Highlights";
import { HighlightsError, HighlightsProvider } from "../highlights/useHighlights";
import Tables, { type TableRequest } from "../tables/Tables";
import ReviewQueue from "../review/ReviewQueue";
import { displaySafe } from "../text";
import Icon, { BrandMark } from "../ui/Icon";
import AgentChip from "./AgentChip";
import AnalystPrompt from "./AnalystPrompt";
import ExportMenu from "./ExportMenu";
import {
  DataVersionContext,
  FocusAnalystContext,
  NavContext,
  RefreshBadgesContext,
  WriteBlockedContext,
  writeBlockedReason,
} from "./nav";
import ImportDialog, { type ImportMode } from "./ImportDialog";
import OpenCase, { type UpgradePrompt } from "./OpenCase";
import ReadOnlyBanner from "./ReadOnlyBanner";
import "./shell.css";
import TabStrip, { type TabBadges } from "./TabStrip";
import {
  closeTab,
  FIXED_TABS,
  initialTabs,
  isAccessRef,
  loadTabs,
  openAccess as openAccessTab,
  openEntity as openEntityTab,
  saveTabs,
  showTab,
  tabKey,
  tabName,
  type AccessRef,
  type EntityRef,
  type FixedTab,
  type OpenTab,
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
  /** The body of an Access tab; until it is built, a placeholder names it. */
  accessTab?: (a: AccessRef) => ReactNode;
}

const TOAST_MS = 6000;

/** The `inert` attribute (React 18's types do not know it): the subtree takes no focus and no clicks. */
const inertWhen = (on: boolean): Record<string, string> => (on ? { inert: "" } : {});

/** Up to two capitals for the analyst chip: the first letters of the first two words, or the first two letters. */
function initials(name: string): string {
  const words = displaySafe(name).split(/[\s._-]+/).filter(Boolean);
  const letters = words.length > 1 ? words[0][0] + words[1][0] : (words[0] ?? "?").slice(0, 2);
  return letters.toUpperCase();
}

export default function Shell({ screens = {}, entityTab, accessTab }: ShellProps) {
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
  // The import dialog, when open; `dataEpoch` remounts the screens after an import so each one loads the new data.
  const [importMode, setImportMode] = useState<ImportMode | null>(null);
  const [dataEpoch, setDataEpoch] = useState(0);
  // Collections an import loaded but never profiled (it was killed): the banner offers to run the profile.
  const [unprofiled, setUnprofiled] = useState(0);
  const [profiling, setProfiling] = useState(false);
  // The agent bridge: a write bumps `dataVersion` (screens read their data again, keeping their state); the chip
  // shows the last request.
  const [dataVersion, setDataVersion] = useState(0);
  const [agentOf, setAgentOf] = useState<{ caseId: string; activity: AgentActivity } | null>(null);

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

  const agent = agentOf !== null && agentOf.caseId === caseId ? agentOf.activity : null;
  useEffect(() => {
    if (caseId === undefined) return;
    let live = true;
    const offs: Promise<() => void>[] = [
      onCaseChanged(() => {
        if (!live) return;
        setDataVersion((n) => n + 1);
        refreshBadges();
      }),
      onAgentActivity((activity) => live && setAgentOf({ caseId, activity })),
    ];
    return () => {
      live = false;
      for (const off of offs) void off.then((f) => f(), () => {});
    };
  }, [caseId, refreshBadges]);

  const readOnly = info?.read_only_reason !== null && info !== null;
  useEffect(() => {
    if (caseId === undefined || readOnly) return;
    let live = true;
    ingestUnprofiled().then(
      (ids) => live && setUnprofiled(ids.length),
      () => live && setUnprofiled(0),
    );
    return () => {
      live = false;
    };
  }, [caseId, readOnly, dataEpoch]);

  const profileNow = async () => {
    setProfiling(true);
    try {
      const id = typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `profile-${Date.now()}`;
      const r = await ingestProfile(id);
      setToast(r.profile_error !== null ? `The profile step failed: ${r.profile_error}` : "Profile finished");
      setDataEpoch((n) => n + 1);
      refreshBadges();
    } catch (e) {
      setError(isCmdError(e) ? e.message : String(e));
    } finally {
      setProfiling(false);
    }
  };

  const openCase = async (path: string, allowUpgrade = false) => {
    setError(null);
    setUpgrade(null);
    try {
      const opened = await caseOpen(path, allowUpgrade);
      setTabs(loadTabs(opened.case_id));
      setInfo(opened);
      // A new bridge session: no request of the previous one shows.
      setAgentOf(null);
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
    setAgentOf(null);
    setTabs(initialTabs());
    setEventsEntity(null);
    setFindingReq(null);
    setTableReq(null);
    setToast(null);
  };

  const closeImport = async (changed: boolean) => {
    const mode = importMode;
    setImportMode(null);
    // Into the open case: read it again (tenants, tabs) and remount every screen.
    if (changed && mode === "open" && info) {
      await openCase(info.path);
      setDataEpoch((n) => n + 1);
      refreshBadges();
    }
  };

  if (!info) {
    return (
      <>
      <div {...inertWhen(importMode !== null)}>
      <OpenCase
        recent={settings.recent}
        error={error}
        upgrade={upgrade}
        onOpen={(p) => void openCase(p)}
        onNewFromFolder={() => setImportMode("new")}
        onConfirmUpgrade={() => upgrade && void openCase(upgrade.path, true)}
        onCancelUpgrade={() => {
          setUpgrade(null);
          setError(null);
        }}
      />
      </div>
      {importMode === "new" && (
        <ImportDialog
          mode="new"
          onClose={() => setImportMode(null)}
          onOpenCase={(p) => {
            setImportMode(null);
            void openCase(p);
          }}
        />
      )}
      </>
    );
  }

  const canWrite = info.read_only_reason === null && settings.analyst !== null;
  // A menu item blocked by the missing analyst name sends the analyst to the prompt.
  const focusAnalyst =
    info.read_only_reason === null && settings.analyst === null
      ? () => {
          const input = document.querySelector<HTMLInputElement>(".analyst-prompt input");
          if (!input) return;
          input.focus();
          input.classList.add("analyst-flash");
          window.setTimeout(() => input.classList.remove("analyst-flash"), 1500);
        }
      : null;
  // Importing needs a writable case; it does not need an analyst name (`sparrow ingest` has none).
  const importBlocked = info.read_only_reason !== null ? `Read-only case: ${info.read_only_reason}` : null;
  const show = (t: FixedTab | OpenTab) => setTabs(showTab(tabs, t));
  const showAccount = (upn: string) => {
    setAccountFilter(upn);
    show("review");
  };
  const showQueue = () => {
    setAccountFilter(null);
    show("review");
  };
  // An entity tab by its value (as before Access tabs existed), an Access tab by its name.
  const evicted = (t: OpenTab) => `Closed ${displaySafe(isAccessRef(t) ? tabName(t) : t.value)} (10 tabs max)`;
  const openEntity = (e: EntityRef) => {
    const { state, closed } = openEntityTab(tabs, e);
    setTabs(state);
    if (closed) setToast(evicted(closed));
  };
  const openAccess = (a: AccessRef) => {
    const { state, closed } = openAccessTab(tabs, a);
    setTabs(state);
    if (closed) setToast(evicted(closed));
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
  const screen = typeof tabs.active === "string" ? tabs.active : null;
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
      <div className="shell-body" {...inertWhen(importMode !== null || profiling)}>
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
        <AgentChip activity={agent} />
        {settings.analyst && (
          <span className="analyst-chip" title={displaySafe(settings.analyst)}>
            <span className="analyst-initials" aria-hidden="true">
              {initials(settings.analyst)}
            </span>
            <span className="analyst-name">{displaySafe(settings.analyst)}</span>
            <span className="analyst-role"> · analyst</span>
          </span>
        )}
        <button
          className="btn btn-ghost"
          disabled={importBlocked !== null}
          title={importBlocked ?? "Add a collector output folder to this case"}
          onClick={() => setImportMode("open")}
        >
          <Icon name="download" size={13} />
          Import data…
        </button>
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
      {unprofiled > 0 && !readOnly && (
        <div role="status" className="warnings profile-banner">
          Some imported data was not profiled ({unprofiled === 1 ? "1 collection" : `${unprofiled} collections`}), so
          derived views may be incomplete.{" "}
          <button className="btn" disabled={profiling} onClick={() => void profileNow()}>
            {profiling ? "Profiling…" : "Run profile now"}
          </button>
        </div>
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
          <NavContext.Provider value={{ openEntity, openAccess, openTable, showInEvents, openFinding }}>
            <RefreshBadgesContext.Provider value={refreshBadges}>
            <WriteBlockedContext.Provider value={writeBlockedReason(info.read_only_reason, settings.analyst)}>
            <FocusAnalystContext.Provider value={focusAnalyst}>
            <DataVersionContext.Provider value={dataVersion}>
            <main key={dataEpoch}>
              {screen !== "highlights" && <HighlightsError />}
              {body}
              {screens.events && (
                <section hidden={screen !== "events"} aria-label="Events">
                  {screens.events(screenProps)}
                </section>
              )}
              {tabs.open.map((e) => (
                <section key={tabKey(e)} hidden={tabKey(e) !== activeKey} aria-label={isAccessRef(e) ? displaySafe(tabName(e)) : `${e.kind} ${displaySafe(e.value)}`}>
                  {isAccessRef(e)
                    ? accessTab
                      ? accessTab(e)
                      : <p>{displaySafe(tabName(e))}</p>
                    : entityTab
                      ? entityTab(e, screenProps)
                      : <p>{`${e.kind} ${displaySafe(e.value)}`}</p>}
                </section>
              ))}
            </main>
            </DataVersionContext.Provider>
            </FocusAnalystContext.Provider>
            </WriteBlockedContext.Provider>
            </RefreshBadgesContext.Provider>
          </NavContext.Provider>
        </HighlightsProvider>
      </div>
      </div>
      {importMode === "open" && <ImportDialog mode="open" onClose={(changed) => void closeImport(changed)} />}
    </div>
  );
}
