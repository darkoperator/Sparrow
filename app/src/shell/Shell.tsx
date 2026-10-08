// The window shell: case opening, the analyst name, the read-only banner and the sidebar. Screens are plugged in
// by name; a screen that is not built yet renders a placeholder.
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { caseClose, caseOpen, isCmdError, settingsGet, type CaseInfo, type Filter, type Settings } from "../api";
import Highlights from "../highlights/Highlights";
import { HighlightsError, HighlightsProvider } from "../highlights/useHighlights";
import Pivot, { type PivotRequest } from "../pivot/Pivot";
import Tables, { type TableRequest } from "../tables/Tables";
import ReviewQueue from "../review/ReviewQueue";
import { displaySafe } from "../text";
import type { PivotKind } from "../value";
import AnalystPrompt from "./AnalystPrompt";
import ExportMenu from "./ExportMenu";
import { NavContext } from "./nav";
import OpenCase, { type UpgradePrompt } from "./OpenCase";
import ReadOnlyBanner from "./ReadOnlyBanner";

export type ScreenId = "review" | "timeline" | "accounts" | "pivot" | "tables" | "sql" | "share" | "highlights";

const NAV: ReadonlyArray<{ id: ScreenId; label: string }> = [
  { id: "review", label: "Review queue" },
  { id: "timeline", label: "Timeline" },
  { id: "accounts", label: "Accounts" },
  { id: "pivot", label: "Pivot" },
  { id: "tables", label: "Tables" },
  { id: "sql", label: "SQL" },
  { id: "share", label: "Share" },
  { id: "highlights", label: "Highlights" },
];

export interface ScreenProps {
  canWrite: boolean;
  /** Show the review queue filtered to this account. */
  showAccount: (upn: string) => void;
  /** Show the review queue, unfiltered. */
  showQueue: () => void;
  /** Open the pivot screen on an IP or an account. */
  openPivot: (kind: PivotKind, value: string) => void;
  /** Open the table browser on a table, with these filters applied. */
  openTable: (table: string, filters: Filter[]) => void;
}

interface ShellProps {
  /** Screens built elsewhere, by id; anything missing renders a placeholder. */
  screens?: Partial<Record<Exclude<ScreenId, "review" | "pivot" | "tables" | "highlights">, (p: ScreenProps) => ReactNode>>;
}

export default function Shell({ screens = {} }: ShellProps) {
  const [settings, setSettings] = useState<Settings>({ analyst: null, recent: [] });
  const [info, setInfo] = useState<CaseInfo | null>(null);
  const [screen, setScreen] = useState<ScreenId>("review");
  // The review queue's account filter lives here: the accounts screen sets it, the queue shows it.
  const [accountFilter, setAccountFilter] = useState<string | null>(null);
  // The pivot request that opened the pivot screen; `nonce` remounts the screen for each new request.
  const [pivotReq, setPivotReq] = useState<(PivotRequest & { nonce: number }) | null>(null);
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

  const openCase = async (path: string, allowUpgrade = false) => {
    setError(null);
    setUpgrade(null);
    try {
      setInfo(await caseOpen(path, allowUpgrade));
      setScreen("review");
      setAccountFilter(null);
      setPivotReq(null);
      setTableReq(null);
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
    setPivotReq(null);
    setTableReq(null);
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
  const showAccount = (upn: string) => {
    setAccountFilter(upn);
    setScreen("review");
  };
  const showQueue = () => {
    setAccountFilter(null);
    setScreen("review");
  };
  const openPivot = (kind: PivotKind, value: string) => {
    setPivotReq((r) => ({ kind, value, nonce: (r?.nonce ?? 0) + 1 }));
    setScreen("pivot");
  };
  const openTable = (table: string, filters: Filter[]) => {
    setTableReq((r) => ({ table, filters, nonce: (r?.nonce ?? 0) + 1 }));
    setScreen("tables");
  };
  const body = (() => {
    if (screen === "review") {
      return (
        <ReviewQueue canWrite={canWrite} accountFilter={accountFilter} onClearFilter={() => setAccountFilter(null)} />
      );
    }
    if (screen === "tables") return <Tables key={tableReq?.nonce ?? 0} initial={tableReq ?? undefined} />;
    if (screen === "highlights") return <Highlights />;
    if (screen === "pivot") return <Pivot key={pivotReq?.nonce ?? 0} initial={pivotReq ?? undefined} />;
    const render = screens[screen];
    if (render) return render({ canWrite, showAccount, showQueue, openPivot, openTable });
    const label = NAV.find((n) => n.id === screen)?.label ?? screen;
    return <p>{label} is not built yet.</p>;
  })();

  return (
    <div className="shell">
      <header className="titlebar">
        <strong>Sparrow</strong> <span title={info.path}>{displaySafe(info.case_id)}</span>{" "}
        {settings.analyst && <span>Analyst: {displaySafe(settings.analyst)}</span>}{" "}
        <ExportMenu /> <button onClick={() => void closeCase()}>Close case</button>
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
      <div className="layout">
        <nav aria-label="Screens">
          {NAV.map((n) => (
            <button key={n.id} aria-current={n.id === screen ? "page" : undefined} onClick={() => setScreen(n.id)}>
              {n.label}
            </button>
          ))}
        </nav>
        <HighlightsProvider caseId={info.case_id}>
          <NavContext.Provider value={{ openPivot, openTable }}>
            <main>
              {screen !== "highlights" && <HighlightsError />}
              {body}
            </main>
          </NavContext.Provider>
        </HighlightsProvider>
      </div>
    </div>
  );
}
