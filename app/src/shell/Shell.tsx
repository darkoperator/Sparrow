// The window shell: case opening, the analyst name, the read-only banner and the sidebar. Screens are plugged in
// by name; a screen that is not built yet renders a placeholder.
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { caseClose, caseOpen, isCmdError, settingsGet, type CaseInfo, type Settings } from "../api";
import ReviewQueue from "../review/ReviewQueue";
import { displaySafe } from "../text";
import AnalystPrompt from "./AnalystPrompt";
import ExportMenu from "./ExportMenu";
import OpenCase, { type UpgradePrompt } from "./OpenCase";
import ReadOnlyBanner from "./ReadOnlyBanner";

export type ScreenId = "review" | "timeline" | "accounts" | "sql" | "share";

const NAV: ReadonlyArray<{ id: ScreenId; label: string }> = [
  { id: "review", label: "Review queue" },
  { id: "timeline", label: "Timeline" },
  { id: "accounts", label: "Accounts" },
  { id: "sql", label: "SQL" },
  { id: "share", label: "Share" },
];

export interface ScreenProps {
  canWrite: boolean;
  /** Show the review queue filtered to this account. */
  showAccount: (upn: string) => void;
  /** Show the review queue, unfiltered. */
  showQueue: () => void;
}

interface ShellProps {
  /** Screens built elsewhere, by id; anything missing renders a placeholder. */
  screens?: Partial<Record<Exclude<ScreenId, "review">, (p: ScreenProps) => ReactNode>>;
}

export default function Shell({ screens = {} }: ShellProps) {
  const [settings, setSettings] = useState<Settings>({ analyst: null, recent: [] });
  const [info, setInfo] = useState<CaseInfo | null>(null);
  const [screen, setScreen] = useState<ScreenId>("review");
  // The review queue's account filter lives here: the accounts screen sets it, the queue shows it.
  const [accountFilter, setAccountFilter] = useState<string | null>(null);
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
  const body = (() => {
    if (screen === "review") {
      return (
        <ReviewQueue canWrite={canWrite} accountFilter={accountFilter} onClearFilter={() => setAccountFilter(null)} />
      );
    }
    const render = screens[screen];
    if (render) return render({ canWrite, showAccount, showQueue });
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
        <main>{body}</main>
      </div>
    </div>
  );
}
