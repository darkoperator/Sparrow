import { open } from "../dialog";
import { displaySafe } from "../text";
import Icon from "../ui/Icon";

export interface UpgradePrompt {
  path: string;
  message: string;
}

interface Props {
  recent: string[];
  error: string | null;
  upgrade: UpgradePrompt | null;
  onOpen: (path: string) => void;
  /** Make a new case from a collector output folder. */
  onNewFromFolder: () => void;
  onConfirmUpgrade: () => void;
  onCancelUpgrade: () => void;
}

/** The screen with no case: pick a file, or one of the recent paths. */
export default function OpenCase({ recent, error, upgrade, onOpen, onNewFromFolder, onConfirmUpgrade, onCancelUpgrade }: Props) {
  const pick = async () => {
    const chosen = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "Sparrow case", extensions: ["duckdb"] }],
    });
    if (typeof chosen === "string") onOpen(chosen);
  };

  return (
    <section className="open-case">
      <div className="open-card card">
        <h2>Open a case</h2>
        {error && <div role="alert">{displaySafe(error)}</div>}
        {upgrade ? (
          <div className="upgrade-confirm">
            <p>{displaySafe(upgrade.message)}</p>
            <p className="mono open-path">{displaySafe(upgrade.path)}</p>
            <div className="open-actions">
              <button className="btn btn-primary" onClick={onConfirmUpgrade}>Upgrade and open</button>
              <button className="btn btn-ghost" onClick={onCancelUpgrade}>Cancel</button>
            </div>
          </div>
        ) : (
          <>
            <div className="open-actions">
              <button className="btn btn-primary" onClick={() => void pick()}>
                <Icon name="plus" size={13} />
                Open a case
              </button>
              <button className="btn" onClick={onNewFromFolder}>
                <Icon name="download" size={13} />
                New case from a folder…
              </button>
            </div>
            {recent.length > 0 && (
              <>
                <h3 className="label">Recent</h3>
                <ul className="plain recent">
                  {recent.map((p) => (
                    <li key={p}>
                      <button className="link mono" title={displaySafe(p)} onClick={() => onOpen(p)}>
                        {displaySafe(p)}
                      </button>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </>
        )}
      </div>
    </section>
  );
}
