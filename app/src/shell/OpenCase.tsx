import { open } from "../dialog";
import { displaySafe } from "../text";

export interface UpgradePrompt {
  path: string;
  message: string;
}

interface Props {
  recent: string[];
  error: string | null;
  upgrade: UpgradePrompt | null;
  onOpen: (path: string) => void;
  onConfirmUpgrade: () => void;
  onCancelUpgrade: () => void;
}

/** The screen with no case: pick a file, or one of the recent paths. */
export default function OpenCase({ recent, error, upgrade, onOpen, onConfirmUpgrade, onCancelUpgrade }: Props) {
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
      <h2>Open a case</h2>
      {error && <div role="alert">{displaySafe(error)}</div>}
      {upgrade ? (
        <div className="upgrade-confirm">
          <p>{displaySafe(upgrade.message)}</p>
          <p>{displaySafe(upgrade.path)}</p>
          <button onClick={onConfirmUpgrade}>Upgrade and open</button> <button onClick={onCancelUpgrade}>Cancel</button>
        </div>
      ) : (
        <>
          <button onClick={() => void pick()}>Open a case</button>
          {recent.length > 0 && (
            <>
              <h3>Recent</h3>
              <ul>
                {recent.map((p) => (
                  <li key={p}>
                    <button className="link" onClick={() => onOpen(p)}>
                      {displaySafe(p)}
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </>
      )}
    </section>
  );
}
