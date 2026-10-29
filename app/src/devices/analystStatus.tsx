// The analyst's status of a device (Removed, Disabled, Confirmed attacker, Benign): the right-click menu item that sets
// it, the dialog that takes the optional note, and the pill that shows it next to the status Sparrow computes. The
// analyst's status never replaces the computed one; both are always shown.
import { useState } from "react";
import { devicesSetAnalystStatus, isCmdError, type AnalystDeviceStatus, type DeviceDecision } from "../api";
import type { MenuItem } from "../grid/CellMenu";
import { displaySafe } from "../text";
import "./analyst.css";

export const ANALYST_LABELS: Record<AnalystDeviceStatus, string> = {
  removed: "Removed",
  disabled: "Disabled",
  confirmed_attacker: "Confirmed attacker",
  benign: "Benign",
};

const ORDER: AnalystDeviceStatus[] = ["removed", "disabled", "confirmed_attacker", "benign"];

/** Green once the device is out of the attacker's hands, red for a confirmed attacker device, neutral for benign. */
const TONE: Record<AnalystDeviceStatus, string> = {
  removed: "pill-ok",
  disabled: "pill-ok",
  confirmed_attacker: "pill-mal",
  benign: "",
};

/** The warning on a device the analyst said was removed or disabled and that was seen after that. */
export const ACTIVE_AFTER_TEXT = "active after your removal";

/**
 * `Set analyst status` and its five choices. A status opens the note dialog (`choose`); Clear clears at once. Disabled,
 * with the reason as its title, when writes are off; Clear is disabled when the device has no status.
 */
export function analystStatusItem(
  current: DeviceDecision | null,
  readOnly: string | null,
  choose: (status: AnalystDeviceStatus) => void,
  clear: () => void,
): MenuItem {
  const items: MenuItem[] = ORDER.map((s) => ({
    label: current?.status === s ? `${ANALYST_LABELS[s]} (current)…` : `${ANALYST_LABELS[s]}…`,
    run: () => choose(s),
  }));
  items.push(current ? { label: "Clear", run: clear } : { label: "Clear", disabled: "This device has no analyst status" });
  const item: MenuItem = { label: "Set analyst status", items };
  return readOnly !== null ? { ...item, disabled: readOnly } : item;
}

/** The hover of an analyst pill: who decided, when, and the note. */
export function analystTitle(d: DeviceDecision): string {
  return `Analyst status: ${ANALYST_LABELS[d.status]}, set by ${d.decided_by} at ${d.decided_at}${d.note ? ` · Note: ${d.note}` : ""}`;
}

/** The analyst's status as a pill (the note on hover), with the warning when the device was active after the removal. */
export function AnalystPill({ decision, activeAfter }: { decision: DeviceDecision | null; activeAfter: boolean }) {
  if (!decision) return <span className="meta analyst-none">—</span>;
  return (
    <span className="analyst">
      <span
        data-testid="analyst-status"
        data-status={decision.status}
        className={`pill ${TONE[decision.status]} analyst-pill`}
        title={displaySafe(analystTitle(decision))}
      >
        {ANALYST_LABELS[decision.status]}
        {decision.note && <span className="sr-only">, note: {displaySafe(decision.note)}</span>}
      </span>
      {activeAfter && (
        <span className="pill pill-mal analyst-warn" data-testid="analyst-warning" title="A sighting is later than your removal: containment did not hold">
          <span aria-hidden="true">⚠ </span>
          <span className="sr-only">Warning: </span>
          {ACTIVE_AFTER_TEXT}
        </span>
      )}
    </span>
  );
}

/** The dialog of one status: an optional note, then Save. The current note is kept when the status stays the same. */
export function AnalystStatusDialog({
  deviceId,
  status,
  current,
  onDone,
  onClose,
}: {
  deviceId: string;
  status: AnalystDeviceStatus;
  current: DeviceDecision | null;
  /** Saved; the text is for the confirmation. */
  onDone: (message: string) => void;
  onClose: () => void;
}) {
  const [note, setNote] = useState(current?.status === status ? (current.note ?? "") : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await devicesSetAnalystStatus(deviceId, status, note.trim() === "" ? null : note.trim());
      onDone(`Device ${displaySafe(deviceId)}: analyst status ${ANALYST_LABELS[status]}`);
    } catch (e) {
      setError(isCmdError(e) ? e.message : String(e));
      setBusy(false);
    }
  };
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Set analyst status"
      className="mark-dialog"
      onKeyDown={(e) => {
        if (e.key === "Escape") onClose();
      }}
    >
      <h4 className="mark-title">
        Set device <span className="mono">{displaySafe(deviceId)}</span> to {ANALYST_LABELS[status]}
      </h4>
      <p>Recorded next to the status Sparrow computes from the logs, never instead of it, and audited.</p>
      <label className="mark-field">
        Note (optional)
        <textarea autoFocus value={note} onChange={(e) => setNote(e.target.value)} />
      </label>
      {error && <p role="alert">{displaySafe(error)}</p>}
      <div className="mark-buttons">
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
        <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void submit()}>
          Save
        </button>
      </div>
    </div>
  );
}

/** Clear the analyst status of a device; resolves to the confirmation text. */
export async function clearAnalystStatus(deviceId: string): Promise<string> {
  await devicesSetAnalystStatus(deviceId, null, null);
  return `Device ${displaySafe(deviceId)}: analyst status cleared`;
}
