import { useEffect, useState } from "react";
import {
  devicesList,
  evidenceFilter,
  isCmdError,
  type AnalystDeviceStatus,
  type DeviceStatus,
  type LifecycleMark,
  type SuspectDevice,
} from "../api";
import CellMenu, { type MenuItem } from "../grid/CellMenu";
import { useNav, useWriteBlocked } from "../shell/nav";
import { displaySafe } from "../text";
import Icon from "../ui/Icon";
import { AnalystPill, AnalystStatusDialog, analystStatusItem, clearAnalystStatus } from "./analystStatus";
import "../marks/marks.css";
import "./devices.css";

const STATUS_LABELS: Record<DeviceStatus, string> = {
  active_after_removal: "Active after removal",
  active: "Active",
  unknown: "Unknown",
  not_in_latest_inventory: "Not in latest inventory",
  disabled: "Disabled",
  removed: "Removed",
};

/** What to do about a device in this status (the same words as the exports). */
const NOTES: Partial<Record<DeviceStatus, string>> = {
  unknown: "treat as active — collect Get-Devices to confirm",
  not_in_latest_inventory: "treat as active — collect Get-Devices to confirm",
  active_after_removal: "seen after removal — containment did not hold",
};

/** The status pill's colour: red when containment failed, amber while the device may still be active, green once it
 *  is removed or disabled. The status is always written in the pill. */
const STATUS_TONE: Record<DeviceStatus, string> = {
  active_after_removal: "pill-mal",
  active: "pill-sus",
  unknown: "pill-sus",
  not_in_latest_inventory: "pill-sus",
  disabled: "pill-ok",
  removed: "pill-ok",
};

const keyOf = (d: SuspectDevice) => `${d.tenant_key ?? ""}/${d.device_id}`;

function markText(label: string, m: LifecycleMark | null): string | null {
  return m ? `${label} ${m.at} (${m.source_table}:${m.record_key})` : null;
}

/** One sighting's evidence reference, opening the record in the table browser. */
function EvidenceLink({ table, recordKey }: { table: string; recordKey: string }) {
  const nav = useNav();
  const [error, setError] = useState<string | null>(null);
  const text = `${table}:${recordKey}`;
  if (!nav) return <code className="dev-evidence">{displaySafe(text)}</code>;
  return (
    <>
      <button
        className="link dev-evidence"
        onClick={() => {
          setError(null);
          evidenceFilter(table, recordKey).then(
            (t) => nav.openTable(t.table, t.filters),
            (e: unknown) => setError(isCmdError(e) ? e.message : String(e)),
          );
        }}
      >
        {displaySafe(text)}
      </button>
      {error && <span role="alert"> {displaySafe(error)}</span>}
    </>
  );
}

function Detail({ device }: { device: SuspectDevice }) {
  const nav = useNav();
  const lc = device.lifecycle;
  const marks = [
    markText("registered", lc.registered),
    markText("removed", lc.removed),
    markText("disabled", lc.disabled),
    markText("last active", lc.last_active),
  ].filter((m): m is string => m !== null);
  return (
    <section className="card dev-detail" aria-label={`Sightings of ${device.device_id}`}>
      <h3>{displaySafe(device.display_name ?? device.device_id)}</h3>
      {device.analyst && (
        <p className="meta dev-analyst-line">
          Analyst: <AnalystPill decision={device.analyst} activeAfter={device.active_after_analyst_removal} />
          {device.analyst.note && <span className="dev-analyst-note"> {displaySafe(device.analyst.note)}</span>}
        </p>
      )}
      {marks.length > 0 && (
        <ul className="plain dev-lifecycle" aria-label="Lifecycle">
          {marks.map((m) => (
            <li key={m}>{displaySafe(m)}</li>
          ))}
        </ul>
      )}
      {device.other_ips.length > 0 && (
        <p className="meta dev-other">
          Other addresses to check:{" "}
          {device.other_ips.map((o, i) => (
            <span key={o.ip}>
              {i > 0 && "; "}
              <span className="mono">{displaySafe(o.asn_org ? `${o.ip} (${o.asn_org})` : o.ip)}</span>
              {nav && (
                <>
                  {" "}
                  <button className="link" aria-label={`Open IP tab ${displaySafe(o.ip)}`} onClick={() => nav.openEntity({ kind: "ip", value: o.ip })}>
                    Open tab
                  </button>
                </>
              )}
            </span>
          ))}
        </p>
      )}
      <div className="label dev-section">Sightings</div>
      <ol className="plain dev-sightings" aria-label="Sightings">
        {device.sightings.map((s) => {
          const malicious = s.ip !== null && device.malicious_ips.some((m) => m.toLowerCase() === s.ip!.toLowerCase());
          return (
            <li key={`${s.source_table}:${s.record_key}`}>
              <span className="mono dev-time">{s.event_time ? displaySafe(s.event_time) : "no time"}</span>{" "}
              {s.user_upn && <span>{displaySafe(s.user_upn)}</span>}{" "}
              {s.ip && <span className={malicious ? "mono dev-mal-ip" : "mono"}>{displaySafe(s.ip)}</span>}
              {malicious && <strong className="malicious pill pill-mal"> malicious</strong>}{" "}
              <span className="dev-activity">{displaySafe(s.activity)}</span>{" "}
              <EvidenceLink table={s.source_table} recordKey={s.record_key} />
            </li>
          );
        })}
      </ol>
    </section>
  );
}

/**
 * The devices to contain: every device seen on a malicious IP, with its lifecycle. The list keeps the backend's order
 * (status, confidence, last active). Selecting a device shows every sighting, each opening its evidence row.
 */
export default function Devices() {
  const writeBlocked = useWriteBlocked();
  const [list, setList] = useState<SuspectDevice[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // A row's menu (right-click, the menu key or Shift+F10), and the status dialog it opens.
  const [menu, setMenu] = useState<{ x: number; y: number; items: MenuItem[]; opener: HTMLElement } | null>(null);
  const [setting, setSetting] = useState<{ device: SuspectDevice; status: AnalystDeviceStatus } | null>(null);
  // Bumped after the analyst changes a status: the list is read again.
  const [reloadN, setReloadN] = useState(0);
  // Per viewer, in component state only: low-confidence devices (reached only through impossible-travel legs) are hidden
  // until asked for.
  const [showLow, setShowLow] = useState(false);

  useEffect(() => {
    let live = true;
    devicesList().then(
      (l) => live && setList(l),
      (e: unknown) => live && setError(isCmdError(e) ? e.message : String(e)),
    );
    return () => {
      live = false;
    };
  }, [reloadN]);

  const done = (message: string) => {
    setSetting(null);
    setNotice(message);
    setReloadN((n) => n + 1);
  };
  const itemsFor = (d: SuspectDevice): MenuItem[] => [
    analystStatusItem(
      d.analyst,
      writeBlocked,
      (status) => setSetting({ device: d, status }),
      () =>
        clearAnalystStatus(d.device_id).then(done, (e: unknown) => setError(isCmdError(e) ? e.message : String(e))),
    ),
  ];

  const lowCount = list?.filter((d) => d.confidence === "low").length ?? 0;
  const shown = list?.filter((d) => showLow || d.confidence !== "low") ?? [];
  const current = shown.find((d) => keyOf(d) === selected) ?? null;

  return (
    <section className="devices">
      <header className="dev-head">
        <div>
          <h2>Devices</h2>
          <p className="dev-sub">Every device seen on a malicious IP, with its lifecycle. Select one to see its sightings.</p>
        </div>
        {list && lowCount > 0 && (
          <p className="dev-toggle">
            <button className={showLow ? "dev-filter dev-filter-on" : "dev-filter"} onClick={() => setShowLow((v) => !v)}>
              {showLow ? "Hide" : "Show"} {lowCount} low-confidence devices
            </button>
          </p>
        )}
      </header>
      {error && <div role="alert">{displaySafe(error)}</div>}
      {notice && (
        <p role="status" className="dev-notice">
          {notice}
        </p>
      )}
      {list && list.length === 0 && (
        <p className="dev-empty">No device was seen on a malicious IP. Mark IPs malicious with an indicator, or run detection.</p>
      )}
      {list && list.length > 0 && lowCount === list.length && !showLow && (
        <p className="dev-empty">No high-confidence device was seen on a malicious IP.</p>
      )}
      {shown.length > 0 && (
        <div className="table-scroll card dev-card">
          <table className="dev-table" aria-label="Devices to contain">
            <thead>
              <tr>
                <th>Status</th>
                <th title="What you recorded about the device (right-click a row to set it); Status is what the logs show">Analyst</th>
                <th>Device</th>
                <th>Last active</th>
                <th>Users</th>
                <th>Malicious IPs</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((d) => {
                const status = d.lifecycle.status;
                const note = NOTES[status];
                return (
                  <tr
                    key={keyOf(d)}
                    aria-selected={keyOf(d) === selected}
                    className={status === "active_after_removal" || d.active_after_analyst_removal ? "dev-row dev-row-alert" : "dev-row"}
                    onContextMenu={(e) => {
                      e.preventDefault();
                      setMenu({ x: e.clientX, y: e.clientY, items: itemsFor(d), opener: e.currentTarget });
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey)) {
                        e.preventDefault();
                        const b = e.currentTarget.getBoundingClientRect();
                        setMenu({ x: b.left + 24, y: b.bottom, items: itemsFor(d), opener: e.target as HTMLElement });
                      }
                    }}
                  >
                    <td>
                      <span
                        data-testid="status"
                        data-status={status}
                        className={`pill ${STATUS_TONE[status]} ${status === "active_after_removal" ? "status status-alert" : "status"}`}
                      >
                        {status === "active_after_removal" && (
                          <>
                            <span aria-hidden="true">⚠ </span>
                            <span className="sr-only">Warning: </span>
                          </>
                        )}
                        {STATUS_LABELS[status]}
                      </span>
                      {note && <div className="meta dev-note">{note}</div>}
                    </td>
                    <td className="dev-analyst">
                      <AnalystPill decision={d.analyst} activeAfter={d.active_after_analyst_removal} />
                    </td>
                    <td>
                      <div className="dev-device">
                        <span className="dev-icon" aria-hidden="true">
                          <Icon name="monitor" size={14} />
                        </span>
                        <div className="dev-who">
                          <button
                            className="link dev-name"
                            title={displaySafe(`${d.display_name ?? "(unnamed)"} ${d.device_id}`)}
                            onClick={() => setSelected(keyOf(d))}
                          >
                            <span>{displaySafe(d.display_name ?? "(unnamed)")}</span>{" "}
                            <span className="mono dev-id">{displaySafe(d.device_id)}</span>
                          </button>
                          {d.confidence === "low" && (
                            <div className="meta">low confidence — impossible-travel leg only</div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="mono dev-time">{d.lifecycle.last_active ? displaySafe(d.lifecycle.last_active.at) : ""}</td>
                    <td className="dev-users" title={displaySafe(d.users.join("; "))}>
                      {displaySafe(d.users.join("; "))}
                    </td>
                    <td className="mono dev-mal-ip" title={displaySafe(d.malicious_ips.join("; "))}>
                      {displaySafe(d.malicious_ips.join("; "))}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {current && <Detail device={current} />}
      {menu && (
        <CellMenu
          x={menu.x}
          y={menu.y}
          items={menu.items}
          onClose={() => {
            menu.opener.focus();
            setMenu(null);
          }}
        />
      )}
      {setting && (
        <AnalystStatusDialog
          deviceId={setting.device.device_id}
          status={setting.status}
          current={setting.device.analyst}
          onDone={done}
          onClose={() => setSetting(null)}
        />
      )}
    </section>
  );
}
