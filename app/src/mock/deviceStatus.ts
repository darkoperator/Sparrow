// DEV ONLY: the mock backend's analyst device status (`devices_set_analyst_status`), kept in memory: one live decision
// per device id, set or cleared by the analyst, shown by the Devices list and the device tab. All data is synthetic.
import type { AnalystDeviceStatus, AuditEntry, CmdErrorKind, DeviceDecision, EntitySummary, SuspectDevice } from "../api";
import * as fx from "../test/fixtures";

const STATUSES: AnalystDeviceStatus[] = ["removed", "disabled", "confirmed_attacker", "benign"];
// Seeded with the decisions of the synthetic device list, so the screens show them before any change.
const decisions = new Map<string, DeviceDecision>(
  fx.devices().flatMap((d) => (d.analyst ? [[d.analyst.device_id, d.analyst] as const] : [])),
);

interface Deps {
  fail: (kind: CmdErrorKind, message: string) => never;
  audit: (action: string, objectType: string, objectId: string, reason?: string | null) => AuditEntry;
  writable: () => void;
  analyst: () => string;
}

const takesOut = (d: DeviceDecision) => d.status === "removed" || d.status === "disabled";
const later = (seen: string | null | undefined, d: DeviceDecision) => !!seen && Date.parse(seen) > Date.parse(d.decided_at);

/** The live decision on `id` (any spelling), or null. */
export const decisionOf = (id: string | null | undefined): DeviceDecision | null => decisions.get((id ?? "").trim().toLowerCase()) ?? null;

/** A device of the list with its analyst status, as core attaches it (by device id, else object id). */
export function withDecision(d: SuspectDevice): SuspectDevice {
  const a = decisionOf(d.device_id) ?? decisionOf(d.object_id);
  return { ...d, analyst: a, active_after_analyst_removal: a !== null && takesOut(a) && later(d.lifecycle.last_active?.at, a) };
}

/** A device tab's summary with its analyst status; other kinds have none. */
export function summaryWithDecision(s: EntitySummary): EntitySummary {
  const a = s.entity.kind === "device" ? decisionOf(s.entity.value) : null;
  return { ...s, analyst_status: a, active_after_analyst_removal: a !== null && takesOut(a) && later(s.last_seen, a) };
}

export function deviceStatusHandlers(deps: Deps): Record<string, (a: Record<string, unknown> | undefined) => unknown> {
  return {
    devices_set_analyst_status: (a) => {
      deps.writable();
      const id = String(a?.deviceId ?? "").trim().toLowerCase();
      if (!id) deps.fail("invalid", "a device id must be non-empty text without control characters");
      const status = (a?.status ?? null) as AnalystDeviceStatus | null;
      const note = typeof a?.note === "string" && a.note.trim() !== "" ? a.note.trim() : null;
      const before = decisions.get(id) ?? null;
      if (status === null) {
        if (!before) deps.fail("decision", `device ${id} has no analyst status to clear`);
        decisions.delete(id);
        return deps.audit("clear_device_status", "device_status", id);
      }
      if (!STATUSES.includes(status)) deps.fail("invalid", `unknown device status "${status}"`);
      if (before && before.status === status && before.note === note) deps.fail("decision", `device ${id} is already ${status}`);
      decisions.set(id, { device_id: id, status, note, decided_by: `analyst:${deps.analyst()}`, decided_at: new Date().toISOString() });
      return deps.audit("set_device_status", "device_status", id);
    },
  };
}
