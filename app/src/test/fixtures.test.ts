import { describe, expect, it } from "vitest";
import {
  accounts, caseInfo, devices, devicesRecorded, entityFindings, entityPivots, entitySummary, eventsDetail, eventsDetailFlagged,
  eventsHistogram, eventsList, eventsPage, eventsSuggest, eventsSummary, findingDetail, marksTags, queue, schema, sharePreview,
  sqlResult, timelineAdded,
} from "./fixtures";

describe("recorded fixtures", () => {
  it("load, validate and contain what the screen tests rely on", () => {
    expect(caseInfo().schema_version).toBeGreaterThanOrEqual(21);
    const q = queue();
    expect(q.filter((i) => i.source === "decision").length).toBeGreaterThanOrEqual(3);
    expect(q.filter((i) => i.source === "proposal").length).toBeGreaterThanOrEqual(2);
    expect(findingDetail().finding.finding_id).toBeTruthy();
  });
  it("loads the recorded account roll-up with addresses to show", () => {
    const page = accounts();
    expect(page.accounts.length).toBeGreaterThan(0);
    expect(page.accounts.some((a) => a.addresses.length > 0)).toBe(true);
  });
  it("loads the synthetic devices: one per status, with an untimed sighting and a low-confidence device", () => {
    const list = devices();
    expect(list.map((d) => d.lifecycle.status)).toEqual(["active_after_removal", "unknown", "not_in_latest_inventory", "removed"]);
    expect(list.some((d) => d.sightings.some((s) => s.event_time === null))).toBe(true);
    expect(list.some((d) => d.confidence === "low")).toBe(true);
  });
  it("validates the devices_list response recorded from the Rust case (nested shape, enums, nullable fields)", () => {
    const list = devicesRecorded();
    expect(list.length).toBeGreaterThan(0);
    for (const d of list) {
      expect(["high", "low"]).toContain(d.confidence);
      expect(d.sightings.length).toBeGreaterThan(0);
      expect(d.reasons.length).toBeGreaterThan(0);
    }
  });
  it("loads the SQL schema, a query result and a share preview", () => {
    const tables = schema();
    expect(tables.some((t) => t.kind === "view")).toBe(true);
    expect(tables.some((t) => t.columns.some((c) => c.comment !== null))).toBe(true);
    const r = sqlResult();
    expect(r.rows.length).toBeGreaterThan(0);
    expect(tables.some((t) => t.name === "signins")).toBe(true);
    const p = sharePreview();
    expect(p.summary.already_imported).toBe(false);
    expect(p.summary.new + p.summary.conflicts).toBeGreaterThan(0);
    expect(p.items).toBeGreaterThan(0);
    expect(p.analyst).toBe(p.summary.analyst);
  });
  it("returns independent copies", () => {
    queue()[0].source = "proposal" as never;
    expect(queue()[0].source).toBe("decision");
  });
  it("loads the recorded events: a list with every kind of mark, a page, the summary bar and the histogram", () => {
    const list = eventsList();
    expect(list.length).toBe(81);
    expect(new Set(list.map((r) => r.source)).size).toBe(9);
    expect(list.filter((r) => r.flag === "malicious").length).toBe(1);
    expect(list.filter((r) => r.flag === "suspicious" && !r.flag_ai).length).toBe(2);
    expect(list.filter((r) => r.flag_ai).length).toBe(1);
    expect(list.filter((r) => r.tags.some((t) => !t.ai)).map((r) => r.tags[0].name)).toEqual(["phish-lure", "phish-lure"]);
    expect(list.filter((r) => r.tags.some((t) => t.ai)).length).toBe(1);
    expect(list.filter((r) => r.note_count > 0).length).toBe(1);
    const times = list.map((r) => Date.parse(r.event_time!));
    expect(times).toEqual([...times].sort((a, b) => b - a));
    const page = eventsPage();
    expect([page.rows.length, page.offset, page.total_capped]).toEqual([25, 0, false]);
    expect(page.rows.every((r) => r.source === "signin_interactive")).toBe(true);
    const s = eventsSummary();
    expect(s.per_source.reduce((n, [, c]) => n + c, 0)).toBe(s.total);
    expect([s.malicious, s.suspicious, s.hidden_trace_events]).toEqual([1, 3, 0]);
    const h = eventsHistogram();
    expect(h.series.flatMap(([, c]) => c).reduce((a, b) => a + b, 0)).toBe(s.total);
    expect(h.bucket_seconds).toBe(86_400);
    expect(eventsSuggest().length).toBeGreaterThan(0);
  });
  it("loads event details, entity tiles and pivots for each kind, findings, tags and an add-to-timeline outcome", () => {
    expect(eventsDetail().notes.length).toBe(1);
    expect(eventsDetail().row.latest_note).toBe(eventsDetail().notes[0].text);
    expect(eventsDetailFlagged().flag).toBe("malicious");
    expect(eventsDetailFlagged().flag_sources.map((f) => f.origin)).toEqual(["row"]);
    for (const kind of ["account", "ip", "device", "session"] as const) {
      const t = entitySummary(kind);
      expect(Object.keys(t.entity).sort()).toEqual(["kind", "value"]);
      expect(t.entity.kind).toBe(kind);
      expect(t.entity.value).toBe(t.entity.value.trim());
      expect(t.events).toBeGreaterThan(0);
      expect(Object.keys(t.distinct).sort()).toEqual(["accounts", "asns", "countries", "devices", "ips", "sessions"]);
    }
    expect(entitySummary("account").roles_matched.length).toBeGreaterThan(0);
    expect(entitySummary("device").device).not.toBeNull();
    const p = entityPivots();
    expect(Object.keys(p).sort()).toEqual(["accounts", "device_changes", "devices", "ips", "sessions"]);
    expect(p.ips.total).toBeGreaterThan(p.ips.rows.length);
    expect(p.device_changes.rows.length).toBeGreaterThan(0);
    expect(entityFindings().every((f) => ["high", "medium", "low", "critical", "info"].includes(f.severity))).toBe(true);
    expect(marksTags().map((t) => [t.name, t.count, t.agent_unreviewed])).toEqual([["ai:relay", 1, 1], ["phish-lure", 2, 0]]);
    expect(timelineAdded().outcome).toBe("Added 1 grouped timeline entry covering 22 events");
  });
});
