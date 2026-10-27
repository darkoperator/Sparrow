import { describe, expect, it } from "vitest";
import { accounts, caseInfo, devices, devicesRecorded, findingDetail, queue, schema, sharePreview, sqlResult } from "./fixtures";

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
});
