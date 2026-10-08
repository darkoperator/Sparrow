import { describe, expect, it } from "vitest";
import { accounts, caseInfo, findingDetail, queue } from "./fixtures";

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
  it("returns independent copies", () => {
    queue()[0].source = "proposal" as never;
    expect(queue()[0].source).toBe("decision");
  });
});
