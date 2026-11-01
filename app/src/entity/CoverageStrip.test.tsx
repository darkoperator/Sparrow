import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { CoverageSource, CoverageState, EntityCoverage, TenantCoverage } from "../api";
import { entityCoverage } from "../test/fixtures";
import CoverageStrip, { CLOSING_LINE } from "./CoverageStrip";

const A = "admin@contoso.example";
const B = "frances.rourke@contoso.example";

function src(source: string, title: string, state: CoverageState, by: CoverageSource["accounts_by_state"] = {}): CoverageSource {
  return { source, title, state, accounts_by_state: by };
}
const allCovered = (key = "t1"): TenantCoverage => ({
  tenant_key: key,
  accounts: [A],
  sources: [src("ual", "Unified audit log", "covered", { covered: [A] }), src("message_trace", "Message trace", "covered")],
});
const cov = (...tenants: TenantCoverage[]): EntityCoverage => ({ from: "2026-08-01", to: "2026-09-09", tenants });

describe("CoverageStrip", () => {
  it("strip_hidden_when_all_covered", () => {
    const { container, rerender } = render(<CoverageStrip coverage={cov(allCovered("t1"), allCovered("t2"))} />);
    expect(container).toBeEmptyDOMElement();
    // Nothing known yet, and an entity with no events: also nothing.
    rerender(<CoverageStrip coverage={null} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<CoverageStrip coverage={{ from: null, to: null, tenants: [] }} />);
    expect(container).toBeEmptyDOMElement();
    // One source not covered anywhere shows it.
    rerender(<CoverageStrip coverage={cov({ ...allCovered(), sources: [src("mailbox_audit", "Mailbox audit log (legacy)", "absent", { absent: [A] })] })} />);
    expect(screen.getByRole("region", { name: "Coverage warning" })).toBeInTheDocument();
  });

  it("strip_warns_and_hover_lists_accounts", () => {
    render(<CoverageStrip coverage={entityCoverage()} />);
    const strip = screen.getByRole("region", { name: "Coverage warning" });
    expect(within(strip).getByText("Evidence coverage 2026-08-01 to 2026-09-09 (UTC days)")).toBeInTheDocument();
    // One chip per source that is not covered, in the order the backend gave; covered sources have none.
    const chips = within(strip).getAllByRole("listitem").map((li) => li.textContent);
    expect(chips).toEqual([
      "Unified audit log in this range is sampled (capped export) for 1 of 2 accounts",
      "MailItemsAccessed in this range has no data",
      "Mailbox audit log (legacy) in this range has no data",
    ]);
    // The closing line, once.
    expect(within(strip).getAllByText(CLOSING_LINE)).toHaveLength(1);
    expect(CLOSING_LINE).toBe("Absence of an action here is not proof it didn't happen.");
    // Hover: the accounts per state, and that days are UTC days.
    expect(screen.getByText("Unified audit log in this range is sampled (capped export) for 1 of 2 accounts")).toHaveAttribute(
      "title",
      `Sampled: ${B}\nCovered: ${A}\nDays are UTC days, 2026-08-01 to 2026-09-09, both included.`,
    );
    expect(screen.getByText("MailItemsAccessed in this range has no data")).toHaveAttribute(
      "title",
      `Absent: ${A}, ${B}\nDays are UTC days, 2026-08-01 to 2026-09-09, both included.`,
    );
  });

  it("a_source_missing_for_some_accounts_says_how_many", () => {
    const C = "zion.osborn@contoso.example";
    render(
      <CoverageStrip
        coverage={cov({
          tenant_key: "t1",
          accounts: [A, B, C],
          sources: [
            src("ual", "Unified audit log", "absent", { absent: [A], covered: [B, C] }),
            src("mailbox_audit", "Mailbox audit log (legacy)", "absent", { absent: [A, B, C] }),
          ],
        })}
      />,
    );
    const chips = screen.getAllByRole("listitem").map((li) => li.textContent);
    // Missing for one account of three is not "no data"; missing for all of them is.
    expect(chips).toEqual(["Unified audit log in this range has no data for 1 of 3 accounts", "Mailbox audit log (legacy) in this range has no data"]);
  });

  it("a_tenant_wide_source_says_so_and_lists_no_accounts", () => {
    render(<CoverageStrip coverage={cov({ tenant_key: "t1", accounts: [], sources: [src("message_trace", "Message trace", "absent"), src("entra_audit", "Entra audit log", "covered")] })} />);
    expect(screen.getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Message trace in this range has no data"]);
    expect(screen.getByText("Message trace in this range has no data")).toHaveAttribute(
      "title",
      "Judged for the whole tenant: absent.\nDays are UTC days, 2026-08-01 to 2026-09-09, both included.",
    );
    expect(screen.getAllByText(CLOSING_LINE)).toHaveLength(1);
  });

  it("several_tenants_get_a_section_each_and_covered_ones_none", () => {
    const sampled = (key: string): TenantCoverage => ({ tenant_key: key, accounts: [A], sources: [src("ual", "Unified audit log", "sampled", { sampled: [A] })] });
    render(<CoverageStrip coverage={cov(sampled("tenant-one"), allCovered("tenant-two"), sampled("tenant-three"))} />);
    const groups = screen.getAllByRole("group");
    expect(groups.map((g) => g.getAttribute("aria-label"))).toEqual(["Coverage of tenant tenant-one", "Coverage of tenant tenant-three"]);
    for (const g of groups) expect(within(g).getAllByRole("listitem")).toHaveLength(1);
    expect(screen.getAllByText(CLOSING_LINE)).toHaveLength(1);
    expect(screen.queryByText(/tenant-two/)).not.toBeInTheDocument();
  });

  it("hostile_values_render_as_text", () => {
    const evil = "<img src=x onerror=alert(1)>@contoso.example";
    const { container } = render(
      <CoverageStrip coverage={cov({ tenant_key: "t1", accounts: [evil], sources: [src("ual", "<b>UAL</b>", "sampled", { sampled: [evil] })] })} />,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(screen.getByText("<b>UAL</b> in this range is sampled (capped export)")).toHaveAttribute("title", expect.stringContaining(evil));
  });
});
