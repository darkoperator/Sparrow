import { render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import TabStrip from "./TabStrip";
import { initialTabs, openAccess, openEntity, showTab } from "./tabs";

const badges = { review: 0, timeline: 0 };
const original = Element.prototype.scrollIntoView;

afterEach(() => {
  Element.prototype.scrollIntoView = original;
});

describe("TabStrip", () => {
  it("brings_the_active_tab_into_view", () => {
    // jsdom has no scrollIntoView: the strip scrolls sideways when many tabs are open.
    const seen: string[] = [];
    Element.prototype.scrollIntoView = function (this: Element) {
      seen.push(this.getAttribute("aria-label") ?? this.textContent ?? "");
    };
    let s = initialTabs();
    for (let n = 0; n < 8; n++) s = openEntity(s, { kind: "account", value: `u${n}@contoso.example` }).state;
    const view = render(<TabStrip state={s} badges={badges} onShow={() => {}} onClose={() => {}} />);
    expect(seen.at(-1)).toBe("account u7@contoso.example");
    s = openAccess(showTab(s, { kind: "account", value: "u0@contoso.example" }), { access: "case", value: "" }).state;
    view.rerender(<TabStrip state={s} badges={badges} onShow={() => {}} onClose={() => {}} />);
    expect(seen.at(-1)).toBe("Access whole case");
    const n = seen.length;
    // Same tab, another render (a badge changed): no scrolling.
    view.rerender(<TabStrip state={s} badges={{ review: 3, timeline: 0 }} onShow={() => {}} onClose={() => {}} />);
    expect(seen).toHaveLength(n);
  });
});
