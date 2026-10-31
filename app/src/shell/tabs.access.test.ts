// Access tabs in the tab model: their own keys beside entity tabs, one shared limit, and per-case persistence.
import { afterEach, describe, expect, it, vi } from "vitest";
import { closeTab, initialTabs, isAccessRef, loadTabs, MAX_ENTITY_TABS, openAccess, openEntity, saveTabs, showTab, tabKey, type AccessRef, type TabsState } from "./tabs";

const keys = (s: TabsState) => s.open.map(tabKey);
const CASE: AccessRef = { access: "case", value: "" };

function fakeStorage() {
  const data = new Map<string, string>();
  return {
    data,
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    removeItem: (k: string) => void data.delete(k),
  };
}

afterEach(() => vi.unstubAllGlobals());

describe("access tabs", () => {
  it("opens_an_access_tab_and_reuses_it", () => {
    let s = openAccess(initialTabs(), { access: "ip", value: "[203.0.113.7]:443" }).state;
    s = openAccess(s, { access: "ip", value: "203.0.113.7" }).state;
    expect(keys(s)).toEqual(["access:ip:203.0.113.7"]);
    expect(tabKey(s.active)).toBe("access:ip:203.0.113.7");
    expect(isAccessRef(s.active)).toBe(true);
  });

  it("canonicalises_like_its_entity", () => {
    const s = openAccess(initialTabs(), { access: "account", value: " JDoe@Contoso.Example " }).state;
    expect(keys(s)).toEqual(["access:account:jdoe@contoso.example"]);
  });

  it("the_case_tab_is_one_tab", () => {
    let s = openAccess(initialTabs(), CASE).state;
    s = openAccess(s, { access: "case", value: "anything" }).state;
    expect(keys(s)).toEqual(["access:case:"]);
  });

  it("access_tab_differs_from_its_entity_tab", () => {
    let s = openEntity(initialTabs(), { kind: "ip", value: "203.0.113.7" }).state;
    s = openAccess(s, { access: "ip", value: "203.0.113.7" }).state;
    expect(keys(s)).toEqual(["ip:203.0.113.7", "access:ip:203.0.113.7"]);
  });

  it("access_and_entity_tabs_share_the_limit", () => {
    let s = initialTabs();
    for (let n = 0; n < MAX_ENTITY_TABS; n++) s = openEntity(s, { kind: "account", value: `u${n}@x` }).state;
    const r = openAccess(s, CASE);
    expect(r.state.open).toHaveLength(MAX_ENTITY_TABS);
    expect(r.closed).toEqual({ kind: "account", value: "u0@x" });
    expect(keys(r.state)).toContain("access:case:");
    // And the other way round: an access tab can be the one closed.
    const back = openEntity(showTab(r.state, { kind: "account", value: "u1@x" }), { kind: "ip", value: "198.51.100.1" });
    expect(back.closed).toEqual({ kind: "account", value: "u2@x" });
  });

  it("closing_an_access_tab_goes_back", () => {
    let s = openAccess(initialTabs(), CASE).state;
    s = closeTab(s, "access:case:");
    expect(s.open).toEqual([]);
    expect(s.active).toBe("events");
  });

  it("an_empty_or_unknown_access_opens_nothing", () => {
    const s = initialTabs();
    expect(openAccess(s, { access: "ip", value: "  " }).state).toBe(s);
    expect(openAccess(s, { access: "session", value: "x" } as unknown as AccessRef).state).toBe(s);
  });

  it("saves_and_restores_access_tabs", () => {
    vi.stubGlobal("localStorage", fakeStorage());
    let s = openEntity(initialTabs(), { kind: "account", value: "jdoe@contoso.example" }).state;
    s = openAccess(s, { access: "device", value: "d-1" }).state;
    s = openAccess(s, CASE).state;
    saveTabs("case-a", s);
    const back = loadTabs("case-a");
    expect(back).toEqual(s);
    expect(tabKey(back.active)).toBe("access:case:");
  });

  it("old_saved_state_still_loads", () => {
    const store = fakeStorage();
    vi.stubGlobal("localStorage", store);
    store.setItem(
      "sparrow.tabs.v1.case-a",
      JSON.stringify({ open: [{ kind: "ip", value: "203.0.113.7" }], active: "ip:203.0.113.7", viewed: ["events", "ip:203.0.113.7"] }),
    );
    const s = loadTabs("case-a");
    expect(keys(s)).toEqual(["ip:203.0.113.7"]);
    expect(tabKey(s.active)).toBe("ip:203.0.113.7");
  });

  it("drops_unknown_access_kinds", () => {
    const store = fakeStorage();
    vi.stubGlobal("localStorage", store);
    store.setItem(
      "sparrow.tabs.v1.case-a",
      JSON.stringify({
        open: [{ access: "session", value: "x" }, { access: "ip", value: "" }, { access: "case", value: "" }],
        active: "access:case:",
        viewed: [],
      }),
    );
    const s = loadTabs("case-a");
    expect(keys(s)).toEqual(["access:case:"]);
    expect(tabKey(s.active)).toBe("access:case:");
  });

  it("a_malformed_access_entry_is_not_read_as_an_entity", () => {
    const store = fakeStorage();
    vi.stubGlobal("localStorage", store);
    store.setItem(
      "sparrow.tabs.v1.case-a",
      JSON.stringify({
        open: [
          { access: 42, kind: "ip", value: "203.0.113.7" },
          { access: null, kind: "account", value: "x@y" },
          { access: "ip", kind: "account", value: "198.51.100.1" },
        ],
        active: "events",
        viewed: [],
      }),
    );
    expect(keys(loadTabs("case-a"))).toEqual(["access:ip:198.51.100.1"]);
  });
});
