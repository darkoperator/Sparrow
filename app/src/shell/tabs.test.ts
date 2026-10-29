import { afterEach, describe, expect, it, vi } from "vitest";
import {
  canonical,
  closeTab,
  initialTabs,
  loadTabs,
  MAX_ENTITY_TABS,
  openEntity,
  saveTabs,
  shortValue,
  showTab,
  tabKey,
  type EntityRef,
  type TabsState,
} from "./tabs";

const acct = (value: string): EntityRef => ({ kind: "account", value });
const ip = (value: string): EntityRef => ({ kind: "ip", value });
const keys = (s: TabsState) => s.open.map(tabKey);

afterEach(() => vi.unstubAllGlobals());

describe("canonical", () => {
  it("lower-cases account, device and session and trims", () => {
    expect(canonical(acct("  JDoe@Contoso.Example "))).toEqual(acct("jdoe@contoso.example"));
    expect(canonical({ kind: "device", value: "ABC-123" })).toEqual({ kind: "device", value: "abc-123" });
    expect(canonical({ kind: "session", value: "4F1C-9A2E" })).toEqual({ kind: "session", value: "4f1c-9a2e" });
  });
  it("normalizes an IP the way the backend does", () => {
    const cases: [string, string][] = [
      ["203.0.113.9", "203.0.113.9"],
      [" 203.0.113.9 ", "203.0.113.9"],
      ["203.0.113.9:443", "203.0.113.9"],
      ["2001:DB8::1", "2001:db8::1"],
      ["2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"],
      ["[2001:DB8::1]:443", "2001:db8::1"],
      ["::ffff:192.0.2.1", "192.0.2.1"],
      ["::FFFF:C000:201", "192.0.2.1"],
    ];
    for (const [raw, want] of cases) expect(canonical(ip(raw)).value, raw).toBe(want);
  });
});

describe("openEntity", () => {
  it("dedupes_spellings", () => {
    let s = initialTabs();
    for (const v of ["JDoe@Contoso.Example", "jdoe@contoso.example", " jdoe@CONTOSO.example"]) {
      s = openEntity(s, acct(v)).state;
    }
    expect(s.open).toEqual([acct("jdoe@contoso.example")]);
    for (const v of ["2001:DB8::1", "2001:db8::1", "2001:db8:0:0:0:0:0:1"]) s = openEntity(s, ip(v)).state;
    expect(keys(s)).toEqual(["account:jdoe@contoso.example", "ip:2001:db8::1"]);
    expect(s.active).toEqual(ip("2001:db8::1"));
    expect(s.viewed).toEqual(["events", "account:jdoe@contoso.example", "ip:2001:db8::1"]);
  });

  it("opening one that is open switches to it without a new tab", () => {
    let s = openEntity(initialTabs(), acct("a@contoso.example")).state;
    s = openEntity(s, acct("b@contoso.example")).state;
    const r = openEntity(s, acct("A@contoso.example"));
    expect(r.closed).toBeUndefined();
    expect(keys(r.state)).toEqual(["account:a@contoso.example", "account:b@contoso.example"]);
    expect(r.state.active).toEqual(acct("a@contoso.example"));
  });

  it("eleventh_evicts_least_recently_viewed", () => {
    let s = initialTabs();
    for (let i = 1; i <= MAX_ENTITY_TABS; i++) {
      const r = openEntity(s, acct(`u${i}@contoso.example`));
      expect(r.closed).toBeUndefined();
      s = r.state;
    }
    expect(s.open).toHaveLength(10);
    // u1 is the oldest, but looking at it again makes u2 the least recently viewed.
    s = showTab(s, acct("u1@contoso.example"));
    const r = openEntity(s, ip("203.0.113.9"));
    expect(r.closed).toEqual(acct("u2@contoso.example"));
    expect(r.state.open).toHaveLength(10);
    expect(keys(r.state)).not.toContain("account:u2@contoso.example");
    expect(keys(r.state)).toContain("account:u1@contoso.example");
    expect(r.state.active).toEqual(ip("203.0.113.9"));
    expect(r.state.viewed).not.toContain("account:u2@contoso.example");
    // The next eviction takes u3, not the tab just opened.
    expect(openEntity(r.state, ip("203.0.113.10")).closed).toEqual(acct("u3@contoso.example"));
  });

  it("never evicts the tab being opened, even if it is the only candidate", () => {
    let s = initialTabs();
    for (let i = 1; i <= MAX_ENTITY_TABS; i++) s = openEntity(s, acct(`u${i}@contoso.example`)).state;
    const r = openEntity({ ...s, viewed: ["events"] }, acct("new@contoso.example"));
    expect(r.closed).toEqual(acct("u1@contoso.example"));
    expect(keys(r.state)).toContain("account:new@contoso.example");
  });

  it("opens nothing for an empty value", () => {
    const s = initialTabs();
    expect(openEntity(s, acct("   ")).state).toBe(s);
    expect(openEntity(s, ip("")).state).toBe(s);
  });
});

describe("showTab and closeTab", () => {
  it("showTab switches to a fixed tab, and ignores an entity that is not open", () => {
    const s = openEntity(initialTabs(), acct("a@contoso.example")).state;
    const t = showTab(s, "tables");
    expect(t.active).toBe("tables");
    expect(t.viewed).toEqual(["events", "account:a@contoso.example", "tables"]);
    expect(showTab(t, acct("nobody@contoso.example"))).toBe(t);
  });

  it("close_returns_to_previous", () => {
    let s = initialTabs();
    s = openEntity(s, acct("a@contoso.example")).state;
    s = openEntity(s, acct("b@contoso.example")).state;
    s = openEntity(s, acct("c@contoso.example")).state;
    s = showTab(s, acct("a@contoso.example"));
    s = showTab(s, acct("c@contoso.example"));
    // c is active and a was viewed before it.
    s = closeTab(s, "account:c@contoso.example");
    expect(s.active).toEqual(acct("a@contoso.example"));
    expect(keys(s)).toEqual(["account:a@contoso.example", "account:b@contoso.example"]);
    expect(s.viewed).toEqual(["events", "account:b@contoso.example", "account:a@contoso.example"]);
    // Closing a tab that is not showing leaves the active one alone.
    const t = closeTab(s, "account:b@contoso.example");
    expect(t.active).toEqual(acct("a@contoso.example"));
    expect(keys(t)).toEqual(["account:a@contoso.example"]);
    // The previous tab can be a fixed one.
    const u = closeTab(showTab(t, "timeline"), "account:a@contoso.example");
    expect(u.active).toBe("timeline");
    const v = closeTab(openEntity(showTab(initialTabs(), "sql"), ip("203.0.113.9")).state, "ip:203.0.113.9");
    expect(v).toEqual({ open: [], active: "sql", viewed: ["events", "sql"] });
  });

  it("closing the only tab goes back to Events; a fixed tab or unknown key cannot be closed", () => {
    const s = openEntity(initialTabs(), acct("a@contoso.example")).state;
    expect(closeTab(s, "account:a@contoso.example")).toEqual(initialTabs());
    expect(closeTab(s, "events")).toBe(s);
    expect(closeTab(s, "account:zz@contoso.example")).toBe(s);
  });
});

describe("shortValue", () => {
  it("shortens a GUID to first and last four, and cuts a long value", () => {
    expect(shortValue("4f1c0000-1111-2222-3333-44449a2e5555")).toBe("4f1c…5555");
    expect(shortValue("jdoe@contoso.example")).toBe("jdoe@contoso.example");
    expect(shortValue("x".repeat(40))).toBe(`${"x".repeat(27)}…`);
  });
});

function fakeStorage(initial: Record<string, string> = {}) {
  const data = new Map(Object.entries(initial));
  return {
    data,
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    removeItem: (k: string) => void data.delete(k),
  };
}

describe("persistence", () => {
  it("persists_per_case_and_survives_bad_storage", () => {
    const store = fakeStorage();
    vi.stubGlobal("localStorage", store);
    let s = initialTabs();
    s = openEntity(s, acct("jdoe@contoso.example")).state;
    s = openEntity(s, ip("2001:db8::1")).state;
    saveTabs("case-a", s);
    saveTabs("case-b", openEntity(initialTabs(), { kind: "device", value: "d1" }).state);
    expect(store.data.size).toBe(2);
    expect(loadTabs("case-a")).toEqual(s);
    expect(loadTabs("case-b").open).toEqual([{ kind: "device", value: "d1" }]);
    expect(loadTabs("case-c")).toEqual(initialTabs());

    // A fixed tab showing is remembered too, with the entity tabs.
    const onTables = showTab(s, "tables");
    saveTabs("case-a", onTables);
    expect(loadTabs("case-a")).toEqual(onTables);
    expect(loadTabs("case-a").active).toBe("tables");
    expect(keys(loadTabs("case-a"))).toEqual(["account:jdoe@contoso.example", "ip:2001:db8::1"]);

    // An unknown tab id, or an entity tab that is not open, reopens on Events.
    for (const active of ["nonsense", "ip:203.0.113.9", 7, null]) {
      store.data.set("sparrow.tabs.v1.case-a", JSON.stringify({ open: onTables.open, active, viewed: onTables.viewed }));
      const back = loadTabs("case-a");
      expect(back.active, String(active)).toBe("events");
      expect(back.viewed[back.viewed.length - 1]).toBe("events");
      expect(keys(back)).toEqual(["account:jdoe@contoso.example", "ip:2001:db8::1"]);
    }

    // Damaged saves give the Events tab, never a crash.
    for (const bad of ["not json", "null", "[]", '{"open":"x"}', '{"open":[null,1,{"kind":"bogus","value":"x"},{"kind":"ip"}]}']) {
      store.data.set("sparrow.tabs.v1.case-a", bad);
      expect(loadTabs("case-a"), bad).toEqual(initialTabs());
    }
  });

  it("re-canonicalizes and caps what it loads, and drops a stale active tab", () => {
    const many = Array.from({ length: 14 }, (_, i) => ({ kind: "account", value: `U${i}@Contoso.example` }));
    vi.stubGlobal(
      "localStorage",
      fakeStorage({
        "sparrow.tabs.v1.c": JSON.stringify({
          open: [{ kind: "account", value: "U0@CONTOSO.example" }, ...many],
          active: "account:gone@contoso.example",
          viewed: ["account:u3@contoso.example", "bogus", "account:u3@contoso.example", "tables"],
        }),
      }),
    );
    const s = loadTabs("c");
    expect(s.open).toHaveLength(MAX_ENTITY_TABS);
    expect(s.open[0]).toEqual(acct("u0@contoso.example"));
    expect(s.active).toBe("events");
    expect(s.viewed[s.viewed.length - 1]).toBe("events");
    expect(new Set(s.viewed).size).toBe(s.viewed.length);
    expect(s.viewed).not.toContain("bogus");
  });

  it("a throwing localStorage gives the Events tab and saving does not throw", () => {
    const boom = () => {
      throw new Error("blocked");
    };
    vi.stubGlobal("localStorage", { getItem: boom, setItem: boom, removeItem: boom });
    expect(loadTabs("x")).toEqual(initialTabs());
    expect(() => saveTabs("x", openEntity(initialTabs(), acct("a@contoso.example")).state)).not.toThrow();
  });
});
