// One list from an access report's accounts: what an Access tab shows when it can span accounts (a device or IP
// what-if, the whole case). Counts add up; a category reads "collected" only when every shown account's source was
// collected, and "none seen" only when every shown account says so, so a merge never turns a gap into a zero; each
// account's qualifier is kept, named; a gap shared by several accounts is said once. `only` is the tab's Account filter. A single account comes back as it was.
import type { AccessItem, AccessReport, AccessTile, ScopeValue } from "../api";

export interface MergedTile extends AccessTile {
  /** Of the `of` accounts shown, how many did not have this category's source collected. */
  notCollectedFor: number;
  of: number;
  /** The distinct coverage statuses of those accounts, in account order (`not_licensed`, `beyond_retention`…). */
  missingStatuses: string[];
}

export interface MergedAccess {
  /** Every account in the report, in its order (the filter's choices). */
  accounts: string[];
  scope: ScopeValue[];
  tiles: MergedTile[];
  /** By `accessed` (as an instant), oldest first; equal times keep the report's order. */
  items: AccessItem[];
  /**
   * Each gap once, in order: as is when the report has one account; named by its account when one shown account has
   * it; else with how many accounts have it (`… (all 3 accounts)`, `… (4 accounts: a, b, c +1 more)`). Then what
   * Microsoft never logs, once.
   */
  gaps: string[];
}

/** Accounts named in a shared gap before "+N more". */
const GAP_NAMES = 3;

export function mergeAccess(report: AccessReport, only: string | null): MergedAccess {
  const accounts = report.accounts.map((a) => a.account);
  const shown = only === null ? report.accounts : report.accounts.filter((a) => a.account === only);
  const several = report.accounts.length > 1;

  const scope: ScopeValue[] = [];
  for (const s of shown.flatMap((a) => a.scope)) {
    const same = scope.find((x) => x.kind === s.kind && x.value === s.value && x.basis === s.basis);
    if (same) same.windows = [...same.windows, ...s.windows].sort((x, y) => (instant(x.start) < instant(y.start) ? -1 : instant(x.start) > instant(y.start) ? 1 : 0));
    else scope.push({ ...s, windows: [...s.windows] });
  }

  const tiles: MergedTile[] = (shown[0]?.tiles ?? []).map((first) => {
    const of = shown
      .map((a) => ({ account: a.account, tile: a.tiles.find((t) => t.category === first.category) }))
      .filter((x): x is { account: string; tile: AccessTile } => x.tile !== undefined);
    const all = of.map((x) => x.tile);
    // A qualifier is built from an account's own items (folders, MB, recipients) and cannot be added up: across
    // accounts each keeps its own, named, so a synced-only exposure (no count) is neither lost nor misattributed.
    const named = of.filter((x) => x.tile.qualifier !== null).map((x) => (of.length > 1 ? `${x.account}: ${x.tile.qualifier}` : x.tile.qualifier!));
    const missing = all.filter((t) => t.coverage.status !== "collected");
    const sum = (k: "direct" | "by_time" | "pending" | "adhoc") => all.reduce((n, t) => n + t[k], 0);
    return {
      category: first.category,
      direct: sum("direct"),
      by_time: sum("by_time"),
      pending: sum("pending"),
      adhoc: sum("adhoc"),
      qualifier: named.length > 0 ? named.join(" · ") : null,
      coverage: missing[0]?.coverage ?? first.coverage,
      none_seen: all.every((t) => t.none_seen),
      notCollectedFor: missing.length,
      of: all.length,
      missingStatuses: [...new Set(missing.map((t) => t.coverage.status))],
    };
  });

  const items = shown
    .flatMap((a) => a.items)
    .map((i, n) => ({ i, n, at: instant(i.accessed) }))
    .sort((x, y) => (x.at < y.at ? -1 : x.at > y.at ? 1 : x.n - y.n))
    .map((x) => x.i);

  // A gap shared by many accounts (the same collection limit) is said once, not once per account.
  const holders = new Map<string, string[]>();
  for (const a of shown) {
    for (const g of a.gaps) {
      const who = holders.get(g);
      if (who) who.push(a.account);
      else holders.set(g, [a.account]);
    }
  }
  const own = [...holders].map(([g, who]) => {
    if (!several) return g;
    if (who.length === 1) return `${who[0]}: ${g}`;
    if (who.length === shown.length) return `${g} (all ${who.length} accounts)`;
    const named = who.slice(0, GAP_NAMES).join(", ");
    return `${g} (${who.length} accounts: ${named}${who.length > GAP_NAMES ? ` +${who.length - GAP_NAMES} more` : ""})`;
  });
  return { accounts, scope, tiles, items, gaps: [...own, ...report.never_logged.filter((g) => !holders.has(g))] };
}

/**
 * An RFC 3339 UTC time (`…:SS[.fraction]Z`, as the core writes it) as text that sorts in time order: the fraction padded
 * to nine digits, so `10:00:00Z` < `10:00:00.25Z` < `10:00:00.250001Z` < `10:00:00.5Z`.
 */
function instant(t: string): string {
  const m = /^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(t);
  return m ? `${m[1]}.${(m[2] ?? "").padEnd(9, "0")}` : t;
}
