// Synthetic stress data for the mock backend: a wide, long table whose values are all invented (RFC 5737 addresses,
// example domains, a seeded generator so every run shows the same rows). Built once, on first use.
import type { Filter, Sort } from "../api";

export const GEN_ROWS = 5000;

/** Hostile strings the grid and viewers must show as text: bidi controls, markup, a formula, a control character. */
const HOSTILE = [
  "‮evil.exe‬ (bidi override)",
  '<img src=x onerror="alert(1)">',
  "<script>alert('mock')</script>",
  "=HYPERLINK(\"http://198.51.100.9/\",\"click\")",
  "tab\there\u0007bell​zero-width",
];

const NAMED: string[] = [
  "record_key", "event_time", "user_upn", "ip", "user_agent", "status", "error_code", "app_name", "resource_name",
  "client_app", "is_interactive", "asn", "country", "city", "session_id", "correlation_id", "device", "notes", "raw",
];
const FILLER = 40 - NAMED.length;
export const GEN_COLUMNS: string[] = [...NAMED, ...Array.from({ length: FILLER }, (_, i) => `attr_${String(i + 1).padStart(2, "0")}`)];

function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const APPS = ["Microsoft Office", "Azure Portal", "Outlook Mobile", "Teams", "OneDrive Sync", "Graph Explorer"];
const CITIES = [["Port Sable", "AU"], ["Northbridge", "US"], ["Lakeside", "DE"], ["Eastvale", "SG"], ["Hollow Creek", "CA"]];
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 " +
  "Edg/128.0.0.0 mock-agent-suffix-" + "x".repeat(170) + " end";

function uuid(r: () => number): string {
  const h = () => Math.floor(r() * 0x10000).toString(16).padStart(4, "0");
  return `${h()}${h()}-${h()}-${h()}-${h()}-${h()}${h()}${h()}`;
}

let cache: unknown[][] | null = null;

export function genRows(): unknown[][] {
  if (cache) return cache;
  const r = rng(20261009);
  const t0 = Date.UTC(2026, 7, 1);
  const rows: unknown[][] = [];
  for (let i = 0; i < GEN_ROWS; i++) {
    const [city, country] = CITIES[Math.floor(r() * CITIES.length)];
    const failed = r() < 0.12;
    const ip = `203.0.113.${Math.floor(r() * 254) + 1}`;
    const upn = `user${String(Math.floor(r() * 60)).padStart(2, "0")}@contoso.example`;
    const time = new Date(t0 + i * 61_000 + Math.floor(r() * 30_000)).toISOString().replace(".000Z", ".000000Z");
    const raw = JSON.stringify({
      id: uuid(r),
      createdDateTime: time,
      userPrincipalName: upn,
      ipAddress: ip,
      status: { errorCode: failed ? 50126 : 0 },
      details: Array.from({ length: 24 }, (_, k) => ({ step: k, method: "Password", note: "synthetic mock value ".repeat(3) })),
    }).padEnd(2048, " ");
    const named: unknown[] = [
      uuid(r), time, i % 97 === 0 ? HOSTILE[(i / 97) % HOSTILE.length | 0] : upn, ip, i % 5 === 0 ? UA : "Mozilla/5.0 (Mock)",
      failed ? "Failure" : "Success", failed ? 50126 : 0, APPS[Math.floor(r() * APPS.length)],
      "Office 365 Exchange Online", "Browser", r() < 0.8, 64496 + Math.floor(r() * 4), country, city, uuid(r), uuid(r),
      JSON.stringify({ display_name: `MOCK-LAPTOP-${i % 40}`, os: "Windows 11", is_managed: r() < 0.5 }),
      i % 11 === 0 ? null : `note ${i}`, raw,
    ];
    const filler = Array.from({ length: FILLER }, (_, k) => (k % 7 === 3 ? null : `v${k + 1}-${Math.floor(r() * 1000)}`));
    rows.push([...named, ...filler]);
  }
  cache = rows;
  return rows;
}

function cmp(a: unknown, b: unknown): number {
  if (a === null || a === undefined) return b === null || b === undefined ? 0 : 1; // nulls last
  if (b === null || b === undefined) return -1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a) < String(b) ? -1 : String(a) > String(b) ? 1 : 0;
}

function matches(row: unknown[], f: Filter): boolean {
  const i = GEN_COLUMNS.indexOf(f.column);
  if (i < 0) return false;
  const v = row[i];
  switch (f.op) {
    case "eq": return v === f.value || (v !== null && String(v) === String(f.value));
    case "ne": return !(v === f.value || (v !== null && String(v) === String(f.value)));
    case "contains": return v !== null && String(v).toLowerCase().includes(f.value.toLowerCase());
    case "between": return v !== null && cmp(v, f.low) >= 0 && cmp(v, f.high) <= 0;
    case "in": return f.values.some((x) => String(x) === String(v));
    case "is_null": return v === null;
    case "not_null": return v !== null;
  }
}

/** Matching rows in sort order (a stable sort; `sort` on an unknown column is ignored). */
export function selectRows(filters: Filter[], sort: Sort | null): unknown[][] {
  let rows = genRows().filter((row) => filters.every((f) => matches(row, f)));
  const si = sort ? GEN_COLUMNS.indexOf(sort.column) : -1;
  if (sort && si >= 0) {
    const dir = sort.descending ? -1 : 1;
    rows = [...rows].sort((a, b) => {
      const an = a[si] === null, bn = b[si] === null;
      if (an || bn) return cmp(a[si], b[si]); // nulls stay last either way
      return dir * cmp(a[si], b[si]);
    });
  }
  return rows;
}

/** A pivot section's rows: JSON objects of the synthetic columns (the first `n`). */
export function genObjects(n: number): Record<string, unknown>[] {
  return genRows().slice(0, n).map((row) => Object.fromEntries(GEN_COLUMNS.map((c, i) => [c, row[i]])));
}
