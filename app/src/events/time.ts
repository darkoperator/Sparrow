// The Events range boxes' time syntax, shared by the filter row and its calendar picker.
export type Range = "from" | "to";

/**
 * A From/To box read as UTC: ISO 8601 (`2026-09-10`, `2026-09-10T01:55`, `2026-09-10 01:55:36`, `…Z`, with optional
 * fractions) or US month/day/year (`10/23/2026`, `10/23/2026 14:30`). A date alone means the start of that day for From
 * and its last instant for To; a To with minutes and no seconds likewise covers its whole minute (both ends are
 * inclusive). The result is the text sent and shown. Anything with an offset, or not a real date, is refused.
 */
export function parseUtc(text: string, end: Range): { ok: true; value: string | undefined } | { ok: false; message: string } {
  const typed = text.trim();
  if (typed === "") return { ok: true, value: undefined };
  const bad = { ok: false as const, message: `${JSON.stringify(typed)} is not a UTC time, like 2026-09-10T01:55:00Z or 10/23/2026 14:30` };
  const us = /^(\d{1,2})\/(\d{1,2})\/(\d{4})(?: (\d{2}):(\d{2}))?$/.exec(typed);
  const pad = (n: string) => n.padStart(2, "0");
  const t = us ? `${us[3]}-${pad(us[1])}-${pad(us[2])}${us[4] === undefined ? "" : `T${us[4]}:${us[5]}`}` : typed;
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(\.\d{1,6})?)?)?Z?$/.exec(t);
  if (!m) return bad;
  const [, y, mo, d, hh, mi, ss, frac] = m;
  const parts = [Number(y), Number(mo), Number(d), Number(hh ?? 0), Number(mi ?? 0), Number(ss ?? 0)];
  const ms = Date.UTC(parts[0], parts[1] - 1, parts[2], parts[3], parts[4], parts[5]);
  const back = new Date(ms);
  if (back.getUTCFullYear() !== parts[0] || back.getUTCMonth() !== parts[1] - 1 || back.getUTCDate() !== parts[2] || parts[3] > 23 || parts[4] > 59 || parts[5] > 59) {
    return bad;
  }
  if (hh === undefined && end === "to") return { ok: true, value: `${y}-${mo}-${d}T23:59:59.999999Z` };
  if (hh !== undefined && ss === undefined && end === "to") return { ok: true, value: `${y}-${mo}-${d}T${hh}:${mi}:59.999999Z` };
  const clock = `${hh ?? "00"}:${mi ?? "00"}:${ss ?? "00"}${frac ?? ""}`;
  return { ok: true, value: `${y}-${mo}-${d}T${clock}Z` };
}
