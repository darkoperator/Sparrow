// How a column's catalog type (`ColumnInfo.type`) is edited in the filter builder. Mirrors the grouping the
// backend uses to compare values (core `browse::kind_of`); it only picks the input widget, the backend decides.

export type ColumnKind = "number" | "time" | "date" | "text";

const INTEGERS = new Set([
  "TINYINT", "SMALLINT", "INTEGER", "BIGINT", "HUGEINT", "UTINYINT", "USMALLINT", "UINTEGER", "UBIGINT",
]);

export function columnKind(dataType: string): ColumnKind {
  const t = dataType.toUpperCase();
  if (INTEGERS.has(t) || t === "FLOAT" || t === "DOUBLE" || t.startsWith("DECIMAL(")) return "number";
  if (t === "TIMESTAMP WITH TIME ZONE" || t === "TIMESTAMPTZ" || t === "TIMESTAMP") return "time";
  if (t === "DATE") return "date";
  return "text";
}

/** A `datetime-local` value ("2026-08-17T00:20" or with seconds) read as UTC, as RFC 3339. */
export function toRfc3339Utc(local: string): string {
  const withSeconds = /T\d\d:\d\d$/.test(local) ? `${local}:00` : local;
  return `${withSeconds}Z`;
}

/** A typed filter value for a column kind; `null` when the text is not a valid value for it. */
export function typedValue(kind: ColumnKind, text: string): unknown {
  const t = text.trim();
  if (t === "") return null;
  if (kind === "number") {
    // Only a safe integer travels as a JSON number; any other valid decimal or exponent form is sent as its exact text
    // (a JSON number would round it to a double), which the backend compares exactly.
    if (!/^-?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(t)) return null;
    const n = Number(t);
    if (!Number.isFinite(n)) return null;
    return /^-?\d+$/.test(t) && Number.isSafeInteger(n) ? n : t;
  }
  if (kind === "time") return toRfc3339Utc(t);
  return text;
}
