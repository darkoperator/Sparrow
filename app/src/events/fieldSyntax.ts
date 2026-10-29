// Harrier's field syntax as the column filters write and read it, the same rules as core's `events::filter::parse_list`:
// comma separates values (any of), a leading `!` excludes, `*` is a wildcard, and a value in double quotes is literal
// (commas, `*`, a leading `!` and outer spaces included; `""` inside it is one quote). A quote anywhere else is an
// ordinary character. The backend parses the text itself; this is for building it and for showing what it holds.

export interface Term {
  /** The value, without its `!` or quotes. */
  text: string;
  exclude: boolean;
  /** Unquoted with a `*`: a pattern, not one value. */
  wild: boolean;
}

/**
 * The terms of a field's text, or the refusal the backend would give (without its "<Field> filter: " prefix). A blank
 * text is no terms.
 */
export function parseField(text: string): { ok: true; terms: Term[] } | { ok: false; message: string } {
  const terms: Term[] = [];
  if (text.trim() === "") return { ok: true, terms };
  const n = text.length;
  let i = 0;
  const space = () => {
    while (i < n && /\s/.test(text[i])) i++;
  };
  while (i <= n) {
    space();
    const exclude = text[i] === "!";
    if (exclude) {
      i++;
      space();
    }
    if (text[i] === '"') {
      let value = "";
      i++;
      for (;;) {
        if (i >= n) return { ok: false, message: 'a quote is not closed (a quoted value ends with ")' };
        if (text[i] === '"' && text[i + 1] === '"') {
          value += '"';
          i += 2;
        } else if (text[i] === '"') {
          i++;
          break;
        } else {
          value += text[i++];
        }
      }
      space();
      if (i < n && text[i] !== ",") return { ok: false, message: "a quoted value must end at its closing quote (put a comma after it)" };
      terms.push({ text: value, exclude, wild: false });
    } else {
      const start = i;
      while (i < n && text[i] !== ",") i++;
      const value = text.slice(start, i).trim();
      if (value === "") {
        if (exclude) return { ok: false, message: "a '!' needs a value after it (like !value)" };
      } else {
        terms.push({ text: value, exclude, wild: value.includes("*") });
      }
    }
    i++;
  }
  if (terms.length === 0) return { ok: false, message: "only commas, no value" };
  return { ok: true, terms };
}

/** One value as the syntax reads it back as exactly that value: quoted when it holds anything the syntax would read. */
export function quoteValue(value: string): string {
  const plain = value !== "" && value.trim() === value && !/[,*"]/.test(value) && !value.startsWith("!");
  return plain ? value : `"${value.replaceAll('"', '""')}"`;
}

/** A term written back as text. */
export function formatTerm(t: Term): string {
  return `${t.exclude ? "!" : ""}${t.wild ? t.text : quoteValue(t.text)}`;
}

/**
 * The text of a column filter: the ticked values (any of; with `exclude`, none of) and the pattern box as typed, joined
 * by commas. Blank when there is neither.
 */
export function buildField(values: string[], exclude: boolean, pattern: string): string {
  const parts = values.map((v) => `${exclude ? "!" : ""}${quoteValue(v)}`);
  if (pattern.trim() !== "") parts.push(pattern.trim());
  return parts.join(",");
}

/**
 * What a column filter popover shows for a field's text: the exact values as ticks (the polarity most of them have),
 * and the rest (wildcards, values of the other polarity) as pattern text. A text the syntax refuses is all pattern.
 */
export function splitField(text: string): { values: string[]; exclude: boolean; pattern: string } {
  const parsed = parseField(text);
  if (!parsed.ok) return { values: [], exclude: false, pattern: text.trim() };
  const exact = parsed.terms.filter((t) => !t.wild);
  const excluded = exact.filter((t) => t.exclude).length;
  const exclude = excluded > exact.length - excluded;
  const ticked = exact.filter((t) => t.exclude === exclude);
  const rest = parsed.terms.filter((t) => t.wild || t.exclude !== exclude);
  return { values: ticked.map((t) => t.text), exclude, pattern: rest.map(formatTerm).join(",") };
}
