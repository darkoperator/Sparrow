// Untrusted text (evidence, agent text, bundle text) for display on one line: the same rule as the CLI's
// `display_safe_line` (crates/sparrow-core/src/case/text.rs). Every control character except tab and every Unicode
// format character (bidi overrides and isolates, zero-width characters, BOM) becomes `\u{XXXX}`, so a value cannot
// reorder what is shown or forge an extra line. Keep the two in step.

// General category Cf, as `is_format` in text.rs.
const FORMAT_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x00ad, 0x00ad],
  [0x0600, 0x0605],
  [0x061c, 0x061c],
  [0x06dd, 0x06dd],
  [0x070f, 0x070f],
  [0x0890, 0x0891],
  [0x08e2, 0x08e2],
  [0x180e, 0x180e],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x206f],
  [0xfeff, 0xfeff],
  [0xfff9, 0xfffb],
  [0x110bd, 0x110bd],
  [0x110cd, 0x110cd],
  [0x13430, 0x1343f],
  [0x1bca0, 0x1bca3],
  [0x1d173, 0x1d17a],
  [0xe0001, 0xe0001],
  [0xe0020, 0xe007f],
];

function isFormat(cp: number): boolean {
  return FORMAT_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi);
}

// Rust's `char::is_control`: general category Cc.
function isControl(cp: number): boolean {
  return cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f);
}

export function displaySafe(s: string): string {
  let out = "";
  // for..of walks code points, so astral format characters (U+E0001 tags) are seen whole.
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if ((isControl(cp) || isFormat(cp)) && ch !== "\t") {
      out += "\\u{" + cp.toString(16).toUpperCase().padStart(4, "0") + "}";
    } else {
      out += ch;
    }
  }
  return out;
}
