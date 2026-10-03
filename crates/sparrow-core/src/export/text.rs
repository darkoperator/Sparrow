//! Text for the exports. Agent text is stored as given. The Markdown report escapes it for display; the CSV and
//! the workbook keep the raw stored text (they are data: the csv crate quotes, and a workbook cell holds any text).
//!
//! LOCAL helpers: `single_line` and `block` mirror the rules of the single-line `display_safe` variant that is
//! being added to `case::text`; switch to that function when it lands.

use std::fmt::Write as _;

/// Unicode format characters (category Cf): bidirectional marks and overrides, zero-width characters, the BOM,
/// the soft hyphen, the interlinear and tag characters. They change how text reads without showing.
fn is_format(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

fn escape(out: &mut String, c: char) {
    let _ = write!(out, "\\u{{{:04X}}}", c as u32);
}

/// `s` for one line of Markdown: every control character (newline, carriage return and tab included) and every
/// format character becomes `\u{XXXX}`.
pub fn single_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() || is_format(c) {
            escape(&mut out, c);
        } else {
            out.push(c);
        }
    }
    out
}

/// `s` for a Markdown block (a narrative, a note): newlines and tabs stay, every other control character and every
/// format character becomes `\u{XXXX}`; a carriage return before a newline is dropped.
pub fn block(s: &str) -> String {
    let s = s.replace("\r\n", "\n");
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if (c.is_control() && c != '\n' && c != '\t') || is_format(c) {
            escape(&mut out, c);
        } else {
            out.push(c);
        }
    }
    out
}

/// `s` for a Markdown table cell: line breaks become `<br>`, `|` becomes `\|`, every other control character and
/// every format character becomes `\u{XXXX}`.
pub fn md_cell(s: &str) -> String {
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("<br>"),
            '|' => out.push_str("\\|"),
            c if c.is_control() || is_format(c) => escape(&mut out, c),
            c => out.push(c),
        }
    }
    out
}

/// A block as the continuation of a list item: every line after the first is indented by two spaces.
pub fn indented(s: &str) -> String {
    block(s).replace('\n', "\n  ")
}
