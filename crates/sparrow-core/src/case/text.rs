//! Agent text: length caps (checked before any write) and a display form for terminals. Text is always stored as
//! given; only its display is escaped.

use crate::{Error, Result};

/// Notes, narratives, reasons and review comments: at most 16 KiB of UTF-8.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
/// Titles: at most 500 characters.
pub const MAX_TITLE_CHARS: usize = 500;

/// Fails (Error::Decision) when `s` is longer than [`MAX_TEXT_BYTES`].
pub fn check_text(what: &str, s: &str) -> Result<()> {
    if s.len() > MAX_TEXT_BYTES {
        return Err(Error::Decision(format!(
            "{what} is {} bytes; the limit is {MAX_TEXT_BYTES}",
            s.len()
        )));
    }
    Ok(())
}

/// Fails (Error::Decision) when `s` has more than [`MAX_TITLE_CHARS`] characters.
pub fn check_title(s: &str) -> Result<()> {
    let n = s.chars().count();
    if n > MAX_TITLE_CHARS {
        return Err(Error::Decision(format!(
            "a title is {n} characters; the limit is {MAX_TITLE_CHARS}"
        )));
    }
    Ok(())
}

/// Unicode format characters (general category Cf): invisible, and some reorder text on screen (bidi overrides
/// and isolates), so a display never shows them raw.
fn is_format(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2 | 0x180E
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB
        | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001
        | 0xE0020..=0xE007F)
}

fn escape(s: &str, keep: &[char]) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if (c.is_control() || is_format(c)) && !keep.contains(&c) {
            out.push_str(&format!("\\u{{{:04X}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// `s` for a multi-line block on a terminal (guidance, a narrative): every control character except `\n` and `\t`
/// (ESC included) and every Unicode format character (bidi overrides, zero-width characters, BOM) becomes
/// `\u{XXXX}`, so agent text cannot move the cursor, recolour, clear the screen or reorder what is shown.
pub fn display_safe(s: &str) -> String {
    escape(s, &['\n', '\t'])
}

/// [`display_safe`] for text printed on ONE line (titles, summaries, list rows, decision lines): `\n` is escaped
/// too, so a value cannot forge an extra output line.
pub fn display_safe_line(s: &str) -> String {
    escape(s, &['\t'])
}
