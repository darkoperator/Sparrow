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

/// `s` for a terminal: every control character except `\n` and `\t` (ESC included) becomes `\u{XXXX}`, so agent
/// text cannot move the cursor, recolour or clear the screen.
pub fn display_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() && c != '\n' && c != '\t' {
            out.push_str(&format!("\\u{{{:04X}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}
