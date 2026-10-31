//! `[name]` placeholders in notebook SQL: text the analyst replaces before running. The form is `[`, a letter, then
//! letters, digits or `_`, then `]`, with no spaces. It is found anywhere in the SQL, inside string literals and
//! quoted identifiers too (the built-in queries write `'[account]'`), but never in `--` or `/* */` comments, so a
//! query's comment block can say "replace [account]". DuckDB list syntax (`[1, 2]`, `arr[1]`) does not match.

use crate::{Error, Result};

#[derive(Clone, Copy, PartialEq)]
enum State {
    Code,
    Str,
    Ident,
    Line,
    Block,
}

/// The placeholder names in `sql` (without brackets), each once, in order of first appearance.
pub fn placeholders(sql: &str) -> Vec<String> {
    scan(sql).0
}

/// Whether `sql` ends inside a string literal, a quoted identifier or a `/* */` comment: a file query cut there was
/// split by a separator line inside its text.
pub(crate) fn ends_open(sql: &str) -> bool {
    matches!(scan(sql).1, State::Str | State::Ident | State::Block)
}

/// The placeholders and the state the scanner ends in.
fn scan(sql: &str) -> (Vec<String>, State) {
    let b = sql.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut state = State::Code;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        match state {
            State::Line => {
                if c == b'\n' {
                    state = State::Code;
                }
            }
            State::Block => {
                if c == b'*' && next == Some(b'/') {
                    state = State::Code;
                    i += 1;
                }
            }
            State::Code | State::Str | State::Ident => {
                if c == b'[' {
                    if let Some(len) = placeholder_at(&b[i..]) {
                        let name = &sql[i + 1..i + len - 1];
                        if !out.iter().any(|n| n == name) {
                            out.push(name.to_string());
                        }
                        i += len;
                        continue;
                    }
                }
                match (state, c) {
                    (State::Code, b'\'') => state = State::Str,
                    (State::Code, b'"') => state = State::Ident,
                    (State::Code, b'-') if next == Some(b'-') => {
                        state = State::Line;
                        i += 1;
                    }
                    (State::Code, b'/') if next == Some(b'*') => {
                        state = State::Block;
                        i += 1;
                    }
                    // A doubled quote is an escaped quote and stays in the literal.
                    (State::Str, b'\'') if next == Some(b'\'') => i += 1,
                    (State::Str, b'\'') => state = State::Code,
                    (State::Ident, b'"') if next == Some(b'"') => i += 1,
                    (State::Ident, b'"') => state = State::Code,
                    _ => {}
                }
            }
        }
        i += 1;
    }
    (out, state)
}

/// The byte length of a placeholder starting at `b[0] == b'['`, if one does.
fn placeholder_at(b: &[u8]) -> Option<usize> {
    if !b.get(1).is_some_and(u8::is_ascii_alphabetic) {
        return None;
    }
    let mut j = 2;
    while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
        j += 1;
    }
    (b.get(j) == Some(&b']')).then_some(j + 1)
}

/// Refuses (Error::Decision) a query that still holds placeholders, naming each: `Fill in [a] first`,
/// `Fill in [a] and [b] first`, `Fill in [a], [b] and [c] first`.
pub fn refuse_placeholders(sql: &str) -> Result<()> {
    let names: Vec<String> = placeholders(sql).iter().map(|n| format!("[{n}]")).collect();
    let list = match names.as_slice() {
        [] => return Ok(()),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    };
    Err(Error::Decision(format!("Fill in {list} first")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_scan_cases() {
        assert_eq!(
            placeholders("WHERE upn = '[account]' AND ip = '[ip]' OR upn = '[account]'"),
            ["account", "ip"]
        );
        assert!(placeholders("SELECT [1, 2], arr[1], list_value(1)[1]").is_empty());
        assert!(placeholders("-- replace [account]\nSELECT 1 /* [ip] */").is_empty());
        assert_eq!(placeholders("SELECT 'a--[ip]'"), ["ip"]);
        assert_eq!(placeholders("SELECT 'it''s [ip]'"), ["ip"]);
        assert!(placeholders("SELECT '[ not one ]', '[1x]'").is_empty());
        assert_eq!(placeholders("SELECT \"[col_2]\""), ["col_2"]);
    }

    #[test]
    fn refusal_names_every_placeholder() {
        assert!(refuse_placeholders("SELECT 1").is_ok());
        let msg = |s| refuse_placeholders(s).unwrap_err().to_string();
        assert!(msg("'[a]'").ends_with("Fill in [a] first"));
        assert!(msg("'[a]' '[b]'").ends_with("Fill in [a] and [b] first"));
        assert!(msg("'[a]' '[b]' '[c]'").ends_with("Fill in [a], [b] and [c] first"));
    }
}
