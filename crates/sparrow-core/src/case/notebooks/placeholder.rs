//! `[name]` placeholders in notebook SQL: text the analyst replaces before running. The form is `[`, a letter, then
//! letters, digits or `_`, then `]`, with no spaces. It is found anywhere in the SQL, inside string literals and
//! quoted identifiers too (the built-in queries write `'[account]'`), but never in `--` or `/* */` comments, so a
//! query's comment block can say "replace [account]". DuckDB list syntax (`[1, 2]`, `arr[1]`) does not match.
//! The scanner knows DuckDB's string forms: `'…'` (`''` escapes a quote), `E'…'` (a backslash escapes the next
//! character) and dollar quotes `$$…$$` / `$tag$…$tag$` (nothing escapes; quotes and `--` inside are text).

use crate::{Error, Result};

#[derive(Clone, Copy, PartialEq)]
enum State {
    Code,
    Str,
    /// An `E'…'` string.
    EStr,
    /// A dollar-quoted string; its closing delimiter is `sql[open..close]`.
    Dollar(usize, usize),
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
    matches!(
        scan(sql).1,
        State::Str | State::EStr | State::Dollar(..) | State::Ident | State::Block
    )
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
            State::Code | State::Str | State::EStr | State::Dollar(..) | State::Ident => {
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
                let after_word = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
                match (state, c) {
                    (State::Code, b'E' | b'e') if next == Some(b'\'') && !after_word => {
                        state = State::EStr;
                        i += 1;
                    }
                    (State::Code, b'$') if !after_word => {
                        if let Some(len) = dollar_tag_at(&b[i..]) {
                            state = State::Dollar(i, i + len);
                            i += len - 1;
                        }
                    }
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
                    // Only an escaped quote or backslash can change the state; `\[` is still scanned.
                    (State::EStr, b'\\') if matches!(next, Some(b'\'' | b'\\')) => i += 1,
                    (State::EStr, b'\'') if next == Some(b'\'') => i += 1,
                    (State::EStr, b'\'') => state = State::Code,
                    (State::Dollar(open, close), b'$') if b[i..].starts_with(&b[open..close]) => {
                        state = State::Code;
                        i += close - open - 1;
                    }
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

/// The byte length of a dollar-quote delimiter (`$$` or `$tag$`, the tag a letter or `_` then letters, digits or `_`)
/// starting at `b[0] == b'$'`, if one does. `$1` and `$name` are parameters, not delimiters.
fn dollar_tag_at(b: &[u8]) -> Option<usize> {
    let mut j = 1;
    if b.get(1).is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_') {
        while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
            j += 1;
        }
    }
    (b.get(j) == Some(&b'$')).then_some(j + 1)
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
    fn escape_strings_end_at_their_closing_quote() {
        assert!(placeholders("SELECT E'don\\'t' -- fill [x] later").is_empty());
        assert_eq!(placeholders("SELECT e'a\\\\', '[ip]'"), ["ip"]);
        assert!(!ends_open("SELECT E'don\\'t'"));
        assert!(ends_open("SELECT E'don\\'"));
        // An escaped bracket is still a bracket.
        assert_eq!(placeholders("SELECT E'\\[ip]'"), ["ip"]);
        // A name ending in e is not an escape string's prefix.
        assert!(placeholders("SELECT name'x' -- [x]").is_empty());
    }

    #[test]
    fn dollar_quoted_strings_hold_quotes_and_dashes() {
        assert!(placeholders("SELECT $$it's$$ -- [x]").is_empty());
        assert_eq!(placeholders("SELECT $$-- [ip]$$"), ["ip"]);
        assert!(placeholders("SELECT $q$ a $$ b's $q$ -- [x]").is_empty());
        assert!(!ends_open("SELECT $q$ it's $q$"));
        assert!(ends_open("SELECT $q$ it's $$"));
        // A parameter is not a dollar quote.
        assert!(placeholders("SELECT $1, $name -- [x]").is_empty());
        assert!(!ends_open("SELECT $1 || 'a'"));
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
