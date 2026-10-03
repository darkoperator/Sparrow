//! Text for the exports. Agent text is stored as given. The Markdown report escapes it for display, as Markdown
//! AND HTML (evidence text can be attacker-controlled: a rule named `x <!--` would otherwise hide the rest of the
//! report, `[Verify](https://evil.example)` would become a link, `[^3]` a forged citation); the CSV and the
//! workbook keep the raw stored text (they are data: the csv crate quotes, and a workbook cell holds any text).
//!
//! Control and format (bidi) characters are escaped by `case::text::{display_safe, display_safe_line}`; this module
//! adds the Markdown and HTML escaping on top.

use crate::case::text::{display_safe, display_safe_line};

/// Push `c` as literal text: Markdown punctuation is backslash-escaped, and `&`, `<` and `>` are HTML-escaped
/// (`&amp;` `&lt;` `&gt;`), so raw HTML, comments, autolinks, images, links, footnote references (`[^n]`), emphasis,
/// headings, tables and code spans written by an attacker render as the characters they are. Control and format
/// characters are left for `case::text`'s `display_safe` family, which runs afterwards.
fn literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\\' | '`' | '*' | '_' | '[' | ']' | '(' | ')' | '!' | '#' | '|' | '~' | '{' | '}'
            | '+' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

/// `s` for one line of Markdown: [`literal`], then every control character (newline and carriage return included)
/// and every format character becomes `\u{XXXX}` (`display_safe_line`).
pub fn single_line(s: &str) -> String {
    display_safe_line(&literal(s))
}

/// `s` for a Markdown block (a narrative, a note): newlines and tabs stay, every other control character and every
/// format character becomes `\u{XXXX}`, everything else is [`literal`], and a line cannot start a list, a setext
/// heading or an ordered list (`-`, `=` or `1.` at its start are backslash-escaped). A carriage return before a
/// newline is dropped.
pub fn block(s: &str) -> String {
    let s = s.replace("\r\n", "\n");
    display_safe(&literal(&s))
        .split('\n')
        .map(line_start)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Escape what would turn the line into a list item, a setext underline or an ordered list item.
fn line_start(line: &str) -> String {
    let body = line.trim_start_matches([' ', '\t']);
    let lead = &line[..line.len() - body.len()];
    let digits = body.chars().take_while(char::is_ascii_digit).count();
    if body.starts_with('-') || body.starts_with('=') {
        format!("{lead}\\{body}")
    } else if digits > 0 && body[digits..].starts_with('.') {
        format!("{lead}{}\\{}", &body[..digits], &body[digits..])
    } else {
        line.to_string()
    }
}

/// `s` for a Markdown table cell: line breaks become `<br>` (ours), every other control character and every
/// format character becomes `\u{XXXX}`, and everything else is [`literal`] (`|` becomes `\|`).
pub fn md_cell(s: &str) -> String {
    s.replace("\r\n", "\n")
        .replace('\r', "\n")
        .split('\n')
        .map(single_line)
        .collect::<Vec<_>>()
        .join("<br>")
}

/// A block as the continuation of a list item: every line after the first is indented by two spaces.
pub fn indented(s: &str) -> String {
    block(s).replace('\n', "\n  ")
}
