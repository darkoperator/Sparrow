//! The notebook file: a readable `.sql` file that any editor and the DuckDB UI open, and that Sparrow reads back on
//! import. A header comment names the notebook and the Sparrow that wrote it; each query follows a [`MARKER`] line.
//!
//! ```text
//! -- sparrow notebook: <name>
//! -- exported by Sparrow <version> at <time>
//! -- ==== query ====
//! <query 1>
//! -- ==== query ====
//! <query 2>
//! ```

use crate::{Error, Result};

/// The line before each query.
pub const MARKER: &str = "-- ==== query ====";
const HEADER: &str = "-- sparrow notebook: ";
/// The largest query, in bytes of UTF-8.
pub const MAX_QUERY_BYTES: usize = 64 * 1024;
/// The most queries a notebook holds.
pub const MAX_QUERIES: usize = 200;

/// A parsed notebook file.
#[derive(Debug, Clone, PartialEq)]
pub struct NotebookFile {
    pub name: String,
    pub queries: Vec<String>,
}

/// The file text for `queries` of notebook `name`.
pub fn write_file(name: &str, version: &str, exported_at: &str, queries: &[&str]) -> String {
    let mut out = format!("{HEADER}{name}\n-- exported by Sparrow {version} at {exported_at}\n");
    for q in queries {
        out.push_str(MARKER);
        out.push('\n');
        out.push_str(q.trim_end());
        out.push('\n');
    }
    out
}

/// Reads a notebook file. CRLF line ends are accepted; a bad query is reported with the line its text starts on.
pub fn parse_file(text: &str) -> Result<NotebookFile> {
    let text = text.replace("\r\n", "\n");
    let mut lines = text.split('\n');
    let name = lines
        .next()
        .and_then(|l| l.strip_prefix(HEADER))
        .map(str::trim)
        .ok_or_else(|| {
            Error::Decision(
                "not a Sparrow notebook file: the first line must be \"-- sparrow notebook: <name>\"".into(),
            )
        })?;
    if name.is_empty() {
        return Err(Error::Decision("line 1: the file names no notebook".into()));
    }
    crate::case::text::check_title(name).map_err(|e| Error::Decision(format!("line 1: {e}")))?;
    // (first line of the chunk's text, its lines); text before the first marker is header comments, ignored.
    let mut chunks: Vec<(usize, Vec<&str>)> = Vec::new();
    for (i, line) in lines.enumerate() {
        let n = i + 2;
        if line.trim_end() == MARKER {
            chunks.push((n + 1, Vec::new()));
        } else if let Some((_, body)) = chunks.last_mut() {
            body.push(line);
        } else if !line.trim().is_empty() && !line.trim_start().starts_with("--") {
            return Err(Error::Decision(format!(
                "line {n}: only comments may come before the first query ({MARKER})"
            )));
        }
    }
    let mut queries = Vec::new();
    for (start, body) in chunks {
        let first = body.iter().position(|l| !l.trim().is_empty());
        let Some(first) = first else { continue };
        let last = body
            .iter()
            .rposition(|l| !l.trim().is_empty())
            .unwrap_or(first);
        let sql = body[first..=last].join("\n");
        let line = start + first;
        check_query_sql(&sql).map_err(|e| Error::Decision(format!("line {line}: {e}")))?;
        if super::placeholder::ends_open(&sql) {
            return Err(Error::Decision(format!(
                "line {line}: this query ends inside a string or comment; a {MARKER} line cannot be inside a query"
            )));
        }
        queries.push(sql);
    }
    if queries.is_empty() {
        return Err(Error::Decision("the file holds no queries".into()));
    }
    if queries.len() > MAX_QUERIES {
        return Err(Error::Decision(format!(
            "a notebook is limited to {MAX_QUERIES} queries"
        )));
    }
    Ok(NotebookFile {
        name: name.to_string(),
        queries,
    })
}

/// Refuses (Error::Decision) a query that is empty, over [`MAX_QUERY_BYTES`], or holds a [`MARKER`] line (it
/// could not be read back from a file).
pub fn check_query_sql(sql: &str) -> Result<()> {
    if sql.trim().is_empty() {
        return Err(Error::Decision("a query must not be empty".into()));
    }
    if sql.len() > MAX_QUERY_BYTES {
        return Err(Error::Decision(format!(
            "a query is limited to {MAX_QUERY_BYTES} bytes"
        )));
    }
    if sql.lines().any(|l| l.trim_end() == MARKER) {
        return Err(Error::Decision(format!(
            "a query cannot contain the line {MARKER}"
        )));
    }
    Ok(())
}

/// The title of a query: its first `--` comment line's text; for a query without a leading comment, its first
/// non-empty line, cut to 80 characters; `(untitled)` when it is empty.
pub fn title(sql: &str) -> String {
    let mut lines = sql
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .peekable();
    let Some(first) = lines.peek().copied() else {
        return "(untitled)".into();
    };
    if first.starts_with("--") {
        for l in lines {
            let Some(text) = l.strip_prefix("--") else {
                break;
            };
            let text = text.trim();
            if !text.is_empty() {
                return text.to_string();
            }
        }
        return "(untitled)".into();
    }
    first.chars().take(80).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_is_the_first_comment_line() {
        assert_eq!(
            title("-- Sign-ins by country\n-- more\nSELECT 1"),
            "Sign-ins by country"
        );
        assert_eq!(title("\n  SELECT 1"), "SELECT 1");
        assert_eq!(title(""), "(untitled)");
    }

    #[test]
    fn file_round_trips() {
        let text = write_file(
            "BEC triage",
            "0.1.0",
            "2026-10-31T12:00:00Z",
            &["-- a\nSELECT 1", "SELECT 2"],
        );
        assert!(text.starts_with("-- sparrow notebook: BEC triage\n"));
        let f = parse_file(&text.replace('\n', "\r\n")).unwrap();
        assert_eq!(f.name, "BEC triage");
        assert_eq!(f.queries, ["-- a\nSELECT 1", "SELECT 2"]);
    }

    #[test]
    fn bad_files_are_refused_with_the_line() {
        assert!(
            parse_file("SELECT 1")
                .unwrap_err()
                .to_string()
                .contains("not a Sparrow notebook file")
        );
        assert!(
            parse_file("-- sparrow notebook: x\n")
                .unwrap_err()
                .to_string()
                .contains("holds no queries")
        );
        let big = format!("-- sparrow notebook: x\n{MARKER}\n{}", "x".repeat(65_537));
        assert!(
            parse_file(&big)
                .unwrap_err()
                .to_string()
                .contains("line 3: a query is limited to 65536 bytes")
        );
    }

    #[test]
    fn a_marker_inside_a_string_is_refused() {
        let text = format!("-- sparrow notebook: x\n{MARKER}\nSELECT '\n{MARKER}\n';\n");
        let m = parse_file(&text).unwrap_err().to_string();
        assert!(
            m.contains("line 3:") && m.contains("ends inside a string"),
            "{m}"
        );
    }

    #[test]
    fn sql_before_the_first_marker_is_refused() {
        let text = format!("-- sparrow notebook: x\n-- a note\nSELECT 1\n{MARKER}\nSELECT 2\n");
        let m = parse_file(&text).unwrap_err().to_string();
        assert!(
            m.contains("line 3:") && m.contains("before the first query"),
            "{m}"
        );
    }

    #[test]
    fn a_query_may_not_hold_the_marker() {
        assert!(check_query_sql(&format!("SELECT 1\n{MARKER}\nSELECT 2")).is_err());
        assert!(check_query_sql("   ").is_err());
        assert!(check_query_sql("SELECT 1").is_ok());
    }
}
