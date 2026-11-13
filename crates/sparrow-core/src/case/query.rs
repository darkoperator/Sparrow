//! `sparrow query`: one read-only SELECT over a case, on a locked-down connection. All of the lockdown lives in this
//! file.
//!
//! Layers, each sufficient against writes on its own:
//! 1. **One SELECT only.** DuckDB's own parser checks the text: `json_serialize_sql` serializes SELECT statements
//!    only, so any other statement (INSERT, COPY, ATTACH, SET, PRAGMA, CALL, EXPORT, LOAD, INSTALL, a transaction,
//!    ...) fails, and the parsed result must hold exactly one statement, so a second statement after `;` (also one
//!    hidden behind a comment) is refused. The query that runs is DuckDB's re-rendering of that one parsed SELECT, so
//!    comments and text after it never reach execution. The check runs on its own in-memory instance with no case
//!    attached.
//! 2. **A separate, locked instance.** A fresh in-memory DuckDB with extension auto-install/auto-load and community
//!    extensions off, the case `ATTACH`ed `READ_ONLY`, then `enable_external_access = false` (no file, network or
//!    environment access: read_csv, glob, COPY, ATTACH, getenv) and `lock_configuration = true` (no SET can undo it).
//!    The lockdown is probed before the query runs; if a probe succeeds the query is refused.
//! 3. **Never a writer.** The case file is only ever attached read-only, so no statement can change it.
//!
//!
//! **In the review app** the case's own writer instance is locked down once after opening (`Case::lock_down`);
//! `run_on` runs the one parsed SELECT on it inside a transaction that is always rolled back. Layers 1 and the
//! lockdown hold; layer 3 (a read-only attach) is replaced by the rollback.
//!
//! The query sees every table and view of the case, including `case_meta` (the case id, the audit chain's
//! `audit_head` and `audit_verified` bookkeeping, and `db::POST_MIGRATION_PENDING` and
//! `db::CREDENTIAL_FAILURE_CODES`). That is harmless: they are not secret, and reading them changes
//! nothing; the audit chain's integrity comes from `audit verify`, not from hiding them.

use crate::export::timeline_csv::neutralise;
use crate::{Case, Error, Result};
use duckdb::{Connection, params};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthChar;

#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    pub columns: Vec<String>,
    /// Each value as JSON (DuckDB's `to_json` of the column).
    pub rows: Vec<Vec<Value>>,
    /// True when the query has more rows than the limit.
    pub truncated: bool,
    /// True when the query's top-level SELECT has an ORDER BY (DuckDB's parse, not a text search): only then are
    /// pages at different offsets slices of one stable order.
    pub ordered: bool,
}

/// The largest `offset` [`run_on`] accepts.
pub const MAX_OFFSET: usize = 100_000_000;

/// The most rows [`export_csv_on`] writes in the app (`capped` reports that more existed).
pub const EXPORT_CAP: u64 = 1_000_000;

/// What [`check_on`] found: `ok`, or the first error with where it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CheckError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckError {
    /// DuckDB's message without its `LINE n:` excerpt and caret (the editor marks the place instead).
    pub message: String,
    pub kind: CheckKind,
    /// UTF-16 code-unit offsets into the checked text (what CodeMirror uses): the start of the offending token and
    /// its end (else `from + 1`), both within the text. Absent when DuckDB gave no position.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<usize>,
    /// DuckDB's "Did you mean" / "Candidate bindings" / "Candidate tables" names, in its order.
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckKind {
    Syntax,
    Binder,
    Catalog,
    Other,
}

/// What [`export_csv_on`] wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Exported {
    /// Data rows written (not the header).
    pub rows: u64,
    /// True when the query had more rows than the cap.
    pub capped: bool,
}

/// The one SELECT of a query, as DuckDB's parser saw it.
struct Parsed {
    /// Re-rendered by the parser: no comments, no trailing text.
    select: String,
    /// The top-level node has an ORDER BY modifier.
    ordered: bool,
}

/// Why the parser refused a query: the message `the_select` reports, and the parser's error position (code points
/// into the text) when it gave one.
struct Refusal {
    message: String,
    position: Option<usize>,
}

/// The one SELECT in `sql`, or why it is not one. Runs on its own in-memory instance with no case attached.
fn parse_select(sql: &str) -> Result<std::result::Result<Parsed, Refusal>> {
    let parser = Connection::open_in_memory()?;
    let parsed: String =
        parser.query_row("SELECT json_serialize_sql(?::VARCHAR)", params![sql], |r| {
            r.get(0)
        })?;
    let v: Value = serde_json::from_str(&parsed)
        .map_err(|e| Error::Invalid(format!("the query parser returned invalid JSON: {e}")))?;
    if v["error"] != Value::Bool(false) {
        return Ok(Err(Refusal {
            message: {
                let m = format!(
                    "query accepts one SELECT statement only: {}",
                    v["error_message"].as_str().unwrap_or("not a SELECT")
                );
                match hint_for(&m) {
                    Some(h) => format!("{m}\nhint: {h}"),
                    None => m,
                }
            },
            position: v["position"].as_str().and_then(|p| p.parse().ok()),
        }));
    }
    let n = v["statements"].as_array().map_or(0, Vec::len);
    if n != 1 {
        return Ok(Err(Refusal {
            message: format!("query accepts exactly one SELECT statement, got {n}"),
            position: None,
        }));
    }
    let ordered = v["statements"][0]["node"]["modifiers"]
        .as_array()
        .is_some_and(|m| m.iter().any(|m| m["type"] == "ORDER_MODIFIER"));
    let one = serde_json::json!({ "error": false, "statements": [v["statements"][0].clone()] });
    let select: String = parser.query_row(
        "SELECT json_deserialize_sql(?::JSON)",
        params![one.to_string()],
        |r| r.get(0),
    )?;
    Ok(Ok(Parsed { select, ordered }))
}

/// The one SELECT in `sql` (see [`parse_select`]); `Error::Invalid` for anything else.
fn the_select(sql: &str) -> Result<Parsed> {
    parse_select(sql)?.map_err(|r| Error::Invalid(r.message))
}

/// The locked query instance with the case attached read-only as `c`.
fn locked(case_path: &Path) -> Result<Connection> {
    if !case_path.is_file() {
        return Err(Error::NotFound(format!(
            "case database {}",
            case_path.display()
        )));
    }
    let conn = Connection::open_in_memory()?;
    crate::db::cap_memory(&conn, true)?;
    conn.execute_batch(
        "SET autoinstall_known_extensions = false; SET autoload_known_extensions = false; \
         SET allow_community_extensions = false;",
    )?;
    let file = case_path.display().to_string().replace('\'', "''");
    conn.execute_batch(&format!("ATTACH '{file}' AS c (READ_ONLY); USE c;"))
        .map_err(|e| crate::db::lock_error(case_path, e))?;
    crate::db::migrations::check_readable(&conn)?;
    conn.execute_batch("SET enable_external_access = false; SET lock_configuration = true;")?;
    probe_lockdown(&conn)?;
    Ok(conn)
}

/// Prove the lockdown holds on `conn`: each attempt to undo it or reach outside the process must fail, else
/// `Error::Invalid`. Shared by [`locked`] and `Case::lock_down`.
pub(crate) fn probe_lockdown(conn: &Connection) -> Result<()> {
    let probe_file =
        std::env::temp_dir().join(format!("sparrow-query-probe-{}.duckdb", std::process::id()));
    let attach_probe = format!(
        "ATTACH '{}' AS sparrow_probe",
        probe_file.display().to_string().replace('\'', "''")
    );
    for probe in [
        "SET enable_external_access = true",
        "SET lock_configuration = false",
        "SELECT * FROM read_csv('/dev/null')",
        "SELECT getenv('HOME')",
        attach_probe.as_str(),
    ] {
        if conn.execute_batch(probe).is_ok() {
            let _ = std::fs::remove_file(&probe_file);
            return Err(Error::Invalid(format!(
                "the query connection is not locked down ({probe} succeeded)"
            )));
        }
    }
    Ok(())
}

/// The tables and views [`run`] can read: every table and view of the case (not DuckDB's own catalog objects), with
/// their table and column comments, read from the same locked connection; only `table` when given.
pub fn schema(case_path: &Path, table: Option<&str>) -> Result<Vec<crate::db::TableInfo>> {
    let conn = locked(case_path)?;
    crate::db::describe::describe_conn(&conn, table)
}

/// Run one SELECT over the case at `case_path`, returning at most `limit` rows.
pub fn run(case_path: &Path, sql: &str, limit: usize) -> Result<QueryResult> {
    let parsed = the_select(sql)?;
    let conn = locked(case_path)?;
    run_select(&conn, &parsed, limit, 0)
}

/// `parsed` (from [`the_select`]) on `conn`: at most `limit` rows after skipping `offset`.
fn run_select(
    conn: &Connection,
    parsed: &Parsed,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    run_select_inner(conn, parsed, limit, offset).map_err(with_hint)
}

/// `e` with the [`hint_for`] workaround appended when it is a DuckDB error that has one; anything else unchanged.
///
/// The error kind depends on whether a hint matched: a hinted `Error::Db` comes back as
/// `Error::Invalid` (its text is the database error plus the hint, so a caller that maps kinds
/// to exit codes sees an invalid query rather than a database failure); an unhinted one stays
/// `Error::Db`.
fn with_hint(e: Error) -> Error {
    match e {
        Error::Db(d) => match hint_for(&d.to_string()) {
            Some(h) => Error::Invalid(format!("database error: {d}\nhint: {h}")),
            None => Error::Db(d),
        },
        other => other,
    }
}

/// True when `word` is a DuckDB keyword (`duckdb_keywords()`), so a bare alias of it fails to parse.
fn is_keyword(word: &str) -> bool {
    Connection::open_in_memory()
        .and_then(|c| {
            c.query_row(
                "SELECT count(*) FROM duckdb_keywords() WHERE keyword_name = lower(?)",
                params![word],
                |r| r.get::<_, i64>(0),
            )
        })
        .is_ok_and(|n| n > 0)
}

/// A short workaround for a known opaque DuckDB error, from its text.
fn hint_for(error_text: &str) -> Option<String> {
    if error_text.contains("extension 'icu'") {
        return Some(
            "time-zone functions need ICU, which is not loaded: cast first, e.g. date_trunc('day', CAST(event_time AS TIMESTAMP)) (values are UTC)"
                .into(),
        );
    }
    let rest = error_text.split("syntax error at or near \"").nth(1)?;
    let word = &rest[..rest.find('"')?];
    if word.is_empty() || !is_keyword(word) {
        return None;
    }
    Some(format!(
        "\"{word}\" is a keyword: quote it (\"{word}\") or alias with AS"
    ))
}

fn run_select_inner(
    conn: &Connection,
    parsed: &Parsed,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let select = &parsed.select;
    let columns = {
        let mut stmt = conn.prepare(&format!("SELECT * FROM ({select}) LIMIT 0"))?;
        let _ = stmt.query([])?;
        stmt.column_names()
    };
    let limit_plus = i64::try_from(limit).unwrap_or(i64::MAX - 1) + 1;
    let offset = i64::try_from(offset).unwrap_or(i64::MAX);
    let mut stmt = conn.prepare(&format!(
        "SELECT to_json(COLUMNS(*))::VARCHAR FROM ({select}) LIMIT ? OFFSET ?"
    ))?;
    let mut rows_iter = stmt.query(params![limit_plus, offset])?;
    let mut rows = Vec::new();
    while let Some(r) = rows_iter.next()? {
        let mut row = Vec::with_capacity(columns.len());
        for i in 0..columns.len() {
            let text: Option<String> = r.get(i)?;
            row.push(match text {
                None => Value::Null,
                Some(t) => serde_json::from_str(&t).unwrap_or(Value::String(t)),
            });
        }
        rows.push(row);
    }
    let truncated = rows.len() > limit;
    rows.truncate(limit);
    Ok(QueryResult {
        columns,
        rows,
        truncated,
        ordered: parsed.ordered,
    })
}

fn need_locked(case: &Case, what: &str) -> Result<()> {
    if case.is_locked_down()? {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "{what} needs a locked-down case (Case::lock_down)"
        )))
    }
}

/// Like [`schema`], on a case this process holds open and has locked down with `Case::lock_down`.
pub fn schema_on(case: &Case, table: Option<&str>) -> Result<Vec<crate::db::TableInfo>> {
    need_locked(case, "schema_on")?;
    crate::db::describe::describe_conn(case.conn(), table)
}

/// Like [`run`], on the case's own locked-down writer instance: the one parsed SELECT runs inside a transaction that
/// is always rolled back, as `SELECT * FROM (<select>) LIMIT limit OFFSET offset` (offset at most [`MAX_OFFSET`]).
/// Refused when the case is not locked down or a transaction is already open (the caller's transaction is left
/// alone).
pub fn run_on(case: &Case, sql: &str, limit: usize, offset: usize) -> Result<QueryResult> {
    case.ensure_usable()?;
    need_locked(case, "run_on")?;
    if offset > MAX_OFFSET {
        return Err(Error::Invalid(format!(
            "the offset is at most {MAX_OFFSET}, got {offset}"
        )));
    }
    let parsed = the_select(sql)?;
    in_rolled_back_tx(case, |conn| run_select(conn, &parsed, limit, offset))
}

/// Check `sql` without running it: DuckDB's parser (as [`run_on`] does), then `prepare` of the analyst's ORIGINAL
/// text on the locked case inside a rolled-back transaction, which binds it (tables, columns, functions) but
/// executes nothing. A parser refusal (also a second statement or a non-SELECT) is `syntax`; a prepare error is
/// `binder`, `catalog` or `other` by DuckDB's error type. Offsets are UTF-16 code units into `sql`.
pub fn check_on(case: &Case, sql: &str) -> Result<Check> {
    case.ensure_usable()?;
    need_locked(case, "check_on")?;
    let error = match parse_select(sql)? {
        Err(refusal) => {
            // The parser's position counts code points.
            let at = refusal
                .position
                .map(|cp| sql.char_indices().nth(cp).map_or(sql.len(), |(b, _)| b));
            Some(check_error(
                sql,
                CheckKind::Syntax,
                refusal.message,
                Vec::new(),
                at,
            ))
        }
        Ok(_) => in_rolled_back_tx(case, |conn| Ok(conn.prepare(sql).err()))?
            .map(|e| prepare_error(sql, &e.to_string())),
    };
    Ok(Check {
        ok: error.is_none(),
        error,
    })
}

/// A [`CheckError`] marking the token at byte `at` of `sql`.
fn check_error(
    sql: &str,
    kind: CheckKind,
    message: String,
    suggestions: Vec<String>,
    at: Option<usize>,
) -> CheckError {
    let (from, to) = match at {
        Some(b) => {
            let b = b.min(sql.len());
            let from = sql[..b].encode_utf16().count();
            let len = sql[b..token_end(sql, b)].encode_utf16().count();
            (Some(from), Some(from + len))
        }
        None => (None, None),
    };
    CheckError {
        message,
        kind,
        from,
        to,
        suggestions,
    }
}

/// The byte where the token starting at byte `b` ends: a quoted identifier or string through its closing quote, a
/// word, else the one character at `b`; `b` itself at the end of the text.
fn token_end(sql: &str, b: usize) -> usize {
    let rest = &sql[b..];
    let Some(first) = rest.chars().next() else {
        return b;
    };
    let one = b + first.len_utf8();
    if first == '"' || first == '\'' {
        // A doubled quote is an escaped one.
        let mut it = rest.char_indices().skip(1).peekable();
        while let Some((i, ch)) = it.next() {
            if ch == first {
                if it.peek().is_some_and(|&(_, n)| n == first) {
                    it.next();
                } else {
                    return b + i + 1;
                }
            }
        }
        return one;
    }
    let word = |ch: char| ch.is_alphanumeric() || ch == '_' || ch == '$';
    if !word(first) {
        return one;
    }
    rest.char_indices()
        .find(|&(_, ch)| !word(ch))
        .map_or(sql.len(), |(i, _)| b + i)
}

/// A `prepare` error of the analyst's text as a [`CheckError`]: DuckDB's error type, the message without its
/// location excerpt, the names it suggests, and the place its `LINE n:` excerpt and caret point at.
fn prepare_error(sql: &str, text: &str) -> CheckError {
    let (body, location) = split_location(text);
    let kind = if body.starts_with("Binder Error") {
        CheckKind::Binder
    } else if body.starts_with("Catalog Error") {
        CheckKind::Catalog
    } else if body.starts_with("Parser Error") {
        CheckKind::Syntax
    } else {
        CheckKind::Other
    };
    let at = location.and_then(|(line, excerpt, col)| locate(sql, line, excerpt, col));
    let mut message = body.trim_end().to_string();
    if let Some(h) = hint_for(&message) {
        message = format!("{message}\nhint: {h}");
    }
    check_error(sql, kind, message, suggestions(body), at)
}

/// DuckDB's error text split into the message and its trailing location block (`\n\nLINE n: <excerpt>\n<spaces>^`):
/// the line number, the excerpt, and the caret's column within the excerpt (after the `LINE n: ` prefix).
fn split_location(text: &str) -> (&str, Option<(usize, &str, usize)>) {
    let parse = || {
        let at = text.rfind("\n\nLINE ")?;
        let (first, caret) = text[at + 2..].split_once('\n')?;
        let pad = caret.strip_suffix('^')?;
        if !pad.bytes().all(|c| c == b' ') {
            return None;
        }
        let (n, excerpt) = first.strip_prefix("LINE ")?.split_once(": ")?;
        let line: usize = n.parse().ok()?;
        let col = pad.len().checked_sub(format!("LINE {n}: ").len())?;
        Some((at, (line, excerpt, col)))
    };
    match parse() {
        Some((at, loc)) => (&text[..at], Some(loc)),
        None => (text, None),
    }
}

/// The byte of `sql` that DuckDB's caret points at (`QueryErrorContext::Format`). DuckDB shows line `line` (counting
/// `\n`, and `\r` not followed by `\n`, as newlines), cut to about 120 columns around the error with `...` at a cut
/// end, and puts the caret `col` render columns into the excerpt (each grapheme counts its first code point's
/// display width, so a tab counts 0). Inverted here: find the excerpt in that line, then walk its graphemes until
/// `col` columns have passed, skipping zero-width ones (no token starts with one).
fn locate(sql: &str, line: usize, excerpt: &str, col: usize) -> Option<usize> {
    let bytes = sql.as_bytes();
    let (mut start, mut n) = (0, 1);
    for (i, &c) in bytes.iter().enumerate() {
        if n == line {
            break;
        }
        if c == b'\n' || (c == b'\r' && bytes.get(i + 1) != Some(&b'\n')) {
            n += 1;
            start = i + 1;
        }
    }
    if n != line {
        return None;
    }
    let end = sql[start..]
        .find(['\n', '\r'])
        .map_or(sql.len(), |i| start + i);
    let text = &sql[start..end];
    let find = |ex: &str| {
        text.find(ex)
            .or_else(|| ex.strip_suffix("...").and_then(|ex| text.find(ex)))
    };
    // Where the excerpt starts in the line, and the width of the cut mark DuckDB put before it.
    let (skip, cut) = match find(excerpt) {
        Some(0) => (0, 0),
        _ => (find(excerpt.strip_prefix("...")?)?, 3),
    };
    let col = col.checked_sub(cut)?;
    let mut seen = 0;
    for (i, g) in text[skip..].grapheme_indices(true) {
        let w = g
            .chars()
            .next()
            .and_then(UnicodeWidthChar::width)
            .unwrap_or(0);
        if seen >= col && w > 0 {
            return Some(start + skip + i);
        }
        seen += w;
    }
    Some(end)
}

/// The names DuckDB suggests: the quoted names on its `Did you mean` and `Candidate bindings` / `Candidate tables`
/// lines, first mention first.
fn suggestions(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in body.lines().map(str::trim_start) {
        if !["Did you mean", "Candidate bindings", "Candidate tables"]
            .iter()
            .any(|p| line.starts_with(p))
        {
            continue;
        }
        // Quoted names sit at the odd positions between quotes.
        for name in line.split('"').skip(1).step_by(2) {
            if !name.is_empty() && !out.iter().any(|o| o == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// How a result column is written to CSV.
#[derive(Clone, Copy)]
enum CsvCell {
    /// Numbers and booleans: their text, never a formula.
    Plain,
    /// Timestamps (with or without time zone): the core's `ts_text` form, UTC with microseconds.
    Timestamp,
    /// Lists, structs, maps, unions: their JSON, neutralised.
    Json,
    /// Everything else (text, dates, intervals, ...): DuckDB's text form, neutralised.
    Text,
}

/// Run the one SELECT in `sql` on the locked case (in a rolled-back transaction, like [`run_on`]) and stream every
/// row, at most `cap`, to `out` as CSV: a UTF-8 BOM, a header of the column names, then the rows, with the timeline
/// CSV's cell rules ([`neutralise`] on every text cell and the header; the csv crate's quoting). NULL is an empty
/// cell. `capped` is true when the query had more rows than `cap`. Nothing is written when the query is refused or
/// fails to bind; a failure mid-way (an interrupt) leaves a partial stream, so the caller writes to a temporary file.
pub fn export_csv_on(
    case: &Case,
    sql: &str,
    out: &mut dyn std::io::Write,
    cap: u64,
) -> Result<Exported> {
    case.ensure_usable()?;
    need_locked(case, "export_csv_on")?;
    let parsed = the_select(sql)?;
    let select = &parsed.select;
    export_in_tx(case, select, cap, out).map_err(with_hint)
}

fn export_in_tx(
    case: &Case,
    select: &str,
    cap: u64,
    out: &mut dyn std::io::Write,
) -> Result<Exported> {
    use duckdb::arrow::datatypes::DataType as T;
    in_rolled_back_tx(case, |conn| {
        let (columns, kinds) = {
            let mut stmt = conn.prepare(&format!("SELECT * FROM ({select}) LIMIT 0"))?;
            let _ = stmt.query([])?;
            let kinds: Vec<CsvCell> = (0..stmt.column_count())
                .map(|i| match stmt.column_type(i) {
                    T::Timestamp(..) => CsvCell::Timestamp,
                    T::List(_)
                    | T::LargeList(_)
                    | T::FixedSizeList(..)
                    | T::Struct(_)
                    | T::Map(..)
                    | T::Union(..) => CsvCell::Json,
                    t if t.is_numeric() || t == T::Boolean => CsvCell::Plain,
                    _ => CsvCell::Text,
                })
                .collect();
            (stmt.column_names(), kinds)
        };
        // By position: result column names may repeat.
        let exprs: Vec<String> = kinds
            .iter()
            .enumerate()
            .map(|(i, k)| match k {
                CsvCell::Timestamp => format!("epoch_us(#{})", i + 1),
                CsvCell::Json => format!("to_json(#{})::VARCHAR", i + 1),
                CsvCell::Plain | CsvCell::Text => format!("#{}::VARCHAR", i + 1),
            })
            .collect();
        let cap_plus = i64::try_from(cap).unwrap_or(i64::MAX - 1) + 1;
        let mut stmt = conn.prepare(&format!(
            "SELECT {} FROM ({select}) LIMIT ?",
            exprs.join(", ")
        ))?;
        let mut rows = stmt.query(params![cap_plus])?;
        let csv_err = |e: csv::Error| Error::Invalid(format!("csv: {e}"));
        let io_err = |e: std::io::Error| Error::Invalid(format!("cannot write the CSV: {e}"));
        out.write_all("\u{feff}".as_bytes()).map_err(io_err)?;
        let mut w = csv::Writer::from_writer(out);
        w.write_record(columns.iter().map(|c| neutralise(c)))
            .map_err(csv_err)?;
        let (mut n, mut capped) = (0u64, false);
        let mut cells = Vec::with_capacity(kinds.len());
        while let Some(r) = rows.next()? {
            if n == cap {
                capped = true;
                break;
            }
            cells.clear();
            for (i, k) in kinds.iter().enumerate() {
                cells.push(match k {
                    CsvCell::Timestamp => r
                        .get::<_, Option<i64>>(i)?
                        .map(|us| {
                            chrono::DateTime::from_timestamp_micros(us)
                                .map_or_else(|| us.to_string(), |t| crate::case::audit::ts_text(&t))
                        })
                        .unwrap_or_default(),
                    CsvCell::Plain => r.get::<_, Option<String>>(i)?.unwrap_or_default(),
                    CsvCell::Json | CsvCell::Text => {
                        neutralise(&r.get::<_, Option<String>>(i)?.unwrap_or_default())
                    }
                });
            }
            w.write_record(&cells).map_err(csv_err)?;
            n += 1;
        }
        w.flush().map_err(io_err)?;
        Ok(Exported { rows: n, capped })
    })
}

/// `f` inside a transaction that is always rolled back. A failed ROLLBACK is tried once more; if that fails too the
/// case is made unusable (no further `run_on`, `ensure_usable` fails) and the error says so; the error of `f` wins
/// when both fail.
fn in_rolled_back_tx<T>(case: &Case, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
    let conn = case.conn();
    conn.execute_batch("BEGIN TRANSACTION").map_err(|e| {
        Error::Invalid(format!(
            "run_on refuses to run inside an open transaction: {e}"
        ))
    })?;
    let out = f(conn);
    let ended = conn
        .execute_batch("ROLLBACK")
        .or_else(|_| conn.execute_batch("ROLLBACK"));
    if let Err(e) = ended {
        let msg = format!(
            "the case's read-only query transaction could not be rolled back: {e}; this Case is unusable, open the case again"
        );
        case.poison(msg.clone());
        return out.and(Err(Error::Invalid(msg)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked_case() -> Case {
        let c = Case::in_memory().unwrap();
        c.lock_down().unwrap();
        c
    }

    #[test]
    fn a_write_inside_the_transaction_is_rolled_back() {
        let c = locked_case();
        let n = |c: &Case| -> i64 {
            c.conn()
                .query_row("SELECT count(*) FROM case_meta WHERE key = 'zz'", [], |r| {
                    r.get(0)
                })
                .unwrap()
        };
        in_rolled_back_tx(&c, |conn| {
            conn.execute_batch("INSERT INTO case_meta VALUES ('zz', '1')")?;
            let inside: i64 =
                conn.query_row("SELECT count(*) FROM case_meta WHERE key = 'zz'", [], |r| {
                    r.get(0)
                })?;
            assert_eq!(inside, 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(n(&c), 0);
        // A write outside any transaction works afterwards.
        crate::case::write::in_tx(c.conn(), |tx| {
            tx.execute_batch("INSERT INTO case_meta VALUES ('zz', '2')")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(n(&c), 1);
    }

    #[test]
    fn an_error_inside_the_transaction_still_rolls_back() {
        let c = locked_case();
        let e = run_on(&c, "SELECT CAST('x' AS INTEGER)", 10, 0).unwrap_err();
        assert!(!matches!(e, Error::NotFound(_)), "{e}");
        c.conn()
            .execute_batch("BEGIN TRANSACTION; ROLLBACK")
            .unwrap();
        assert_eq!(run_on(&c, "SELECT 1", 10, 0).unwrap().rows.len(), 1);
    }

    #[test]
    fn a_failed_rollback_fails_the_case_closed_and_keeps_the_query_error() {
        // Ending the transaction inside `f` makes the ROLLBACK fail (no transaction is active), both times.
        let c = locked_case();
        let r: Result<()> = in_rolled_back_tx(&c, |conn| {
            conn.execute_batch("COMMIT")?;
            Ok(())
        });
        let e = r.unwrap_err();
        assert!(
            matches!(&e, Error::Invalid(m) if m.contains("rolled back")),
            "{e}"
        );
        assert!(c.ensure_usable().is_err());
        assert!(run_on(&c, "SELECT 1", 10, 0).is_err());

        // When the query failed too, its error is the one reported, and the case is still marked unusable.
        let c = locked_case();
        let r: Result<()> = in_rolled_back_tx(&c, |conn| {
            conn.execute_batch("COMMIT")?;
            Err(Error::Invalid("the query failed".into()))
        });
        assert!(
            matches!(&r, Err(Error::Invalid(m)) if m == "the query failed"),
            "{r:?}"
        );
        assert!(c.ensure_usable().is_err());
    }
}
