//! The Timeline Explorer CSV (Addendum D.6): UTF-8 with a BOM, `Timestamp` (UTC `yyyy-MM-dd HH:mm:ss`) first, then
//! `Source, Category, User, IP, Operation, Summary, Phase, Status, DecidedBy, ReviewState, FindingIds, EvidenceRef`.
//! Cells keep the raw stored text; the csv crate quotes commas, quotes and newlines. One exception, against
//! spreadsheet formula injection (the evidence text can be attacker-controlled: rule names, subjects, user agents,
//! display names, and the CSV may be opened in Excel): every TEXT cell whose first character is `=`, `+`, `-`,
//! `@`, TAB or CR is prefixed with a single quote `'` (OWASP CSV-injection guidance). The Timestamp and the
//! FindingIds (hex ids) are left as they are; a character in the middle of a cell is never touched.
//!
//! Scope `Verified` writes the curated timeline entries (one row each, in event-time order). Scope `All` writes
//! every row of the `timeline` view, STREAMED through a statement iterator (a case can hold 100k+ rows; nothing
//! is collected), each carrying the phase, status and decision of the verified entry that cites it (the earliest by event time, then
//! entry id). The file
//! ends with one record (Source `sparrow-export`, Category `header`, Timestamp = the generation time) that carries the
//! export header.

use super::header;
use super::{at, when};
use crate::Result;
use crate::case::read::{TimelineFilter, timeline_where};
use crate::case::timeline_entries::{self, Entry};
use chrono::{DateTime, Utc};
use duckdb::{Connection, params_from_iter};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

pub const COLUMNS: [&str; 13] = [
    "Timestamp",
    "Source",
    "Category",
    "User",
    "IP",
    "Operation",
    "Summary",
    "Phase",
    "Status",
    "DecidedBy",
    "ReviewState",
    "FindingIds",
    "EvidenceRef",
];

/// Test-only probe (never compiled into a normal build): the number of timeline rows `Scope::All` has fetched from
/// the statement on this thread, so a test can show that bytes reach the sink while most rows are still unread.
#[cfg(any(test, feature = "test-fixtures"))]
#[doc(hidden)]
pub mod probe {
    use std::cell::Cell;

    thread_local! {
        static FETCHED: Cell<u64> = const { Cell::new(0) };
    }

    pub fn reset() {
        FETCHED.with(|c| c.set(0));
    }

    pub fn fetched() -> u64 {
        FETCHED.with(Cell::get)
    }

    pub(super) fn bump() {
        FETCHED.with(|c| c.set(c.get() + 1));
    }
}

/// `cell` as a CSV text cell: prefixed with `'` when a spreadsheet would read it as a formula (first character
/// `=`, `+`, `-`, `@`, TAB or CR).
pub fn neutralise(cell: &str) -> String {
    match cell.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => format!("'{cell}"),
        _ => cell.to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Verified,
    All,
}

#[derive(Debug, Clone)]
pub struct CsvOpts {
    pub scope: Scope,
    /// Inclusive bounds on the event time.
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// The actor or target of the underlying evidence (case-insensitive).
    pub user: Option<String>,
    pub generated_at: DateTime<Utc>,
}

/// Write the CSV to `out`; returns the data rows written (not the header record or the closing record).
pub fn write(conn: &Connection, out: &mut dyn Write, opts: &CsvOpts) -> Result<u64> {
    #[cfg(any(test, feature = "test-fixtures"))]
    probe::reset();
    let head = header::build(conn, opts.generated_at)?;
    out.write_all("\u{feff}".as_bytes())
        .map_err(super::io_err)?;
    let mut w = csv::Writer::from_writer(out);
    w.write_record(COLUMNS).map_err(csv_err)?;
    let n = match opts.scope {
        Scope::All => write_all(conn, &mut w, opts)?,
        Scope::Verified => write_verified(conn, &mut w, opts)?,
    };
    let mut closing: [String; 13] = Default::default();
    closing[0] = when(&opts.generated_at);
    closing[1] = "sparrow-export".into();
    closing[2] = "header".into();
    closing[6] = head.one_line();
    put(&mut w, closing)?;
    w.flush().map_err(super::io_err)?;
    Ok(n)
}

/// One record: every cell but the Timestamp (0) and the FindingIds (11) goes through [`neutralise`].
fn put<W: Write>(w: &mut csv::Writer<W>, cells: [String; 13]) -> Result<()> {
    let cells: Vec<String> = cells
        .into_iter()
        .enumerate()
        .map(|(i, c)| if i == 0 || i == 11 { c } else { neutralise(&c) })
        .collect();
    w.write_record(&cells).map_err(csv_err)
}

fn csv_err(e: csv::Error) -> crate::Error {
    crate::Error::Invalid(format!("csv: {e}"))
}

fn write_all<W: Write>(conn: &Connection, w: &mut csv::Writer<W>, opts: &CsvOpts) -> Result<u64> {
    let (filter, args) = timeline_where(
        conn,
        &TimelineFilter {
            user: opts.user.clone(),
            from: opts.from,
            to: opts.to,
            ..TimelineFilter::default()
        },
    )?;
    // Not cached: a sort and an aggregate (the cited CTE) planned on an empty case misread real rows later.
    let mut stmt = conn.prepare(&format!(
        "WITH cited AS ( \
           SELECT ev.source_table, ev.record_key, arg_min(CAST(e.phase AS VARCHAR), struct_pack(t := e.event_time, id := e.entry_id)) AS phase, \
                  arg_min(e.decided_by, struct_pack(t := e.event_time, id := e.entry_id)) AS decided_by, \
                  arg_min(CAST(e.review_state AS VARCHAR), struct_pack(t := e.event_time, id := e.entry_id)) AS review_state \
           FROM timeline_entry_evidence ev JOIN timeline_entries e ON e.entry_id = ev.entry_id \
           WHERE CAST(e.status AS VARCHAR) = 'verified' GROUP BY ev.source_table, ev.record_key) \
         SELECT epoch_us(t.event_time), t.source_table, CAST(t.category AS VARCHAR), t.actor_upn, t.ip, \
                t.operation, t.summary, c.phase, c.decided_by, c.review_state, to_json(t.finding_ids)::VARCHAR, \
                t.record_key \
         FROM timeline t LEFT JOIN cited c ON c.source_table = t.source_table AND c.record_key = t.record_key \
         WHERE {filter} ORDER BY t.event_time, t.source_table, t.record_key"
    ))?;
    let mut rows = stmt.query(params_from_iter(args.iter()))?;
    let mut n = 0u64;
    while let Some(r) = rows.next()? {
        #[cfg(any(test, feature = "test-fixtures"))]
        probe::bump();
        let when_text = when(&at(r.get::<_, Option<i64>>(0)?.unwrap_or_default()));
        let source: String = r.get(1)?;
        let phase: Option<String> = r.get(7)?;
        let finding_ids = r
            .get::<_, Option<String>>(10)?
            .and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok())
            .unwrap_or_default();
        let key: String = r.get(11)?;
        let text = |i: usize| -> duckdb::Result<String> {
            Ok(r.get::<_, Option<String>>(i)?.unwrap_or_default())
        };
        put(
            w,
            [
                when_text,
                source.clone(),
                text(2)?,
                text(3)?,
                text(4)?,
                text(5)?,
                text(6)?,
                phase.clone().unwrap_or_default(),
                if phase.is_some() {
                    "verified".into()
                } else {
                    String::new()
                },
                text(8)?,
                text(9)?,
                finding_ids.join(";"),
                format!("{source}:{key}"),
            ],
        )?;
        n += 1;
    }
    Ok(n)
}

fn write_verified<W: Write>(
    conn: &Connection,
    w: &mut csv::Writer<W>,
    opts: &CsvOpts,
) -> Result<u64> {
    let entries = timeline_entries::list(conn, Some("verified"), None)?;
    let by_user: Option<BTreeSet<String>> = match &opts.user {
        None => None,
        Some(u) => {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT ev.entry_id FROM timeline_entry_evidence ev JOIN timeline t \
                   ON t.source_table = ev.source_table AND t.record_key = ev.record_key \
                 WHERE lower(t.actor_upn) = lower(?) OR lower(t.target) = lower(?)",
            )?;
            let rows = stmt.query_map([u, u], |r| r.get::<_, String>(0))?;
            Some(rows.collect::<std::result::Result<_, _>>()?)
        }
    };
    let findings = entry_finding_ids(conn)?;
    let mut n = 0u64;
    for e in entries.iter().filter(|e| keep(e, opts, by_user.as_ref())) {
        let summary = match e.narrative.as_deref().filter(|n| !n.is_empty()) {
            Some(n) => format!("{} — {n}", e.title),
            None => e.title.clone(),
        };
        put(
            w,
            [
                when(&e.event_time),
                "timeline_entry".to_string(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                summary,
                e.phase.clone(),
                e.status.clone(),
                e.decided_by.clone(),
                e.review_state.clone(),
                findings
                    .get(&e.entry_id)
                    .cloned()
                    .unwrap_or_default()
                    .join(";"),
                e.evidence
                    .iter()
                    .map(|r| r.text())
                    .collect::<Vec<_>>()
                    .join(";"),
            ],
        )?;
        n += 1;
    }
    Ok(n)
}

fn keep(e: &Entry, opts: &CsvOpts, by_user: Option<&BTreeSet<String>>) -> bool {
    opts.from.is_none_or(|f| e.event_time >= f)
        && opts.to.is_none_or(|t| e.event_time <= t)
        && by_user.is_none_or(|s| s.contains(&e.entry_id))
}

/// The finding ids of the timeline rows each entry cites (sorted, distinct).
fn entry_finding_ids(conn: &Connection) -> Result<BTreeMap<String, Vec<String>>> {
    let mut stmt = conn.prepare(
        "SELECT ev.entry_id, to_json(flatten(list(t.finding_ids)))::VARCHAR \
         FROM timeline_entry_evidence ev JOIN timeline t \
           ON t.source_table = ev.source_table AND t.record_key = ev.record_key GROUP BY ev.entry_id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
    })?;
    let mut out = BTreeMap::new();
    for row in rows {
        let (id, json) = row?;
        let ids: BTreeSet<String> = json
            .and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok())
            .unwrap_or_default()
            .into_iter()
            .collect();
        out.insert(id, ids.into_iter().collect());
    }
    Ok(out)
}
