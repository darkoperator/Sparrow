//! The access report's exports: the CSV for legal (one row per item, every account; UTF-8 with a BOM, ISO 8601 UTC
//! times, every text cell through [`neutralise`]) and the Markdown summary for the final report (a row per account with
//! the counts per category, then the coverage gaps). Item text can be attacker-controlled (subjects, file names).

use super::text::md_cell;
use super::timeline_csv::neutralise;
use crate::Result;
use crate::case::access::{AccessReport, Category, Tile};
use chrono::{DateTime, Utc};
use std::io::Write;

pub const CSV_COLUMNS: [&str; 18] = [
    "account",
    "category",
    "attribution",
    "accessed_utc",
    "action",
    "item",
    "location",
    "from",
    "to",
    "size_bytes",
    "item_time_utc",
    "app",
    "ip",
    "session_id",
    "owner",
    "note",
    "source",
    "record_id",
];

fn iso(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn csv_err(e: csv::Error) -> crate::Error {
    crate::Error::Invalid(format!("csv: {e}"))
}

/// Every item of every account in `report`.
pub fn write_csv(report: &AccessReport, out: &mut impl Write) -> Result<()> {
    out.write_all("\u{feff}".as_bytes())
        .map_err(super::io_err)?;
    let mut w = csv::Writer::from_writer(out);
    w.write_record(CSV_COLUMNS).map_err(csv_err)?;
    let text = |s: &Option<String>| s.as_deref().map(neutralise).unwrap_or_default();
    for a in &report.accounts {
        for i in &a.items {
            w.write_record([
                neutralise(&i.account),
                i.category.as_str().to_string(),
                i.attribution.as_str().to_string(),
                iso(&i.accessed),
                neutralise(&i.action),
                text(&i.item),
                text(&i.location),
                text(&i.from),
                text(&i.to),
                i.size_bytes.map(|n| n.to_string()).unwrap_or_default(),
                i.item_time.as_ref().map(iso).unwrap_or_default(),
                text(&i.app),
                text(&i.ip),
                text(&i.session_id),
                text(&i.owner),
                text(&i.note),
                neutralise(&i.source),
                neutralise(&i.record_key),
            ])
            .map_err(csv_err)?;
        }
    }
    w.flush().map_err(super::io_err)?;
    Ok(())
}

fn status_label(status: &str) -> &str {
    match status {
        "none" => "no coverage data",
        "not_licensed" => "not licensed",
        "not_enabled" => "not enabled",
        "beyond_retention" => "beyond retention",
        "available_not_collected" => "not collected",
        other => other,
    }
}

/// A tile as a table cell: `48`, `48 (+3 by time)`, `0 (1 folder synced)`, `0 none seen`, or `0 (<why it cannot say>)`.
fn cell(t: &Tile) -> String {
    let n = match t.by_time {
        0 => t.direct.to_string(),
        k => format!("{} (+{k} by time)", t.direct),
    };
    if t.direct + t.by_time > 0 {
        n
    } else if let Some(q) = &t.qualifier {
        // Nothing counted but something exposed (folders synced as a whole).
        format!("0 ({})", md_cell(q))
    } else if t.none_seen {
        "0 none seen".to_string()
    } else {
        format!("0 ({})", status_label(&t.coverage.status))
    }
}

/// The summary table, then the coverage gaps per account.
pub fn write_summary(report: &AccessReport, out: &mut impl Write) -> Result<()> {
    let mut s = String::from("| Account |");
    for c in Category::ALL {
        s.push_str(&format!(" {} |", c.title()));
    }
    s.push_str("\n|---|");
    s.push_str(&"---|".repeat(Category::ALL.len()));
    s.push('\n');
    for a in &report.accounts {
        s.push_str(&format!("| {} |", md_cell(&a.account)));
        for t in &a.tiles {
            s.push_str(&format!(" {} |", cell(t)));
        }
        s.push('\n');
    }
    s.push_str("\n### Coverage gaps\n\n");
    for a in &report.accounts {
        for g in &a.gaps {
            s.push_str(&format!("- {}: {}\n", md_cell(&a.account), md_cell(g)));
        }
    }
    out.write_all(s.as_bytes()).map_err(super::io_err)?;
    Ok(())
}
