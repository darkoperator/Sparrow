//! The XLSX workbook (Addendum D.6). Sheets: Summary, Accounts, Findings, Timeline, Indicators, Devices, Devices (low confidence), Evidence gaps, Audit.
//! Accounts is the roll-up detection builds (one row per account, its addresses joined; empty, with the reason in
//! the Summary, when the roll-up is not current) and the Findings sheet has a `Facts` column (the stored facts as
//! compact JSON, or `{"facts_unavailable": ...}`; empty for a finding outside the facts families). Every
//! decision sheet has `DecidedBy`, `OnBehalfOf` and `ReviewState` columns plus an empty `Analyst notes` column for
//! work outside Sparrow. Frozen header row, filter, real date cells (`yyyy-mm-dd hh:mm:ss`, UTC) and fixed column
//! widths. Cells keep the raw stored text, as strings (a text that starts with `=` stays text). A date outside
//! Excel's range is written as ISO text with a note.

use super::devices_csv::{self, DEVICE_COLUMNS};
use super::facts_text::{self, FactRules};
use super::header;
use super::{
    Provenance, entry_provenance, evidence_gaps, finding_provenance, indicator_rows, legacy_objects,
};
use crate::case::{audit, read, timeline_entries};
use crate::data::DataDirs;
use crate::summary::summarize_conn;
use crate::{Error, Result};
use chrono::{DateTime, Datelike, Timelike, Utc};
use duckdb::Connection;
use rust_xlsxwriter::{ExcelDateTime, Format, Workbook, Worksheet};
use std::path::Path;

/// The sheets, in order.
pub const SHEETS: [&str; 9] = [
    "Summary",
    "Accounts",
    "Findings",
    "Timeline",
    "Indicators",
    "Devices",
    "Devices (low confidence)",
    "Evidence gaps",
    "Audit",
];

/// Excel holds at most this many characters in a cell.
const MAX_CELL_CHARS: usize = 32_000;

enum Cell {
    Empty,
    Text(String),
    Int(i64),
    Bool(bool),
    Time(Option<DateTime<Utc>>),
}

fn t(s: impl Into<String>) -> Cell {
    Cell::Text(s.into())
}

fn ot(s: Option<&str>) -> Cell {
    s.map(t).unwrap_or(Cell::Empty)
}

fn x(e: rust_xlsxwriter::XlsxError) -> Error {
    Error::Invalid(format!("workbook: {e}"))
}

/// Excel dates run from 1900-01-01 to 9999-12-31.
fn in_excel_range(d: &DateTime<Utc>) -> bool {
    (1900..=9999).contains(&d.year())
}

fn excel_time(d: &DateTime<Utc>) -> Result<ExcelDateTime> {
    ExcelDateTime::from_ymd(d.year() as u16, d.month() as u8, d.day() as u8)
        .and_then(|e| e.and_hms(d.hour() as u16, d.minute() as u8, d.second() as f64))
        .map_err(x)
}

fn clip(s: &str) -> String {
    if s.chars().count() <= MAX_CELL_CHARS {
        s.to_string()
    } else {
        let mut o: String = s.chars().take(MAX_CELL_CHARS).collect();
        o.push_str("…[truncated]");
        o
    }
}

/// One sheet: a header row (frozen, filtered, bold), then `rows`; `cols` are (header, width).
fn sheet(wb: &mut Workbook, name: &str, cols: &[(&str, f64)], rows: Vec<Vec<Cell>>) -> Result<()> {
    let bold = Format::new().set_bold();
    let date = Format::new().set_num_format("yyyy-mm-dd hh:mm:ss");
    let ws: &mut Worksheet = wb.add_worksheet();
    ws.set_name(name).map_err(x)?;
    for (c, (h, w)) in cols.iter().enumerate() {
        ws.write_string_with_format(0, c as u16, *h, &bold)
            .map_err(x)?;
        ws.set_column_width(c as u16, *w).map_err(x)?;
    }
    for (i, row) in rows.iter().enumerate() {
        let r = i as u32 + 1;
        for (c, cell) in row.iter().enumerate() {
            let c = c as u16;
            match cell {
                Cell::Empty => {}
                Cell::Text(s) => {
                    ws.write_string(r, c, clip(s)).map_err(x)?;
                }
                Cell::Int(n) => {
                    ws.write_number(r, c, *n as f64).map_err(x)?;
                }
                Cell::Bool(b) => {
                    ws.write_boolean(r, c, *b).map_err(x)?;
                }
                Cell::Time(Some(d)) if !in_excel_range(d) => {
                    // A date Excel cannot hold (before 1900-01-01, after 9999-12-31: a `DateTime.MinValue`
                    // sentinel, a mistyped year) is written as ISO text with a note, never an export failure.
                    ws.write_string(
                        r,
                        c,
                        format!(
                            "{} (outside Excel's date range; written as text)",
                            d.format("%Y-%m-%dT%H:%M:%SZ")
                        ),
                    )
                    .map_err(x)?;
                }
                Cell::Time(Some(d)) => {
                    ws.write_datetime_with_format(r, c, &excel_time(d)?, &date)
                        .map_err(x)?;
                }
                Cell::Time(None) => {}
            }
        }
    }
    ws.set_freeze_panes(1, 0).map_err(x)?;
    let last_row = (rows.len() as u32).max(1);
    ws.autofilter(0, 0, last_row, cols.len() as u16 - 1)
        .map_err(x)?;
    Ok(())
}

fn decision_cells(p: &Provenance) -> Vec<Cell> {
    vec![
        ot(p.decided_by.as_deref()),
        Cell::Time(p.decided_at),
        ot(p.on_behalf_of.as_deref()),
        ot(p.review_state.as_deref()),
        t(p.label()),
        ot(p.reviewed_by.as_deref()),
        Cell::Time(p.reviewed_at),
        ot(p.review_comment.as_deref()),
    ]
}

const DECISION_COLS: [(&str, f64); 8] = [
    ("DecidedBy", 18.0),
    ("DecidedAt", 20.0),
    ("OnBehalfOf", 18.0),
    ("ReviewState", 15.0),
    ("DecisionLabel", 34.0),
    ("ReviewedBy", 18.0),
    ("ReviewedAt", 20.0),
    ("ReviewComment", 30.0),
];

/// Write the workbook to `path`.
pub fn write(
    conn: &Connection,
    path: &Path,
    generated_at: DateTime<Utc>,
    dirs: &DataDirs,
) -> Result<()> {
    let head = header::build(conn, generated_at)?;
    let legacy = legacy_objects(conn)?;
    let mut wb = Workbook::new();

    // ---- Summary
    let summary = summarize_conn(conn)?;
    let mut rows: Vec<Vec<Cell>> = head
        .pairs()
        .into_iter()
        .map(|(k, v)| vec![t(k), t(v)])
        .collect();
    let d = &head.decisions;
    for (k, n) in [
        ("AI-decided, not reviewed", d.pending_review),
        ("Recorded before the audit trail", d.legacy),
        ("Accepted", d.accepted),
        ("Discarded", d.discarded),
    ] {
        rows.push(vec![t(format!("Decisions: {k}")), Cell::Int(n)]);
    }
    for ten in &summary.tenants {
        rows.push(vec![
            t(format!("Tenant {}", ten.tenant_key)),
            t(ten.tenant_name.clone().unwrap_or_default()),
        ]);
        rows.push(vec![
            t(format!("Domains ({})", ten.tenant_key)),
            t(ten.domains.join(", ")),
        ]);
    }
    let accounts = read::accounts(conn, None, None)?;
    rows.push(vec![
        t("Accounts"),
        t(match accounts.warnings.first() {
            Some(w) => w.clone(),
            None => format!("{} accounts with findings", accounts.total),
        }),
    ]);
    sheet(&mut wb, "Summary", &[("Item", 34.0), ("Value", 90.0)], rows)?;

    // ---- Accounts (facts, not decisions; empty when the roll-up is not current, the Summary says why)
    let reviewed = super::report_md::reviewed_counts(conn)?;
    let rows = accounts
        .accounts
        .iter()
        .map(|a| {
            let addresses = a
                .addresses
                .iter()
                .map(|x| format!("{} ({})", x.ip, x.reasons.join(", ")))
                .collect::<Vec<_>>()
                .join("; ");
            vec![
                t(&a.tenant_key),
                t(&a.upn),
                t(&a.worst_severity),
                Cell::Int(i64::from(a.finding_count)),
                t(serde_json::to_string(&a.by_severity).unwrap_or_default()),
                t(a.stages
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")),
                Cell::Time(a.first_suspicious),
                t(a.rules.join("; ")),
                t(addresses),
                Cell::Int(i64::from(a.addresses_total)),
                Cell::Bool(a.addresses_truncated),
                Cell::Int(i64::from(
                    reviewed
                        .get(&(a.tenant_key.clone(), a.upn.to_lowercase()))
                        .copied()
                        .unwrap_or(0),
                )),
            ]
        })
        .collect();
    sheet(
        &mut wb,
        "Accounts",
        &[
            ("Tenant", 14.0),
            ("Account", 32.0),
            ("WorstSeverity", 14.0),
            ("FindingCount", 13.0),
            ("BySeverity", 28.0),
            ("Stages", 40.0),
            ("FirstSuspicious", 20.0),
            ("Rules", 40.0),
            ("Addresses", 70.0),
            ("AddressesTotal", 15.0),
            ("AddressesTruncated", 18.0),
            ("Reviewed", 10.0),
        ],
        rows,
    )?;

    // ---- Findings
    // Rules are needed only to tell which findings should have facts when the enrichment is not current.
    let rules = FactRules::for_case(conn, dirs)?;
    let findings = read::finding_list(conn, &read::FindingFilter::default())?;
    let mut rows = Vec::new();
    for f in &findings {
        let mut row = vec![
            t(&f.finding_id),
            t(&f.tenant_key),
            ot(f.rule_id.as_deref()),
            t(&f.severity),
            t(&f.title),
            ot(f.actor_upn.as_deref()),
            Cell::Time(f.first_seen),
            Cell::Time(f.last_seen),
            t(&f.status),
            ot(f.disposition_reason.as_deref()),
            ot(f.assigned_to.as_deref()),
            Cell::Bool(f.rule_updated),
            Cell::Int(f.evidence_count),
        ];
        row.extend(decision_cells(&finding_provenance(f, &legacy)));
        let facts = read::finding_facts(conn, &f.finding_id, f.rule_id.as_deref(), &rules.set)?;
        row.push(
            facts
                .as_ref()
                .map(|x| t(facts_text::facts_json(x, &rules)))
                .unwrap_or(Cell::Empty),
        );
        row.push(Cell::Empty);
        rows.push(row);
    }
    let mut cols = vec![
        ("FindingId", 18.0),
        ("Tenant", 14.0),
        ("Rule", 14.0),
        ("Severity", 10.0),
        ("Title", 50.0),
        ("User", 30.0),
        ("FirstSeen", 20.0),
        ("LastSeen", 20.0),
        ("Status", 14.0),
        ("Reason", 40.0),
        ("AssignedTo", 18.0),
        ("RuleUpdated", 12.0),
        ("EvidenceCount", 14.0),
    ];
    cols.extend(DECISION_COLS);
    cols.push(("Facts", 60.0));
    cols.push(("Analyst notes", 40.0));
    sheet(&mut wb, "Findings", &cols, rows)?;

    // ---- Timeline (every timeline entry, with its status)
    let entries = timeline_entries::list(conn, None, None)?;
    let mut rows = Vec::new();
    for e in &entries {
        let mut row = vec![
            Cell::Time(Some(e.event_time)),
            t(&e.phase),
            t(&e.title),
            ot(e.narrative.as_deref()),
            t(&e.status),
            ot(e.supersedes.as_deref()),
            t(&e.entry_id),
            t(e.evidence
                .iter()
                .map(|r| r.text())
                .collect::<Vec<_>>()
                .join("; ")),
        ];
        row.extend(decision_cells(&entry_provenance(e, &legacy)));
        row.push(Cell::Empty);
        rows.push(row);
    }
    let mut cols = vec![
        ("Timestamp", 20.0),
        ("Phase", 16.0),
        ("Title", 50.0),
        ("Narrative", 60.0),
        ("Status", 12.0),
        ("Supersedes", 14.0),
        ("EntryId", 14.0),
        ("EvidenceRef", 60.0),
    ];
    cols.extend(DECISION_COLS);
    cols.push(("Analyst notes", 40.0));
    sheet(&mut wb, "Timeline", &cols, rows)?;

    // ---- Indicators
    let mut rows = Vec::new();
    for i in indicator_rows(conn)? {
        let mut row = vec![
            t(&i.indicator_id),
            ot(i.tenant_key.as_deref()),
            t(&i.ty),
            t(&i.value),
            t(&i.verdict),
            ot(i.note.as_deref()),
            t(&i.added_by),
            Cell::Time(Some(i.added_at)),
            Cell::Time(i.removed_at),
            ot(i.removed_by.as_deref()),
        ];
        row.extend(decision_cells(&i.prov));
        row.push(Cell::Empty);
        rows.push(row);
    }
    let mut cols = vec![
        ("IndicatorId", 18.0),
        ("Tenant", 14.0),
        ("Type", 12.0),
        ("Value", 40.0),
        ("Verdict", 12.0),
        ("Note", 40.0),
        ("AddedBy", 18.0),
        ("AddedAt", 20.0),
        ("RemovedAt", 20.0),
        ("RemovedBy", 18.0),
    ];
    cols.extend(DECISION_COLS);
    cols.push(("Analyst notes", 40.0));
    sheet(&mut wb, "Indicators", &cols, rows)?;

    // ---- Devices: every suspect device, removed ones included, with the `devices.csv` columns. The high-confidence
    // ones are on `Devices`, the ones reached only through impossible-travel legs on `Devices (low confidence)`.
    let mut rows = Vec::new();
    let mut low_rows = Vec::new();
    let devices = crate::case::devices::suspect_devices(conn, None)?;
    let sources = devices_csv::first_sources(conn, &devices_csv::mark_keys(&devices))?;
    for d in devices {
        let lc = &d.lifecycle;
        let src = |m: &Option<crate::case::devices::LifecycleMark>| -> Cell {
            m.as_ref()
                .map(|_| t(devices_csv::mark_source(&sources, m)))
                .unwrap_or(Cell::Empty)
        };
        let time =
            |m: &Option<crate::case::devices::LifecycleMark>| Cell::Time(m.as_ref().map(|m| m.at));
        let row = vec![
            t(lc.status.as_str()),
            t(d.confidence.as_str()),
            ot(d.tenant_key.as_deref()),
            t(&d.device_id),
            ot(d.object_id.as_deref()),
            ot(d.display_name.as_deref()),
            ot(d.os.as_deref()),
            ot(d.trust_type.as_deref()),
            d.is_compliant.map(Cell::Bool).unwrap_or(Cell::Empty),
            d.is_managed.map(Cell::Bool).unwrap_or(Cell::Empty),
            time(&lc.registered),
            src(&lc.registered),
            time(&lc.removed),
            src(&lc.removed),
            time(&lc.disabled),
            src(&lc.disabled),
            time(&lc.last_active),
            src(&lc.last_active),
            t(d.users.join("; ")),
            t(d.malicious_ips.join("; ")),
            t(d.other_ips
                .iter()
                .map(devices_csv::other_ip_text)
                .collect::<Vec<_>>()
                .join("; ")),
            t(d.reasons
                .iter()
                .map(devices_csv::reason_text)
                .collect::<Vec<_>>()
                .join("; ")),
            t(devices_csv::note(lc.status)),
        ];
        if d.confidence == crate::case::devices::Confidence::Low {
            low_rows.push(row);
        } else {
            rows.push(row);
        }
    }
    let widths = [
        18.0, 10.0, 14.0, 38.0, 38.0, 24.0, 14.0, 12.0, 12.0, 12.0, 20.0, 40.0, 20.0, 40.0, 20.0,
        40.0, 20.0, 40.0, 30.0, 30.0, 50.0, 60.0, 50.0,
    ];
    let cols: Vec<(&str, f64)> = DEVICE_COLUMNS.iter().copied().zip(widths).collect();
    sheet(&mut wb, "Devices", &cols, rows)?;
    sheet(&mut wb, "Devices (low confidence)", &cols, low_rows)?;

    // ---- Evidence gaps
    let rows = evidence_gaps(conn)?
        .into_iter()
        .map(|g| {
            vec![
                t(g.tenant_key),
                t(g.evidence),
                t(g.title),
                t(g.status),
                t(g.reason),
                ot(g.remediation.as_deref()),
                Cell::Int(g.rows),
                Cell::Time(g.min_time),
                Cell::Time(g.max_time),
                g.users_covered.map(Cell::Int).unwrap_or(Cell::Empty),
            ]
        })
        .collect();
    sheet(
        &mut wb,
        "Evidence gaps",
        &[
            ("Tenant", 14.0),
            ("Evidence", 22.0),
            ("Title", 40.0),
            ("Status", 14.0),
            ("Reason", 60.0),
            ("Remediation", 50.0),
            ("Rows", 10.0),
            ("MinTime", 20.0),
            ("MaxTime", 20.0),
            ("UsersCovered", 14.0),
        ],
        rows,
    )?;

    // ---- Audit
    let rows = audit::log(conn, None)?
        .into_iter()
        .map(|e| {
            vec![
                Cell::Int(e.seq),
                Cell::Time(Some(e.ts)),
                t(e.actor),
                ot(e.on_behalf_of.as_deref()),
                t(e.action),
                t(e.object_type),
                t(e.object_id),
                ot(e.reason.as_deref()),
                t(e.before.map(|v| audit::canonical(&v)).unwrap_or_default()),
                t(e.after.map(|v| audit::canonical(&v)).unwrap_or_default()),
                t(e.prev_hash),
                t(e.hash),
            ]
        })
        .collect();
    sheet(
        &mut wb,
        "Audit",
        &[
            ("Seq", 8.0),
            ("Time", 20.0),
            ("Actor", 20.0),
            ("OnBehalfOf", 18.0),
            ("Action", 18.0),
            ("ObjectType", 16.0),
            ("ObjectId", 18.0),
            ("Reason", 40.0),
            ("Before", 60.0),
            ("After", 60.0),
            ("PrevHash", 66.0),
            ("Hash", 66.0),
        ],
        rows,
    )?;
    wb.save(path).map_err(x)
}
