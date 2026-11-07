//! Get-UAL (research event layouts §1) and Get-MailboxAuditLog (§4, Get-UAL with
//! `-RecordType ExchangeItem -Interval 1440`).
//!
//! Get-UAL queries the window in consecutive windows of one `Search-UnifiedAuditLog` call each
//! (up to 5000 records, newest first): a window that hits the cap is halved and queried again,
//! a quiet window lets the interval grow back (at most one day here). Every non-empty window
//! is one file `UAL-<startUTC>-<endUTC>.<ext>`; `-MergeOutput` adds `Merged/UAL-Combined.<ext>`.

use super::Ctx;
use crate::Result;
use crate::events::{RecordType, Ual};
use crate::keys;
use crate::options::UalFormat;
use crate::ps::{
    DateEvidence, DtKind, Origin, PsDate, Row, Val, convert_to_json, csv_imported, export_csv,
    export_csv_append, json_text, json_value,
};
use crate::story::Evidence;
use crate::tree::{FileSpec, Tree};
use crate::ual::creation_time;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::{Map, Value};
use std::cmp::Reverse;
use std::collections::BTreeSet;
use uuid::Uuid;

/// `Search-UnifiedAuditLog -ResultSize` without session paging.
const RESULT_CAP: usize = 5000;
const DAY_MS: i64 = 86_400_000;
/// Get-UAL's smallest interval: 0.1 minute.
const MIN_MS: i64 = 6_000;

/// One `Search-UnifiedAuditLog` window and its records, oldest first.
#[cfg(test)]
struct Window<'a> {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    records: Vec<&'a Ual>,
}

/// Splits `[start, end)` the way Get-UAL walks it from `start`: `max_ms` windows; a window with
/// at least 5000 records is halved and queried again; after a window, fewer than 500 records
/// triple the interval, fewer than 1000 grow it by half, 4500 or more shrink it to 80% (capped
/// at `max_ms`). `records` must be sorted by time.
#[cfg(test)]
fn windows<'a>(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    records: &[&'a Ual],
    max_ms: i64,
) -> Vec<Window<'a>> {
    let mut out = Vec::new();
    let mut s = start;
    let mut interval = max_ms;
    while s < end {
        let e = (s + Duration::milliseconds(interval)).min(end);
        let from = records.partition_point(|u| u.time < s);
        let to = records.partition_point(|u| u.time < e);
        let n = to - from;
        if n >= RESULT_CAP && interval > MIN_MS {
            interval = (interval / 2).max(MIN_MS);
            continue;
        }
        out.push(Window {
            start: s,
            end: e,
            records: records[from..to].to_vec(),
        });
        interval = if n >= 4500 {
            interval * 4 / 5
        } else if n < 500 {
            interval * 3
        } else if n < 1000 {
            interval * 3 / 2
        } else {
            interval
        }
        .clamp(MIN_MS, max_ms);
        s = e;
    }
    out
}

fn extension(f: UalFormat) -> &'static str {
    match f {
        UalFormat::Csv | UalFormat::CsvAuditDataOnly => "csv",
        UalFormat::Json | UalFormat::JsonAuditDataOnly | UalFormat::SofElk => "json",
        UalFormat::Jsonl => "jsonl",
    }
}

fn format_label(f: UalFormat) -> &'static str {
    match f {
        UalFormat::Csv | UalFormat::CsvAuditDataOnly => "CSV",
        UalFormat::Json | UalFormat::JsonAuditDataOnly => "JSON",
        UalFormat::SofElk => "SOF-ELK",
        UalFormat::Jsonl => "JSONL",
    }
}

/// A JSON value as PowerShell holds it after `ConvertFrom-Json`.
fn json_to_val(v: &Value) -> Val {
    match v {
        Value::Null => Val::Null,
        Value::Bool(b) => Val::Bool(*b),
        Value::Number(n) => match n.as_i64() {
            Some(i) => Val::Int(i),
            None => Val::Float(n.as_f64().unwrap_or_default()),
        },
        Value::String(s) => Val::Str(s.clone()),
        other => Val::Raw(other.clone()),
    }
}

/// AuditData `CreationTime` after `ConvertFrom-Json`: a DateTime on PowerShell 7 (rendered in
/// the host culture by Export-Csv), the ISO text on 5.1.
fn creation_time_val(u: &Ual) -> Val {
    Val::Date(PsDate {
        utc: u.time,
        origin: Origin::IsoText(creation_time(u.time)),
    })
}

/// The AuditData object's properties (`-AuditDataOnly` CSV rows).
fn audit_row(u: &Ual) -> Row {
    u.audit
        .iter()
        .map(|(k, v)| {
            let val = if k == "CreationTime" {
                creation_time_val(u)
            } else {
                json_to_val(v)
            };
            (k.clone(), val)
        })
        .collect()
}

/// The 11 properties of a Search-UnifiedAuditLog result (current EXO module).
fn record_row(c: &Ctx<'_>, u: &Ual, index: usize, count: usize, audit: Val) -> Row {
    let nl = c.nl();
    vec![
        ("RecordType".into(), Val::Str(u.record_type.name().into())),
        (
            "CreationDate".into(),
            Val::DateText(PsDate::dotnet(u.time, DtKind::Utc)),
        ),
        ("UserIds".into(), Val::Str(u.user_id.clone())),
        ("Operations".into(), Val::Str(u.operation.clone())),
        ("AuditData".into(), audit),
        ("ResultIndex".into(), Val::Int(index as i64 + 1)),
        ("ResultCount".into(), Val::Int(count as i64)),
        (
            "AuditSearchRequestMetadata".into(),
            Val::Str(format!("{{{nl}  \"moreRecordsAvailable\": false{nl}}}")),
        ),
        ("Identity".into(), Val::Str(u.id.to_string())),
        ("IsValid".into(), Val::Bool(true)),
        ("ObjectState".into(), Val::Str("Unchanged".into())),
    ]
}

/// One window file's content: text, each record's 1-based line span (in `records` order), the
/// rows Import-Csv would read back (CSV formats, for the merge) and the culture dates.
struct WindowText {
    text: String,
    spans: Vec<(u32, u32)>,
    imported: Vec<Row>,
    dates: DateEvidence,
}

/// One compact JSON document per line, then Get-UAL's `Add-Content "`n"` trailer when
/// `trailer`.
fn lines(c: &Ctx<'_>, docs: Vec<String>, trailer: bool) -> WindowText {
    let nl = c.nl();
    let mut text = String::new();
    let mut spans = Vec::new();
    for (i, d) in docs.iter().enumerate() {
        text.push_str(d);
        text.push_str(nl);
        spans.push((i as u32 + 1, i as u32 + 1));
    }
    if trailer {
        text.push('\n');
        text.push_str(nl);
    }
    WindowText {
        text,
        spans,
        imported: Vec::new(),
        dates: DateEvidence::default(),
    }
}

/// The bytes of one window file in `format`; `records` newest first.
fn render(c: &Ctx<'_>, format: UalFormat, records: &[&Ual]) -> WindowText {
    let n = records.len();
    let nl = c.nl();
    match format {
        UalFormat::Csv | UalFormat::CsvAuditDataOnly => {
            let rows: Vec<Row> = records
                .iter()
                .enumerate()
                .map(|(i, u)| match format {
                    UalFormat::Csv => record_row(c, u, i, n, Val::Str(u.audit_data_text())),
                    _ => audit_row(u),
                })
                .collect();
            let mut dates = DateEvidence::default();
            let r = export_csv(&c.host, &rows, &mut dates);
            // Import-Csv reads each file with its own header.
            let header: Vec<&String> = rows[0].iter().map(|(k, _)| k).collect();
            let imported = rows
                .iter()
                .map(|row| {
                    let full: Row = header
                        .iter()
                        .map(|h| {
                            let v = row
                                .iter()
                                .find(|(k, _)| k == *h)
                                .map_or(Val::Null, |(_, v)| v.clone());
                            ((*h).clone(), v)
                        })
                        .collect();
                    csv_imported(&c.host, &full)
                })
                .collect();
            WindowText {
                text: r.text,
                spans: r.spans,
                imported,
                dates,
            }
        }
        UalFormat::Json => {
            let rows: Vec<Row> = records
                .iter()
                .enumerate()
                .map(|(i, u)| record_row(c, u, i, n, Val::Raw(Value::Object(u.audit.clone()))))
                .collect();
            let r = convert_to_json(&c.host, &rows, false);
            let mut text = r.text;
            text.push_str(nl);
            text.push('\n');
            text.push_str(nl);
            WindowText {
                text,
                spans: r.spans,
                imported: Vec::new(),
                dates: DateEvidence::default(),
            }
        }
        UalFormat::JsonAuditDataOnly => lines(
            c,
            records.iter().map(|u| u.audit_data_text()).collect(),
            true,
        ),
        UalFormat::SofElk => lines(
            c,
            records
                .iter()
                .map(|u| json_text(&c.host, &Value::Object(u.audit.clone()), true))
                .collect(),
            true,
        ),
        UalFormat::Jsonl => lines(
            c,
            records
                .iter()
                .enumerate()
                .map(|(i, u)| {
                    let row = record_row(c, u, i, n, Val::Str(u.audit_data_text()));
                    let obj: Map<String, Value> = row
                        .iter()
                        .map(|(k, v)| (k.clone(), json_value(&c.host, v)))
                        .collect();
                    json_text(&c.host, &Value::Object(obj), true)
                })
                .collect(),
            false,
        ),
    }
}

/// The `mail_items_accessed` rows one MailItemsAccessed record yields from a file: one per
/// folder item, one per folder that lists none, one for a record without folders; a CSV of
/// AuditData properties keeps `Folders` only as `System.Object[]`, so one row per record.
/// `full`: the record will be loaded from the full AuditData at some point (the window format
/// itself, or a later Get-UALGraph / QuickUAL copy for a victim), so its real child count is
/// what the table ends up holding even when this window lost `Folders`.
fn mia_children(u: &Ual, full: bool) -> u64 {
    if !full {
        return 1;
    }
    let folders = u
        .audit
        .get("Folders")
        .and_then(Value::as_array)
        .map(|f| f.as_slice())
        .unwrap_or_default();
    let n: u64 = folders
        .iter()
        .filter(|f| f.is_object())
        .map(|f| {
            f.get("FolderItems")
                .and_then(Value::as_array)
                .map_or(1, |items| (items.len() as u64).max(1))
        })
        .sum();
    n.max(1)
}

/// Streams `Merged/UAL-Combined.<ext>` as each window is written, so the whole merged text is
/// never held in memory. Byte-identical to rendering all windows and merging them at once.
struct Merged {
    rel: String,
    format: UalFormat,
    /// The CSV header of the first window's imported rows (all windows share it).
    csv_header: Vec<String>,
    /// A chunk has been written (CSV) / the `[` opening been written (JSON) / a part exists.
    started: bool,
    /// A JSON inner part has been written (controls the `,`).
    json_any: bool,
    /// The merge of every CSV window's culture dates.
    dates: DateEvidence,
}

impl Merged {
    fn new(rel: &str, format: UalFormat) -> Merged {
        Merged {
            rel: rel.to_string(),
            format,
            csv_header: Vec::new(),
            started: false,
            json_any: false,
            dates: DateEvidence::default(),
        }
    }

    fn spec(&self, c: &Ctx<'_>) -> FileSpec {
        FileSpec::new(&self.rel, Some("inv.ual.merged"), c.utf8())
            .derived()
            .source_derived()
    }

    /// Appends one already-rendered window (its text and imported rows) to the merged file.
    fn push(&mut self, c: &Ctx<'_>, tree: &mut Tree<'_>, r: &WindowText) -> Result<()> {
        let nl = c.nl();
        let spec = self.spec(c);
        match self.format {
            UalFormat::Csv | UalFormat::CsvAuditDataOnly => {
                let mut ev = DateEvidence::default();
                let text = if self.started {
                    export_csv_append(&c.host, &self.csv_header, &r.imported, &mut ev).text
                } else {
                    self.csv_header = r
                        .imported
                        .first()
                        .map(|row| row.iter().map(|(k, _)| k.clone()).collect())
                        .unwrap_or_default();
                    self.started = true;
                    export_csv(&c.host, &r.imported, &mut ev).text
                };
                tree.write(&spec, &text)?;
                self.dates.merge(&r.dates);
            }
            UalFormat::Json | UalFormat::JsonAuditDataOnly => {
                if !self.started {
                    let mut open = String::new();
                    open.push('[');
                    open.push_str(nl);
                    tree.write(&spec, &open)?;
                    self.started = true;
                }
                let inner = json_inner(&r.text);
                if !inner.is_empty() {
                    let mut text = String::new();
                    if self.json_any {
                        text.push(',');
                    }
                    text.push_str(inner);
                    tree.write(&spec, &text)?;
                    self.json_any = true;
                }
            }
            UalFormat::SofElk => {
                for line in r.text.lines().filter(|l| !l.trim().is_empty()) {
                    let mut text = String::new();
                    text.push_str(line);
                    text.push_str(nl);
                    tree.write(&spec, &text)?;
                    self.started = true;
                }
            }
            UalFormat::Jsonl => {
                let mut text = String::new();
                if self.started {
                    text.push('\n');
                }
                text.push_str(r.text.trim());
                tree.write(&spec, &text)?;
                self.started = true;
            }
        }
        Ok(())
    }

    /// Whether the merge produced a file (`merged_text` returned some text).
    fn wrote(&self) -> bool {
        match self.format {
            UalFormat::Csv | UalFormat::CsvAuditDataOnly => true,
            UalFormat::Json | UalFormat::JsonAuditDataOnly => true,
            UalFormat::SofElk | UalFormat::Jsonl => self.started,
        }
    }

    /// Writes the closing bytes and the empty-file cases, matching `merged_text`'s `Some`/`None`.
    fn finish(&mut self, c: &Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
        let nl = c.nl();
        let spec = self.spec(c);
        match self.format {
            UalFormat::Csv | UalFormat::CsvAuditDataOnly => {
                if !self.started {
                    tree.write(&spec, "")?;
                }
            }
            UalFormat::Json | UalFormat::JsonAuditDataOnly => {
                let mut text = String::new();
                if !self.started {
                    text.push('[');
                    text.push_str(nl);
                }
                text.push(']');
                text.push_str(nl);
                tree.write(&spec, &text)?;
            }
            // No lines / no windows -> no merged file (as `merged_text` returned None).
            // No lines -> no SOF-ELK file. JSONL closes with the trailing newline.
            UalFormat::SofElk => {}
            UalFormat::Jsonl => {
                if self.started {
                    tree.write(&spec, nl)?;
                }
            }
        }
        Ok(())
    }
}

/// Writes one Get-UAL run's window files into `dir` (a tree path) and returns them, oldest
/// first. `records` sorted by time.
#[allow(clippy::too_many_arguments)]
/// The window's logged UAL records, oldest first, generated a day at a time so the whole
/// window's records are never held at once. `world.day` is deterministic, so this is the same
/// sequence `window_records` read from `Ctx::days`.
struct WindowSource<'a, F: Fn(&Ual) -> bool> {
    world: &'a crate::world::World,
    dates: std::slice::Iter<'a, NaiveDate>,
    current: std::vec::IntoIter<Ual>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    keep: F,
}

impl<F: Fn(&Ual) -> bool> Iterator for WindowSource<'_, F> {
    type Item = Ual;

    fn next(&mut self) -> Option<Ual> {
        loop {
            if let Some(u) = self.current.next() {
                if (self.keep)(&u) && u.time >= self.start && u.time < self.end {
                    return Some(u);
                }
                continue;
            }
            let date = self.dates.next()?;
            let mut d = self.world.day(*date);
            d.ual.retain(|u| u.time >= self.start && u.time < self.end);
            self.current = d.ual.into_iter();
        }
    }
}

/// Splits `[start, end)` exactly like [`windows`], but over a streaming, time-sorted owned
/// iterator. Buffers at most the records not yet assigned to a window (≈ one window's worth).
fn for_each_window(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    records: impl Iterator<Item = Ual>,
    max_ms: i64,
    mut f: impl FnMut(DateTime<Utc>, DateTime<Utc>, Vec<Ual>) -> Result<()>,
) -> Result<()> {
    let mut it = records.peekable();
    let mut pending: std::collections::VecDeque<Ual> = std::collections::VecDeque::new();
    let mut s = start;
    let mut interval = max_ms;
    while s < end {
        let e = (s + Duration::milliseconds(interval)).min(end);
        while it.peek().is_some_and(|u| u.time < e) {
            pending.push_back(it.next().expect("peeked"));
        }
        let n = pending.iter().take_while(|u| u.time < e).count();
        if n >= RESULT_CAP && interval > MIN_MS {
            interval = (interval / 2).max(MIN_MS);
            continue;
        }
        let mut win: Vec<Ual> = Vec::with_capacity(n);
        while pending.front().is_some_and(|u| u.time < e) {
            win.push(pending.pop_front().expect("front"));
        }
        f(s, e, win)?;
        interval = if n >= 4500 {
            interval * 4 / 5
        } else if n < 500 {
            interval * 3
        } else if n < 1000 {
            interval * 3 / 2
        } else {
            interval
        }
        .clamp(MIN_MS, max_ms);
        s = e;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_windows(
    c: &mut Ctx<'_>,
    tree: &mut Tree<'_>,
    dir: &str,
    format: UalFormat,
    world: &crate::world::World,
    dates: &[NaiveDate],
    max_ms: i64,
    at: &mut chrono::NaiveDateTime,
    full_ids: &BTreeSet<Uuid>,
    keep: impl Fn(&Ual) -> bool,
    mut merged: Option<&mut Merged>,
) -> Result<u64> {
    let (start, end) = (world.window_start(), world.window_end());
    let source = WindowSource {
        world,
        dates: dates.iter(),
        current: Vec::new().into_iter(),
        start,
        end,
        keep,
    };
    let mut total = 0u64;
    for_each_window(start, end, source, max_ms, |w_start, w_end, win| {
        total += win.len() as u64;
        *at += Duration::seconds(1);
        let (a, b) = (
            w_start.format("%Y-%m-%dT%H:%M:%SZ"),
            w_end.format("%Y-%m-%dT%H:%M:%SZ"),
        );
        c.log.add(
            *at,
            format!("[INFO] Found {} audit logs between {a} and {b}", win.len()),
        );
        if win.is_empty() {
            return Ok(());
        }
        let mut newest: Vec<&Ual> = win.iter().collect();
        newest.sort_by_key(|u| Reverse((u.time, u.id)));
        let name = format!(
            "UAL-{}-{}.{}",
            w_start.format("%Y%m%d%H%M%S"),
            w_end.format("%Y%m%d%H%M%S"),
            extension(format)
        );
        let rel = format!("{dir}/{name}");
        let spec = FileSpec::new(&rel, Some("inv.ual.window"), c.utf8());
        let r = render(c, format, &newest);
        tree.write(&spec, &r.text)?;
        if r.dates.culture_dates > 0 {
            tree.date_evidence(&rel, r.dates);
        }
        for (u, span) in newest.iter().zip(&r.spans) {
            tree.row(&rel, "ual_events", keys::ual(u.id));
            tree.deliver(&Evidence::Ual(u.id), "ual_events", &rel, *span);
            if u.operation == "MailItemsAccessed" {
                // `-AuditDataOnly` loses `Folders`, so the window loads one child per record;
                // a full copy from Get-UALGraph or QuickUAL later replaces them with the real
                // children. `full_ids` is exactly the set those writers emit full.
                let full = format != UalFormat::CsvAuditDataOnly || full_ids.contains(&u.id);
                tree.rows_counted(&rel, "mail_items_accessed", mia_children(u, full));
            }
        }
        if let Some(m) = merged.as_mut() {
            m.push(c, tree, &r)?;
            for u in &newest {
                tree.row(&m.rel, "ual_events", keys::ual(u.id));
            }
        }
        Ok(())
    })?;
    Ok(total)
}

/// `Get-Content -Raw`, `.Trim()`, one leading `[` and one trailing `]` removed, `.Trim()`.
pub(super) fn json_inner(text: &str) -> &str {
    let t = text.trim();
    let t = t.strip_prefix('[').unwrap_or(t);
    let t = t.strip_suffix(']').unwrap_or(t);
    t.trim()
}

/// Merge-OutputFiles' JSON merge: `[`, the files' inner parts joined with `,`, `]`. The writers
/// now stream this; kept as the reference the `JsonMerge` output is tested against.
#[cfg(test)]
pub(super) fn merge_json(nl: &str, texts: &[&str]) -> String {
    let inner: Vec<&str> = texts
        .iter()
        .map(|t| json_inner(t))
        .filter(|t| !t.is_empty())
        .collect();
    format!("[{nl}{}]{nl}", inner.join(","))
}

/// Start-EvidenceCollection's `Get-UAL -MergeOutput -Output <format>` over the window.
pub(super) fn write_get_ual(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("UnifiedAuditLog", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    let format = c.opts.ual_format;
    let mut at = run.local;
    let fmt = "%Y-%m-%d %H:%M:%S";
    c.log
        .add(at, "=== Starting Unified Audit Log Collection ===");
    c.log.add(
        at,
        format!("Start date: {}", c.world.window_start().format(fmt)),
    );
    c.log.add(
        at,
        format!("End date: {}", c.world.window_end().format(fmt)),
    );
    c.log
        .add(at, format!("Output format: {}", format_label(format)));
    c.log
        .add(at, format!("Output Directory: {}", c.shown(&run.rel)));
    let (world, dates) = (c.world, c.dates.clone());
    // The records Get-UALGraph and QuickUAL emit from the full AuditData, so this run can
    // predict which `-AuditDataOnly` window records a later full copy will upgrade.
    let full_ids: BTreeSet<Uuid> = super::quickual::full_records(c)
        .into_iter()
        .chain(super::ual_graph::full_records(c))
        .map(|u| u.id)
        .collect();
    let merged_dir = format!("{dir}/Merged");
    let merged_rel = format!("{merged_dir}/UAL-Combined.{}", extension(format));
    tree.dir(&merged_dir)?;
    // The merged file is streamed while the windows are written, so neither the window texts
    // nor their rows are held in memory; the log lines keep their original order and times.
    let mut merged = Merged::new(&merged_rel, format);
    let total = write_windows(
        c,
        tree,
        &dir,
        format,
        world,
        &dates,
        DAY_MS,
        &mut at,
        &full_ids,
        |_| true,
        Some(&mut merged),
    )?;
    merged.finish(c, tree)?;
    at += Duration::seconds(1);
    c.log
        .add(at, "[INFO] Merging all output files into one file");
    c.log.add(
        at,
        format!(
            "[INFO] Creating the following directory: {}\\Merged",
            c.shown(&run.rel)
        ),
    );
    // A merged CSV keeps the windows' culture dates as text.
    if matches!(format, UalFormat::Csv | UalFormat::CsvAuditDataOnly)
        && merged.dates.culture_dates > 0
    {
        tree.date_evidence(&merged_rel, merged.dates);
    }
    if merged.wrote() {
        c.log.add(
            at,
            format!(
                "[INFO] {} files merged into {}\\Merged\\UAL-Combined.{}",
                format_label(format),
                c.shown(&run.rel),
                extension(format)
            ),
        );
    } else {
        c.log.add(
            at,
            format!(
                "[ERROR] No {} files found in {}",
                format_label(format),
                c.shown(&run.rel)
            ),
        );
    }
    c.log
        .add(at, "\n=== Unified Audit Log Collection Summary ===");
    c.log.add(at, "\nCollection Statistics:");
    c.log.add(at, format!("  Total Records: {total}"));
    c.log.add(at, "----------------------------------------\n");
    let unit = super::ManifestUnit {
        sources: &["ual"],
        start: world.window_start(),
        end: world.window_end(),
        records: total,
        files: tree.files_in(&dir),
    };
    c.write_manifest(tree, &run, &dir, "Get-UAL", at, &[unit])?;
    c.runs.busy_until(at);
    Ok(())
}

/// Get-MailboxAuditLog for the storylines' users: Get-UAL `-RecordType ExchangeItem -UserIds
/// <users> -Interval 1440 -Output CSV` below `Mailbox Audit Log/<ts>`. Nothing runs when the
/// scenario names no users.
pub(super) fn write_mailbox_audit_log(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let users: BTreeSet<String> = c
        .world
        .victims
        .iter()
        .map(|n| c.world.user(*n).upn.clone())
        .collect();
    if users.is_empty() {
        return Ok(());
    }
    let run = c.runs.next("Mailbox Audit Log", None);
    let outer = c.path(&run.rel);
    tree.dir(&outer)?;
    let mut at = run.local;
    c.log.add(
        at,
        "== Starting the Mailbox Audit Log Collection (utilizing Get-UAL) ==",
    );
    // Get-UAL's own Init-OutputDir, a second later.
    at += Duration::seconds(1);
    let inner_rel = format!("{}/UnifiedAuditLog/{}", run.rel, at.format("%Y%m%d-%H%M%S"));
    let dir = c.path(&inner_rel);
    tree.dir(&dir)?;
    c.log
        .add(at, "=== Starting Unified Audit Log Collection ===");
    c.log
        .add(at, format!("Output Directory: {}", c.shown(&inner_rel)));
    let (world, dates) = (c.world, c.dates.clone());
    write_windows(
        c,
        tree,
        &dir,
        UalFormat::Csv,
        world,
        &dates,
        DAY_MS,
        &mut at,
        &BTreeSet::new(),
        |u| u.record_type == RecordType::ExchangeItem && users.contains(&u.user_id),
        None,
    )?;
    c.runs.busy_until(at);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::RecordType;
    use serde_json::Map;
    use uuid::Uuid;

    fn rec(t: DateTime<Utc>, n: u128) -> Ual {
        Ual {
            id: Uuid::from_u128(n),
            time: t,
            record_type: RecordType::ExchangeItem,
            operation: "Update".into(),
            user_id: "a@contoso.example".into(),
            audit: Map::new(),
        }
    }

    #[test]
    fn busy_windows_are_halved_and_quiet_ones_grow_back_to_a_day() {
        let start: DateTime<Utc> = "2026-08-01T00:00:00Z".parse().unwrap();
        let end = start + Duration::days(3);
        // 6000 records in the first 6 hours, then nothing.
        let v: Vec<Ual> = (0..6000)
            .map(|i| rec(start + Duration::seconds(i as i64 * 3), i))
            .collect();
        let refs: Vec<&Ual> = v.iter().collect();
        let w = windows(start, end, &refs, DAY_MS);
        assert!(w.iter().all(|w| w.records.len() < RESULT_CAP));
        assert_eq!(w.iter().map(|w| w.records.len()).sum::<usize>(), 6000);
        assert_eq!(w[0].end - w[0].start, Duration::hours(3));
        assert_eq!(w.last().unwrap().end, end);
        assert!(w.windows(2).all(|p| p[0].end == p[1].start));
        assert!(w.iter().all(|w| w.end - w.start <= Duration::days(1)));
    }

    #[test]
    fn json_merge_strips_one_bracket_pair_per_file() {
        let merged = merge_json(
            "\r\n",
            &["[\r\n  1,\r\n  2\r\n]\r\n\n\r\n", "{\"a\": 1}\r\n", ""],
        );
        assert_eq!(merged, "[\r\n1,\r\n  2,{\"a\": 1}]\r\n");
    }
}
