//! Shared plumbing for the state-table parsers: collect rows per table, resolve culture
//! date order across the whole file, stage the cells and load them.

use crate::db::state_tables::{LoadMode, TableSpec};
use crate::hash::sha256_hex;
use crate::ingest::context::ParseContext;
use crate::ingest::progress::SAVING_RECORDS;
use crate::ingest::state::{LoadOutcome, StagedRow, StateFileStage, load_rows};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::records::{
    RecordEvent, RecordFormat, SourceRecord, for_each_record, placeholder_warning, read_records,
};
use crate::readers::stream::Sight;
use crate::readers::text::SourcePos;
use crate::readers::time::{DateOrder, DateOrderDetector, parse_timestamp};
use crate::{Error, Result};
use serde_json::{Map, Value};

pub struct RowDraft {
    pub ordinal: u64,
    /// Where the row's record lives (an XLSX row: [`ParseContext::row_sighting`]).
    pub sight: Sight,
    /// The record's `parse_errors.raw_snippet`, should a cell fail to stage.
    pub snippet: String,
    pub record_key: String,
    pub cells: Vec<Cell>,
    pub raw: Option<Value>,
}

/// Rows of one table read from one file; `cells` of each row align with `columns`.
pub struct TableRows {
    pub spec: &'static TableSpec,
    pub columns: &'static [&'static str],
    pub rows: Vec<RowDraft>,
}

impl TableRows {
    pub fn new(spec: &'static TableSpec, columns: &'static [&'static str]) -> Self {
        TableRows {
            spec,
            columns,
            rows: Vec::new(),
        }
    }

    /// A row for record `r` (raw = the record).
    pub fn push(&mut self, r: &SourceRecord, record_key: String, cells: Vec<Cell>) {
        self.push_draft(RowDraft {
            ordinal: r.ordinal,
            sight: r.sight.clone(),
            snippet: r.snippet.clone(),
            record_key,
            cells,
            raw: Some(Value::Object(r.map.clone())),
        });
    }

    pub fn push_draft(&mut self, d: RowDraft) {
        assert_eq!(
            d.cells.len(),
            self.columns.len(),
            "{}: cells do not match columns",
            self.spec.table
        );
        self.rows.push(d);
    }
}

/// `UnsupportedShape` naming `what` and the first record's keys.
pub fn unsupported(first: &SourceRecord, what: &str) -> Error {
    let cols: Vec<&str> = first.map.keys().take(12).map(String::as_str).collect();
    Error::UnsupportedShape(format!("no {what} fields in [{}]", cols.join(", ")))
}

/// Shape check: unless no record was read, some record must have one of `keys`
/// (case-insensitive), else the file is `not_supported`.
pub fn require_any_key(records: &[SourceRecord], keys: &[&str], what: &str) -> Result<()> {
    match records.first() {
        Some(first)
            if !records.iter().any(|r| {
                let rec = Rec::new(&r.map, false);
                keys.iter().any(|k| rec.has(k))
            }) =>
        {
            Err(unsupported(first, what))
        }
        _ => Ok(()),
    }
}

/// Records of a state file; CSV records holding PowerShell placeholders add a warning.
pub fn read_state_records(
    ctx: &mut ParseContext<'_>,
    format: RecordFormat,
) -> Result<Vec<SourceRecord>> {
    let records = read_records(ctx, format)?;
    if !ctx.portal_export
        && let Some(w) = placeholder_warning(&records, format)
    {
        ctx.warn(w);
    }
    Ok(records)
}

pub fn lower(v: Option<String>) -> Option<String> {
    v.map(|s| s.to_lowercase())
}

/// Count `r` as read and record why it could not be loaded.
pub fn reject(ctx: &mut ParseContext<'_>, r: &SourceRecord, msg: &str) -> Result<()> {
    reject_at(ctx, r.ordinal, &r.sight.pos, &r.snippet, msg)
}

/// [`reject`] a record the collector lost (it wrote a failure placeholder, not data): the message is prefixed with
/// [`crate::ingest::COLLECTOR_LOSS`] so availability does not report it as a parse failure.
pub fn reject_collector_loss(
    ctx: &mut ParseContext<'_>,
    r: &SourceRecord,
    msg: &str,
) -> Result<()> {
    reject(ctx, r, &format!("{}{msg}", crate::ingest::COLLECTOR_LOSS))?;
    ctx.stats.collector_lost += 1;
    Ok(())
}

/// Count a record as read and record why it could not be loaded, at its position with its snippet.
pub fn reject_at(
    ctx: &mut ParseContext<'_>,
    ordinal: u64,
    pos: &SourcePos,
    snippet: &str,
    msg: &str,
) -> Result<()> {
    ctx.stats.read += 1;
    ctx.parse_error_at(ordinal, pos, snippet, msg)
}

/// Cells addressed by column name, in the order of `columns`; unset columns stay NULL.
pub struct CellRow {
    columns: &'static [&'static str],
    cells: Vec<Cell>,
}

impl CellRow {
    pub fn new(columns: &'static [&'static str]) -> Self {
        CellRow {
            columns,
            cells: vec![Cell::Null; columns.len()],
        }
    }

    /// Set `column`. Panics on a name not in `columns` (a programming error).
    pub fn set(&mut self, column: &str, cell: Cell) -> &mut Self {
        let i = self
            .columns
            .iter()
            .position(|c| *c == column)
            .unwrap_or_else(|| panic!("no column {column}"));
        self.cells[i] = cell;
        self
    }

    pub fn into_cells(self) -> Vec<Cell> {
        self.cells
    }
}

/// `s` as UTC `YYYY-MM-DDTHH:MM:SSZ` (sub-seconds dropped) for record keys built from a
/// time; the trimmed text when it cannot be parsed (the row then fails when staged).
pub fn key_time(s: &str, order: Option<DateOrder>) -> String {
    parse_timestamp(s, order)
        .map(|t| t.utc.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|_| s.trim().to_string())
}

/// Day/month order of one file's culture dates `texts`, resolved like
/// `ParseContext::resolve_date_order` (collection hint, deferral, `--culture`).
pub fn file_date_order<'t>(
    ctx: &mut ParseContext<'_>,
    texts: impl IntoIterator<Item = &'t str>,
) -> Result<Option<DateOrder>> {
    let mut detector = DateOrderDetector::default();
    for t in texts {
        detector.observe(t);
    }
    ctx.resolve_date_order(&detector)
}

/// Resolve the file's day/month order from every time cell, stage every row (a time that
/// cannot be parsed makes that row a parse error) and load each table.
pub fn load_tables(ctx: &mut ParseContext<'_>, tables: Vec<TableRows>) -> Result<()> {
    let mut detector = DateOrderDetector::default();
    for cell in tables.iter().flat_map(|t| &t.rows).flat_map(|r| &r.cells) {
        if let Cell::Time(s) = cell {
            detector.observe(s);
        }
    }
    let order = ctx.resolve_date_order(&detector)?;
    for t in tables {
        let mut staged = Vec::with_capacity(t.rows.len());
        for r in t.rows {
            if let Some(row) = stage_draft(ctx, t.spec, r, order)? {
                staged.push(row);
            }
        }
        let out = load_rows(
            ctx.conn,
            t.spec,
            t.columns,
            ctx.collection_id,
            ctx.file_id,
            &staged,
        )?;
        count_load(ctx, t.spec, out);
    }
    Ok(())
}

/// Count `draft` as read and stage it: its cells parsed with `order` and its sighting located, or a parse error
/// (`None`) when a cell cannot be parsed.
fn stage_draft(
    ctx: &mut ParseContext<'_>,
    spec: &TableSpec,
    r: RowDraft,
    order: Option<DateOrder>,
) -> Result<Option<StagedRow>> {
    ctx.stats.read += 1;
    let cells: std::result::Result<Vec<(Option<String>, bool)>, String> =
        r.cells.iter().map(|c| c.stage_zoned(order)).collect();
    match cells {
        Ok(cells) => {
            let (cells, tz_assumed): (Vec<_>, Vec<_>) = cells.into_iter().unzip();
            Ok(Some(StagedRow {
                ordinal: r.ordinal,
                pos: r.sight.pos,
                raw_sha256: r.sight.raw_sha256,
                record_key: r.record_key,
                cells,
                raw: r.raw.map(|v| v.to_string()),
                tz_assumed,
            }))
        }
        Err(msg) => {
            let msg = format!("{}: {msg}", spec.table);
            ctx.parse_error_at(r.ordinal, &r.sight.pos, &r.snippet, &msg)?;
            Ok(None)
        }
    }
}

/// Add one table's load to the file's counts (and its fill-missing warning).
fn count_load(ctx: &mut ParseContext<'_>, spec: &TableSpec, out: LoadOutcome) {
    ctx.stats.loaded += out.inserted + out.updated;
    ctx.stats.duplicate += out.duplicate();
    if spec.mode == LoadMode::FillMissing && out.updated > 0 {
        ctx.warn(format!(
            "{} {} records filled values missing from copies loaded earlier",
            out.updated, spec.table
        ));
    }
}

/// [`load_streamed`]'s steps, after the caller's own (its `first_step` argument), and the `steps()` of UAL, whose
/// passes and merge are the same: the two passes, then the merge of what they staged.
pub const LOAD_STREAMED_STEPS: &[&str] = &["Checking dates", "Loading records", SAVING_RECORDS];

/// Where [`load_streamed`]'s `tail` hands each of its rows: `(table, draft)`, staged at once.
pub type TailSink<'s> = dyn FnMut(usize, RowDraft) -> Result<()> + 's;

/// A [`load_streamed`] `tail` that produces no row.
pub fn no_tail(_: &mut TailSink<'_>) -> Result<()> {
    Ok(())
}

/// What one record gives [`load_streamed`].
pub enum RowOut {
    /// A row for `tables[table]`.
    Row { table: usize, draft: RowDraft },
    /// The record cannot be loaded, for this reason ([`reject`]).
    Reject(String),
}

/// [`load_tables`] for a large CSV/JSON file, without holding its records or rows: the records are streamed twice
/// (the first pass records the unreadable ones and reads every time cell for the day/month order, the second turns
/// each record into rows with `rows_of` again and stages them) and each table's rows are appended every
/// [`crate::ingest::IngestOptions::batch_rows`] rows to one [`StateFileStage`] per table, merged once at the end of
/// the file, so a key keeps the file's first copy. `rows_of` must be pure: it runs twice per record. `tail` produces
/// rows the caller builds apart from the records (e.g. per-message rows collapsed from them): called once, after the
/// streamed rows are staged, it hands each `(table, draft)` to the sink it is given, which stages it, so the tail is
/// never held whole; they are staged after the streamed rows, as [`load_tables`] would after the earlier tables. The
/// tail's time cells are not read for the day/month order (it is resolved before the tail is produced): each must be a
/// copy of a time cell of a streamed row, so it adds no evidence (checked: the file fails otherwise). Counts, errors and
/// warnings are those of [`load_tables`] over the same rows. The two passes are steps `first_step` and `first_step + 1`
/// of the parser ([`LOAD_STREAMED_STEPS`]); the tail runs within the second, after its pass, and the merge is step
/// `first_step + 2`.
pub fn load_streamed(
    ctx: &mut ParseContext<'_>,
    first_step: usize,
    format: RecordFormat,
    tables: &[(&'static TableSpec, &'static [&'static str])],
    tail: impl FnOnce(&mut TailSink<'_>) -> Result<()>,
    mut rows_of: impl FnMut(&SourceRecord) -> Vec<RowOut>,
) -> Result<()> {
    let mut detector = DateOrderDetector::default();
    ctx.set_step(first_step);
    // The first pass reads only times: the records' sightings are not needed.
    for_each_record(&ctx.input().with_sights(false), format, |event| {
        match event {
            RecordEvent::Error {
                ordinal,
                pos,
                snippet,
                message,
            } => {
                ctx.stats.read += 1;
                ctx.parse_error_at(ordinal, &pos, &snippet, &message)?;
            }
            RecordEvent::Record(r) => {
                for out in rows_of(&r) {
                    if let RowOut::Row { draft, .. } = out {
                        for cell in &draft.cells {
                            if let Cell::Time(s) = cell {
                                detector.observe(s);
                            }
                        }
                    }
                }
            }
        }
        Ok(true)
    })?;
    let order = ctx.resolve_date_order(&detector)?;
    let batch = ctx.options.batch_rows.max(1);
    // One stage per table for the whole file (staged once, merged once by `finish`): a per-batch merge inside the
    // file's transaction would keep every batch's staging until COMMIT.
    let conn = ctx.conn;
    let mut stages = tables
        .iter()
        .map(|(spec, columns)| StateFileStage::begin(conn, spec, columns, ctx.file_id))
        .collect::<Result<Vec<_>>>()?;
    let mut staged: Vec<Vec<StagedRow>> = tables.iter().map(|_| Vec::new()).collect();
    let mut check = PickOrderCheck::new(tables.len());
    let flush =
        |ctx: &ParseContext<'_>, stage: &mut StateFileStage<'_>, rows: &mut Vec<StagedRow>| {
            if rows.is_empty() {
                return Ok(());
            }
            ctx.check_cancelled()?;
            stage.stage(rows)?;
            ctx.note_staged(rows.len() as u64);
            rows.clear();
            Ok::<(), Error>(())
        };
    ctx.set_step(first_step + 1);
    for_each_record(&ctx.input(), format, |event| {
        let RecordEvent::Record(r) = event else {
            return Ok(true);
        };
        for out in rows_of(&r) {
            match out {
                RowOut::Reject(msg) => reject(ctx, &r, &msg)?,
                RowOut::Row { table, draft } => {
                    if let Some(row) = stage_draft(ctx, tables[table].0, draft, order)? {
                        check.streamed(table, &row);
                        staged[table].push(row);
                        if staged[table].len() >= batch {
                            flush(ctx, &mut stages[table], &mut staged[table])?;
                        }
                    }
                }
            }
        }
        Ok(true)
    })?;
    for (stage, rows) in stages.iter_mut().zip(staged.iter_mut()) {
        flush(ctx, stage, rows)?;
    }
    // The evidence the tail's times give, had they been read with the records': it must be what resolved `order`.
    let mut with_tail = detector.clone();
    tail(&mut |table, draft| {
        for cell in &draft.cells {
            if let Cell::Time(s) = cell {
                with_tail.observe(s);
            }
        }
        if let Some(row) = stage_draft(ctx, tables[table].0, draft, order)? {
            check.tail(table, &row);
            staged[table].push(row);
            if staged[table].len() >= batch {
                flush(ctx, &mut stages[table], &mut staged[table])?;
            }
        }
        Ok(())
    })?;
    if with_tail != detector {
        // Fail closed: the order the rows were staged with is not the one their times prove.
        return Err(Error::Invalid(
            "a collapsed row's time is not one of its records' times: it changes the day/month order".into(),
        ));
    }
    for (stage, rows) in stages.iter_mut().zip(staged.iter_mut()) {
        flush(ctx, stage, rows)?;
    }
    ctx.check_cancelled()?;
    ctx.set_step(first_step + 2);
    let mut outcomes = Vec::with_capacity(tables.len());
    for stage in stages {
        outcomes.push(stage.finish(ctx.collection_id)?);
    }
    for (i, out) in outcomes.into_iter().enumerate() {
        count_load(ctx, tables[i].0, out);
    }
    Ok(())
}

/// Debug check that [`load_streamed`]'s staging order picks what batches picked: a batch picked a key's copy by
/// (ordinal, position in batch), the whole-file stage picks the first staged copy. They agree when the copies of a
/// key are staged in ordinal order within the streamed rows and within the tail (the tail is staged after the
/// streamed rows and loses to them either way). Streamed rows follow the records, so their ordinals never fall.
struct PickOrderCheck {
    last_streamed: Vec<Option<u64>>,
    tail: std::collections::HashMap<(usize, String), u64>,
}

impl PickOrderCheck {
    fn new(tables: usize) -> Self {
        PickOrderCheck {
            last_streamed: vec![None; tables],
            tail: Default::default(),
        }
    }

    fn streamed(&mut self, table: usize, row: &StagedRow) {
        if cfg!(debug_assertions) {
            let last = self.last_streamed[table].replace(row.ordinal);
            debug_assert!(
                last.is_none_or(|l| l <= row.ordinal),
                "streamed rows of table {table} staged out of ordinal order ({last:?} then {})",
                row.ordinal
            );
        }
    }

    fn tail(&mut self, table: usize, row: &StagedRow) {
        if cfg!(debug_assertions)
            && let Some(prev) = self
                .tail
                .insert((table, row.record_key.clone()), row.ordinal)
        {
            debug_assert!(
                prev <= row.ordinal,
                "tail copies of key {} staged out of ordinal order ({prev} then {})",
                row.record_key,
                row.ordinal
            );
        }
    }
}

/// Non-empty cells of a CSV row (blank cells are dropped, other values kept as they are).
pub fn non_empty_cells(map: &Map<String, Value>) -> Vec<(String, String)> {
    map.iter()
        .filter_map(|(k, v)| match v {
            Value::String(s) if !s.trim().is_empty() => Some((k.clone(), s.clone())),
            _ => None,
        })
        .collect()
}

/// `csvrow:` + SHA-256 hex of the row's non-empty cells, sorted by lower-case header, each pair
/// written as `<byte length of header>:<header><byte length of value>:<value>` so no value can
/// pass for another cell. Two downloads that order or trim columns differently agree.
pub fn csv_row_key(cells: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, &str)> = cells
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.as_str()))
        .collect();
    pairs.sort();
    let mut input = String::new();
    for (h, v) in pairs {
        input += &format!("{}:{h}{}:{v}", h.len(), v.len());
    }
    format!("csvrow:{}", sha256_hex(input.as_bytes()))
}

/// Record key of a collection's organization-level row (`audit_config`, one per collection).
pub fn org_key(collection_id: i64) -> String {
    format!("organization|{collection_id}")
}

/// Record key of a collection's row of a per-collection tenant-wide table (`transport_rules`,
/// `remote_domains`): `<collection_id>|<lower name>`, so captures of different tenants in one
/// case never merge into one row.
pub fn collection_key(collection_id: i64, name: &str) -> String {
    format!("{collection_id}|{}", name.to_lowercase())
}

/// Record key of a collection's `tenant_settings` row.
pub fn setting_key(collection_id: i64, source: &str, name: &str) -> String {
    format!("{collection_id}|{source}|{}", name.to_lowercase())
}
