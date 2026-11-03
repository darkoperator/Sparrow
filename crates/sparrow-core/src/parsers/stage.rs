//! Shared plumbing for the state-table parsers: collect rows per table, resolve culture
//! date order across the whole file, stage the cells and load them.

use crate::db::state_tables::{LoadMode, TableSpec};
use crate::hash::sha256_hex;
use crate::ingest::context::ParseContext;
use crate::ingest::state::{LoadOutcome, StagedRow, load_rows, load_rows_batch};
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

/// The `steps()` of a parser that loads with [`load_streamed`] (and of UAL, whose passes are the same).
pub const LOAD_STREAMED_STEPS: &[&str] = &["Checking dates", "Loading records"];

/// What one record gives [`load_streamed`].
pub enum RowOut {
    /// A row for `tables[table]`.
    Row { table: usize, draft: RowDraft },
    /// The record cannot be loaded, for this reason ([`reject`]).
    Reject(String),
}

/// [`load_tables`] for a large CSV/JSON file, without holding its records or rows: the records are streamed twice
/// (the first pass records the unreadable ones and reads every time cell for the day/month order, the second turns
/// each record into rows with `rows_of` again and stages them) and each table is loaded every
/// [`crate::ingest::IngestOptions::batch_rows`] rows with [`load_rows_batch`], so a key keeps the file's first copy
/// across batches as within one. `rows_of` must be pure: it runs twice per record. `tail` are rows the caller built
/// before (each `(table, draft)`; e.g. per-message rows collapsed from the records): their times count for the order
/// and they are staged after the streamed rows, as [`load_tables`] would after the earlier tables. Counts, errors and
/// warnings are those of [`load_tables`] over the same rows. The two passes are steps 0 and 1 of the parser
/// ([`LOAD_STREAMED_STEPS`]).
pub fn load_streamed(
    ctx: &mut ParseContext<'_>,
    format: RecordFormat,
    tables: &[(&'static TableSpec, &'static [&'static str])],
    tail: Vec<(usize, RowDraft)>,
    mut rows_of: impl FnMut(&SourceRecord) -> Vec<RowOut>,
) -> Result<()> {
    let mut detector = DateOrderDetector::default();
    for cell in tail.iter().flat_map(|(_, d)| &d.cells) {
        if let Cell::Time(s) = cell {
            detector.observe(s);
        }
    }
    ctx.set_step(0);
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
    let mut staged: Vec<Vec<StagedRow>> = tables.iter().map(|_| Vec::new()).collect();
    let mut outcomes: Vec<LoadOutcome> = vec![LoadOutcome::default(); tables.len()];
    let load =
        |ctx: &ParseContext<'_>, i: usize, rows: &mut Vec<StagedRow>, total: &mut LoadOutcome| {
            if rows.is_empty() {
                return Ok(());
            }
            ctx.check_cancelled()?;
            let (spec, columns) = tables[i];
            let out = load_rows_batch(
                ctx.conn,
                spec,
                columns,
                ctx.collection_id,
                ctx.file_id,
                rows,
            )?;
            total.staged += out.staged;
            total.inserted += out.inserted;
            total.updated += out.updated;
            rows.clear();
            Ok::<(), Error>(())
        };
    ctx.set_step(1);
    for_each_record(&ctx.input(), format, |event| {
        let RecordEvent::Record(r) = event else {
            return Ok(true);
        };
        for out in rows_of(&r) {
            match out {
                RowOut::Reject(msg) => reject(ctx, &r, &msg)?,
                RowOut::Row { table, draft } => {
                    if let Some(row) = stage_draft(ctx, tables[table].0, draft, order)? {
                        staged[table].push(row);
                        if staged[table].len() >= batch {
                            load(ctx, table, &mut staged[table], &mut outcomes[table])?;
                        }
                    }
                }
            }
        }
        Ok(true)
    })?;
    for (i, rows) in staged.iter_mut().enumerate() {
        load(ctx, i, rows, &mut outcomes[i])?;
    }
    for (table, draft) in tail {
        if let Some(row) = stage_draft(ctx, tables[table].0, draft, order)? {
            staged[table].push(row);
            if staged[table].len() >= batch {
                load(ctx, table, &mut staged[table], &mut outcomes[table])?;
            }
        }
    }
    for (i, rows) in staged.iter_mut().enumerate() {
        load(ctx, i, rows, &mut outcomes[i])?;
    }
    for (i, out) in outcomes.into_iter().enumerate() {
        count_load(ctx, tables[i].0, out);
    }
    Ok(())
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
