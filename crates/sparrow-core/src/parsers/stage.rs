//! Shared plumbing for the state-table parsers: collect rows per table, resolve culture
//! date order across the whole file, stage the cells and load them.

use crate::db::state_tables::TableSpec;
use crate::ingest::context::ParseContext;
use crate::ingest::state::{StagedRow, load_rows};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::records::{RecordFormat, SourceRecord, placeholder_warning, read_records};
use crate::readers::text::Span;
use crate::readers::time::DateOrderDetector;
use crate::{Error, Result};
use serde_json::Value;

pub struct RowDraft {
    pub ordinal: u64,
    pub span: Span,
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
            span: r.span,
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
    if let Some(w) = placeholder_warning(&records, format) {
        ctx.warn(w);
    }
    Ok(records)
}

pub fn lower(v: Option<String>) -> Option<String> {
    v.map(|s| s.to_lowercase())
}

/// Count `r` as read and record why it could not be loaded.
pub fn reject(ctx: &mut ParseContext<'_>, r: &SourceRecord, msg: &str) -> Result<()> {
    ctx.stats.read += 1;
    ctx.parse_error(r.ordinal, r.span, msg)
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
    let order = detector
        .resolve(ctx.options.date_order)
        .map_err(Error::Invalid)?;
    for t in tables {
        let mut staged = Vec::with_capacity(t.rows.len());
        for r in t.rows {
            ctx.stats.read += 1;
            let cells: std::result::Result<Vec<Option<String>>, String> =
                r.cells.iter().map(|c| c.stage(order)).collect();
            match cells {
                Ok(cells) => {
                    let (pos, raw_sha256) = ctx.sighting(r.span);
                    staged.push(StagedRow {
                        ordinal: r.ordinal,
                        pos,
                        raw_sha256,
                        record_key: r.record_key,
                        cells,
                        raw: r.raw.map(|v| v.to_string()),
                    });
                }
                Err(msg) => {
                    ctx.parse_error(r.ordinal, r.span, &format!("{}: {msg}", t.spec.table))?
                }
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
        ctx.stats.loaded += out.inserted + out.updated;
        ctx.stats.duplicate += out.duplicate();
    }
    Ok(())
}
