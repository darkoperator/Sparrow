//! Unified audit log artifacts: every Hawk 3.x/4.x UAL file and the Purview audit search
//! export. The record shape is detected from the keys, never from the file name (Addendum A.3).

use crate::discovery::{FileFormat, format_from_path};
use crate::ingest::bulk::{StagedUal, load_ual_batch};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::ual::{event_time_text, normalize_audit};
use crate::normalize::ual_shape::{AuditInput, UalShape, detect_shape, to_audit};
use crate::readers::csv_scan::read_csv;
use crate::readers::json_scan::scan_json;
use crate::readers::text::Span;
use crate::readers::time::DateOrderDetector;
use crate::{Error, Result};
use serde_json::{Map, Value};

/// Artifact ids loaded into `ual_events`, and whether each is a derived Hawk file
/// (flattened or pre-processed, so its records are `partial`).
pub const UAL_ARTIFACTS: &[(&str, bool)] = &[
    ("hawk.tenant.raw_ual", false),
    ("hawk.tenant.simple_ual", true),
    ("hawk.tenant.entra_app_audit", false),
    ("hawk.user.raw_ual", false),
    ("hawk.user.simple_ual", true),
    ("hawk.user.raw_auth", false),
    ("hawk.user.converted_auth", true),
    ("hawk.ip.events", false),
    ("portal.ual", false),
];

pub struct UalParser {
    derived: bool,
}

pub fn register(r: &mut ParserRegistry) {
    for (id, derived) in UAL_ARTIFACTS {
        r.register(id, Box::new(UalParser { derived: *derived }));
    }
}

struct SourceRecord {
    ordinal: u64,
    span: Span,
    map: Map<String, Value>,
}

/// Every record of the file as a key → value map. Unreadable records go to `parse_errors`.
fn read_records(ctx: &mut ParseContext<'_>, is_csv: bool) -> Result<Vec<SourceRecord>> {
    let text = ctx.text;
    let mut out = Vec::new();
    if is_csv {
        let table = read_csv(&text.text);
        for e in &table.errors {
            ctx.stats.read += 1;
            ctx.parse_error(e.ordinal, e.span, &e.message)?;
        }
        for row in &table.rows {
            ctx.stats.read += 1;
            out.push(SourceRecord {
                ordinal: row.ordinal,
                span: row.span,
                map: table.row_map(row),
            });
        }
    } else {
        let scan = scan_json(&text.text);
        for e in &scan.errors {
            ctx.stats.read += 1;
            ctx.parse_error(e.ordinal, e.span, &e.message)?;
        }
        for r in scan.records {
            ctx.stats.read += 1;
            match r.value {
                Value::Object(map) => out.push(SourceRecord {
                    ordinal: r.ordinal,
                    span: r.span,
                    map,
                }),
                _ => ctx.parse_error(r.ordinal, r.span, "record is not a JSON object")?,
            }
        }
    }
    Ok(out)
}

fn preview_keys(map: &Map<String, Value>) -> String {
    map.keys()
        .take(12)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

impl ArtifactParser for UalParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let is_csv = format_from_path(ctx.rel_path) == FileFormat::Csv;
        let records = read_records(ctx, is_csv)?;
        let Some(first) = records.first() else {
            return Ok(());
        };
        let shape = detect_shape(first.map.keys().map(String::as_str), self.derived);
        match shape {
            UalShape::AdminAudit | UalShape::AdminAuditSimple => {
                return Err(Error::UnsupportedShape(
                    "Search-AdminAuditLog records (Hawk 3.x); they load into admin_audit_events in a later sparrow version".into(),
                ));
            }
            UalShape::Unknown => {
                return Err(Error::UnsupportedShape(format!(
                    "no unified audit log record shape matches columns [{}]",
                    preview_keys(&first.map)
                )));
            }
            _ => {}
        }
        let lossy = is_csv || self.derived;
        let inputs: Vec<(SourceRecord, std::result::Result<AuditInput, String>)> = records
            .into_iter()
            .map(|r| {
                let input = to_audit(shape, &r.map, lossy);
                (r, input)
            })
            .collect();
        let mut detector = DateOrderDetector::default();
        for input in inputs.iter().filter_map(|(_, i)| i.as_ref().ok()) {
            if let Some(t) = event_time_text(input) {
                detector.observe(&t);
            }
        }
        let order = detector
            .resolve(ctx.options.date_order)
            .map_err(Error::Invalid)?;
        let mut staged = Vec::with_capacity(inputs.len());
        for (r, input) in inputs {
            match input.and_then(|i| normalize_audit(&i, order)) {
                Ok(rec) => {
                    let (pos, raw_sha256) = ctx.sighting(r.span);
                    staged.push(StagedUal {
                        ordinal: r.ordinal,
                        pos,
                        raw_sha256,
                        rec,
                    });
                }
                Err(msg) => ctx.parse_error(r.ordinal, r.span, &msg)?,
            }
        }
        let out = load_ual_batch(ctx.conn, ctx.collection_id, ctx.file_id, &staged)?;
        ctx.stats.loaded += out.inserted + out.upgraded;
        ctx.stats.duplicate += out.duplicate();
        if out.upgraded > 0 {
            ctx.warn(format!(
                "{} records replaced partial rows loaded earlier from CSV or derived files",
                out.upgraded
            ));
        }
        let synthetic = staged.iter().filter(|s| s.rec.synthetic_id).count();
        if synthetic > 0 {
            ctx.warn(format!(
                "{synthetic} records have no valid AuditData Id; a content-derived id was used"
            ));
        }
        Ok(())
    }
}
