//! Unified audit log artifacts: every Hawk 3.x/4.x UAL file, every Microsoft-Extractor-Suite
//! Get-UAL output and the Purview audit search export. The record shape is detected from the
//! keys, never from the file name (Addendum A.3).

use crate::discovery::{FileFormat, format_from_path};
use crate::ingest::bulk::{StagedUal, load_ual_batch};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::Rec;
use crate::normalize::ual::{event_time_text, normalize_audit};
use crate::normalize::ual_shape::{AuditInput, Completeness, UalShape, detect_shape, to_audit};
use crate::parsers::admin_audit::load_admin_audit;
use crate::parsers::records::{RecordFormat, SourceRecord, read_records};
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
    // Microsoft-Extractor-Suite Get-UAL: CSV, JSON, JSONL, SOF-ELK and -AuditDataOnly all
    // reach the Raw / Record shapes. The Merged copy is complete (not flattened); the
    // registry marks it derived only so that it is processed last and superseded.
    ("inv.quickual.combined", true),
    ("inv.quickual.operation", false),
    ("inv.ual.graph", false),
    ("inv.ual.window", false),
    ("inv.ual.merged", false),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UalSource {
    Standard,
    Graph,
    Quickual,
}

pub struct UalParser {
    derived: bool,
    source: UalSource,
}

pub fn register(r: &mut ParserRegistry) {
    for (id, derived) in UAL_ARTIFACTS {
        let source = match *id {
            "inv.ual.graph" => UalSource::Graph,
            "inv.quickual.combined" | "inv.quickual.operation" => UalSource::Quickual,
            _ => UalSource::Standard,
        };
        r.register(
            id,
            Box::new(UalParser {
                derived: *derived,
                source,
            }),
        );
    }
}

/// UAL RecordType 24, `Discovery`.
const DISCOVERY_RECORD_TYPE: &str = "24";

/// `Tenant/eDiscoveryLogs.(csv|json)`, Hawk 3.1's search of the audit log for eDiscovery activity.
/// Provenance: the collector runs `Search-UnifiedAuditLog -RecordType Discovery` (survey / hawk
/// layouts) and writes a reduced 8-column CSV without RecordType, so every row of that artifact is
/// a Discovery (24) record even though the file does not say so. A RecordType the file carries
/// (Hawk 4, or a full export) always wins.
fn is_hawk3_ediscovery(rel_path: &str) -> bool {
    let lower = rel_path.replace('\\', "/").to_ascii_lowercase();
    lower.rsplit('/').next().is_some_and(|f| {
        f.strip_suffix(".csv")
            .or_else(|| f.strip_suffix(".json"))
            .is_some_and(|s| s == "ediscoverylogs")
    })
}

fn preview_keys(map: &Map<String, Value>) -> String {
    let mut s = map
        .keys()
        .take(12)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if map.len() > 12 {
        s.push_str(&format!(", … ({} more)", map.len() - 12));
    }
    s
}

fn value_text(map: &Map<String, Value>, key: &str) -> Option<String> {
    crate::normalize::ual_shape::get_ci(map, key).and_then(crate::normalize::ual_shape::value_text)
}

/// The 16 columns `Get-QuickUALOperations` writes (research event layouts §3).
const QUICKUAL_CSV_COLUMNS: &[&str] = &[
    "RecordType",
    "CreationDate",
    "UserIds",
    "Operations",
    "ResultIndex",
    "ResultCount",
    "AuditSearchRequestMetadata",
    "Identity",
    "IsValid",
    "ObjectState",
    "OperationQueried",
    "AuditData_UserId",
    "AuditData_ClientIP",
    "AuditData_UserAgent",
    "AuditData_ObjectId",
    "AuditData_Raw",
];

/// Whether a QuickUAL record has the fields the collector writes: JSON records carry
/// `OperationQueried` and a parsed `AuditData`; CSV rows carry the 16-column header. Anything
/// else in a triage root (for example an analyst's own `notes.csv`) is not a QuickUAL export.
fn is_quickual_record(rec: &Rec<'_>, is_csv: bool) -> bool {
    if is_csv {
        QUICKUAL_CSV_COLUMNS.iter().all(|c| rec.has(c))
    } else {
        rec.has("OperationQueried") && rec.has("AuditData")
    }
}

fn quickual_csv_input(record: &Map<String, Value>) -> Result<AuditInput> {
    if let Some(raw) = value_text(record, "AuditData_Raw") {
        let audit = match serde_json::from_str::<Value>(&raw) {
            Ok(Value::Object(m)) => m,
            Ok(_) => return Err(Error::Invalid("AuditData_Raw is not a JSON object".into())),
            Err(e) => {
                return Err(Error::Invalid(format!(
                    "AuditData_Raw is not valid JSON: {e}"
                )));
            }
        };
        return Ok(AuditInput {
            audit,
            completeness: Completeness::Full,
            outer_record_type: value_text(record, "RecordType"),
            outer_time: value_text(record, "CreationDate"),
            flat_params: Vec::new(),
        });
    }
    let mut audit = Map::new();
    for (src, dst) in [
        ("Operations", "Operation"),
        ("AuditData_UserId", "UserId"),
        ("UserIds", "UserId"),
        ("AuditData_ClientIP", "ClientIP"),
        ("AuditData_ObjectId", "ObjectId"),
    ] {
        if !audit.contains_key(dst) {
            if let Some(v) = value_text(record, src) {
                audit.insert(dst.into(), Value::String(v));
            }
        }
    }
    if let Some(v) = value_text(record, "CreationDate") {
        audit.insert("CreationTime".into(), Value::String(v));
    }
    if let Some(v) = value_text(record, "RecordType") {
        audit.insert("RecordType".into(), Value::String(v));
    }
    Ok(AuditInput {
        audit,
        completeness: Completeness::Partial,
        outer_record_type: value_text(record, "RecordType"),
        outer_time: value_text(record, "CreationDate"),
        flat_params: Vec::new(),
    })
}

impl ArtifactParser for UalParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let is_csv = format_from_path(ctx.rel_path) == FileFormat::Csv;
        let format = if is_csv {
            RecordFormat::Csv
        } else {
            RecordFormat::Json
        };
        if self.source == UalSource::Graph && !is_csv && ctx.text.text.trim() == "[" {
            ctx.warn("Get-UALGraph found no results (the file holds only \"[\")");
            return Ok(());
        }
        let records = read_records(ctx, format)?;
        let Some(first) = records.first() else {
            return Ok(());
        };
        let shape = if self.source == UalSource::Quickual {
            if !is_quickual_record(&Rec::new(&first.map, false), is_csv) {
                return Err(Error::UnsupportedShape(format!(
                    "not a QuickUAL export (missing {})",
                    if is_csv {
                        "the 16-column header"
                    } else {
                        "OperationQueried/AuditData"
                    }
                )));
            }
            UalShape::Raw
        } else {
            detect_shape(first.map.keys().map(String::as_str), self.derived)
        };
        match shape {
            // Hawk 3 writes Search-AdminAuditLog records under UAL-looking names
            // (RBAC_Changes, User_Changes, Simple_*): they belong in admin_audit_events.
            UalShape::AdminAudit | UalShape::AdminAuditSimple => {
                return load_admin_audit(
                    ctx,
                    &records,
                    is_csv,
                    shape == UalShape::AdminAuditSimple,
                );
            }
            UalShape::Unknown => {
                return Err(Error::UnsupportedShape(format!(
                    "no unified audit log record shape matches columns [{}]",
                    preview_keys(&first.map)
                )));
            }
            _ => {}
        }
        ctx.stats.read += records.len() as u64;
        let lossy = is_csv || self.derived;
        let ediscovery = is_hawk3_ediscovery(ctx.rel_path);
        let input_of = |r: &SourceRecord| -> std::result::Result<AuditInput, String> {
            if self.source == UalSource::Quickual && is_csv {
                quickual_csv_input(&r.map).map_err(|e| e.to_string())
            } else {
                to_audit(shape, &r.map, lossy).map(|mut i| {
                    // Hawk 3.1's reduced eDiscoveryLogs CSV has no RecordType column.
                    if ediscovery
                        && shape == UalShape::Record
                        && i.outer_record_type.is_none()
                        && crate::normalize::ual_shape::get_ci(&i.audit, "RecordType").is_none()
                    {
                        i.outer_record_type = Some(DISCOVERY_RECORD_TYPE.to_string());
                    }
                    i
                })
            }
        };
        // Two passes so the file's parsed records are never all held at once (a 1.76 GB Purview export held every
        // AuditData tree next to its row and peaked at 21.5 GB): the first reads each record's time for the
        // day/month order and drops the record's tree, the second parses again and normalizes one record at a time.
        let mut detector = DateOrderDetector::default();
        let mut any_timed = false;
        for r in &records {
            if let Some(t) = input_of(r).ok().as_ref().and_then(event_time_text) {
                any_timed = true;
                detector.observe(&t);
            }
        }
        if shape == UalShape::AppAudit && !any_timed {
            return Err(Error::UnsupportedShape(
                "Hawk application audit export has no timestamps (env_time is null); the same events are in the raw UAL and directory audit logs".into(),
            ));
        }
        let order = ctx.resolve_date_order(&detector)?;
        let mut staged = Vec::with_capacity(records.len());
        for r in records {
            match input_of(&r).and_then(|i| normalize_audit(&i, order)) {
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
