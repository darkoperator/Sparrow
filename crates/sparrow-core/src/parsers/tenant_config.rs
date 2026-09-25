//! Organization configuration: AdminAuditLogConfig.txt and OrgConfig.txt (Format-List, one
//! object) and TransportConfig (JSON/CSV). Every property becomes a tenant_settings row
//! pointing at its own lines; the audit switches also fill the single audit_config row.

use crate::Result;
use crate::db::state_tables::{AUDIT_CONFIG, TENANT_SETTINGS};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{RowDraft, TableRows, load_tables, read_state_records};
use serde_json::Value;

pub fn register(r: &mut ParserRegistry) {
    r.register(
        "hawk.tenant.admin_audit_log_config",
        Box::new(ConfigParser {
            source: "admin_audit_log_config",
            audit_columns: ADMIN_AUDIT_COLS,
            audit_fields: ADMIN_AUDIT_FIELDS,
        }),
    );
    r.register(
        "hawk.tenant.org_config",
        Box::new(ConfigParser {
            source: "organization_config",
            audit_columns: ORG_AUDIT_COLS,
            audit_fields: ORG_AUDIT_FIELDS,
        }),
    );
    r.register(
        "hawk.tenant.transport_config",
        Box::new(ConfigParser {
            source: "transport_config",
            audit_columns: &[],
            audit_fields: &[],
        }),
    );
}

const ADMIN_AUDIT_COLS: &[&str] = &[
    "admin_audit_log_enabled",
    "unified_audit_log_ingestion_enabled",
    "admin_audit_log_age_limit",
    "log_level",
];
/// (property, is boolean), aligned with ADMIN_AUDIT_COLS.
const ADMIN_AUDIT_FIELDS: &[(&str, bool)] = &[
    ("AdminAuditLogEnabled", true),
    ("UnifiedAuditLogIngestionEnabled", true),
    ("AdminAuditLogAgeLimit", false),
    ("LogLevel", false),
];
const ORG_AUDIT_COLS: &[&str] = &["audit_disabled"];
const ORG_AUDIT_FIELDS: &[(&str, bool)] = &[("AuditDisabled", true)];
const SETTING_COLS: &[&str] = &["source", "name", "value"];

pub struct ConfigParser {
    pub source: &'static str,
    pub audit_columns: &'static [&'static str],
    pub audit_fields: &'static [(&'static str, bool)],
}

impl ArtifactParser for ConfigParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = match RecordFormat::of(ctx.rel_path) {
            RecordFormat::FormatList => RecordFormat::FormatListObject,
            f => f,
        };
        let records = read_state_records(ctx, format)?;
        let mut settings = TableRows::new(&TENANT_SETTINGS, SETTING_COLS);
        let mut audit = TableRows::new(&AUDIT_CONFIG, self.audit_columns);
        for r in &records {
            for (name, value) in &r.map {
                let span = r
                    .field_spans
                    .iter()
                    .find(|(k, _)| k == name)
                    .map_or(r.span, |(_, s)| *s);
                let value = match value {
                    Value::Null => None,
                    Value::String(s) if s.trim().is_empty() => None,
                    v => Some(v.clone()),
                };
                settings.push_draft(RowDraft {
                    ordinal: r.ordinal,
                    span,
                    record_key: format!("{}|{}", self.source, name.to_lowercase()),
                    cells: vec![
                        Cell::text(Some(self.source.into())),
                        Cell::text(Some(name.clone())),
                        Cell::json(value),
                    ],
                    raw: None,
                    sheet_row: None,
                });
            }
            if !self.audit_columns.is_empty() {
                let rec = Rec::new(&r.map, format.lossy());
                let cells = self
                    .audit_fields
                    .iter()
                    .map(|(field, is_bool)| {
                        if *is_bool {
                            Cell::bool(rec.bool(field))
                        } else {
                            Cell::text(rec.text(field))
                        }
                    })
                    .collect();
                audit.push(r, "organization".into(), cells);
            }
        }
        load_tables(ctx, vec![audit, settings])
    }
}
