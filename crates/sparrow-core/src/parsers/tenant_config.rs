//! Organization configuration: AdminAuditLogConfig.txt and OrgConfig.txt (Format-List, one
//! object) and TransportConfig (JSON/CSV), and Microsoft-Extractor-Suite EntraSecurityDefaults.csv.
//! Every property becomes a tenant_settings row pointing at its own lines; the audit switches
//! also fill the collection's audit_config row.

use crate::Result;
use crate::db::state_tables::{AUDIT_CONFIG, TENANT_SETTINGS};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, InputMode, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{
    RowDraft, TableRows, load_tables, org_key, read_state_records, require_any_key, setting_key,
};
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
    r.register(
        "inv.licenses.security_defaults",
        Box::new(SecurityDefaultsParser),
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
    fn input(&self) -> InputMode {
        InputMode::Whole
    }

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
                let sight = r
                    .field_sights
                    .iter()
                    .find(|(k, _)| k == name)
                    .map_or(&r.sight, |(_, s)| s)
                    .clone();
                let value = match value {
                    Value::Null => None,
                    Value::String(s) if s.trim().is_empty() => None,
                    v => Some(v.clone()),
                };
                settings.push_draft(RowDraft {
                    ordinal: r.ordinal,
                    sight,
                    // Text and JSON cells always stage, so a setting row never needs a snippet; the record's stands in.
                    snippet: r.snippet.clone(),
                    record_key: setting_key(ctx.collection_id, self.source, name),
                    cells: vec![
                        Cell::text(Some(self.source.into())),
                        Cell::text(Some(name.clone())),
                        Cell::json(value),
                    ],
                    raw: None,
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
                audit.push(r, org_key(ctx.collection_id), cells);
            }
        }
        load_tables(ctx, vec![audit, settings])
    }
}

/// `Yes`/`No` (Microsoft-Extractor-Suite licence reports) or `True`/`False`.
pub fn yes_no(rec: &Rec, key: &str) -> Option<bool> {
    rec.bool(key)
        .or_else(|| match rec.text(key)?.to_ascii_lowercase().as_str() {
            "yes" => Some(true),
            "no" => Some(false),
            _ => None,
        })
}

const SECURITY_DEFAULTS_SOURCE: &str = "entra_security_defaults";

/// Microsoft-Extractor-Suite Get-EntraSecurityDefaults: one row (`SecurityDefaultsEnabled,
/// HasPremiumLicense, RecommendedState, AlignedWithRecommendations, CheckDate`). Every column
/// but `CheckDate` (the collector's local clock) becomes a tenant setting;
/// `SecurityDefaultsEnabled` also fills `audit_config`.
pub struct SecurityDefaultsParser;

impl ArtifactParser for SecurityDefaultsParser {
    fn input(&self) -> InputMode {
        InputMode::Whole
    }

    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(
            &records,
            &["SecurityDefaultsEnabled"],
            "Entra security defaults",
        )?;
        let mut settings = TableRows::new(&TENANT_SETTINGS, SETTING_COLS);
        let mut audit = TableRows::new(&AUDIT_CONFIG, &["security_defaults_enabled"]);
        for r in &records {
            for (name, value) in &r.map {
                if name.eq_ignore_ascii_case("CheckDate") {
                    continue;
                }
                let value = match value {
                    Value::String(s) if s.trim().is_empty() => None,
                    Value::Null => None,
                    v => Some(v.clone()),
                };
                settings.push_draft(RowDraft {
                    ordinal: r.ordinal,
                    sight: r.sight.clone(),
                    snippet: r.snippet.clone(),
                    record_key: setting_key(ctx.collection_id, SECURITY_DEFAULTS_SOURCE, name),
                    cells: vec![
                        Cell::text(Some(SECURITY_DEFAULTS_SOURCE.into())),
                        Cell::text(Some(name.clone())),
                        Cell::json(value),
                    ],
                    raw: None,
                });
            }
            let rec = Rec::new(&r.map, format.lossy());
            audit.push(
                r,
                org_key(ctx.collection_id),
                vec![Cell::bool(yes_no(&rec, "SecurityDefaultsEnabled"))],
            );
        }
        load_tables(ctx, vec![audit, settings])
    }
}
