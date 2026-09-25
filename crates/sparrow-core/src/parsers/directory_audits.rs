//! Entra ID directory audit events (spec 5.1 `directory_audits`): Hawk `EntraIDAuditLogs`
//! (Get-MgAuditLogDirectoryAudit objects; the CSV twin holds .NET type names in its nested
//! columns and is only used when the JSON is missing), and Microsoft-Extractor-Suite's
//! Get-GraphEntraAuditLogs (v1.0 `/auditLogs/directoryAudits` REST JSON, one page per file
//! under `EntraID/<ts>-AuditLogs/`). Its keys match the Hawk parser unchanged.

use crate::Result;
use crate::db::state_tables::DIRECTORY_AUDITS;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::{normalize_ip, normalize_upn};
use crate::normalize::ual_shape::get_ci;
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{
    CellRow, TableRows, load_tables, lower, read_state_records, reject, require_any_key,
};
use crate::readers::time::zone_assumed;
use serde_json::{Value, json};

pub fn register(r: &mut ParserRegistry) {
    r.register("hawk.tenant.entra_audit", Box::new(DirectoryAuditsParser));
    r.register("inv.entra_audit", Box::new(DirectoryAuditsParser));
    r.register("inv.entra_audit.merged", Box::new(DirectoryAuditsParser));
}

/// directory_audits.record_key: the audit Id, lower-case.
pub fn directory_audit_key(rec: &Rec) -> Option<String> {
    lower(rec.text("Id"))
}

const COLS: &[&str] = &[
    "audit_id",
    "event_time",
    "time_tz_assumed",
    "activity",
    "category",
    "operation_type",
    "result",
    "result_reason",
    "logged_by_service",
    "initiated_by_upn",
    "initiated_by_user_id",
    "initiated_by_app_id",
    "initiated_by_app_name",
    "initiated_by_ip",
    "targets",
    "modified_properties",
    "additional_details",
    "correlation_id",
];

/// `TargetResources[].ModifiedProperties` as `[{target, property, old, new}]`.
fn modified_properties(targets: Option<&Value>) -> Option<Value> {
    let mut out = Vec::new();
    for t in targets?.as_array()?.iter().filter_map(Value::as_object) {
        let target = Rec::new(t, false).first_text(&["UserPrincipalName", "DisplayName", "Id"]);
        if let Some(Value::Array(props)) = get_ci(t, "ModifiedProperties") {
            for p in props.iter().filter_map(Value::as_object) {
                let p = Rec::new(p, false);
                out.push(json!({
                    "target": target, "property": p.text("DisplayName"),
                    "old": p.text("OldValue"), "new": p.text("NewValue")
                }));
            }
        }
    }
    (!out.is_empty()).then_some(Value::Array(out))
}

pub struct DirectoryAuditsParser;

impl ArtifactParser for DirectoryAuditsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["ActivityDateTime"], "Entra ID directory audit")?;
        let mut rows = TableRows::new(&DIRECTORY_AUDITS, COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = directory_audit_key(&rec) else {
                reject(ctx, r, "directory audit has no Id")?;
                continue;
            };
            let by = rec.object("InitiatedBy");
            let user = by.as_ref().and_then(|b| b.object("User"));
            let app = by.as_ref().and_then(|b| b.object("App"));
            let targets = rec.json("TargetResources").filter(Value::is_array);
            let time = rec.text("ActivityDateTime");
            let mut c = CellRow::new(COLS);
            c.set("audit_id", Cell::text(Some(key.clone())))
                .set("event_time", Cell::time(time.clone()))
                .set(
                    "time_tz_assumed",
                    Cell::bool(time.as_deref().map(zone_assumed)),
                )
                .set("activity", Cell::text(rec.text("ActivityDisplayName")))
                .set("category", Cell::text(rec.text("Category")))
                .set("operation_type", Cell::text(rec.text("OperationType")))
                .set("result", Cell::text(rec.text("Result")))
                .set("result_reason", Cell::text(rec.text("ResultReason")))
                .set("logged_by_service", Cell::text(rec.text("LoggedByService")))
                .set(
                    "initiated_by_upn",
                    Cell::text(
                        user.as_ref()
                            .and_then(|u| u.text("UserPrincipalName"))
                            .and_then(|s| normalize_upn(&s)),
                    ),
                )
                .set(
                    "initiated_by_user_id",
                    Cell::text(lower(user.as_ref().and_then(|u| u.text("Id")))),
                )
                .set(
                    "initiated_by_app_id",
                    Cell::text(lower(app.as_ref().and_then(|a| a.text("AppId")))),
                )
                .set(
                    "initiated_by_app_name",
                    Cell::text(app.as_ref().and_then(|a| a.text("DisplayName"))),
                )
                .set(
                    "initiated_by_ip",
                    Cell::text(
                        user.as_ref()
                            .and_then(|u| u.text("IPAddress"))
                            .and_then(|s| normalize_ip(&s)),
                    ),
                )
                .set(
                    "modified_properties",
                    Cell::json(modified_properties(targets.as_ref())),
                )
                .set("targets", Cell::json(targets))
                .set(
                    "additional_details",
                    Cell::json(
                        rec.json("AdditionalDetails")
                            .filter(|v| v.as_array().is_some_and(|a| !a.is_empty())),
                    ),
                )
                .set(
                    "correlation_id",
                    Cell::text(lower(rec.text("CorrelationId"))),
                );
            rows.push(r, key, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}
