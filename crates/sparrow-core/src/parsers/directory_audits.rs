//! Entra ID directory audit events (spec 5.1 `directory_audits`): Hawk `EntraIDAuditLogs`
//! (Get-MgAuditLogDirectoryAudit objects; the CSV twin holds .NET type names in its nested
//! columns and is only used when the JSON is missing), and Microsoft-Extractor-Suite's
//! Get-GraphEntraAuditLogs (v1.0 `/auditLogs/directoryAudits` REST JSON, one page per file
//! under `EntraID/<ts>-AuditLogs/`). Its keys match the Hawk parser unchanged.
//!
//! The Entra admin center audit log download (`portal.entra_audit`) is either that same Graph
//! JSON (keyed by `id`) or an 86-column CSV with no audit id. A CSV row is rebuilt into the
//! Graph shape (`graph_shaped`) and goes through the same extraction as the JSON.

use crate::Result;
use crate::db::state_tables::DIRECTORY_AUDITS;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::{normalize_ip, normalize_upn};
use crate::normalize::ual_shape::get_ci;
use crate::parsers::records::{RecordFormat, SourceRecord};
use crate::parsers::stage::{
    CellRow, RowDraft, TableRows, csv_row_key, load_tables, lower, non_empty_cells,
    read_state_records, reject, require_any_key,
};
use crate::readers::time::zone_assumed;
use serde_json::{Map, Value, json};

pub fn register(r: &mut ParserRegistry) {
    r.register("hawk.tenant.entra_audit", Box::new(DirectoryAuditsParser));
    r.register("inv.entra_audit", Box::new(DirectoryAuditsParser));
    r.register("inv.entra_audit.merged", Box::new(DirectoryAuditsParser));
    r.register("portal.entra_audit", Box::new(DirectoryAuditsParser));
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
    "data_completeness",
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

/// The portal CSV has these (case-insensitive) columns and no `ActivityDateTime`.
fn is_portal_csv(records: &[SourceRecord]) -> bool {
    records.first().is_some_and(|r| {
        let rec = Rec::new(&r.map, false);
        rec.has("Date (UTC)") && rec.has("Activity") && !rec.has("ActivityDateTime")
    })
}

/// A portal CSV row as a Graph `directoryAudit` object (camelCase). Empty cells are left out;
/// a target whose cells are all empty and a property without a name are dropped.
fn graph_shaped(row: &Map<String, Value>) -> Map<String, Value> {
    let rec = Rec::new(row, false);
    let put = |m: &mut Map<String, Value>, key: &str, v: Option<String>| {
        if let Some(v) = v {
            m.insert(key.into(), Value::String(v));
        }
    };
    let mut out = Map::new();
    put(&mut out, "activityDateTime", rec.text("Date (UTC)"));
    put(&mut out, "correlationId", rec.text("CorrelationId"));
    put(&mut out, "loggedByService", rec.text("Service"));
    put(&mut out, "category", rec.text("Category"));
    put(&mut out, "activityDisplayName", rec.text("Activity"));
    put(&mut out, "result", rec.text("Result"));
    put(&mut out, "resultReason", rec.text("ResultReason"));

    let mut by = Map::new();
    if rec
        .text("ActorType")
        .is_some_and(|t| t.eq_ignore_ascii_case("Application"))
    {
        let mut app = Map::new();
        put(&mut app, "displayName", rec.text("ActorDisplayName"));
        put(
            &mut app,
            "servicePrincipalId",
            rec.text("ActorServicePrincipalId"),
        );
        put(
            &mut app,
            "servicePrincipalName",
            rec.text("ActorServicePrincipalName"),
        );
        if !app.is_empty() {
            by.insert("app".into(), Value::Object(app));
        }
    } else {
        let mut user = Map::new();
        put(&mut user, "id", rec.text("ActorObjectId"));
        put(&mut user, "displayName", rec.text("ActorDisplayName"));
        put(
            &mut user,
            "userPrincipalName",
            rec.text("ActorUserPrincipalName"),
        );
        put(&mut user, "ipAddress", rec.text("IPAddress"));
        if !user.is_empty() {
            by.insert("user".into(), Value::Object(user));
        }
    }
    if !by.is_empty() {
        out.insert("initiatedBy".into(), Value::Object(by));
    }

    let mut targets = Vec::new();
    for n in 1..=3 {
        let mut t = Map::new();
        put(&mut t, "type", rec.text(&format!("Target{n}Type")));
        put(
            &mut t,
            "displayName",
            rec.text(&format!("Target{n}DisplayName")),
        );
        put(&mut t, "id", rec.text(&format!("Target{n}ObjectId")));
        put(
            &mut t,
            "userPrincipalName",
            rec.text(&format!("Target{n}UserPrincipalName")),
        );
        let mut props = Vec::new();
        for m in 1..=5 {
            let cell = |what: &str| rec.text(&format!("Target{n}ModifiedProperty{m}{what}"));
            let (name, old, new) = (cell("Name"), cell("OldValue"), cell("NewValue"));
            if let Some(name) = name {
                let mut p = Map::new();
                p.insert("displayName".into(), Value::String(name));
                put(&mut p, "oldValue", old);
                put(&mut p, "newValue", new);
                props.push(Value::Object(p));
            }
        }
        if t.is_empty() && props.is_empty() {
            continue;
        }
        t.insert("modifiedProperties".into(), Value::Array(props));
        targets.push(Value::Object(t));
    }
    out.insert("targetResources".into(), Value::Array(targets));

    let details: Vec<Value> = (1..=6)
        .filter_map(|k| {
            let key = rec.text(&format!("AdditionalDetail{k}Key"))?;
            let mut d = Map::new();
            d.insert("key".into(), Value::String(key));
            put(
                &mut d,
                "value",
                rec.text(&format!("AdditionalDetail{k}Value")),
            );
            Some(Value::Object(d))
        })
        .collect();
    out.insert("additionalDetails".into(), Value::Array(details));
    out
}

/// The `directory_audits` cells for one Graph-shaped (or Hawk PascalCase) audit record.
fn audit_cells(rec: &Rec, audit_id: Option<String>, completeness: &str) -> Vec<Cell> {
    let by = rec.object("InitiatedBy");
    let user = by.as_ref().and_then(|b| b.object("User"));
    let app = by.as_ref().and_then(|b| b.object("App"));
    let targets = rec.json("TargetResources").filter(Value::is_array);
    let time = rec.text("ActivityDateTime");
    let mut c = CellRow::new(COLS);
    c.set("audit_id", Cell::text(audit_id))
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
        )
        .set(
            "data_completeness",
            Cell::text(Some(completeness.to_string())),
        );
    c.into_cells()
}

pub struct DirectoryAuditsParser;

impl ArtifactParser for DirectoryAuditsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        let portal_csv = format == RecordFormat::Csv && is_portal_csv(&records);
        if !portal_csv {
            require_any_key(&records, &["ActivityDateTime"], "Entra ID directory audit")?;
        }
        let mut rows = TableRows::new(&DIRECTORY_AUDITS, COLS);
        for r in &records {
            if portal_csv {
                // No audit id: the key is a hash of the row's cells; the CSV stops at 3 targets x 5
                // properties and 6 details, so the row is partial.
                let cells = non_empty_cells(&r.map);
                let key = csv_row_key(&cells);
                let shaped = graph_shaped(&r.map);
                let cells_out = audit_cells(&Rec::new(&shaped, false), None, "partial");
                let raw: Map<String, Value> = cells
                    .into_iter()
                    .map(|(k, v)| (k, Value::String(v)))
                    .collect();
                rows.push_draft(RowDraft {
                    ordinal: r.ordinal,
                    sight: r.sight.clone(),
                    snippet: r.snippet.clone(),
                    record_key: key,
                    cells: cells_out,
                    raw: Some(Value::Object(raw)),
                });
                continue;
            }
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = directory_audit_key(&rec) else {
                reject(ctx, r, "directory audit has no Id")?;
                continue;
            };
            let completeness = if format == RecordFormat::Json {
                "full"
            } else {
                "partial"
            };
            let cells = audit_cells(&rec, Some(key.clone()), completeness);
            rows.push(r, key, cells);
        }
        load_tables(ctx, vec![rows])
    }
}
