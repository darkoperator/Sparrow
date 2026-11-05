//! Entra ID directory audit events (spec 5.1 `directory_audits`): Hawk `EntraIDAuditLogs`
//! (Get-MgAuditLogDirectoryAudit objects; the CSV twin holds .NET type names in its nested
//! columns and is only used when the JSON is missing), and Microsoft-Extractor-Suite's
//! Get-GraphEntraAuditLogs (v1.0 `/auditLogs/directoryAudits` REST JSON, one page per file
//! under `EntraID/<ts>-AuditLogs/`). Its keys match the Hawk parser unchanged.
//!
//! The Entra admin center audit log download (`portal.entra_audit`) is either that same Graph
//! JSON (keyed by `id`) or an 86-column CSV with no audit id. A CSV row is rebuilt into the
//! Graph shape (`graph_shaped`) and goes through the same extraction as the JSON.

use crate::db::state_tables::DIRECTORY_AUDITS;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::ingest::progress::SAVING_RECORDS;
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::{normalize_ip, normalize_upn};
use crate::normalize::ual_shape::get_ci;
use crate::parsers::records::{
    RecordEvent, RecordFormat, SourceRecord, for_each_record, holds_placeholder,
    placeholder_message,
};
use crate::parsers::stage::{
    CellRow, RowDraft, RowOut, csv_row_key, load_streamed, lower, no_tail, non_empty_cells,
    read_state_records,
};
use crate::readers::time::zone_assumed;
use crate::{Error, Result};
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

/// The portal CSV has these (case-insensitive) columns and no `ActivityDateTime` (read from its first record).
fn is_portal_csv(first: &Rec) -> bool {
    first.has("Date (UTC)") && first.has("Activity") && !first.has("ActivityDateTime")
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

/// [`DirectoryAuditsParser`]'s steps: the shape pass, then [`load_streamed`]'s.
const DIRECTORY_AUDITS_STEPS: &[&str] = &[
    "Checking columns",
    "Checking dates",
    "Loading records",
    SAVING_RECORDS,
];

/// The row of one record, or why it is rejected. Pure: [`load_streamed`] calls it twice per record.
fn rows_of(r: &SourceRecord, format: RecordFormat, portal_csv: bool) -> RowOut {
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
        return RowOut::Row {
            table: 0,
            draft: RowDraft {
                ordinal: r.ordinal,
                sight: r.sight.clone(),
                snippet: r.snippet.clone(),
                record_key: key,
                cells: cells_out,
                raw: Some(Value::Object(raw)),
            },
        };
    }
    let rec = Rec::new(&r.map, format.lossy());
    let Some(key) = directory_audit_key(&rec) else {
        return RowOut::Reject("directory audit has no Id".into());
    };
    let completeness = if format == RecordFormat::Json {
        "full"
    } else {
        "partial"
    };
    let cells = audit_cells(&rec, Some(key.clone()), completeness);
    // What `TableRows::push` filled: raw = the record.
    RowOut::Row {
        table: 0,
        draft: RowDraft {
            ordinal: r.ordinal,
            sight: r.sight.clone(),
            snippet: r.snippet.clone(),
            record_key: key,
            cells,
            raw: Some(Value::Object(r.map.clone())),
        },
    }
}

impl ArtifactParser for DirectoryAuditsParser {
    /// The shape pass (which stops once the shape is settled when it need not count placeholders), then
    /// [`load_streamed`]'s two passes and its merge. Every registered path is `.csv` or `.json`.
    fn steps(&self) -> &'static [&'static str] {
        DIRECTORY_AUDITS_STEPS
    }

    /// A CSV/JSON audit log, streamed (see [`load_streamed`]): a tenant's directory audits can be millions of events.
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        ctx.set_step(0);
        // What the collected records decided: a portal CSV by its first record, else some record must have
        // `ActivityDateTime` (the error names the first record's columns); and the placeholder count.
        let (mut first, mut portal_csv, mut timed, mut placeholders) = (None, false, false, 0usize);
        let count_placeholders = format == RecordFormat::Csv && !ctx.portal_export;
        // A shape pass: the records' sightings are not needed.
        for_each_record(&ctx.input().with_sights(false), format, |event| {
            if let RecordEvent::Record(r) = event {
                let rec = Rec::new(&r.map, false);
                if first.is_none() {
                    portal_csv = format == RecordFormat::Csv && is_portal_csv(&rec);
                    first = Some(r.map.keys().take(12).cloned().collect::<Vec<_>>());
                }
                timed |= rec.has("ActivityDateTime");
                if count_placeholders && holds_placeholder(&r) {
                    placeholders += 1;
                }
                // Settled once a portal CSV is seen or a record has its time; only the count can still change.
                return Ok(!((portal_csv || timed) && !count_placeholders));
            }
            Ok(true)
        })?;
        let Some(first) = first else {
            // No readable record: recording the unreadable ones is all there is to do (the load step's pass).
            ctx.set_step(2);
            read_state_records(ctx, format)?;
            return Ok(());
        };
        if !ctx.portal_export
            && let Some(w) = placeholder_message(placeholders)
        {
            ctx.warn(w);
        }
        if !portal_csv && !timed {
            return Err(Error::UnsupportedShape(format!(
                "no Entra ID directory audit fields in [{}]",
                first.join(", ")
            )));
        }
        load_streamed(ctx, 1, format, &[(&DIRECTORY_AUDITS, COLS)], no_tail, |r| {
            vec![rows_of(r, format, portal_csv)]
        })
    }
}
