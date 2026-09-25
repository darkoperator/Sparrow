//! Exchange admin audit log (Addendum A.3 `admin_audit_events`): Hawk 3 Search-AdminAuditLog
//! records (`New_/Set_/Remove_InboxRules`, `RBAC_Changes`, `User_Changes_<user>`) and Hawk's
//! five-column summary of them (`Caller, Cmdlet, FullCommand, RunDate(UTC), ObjectModified`,
//! written by `Get-SimpleAdminAuditLog`). Hawk 4 writes these commands as UAL records, which
//! stay in `ual_events`. Every copy of a command (JSON, CSV, Format-List, `_Investigate_`,
//! summary) gets the same key: it is built only from what the summary keeps, in the form the
//! summary writes it.

use crate::Result;
use crate::db::state_tables::ADMIN_AUDIT_EVENTS;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::{normalize_ip, normalize_upn};
use crate::normalize::ual_shape::{UalShape, detect_shape, get_ci};
use crate::parsers::records::{RecordFormat, SourceRecord};
use crate::parsers::stage::{
    CellRow, TableRows, file_date_order, key_time, load_tables, lower, read_state_records, reject,
    unsupported,
};
use crate::readers::time::{DateOrder, zone_assumed};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub fn register(r: &mut ParserRegistry) {
    r.register("hawk.tenant.admin_audit", Box::new(AdminAuditParser));
}

/// Caller as `Get-SimpleAdminAuditLog` writes it: empty gives `***`; a caller containing
/// `on behalf of` gives `<first word of its 4th /-segment> on behalf of <its last /-segment>`
/// (trailing quotes trimmed); anything else is unchanged. A summary's caller maps to itself.
pub fn simple_caller(caller: Option<&str>) -> String {
    let c = caller.map(str::trim).unwrap_or("");
    if c.is_empty() {
        return "***".to_string();
    }
    if c.to_ascii_lowercase().contains("on behalf of") {
        let parts: Vec<&str> = c.split('/').collect();
        if parts.len() >= 4 {
            let start = parts[3]
                .split(' ')
                .next()
                .unwrap_or("")
                .trim_end_matches('"');
            let end = parts[parts.len() - 1].trim_end_matches('"');
            return format!("{start} on behalf of {end}");
        }
    }
    c.to_string()
}

/// ObjectModified as the summary writes it: the part after the last `/`, then after the
/// last `\`.
pub fn short_object(object: Option<&str>) -> String {
    let o = object.map(str::trim).unwrap_or("");
    let after_slash = o.rsplit('/').next().unwrap_or(o);
    after_slash
        .rsplit('\\')
        .next()
        .unwrap_or(after_slash)
        .to_string()
}

fn run_date(rec: &Rec) -> Option<String> {
    rec.first_text(&["RunDate", "RunDate(UTC)"])
}

/// admin_audit_events.record_key (see the table COMMENT); `None` without a cmdlet or run date.
pub fn admin_audit_key(rec: &Rec, order: Option<DateOrder>) -> Option<String> {
    let cmdlet = rec.first_text(&["CmdletName", "Cmdlet"])?;
    let run = run_date(rec)?;
    let parts = [
        "admin_audit".to_string(),
        key_time(&run, order),
        cmdlet.to_lowercase(),
        short_object(rec.text("ObjectModified").as_deref()).to_lowercase(),
        simple_caller(rec.text("Caller").as_deref()).to_lowercase(),
    ];
    Some(hex::encode(Sha256::digest(parts.join("\n").as_bytes())))
}

/// CmdletParameters (`[{Name, Value}]`) as a name -> value object (JSON sources only; the
/// first of repeated names wins).
fn parameters(rec: &Rec) -> Option<Value> {
    let Some(Value::Array(items)) = rec.json("CmdletParameters") else {
        return None;
    };
    let mut map = Map::new();
    for p in items.iter().filter_map(Value::as_object) {
        let Some(name) = Rec::new(p, false).text("Name") else {
            continue;
        };
        let value = match get_ci(p, "Value") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
        };
        map.entry(name).or_insert(Value::String(value));
    }
    (!map.is_empty()).then_some(Value::Object(map))
}

const COLS: &[&str] = &[
    "run_time",
    "time_tz_assumed",
    "caller",
    "cmdlet",
    "object_modified",
    "parameters",
    "modified_properties",
    "succeeded",
    "error",
    "external_access",
    "client_ip",
    "session_id",
    "app_id",
    "client_app_id",
    "originating_server",
    "full_command",
    "data_completeness",
];

/// Load Search-AdminAuditLog records. `simple`: Hawk's five-column summary. `lossy`: CSV or
/// Format-List text, whose parameters and modified properties are lost.
pub fn load_admin_audit(
    ctx: &mut ParseContext<'_>,
    records: &[SourceRecord],
    lossy: bool,
    simple: bool,
) -> Result<()> {
    let dates: Vec<String> = records
        .iter()
        .filter_map(|r| run_date(&Rec::new(&r.map, lossy)))
        .collect();
    let order = file_date_order(ctx, dates.iter().map(String::as_str))?;
    let completeness = if simple || lossy { "partial" } else { "full" };
    let mut rows = TableRows::new(&ADMIN_AUDIT_EVENTS, COLS);
    for r in records {
        let rec = Rec::new(&r.map, lossy);
        let Some(key) = admin_audit_key(&rec, order) else {
            reject(ctx, r, "admin audit record has no cmdlet or run date")?;
            continue;
        };
        let run = run_date(&rec);
        // The summary's RunDate(UTC) is UTC even though it carries no zone.
        let tz_assumed = run.as_deref().map(|s| !simple && zone_assumed(s));
        let mut c = CellRow::new(COLS);
        c.set("run_time", Cell::time(run))
            .set("time_tz_assumed", Cell::bool(tz_assumed))
            .set(
                "caller",
                Cell::text(rec.text("Caller").and_then(|s| normalize_upn(&s))),
            )
            .set(
                "cmdlet",
                Cell::text(rec.first_text(&["CmdletName", "Cmdlet"])),
            )
            .set("object_modified", Cell::text(rec.text("ObjectModified")))
            .set("parameters", Cell::json(parameters(&rec)))
            .set(
                "modified_properties",
                Cell::json(
                    rec.json("ModifiedProperties")
                        .filter(|v| v.as_array().is_some_and(|a| !a.is_empty())),
                ),
            )
            .set("succeeded", Cell::bool(rec.bool("Succeeded")))
            .set("error", Cell::text(rec.text("Error")))
            .set("external_access", Cell::bool(rec.bool("ExternalAccess")))
            .set(
                "client_ip",
                Cell::text(rec.text("ClientIP").and_then(|s| normalize_ip(&s))),
            )
            .set("session_id", Cell::text(rec.text("SessionId")))
            .set("app_id", Cell::text(lower(rec.text("AppId"))))
            .set("client_app_id", Cell::text(lower(rec.text("ClientAppId"))))
            .set(
                "originating_server",
                Cell::text(rec.text("OriginatingServer")),
            )
            .set("full_command", Cell::text(rec.text("FullCommand")))
            .set(
                "data_completeness",
                Cell::text(Some(completeness.to_string())),
            );
        rows.push(r, key, c.into_cells());
    }
    if simple && !records.is_empty() {
        ctx.warn(
            "Hawk 3 five-column admin audit summary (Caller, Cmdlet, FullCommand, RunDate(UTC), ObjectModified) loaded as partial rows: the full Search-AdminAuditLog file for these records is missing",
        );
    }
    load_tables(ctx, vec![rows])
}

/// `Tenant/New_|Set_|Remove_InboxRules`: Search-AdminAuditLog output (full or summary form).
pub struct AdminAuditParser;

impl ArtifactParser for AdminAuditParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        let Some(first) = records.first() else {
            return Ok(());
        };
        match detect_shape(first.map.keys().map(String::as_str), false) {
            UalShape::AdminAudit => load_admin_audit(ctx, &records, format.lossy(), false),
            UalShape::AdminAuditSimple => load_admin_audit(ctx, &records, format.lossy(), true),
            _ => Err(unsupported(first, "Search-AdminAuditLog")),
        }
    }
}
