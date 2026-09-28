//! Microsoft-Extractor-Suite Azure activity state (research event layouts §5, §6):
//! Get-ActivityLogs `Activity Logs/<ts>/<stamp14>-<sub>-ActivityLog.json` and
//! Get-DirectoryActivityLogs `Directory Activity Logs/.../DirectoryActivityLogs.{csv,JSON}`
//! plus `...-DirectoryActivityLogs.jsonl` (a pretty array) into `azure_activity`. The four
//! renderings carry the same EventData objects, so they deduplicate by `eventDataId`.

use crate::Result;
use crate::db::state_tables::AZURE_ACTIVITY;
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
use serde_json::{Map, Value};

pub fn register(r: &mut ParserRegistry) {
    r.register("inv.activity", Box::new(ActivityParser));
    r.register("inv.directory_activity", Box::new(ActivityParser));
}

/// The raw scalar cell text of `key`, even when it is a PowerShell placeholder (`@{...}`),
/// which `Rec::text` filters out.
fn raw_text(rec: &Rec, key: &str) -> Option<String> {
    match get_ci(rec.map(), key)? {
        Value::String(s) => {
            let t = s.trim();
            (!t.is_empty()).then(|| t.to_string())
        }
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Field `name` of a flattened CSV PowerShell object cell `@{k=v; k2=v2}`, trimmed.
fn ps_object_field(text: &str, name: &str) -> Option<String> {
    let inner = text.strip_prefix("@{")?.strip_suffix('}')?;
    inner.split("; ").find_map(|entry| {
        let (k, v) = entry.split_once('=')?;
        (k.trim() == name)
            .then(|| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

/// The `value` of an ARM `{value, localizedValue}` field, from a JSON object or a flattened
/// CSV `@{value=...; localizedValue=...}` cell (`operationName`, `category`, `status`,
/// `subStatus`, `resourceProviderName`).
fn arm_value(rec: &Rec, key: &str) -> Option<String> {
    if let Some(Value::Object(m)) = get_ci(rec.map(), key) {
        return get_ci(m, "value")
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    ps_object_field(&raw_text(rec, key)?, "value")
}

/// A string map (`claims`, `properties`), from a JSON object or a flattened CSV `@{k=v; ...}`
/// cell.
fn string_map(rec: &Rec, key: &str) -> Option<Value> {
    if let Some(v @ Value::Object(_)) = get_ci(rec.map(), key) {
        return Some(v.clone());
    }
    let inner = raw_text(rec, key)?;
    let inner = inner.strip_prefix("@{")?.strip_suffix('}')?;
    let map: Map<String, Value> = inner
        .split("; ")
        .filter_map(|entry| {
            let (k, v) = entry.split_once('=')?;
            (!k.is_empty()).then(|| (k.to_string(), Value::String(v.to_string())))
        })
        .collect();
    (!map.is_empty()).then_some(Value::Object(map))
}

/// The client IP at `httpRequest.clientIpAddress`, from the JSON object or its flattened CSV
/// cell, normalized.
fn client_ip(rec: &Rec) -> Option<String> {
    if let Some(Value::Object(m)) = get_ci(rec.map(), "httpRequest") {
        return get_ci(m, "clientIpAddress")
            .and_then(Value::as_str)
            .and_then(normalize_ip);
    }
    ps_object_field(&raw_text(rec, "httpRequest")?, "clientIpAddress")
        .and_then(|s| normalize_ip(&s))
}

const AZURE_COLS: &[&str] = &[
    "event_data_id",
    "event_time",
    "time_tz_assumed",
    "caller",
    "operation_name",
    "category",
    "level",
    "status",
    "sub_status",
    "resource_id",
    "resource_group",
    "resource_provider",
    "subscription_id",
    "tenant_id",
    "ip",
    "correlation_id",
    "claims",
    "properties",
];

/// One `azure_activity` row per EventData record, keyed by the lower-case `eventDataId`.
pub struct ActivityParser;

impl ArtifactParser for ActivityParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["eventDataId", "operationName"], "activity log")?;
        let mut rows = TableRows::new(&AZURE_ACTIVITY, AZURE_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(id) = lower(rec.text("eventDataId")) else {
                reject(ctx, r, "activity log record has no eventDataId")?;
                continue;
            };
            let time = rec.text("eventTimestamp");
            let tz_assumed = time.as_deref().map(zone_assumed);
            let mut c = CellRow::new(AZURE_COLS);
            c.set("event_data_id", Cell::text(Some(id.clone())))
                .set("event_time", Cell::time(time))
                .set("time_tz_assumed", Cell::bool(tz_assumed))
                .set(
                    "caller",
                    Cell::text(rec.text("caller").and_then(|s| normalize_upn(&s))),
                )
                .set(
                    "operation_name",
                    Cell::text(arm_value(&rec, "operationName")),
                )
                .set("category", Cell::text(arm_value(&rec, "category")))
                .set("level", Cell::text(rec.text("level")))
                .set("status", Cell::text(arm_value(&rec, "status")))
                .set("sub_status", Cell::text(arm_value(&rec, "subStatus")))
                .set("resource_id", Cell::text(rec.text("resourceId")))
                .set("resource_group", Cell::text(rec.text("resourceGroupName")))
                .set(
                    "resource_provider",
                    Cell::text(arm_value(&rec, "resourceProviderName")),
                )
                .set(
                    "subscription_id",
                    Cell::text(lower(rec.text("subscriptionId"))),
                )
                .set("tenant_id", Cell::text(lower(rec.text("tenantId"))))
                .set("ip", Cell::text(client_ip(&rec)))
                .set(
                    "correlation_id",
                    Cell::text(lower(rec.text("correlationId"))),
                )
                .set("claims", Cell::json(string_map(&rec, "claims")))
                .set("properties", Cell::json(string_map(&rec, "properties")));
            rows.push(r, id, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}
