//! Entra ID Protection: risky users (Get-MgRiskyUser) and risk detections
//! (Get-MgRiskDetection; Hawk writes the raw objects as JSON and a flattened CSV).

use crate::Result;
use crate::db::state_tables::{RISK_DETECTIONS, RISKY_USERS};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::{normalize_ip, normalize_upn};
use crate::normalize::ual_shape::get_ci;
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{TableRows, load_tables, lower, read_state_records, reject};
use serde_json::{Map, Value, json};

pub fn register(r: &mut ParserRegistry) {
    r.register("hawk.tenant.risky_users", Box::new(RiskyUsersParser));
    r.register(
        "hawk.tenant.risk_detections",
        Box::new(RiskDetectionsParser),
    );
}

fn upn(rec: &Rec) -> Option<String> {
    rec.text("UserPrincipalName")
        .and_then(|u| normalize_upn(&u))
}

/// risky_users.record_key: lower user id, else lower UPN.
pub fn risky_user_key(rec: &Rec) -> Option<String> {
    lower(rec.text("Id")).or_else(|| upn(rec))
}

/// risk_detections.record_key: lower detection id.
pub fn risk_detection_key(rec: &Rec) -> Option<String> {
    lower(rec.text("Id"))
}

const RISKY_USER_COLS: &[&str] = &[
    "user_id",
    "upn",
    "display_name",
    "risk_level",
    "risk_state",
    "risk_detail",
    "risk_last_updated",
    "is_deleted",
    "is_processing",
];

pub struct RiskyUsersParser;

impl ArtifactParser for RiskyUsersParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        let mut rows = TableRows::new(&RISKY_USERS, RISKY_USER_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = risky_user_key(&rec) else {
                reject(ctx, r, "risky user has neither Id nor UserPrincipalName")?;
                continue;
            };
            rows.push(
                r,
                key,
                vec![
                    Cell::text(lower(rec.text("Id"))),
                    Cell::text(upn(&rec)),
                    Cell::text(rec.text("UserDisplayName")),
                    Cell::text(rec.text("RiskLevel")),
                    Cell::text(rec.text("RiskState")),
                    Cell::text(rec.text("RiskDetail")),
                    Cell::time(rec.text("RiskLastUpdatedDateTime")),
                    Cell::bool(rec.bool("IsDeleted")),
                    Cell::bool(rec.bool("IsProcessing")),
                ],
            );
        }
        load_tables(ctx, vec![rows])
    }
}

/// The Location object as the table's STRUCT (every key present, as the cast requires).
fn location(rec: &Rec) -> Option<Value> {
    let Value::Object(loc) = rec.json("Location")? else {
        return None;
    };
    let l = Rec::new(&loc, false);
    let geo = get_ci(&loc, "GeoCoordinates").and_then(Value::as_object);
    let num = |k: &str| geo.and_then(|g| get_ci(g, k)).and_then(Value::as_f64);
    Some(json!({
        "city": l.text("City"), "state": l.text("State"),
        "country": l.first_text(&["CountryOrRegion", "Country"]),
        "latitude": num("Latitude"), "longitude": num("Longitude")
    }))
}

/// AdditionalInfo parsed from its embedded JSON, else the flattened `AdditionalInfo_*` columns.
fn additional_info(rec: &Rec) -> Option<Value> {
    if let Some(v) = rec.json("AdditionalInfo") {
        return Some(v);
    }
    let flat: Map<String, Value> = rec
        .map()
        .iter()
        .filter_map(|(k, v)| {
            let name = k.strip_prefix("AdditionalInfo_")?;
            let s = v.as_str()?.trim();
            (!s.is_empty()).then(|| (name.to_string(), Value::String(s.to_string())))
        })
        .collect();
    (!flat.is_empty()).then_some(Value::Object(flat))
}

const DETECTION_COLS: &[&str] = &[
    "detection_id",
    "detected_time",
    "activity_time",
    "last_updated_time",
    "activity",
    "risk_event_type",
    "risk_level",
    "risk_state",
    "risk_detail",
    "detection_timing",
    "source",
    "token_issuer_type",
    "ip",
    "user_upn",
    "user_id",
    "user_display_name",
    "correlation_id",
    "request_id",
    "location",
    "additional_info",
];

pub struct RiskDetectionsParser;

impl ArtifactParser for RiskDetectionsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        let mut rows = TableRows::new(&RISK_DETECTIONS, DETECTION_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = risk_detection_key(&rec) else {
                reject(ctx, r, "risk detection has no Id")?;
                continue;
            };
            rows.push(
                r,
                key,
                vec![
                    Cell::text(rec.text("Id")),
                    Cell::time(rec.text("DetectedDateTime")),
                    Cell::time(rec.text("ActivityDateTime")),
                    Cell::time(rec.text("LastUpdatedDateTime")),
                    Cell::text(rec.text("Activity")),
                    Cell::text(rec.text("RiskEventType")),
                    Cell::text(rec.text("RiskLevel")),
                    Cell::text(rec.text("RiskState")),
                    Cell::text(rec.text("RiskDetail")),
                    Cell::text(rec.text("DetectionTimingType")),
                    Cell::text(rec.text("Source")),
                    Cell::text(rec.text("TokenIssuerType")),
                    Cell::text(rec.text("IPAddress").and_then(|s| normalize_ip(&s))),
                    Cell::text(upn(&rec)),
                    Cell::text(lower(rec.text("UserId"))),
                    Cell::text(rec.text("UserDisplayName")),
                    Cell::text(rec.text("CorrelationId")),
                    Cell::text(rec.text("RequestId")),
                    Cell::json(location(&rec)),
                    Cell::json(additional_info(&rec)),
                ],
            );
        }
        load_tables(ctx, vec![rows])
    }
}
