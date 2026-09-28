//! Microsoft-Extractor-Suite Identity Protection and Defender state (research state layouts
//! §9-§11): RiskyEvents RiskyUsers.csv and RiskyEvents.csv into `risky_users` /
//! `risk_detections` (the same tables and columns as the Hawk risk parsers), and
//! SecurityAlerts.csv / SecureScore.csv into `security_alerts` / `secure_score`.

use crate::Result;
use crate::db::state_tables::{RISK_DETECTIONS, RISKY_USERS, SECURE_SCORE, SECURITY_ALERTS};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::records::RecordFormat;
use crate::parsers::risk::{
    DETECTION_COLS, RISKY_USER_COLS, risk_detection_cells, risky_user_cells,
};
use crate::parsers::stage::{
    CellRow, TableRows, collection_key, load_tables, lower, read_state_records, reject,
    require_any_key,
};
use serde_json::{Value, json};

pub fn register(r: &mut ParserRegistry) {
    r.register("inv.risky_users", Box::new(InvRiskyUsersParser));
    r.register("inv.risk_detections", Box::new(InvRiskDetectionsParser));
    r.register("inv.security_alerts", Box::new(SecurityAlertsParser));
    r.register("inv.secure_score", Box::new(SecureScoreParser));
}

/// A `"; "`-joined collector list (`""` gives no items).
fn semi_list(rec: &Rec, key: &str) -> Vec<String> {
    rec.text(key)
        .map(|s| {
            s.split("; ")
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// A `", "`-joined collector list (`""` gives no items).
fn comma_list(rec: &Rec, key: &str) -> Vec<String> {
    rec.text(key)
        .map(|s| {
            s.split(", ")
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// The location STRUCT from the flattened City / State / CountryOrRegion columns (the
/// Microsoft-Extractor-Suite rendering of the Graph Location object; no GeoCoordinates), or
/// `None` when the file carries no location.
fn csv_location(rec: &Rec) -> Option<Value> {
    let city = rec.text("City");
    let state = rec.text("State");
    let country = rec.first_text(&["CountryOrRegion", "Country"]);
    (city.is_some() || state.is_some() || country.is_some()).then(|| {
        json!({
            "city": city, "state": state, "country": country,
            "latitude": Value::Null, "longitude": Value::Null
        })
    })
}

/// RiskyUsers.csv: one `risky_users` row per risky user, the same columns as the Hawk parser.
pub struct InvRiskyUsersParser;

impl ArtifactParser for InvRiskyUsersParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["Id", "UserPrincipalName"], "risky user")?;
        let mut rows = TableRows::new(&RISKY_USERS, RISKY_USER_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let (key, cells) = risky_user_cells(&rec);
            let Some(key) = key else {
                reject(ctx, r, "risky user has neither Id nor UserPrincipalName")?;
                continue;
            };
            rows.push(r, key, cells);
        }
        load_tables(ctx, vec![rows])
    }
}

/// RiskyEvents.csv: one `risk_detections` row per detection, the Hawk columns with the
/// location taken from the flattened City / State / CountryOrRegion columns.
pub struct InvRiskDetectionsParser;

impl ArtifactParser for InvRiskDetectionsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["Id", "RiskEventType"], "risk detection")?;
        let mut rows = TableRows::new(&RISK_DETECTIONS, DETECTION_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let (key, cells) = risk_detection_cells(&rec, csv_location(&rec));
            let Some(key) = key else {
                reject(ctx, r, "risk detection has no Id")?;
                continue;
            };
            rows.push(r, key, cells);
        }
        load_tables(ctx, vec![rows])
    }
}

/// The `<user>/<ip>` entries of an AffectedUser cell (`"; "`-joined), split into the parts
/// before `/` (the user side) and after it (the IP side). The literal `null` IP is dropped by
/// the caller.
fn affected_parts(rec: &Rec, key: &str, want_user: bool) -> Vec<String> {
    semi_list(rec, key)
        .iter()
        .filter_map(|entry| {
            entry
                .rsplit_once('/')
                .map(|(left, right)| if want_user { left } else { right })
        })
        .filter(|part| !part.is_empty())
        .map(String::from)
        .collect()
}

/// The AffectedUser user parts (UPNs or names).
fn affected_users(rec: &Rec) -> Vec<String> {
    affected_parts(rec, "AffectedUser", true)
}

/// The AffectedUser IP parts, the literal `null` dropped.
fn affected_ips(rec: &Rec) -> Vec<String> {
    affected_parts(rec, "AffectedUser", false)
        .into_iter()
        .filter(|ip| !ip.eq_ignore_ascii_case("null"))
        .collect()
}

/// The AffectedHost host parts.
fn affected_hosts(rec: &Rec) -> Vec<String> {
    affected_parts(rec, "AffectedHost", true)
}

const SECURITY_ALERT_COLS: &[&str] = &[
    "alert_id",
    "created_time",
    "event_time",
    "last_modified",
    "closed_time",
    "title",
    "category",
    "severity",
    "status",
    "description",
    "detection_source",
    "affected_users",
    "affected_ips",
    "affected_hosts",
    "azure_tenant_id",
    "confidence",
    "provider",
    "vendor",
    "incident_ids",
    "comments",
    "tags",
];

/// SecurityAlerts.csv: the legacy Get-MgSecurityAlert rendering, one `security_alerts` row per
/// alert keyed by the lower-case alert id (fill missing).
pub struct SecurityAlertsParser;

impl ArtifactParser for SecurityAlertsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["Id", "Title"], "security alert")?;
        let mut rows = TableRows::new(&SECURITY_ALERTS, SECURITY_ALERT_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(id) = lower(rec.text("Id")) else {
                reject(ctx, r, "security alert has no Id")?;
                continue;
            };
            let mut c = CellRow::new(SECURITY_ALERT_COLS);
            c.set("alert_id", Cell::text(Some(id.clone())))
                .set("created_time", Cell::time(rec.text("CreatedDateTime")))
                .set("event_time", Cell::time(rec.text("EventDateTime")))
                .set(
                    "last_modified",
                    Cell::time(rec.text("LastModifiedDateTime")),
                )
                .set("closed_time", Cell::time(rec.text("ClosedDateTime")))
                .set("title", Cell::text(rec.text("Title")))
                .set("category", Cell::text(rec.text("Category")))
                .set("severity", Cell::text(rec.text("Severity")))
                .set("status", Cell::text(rec.text("Status")))
                .set("description", Cell::text(rec.text("Description")))
                .set("detection_source", Cell::text(rec.text("DetectionSource")))
                .set("affected_users", Cell::list(affected_users(&rec)))
                .set("affected_ips", Cell::list(affected_ips(&rec)))
                .set("affected_hosts", Cell::list(affected_hosts(&rec)))
                .set("azure_tenant_id", Cell::text(rec.text("AzureTenantId")))
                .set("confidence", Cell::int(rec.int("Confidence")))
                .set("provider", Cell::text(rec.text("Provider")))
                .set("vendor", Cell::text(rec.text("Vendor")))
                .set("incident_ids", Cell::list(comma_list(&rec, "IncidentIds")))
                .set("comments", Cell::text(rec.text("Comments")))
                .set("tags", Cell::list(comma_list(&rec, "Tags")));
            rows.push(r, id, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}

const SECURE_SCORE_COLS: &[&str] = &[
    "title",
    "category",
    "service",
    "status",
    "current_score",
    "max_score",
    "state",
    "action_type",
    "action_url",
    "implementation_cost",
    "user_impact",
    "tier",
    "rank",
    "deprecated",
    "threats",
    "last_modified",
];

/// The collector's culture-formatted double: invariant digits (optionally with a `.` decimal
/// separator), or exactly one comma between digit runs (the de-DE decimal separator). A comma
/// anywhere else (a thousands-separated integer, several commas, a comma beside a dot) is not a
/// number and yields `None`, so `1,234,567` and `1,234.5` are never misread.
fn parse_double(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.contains(',') {
        let mut parts = s.split(',');
        let (left, right) = (parts.next()?, parts.next()?);
        if parts.next().is_some()
            || left.is_empty()
            || right.is_empty()
            || !left.bytes().all(|b| b.is_ascii_digit())
            || !right.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        format!("{left}.{right}").parse().ok()
    } else {
        s.parse().ok()
    }
}

/// SecureScore.csv: one `secure_score` row per control profile, keyed `<collection_id>|<lower
/// Title>` (the export carries no control id).
pub struct SecureScoreParser;

impl ArtifactParser for SecureScoreParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["Title", "MaxScore"], "secure score control")?;
        let mut rows = TableRows::new(&SECURE_SCORE, SECURE_SCORE_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(title) = rec.text("Title") else {
                reject(ctx, r, "secure score row has no Title")?;
                continue;
            };
            let key = collection_key(ctx.collection_id, &title);
            let mut c = CellRow::new(SECURE_SCORE_COLS);
            c.set("title", Cell::text(Some(title)))
                .set("category", Cell::text(rec.text("Category")))
                .set("service", Cell::text(rec.text("Service")))
                .set("status", Cell::text(rec.text("Status")))
                .set(
                    "current_score",
                    Cell::text(
                        rec.text("CurrentScore")
                            .and_then(|s| parse_double(&s))
                            .map(|v| v.to_string()),
                    ),
                )
                .set(
                    "max_score",
                    Cell::text(
                        rec.text("MaxScore")
                            .and_then(|s| parse_double(&s))
                            .map(|v| v.to_string()),
                    ),
                )
                .set("state", Cell::text(rec.text("State")))
                .set("action_type", Cell::text(rec.text("ActionType")))
                .set("action_url", Cell::text(rec.text("ActionUrl")))
                .set(
                    "implementation_cost",
                    Cell::text(rec.text("ImplementationCost")),
                )
                .set("user_impact", Cell::text(rec.text("UserImpact")))
                .set("tier", Cell::text(rec.text("Tier")))
                .set("rank", Cell::int(rec.int("Rank")))
                .set("deprecated", Cell::bool(rec.bool("Deprecated")))
                .set("threats", Cell::list(semi_list(&rec, "Threats")))
                .set(
                    "last_modified",
                    Cell::time(rec.text("LastModifiedDateTime")),
                );
            rows.push(r, key, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}

#[cfg(test)]
mod tests {
    use super::parse_double;

    #[test]
    fn doubles_are_strict() {
        assert_eq!(parse_double("2,5"), Some(2.5));
        assert_eq!(parse_double("7"), Some(7.0));
        assert_eq!(parse_double("2.5"), Some(2.5));
        assert_eq!(parse_double(" 10 "), Some(10.0));
        // Thousands separators and malformed text are not numbers.
        assert_eq!(parse_double("1,234,567"), None);
        assert_eq!(parse_double("1,234.5"), None);
        assert_eq!(parse_double("1,234"), Some(1.234));
        assert_eq!(parse_double(""), None);
        assert_eq!(parse_double(","), None);
        assert_eq!(parse_double("2,"), None);
        assert_eq!(parse_double(",5"), None);
    }
}
