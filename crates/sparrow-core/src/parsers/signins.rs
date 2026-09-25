//! Entra ID sign-ins (spec 5.1 `signins`): Hawk `Entra_Sign_In_Log_*` (Get-MgAuditLogSignIn
//! objects as JSON, or a CSV whose nested columns are .NET type names) and the Entra admin
//! center sign-in export (CSV or XLSX). The record shape comes from the keys. Every source keys
//! a sign-in by its lower-cased id (the portal's Request ID), so copies from several sources
//! are one row that each source fills where the others lack a value.

use crate::db::state_tables::SIGNINS;
use crate::discovery::{FileFormat, format_from_path};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::{normalize_ip, normalize_upn};
use crate::parsers::records::RecordFormat;
use crate::parsers::risk::graph_location;
use crate::parsers::stage::{
    CellRow, RowDraft, SheetRow, TableRows, load_tables, lower, read_state_records, reject_at,
};
use crate::readers::csv_scan::normalize_headers;
use crate::readers::text::Span;
use crate::readers::time::zone_assumed;
use crate::readers::xlsx::read_xlsx;
use crate::{Error, Result};
use serde_json::{Map, Value, json};

pub fn register(r: &mut ParserRegistry) {
    r.register("hawk.user.entra_signin", Box::new(SigninsParser));
    r.register("portal.entra_signins", Box::new(SigninsParser));
}

/// signins.record_key: the sign-in id (Graph `Id`, portal `Request ID`), lower-case. The
/// collector_flags link of `_Investigate_Entra_Sign_In_Log` records uses the same key.
pub fn signin_key(rec: &Rec) -> Option<String> {
    lower(rec.first_text(&["Id", "Request ID"]))
}

const COLS: &[&str] = &[
    "signin_id",
    "event_time",
    "time_tz_assumed",
    "event_type",
    "user_upn",
    "user_id",
    "user_display_name",
    "app_id",
    "app_name",
    "resource_id",
    "resource_name",
    "ip",
    "user_agent",
    "client_app",
    "is_interactive",
    "status",
    "error_code",
    "failure_reason",
    "ca_status",
    "ca_policies",
    "risk_level_during",
    "risk_level_aggregated",
    "risk_state",
    "risk_detail",
    "risk_event_types",
    "auth_requirement",
    "mfa_result",
    "mfa_detail",
    "auth_methods",
    "device",
    "location",
    "asn",
    "session_id",
    "correlation_id",
    "unique_token_id",
    "token_issuer_type",
    "incoming_token_type",
    "cross_tenant_access_type",
    "home_tenant_id",
    "resource_tenant_id",
];

/// One record to load: a CSV/JSON record or an XLSX row.
struct Input {
    ordinal: u64,
    span: Span,
    sheet_row: Option<SheetRow>,
    map: Map<String, Value>,
    lossy: bool,
}

fn text_inputs(ctx: &mut ParseContext<'_>) -> Result<Vec<Input>> {
    let format = RecordFormat::of(ctx.rel_path);
    Ok(read_state_records(ctx, format)?
        .into_iter()
        .map(|r| Input {
            ordinal: r.ordinal,
            span: r.span,
            sheet_row: None,
            map: r.map,
            lossy: format.lossy(),
        })
        .collect())
}

/// XLSX rows keyed by the normalized header row (same cleanup as CSV headers).
fn xlsx_inputs(ctx: &mut ParseContext<'_>) -> Result<Vec<Input>> {
    let table = read_xlsx(ctx.raw).map_err(Error::Invalid)?;
    let headers = normalize_headers(table.headers.iter().map(String::as_str));
    Ok(table
        .rows
        .into_iter()
        .map(|row| {
            let map: Map<String, Value> = row
                .fields
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let key = headers
                        .get(i)
                        .cloned()
                        .unwrap_or_else(|| format!("_extra_{}", i - headers.len()));
                    (key, Value::String(v.clone()))
                })
                .collect();
            Input {
                ordinal: row.row as u64,
                span: Span { start: 0, end: 0 },
                sheet_row: Some(SheetRow {
                    row: row.row,
                    text: row.text(),
                }),
                map,
                lossy: true,
            }
        })
        .collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Graph,
    Portal,
}

fn shape_of(inputs: &[Input]) -> Option<Shape> {
    let has = |i: &Input, k: &str| Rec::new(&i.map, false).has(k);
    if inputs
        .iter()
        .any(|i| has(i, "Date (UTC)") && has(i, "Request ID"))
    {
        Some(Shape::Portal)
    } else if inputs
        .iter()
        .any(|i| has(i, "CreatedDateTime") && has(i, "Id"))
    {
        Some(Shape::Graph)
    } else {
        None
    }
}

/// The portal names its exports after the sign-in type (InteractiveSignIns_...,
/// NonInteractiveSignIns_..., ServicePrincipalSignIns_..., ManagedIdentitySignIns_...).
fn portal_event_type(rel_path: &str) -> Option<&'static str> {
    let name = rel_path
        .rsplit('/')
        .next()
        .unwrap_or(rel_path)
        .to_ascii_lowercase();
    if name.contains("noninteractive") {
        Some("noninteractive")
    } else if name.contains("serviceprincipal") {
        Some("service_principal")
    } else if name.contains("managedidentit") {
        Some("managed_identity")
    } else if name.contains("interactive") {
        Some("interactive")
    } else {
        None
    }
}

fn upn(v: Option<String>) -> Option<String> {
    v.and_then(|s| normalize_upn(&s))
}

fn ip(v: Option<String>) -> Option<String> {
    v.and_then(|s| normalize_ip(&s))
}

/// `True`/`False` or `Yes`/`No` text (portal exports).
fn flag(rec: &Rec, key: &str) -> Option<bool> {
    rec.bool(key)
        .or_else(|| match rec.text(key)?.to_ascii_lowercase().as_str() {
            "yes" => Some(true),
            "no" => Some(false),
            _ => None,
        })
}

/// The device STRUCT with every key (the cast requires them); `None` when all are empty.
fn device(
    device_id: Option<String>,
    display_name: Option<String>,
    os: Option<String>,
    browser: Option<String>,
    is_compliant: Option<bool>,
    is_managed: Option<bool>,
    trust_type: Option<String>,
) -> Option<Value> {
    let v = json!({
        "device_id": device_id, "display_name": display_name, "os": os, "browser": browser,
        "is_compliant": is_compliant, "is_managed": is_managed, "trust_type": trust_type
    });
    v.as_object()
        .is_some_and(|m| m.values().any(|x| !x.is_null()))
        .then_some(v)
}

fn graph_device(rec: &Rec) -> Option<Value> {
    let d = rec.object("DeviceDetail")?;
    device(
        d.text("DeviceId"),
        d.text("DisplayName"),
        d.text("OperatingSystem"),
        d.text("Browser"),
        d.bool("IsCompliant"),
        d.bool("IsManaged"),
        d.text("TrustType"),
    )
}

/// Portal `Location`: `City, State, CC` (fewer parts when unknown); no coordinates.
fn portal_location(text: Option<String>) -> Option<Value> {
    let text = text?;
    let parts: Vec<&str> = text
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    let (city, state, country) = match parts.as_slice() {
        [] => return None,
        [country] => (None, None, Some(country.to_string())),
        [city, country] => (Some(city.to_string()), None, Some(country.to_string())),
        [city, middle @ .., country] => (
            Some(city.to_string()),
            Some(middle.join(", ")),
            Some(country.to_string()),
        ),
    };
    Some(json!({
        "city": city, "state": state, "country": country, "latitude": null, "longitude": null
    }))
}

fn risk_event_types(rec: &Rec) -> Vec<String> {
    let v2 = rec.list("RiskEventTypesV2");
    if v2.is_empty() {
        rec.list("RiskEventTypes")
    } else {
        v2
    }
}

/// Graph beta `authenticationDetails[].authenticationMethod`, distinct, in order.
fn graph_auth_methods(rec: &Rec) -> Vec<String> {
    let Some(Value::Array(items)) = rec.json("AuthenticationDetails") else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for m in items
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|o| Rec::new(o, false).text("AuthenticationMethod"))
    {
        if !out.contains(&m) {
            out.push(m);
        }
    }
    out
}

fn graph_row(rec: &Rec) -> Vec<Cell> {
    let status = rec.object("Status");
    let error_code = status.as_ref().and_then(|s| s.int("ErrorCode"));
    let interactive = rec.bool("IsInteractive");
    let time = rec.text("CreatedDateTime");
    let mut c = CellRow::new(COLS);
    c.set("signin_id", Cell::text(signin_key(rec)))
        .set("event_time", Cell::time(time.clone()))
        .set(
            "time_tz_assumed",
            Cell::bool(time.as_deref().map(zone_assumed)),
        )
        .set(
            "event_type",
            Cell::text(
                interactive.map(|i| if i { "interactive" } else { "noninteractive" }.to_string()),
            ),
        )
        .set("user_upn", Cell::text(upn(rec.text("UserPrincipalName"))))
        .set("user_id", Cell::text(lower(rec.text("UserId"))))
        .set("user_display_name", Cell::text(rec.text("UserDisplayName")))
        .set("app_id", Cell::text(lower(rec.text("AppId"))))
        .set("app_name", Cell::text(rec.text("AppDisplayName")))
        .set("resource_id", Cell::text(lower(rec.text("ResourceId"))))
        .set("resource_name", Cell::text(rec.text("ResourceDisplayName")))
        .set("ip", Cell::text(ip(rec.text("IPAddress"))))
        .set("user_agent", Cell::text(rec.text("UserAgent")))
        .set("client_app", Cell::text(rec.text("ClientAppUsed")))
        .set("is_interactive", Cell::bool(interactive))
        .set(
            "status",
            Cell::text(error_code.map(|e| if e == 0 { "Success" } else { "Failure" }.to_string())),
        )
        .set("error_code", Cell::int(error_code))
        .set(
            "failure_reason",
            Cell::text(status.as_ref().and_then(|s| s.text("FailureReason"))),
        )
        .set("ca_status", Cell::text(rec.text("ConditionalAccessStatus")))
        .set(
            "ca_policies",
            Cell::json(
                rec.json("AppliedConditionalAccessPolicies")
                    .filter(Value::is_array),
            ),
        )
        .set(
            "risk_level_during",
            Cell::text(rec.text("RiskLevelDuringSignIn")),
        )
        .set(
            "risk_level_aggregated",
            Cell::text(rec.text("RiskLevelAggregated")),
        )
        .set("risk_state", Cell::text(rec.text("RiskState")))
        .set("risk_detail", Cell::text(rec.text("RiskDetail")))
        .set("risk_event_types", Cell::list(risk_event_types(rec)))
        .set(
            "auth_requirement",
            Cell::text(rec.text("AuthenticationRequirement")),
        )
        .set("auth_methods", Cell::list(graph_auth_methods(rec)))
        .set("device", Cell::json(graph_device(rec)))
        .set("location", Cell::json(graph_location(rec)))
        .set("asn", Cell::int(rec.int("AutonomousSystemNumber")))
        .set("session_id", Cell::text(rec.text("SessionId")))
        .set(
            "correlation_id",
            Cell::text(lower(rec.text("CorrelationId"))),
        )
        .set(
            "unique_token_id",
            Cell::text(rec.text("UniqueTokenIdentifier")),
        )
        .set("token_issuer_type", Cell::text(rec.text("TokenIssuerType")))
        .set(
            "incoming_token_type",
            Cell::text(rec.text("IncomingTokenType")),
        )
        .set(
            "cross_tenant_access_type",
            Cell::text(rec.text("CrossTenantAccessType")),
        )
        .set(
            "home_tenant_id",
            Cell::text(lower(rec.text("HomeTenantId"))),
        )
        .set(
            "resource_tenant_id",
            Cell::text(lower(rec.text("ResourceTenantId"))),
        );
    c.into_cells()
}

/// Portal export columns (after header cleanup: trimmed, inner spaces collapsed, a repeated
/// `Incoming token type` becomes `Incoming token type_2`).
fn portal_row(rec: &Rec, event_type: Option<&'static str>) -> Vec<Cell> {
    let time = rec.text("Date (UTC)");
    let methods: Vec<String> = rec
        .text("Multifactor authentication auth method")
        .into_iter()
        .collect();
    let interactive = event_type.and_then(|t| match t {
        "interactive" => Some(true),
        "noninteractive" => Some(false),
        _ => None,
    });
    let mut c = CellRow::new(COLS);
    c.set("signin_id", Cell::text(signin_key(rec)))
        .set("event_time", Cell::time(time.clone()))
        // Date (UTC) is UTC by definition, even when XLSX renders it without a zone.
        .set("time_tz_assumed", Cell::bool(time.as_ref().map(|_| false)))
        .set("event_type", Cell::text(event_type.map(Into::into)))
        .set("user_upn", Cell::text(upn(rec.text("Username"))))
        .set("user_id", Cell::text(lower(rec.text("User ID"))))
        .set("user_display_name", Cell::text(rec.text("User")))
        .set("app_id", Cell::text(lower(rec.text("Application ID"))))
        .set("app_name", Cell::text(rec.text("Application")))
        .set("resource_id", Cell::text(lower(rec.text("Resource ID"))))
        .set("resource_name", Cell::text(rec.text("Resource")))
        .set("ip", Cell::text(ip(rec.text("IP address"))))
        .set("user_agent", Cell::text(rec.text("User agent")))
        .set("client_app", Cell::text(rec.text("Client app")))
        .set("is_interactive", Cell::bool(interactive))
        .set("status", Cell::text(rec.text("Status")))
        .set("error_code", Cell::int(rec.int("Sign-in error code")))
        .set("failure_reason", Cell::text(rec.text("Failure reason")))
        .set("ca_status", Cell::text(rec.text("Conditional Access")))
        .set(
            "auth_requirement",
            Cell::text(rec.text("Authentication requirement")),
        )
        .set(
            "mfa_result",
            Cell::text(rec.text("Multifactor authentication result")),
        )
        .set(
            "mfa_detail",
            Cell::text(rec.text("Multifactor authentication auth detail")),
        )
        .set("auth_methods", Cell::list(methods))
        .set(
            "device",
            Cell::json(device(
                rec.text("Device ID"),
                None,
                rec.text("Operating System"),
                rec.text("Browser"),
                flag(rec, "Compliant"),
                flag(rec, "Managed"),
                rec.text("Join Type"),
            )),
        )
        .set(
            "location",
            Cell::json(portal_location(rec.text("Location"))),
        )
        .set("asn", Cell::int(rec.int("Autonomous system number")))
        .set("session_id", Cell::text(rec.text("Session ID")))
        .set(
            "correlation_id",
            Cell::text(lower(rec.text("Correlation ID"))),
        )
        .set(
            "unique_token_id",
            Cell::text(rec.text("Unique token identifier")),
        )
        .set(
            "token_issuer_type",
            Cell::text(rec.text("Token issuer type")),
        )
        .set(
            "incoming_token_type",
            Cell::text(rec.text("Incoming token type")),
        )
        .set(
            "cross_tenant_access_type",
            Cell::text(rec.text("Cross tenant access type")),
        )
        .set(
            "home_tenant_id",
            Cell::text(lower(rec.text("Home tenant ID"))),
        )
        .set(
            "resource_tenant_id",
            Cell::text(lower(rec.text("Resource tenant ID"))),
        );
    c.into_cells()
}

pub struct SigninsParser;

impl ArtifactParser for SigninsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let inputs = if format_from_path(ctx.rel_path) == FileFormat::Xlsx {
            xlsx_inputs(ctx)?
        } else {
            text_inputs(ctx)?
        };
        let Some(first) = inputs.first() else {
            return Ok(());
        };
        let Some(shape) = shape_of(&inputs) else {
            let cols: Vec<&str> = first.map.keys().take(12).map(String::as_str).collect();
            return Err(Error::UnsupportedShape(format!(
                "no Entra sign-in fields (CreatedDateTime + Id, or Date (UTC) + Request ID) in [{}]",
                cols.join(", ")
            )));
        };
        let event_type = portal_event_type(ctx.rel_path);
        let mut rows = TableRows::new(&SIGNINS, COLS);
        for i in inputs {
            let rec = Rec::new(&i.map, i.lossy);
            let Some(key) = signin_key(&rec) else {
                reject_at(
                    ctx,
                    i.ordinal,
                    i.span,
                    i.sheet_row.as_ref(),
                    "sign-in has no Id / Request ID",
                )?;
                continue;
            };
            let cells = match shape {
                Shape::Graph => graph_row(&rec),
                Shape::Portal => portal_row(&rec, event_type),
            };
            rows.push_draft(RowDraft {
                ordinal: i.ordinal,
                span: i.span,
                record_key: key,
                cells,
                raw: Some(Value::Object(i.map)),
                sheet_row: i.sheet_row,
            });
        }
        load_tables(ctx, vec![rows])
    }
}
