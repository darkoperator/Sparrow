//! Get-RiskyEvents, Get-SecurityAlerts and Get-SecureScore (research state layouts §9-§11):
//! `RiskyEvents/<ts>/<ts>-RiskyUsers.csv`, `RiskyEvents/<ts'>/<ts'>-RiskyEvents.csv`,
//! `SecurityAlerts/<ts>/<ts>-SecurityAlerts.csv` and `SecureScore/<ts>/<ts>-SecureScore.csv`.
//! Without Entra ID P2 the two RiskyEvents Graph calls throw and their run folders stay empty.

use super::Ctx;
use crate::Result;
use crate::events::RiskDetection;
use crate::keys;
use crate::ps::{DateEvidence, DtKind, PsDate, Rendered, Row, Val, export_csv};
use crate::story::Evidence;
use crate::tree::{FileSpec, Tree};
use crate::world::{Alert, RiskyUser, SecureScoreControl};
use chrono::{DateTime, Timelike, Utc};

fn r(k: &str, v: Val) -> (String, Val) {
    (k.to_string(), v)
}

fn opt(v: Option<String>) -> Val {
    v.map_or(Val::Null, Val::Str)
}

/// A typed Graph SDK `DateTime` (host culture, UTC wall clock).
fn date(v: Option<DateTime<Utc>>) -> Val {
    v.map_or(Val::Null, |t| Val::Date(PsDate::dotnet(t, DtKind::Utc)))
}

/// A REST `Invoke-MgGraphRequest` timestamp: kept ISO text on PS 5.1, culture on PS7.
fn rest_date(v: Option<DateTime<Utc>>) -> Val {
    v.map_or(Val::Null, |t| {
        let digits = if t.nanosecond() == 0 { 0 } else { 7 };
        Val::Date(PsDate::iso(t, digits))
    })
}

/// Renders `rows`, records the culture dates and one record key per row.
fn write_csv(
    c: &Ctx<'_>,
    tree: &mut Tree<'_>,
    rel: &str,
    artifact: &'static str,
    table: &'static str,
    rows: &[Row],
    keys: &[String],
) -> Result<Rendered> {
    let mut ev = DateEvidence::default();
    let rendered = export_csv(&c.host, rows, &mut ev);
    tree.write(
        &FileSpec::new(rel, Some(artifact), c.utf8()),
        &rendered.text,
    )?;
    if ev.culture_dates > 0 {
        tree.date_evidence(rel, ev);
    }
    for key in keys {
        tree.row(rel, table, key.clone());
    }
    Ok(rendered)
}

/// One RiskyUsers.csv row (10 columns, research §9.1): `AdditionalProperties` is always `""`.
fn risky_user_row(u: &RiskyUser) -> Row {
    vec![
        r("Id", Val::Str(u.user_id.to_string())),
        r("IsDeleted", Val::Bool(false)),
        r("IsProcessing", Val::Bool(false)),
        r("RiskDetail", Val::Str(u.detail.clone())),
        r("RiskLastUpdatedDateTime", rest_date(Some(u.updated))),
        r("RiskLevel", Val::Str(u.level.clone())),
        r("RiskState", Val::Str(u.state.clone())),
        r("UserDisplayName", Val::Str(u.display_name.clone())),
        r("UserPrincipalName", Val::Str(u.upn.clone())),
        r("AdditionalProperties", Val::Str(String::new())),
    ]
}

/// One RiskyEvents.csv row (23 columns, research §9.2): `AdditionalProperties` is always `""`.
fn risk_detection_row(d: &RiskDetection) -> Row {
    vec![
        r("Activity", Val::Str(d.activity.clone())),
        r("ActivityDateTime", rest_date(Some(d.activity_time))),
        r("AdditionalInfo", Val::Str(d.additional_info.clone())),
        r(
            "CorrelationId",
            opt(d.correlation_id.map(|u| u.to_string())),
        ),
        r("DetectedDateTime", rest_date(Some(d.detected))),
        r("IPAddress", opt(d.ip.map(|i| i.to_string()))),
        r("Id", Val::Str(d.id.clone())),
        r("LastUpdatedDateTime", rest_date(Some(d.updated))),
        r("City", opt(d.location.as_ref().map(|l| l.city.clone()))),
        r(
            "CountryOrRegion",
            opt(d.location.as_ref().map(|l| l.country.clone())),
        ),
        r("State", opt(d.location.as_ref().map(|l| l.state.clone()))),
        r("RequestId", opt(d.request_id.map(|u| u.to_string()))),
        r("RiskDetail", Val::Str(d.detail.clone())),
        r("RiskEventType", Val::Str(d.event_type.clone())),
        r("RiskLevel", Val::Str(d.level.clone())),
        r("RiskState", Val::Str(d.state.clone())),
        r("DetectionTimingType", Val::Str(d.timing.clone())),
        r("Source", Val::Str(d.source.clone())),
        // `TokenIssuerType` is the world's value (AzureAD for Entra detections).
        r("TokenIssuerType", Val::Str(d.token_issuer_type.clone())),
        r("UserDisplayName", Val::Str(d.user_display.clone())),
        r("UserId", Val::Str(d.user_id.to_string())),
        r("UserPrincipalName", Val::Str(d.user.clone())),
        r("AdditionalProperties", Val::Str(String::new())),
    ]
}

/// The legacy AffectedUser rendering: `"<upn>/<ip>"`, `"<upn>/null"` when there is no IP.
fn affected_user(a: &Alert) -> Val {
    match &a.affected_user {
        Some(upn) => Val::Str(format!(
            "{upn}/{}",
            a.ip.map(|i| i.to_string()).unwrap_or_else(|| "null".into())
        )),
        None => Val::Str(String::new()),
    }
}

/// One SecurityAlerts.csv row (29 columns, research §10, legacy Get-MgSecurityAlert rendering).
fn alert_row(a: &Alert) -> Row {
    vec![
        r("Id", Val::Str(a.id.clone())),
        r("Title", Val::Str(a.title.clone())),
        r("Category", Val::Str(a.category.clone())),
        r("Severity", Val::Str(a.severity.clone())),
        r("Status", Val::Str(a.status.clone())),
        r("CreatedDateTime", date(Some(a.created))),
        r("EventDateTime", date(Some(a.event))),
        r("LastModifiedDateTime", date(Some(a.last_modified))),
        r("AssignedTo", Val::Null),
        r("Description", Val::Null),
        r("DetectionSource", Val::Null),
        r("AffectedUser", affected_user(a)),
        r("AffectedHost", Val::Str(String::new())),
        r("AzureTenantId", Val::Str(a.azure_tenant_id.to_string())),
        r("AzureSubscriptionId", Val::Null),
        r("Confidence", Val::Int(a.confidence)),
        r("ActivityGroupName", Val::Null),
        r("ClosedDateTime", date(Some(a.closed_time))),
        r("Feedback", Val::Null),
        r("LastEventDateTime", Val::Null),
        r("SourceURL", Val::Str(String::new())),
        r("CloudAppStates", Val::Str(String::new())),
        r("Comments", Val::Str(String::new())),
        r("Tags", Val::Str(String::new())),
        r("Vendor", Val::Str(a.vendor.clone())),
        r("Provider", Val::Str(a.provider.clone())),
        r("SubProvider", Val::Str(a.sub_provider.clone())),
        r("ProviderVersion", Val::Null),
        r("IncidentIds", Val::Str(String::new())),
    ]
}

/// The collector's Status test (Get-SecureScore.ps1:164-179); the world always has a score and
/// a `Default` state, so only the score branches apply.
fn secure_score_status(s: &SecureScoreControl) -> String {
    if matches!(s.state.as_str(), "Ignored" | "ThirdParty" | "Reviewed") {
        format!("Not applicable (overridden: {})", s.state)
    } else if s.current == s.max {
        "Meets standard".into()
    } else if s.current > 0.0 {
        "Partial".into()
    } else {
        "At risk".into()
    }
}

/// One SecureScore.csv row (19 columns, research §11): the doubles render in the host culture.
fn secure_score_row(s: &SecureScoreControl) -> Row {
    vec![
        r("Category", Val::Str(s.category.clone())),
        r("Title", Val::Str(s.title.clone())),
        r("Service", Val::Str(s.service.clone())),
        r("Status", Val::Str(secure_score_status(s))),
        r("CurrentScore", Val::Float(s.current)),
        r("MaxScore", Val::Float(s.max)),
        r("ScoreGap", Val::Float(s.max - s.current)),
        r("State", Val::Str(s.state.clone())),
        r("ActionType", Val::Str(s.action_type.clone())),
        r("ActionUrl", Val::Null),
        r("ImplementationCost", Val::Null),
        r("UserImpact", Val::Null),
        r("Tier", Val::Str(s.tier.clone())),
        r("Rank", Val::Int(s.rank.into())),
        r("Deprecated", Val::Bool(false)),
        r("Threats", Val::Str(s.threats.join("; "))),
        r("Remediation", Val::Null),
        r("RemediationImpact", Val::Null),
        r("LastModifiedDateTime", Val::Null),
    ]
}

/// Get-RiskyUsers: count-guarded, only with Entra ID P2 (without it the Graph call throws and
/// the run folder stays empty).
fn write_risky_users(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("RiskyEvents", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting Risky Users Collection ===");
    if !c.world.licence.p2() {
        return Ok(());
    }
    let users: Vec<RiskyUser> = c.world.risky_users().into_values().collect();
    if users.is_empty() {
        return Ok(());
    }
    let rows: Vec<Row> = users.iter().map(risky_user_row).collect();
    let row_keys: Vec<String> = users.iter().map(|u| keys::risky_user(u.user_id)).collect();
    let rel = format!("{dir}/{}-RiskyUsers.csv", run.stamp);
    let rendered = write_csv(
        c,
        tree,
        &rel,
        "inv.risky_users",
        "risky_users",
        &rows,
        &row_keys,
    )?;
    for (u, span) in users.iter().zip(&rendered.spans) {
        tree.deliver(
            &Evidence::RiskyUser(u.upn.clone()),
            "risky_users",
            &rel,
            *span,
        );
    }
    Ok(())
}

/// Get-RiskyDetections: count-guarded, only with Entra ID P2.
fn write_risk_detections(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("RiskyEvents", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting Risk Detections Collection ===");
    if !c.world.licence.p2() {
        return Ok(());
    }
    let dets: Vec<RiskDetection> = c.world.risk_detections();
    if dets.is_empty() {
        return Ok(());
    }
    let rows: Vec<Row> = dets.iter().map(risk_detection_row).collect();
    let row_keys: Vec<String> = dets.iter().map(|d| keys::risk(&d.id)).collect();
    let rel = format!("{dir}/{}-RiskyEvents.csv", run.stamp);
    let rendered = write_csv(
        c,
        tree,
        &rel,
        "inv.risk_detections",
        "risk_detections",
        &rows,
        &row_keys,
    )?;
    for (d, span) in dets.iter().zip(&rendered.spans) {
        tree.deliver(
            &Evidence::Risk(d.id.clone()),
            "risk_detections",
            &rel,
            *span,
        );
    }
    Ok(())
}

/// Get-SecurityAlerts: written unconditionally (0 bytes with no alerts).
fn write_security_alerts(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("SecurityAlerts", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting Security Alerts Collection ===");
    let rows: Vec<Row> = c.world.alerts.iter().map(alert_row).collect();
    let row_keys: Vec<String> = c
        .world
        .alerts
        .iter()
        .map(|a| keys::security_alert(&a.id))
        .collect();
    let rel = format!("{dir}/{}-SecurityAlerts.csv", run.stamp);
    write_csv(
        c,
        tree,
        &rel,
        "inv.security_alerts",
        "security_alerts",
        &rows,
        &row_keys,
    )?;
    Ok(())
}

/// Get-SecureScore: count-guarded.
fn write_secure_score(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("SecureScore", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting Secure Score Collection ===");
    if c.world.secure_score.is_empty() {
        return Ok(());
    }
    let rows: Vec<Row> = c.world.secure_score.iter().map(secure_score_row).collect();
    let row_keys: Vec<String> = c
        .world
        .secure_score
        .iter()
        .map(|s| keys::secure_score(&s.title))
        .collect();
    let rel = format!("{dir}/{}-SecureScore.csv", run.stamp);
    write_csv(
        c,
        tree,
        &rel,
        "inv.secure_score",
        "secure_score",
        &rows,
        &row_keys,
    )?;
    Ok(())
}

pub(super) fn write(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    write_risky_users(c, tree)?;
    write_risk_detections(c, tree)?;
    write_security_alerts(c, tree)?;
    write_secure_score(c, tree)
}
