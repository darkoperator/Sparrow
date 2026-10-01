//! Analyst portal exports in a standalone folder (spec A.1; research: hawk capture survey §3):
//! the Purview audit log search export (`<guid>.csv`), the Entra interactive sign-in export
//! (CSV, or the same table saved as XLSX) and the Exchange admin center message trace summary
//! report (`MTSummary_*`). Sparrow recognizes all three by their header, so the file names
//! only follow the portals' own.

use crate::events::{SignIn, SignInType, TraceMsg, Ual};
use crate::keys;
use crate::options::{GenerateOptions, SigninExport};
use crate::ps::{DtKind, Encoding, Host};
use crate::reserved::WELL_KNOWN_GUIDS;
use crate::rng::stream;
use crate::story::Evidence;
use crate::tree::{FileSpec, Tree};
use crate::world::World;
use crate::writers::window_days;
use crate::{Error, Result};
use chrono::{DateTime, Duration, Utc};
use rust_xlsxwriter::{DocProperties, ExcelDateTime, Workbook};
use std::borrow::Cow;
use std::cmp::Reverse;
use uuid::Uuid;

/// Rows per Purview audit search export file: the portal's export cap (Sparrow warns that a
/// file of exactly this many rows is likely truncated).
pub const PURVIEW_EXPORT_CAP: usize = 50_000;

/// The Microsoft Services tenant, owner of first-party applications.
const MICROSOFT_SERVICES_TENANT: &str = "f8cdef31-a31e-4b4a-93e4-5f571e91255a";

const PURVIEW_HEADER: &[&str] = &[
    "RecordId",
    "CreationDate",
    "RecordType",
    "Operation",
    "UserId",
    "AuditData",
    "AssociatedAdminUnits",
    "AssociatedAdminUnitsNames",
];

/// The Entra sign-in export's 57 columns in order (survey §3, capture D), with the portal's
/// quirks: `Incoming token type` twice, trailing spaces in `Application ID ` and `Resource ID `,
/// and two spaces in `Autonomous system  number`.
pub const SIGNIN_HEADERS: &[&str] = &[
    "Date (UTC)",
    "Request ID",
    "User agent",
    "Correlation ID",
    "User ID",
    "User",
    "Username",
    "User type",
    "Cross tenant access type",
    "Incoming token type",
    "Authentication Protocol",
    "Unique token identifier",
    "Original transfer method",
    "Client credential type",
    "Token Protection - Sign In Session",
    "Token Protection - Sign In Session StatusCode",
    "Application",
    "Application ID ",
    "App owner tenant ID",
    "Resource",
    "Resource ID ",
    "Resource tenant ID",
    "Resource owner tenant ID",
    "Home tenant ID",
    "Home tenant name",
    "IP address",
    "Location",
    "Status",
    "Sign-in error code",
    "Failure reason",
    "Client app",
    "Device ID",
    "Browser",
    "Operating System",
    "Compliant",
    "Managed",
    "Join Type",
    "Multifactor authentication result",
    "Multifactor authentication auth method",
    "Multifactor authentication auth detail",
    "Authentication requirement",
    "Sign-in identifier",
    "Session ID",
    "IP address (seen by resource)",
    "Through Global Secure Access",
    "Global Secure Access IP address",
    "Autonomous system  number",
    "Flagged for review",
    "Token issuer type",
    "Incoming token type",
    "Token issuer name",
    "Latency",
    "Conditional Access",
    "Managed Identity type",
    "Associated Resource Id",
    "Federated Token Id",
    "Federated Token Issuer",
];

const MT_HEADER: &[&str] = &[
    "origin_timestamp_utc",
    "sender_address",
    "recipient_status",
    "message_subject",
    "total_bytes",
    "message_id",
    "network_message_id",
    "original_client_ip",
    "directionality",
    "connector_id",
    "delivery_priority",
];

/// Writes the portal exports of the collection window into `tree`.
pub fn write(world: &World, opts: &GenerateOptions, tree: &mut Tree<'_>) -> Result<()> {
    let host = Host::new(
        opts.ps,
        opts.culture,
        world.scenario.tenant.host_utc_offset_minutes,
    );
    let days = window_days(world);
    let mut ual: Vec<&Ual> = days.iter().flat_map(|d| &d.ual).collect();
    let mut signins: Vec<&SignIn> = days
        .iter()
        .flat_map(|d| &d.signins)
        .filter(|s| s.event_type == SignInType::Interactive)
        .collect();
    let mut trace: Vec<&TraceMsg> = days.iter().flat_map(|d| &d.trace).collect();
    // The portals list newest first.
    ual.sort_by_key(|u| Reverse((u.time, u.id)));
    signins.sort_by_key(|s| Reverse((s.time, s.id)));
    trace.sort_by_key(|t| Reverse((t.received, t.trace_id)));

    write_purview(world, &host, &ual, tree)?;
    match opts.signin_export {
        SigninExport::Csv => write_signins_csv(world, &signins, tree)?,
        SigninExport::Xlsx => write_signins_xlsx(world, &signins, tree)?,
    }
    write_message_trace(world, &trace, tree)
}

/// RFC 4180 quoting when the value needs it.
fn csv_field(s: &str) -> Cow<'_, str> {
    if s.contains([',', '"', '\r', '\n']) {
        Cow::Owned(quoted(s))
    } else {
        Cow::Borrowed(s)
    }
}

fn quoted(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn csv_line(fields: &[String], newline: &str) -> String {
    let mut line = fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",");
    line.push_str(newline);
    line
}

/// `yyyy-MM-ddTHH:mm:ss.fffffffZ`.
fn iso7(t: DateTime<Utc>) -> String {
    format!(
        "{}.{:07}Z",
        t.format("%Y-%m-%dT%H:%M:%S"),
        t.timestamp_subsec_nanos() / 100
    )
}

fn purview_row(u: &Ual, host: &Host, culture_dates: bool) -> Vec<String> {
    vec![
        u.id.to_string(),
        if culture_dates {
            host.culture_date(u.time, DtKind::Utc)
        } else {
            iso7(u.time)
        },
        u.record_type.number().to_string(),
        u.operation.clone(),
        u.user_id.clone(),
        u.audit_data_text(),
        String::new(),
        String::new(),
    ]
}

/// `<guid>.csv` files of at most `PURVIEW_EXPORT_CAP` rows: UTF-8 without BOM, CRLF. The
/// `CreationDate` form is the tree's export version's (`World::purview_culture_dates`), one form
/// for every row and every file of the tree.
fn write_purview(world: &World, host: &Host, ual: &[&Ual], tree: &mut Tree<'_>) -> Result<()> {
    let mut rng = stream(world.seed, "portal/purview");
    let header: Vec<String> = PURVIEW_HEADER.iter().map(|h| h.to_string()).collect();
    for chunk in ual.chunks(PURVIEW_EXPORT_CAP) {
        let rel = format!("{}.csv", rng.uuid());
        let spec = FileSpec::new(&rel, Some("portal.ual"), Encoding::Utf8);
        let mut text = csv_line(&header, "\r\n");
        for u in chunk {
            text.push_str(&csv_line(
                &purview_row(u, host, world.purview_culture_dates),
                "\r\n",
            ));
        }
        tree.write(&spec, &text)?;
        for (i, u) in chunk.iter().enumerate() {
            let line = i as u32 + 2;
            tree.row(&rel, "ual_events", keys::ual(u.id));
            tree.deliver(&Evidence::Ual(u.id), "ual_events", &rel, (line, line));
        }
    }
    Ok(())
}

/// The window's first and last dates, `yyyy-MM-dd`.
fn window_dates(world: &World) -> (String, String) {
    let last = world.window_end() - Duration::seconds(1);
    (
        world.window_start().format("%Y-%m-%d").to_string(),
        last.format("%Y-%m-%d").to_string(),
    )
}

/// The tenant that owns application `app`: a world application's owner tenant, Microsoft's
/// for first-party applications, else unknown.
fn owner_tenant(world: &World, app: Uuid) -> String {
    if let Some(a) = world.apps.iter().find(|a| a.app_id == app) {
        return a.owner_tenant.to_string();
    }
    let id = app.to_string();
    if WELL_KNOWN_GUIDS.iter().any(|(g, _)| *g == id) {
        MICROSOFT_SERVICES_TENANT.to_string()
    } else {
        String::new()
    }
}

/// The portal's `Status`: interrupted sign-ins (an MFA or device prompt) are neither success
/// nor failure.
fn signin_status(code: i64) -> &'static str {
    match code {
        0 => "Success",
        50055 | 50072 | 50074 | 50076 | 50079 | 50125 | 50140 | 50158 => "Interrupted",
        _ => "Failure",
    }
}

fn portal_ca_status(s: &str) -> String {
    match s {
        "success" => "Success".to_string(),
        "failure" => "Failure".to_string(),
        "notApplied" => "Not Applied".to_string(),
        other => other.to_string(),
    }
}

fn portal_auth_requirement(s: &str) -> String {
    match s {
        "singleFactorAuthentication" => "Single-factor authentication".to_string(),
        "multiFactorAuthentication" => "Multifactor authentication".to_string(),
        other => other.to_string(),
    }
}

fn yes_no(v: Option<bool>) -> String {
    if v == Some(true) { "Yes" } else { "No" }.to_string()
}

/// The 57 cells of one sign-in, in `SIGNIN_HEADERS` order.
fn signin_cells(world: &World, s: &SignIn) -> Vec<String> {
    let loc = &s.location;
    let location = [
        loc.city.as_str(),
        loc.state.as_str(),
        loc.country_iso.as_str(),
    ]
    .iter()
    .filter(|p| !p.is_empty())
    .copied()
    .collect::<Vec<_>>()
    .join(", ");
    let (mfa_result, mfa_method, mfa_detail) = match &s.mfa {
        Some((method, detail)) if s.error_code == 0 => (
            "MFA successfully completed".to_string(),
            method.clone(),
            detail.clone(),
        ),
        Some((method, detail)) => (String::new(), method.clone(), detail.clone()),
        None => (String::new(), String::new(), String::new()),
    };
    let failure = if s.error_code == 0 {
        String::new()
    } else {
        s.failure_reason.clone()
    };
    let device_id = if s.trust_type.is_some() {
        s.device.device_id.to_string()
    } else {
        String::new()
    };
    let ip = s.ip.to_string();
    let latency = (s.id.as_u128() % 900 + 40).to_string();
    let none = || "None".to_string();
    vec![
        s.time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        s.id.to_string(),
        s.user_agent.clone(),
        s.correlation_id.to_string(),
        s.user_id.map(|u| u.to_string()).unwrap_or_default(),
        s.user_display.clone(),
        s.user.clone(),
        "Member".to_string(),
        none(),
        s.incoming_token_type.clone(),
        none(),
        s.unique_token_id.clone(),
        none(),
        none(),
        "Unbound".to_string(),
        String::new(),
        s.app_name.clone(),
        s.app_id.to_string(),
        owner_tenant(world, s.app_id),
        s.resource_name.clone(),
        s.resource_id.to_string(),
        s.resource_tenant_id.to_string(),
        owner_tenant(world, s.resource_id),
        s.home_tenant_id.to_string(),
        String::new(),
        ip.clone(),
        location,
        signin_status(s.error_code).to_string(),
        // The portal leaves the code empty on Success; Failure and Interrupted carry it.
        if s.error_code == 0 {
            String::new()
        } else {
            s.error_code.to_string()
        },
        failure,
        s.client_app.clone(),
        device_id,
        s.device.browser.clone(),
        s.device.os.clone(),
        yes_no(s.device_compliant),
        yes_no(s.device_managed),
        s.trust_type.clone().unwrap_or_default(),
        mfa_result,
        mfa_method,
        mfa_detail,
        portal_auth_requirement(&s.auth_requirement),
        s.user.clone(),
        s.session_id.to_string(),
        ip,
        "No".to_string(),
        String::new(),
        s.asn.to_string(),
        "No".to_string(),
        s.token_issuer.clone(),
        s.incoming_token_type.clone(),
        String::new(),
        latency,
        portal_ca_status(&s.ca_status),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    ]
}

/// `InteractiveSignIns_<d1>_<d2>.csv`: UTF-8 with BOM, LF.
fn write_signins_csv(world: &World, signins: &[&SignIn], tree: &mut Tree<'_>) -> Result<()> {
    let (d1, d2) = window_dates(world);
    let rel = format!("InteractiveSignIns_{d1}_{d2}.csv");
    let spec = FileSpec::new(&rel, Some("portal.entra_signins"), Encoding::Utf8Bom);
    let header: Vec<String> = SIGNIN_HEADERS.iter().map(|h| h.to_string()).collect();
    let mut text = csv_line(&header, "\n");
    for s in signins {
        text.push_str(&csv_line(&signin_cells(world, s), "\n"));
    }
    tree.write(&spec, &text)?;
    deliver_signins(signins, &rel, tree);
    Ok(())
}

/// Data row `i` (0-based) sits on line / sheet row `i + 2`, below the header.
fn deliver_signins(signins: &[&SignIn], rel: &str, tree: &mut Tree<'_>) {
    for (i, s) in signins.iter().enumerate() {
        let line = i as u32 + 2;
        tree.row(rel, "signins", keys::signin(s.id));
        tree.deliver(&Evidence::SignIn(s.id), "signins", rel, (line, line));
    }
}

fn xlsx_err(e: rust_xlsxwriter::XlsxError) -> Error {
    Error::Invalid(format!("xlsx: {e}"))
}

/// `InteractiveSignins_<d1>_<d2>.xlsx`: one sheet, the CSV's headers and cell text (dates as
/// text), empty cells left blank. The workbook's creation time is the collection time, so the
/// bytes are deterministic.
fn write_signins_xlsx(world: &World, signins: &[&SignIn], tree: &mut Tree<'_>) -> Result<()> {
    let (d1, d2) = window_dates(world);
    let rel = format!("InteractiveSignins_{d1}_{d2}.xlsx");
    let created =
        ExcelDateTime::from_timestamp(world.collected_at().timestamp()).map_err(xlsx_err)?;
    let mut wb = Workbook::new();
    wb.set_properties(&DocProperties::new().set_creation_datetime(&created));
    let ws = wb.add_worksheet();
    for (c, h) in SIGNIN_HEADERS.iter().enumerate() {
        ws.write_string(0, c as u16, *h).map_err(xlsx_err)?;
    }
    for (i, s) in signins.iter().enumerate() {
        for (c, v) in signin_cells(world, s).iter().enumerate() {
            if !v.is_empty() {
                ws.write_string(i as u32 + 1, c as u16, v)
                    .map_err(xlsx_err)?;
            }
        }
    }
    let bytes = wb.save_to_buffer().map_err(xlsx_err)?;
    let spec = FileSpec::new(&rel, Some("portal.entra_signins"), Encoding::Utf8);
    tree.write_bytes(&spec, &bytes)?;
    deliver_signins(signins, &rel, tree);
    Ok(())
}

/// One summary-report row per message; `recipient_status` joins `<recipient>##<status>` entries
/// with `;`.
fn trace_row(t: &TraceMsg) -> Vec<String> {
    let recipients = t
        .recipients
        .iter()
        .map(|(r, s)| format!("{r}##{s}"))
        .collect::<Vec<_>>()
        .join(";");
    vec![
        iso7(t.received),
        t.sender.clone(),
        recipients,
        t.subject.clone(),
        t.size.to_string(),
        t.internet_message_id.clone(),
        t.trace_id.to_string(),
        t.from_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        t.direction.clone(),
        t.connector_id.clone().unwrap_or_default(),
        "Normal".to_string(),
    ]
}

/// `MTSummary_Message trace report - _<yyyy-MM-ddTHHmmss.fffZ>__<guid>.csv`: the Exchange admin
/// center's summary download, UTF-16LE without a byte-order mark, every field quoted, CRLF
/// (survey §3, captures A and B) -- unless the analyst re-saved it through Excel, which about
/// one tree in four is: a single-byte file with an unquoted header, which the reader decodes
/// with its Windows-1252 fallback (capture D, "not valid UTF-8, UTF-16 or cp1252 ... unquoted
/// header ... probably re-saved by Excel"). A subject with a non-ASCII character exercises the
/// single-byte path.
fn write_message_trace(world: &World, trace: &[&TraceMsg], tree: &mut Tree<'_>) -> Result<()> {
    let mut rng = stream(world.seed, "portal/message_trace");
    let ts = world.collected_at().format("%Y-%m-%dT%H%M%S%.3fZ");
    let rel = format!("MTSummary_Message trace report - _{ts}__{}.csv", rng.uuid());
    let resaved = world.message_trace_excel_resave;
    let spec = FileSpec::new(
        &rel,
        Some("portal.message_trace"),
        if resaved {
            Encoding::Cp1252
        } else {
            Encoding::Utf16LeNoBom
        },
    );
    // The download quotes every field; an Excel re-save writes the header bare and quotes a
    // data field only when it has to.
    let all_quoted = |fields: &[String]| {
        let mut line = fields
            .iter()
            .map(|f| quoted(f))
            .collect::<Vec<_>>()
            .join(",");
        line.push_str("\r\n");
        line
    };
    let header: Vec<String> = MT_HEADER.iter().map(|h| h.to_string()).collect();
    let mut text = if resaved {
        let mut line = header.join(",");
        line.push_str("\r\n");
        line
    } else {
        all_quoted(&header)
    };
    for t in trace {
        let row = trace_row(t);
        text.push_str(&if resaved {
            let mut line = row
                .iter()
                .map(|f| csv_field(f))
                .collect::<Vec<_>>()
                .join(",");
            line.push_str("\r\n");
            line
        } else {
            all_quoted(&row)
        });
    }
    tree.write(&spec, &text)?;
    for (i, t) in trace.iter().enumerate() {
        let line = i as u32 + 2;
        for (recipient, _) in &t.recipients {
            tree.row(&rel, "message_trace", keys::trace(t.trace_id, recipient));
            let e = Evidence::Trace {
                trace_id: t.trace_id,
                recipient: recipient.clone(),
            };
            tree.deliver(&e, "message_trace", &rel, (line, line));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signin_export_has_the_57_portal_columns() {
        assert_eq!(SIGNIN_HEADERS.len(), 57);
        let incoming = SIGNIN_HEADERS
            .iter()
            .filter(|h| **h == "Incoming token type")
            .count();
        assert_eq!(incoming, 2);
        assert!(SIGNIN_HEADERS.contains(&"Application ID "));
        assert!(SIGNIN_HEADERS.contains(&"Autonomous system  number"));
    }

    #[test]
    fn creation_dates_carry_seven_fraction_digits() {
        let t = DateTime::parse_from_rfc3339("2026-08-01T10:20:30.1234567Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(iso7(t), "2026-08-01T10:20:30.1234567Z");
    }
}
