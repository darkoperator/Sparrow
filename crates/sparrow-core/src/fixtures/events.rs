//! Synthetic Hawk captures holding the Phase 2c event artifacts: Entra sign-ins (Graph JSON,
//! its CSV twin, a flagged copy, a portal export), directory audits, message trace, legacy
//! mailbox audit, Hawk 3 admin audit files with their summaries and `_Investigate_` copies, and
//! the Hawk 3 and PSFramework logs. Invented tenant, users, ids and addresses only.

use crate::fixtures::hawk4::MTSUMMARY_TEXT;
use crate::fixtures::{
    HAWK_LOG, csv_line, ps_json, ps51_dates, utf8_bom, utf16le_bom, utf16le_no_bom, write,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub const ALICE: &str = "alice@contoso.example";
pub const BOB: &str = "bob@contoso.example";
pub const SIGNIN_1: &str = "a1a1a1a1-1111-4111-8111-111111111111";
pub const SIGNIN_2: &str = "a2a2a2a2-2222-4222-8222-222222222222";
pub const SIGNIN_3: &str = "a3a3a3a3-3333-4333-8333-333333333333";
pub const AUDIT_1: &str = "Directory_0E0E0E0E-0000-4000-8000-000000000001_ABCDE_1";
pub const AUDIT_2: &str = "Directory_0E0E0E0E-0000-4000-8000-000000000002_ABCDE_2";
pub const TRACE_1: &str = "0e0e0e0e-0000-4000-8000-000000000011";
pub const TRACE_2: &str = "0e0e0e0e-0000-4000-8000-000000000012";
pub const HAWK4_EVENTS_ROOT: &str = "capture-hawk4-events";
pub const HAWK3_EVENTS_ROOT: &str = "capture-hawk3-events";
pub const PORTAL_SIGNINS_CSV: &str = "Tenant/InteractiveSignIns_2026-09-01_2026-09-10.csv";
pub const MTSUMMARY_NAME: &str = "MTSummary_Message trace report - _2026-09-10T141500.000Z__7c9e6679-7425-40de-944b-e07fc1f90ae7.csv";

/// Entra admin center interactive sign-in export header, with its quirks: a repeated
/// `Incoming token type`, trailing spaces and a double space.
pub const PORTAL_SIGNIN_HEADER: &[&str] = &[
    "Date (UTC)",
    "Request ID",
    "User agent",
    "Correlation ID",
    "User ID",
    "User",
    "Username",
    "Application",
    "Application ID ",
    "Resource",
    "Resource ID ",
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
    "Session ID",
    "Autonomous system  number",
    "Incoming token type",
    "Token issuer type",
    "Incoming token type",
    "Conditional Access",
    "Unique token identifier",
];

/// A Get-MgAuditLogSignIn object as ConvertTo-Json writes it.
pub fn graph_signin(id: &str, created: &str, error: i64, risk: &str) -> Value {
    json!({
        "AppDisplayName": "Office 365 Exchange Online",
        "AppId": "00000002-0000-0FF1-CE00-000000000000",
        "AppliedConditionalAccessPolicies": [],
        "ClientAppUsed": "Browser",
        "ConditionalAccessStatus": "notApplied",
        "CorrelationId": "C0C0C0C0-0000-4000-8000-000000000001",
        "CreatedDateTime": created,
        "DeviceDetail": {"Browser": "Chrome 128.0.0", "DeviceId": "", "DisplayName": "",
                         "IsCompliant": false, "IsManaged": false, "OperatingSystem": "Windows10",
                         "TrustType": ""},
        "IPAddress": "203.0.113.10",
        "Id": id,
        "IsInteractive": true,
        "Location": {"City": "Lagos", "CountryOrRegion": "NG",
                     "GeoCoordinates": {"Latitude": 6.45, "Longitude": 3.39}, "State": "Lagos"},
        "ResourceDisplayName": "Office 365 Exchange Online",
        "ResourceId": "00000002-0000-0ff1-ce00-000000000000",
        "RiskDetail": "none",
        "RiskEventTypes": [],
        "RiskEventTypesV2": if risk == "none" { json!([]) } else { json!(["unfamiliarFeatures"]) },
        "RiskLevelAggregated": risk,
        "RiskLevelDuringSignIn": risk,
        "RiskState": if risk == "none" { "none" } else { "atRisk" },
        "Status": {"AdditionalDetails": null, "ErrorCode": error,
                   "FailureReason": if error == 0 { "Other." } else { "Invalid username or password." }},
        "UserDisplayName": "Alice",
        "UserId": "11111111-1111-4111-8111-111111111111",
        "UserPrincipalName": "Alice@Contoso.example",
        "AdditionalProperties": {}
    })
}

/// One portal sign-in export row aligned with `PORTAL_SIGNIN_HEADER`.
pub fn portal_signin_row(
    id: &str,
    when: &str,
    location: &str,
    compliant: &str,
    session: &str,
) -> Vec<String> {
    [
        when,
        id,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "c0c0c0c0-0000-4000-8000-000000000001",
        "11111111-1111-4111-8111-111111111111",
        "Alice",
        ALICE,
        "Office 365 Exchange Online",
        "00000002-0000-0ff1-ce00-000000000000",
        "Office 365 Exchange Online",
        "00000002-0000-0ff1-ce00-000000000000",
        "203.0.113.10",
        location,
        "Success",
        "0",
        "",
        "Browser",
        "",
        "Chrome 128.0.0",
        "Windows10",
        compliant,
        "No",
        "",
        "MFA successfully completed",
        "Microsoft Authenticator App",
        "",
        "multiFactorAuthentication",
        session,
        "64500",
        "none",
        "AzureAD",
        "primaryRefreshToken",
        "success",
        "tok-1",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Portal sign-in CSV as the Entra admin center writes it: UTF-8 with BOM, LF line ends.
pub fn portal_signins_csv(rows: &[Vec<String>]) -> Vec<u8> {
    let mut s = csv_line(PORTAL_SIGNIN_HEADER).replace("\r\n", "\n");
    for r in rows {
        let cells: Vec<&str> = r.iter().map(String::as_str).collect();
        s.push_str(&csv_line(&cells).replace("\r\n", "\n"));
    }
    utf8_bom(&s)
}

/// A Get-MgAuditLogDirectoryAudit object, initiated by a user or an app.
pub fn directory_audit(id: &str, when: &str, by_user: bool) -> Value {
    let initiated = if by_user {
        json!({"App": null, "User": {"DisplayName": null, "Id": "11111111-1111-4111-8111-111111111111",
               "IPAddress": "203.0.113.10", "UserPrincipalName": "Alice@Contoso.example",
               "AdditionalProperties": {}}, "AdditionalProperties": {}})
    } else {
        json!({"App": {"AppId": "33333333-3333-4333-8333-333333333333", "DisplayName": "Invoice Viewer",
               "ServicePrincipalId": "44444444-4444-4444-8444-444444444444", "ServicePrincipalName": null},
               "User": null, "AdditionalProperties": {}})
    };
    json!({
        "ActivityDateTime": when, "ActivityDisplayName": "Consent to application",
        "AdditionalDetails": [{"Key": "User-Agent", "Value": "Mozilla/5.0"}],
        "Category": "ApplicationManagement", "CorrelationId": "D0D0D0D0-0000-4000-8000-000000000001",
        "Id": id, "InitiatedBy": initiated, "LoggedByService": "Core Directory",
        "OperationType": "Assign", "Result": "success", "ResultReason": "",
        "TargetResources": [{
            "DisplayName": "Invoice Viewer", "Id": "33333333-3333-4333-8333-333333333333",
            "ModifiedProperties": [{"DisplayName": "ConsentAction.Permissions",
                                    "NewValue": "\"[Mail.Read]\"", "OldValue": null}],
            "Type": "ServicePrincipal", "UserPrincipalName": null
        }],
        "AdditionalProperties": {}
    })
}

/// A Search-AdminAuditLog record (Windows PowerShell 5.1 date form after `ps51_dates`).
pub fn admin_audit(object: &str, cmdlet: &str, run_ms: u64, forward: &str) -> Value {
    json!({
        "ObjectModified": object, "CmdletName": cmdlet,
        "CmdletParameters": [{"Name": "Identity", "Value": object}, {"Name": "ForwardTo", "Value": forward}],
        "ModifiedProperties": [], "Caller": "admin@contoso.example", "ExternalAccess": false,
        "Succeeded": true, "Error": "", "RunDate": format!("/Date({run_ms})/"),
        "OriginatingServer": "SRV01", "ClientIP": "198.51.100.7", "SessionId": "s-3",
        "AppId": null, "ClientAppId": null, "Identity": {"ObjectId": "x"}, "IsValid": true,
        "ObjectState": "Unchanged"
    })
}

fn message_trace(id: &str, recipient: &str) -> Value {
    json!({
        "Organization": "contoso.onmicrosoft.com", "MessageId": format!("<{id}@contoso.example>"),
        "Received": "2026-09-14T10:20:00.1234567", "SenderAddress": "Bob@contoso.example",
        "RecipientAddress": recipient, "Subject": "Updated bank details", "Status": "Delivered",
        "ToIP": null, "FromIP": "198.51.100.7", "Size": 2048, "MessageTraceId": id,
        "StartDate": "2026-08-01T00:00:00.0000000Z", "EndDate": "2026-09-15T00:00:00.0000000Z",
        "Index": 0
    })
}

/// The Hawk 4 user-investigation step that wrote alice's `Entra_Sign_In_Log_*` files, appended
/// to [`HAWK_LOG`] in the events tree's Hawk.log (evidence availability reads it).
pub const HAWK4_EVENTS_SIGNIN_LOG_LINE: &str = "[2026-09-10 14:31:00Z] - [INFO]   - Initiating collection of sign-in logs for alice@contoso.example from Entra ID\r\n";

/// Hawk 4.x capture: Tenant/ written by PowerShell 7 (UTF-8, ISO dates), the user folder by
/// Windows PowerShell 5.1 (UTF-8 BOM, `\/Date(ms)\/`), plus analyst portal exports.
pub fn hawk4_events_tree(base: &Path) -> PathBuf {
    let root = base.join(HAWK4_EVENTS_ROOT);
    write(
        &root,
        "Hawk.log",
        format!("{HAWK_LOG}{HAWK4_EVENTS_SIGNIN_LOG_LINE}").as_bytes(),
    );
    write(
        &root,
        "Tenant/EntraIDAuditLogs.json",
        ps_json(&json!([
            directory_audit(AUDIT_1, "2026-09-01T10:05:00.1234567Z", true),
            directory_audit(AUDIT_2, "2026-09-01T10:06:00Z", false)
        ]))
        .as_bytes(),
    );
    let audit_csv = csv_line(&[
        "ActivityDateTime",
        "ActivityDisplayName",
        "Id",
        "InitiatedBy",
    ]) + &csv_line(&[
        "9/1/2026 10:05:00 AM",
        "Consent to application",
        AUDIT_1,
        "Microsoft.Graph.PowerShell.Models.MicrosoftGraphAuditActivityInitiator",
    ]);
    write(&root, "Tenant/EntraIDAuditLogs.csv", audit_csv.as_bytes());
    write(
        &root,
        PORTAL_SIGNINS_CSV,
        &portal_signins_csv(&[
            portal_signin_row(
                &SIGNIN_1.to_uppercase(),
                "2026-09-01T09:30:00Z",
                "Lagos, Lagos, NG",
                "No",
                "sess-1",
            ),
            portal_signin_row(
                SIGNIN_3,
                "2026-09-01T11:00:00Z",
                "Seattle, Washington, US",
                "Yes",
                "sess-3",
            ),
        ]),
    );

    let u = |f: &str| format!("{ALICE}/{f}");
    let signins = json!([
        graph_signin(SIGNIN_1, "/Date(1788255000000)/", 0, "none"),
        graph_signin(SIGNIN_2, "/Date(1788256800000)/", 50126, "medium")
    ]);
    write(
        &root,
        &u(&format!("Entra_Sign_In_Log_{ALICE}_{ALICE}.json")),
        &utf8_bom(&ps51_dates(&ps_json(&signins))),
    );
    let signin_csv = csv_line(&["CreatedDateTime", "Id", "DeviceDetail", "UserPrincipalName"])
        + &csv_line(&[
            "9/1/2026 9:30:00 AM",
            SIGNIN_1,
            "Microsoft.Graph.PowerShell.Models.MicrosoftGraphDeviceDetail",
            ALICE,
        ]);
    write(
        &root,
        &u(&format!("Entra_Sign_In_Log_{ALICE}_{ALICE}.csv")),
        &utf8_bom(&signin_csv),
    );
    write(
        &root,
        &u(&format!(
            "_Investigate_Entra_Sign_In_Log_{ALICE}_{ALICE}.json"
        )),
        &utf8_bom(&ps51_dates(&ps_json(&graph_signin(
            SIGNIN_2,
            "/Date(1788256800000)/",
            50126,
            "medium",
        )))),
    );
    write(&root, &u(MTSUMMARY_NAME), &utf16le_no_bom(MTSUMMARY_TEXT));
    root
}

/// Format-List of one Search-AdminAuditLog record as Out-File writes it (local RunDate).
fn format_list_admin(object: &str, run_local: &str) -> String {
    format!(
        concat!(
            "\r\n\r\n",
            "ObjectModified   : {object}\r\n",
            "CmdletName       : New-InboxRule\r\n",
            "CmdletParameters : {{Identity, ForwardTo}}\r\n",
            "Caller           : admin@contoso.example\r\n",
            "RunDate          : {run}\r\n",
            "\r\n\r\n",
        ),
        object = object,
        run = run_local
    )
}

/// Hawk 3.1.0 capture from Windows PowerShell 5.1 (JSON/TXT/log UTF-16LE BOM, CSV UTF-8 BOM,
/// `\/Date(ms)\/`). The collecting machine runs in UTC, so local times equal UTC.
pub fn hawk3_events_tree(base: &Path) -> PathBuf {
    let root = base.join(HAWK3_EVENTS_ROOT);
    write(
        &root,
        "Hawk.log",
        &utf16le_bom(concat!(
            "[9/14/2026 2:15:00 PM] - *** Version 3.1.0 ***\r\n",
            "[9/14/2026 2:15:01 PM] - ## Tenant ## - Starting tenant investigation\r\n",
        )),
    );
    let psf = csv_line(&[
        "ComputerName",
        "FunctionName",
        "Level",
        "Message",
        "Timestamp",
    ]) + &csv_line(&[
        "WS01",
        "Out-LogFile",
        "Host",
        "Starting",
        "2026-09-14 14:15:00.123",
    ]);
    write(&root, "2026-09-14_logs.csv", &utf8_bom(&psf));

    let r1 = "contoso.example/Users/alice\\Rule1";
    let r2 = "contoso.example/Users/bob\\Rule2";
    let full = json!([
        admin_audit(r1, "New-InboxRule", 1789372800000, "x@fabrikam.example"),
        admin_audit(r2, "New-InboxRule", 1789373100000, "y@fabrikam.example")
    ]);
    write(
        &root,
        "Tenant/New_InboxRules.json",
        &utf16le_bom(&ps51_dates(&ps_json(&full))),
    );
    let full_csv = csv_line(&[
        "ObjectModified",
        "CmdletName",
        "CmdletParameters",
        "Caller",
        "RunDate",
    ]) + &csv_line(&[
        r1,
        "New-InboxRule",
        "System.Collections.ArrayList",
        "admin@contoso.example",
        "9/14/2026 8:00:00 AM",
    ]) + &csv_line(&[
        r2,
        "New-InboxRule",
        "System.Collections.ArrayList",
        "admin@contoso.example",
        "9/14/2026 8:05:00 AM",
    ]);
    write(&root, "Tenant/New_InboxRules.csv", &utf8_bom(&full_csv));
    let header = csv_line(&[
        "Caller",
        "Cmdlet",
        "FullCommand",
        "RunDate(UTC)",
        "ObjectModified",
    ]);
    let simple = |run: &str, object: &str| {
        csv_line(&[
            "admin@contoso.example",
            "New-InboxRule",
            &format!("New-InboxRule -Identity {object} -ForwardTo x@fabrikam.example"),
            run,
            object,
        ])
    };
    write(
        &root,
        "Tenant/Simple_New_InboxRule.csv",
        &utf8_bom(
            &(header.clone()
                + &simple("9/14/2026 8:00:00 AM", "Rule1")
                + &simple("9/14/2026 8:05:00 AM", "Rule2")),
        ),
    );
    write(
        &root,
        "Tenant/_Investigate_Simple_New_InboxRule.csv",
        &utf8_bom(&(header + &simple("9/14/2026 8:00:00 AM", "Rule1"))),
    );
    write(
        &root,
        "Tenant/_Investigate_New_InboxRules.txt",
        &utf16le_bom(&format_list_admin(r2, "9/14/2026 8:05:00 AM")),
    );

    let b = |f: &str| format!("{BOB}/{f}");
    write(
        &root,
        &b(&format!("User_Changes_{BOB}.json")),
        &utf16le_bom(&ps51_dates(&ps_json(&json!([admin_audit(
            "contoso.example/Users/bob",
            "Set-Mailbox",
            1789376400000,
            "z@fabrikam.example"
        )])))),
    );
    write(
        &root,
        &b(&format!("Message_Trace_{BOB}.json")),
        &utf16le_bom(&ps_json(&json!([
            message_trace(TRACE_1, "x@fabrikam.example"),
            message_trace(TRACE_2, "y@fabrikam.example")
        ]))),
    );
    let trace_csv = csv_line(&[
        "Received",
        "SenderAddress",
        "RecipientAddress",
        "MessageTraceId",
    ]) + &csv_line(&["9/14/2026 10:20:00 AM", BOB, "x@fabrikam.example", TRACE_1]);
    write(
        &root,
        &b(&format!("Message_Trace_{BOB}.csv")),
        &utf8_bom(&trace_csv),
    );
    write(
        &root,
        &b(&format!("Exchange_Mailbox_Audit_{BOB}.json")),
        &utf16le_bom(&ps51_dates(&ps_json(&json!([{
            "Operation": "HardDelete", "OperationResult": "Succeeded", "LogonType": "Owner",
            "ClientIPAddress": "198.51.100.7", "MailboxOwnerUPN": BOB,
            "SourceItems": [{"Id": "RgAAAA1", "Subject": "Invoice 42"}],
            "LastAccessed": "/Date(1789380000000)/"
        }])))),
    );
    root
}
