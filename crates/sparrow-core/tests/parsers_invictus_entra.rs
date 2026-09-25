use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures::{self, ps_json};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::verify::verify_record;
use std::path::Path;

const ALICE: &str = "alice@contoso.example";
const S1: &str = "a1a1a1a1-1111-4111-8111-111111111111";
const S2: &str = "a2a2a2a2-2222-4222-8222-222222222222";
const S3: &str = "a3a3a3a3-3333-4333-8333-333333333333";
const AUDIT_1: &str = "Directory_0e0e0e0e-0000-4000-8000-000000000001_ABCDE_1";
const USERS_DIR: &str = "EntraID/20260910-100100-SignInLogs/interactiveUser & nonInteractiveUser";
const SP_DIR: &str = "EntraID/20260910-100100-SignInLogs/servicePrincipal";
const USERS_PAGE: &str = "EntraID/20260910-100100-SignInLogs/interactiveUser & nonInteractiveUser/20260910100105-interactiveUser-nonInteractiveUser-SignInLogs.json";
const SP_PAGE: &str = "EntraID/20260910-100100-SignInLogs/servicePrincipal/20260910100110-servicePrincipal-SignInLogs.json";
const AUDIT_PAGE: &str = "EntraID/20260910-100200-AuditLogs/20260910100205-AuditLogs.json";

/// A beta /auditLogs/signIns record as Microsoft-Extractor-Suite writes it (camelCase REST).
fn signin(id: &str, event_type: &str, interactive: bool) -> Value {
    let user = event_type != "servicePrincipal";
    json!({
        "id": id, "createdDateTime": "2026-09-01T10:20:00Z",
        "userDisplayName": if user { "Alice" } else { "" },
        "userPrincipalName": if user { ALICE } else { "" },
        "userId": if user { "0e0e0e0e-0000-4000-8000-0000000000a1" } else { "" },
        "appId": "0e0e0e0e-0000-4000-8000-0000000000b1", "appDisplayName": "Contoso App",
        "ipAddress": "203.0.113.10", "ipAddressFromResourceProvider": null,
        "clientAppUsed": if user { "Browser" } else { "" }, "userAgent": if user { "Mozilla/5.0" } else { "" },
        "correlationId": "0E0E0E0E-0000-4000-8000-0000000000C1", "conditionalAccessStatus": "notApplied",
        "isInteractive": interactive, "signInEventTypes": [event_type],
        "riskDetail": "hidden", "riskLevelAggregated": "hidden", "riskLevelDuringSignIn": "hidden",
        "riskState": "none", "riskEventTypes_v2": if interactive { json!(["unfamiliarFeatures"]) } else { json!([]) },
        "resourceDisplayName": "Microsoft Graph", "resourceId": "00000003-0000-0000-c000-000000000000",
        "status": {"errorCode": 0, "failureReason": "Other.", "additionalDetails": null},
        "deviceDetail": {"deviceId": "", "displayName": "", "operatingSystem": "Windows10",
                         "browser": "Edge 140.0.0", "isCompliant": false, "isManaged": false, "trustType": ""},
        "location": {"city": "Springfield", "state": "Ohio", "countryOrRegion": "US",
                     "geoCoordinates": {"altitude": null, "latitude": 39.9, "longitude": -82.9}},
        "mfaDetail": if interactive { json!({"authMethod": "Mobile app notification", "authDetail": null}) } else { Value::Null },
        "authenticationDetails": [{"authenticationStepDateTime": "2026-09-01T10:20:00Z",
            "authenticationMethod": "Password", "succeeded": true}],
        "autonomousSystemNumber": 64500, "sessionId": "0e0e0e0e-0000-4000-8000-0000000000d1",
        "uniqueTokenIdentifier": "tok1", "incomingTokenType": "none", "tokenIssuerType": "AzureAD",
        "crossTenantAccessType": "none", "homeTenantId": "0e0e0e0e-0000-4000-8000-00000000000a",
        "resourceTenantId": "0e0e0e0e-0000-4000-8000-00000000000a"
    })
}

fn audit_record() -> Value {
    json!({
        "id": AUDIT_1, "category": "UserManagement",
        "correlationId": "0e0e0e0e-0000-4000-8000-0000000000e1", "result": "success",
        "resultReason": "", "activityDisplayName": "Update user",
        "activityDateTime": "2026-09-01T10:25:00.123456Z", "loggedByService": "Core Directory",
        "operationType": "Update",
        "initiatedBy": {"app": null, "user": {"id": "0e0e0e0e-0000-4000-8000-0000000000a1",
            "displayName": "Alice", "userPrincipalName": ALICE, "ipAddress": "203.0.113.10",
            "userType": null, "agentType": "notAgentic", "homeTenantId": null, "homeTenantName": null}},
        "targetResources": [{"id": "0e0e0e0e-0000-4000-8000-0000000000a2", "displayName": "Bob",
            "type": "User", "userPrincipalName": "bob@contoso.example", "groupType": null,
            "modifiedProperties": [{"displayName": "StrongAuthenticationMethod",
                "oldValue": "[]", "newValue": "[{\"MethodType\":6}]"}]}],
        "additionalDetails": [{"key": "UserType", "value": "Member"}]
    })
}

fn ingest(base: &Path) -> (Case, IngestReport) {
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        base,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    (case, report)
}

fn row<'r>(report: &'r IngestReport, rel: &str) -> &'r FileReport {
    report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .find(|f| f.rel_path == rel)
        .unwrap_or_else(|| panic!("no report row for {rel}"))
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn text(case: &Case, sql: &str) -> String {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn graph_rest_sign_ins_keep_their_event_type() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    fixtures::write(
        &out,
        USERS_PAGE,
        ps_json(&json!([
            signin(S1, "interactiveUser", true),
            signin(S2, "nonInteractiveUser", false)
        ]))
        .as_bytes(),
    );
    fixtures::write(
        &out,
        SP_PAGE,
        ps_json(&json!([signin(S3, "servicePrincipal", false)])).as_bytes(),
    );
    std::fs::create_dir_all(out.join("EntraID/20260910-100100-SignInLogs/managedIdentity"))
        .unwrap();
    let (case, report) = ingest(dir.path());
    assert_eq!(
        row(&report, USERS_PAGE).artifact_id.as_deref(),
        Some("inv.signins")
    );
    assert_eq!(row(&report, USERS_PAGE).records_loaded, 2);
    let event_type = |id: &str| {
        text(
            &case,
            &format!("SELECT CAST(event_type AS VARCHAR) FROM signins WHERE record_key = '{id}'"),
        )
    };
    assert_eq!(event_type(S1), "interactive");
    assert_eq!(event_type(S2), "noninteractive");
    assert_eq!(event_type(S3), "service_principal");
    // Blank user fields of a service principal sign-in are NULL.
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM signins WHERE record_key = '{S3}' AND user_upn IS NULL AND user_agent IS NULL"
            )
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM signins WHERE record_key = '{S1}'
                   AND risk_event_types = ['unfamiliarFeatures']
                   AND list_contains(auth_methods, 'Mobile app notification')
                   AND list_contains(auth_methods, 'Password')
                   AND risk_level_during = 'hidden' AND location.country = 'US' AND asn = 64500
                   AND correlation_id = '0e0e0e0e-0000-4000-8000-0000000000c1'"
            )
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM signins WHERE record_key = '{S2}' AND risk_event_types IS NULL"
            )
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            &format!("SELECT epoch(event_time)::BIGINT FROM signins WHERE record_key = '{S1}'")
        ),
        1_788_258_000
    );
}

#[test]
fn concatenated_pages_load_with_their_own_lines() {
    let dir = tempfile::tempdir().unwrap();
    // Two pages written in the same second: Out-File -Append puts two arrays in one file.
    let body = format!(
        "{}\r\n{}\r\n",
        ps_json(&json!([signin(S1, "interactiveUser", true)])),
        ps_json(&json!([signin(S2, "nonInteractiveUser", false)]))
    );
    fixtures::write(&dir.path().join("OUT"), USERS_PAGE, body.as_bytes());
    let (case, report) = ingest(dir.path());
    let f = row(&report, USERS_PAGE);
    assert_eq!(
        (f.records_read, f.records_loaded, f.records_error),
        (2, 2, 0)
    );
    let line = |id: &str, col: &str| {
        count(
            &case,
            &format!(
                "SELECT {col} FROM record_sources WHERE table_name = 'signins' AND record_key = '{id}'"
            ),
        )
    };
    assert!(line(S2, "line_start") > line(S1, "line_end"));
    assert!(verify_record(&case, "signins", S2, None).unwrap().ok);
}

#[test]
fn merged_sign_ins_and_audits_are_superseded_by_their_pages() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    let page = ps_json(&json!([signin(S1, "interactiveUser", true)]));
    fixtures::write(&out, USERS_PAGE, page.as_bytes());
    let merged =
        format!("{USERS_DIR}/Merged/SignInLogs-interactiveUser-nonInteractiveUser-Combined.json");
    fixtures::write(&out, &merged, page.as_bytes());
    let audits = ps_json(&json!([audit_record()]));
    fixtures::write(&out, AUDIT_PAGE, audits.as_bytes());
    let audit_merged = "EntraID/20260910-100200-AuditLogs/Merged/AuditLogs-Combined.json";
    fixtures::write(&out, audit_merged, audits.as_bytes());
    let (case, report) = ingest(dir.path());
    assert_eq!(
        row(&report, &merged).artifact_id.as_deref(),
        Some("inv.signins.merged")
    );
    assert_eq!(row(&report, &merged).status, FileStatus::SkippedSuperseded);
    assert_eq!(
        row(&report, audit_merged).status,
        FileStatus::SkippedSuperseded
    );
    assert_eq!(count(&case, "SELECT count(*) FROM signins"), 1);
    assert_eq!(count(&case, "SELECT count(*) FROM directory_audits"), 1);
    let _ = SP_DIR;
}

#[test]
fn graph_rest_directory_audits_load() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::write(
        &dir.path().join("OUT"),
        AUDIT_PAGE,
        ps_json(&json!([audit_record()])).as_bytes(),
    );
    let (case, report) = ingest(dir.path());
    assert_eq!(
        row(&report, AUDIT_PAGE).artifact_id.as_deref(),
        Some("inv.entra_audit")
    );
    let key = AUDIT_1.to_lowercase();
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM directory_audits WHERE record_key = '{key}'
                   AND activity = 'Update user' AND category = 'UserManagement'
                   AND initiated_by_upn = '{ALICE}' AND initiated_by_ip = '203.0.113.10'
                   AND json_array_length(modified_properties) = 1
                   AND result_reason IS NULL"
            )
        ),
        1
    );
}

#[test]
fn graph_rest_mfa_detail_loads() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = signin(S1, "interactiveUser", true);
    s["mfaDetail"] =
        json!({"authMethod": "Mobile app notification", "authDetail": "Notification approved"});
    fixtures::write(
        &dir.path().join("OUT"),
        USERS_PAGE,
        ps_json(&json!([s])).as_bytes(),
    );
    let (case, _report) = ingest(dir.path());
    assert_eq!(
        text(
            &case,
            &format!("SELECT mfa_detail FROM signins WHERE record_key = '{S1}'")
        ),
        "Notification approved"
    );
}
