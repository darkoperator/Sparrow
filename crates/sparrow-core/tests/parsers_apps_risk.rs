use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use std::path::{Path, PathBuf};

fn capture(base: &Path) -> PathBuf {
    let root = base.join("cap");
    fixtures::write(&root, "Hawk.log", fixtures::HAWK_LOG.as_bytes());
    root
}

fn json_file(root: &Path, rel: &str, v: &Value) {
    fixtures::write(root, rel, fixtures::ps_json(v).as_bytes());
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

const APP: &str = "33333333-3333-4333-8333-333333333333";
const GRAPH: &str = "44444444-4444-4444-8444-444444444444";
const ALICE_ID: &str = "11111111-1111-4111-8111-111111111111";
const DETECTION: &str = "55555555-5555-4555-8555-555555555555";

fn grant(
    kind: &str,
    permission: &str,
    consent: Option<&str>,
    principal: Option<&str>,
    risk: &str,
) -> Value {
    json!({
        "PermissionType": kind, "ClientObjectId": APP, "ClientDisplayName": "Mail Helper",
        "ResourceObjectId": GRAPH, "ResourceDisplayName": "Microsoft Graph", "Permission": permission,
        "ConsentType": consent, "PrincipalObjectId": principal,
        "PrincipalDisplayName": principal.map(|_| "Alice"), "ConsentGrantRiskCategory": risk
    })
}

#[test]
fn consent_grants_load_with_hawk_risk_category() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    json_file(
        &root,
        "Tenant/Consent_Grants.json",
        &json!([
            grant(
                "Delegated",
                "Mail.Read",
                Some("Principal"),
                Some(ALICE_ID),
                "High Risk"
            ),
            grant(
                "Delegated",
                "offline_access",
                Some("Principal"),
                Some(ALICE_ID),
                ""
            ),
            grant(
                "Application",
                "Mail.ReadWrite",
                None,
                None,
                "Extremely Dangerous"
            )
        ]),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM oauth_grants"), 3);
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT CAST(permission_type AS VARCHAR) || '|' || risk_category FROM oauth_grants WHERE record_key = '{APP}|{GRAPH}|mail.read|{ALICE_ID}'"
            )
        ),
        "delegated|High Risk"
    );
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT CAST(permission_type AS VARCHAR) FROM oauth_grants WHERE record_key = '{APP}|{GRAPH}|mail.readwrite|'"
            )
        ),
        "application"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM oauth_grants WHERE permission = 'offline_access' AND risk_category IS NULL"
        ),
        1
    );
}

#[test]
fn csv_placeholders_become_null_and_warn() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let header = [
        "PermissionType",
        "ClientObjectId",
        "ClientDisplayName",
        "ResourceObjectId",
        "ResourceDisplayName",
        "Permission",
        "ConsentType",
        "PrincipalObjectId",
        "PrincipalDisplayName",
    ];
    let csv = fixtures::csv_line(&header)
        + &fixtures::csv_line(&[
            "Delegated",
            APP,
            "Mail Helper",
            GRAPH,
            "Microsoft Graph",
            "Mail.Read",
            "System.Object[]",
            ALICE_ID,
            "Alice",
        ])
        + &fixtures::csv_line(&[
            "Application",
            APP,
            "Mail Helper",
            GRAPH,
            "Microsoft Graph",
            "Mail.Send",
            "",
            "",
            "",
        ]);
    fixtures::write(
        &root,
        "Tenant/Consent_Grants.csv",
        &fixtures::utf8_bom(&csv),
    );
    let (case, report) = ingest(dir.path());
    let f = row(&report, "Tenant/Consent_Grants.csv");
    assert_eq!((f.status, f.records_loaded), (FileStatus::Parsed, 2));
    assert!(
        f.warnings.iter().any(|w| w.contains("placeholders")),
        "{:?}",
        f.warnings
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM oauth_grants WHERE permission = 'Mail.Read' AND consent_type IS NULL"
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM oauth_grants WHERE consent_type = 'System.Object[]'"
        ),
        0
    );
}

#[test]
fn app_credentials_owner_comes_from_the_file_and_concatenated_json_loads() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let secret = json!({"AppName": "Mail Helper", "AppObjectID": APP, "KeyID": "aaaaaaaa-0000-4000-8000-000000000001",
        "StartDate": "/Date(1788256800000)/", "EndDate": "/Date(1819792800000)/", "KeyType": null, "CredType": "PasswordSecret"});
    let cert = json!({"AppName": "Mail Helper", "AppObjectID": APP, "KeyID": "aaaaaaaa-0000-4000-8000-000000000002",
        "StartDate": "/Date(1788256800000)/", "EndDate": "/Date(1819792800000)/", "KeyType": "AsymmetricX509Cert", "CredType": "X509Certificate"});
    // Hawk 3 appends one ConvertTo-Json document per credential: concatenated objects, no array.
    let concatenated = format!(
        "{}\r\n{}\r\n",
        fixtures::ps_json(&secret),
        fixtures::ps_json(&cert)
    );
    fixtures::write(
        &root,
        "Tenant/ApplicationCertsAndSecrets.json",
        &fixtures::utf16le_bom(&fixtures::ps51_dates(&concatenated)),
    );
    json_file(
        &root,
        "Tenant/SPNCertsAndSecrets.json",
        &json!([{
            "AppName": "Contoso Sync", "AppObjectID": GRAPH, "KeyID": "bbbbbbbb-0000-4000-8000-000000000001",
            "StartDate": "2026-09-01T10:00:00Z", "EndDate": "2027-09-01T10:00:00Z", "KeyType": "AsymmetricX509Cert",
            "CredType": "X509Certificate"
        }]),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM app_credentials"), 3);
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT CAST(owner AS VARCHAR) || '|' || CAST(cred_type AS VARCHAR) FROM app_credentials WHERE record_key = '{APP}|aaaaaaaa-0000-4000-8000-000000000001'"
            )
        ),
        "application|password"
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT epoch(start_time)::BIGINT FROM app_credentials WHERE record_key = '{APP}|aaaaaaaa-0000-4000-8000-000000000002'"
            )
        ),
        1_788_256_800
    );
    assert_eq!(
        text(
            &case,
            "SELECT CAST(owner AS VARCHAR) FROM app_credentials WHERE app_name = 'Contoso Sync'"
        ),
        "service_principal"
    );
}

fn detection() -> Value {
    json!({
        "Activity": "signin", "ActivityDateTime": "2026-09-01T09:58:00Z",
        "AdditionalInfo": "[{\"Key\":\"userAgent\",\"Value\":\"python-requests/2.31\"}]",
        "CorrelationId": "c0000000-0000-4000-8000-00000000000c",
        "DetectedDateTime": "2026-09-01T10:00:00Z", "DetectionTimingType": "realtime",
        "Id": DETECTION, "IPAddress": "203.0.113.50", "LastUpdatedDateTime": "2026-09-01T10:05:00Z",
        "Location": {"City": "Lisbon", "CountryOrRegion": "PT", "State": "Lisboa",
                     "GeoCoordinates": {"Altitude": null, "Latitude": 38.7, "Longitude": -9.1}},
        "RequestId": "r0000000-0000-4000-8000-00000000000r", "RiskDetail": "none",
        "RiskEventType": "anonymizedIPAddress", "RiskLevel": "high", "RiskState": "atRisk",
        "Source": "IdentityProtection", "TokenIssuerType": "AzureAD",
        "UserDisplayName": "Alice", "UserId": ALICE_ID, "UserPrincipalName": "alice@contoso.example",
        "AdditionalProperties": {}
    })
}

fn flattened_detection_csv() -> String {
    let header = [
        "Activity",
        "ActivityDateTime",
        "CorrelationId",
        "DetectedDateTime",
        "DetectionTimingType",
        "Id",
        "IPAddress",
        "LastUpdatedDateTime",
        "Location",
        "RequestId",
        "RiskDetail",
        "RiskEventType",
        "RiskLevel",
        "RiskState",
        "Source",
        "TokenIssuerType",
        "UserDisplayName",
        "UserId",
        "UserPrincipalName",
        "AdditionalInfo_userAgent",
    ];
    fixtures::csv_line(&header)
        + &fixtures::csv_line(&[
            "signin",
            "9/21/2026 9:58:00 AM",
            "c0000000-0000-4000-8000-00000000000c",
            "9/21/2026 10:00:00 AM",
            "realtime",
            DETECTION,
            "203.0.113.50",
            "9/21/2026 10:05:00 AM",
            "Microsoft.Graph.PowerShell.Models.MicrosoftGraphSignInLocation",
            "r0000000-0000-4000-8000-00000000000r",
            "none",
            "anonymizedIPAddress",
            "high",
            "atRisk",
            "IdentityProtection",
            "AzureAD",
            "Alice",
            ALICE_ID,
            "alice@contoso.example",
            "python-requests/2.31",
        ])
}

#[test]
fn risky_users_and_detections_load_and_json_wins_over_the_flattened_csv() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    json_file(
        &root,
        "Tenant/RiskyUsers.json",
        &json!({
            "Id": ALICE_ID, "IsDeleted": false, "IsProcessing": false, "RiskDetail": "none",
            "RiskLastUpdatedDateTime": "2026-09-01T10:05:00Z", "RiskLevel": "high", "RiskState": "atRisk",
            "UserDisplayName": "Alice", "UserPrincipalName": "alice@contoso.example", "History": null,
            "AdditionalProperties": {}
        }),
    );
    json_file(&root, "Tenant/Risk_Detections.json", &detection());
    fixtures::write(
        &root,
        "Tenant/Risk_Detections.csv",
        flattened_detection_csv().as_bytes(),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        row(&report, "Tenant/Risk_Detections.csv").status,
        FileStatus::SkippedSuperseded
    );
    assert_eq!(
        text(
            &case,
            "SELECT risk_level || '|' || risk_state || '|' || upn FROM risky_users"
        ),
        "high|atRisk|alice@contoso.example"
    );
    assert_eq!(
        text(
            &case,
            "SELECT location.city || '|' || location.country || '|' || ip FROM risk_detections"
        ),
        "Lisbon|PT|203.0.113.50"
    );
    assert_eq!(
        text(
            &case,
            "SELECT additional_info->>'$[0].Value' FROM risk_detections"
        ),
        "python-requests/2.31"
    );
    assert_eq!(
        count(
            &case,
            "SELECT epoch(detected_time)::BIGINT FROM risk_detections"
        ),
        1_788_256_800
    );
}

#[test]
fn risk_detections_csv_fallback_collects_additional_info_columns() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        "Tenant/Risk_Detections.csv",
        flattened_detection_csv().as_bytes(),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        text(
            &case,
            "SELECT additional_info->>'$.userAgent' FROM risk_detections"
        ),
        "python-requests/2.31"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM risk_detections WHERE location IS NULL"
        ),
        1
    );
}
