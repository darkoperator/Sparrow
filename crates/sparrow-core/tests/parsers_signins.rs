use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::verify::verify_record;
use std::path::{Path, PathBuf};

const ALICE: &str = "alice@contoso.example";
const S1: &str = "a1a1a1a1-1111-4111-8111-111111111111";
const S2: &str = "a2a2a2a2-2222-4222-8222-222222222222";
const S3: &str = "a3a3a3a3-3333-4333-8333-333333333333";

fn capture(base: &Path) -> PathBuf {
    let root = base.join("cap");
    fixtures::write(&root, "Hawk.log", fixtures::HAWK_LOG.as_bytes());
    root
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

fn graph_signin(id: &str, when: &str, error: i64, risk: &str) -> Value {
    json!({
        "AppDisplayName": "Office 365 Exchange Online",
        "AppId": "00000002-0000-0FF1-CE00-000000000000",
        "AppliedConditionalAccessPolicies": [],
        "ClientAppUsed": "Browser",
        "ConditionalAccessStatus": "notApplied",
        "CorrelationId": "C0C0C0C0-0000-4000-8000-000000000001",
        "CreatedDateTime": when,
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

fn signin_json(root: &Path, records: &[Value]) -> String {
    let rel = format!("{ALICE}/Entra_Sign_In_Log_{ALICE}_{ALICE}.json");
    fixtures::write(root, &rel, fixtures::ps_json(&json!(records)).as_bytes());
    rel
}

const PORTAL_HEADER: &[&str] = &[
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

fn portal_row(id: &str, when: &str, location: &str, compliant: &str, session: &str) -> Vec<String> {
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

/// Portal CSV as the Entra admin center writes it: UTF-8 with BOM, LF line ends.
fn portal_csv(rows: &[Vec<String>]) -> Vec<u8> {
    let mut s = csv_line(PORTAL_HEADER).replace("\r\n", "\n");
    for r in rows {
        let cells: Vec<&str> = r.iter().map(String::as_str).collect();
        s.push_str(&csv_line(&cells).replace("\r\n", "\n"));
    }
    fixtures::utf8_bom(&s)
}

const PORTAL_CSV: &str = "Tenant/InteractiveSignIns_2026-09-01_2026-09-10.csv";

#[test]
fn graph_signins_load_with_nested_fields() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = signin_json(
        &root,
        &[
            graph_signin(S1, "2026-09-01T09:30:00Z", 0, "none"),
            graph_signin(S2, "2026-09-01T10:00:00.1234567Z", 50126, "medium"),
        ],
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(row(&report, &rel).records_loaded, 2);
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT user_upn || '|' || app_id || '|' || ip || '|' || status || '|' || error_code || '|' ||
                        device.os || '|' || device.is_compliant || '|' || location.city || '|' ||
                        location.latitude || '|' || event_type || '|' || correlation_id || '|' || time_tz_assumed
                 FROM signins WHERE record_key = '{S1}'"
            )
        ),
        "alice@contoso.example|00000002-0000-0ff1-ce00-000000000000|203.0.113.10|Success|0|Windows10|false|Lagos|6.45|interactive|c0c0c0c0-0000-4000-8000-000000000001|false"
    );
    assert_eq!(
        count(
            &case,
            &format!("SELECT epoch(event_time)::BIGINT FROM signins WHERE record_key = '{S1}'")
        ),
        1788255000
    );
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT status || '|' || error_code || '|' || failure_reason || '|' || risk_level_during || '|' ||
                        array_to_string(risk_event_types, ',')
                 FROM signins WHERE record_key = '{S2}'"
            )
        ),
        "Failure|50126|Invalid username or password.|medium|unfamiliarFeatures"
    );
}

#[test]
fn csv_twin_is_superseded_and_a_lone_csv_loads_what_it_can() {
    let header = [
        "AppDisplayName",
        "AppId",
        "ClientAppUsed",
        "CorrelationId",
        "CreatedDateTime",
        "DeviceDetail",
        "IPAddress",
        "Id",
        "IsInteractive",
        "Location",
        "Status",
        "UserPrincipalName",
    ];
    let csv = csv_line(&header)
        + &csv_line(&[
            "Office 365 Exchange Online",
            "00000002-0000-0ff1-ce00-000000000000",
            "Browser",
            "c0c0c0c0-0000-4000-8000-000000000001",
            "9/14/2026 9:30:00 AM",
            "Microsoft.Graph.PowerShell.Models.MicrosoftGraphDeviceDetail",
            "203.0.113.10",
            S1,
            "True",
            "Microsoft.Graph.PowerShell.Models.MicrosoftGraphSignInLocation",
            "Microsoft.Graph.PowerShell.Models.MicrosoftGraphSignInStatus",
            ALICE,
        ]);
    let csv_rel = format!("{ALICE}/Entra_Sign_In_Log_{ALICE}_{ALICE}.csv");

    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    signin_json(
        &root,
        &[graph_signin(S1, "2026-09-14T09:30:00Z", 0, "none")],
    );
    fixtures::write(&root, &csv_rel, &fixtures::utf8_bom(&csv));
    let (_case, report) = ingest(dir.path());
    assert_eq!(row(&report, &csv_rel).status, FileStatus::SkippedSuperseded);

    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, &csv_rel, &fixtures::utf8_bom(&csv));
    let (case, report) = ingest(dir.path());
    let f = row(&report, &csv_rel);
    assert_eq!(
        (f.status, f.records_loaded),
        (FileStatus::Parsed, 1),
        "{f:#?}"
    );
    assert!(
        f.warnings
            .iter()
            .any(|w| w.contains("PowerShell placeholders")),
        "{:?}",
        f.warnings
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM signins WHERE device IS NULL AND location IS NULL AND status IS NULL
               AND is_interactive AND time_tz_assumed AND epoch(event_time)::BIGINT = 1789378200"
        ),
        1
    );
}

#[test]
fn portal_row_fills_the_graph_row_and_adds_a_sighting() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let json_rel = signin_json(
        &root,
        &[graph_signin(S1, "2026-09-01T09:30:00Z", 0, "none")],
    );
    fixtures::write(
        &root,
        PORTAL_CSV,
        &portal_csv(&[
            portal_row(
                &S1.to_uppercase(),
                "2026-09-01T09:30:00Z",
                "Lagos, Lagos, NG",
                "No",
                "sess-1",
            ),
            portal_row(
                S3,
                "2026-09-01T11:00:00Z",
                "Seattle, Washington, US",
                "Yes",
                "sess-3",
            ),
        ]),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let portal = row(&report, PORTAL_CSV);
    assert_eq!(portal.artifact_id.as_deref(), Some("portal.entra_signins"));
    assert_eq!((portal.records_loaded, portal.records_duplicate), (2, 0));
    assert!(
        portal
            .warnings
            .iter()
            .any(|w| w.contains("filled values missing")),
        "{:?}",
        portal.warnings
    );
    assert_eq!(row(&report, &json_rel).records_loaded, 1);
    assert_eq!(count(&case, "SELECT count(*) FROM signins"), 2);
    // Graph values stay; the portal adds what Graph lacks.
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT risk_level_during || '|' || session_id || '|' || asn || '|' || mfa_result || '|' ||
                        array_to_string(auth_methods, ',') || '|' || auth_requirement || '|' ||
                        incoming_token_type || '|' || user_agent || '|' || location.latitude
                 FROM signins WHERE record_key = '{S1}'"
            )
        ),
        "none|sess-1|64500|MFA successfully completed|Microsoft Authenticator App|multiFactorAuthentication|none|Mozilla/5.0 (Windows NT 10.0; Win64; x64)|6.45"
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM record_sources WHERE table_name = 'signins' AND record_key = '{S1}'"
            )
        ),
        2
    );
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT location.city || '|' || location.state || '|' || location.country || '|' ||
                        device.is_compliant || '|' || device.is_managed || '|' || event_type || '|' || is_interactive
                 FROM signins WHERE record_key = '{S3}'"
            )
        ),
        "Seattle|Washington|US|true|false|interactive|true"
    );
    let v = verify_record(&case, "signins", S1, None).unwrap();
    assert!(v.ok, "{v:#?}");
    assert_eq!(v.sightings.len(), 2);
}

/// The Entra portal export leaves "Sign-in error code" empty on Success (Failure and Interrupted
/// carry a non-zero integer): an empty code on a Success row is stored as 0, an empty code on any
/// other status stays unknown.
#[test]
fn portal_success_with_an_empty_error_code_stores_zero() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let with = |id: &str, status: &str, code: &str| {
        let mut r = portal_row(
            id,
            "2026-09-01T09:30:00Z",
            "Seattle, Washington, US",
            "Yes",
            "s",
        );
        r[13] = status.to_string();
        r[14] = code.to_string();
        r
    };
    fixtures::write(
        &root,
        PORTAL_CSV,
        &portal_csv(&[
            with(S1, "Success", ""),
            with(S2, "success", ""),
            with(S3, "Failure", "50126"),
            with(
                "c0c0c0c0-0000-4000-8000-0000000000a4",
                "Interrupted",
                "50074",
            ),
            with("c0c0c0c0-0000-4000-8000-0000000000a5", "Failure", ""),
            with("c0c0c0c0-0000-4000-8000-0000000000a6", "", ""),
            with("c0c0c0c0-0000-4000-8000-0000000000a7", "Pending", ""),
        ]),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM signins"), 7);
    assert_eq!(
        text(
            &case,
            "SELECT string_agg(coalesce(CAST(error_code AS VARCHAR), 'NULL'), ',' ORDER BY record_key) FROM signins"
        ),
        {
            // Ordered by record_key (the lower-cased sign-in ids).
            let mut v = [
                (S1.to_lowercase(), "0"),
                (S2.to_lowercase(), "0"),
                (S3.to_lowercase(), "50126"),
                ("c0c0c0c0-0000-4000-8000-0000000000a4".to_string(), "50074"),
                ("c0c0c0c0-0000-4000-8000-0000000000a5".to_string(), "NULL"),
                ("c0c0c0c0-0000-4000-8000-0000000000a6".to_string(), "NULL"),
                ("c0c0c0c0-0000-4000-8000-0000000000a7".to_string(), "NULL"),
            ];
            v.sort();
            v.iter().map(|(_, c)| *c).collect::<Vec<_>>().join(",")
        }
    );
}

#[test]
fn portal_xlsx_rows_load_with_sheet_row_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("exports");
    let mut wb = rust_xlsxwriter::Workbook::new();
    let ws = wb.add_worksheet();
    let rows = [
        (
            0u32,
            PORTAL_HEADER
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        ),
        (
            1,
            portal_row(
                S1,
                "2026-09-01T09:30:00Z",
                "Lagos, Lagos, NG",
                "No",
                "sess-1",
            ),
        ),
        (
            3,
            // XLSX renders Date (UTC) without a zone.
            portal_row(
                S3,
                "2026-09-01 11:00:00",
                "Seattle, Washington, US",
                "Yes",
                "sess-3",
            ),
        ),
    ];
    for (r, cells) in &rows {
        for (c, v) in cells.iter().enumerate() {
            if !v.is_empty() {
                ws.write_string(*r, c as u16, v).unwrap();
            }
        }
    }
    let name = "InteractiveSignins_2026-09-01_2026-09-10.xlsx";
    fixtures::write(&root, name, &wb.save_to_buffer().unwrap());
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let f = row(&report, name);
    assert_eq!((f.status, f.records_loaded), (FileStatus::Parsed, 2));
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT line_start FROM record_sources WHERE table_name = 'signins' AND record_key = '{S3}'"
            )
        ),
        4
    );
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT session_id || '|' || event_type || '|' || time_tz_assumed || '|' || epoch(event_time)::BIGINT
                 FROM signins WHERE record_key = '{S3}'"
            )
        ),
        "sess-3|interactive|false|1788260400"
    );
    let v = verify_record(&case, "signins", S3, None).unwrap();
    assert!(v.ok, "{v:#?}");
}

#[test]
fn signin_without_an_id_is_a_parse_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        PORTAL_CSV,
        &portal_csv(&[
            portal_row(
                S1,
                "2026-09-01T09:30:00Z",
                "Lagos, Lagos, NG",
                "No",
                "sess-1",
            ),
            portal_row(
                "",
                "2026-09-01T09:31:00Z",
                "Lagos, Lagos, NG",
                "No",
                "sess-1",
            ),
        ]),
    );
    let (case, report) = ingest(dir.path());
    let f = row(&report, PORTAL_CSV);
    assert_eq!((f.records_loaded, f.records_error), (1, 1));
    assert!(report.has_errors());
    assert_eq!(count(&case, "SELECT line_start FROM parse_errors"), 3);
}

#[test]
fn unknown_sign_in_shape_is_not_supported() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = signin_json(&root, &[json!({"Foo": 1})]);
    let (_case, report) = ingest(dir.path());
    assert_eq!(row(&report, &rel).status, FileStatus::NotSupported);
}

#[test]
fn risky_signin_flag_links_to_the_signin() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let risky = graph_signin(S2, "2026-09-01T10:00:00Z", 0, "medium");
    signin_json(&root, std::slice::from_ref(&risky));
    let mut flagged = risky;
    flagged["Id"] = json!(S2.to_uppercase());
    fixtures::write(
        &root,
        &format!("{ALICE}/_Investigate_Entra_Sign_In_Log_{ALICE}_{ALICE}.json"),
        fixtures::ps_json(&flagged).as_bytes(),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collector_flags WHERE flag_type = 'risky_signin'
               AND linked_key IN (SELECT record_key FROM signins)"
        ),
        1
    );
}

/// Every base table as (name, rows, content hash), without the random case id and the clock columns.
fn all_tables(case: &Case) -> Vec<(String, i64, String)> {
    let sql: String = case
        .conn()
        .query_row(
            "WITH c AS (
                SELECT table_name,
                       string_agg(format('\"{}\"', column_name), ',' ORDER BY ordinal_position) AS cols
                FROM information_schema.columns
                WHERE table_schema = 'main' AND table_name <> 'case_meta'
                  AND table_name IN (SELECT table_name FROM information_schema.tables
                                     WHERE table_type = 'BASE TABLE' AND table_schema = 'main')
                  AND NOT regexp_matches(column_name, '(_at|started|finished|duration|elapsed)$')
                GROUP BY table_name)
             SELECT string_agg(format('SELECT ''{}'' AS t, count(*) AS n, CAST(coalesce(sum(hash({})), 0) AS VARCHAR) AS h FROM \"{}\"',
                                      table_name, cols, table_name), ' UNION ALL ' ORDER BY table_name)
             FROM c",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut stmt = case.conn().prepare(&format!("{sql} ORDER BY t")).unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn every_batch_size_stores_what_one_batch_stores() {
    // Sign-in files are streamed and loaded in batches: a later copy of a key in the same file must stay a
    // duplicate across batches (the file's first copy wins), rejects and bad times must stay errors, and the
    // portal rows must update the Graph rows exactly as in one batch.
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let mut no_id = graph_signin(S3, "2026-09-01T12:00:00Z", 0, "none");
    no_id.as_object_mut().unwrap().remove("Id");
    let json_rel = signin_json(
        &root,
        &[
            graph_signin(S1, "2026-09-01T09:30:00Z", 0, "none"),
            graph_signin(S2, "2026-09-01T10:00:00Z", 50126, "high"),
            graph_signin(S1, "2026-09-01T09:31:00Z", 50126, "medium"),
            no_id,
            graph_signin(S2, "2026-09-01T10:01:00Z", 0, "none"),
        ],
    );
    let s4 = "a4a4a4a4-4444-4444-8444-444444444444";
    fixtures::write(
        &root,
        PORTAL_CSV,
        &portal_csv(&[
            portal_row(
                &S1.to_uppercase(),
                "2026-09-01T09:30:00Z",
                "Lagos, Lagos, NG",
                "No",
                "sess-1",
            ),
            portal_row(
                S3,
                "2026-09-01T11:00:00Z",
                "Seattle, Washington, US",
                "Yes",
                "sess-3",
            ),
            portal_row(s4, "not a time", "Seattle, Washington, US", "Yes", "sess-4"),
            portal_row(
                S3,
                "2026-09-01T11:05:00Z",
                "Paris, Ile-de-France, FR",
                "No",
                "sess-3b",
            ),
            portal_row(
                "",
                "2026-09-01T11:10:00Z",
                "Paris, Ile-de-France, FR",
                "No",
                "sess-5",
            ),
            portal_row(
                S2,
                "2026-09-01T10:00:00Z",
                "Lagos, Lagos, NG",
                "No",
                "sess-2",
            ),
        ]),
    );
    let run = |batch: usize| {
        let mut case = Case::in_memory().unwrap();
        let opts = IngestOptions {
            batch_rows: batch,
            ..IngestOptions::default()
        };
        let report = ingest_path(&mut case, dir.path(), &ParserRegistry::builtin(), &opts).unwrap();
        let files: Vec<String> = report
            .collections
            .iter()
            .flat_map(|c| &c.files)
            .map(|f| {
                format!(
                    "{} {:?} {} {} {} {} {:?}",
                    f.rel_path,
                    f.status,
                    f.records_read,
                    f.records_loaded,
                    f.records_duplicate,
                    f.records_error,
                    f.warnings
                )
            })
            .collect();
        (all_tables(&case), files)
    };
    let (want_tables, want_files) = run(usize::MAX);
    let file = |rel: &str| {
        want_files
            .iter()
            .find(|f| f.starts_with(rel))
            .unwrap()
            .clone()
    };
    // read / loaded / duplicate / error: JSON 5 records, 2 kept, 2 later copies, 1 without an Id.
    assert!(
        file(&json_rel).contains(" Parsed 5 2 2 1 "),
        "{}",
        file(&json_rel)
    );
    // Portal: 6 rows; S1 and S2 update the Graph rows, S3 is new, its second copy is a duplicate, one bad time and
    // one row without a Request ID are errors.
    assert!(
        file(PORTAL_CSV).contains(" Parsed 6 3 1 2 "),
        "{}",
        file(PORTAL_CSV)
    );
    for batch in [1, 2, 3] {
        let (tables, files) = run(batch);
        assert_eq!(files, want_files, "batch {batch}: file reports");
        assert_eq!(tables, want_tables, "batch {batch}: tables");
    }
}
