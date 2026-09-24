use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::readers::time::DateOrder;
use sparrow_core::verify::verify_record;
use std::path::{Path, PathBuf};

const ID_A: &str = "a1111111-1111-4111-8111-111111111111";
const ID_B: &str = "a2222222-2222-4222-8222-222222222222";
const PURVIEW: &str = "0f8fad5b-d9cb-469f-a165-70867728950e.csv";

fn audit(id: &str, op: &str) -> Value {
    json!({
        "CreationTime": "2026-09-01T10:00:00", "Id": id, "Operation": op, "RecordType": 1,
        "UserId": "admin@contoso.example", "Workload": "Exchange",
        "Parameters": [{"Name": "ForwardTo", "Value": "x@fabrikam.example"}]
    })
}

fn csv_line(fields: &[&str]) -> String {
    let q: Vec<String> = fields
        .iter()
        .map(|f| format!("\"{}\"", f.replace('"', "\"\"")))
        .collect();
    format!("{}\r\n", q.join(","))
}

fn capture(base: &Path) -> PathBuf {
    let root = base.join("cap");
    fixtures::write(&root, "Hawk.log", fixtures::HAWK_LOG.as_bytes());
    root
}

fn ingest(base: &Path, order: Option<DateOrder>) -> (Case, IngestReport) {
    let mut case = Case::in_memory().unwrap();
    let opts = IngestOptions {
        date_order: order,
        ..IngestOptions::default()
    };
    let report = ingest_path(&mut case, base, &ParserRegistry::builtin(), &opts).unwrap();
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

#[test]
fn raw_json_loads_and_its_csv_twin_is_superseded() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let a = audit(ID_A, "New-InboxRule");
    let raw = json!([{
        "RecordType": "ExchangeAdmin", "CreationDate": "2026-09-01T10:00:05",
        "UserIds": "admin@contoso.example", "Operations": "New-InboxRule",
        "AuditData": a.to_string(), "ResultIndex": 1, "ResultCount": 1
    }]);
    fixtures::write(
        &root,
        "Tenant/Admin_Inbox_Rules_Creation.json",
        serde_json::to_string_pretty(&raw).unwrap().as_bytes(),
    );
    let csv = csv_line(&[
        "RecordType",
        "CreationDate",
        "UserIds",
        "Operations",
        "AuditData",
    ]) + &csv_line(&[
        "ExchangeAdmin",
        "9/1/2026 10:00:05 AM",
        "admin@contoso.example",
        "New-InboxRule",
        &a.to_string(),
    ]);
    fixtures::write(
        &root,
        "Tenant/Admin_Inbox_Rules_Creation.csv",
        csv.as_bytes(),
    );
    let (case, report) = ingest(dir.path(), None);
    let json_row = row(&report, "Tenant/Admin_Inbox_Rules_Creation.json");
    assert_eq!(json_row.status, FileStatus::Parsed);
    assert_eq!((json_row.records_read, json_row.records_loaded), (1, 1));
    assert_eq!(
        row(&report, "Tenant/Admin_Inbox_Rules_Creation.csv").status,
        FileStatus::SkippedSuperseded
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE parameters['ForwardTo'] = 'x@fabrikam.example'"
        ),
        1
    );
    assert!(!report.has_errors());
}

#[test]
fn purview_rows_keep_editor_line_numbers_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let a = audit(ID_A, "New-InboxRule").to_string();
    // AuditData of B contains a line break inside the quoted cell: the row spans lines 3-4.
    let b = format!(
        "{{\"CreationTime\":\"2026-09-01T10:10:00\",\"Id\":\"{ID_B}\",\r\n\"Operation\":\"Set-InboxRule\",\"UserId\":\"admin@contoso.example\"}}"
    );
    let text = "RecordId,CreationDate,RecordType,Operation,UserId,AuditData\r\n".to_string()
        + &csv_line(&[
            ID_A,
            "2026-09-01T10:00:00.0000000Z",
            "1",
            "New-InboxRule",
            "admin@contoso.example",
            &a,
        ])
        + &csv_line(&[
            ID_B,
            "2026-09-01T10:10:00.0000000Z",
            "1",
            "Set-InboxRule",
            "admin@contoso.example",
            &b,
        ]);
    fixtures::write(&root, PURVIEW, text.as_bytes());
    let (case, report) = ingest(dir.path(), None);
    let f = row(&report, PURVIEW);
    assert_eq!(f.artifact_id.as_deref(), Some("portal.ual"));
    assert_eq!((f.records_read, f.records_loaded), (2, 2));
    let lines: (i64, i64) = case
        .conn()
        .query_row(
            "SELECT line_start, line_end FROM record_sources WHERE record_key = ?",
            [ID_B],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(lines, (3, 4));
    let v = verify_record(&case, "ual_events", ID_B, None).unwrap();
    assert!(v.ok, "{v:?}");
    assert!(
        v.sightings[0]
            .source_ref
            .ends_with(&format!("{PURVIEW}:3-4"))
    );
}

#[test]
fn invalid_embedded_audit_data_is_a_record_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let a = audit(ID_A, "New-InboxRule").to_string();
    let text = "RecordId,CreationDate,RecordType,Operation,UserId,AuditData\r\n".to_string()
        + &csv_line(&[
            ID_A,
            "2026-09-01T10:00:00Z",
            "1",
            "New-InboxRule",
            "admin@contoso.example",
            &a,
        ])
        + &csv_line(&[
            ID_B,
            "2026-09-01T10:10:00Z",
            "1",
            "Set-InboxRule",
            "admin@contoso.example",
            "{\"Id\":",
        ]);
    fixtures::write(&root, PURVIEW, text.as_bytes());
    let (case, report) = ingest(dir.path(), None);
    let f = row(&report, PURVIEW);
    assert_eq!(f.status, FileStatus::Parsed);
    assert_eq!(
        (f.records_read, f.records_loaded, f.records_error),
        (2, 1, 1)
    );
    let (line, msg): (i64, String) = case
        .conn()
        .query_row("SELECT line_start, error FROM parse_errors", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(line, 3);
    assert!(msg.contains("not valid JSON"), "{msg}");
    assert!(report.has_errors());
}

#[test]
fn admin_audit_shape_is_not_supported() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let admin = json!([{
        "ObjectModified": "svc", "CmdletName": "New-ManagementRoleAssignment",
        "CmdletParameters": [{"Name": "Role", "Value": "ApplicationImpersonation"}],
        "Caller": "admin@contoso.example", "Succeeded": true, "RunDate": "2026-09-02T08:00:00"
    }]);
    fixtures::write(
        &root,
        "Tenant/RBAC_Changes.json",
        admin.to_string().as_bytes(),
    );
    let (case, report) = ingest(dir.path(), None);
    let f = row(&report, "Tenant/RBAC_Changes.json");
    assert_eq!(f.status, FileStatus::NotSupported);
    assert!(
        f.warnings[0].contains("Search-AdminAuditLog"),
        "{:?}",
        f.warnings
    );
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 0);
    assert!(!report.has_errors());
}

#[test]
fn ambiguous_culture_dates_fail_file_unless_culture_given() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cap");
    let rel = "alice@contoso.example/ExchangeItem_Simple_alice@contoso.example.csv";
    let text = csv_line(&["CreationTime", "Id", "Operation", "Workload", "UserId"])
        + &csv_line(&[
            "9/2/2026 8:00:00 AM",
            ID_A,
            "Send",
            "Exchange",
            "alice@contoso.example",
        ]);
    fixtures::write(&root, rel, text.as_bytes());

    let (_case, report) = ingest(dir.path(), None);
    let f = row(&report, rel);
    assert_eq!(f.status, FileStatus::Error);
    assert!(f.warnings[0].contains("--culture"), "{:?}", f.warnings);

    let (case, report) = ingest(dir.path(), Some(DateOrder::MonthFirst));
    assert_eq!(row(&report, rel).status, FileStatus::Parsed);
    let (t, completeness): (String, String) = case
        .conn()
        .query_row(
            "SELECT CAST(event_time AS VARCHAR), CAST(data_completeness AS VARCHAR) FROM ual_events",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (t.as_str(), completeness.as_str()),
        ("2026-09-02 08:00:00+00", "partial")
    );
}

#[test]
fn culture_override_contradicted_by_file_dates_fails_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cap");
    let rel = "alice@contoso.example/ExchangeItem_Simple_alice@contoso.example.csv";
    let line = |t: &str, id: &str| csv_line(&[t, id, "Send", "Exchange", "alice@contoso.example"]);
    let text = csv_line(&["CreationTime", "Id", "Operation", "Workload", "UserId"])
        + &line("24/9/2026 8:00:00 AM", ID_A)
        + &line("6/9/2026 8:00:00 AM", ID_B);
    fixtures::write(&root, rel, text.as_bytes());

    let (case, report) = ingest(dir.path(), Some(DateOrder::MonthFirst));
    let f = row(&report, rel);
    assert_eq!(f.status, FileStatus::Error);
    assert!(
        f.warnings.iter().any(|w| w.contains("--culture")),
        "{:?}",
        f.warnings
    );
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 0);
}

fn app_audit_object(id: &str, env_time: Value) -> String {
    serde_json::to_string_pretty(&json!({
        "Id": id, "Operation": "Consent to application.", "ResultStatus": "Success",
        "Workload": "AzureActiveDirectory", "ClientIP": null, "UserId": "alice@contoso.example",
        "ActorUPN": "alice@contoso.example", "targetName": "Invoice Viewer",
        "env_time": env_time, "correlationId": "c"
    }))
    .unwrap()
}

#[test]
fn application_audit_without_any_timestamp_is_not_supported() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = "Tenant/Entra_ID_Application_Audit.json";
    let text = format!(
        "{}\r\n{}\r\n",
        app_audit_object(ID_A, Value::Null),
        app_audit_object(ID_B, json!(""))
    );
    fixtures::write(&root, rel, text.as_bytes());
    let (case, report) = ingest(dir.path(), None);
    let f = row(&report, rel);
    assert_eq!(f.status, FileStatus::NotSupported);
    assert!(
        f.warnings.iter().any(|w| w.contains("no timestamps")),
        "{:?}",
        f.warnings
    );
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 0);
    assert_eq!(count(&case, "SELECT count(*) FROM parse_errors"), 0);
}

#[test]
fn application_audit_records_without_a_timestamp_are_parse_errors() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = "Tenant/Entra_ID_Application_Audit.json";
    let text = format!(
        "{}\r\n{}\r\n",
        app_audit_object(ID_A, json!("2026-09-02T09:00:00Z")),
        app_audit_object(ID_B, Value::Null)
    );
    fixtures::write(&root, rel, text.as_bytes());
    let (case, report) = ingest(dir.path(), None);
    let f = row(&report, rel);
    assert_eq!(
        (f.status, f.records_loaded, f.records_error),
        (FileStatus::Parsed, 1, 1)
    );
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 1);
    assert_eq!(count(&case, "SELECT count(*) FROM parse_errors"), 1);
}

#[test]
fn concatenated_application_audit_objects_load_as_partial() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let obj = |id: &str| {
        serde_json::to_string_pretty(&json!({
            "Id": id, "Operation": "Consent to application.", "ResultStatus": "Success",
            "Workload": "AzureActiveDirectory", "ClientIP": null, "UserId": "alice@contoso.example",
            "ActorUPN": "alice@contoso.example", "targetName": "Invoice Viewer",
            "env_time": "2026-09-02T09:00:00Z", "correlationId": "c"
        }))
        .unwrap()
    };
    let text = format!("{}\r\n{}\r\n", obj(ID_A), obj(ID_B));
    fixtures::write(
        &root,
        "Tenant/Entra_ID_Application_Audit.json",
        text.as_bytes(),
    );
    let (case, report) = ingest(dir.path(), None);
    let f = row(&report, "Tenant/Entra_ID_Application_Audit.json");
    assert_eq!((f.status, f.records_loaded), (FileStatus::Parsed, 2));
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE data_completeness = 'partial'
             AND event_time = TIMESTAMPTZ '2026-09-02 09:00:00+00'"
        ),
        2
    );
}

#[test]
fn records_without_an_id_get_synthetic_ids_and_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let text = csv_line(&["CreationTime", "Id", "Operation", "Workload", "UserId"])
        + &csv_line(&[
            "2026-09-02T08:00:00",
            "",
            "SearchCreated",
            "SecurityComplianceCenter",
            "admin@contoso.example",
        ]);
    fixtures::write(&root, "Tenant/eDiscoveryLogs.csv", text.as_bytes());
    let (case, report) = ingest(dir.path(), None);
    let f = row(&report, "Tenant/eDiscoveryLogs.csv");
    assert_eq!(f.records_loaded, 1);
    assert!(f.warnings.iter().any(|w| w.contains("content-derived id")));
    assert_eq!(
        count(&case, "SELECT count(*) FROM ual_events WHERE synthetic_id"),
        1
    );
}

#[test]
fn phase1_hawk_fixture_now_loads_its_raw_ual_file() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let (_case, report) = ingest(dir.path(), None);
    let f = row(&report, "Tenant/RBAC_Changes.csv");
    assert_eq!((f.status, f.records_loaded), (FileStatus::Parsed, 1));
    assert_eq!(
        row(&report, "Tenant/Simple_RBAC_Changes.csv").status,
        FileStatus::SkippedSuperseded
    );
    assert!(!report.has_errors(), "{report:#?}");
}
