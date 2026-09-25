use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use std::path::{Path, PathBuf};

const A1: &str = "Directory_0E0E0E0E-0000-4000-8000-000000000001_ABCDE_1";
const A2: &str = "Directory_0E0E0E0E-0000-4000-8000-000000000002_ABCDE_2";

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

fn audit(id: &str, when: &str, by_user: bool) -> Value {
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
        "ActivityDateTime": when,
        "ActivityDisplayName": "Consent to application",
        "AdditionalDetails": [{"Key": "User-Agent", "Value": "Mozilla/5.0"}],
        "Category": "ApplicationManagement",
        "CorrelationId": "D0D0D0D0-0000-4000-8000-000000000001",
        "Id": id,
        "InitiatedBy": initiated,
        "LoggedByService": "Core Directory",
        "OperationType": "Assign",
        "Result": "success",
        "ResultReason": "",
        "TargetResources": [{
            "DisplayName": "Invoice Viewer", "Id": "33333333-3333-4333-8333-333333333333",
            "ModifiedProperties": [{"DisplayName": "ConsentAction.Permissions",
                                    "NewValue": "\"[Mail.Read]\"", "OldValue": null}],
            "Type": "ServicePrincipal", "UserPrincipalName": null
        }],
        "AdditionalProperties": {}
    })
}

const JSON_REL: &str = "Tenant/EntraIDAuditLogs.json";
const CSV_REL: &str = "Tenant/EntraIDAuditLogs.csv";

fn lossy_csv() -> String {
    csv_line(&[
        "ActivityDateTime",
        "ActivityDisplayName",
        "AdditionalDetails",
        "Category",
        "CorrelationId",
        "Id",
        "InitiatedBy",
        "LoggedByService",
        "OperationType",
        "Result",
        "ResultReason",
        "TargetResources",
        "AdditionalProperties",
    ]) + &csv_line(&[
        "9/14/2026 10:05:00 AM",
        "Consent to application",
        "System.Collections.Generic.List`1[Microsoft.Graph.PowerShell.Models.MicrosoftGraphKeyValue]",
        "ApplicationManagement",
        "d0d0d0d0-0000-4000-8000-000000000001",
        A1,
        "Microsoft.Graph.PowerShell.Models.MicrosoftGraphAuditActivityInitiator",
        "Core Directory",
        "Assign",
        "success",
        "",
        "Microsoft.Graph.PowerShell.Models.MicrosoftGraphTargetResource",
        "System.Collections.Generic.Dictionary`2[System.String,System.Object]",
    ])
}

#[test]
fn directory_audits_load_initiator_targets_and_modified_properties() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        JSON_REL,
        fixtures::ps_json(&json!([
            audit(A1, "2026-09-01T10:05:00.1234567Z", true),
            audit(A2, "2026-09-01T10:06:00Z", false)
        ]))
        .as_bytes(),
    );
    fixtures::write(&root, CSV_REL, lossy_csv().as_bytes());
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(row(&report, JSON_REL).records_loaded, 2);
    assert_eq!(row(&report, CSV_REL).status, FileStatus::SkippedSuperseded);
    let k1 = A1.to_lowercase();
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT activity || '|' || category || '|' || operation_type || '|' || result || '|' ||
                        initiated_by_upn || '|' || initiated_by_user_id || '|' || initiated_by_ip || '|' ||
                        correlation_id || '|' || (modified_properties->>'$[0].property') || '|' ||
                        (modified_properties->>'$[0].target') || '|' || (modified_properties->>'$[0].new') || '|' ||
                        (additional_details->>'$[0].Key') || '|' || time_tz_assumed
                 FROM directory_audits WHERE record_key = '{k1}'"
            )
        ),
        "Consent to application|ApplicationManagement|Assign|success|alice@contoso.example|11111111-1111-4111-8111-111111111111|203.0.113.10|d0d0d0d0-0000-4000-8000-000000000001|ConsentAction.Permissions|Invoice Viewer|\"[Mail.Read]\"|User-Agent|false"
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT epoch(event_time)::BIGINT FROM directory_audits WHERE record_key = '{k1}'"
            )
        ),
        1788257100
    );
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT initiated_by_app_id || '|' || initiated_by_app_name || '|' || coalesce(initiated_by_upn, '-')
                 FROM directory_audits WHERE record_key = '{}'",
                A2.to_lowercase()
            )
        ),
        "33333333-3333-4333-8333-333333333333|Invoice Viewer|-"
    );
}

#[test]
fn lone_csv_loads_scalar_columns_and_warns() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, CSV_REL, lossy_csv().as_bytes());
    let (case, report) = ingest(dir.path());
    let f = row(&report, CSV_REL);
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
            "SELECT count(*) FROM directory_audits WHERE initiated_by_upn IS NULL AND targets IS NULL
               AND additional_details IS NULL AND time_tz_assumed AND epoch(event_time)::BIGINT = 1789380300"
        ),
        1
    );
}

#[test]
fn audit_without_an_id_is_a_parse_error_and_other_shapes_are_not_supported() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let mut no_id = audit(A1, "2026-09-01T10:05:00Z", true);
    no_id["Id"] = Value::Null;
    fixtures::write(
        &root,
        JSON_REL,
        fixtures::ps_json(&json!([audit(A2, "2026-09-01T10:06:00Z", true), no_id])).as_bytes(),
    );
    let (_case, report) = ingest(dir.path());
    let f = row(&report, JSON_REL);
    assert_eq!((f.records_loaded, f.records_error), (1, 1));

    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, JSON_REL, br#"[{"Foo": 1}]"#);
    let (_case, report) = ingest(dir.path());
    assert_eq!(row(&report, JSON_REL).status, FileStatus::NotSupported);
}
