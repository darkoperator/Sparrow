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
    // JSON sources are complete.
    assert_eq!(
        text(
            &case,
            "SELECT string_agg(CAST(data_completeness AS VARCHAR), ',') FROM directory_audits"
        ),
        "full,full"
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
               AND additional_details IS NULL AND time_tz_assumed AND epoch(event_time)::BIGINT = 1789380300
               AND data_completeness = 'partial'"
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

/// The tables and each file's report line (status, read, loaded, duplicate, error, warnings) of an ingest of
/// `base` with `batch_rows = batch`.
fn run_batched(base: &Path, batch: usize) -> (Vec<(String, i64, String)>, Vec<String>) {
    let mut case = Case::in_memory().unwrap();
    let opts = IngestOptions {
        batch_rows: batch,
        ..IngestOptions::default()
    };
    let report = ingest_path(&mut case, base, &ParserRegistry::builtin(), &opts).unwrap();
    let files = report
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
}

const A3: &str = "Directory_0E0E0E0E-0000-4000-8000-000000000003_ABCDE_3";
const A4: &str = "Directory_0E0E0E0E-0000-4000-8000-000000000004_ABCDE_4";

/// `lossy_csv`'s header and a row of it for audit `id` at `when`.
fn lossy_csv_rows(rows: &[(&str, &str)]) -> String {
    let mut lines = lossy_csv().lines().map(str::to_string).collect::<Vec<_>>();
    let template = lines.pop().unwrap();
    let mut out = lines.join("\n") + "\n";
    for (id, when) in rows {
        out += &template
            .replace(A1, id)
            .replace("9/14/2026 10:05:00 AM", when);
        out += "\n";
    }
    out
}

#[test]
fn every_batch_size_stores_what_one_batch_stores() {
    // Directory audit files are streamed and staged in batches: a later copy of an id in the same file stays a
    // duplicate across batches (the file's first copy wins), rejects and bad times stay errors.
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let mut no_id = audit(A3, "2026-09-01T10:07:00Z", true);
    no_id["Id"] = Value::Null;
    let mut later = audit(A1, "2026-09-01T10:08:00Z", false);
    later["Result"] = json!("failure");
    fixtures::write(
        &root,
        JSON_REL,
        fixtures::ps_json(&json!([
            audit(A1, "2026-09-01T10:05:00Z", true),
            audit(A2, "2026-09-01T10:06:00Z", false),
            later,
            no_id,
            audit(A3, "not a time", true),
            audit(&A2.to_lowercase(), "2026-09-01T10:09:00Z", true),
            audit(A4, "2026-09-01T10:10:00Z", true),
        ]))
        .as_bytes(),
    );
    let (want_tables, want_files) = run_batched(dir.path(), usize::MAX);
    let line = want_files.iter().find(|f| f.starts_with(JSON_REL)).unwrap();
    // read / loaded / duplicate / error: 7 records, 3 ids kept, 2 later copies, no id and a bad time.
    assert!(line.contains(" Parsed 7 3 2 2 "), "{line}");
    for batch in [1, 2, 3] {
        let (tables, files) = run_batched(dir.path(), batch);
        assert_eq!(files, want_files, "batch {batch}: file reports");
        assert_eq!(tables, want_tables, "batch {batch}: tables");
    }

    // The lone Hawk CSV (placeholders, so a warning; partial rows).
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        CSV_REL,
        lossy_csv_rows(&[
            (A1, "9/14/2026 10:05:00 AM"),
            (A2, "9/14/2026 10:06:00 AM"),
            (A1, "9/14/2026 10:07:00 AM"),
            ("", "9/14/2026 10:08:00 AM"),
            (A3, "not a time"),
            (A2, "9/14/2026 10:09:00 AM"),
            (A4, "9/14/2026 10:10:00 AM"),
        ])
        .as_bytes(),
    );
    let (want_tables, want_files) = run_batched(dir.path(), usize::MAX);
    let line = want_files.iter().find(|f| f.starts_with(CSV_REL)).unwrap();
    assert!(line.contains(" Parsed 7 3 2 2 "), "{line}");
    assert!(
        line.contains("7 CSV records hold PowerShell placeholders"),
        "{line}"
    );
    for batch in [1, 2, 3] {
        let (tables, files) = run_batched(dir.path(), batch);
        assert_eq!(files, want_files, "batch {batch}: file reports");
        assert_eq!(tables, want_tables, "batch {batch}: tables");
    }
}

/// Thirteen keys, so the error names only the first record's first twelve.
fn foreign_record(tag: &str) -> Value {
    let mut m = serde_json::Map::new();
    for k in [
        "Zulu", "Alpha", "Mike", "Bravo", "Yankee", "Charlie", "Xray", "Delta", "Whiskey", "Echo",
        "Victor", "Foxtrot", "Uniform",
    ] {
        m.insert(format!("{k}{tag}"), json!(1));
    }
    Value::Object(m)
}

#[test]
fn an_unsupported_shape_names_the_first_record_s_first_twelve_columns() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        JSON_REL,
        fixtures::ps_json(&json!([foreign_record("1"), foreign_record("2")])).as_bytes(),
    );
    let (case, report) = ingest(dir.path());
    let f = row(&report, JSON_REL);
    // The values the collected parser (aed066fc) gave.
    assert_eq!(
        (f.status, f.records_read, f.records_loaded, f.records_error),
        (FileStatus::NotSupported, 0, 0, 0)
    );
    assert_eq!(
        f.warnings,
        [
            "hawk.tenant.entra_audit: no Entra ID directory audit fields in [Zulu1, Alpha1, Mike1, Bravo1, Yankee1, Charlie1, Xray1, Delta1, Whiskey1, Echo1, Victor1, Foxtrot1]"
        ]
    );
    assert_eq!(count(&case, "SELECT count(*) FROM directory_audits"), 0);
}

#[test]
fn a_file_of_only_unreadable_records_records_them_and_loads_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, JSON_REL, b"[1, \"two\", [3]]");
    let (case, report) = ingest(dir.path());
    let f = row(&report, JSON_REL);
    // The values the collected parser (aed066fc) gave.
    assert_eq!(
        (
            f.status,
            f.records_read,
            f.records_loaded,
            f.records_duplicate,
            f.records_error
        ),
        (FileStatus::Parsed, 3, 0, 0, 3)
    );
    assert!(f.warnings.is_empty(), "{:?}", f.warnings);
    let errs: String = text(
        &case,
        "SELECT string_agg(record_ordinal || ':' || line_start || ':' || byte_offset || ':' || byte_length || ':' || error || ':' || raw_snippet, ' | ' ORDER BY record_ordinal) FROM parse_errors",
    );
    assert_eq!(
        errs,
        "0:1:1:1:record is not a JSON object:1 | 1:1:4:5:record is not a JSON object:\"two\" | 2:1:11:3:record is not a JSON object:[3]"
    );
    assert_eq!(count(&case, "SELECT count(*) FROM directory_audits"), 0);
}
