use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line, ps_json, utf8_bom};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::supersede::truncation_warning;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::verify::verify_record;
use std::path::Path;

const ALICE: &str = "alice@contoso.example";
const ID_1: &str = "11111111-1111-4111-8111-111111111111";
const ID_2: &str = "22222222-2222-4222-8222-222222222222";
const ID_3: &str = "33333333-3333-4333-8333-333333333333";
const RAW_HEADER: &[&str] = &[
    "RecordType",
    "CreationDate",
    "UserIds",
    "Operations",
    "AuditData",
    "ResultIndex",
    "ResultCount",
    "AuditSearchRequestMetadata",
    "Identity",
    "IsValid",
    "ObjectState",
];

fn audit(id: &str, time: &str, op: &str) -> Value {
    json!({
        "CreationTime": time, "Id": id, "Operation": op,
        "OrganizationId": "0e0e0e0e-0000-4000-8000-00000000000a", "RecordType": 1,
        "ResultStatus": "True", "UserKey": "1003200000000001", "UserType": 2, "Version": 1,
        "Workload": "Exchange", "ClientIP": "203.0.113.10", "UserId": ALICE, "ObjectId": ALICE,
        "Parameters": [{"Name": "Identity", "Value": ALICE}]
    })
}

/// One Search-UnifiedAuditLog row as Export-Csv writes it; the metadata cell spans 3 lines.
fn raw_row(a: &Value) -> String {
    csv_line(&[
        "ExchangeAdmin",
        "9/1/2026 10:20:00 AM",
        ALICE,
        a["Operation"].as_str().unwrap(),
        &a.to_string(),
        "1",
        "3",
        "{\n  \"moreRecordsAvailable\": false\n}",
        a["Id"].as_str().unwrap(),
        "True",
        "Unchanged",
    ])
}

/// The record as Get-UAL -Output JSON writes it: AuditData parsed into an object.
fn json_record(a: &Value) -> Value {
    json!({
        "RecordType": "ExchangeAdmin", "CreationDate": "2026-09-01T10:20:00",
        "UserIds": ALICE, "Operations": a["Operation"], "AuditData": a,
        "ResultIndex": 1, "ResultCount": 1, "Identity": a["Id"], "IsValid": true,
        "ObjectState": "Unchanged"
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
fn csv_window_loads_raw_records_with_line_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let a1 = audit(ID_1, "2026-09-01T10:20:00", "Set-Mailbox");
    let a2 = audit(ID_2, "2026-09-01T10:21:00", "New-InboxRule");
    let body = format!(
        "{}{}{}{}",
        csv_line(RAW_HEADER),
        raw_row(&a1),
        raw_row(&a2),
        raw_row(&a1) // Search-UnifiedAuditLog repeats records inside one window
    );
    let rel = "UnifiedAuditLog/20260910-100000/UAL-20260901000000-20260902000000.csv";
    fixtures::write(&dir.path().join("OUT"), rel, &utf8_bom(&body));
    let (case, report) = ingest(dir.path());
    let f = row(&report, rel);
    assert_eq!(f.artifact_id.as_deref(), Some("inv.ual.window"));
    assert_eq!(f.status, FileStatus::Parsed);
    assert_eq!(
        (
            f.records_read,
            f.records_loaded,
            f.records_duplicate,
            f.records_error
        ),
        (3, 2, 1, 0)
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE data_completeness = 'full'"
        ),
        2
    );
    assert_eq!(
        count(
            &case,
            &format!("SELECT epoch(event_time)::BIGINT FROM ual_events WHERE record_id = '{ID_1}'")
        ),
        1_788_258_000
    );
    // Header = line 1; each row spans 3 physical lines (metadata cell).
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT min(line_start) FROM record_sources WHERE table_name = 'ual_events' AND record_key = '{ID_2}'"
            )
        ),
        5
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM record_sources WHERE table_name = 'ual_events' AND record_key = '{ID_1}'"
            )
        ),
        2
    );
    assert!(verify_record(&case, "ual_events", ID_2, None).unwrap().ok);
}

#[test]
fn json_windows_array_and_bare_object_load_full() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    let many = json!([
        json_record(&audit(ID_1, "2026-09-01T10:20:00", "Set-Mailbox")),
        json_record(&audit(ID_2, "2026-09-01T10:21:00", "New-InboxRule"))
    ]);
    fixtures::write(
        &out,
        "UnifiedAuditLog/20260910-100000/UAL-20260901000000-20260902000000.json",
        ps_json(&many).as_bytes(),
    );
    // A window with one record: ConvertTo-Json writes a bare object.
    fixtures::write(
        &out,
        "UnifiedAuditLog/20260910-100000/UAL-20260902000000-20260903000000.json",
        ps_json(&json_record(&audit(
            ID_3,
            "2026-09-02T10:00:00",
            "Set-Mailbox",
        )))
        .as_bytes(),
    );
    let (case, _report) = ingest(dir.path());
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE data_completeness = 'full'"
        ),
        3
    );
    assert_eq!(
        text(
            &case,
            &format!("SELECT operation FROM ual_events WHERE record_id = '{ID_2}'")
        ),
        "New-InboxRule"
    );
}

#[test]
fn jsonl_window_keeps_audit_data_strings() {
    let dir = tempfile::tempdir().unwrap();
    let line = |a: &Value| {
        let mut r = json_record(a);
        r["AuditData"] = Value::String(a.to_string());
        format!("{r}\r\n")
    };
    let body = format!(
        "{}{}",
        line(&audit(ID_1, "2026-09-01T10:20:00", "Set-Mailbox")),
        line(&audit(ID_2, "2026-09-01T10:21:00", "New-InboxRule"))
    );
    let rel = "UnifiedAuditLog/20260910-100000/UAL-20260901000000-20260902000000.jsonl";
    fixtures::write(&dir.path().join("OUT"), rel, body.as_bytes());
    let (case, report) = ingest(dir.path());
    assert_eq!(row(&report, rel).records_loaded, 2);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE data_completeness = 'full'"
        ),
        2
    );
    assert_eq!(
        count(
            &case,
            &format!("SELECT line_start FROM record_sources WHERE record_key = '{ID_2}'")
        ),
        2
    );
}

#[test]
fn sof_elk_audit_data_lines_load_full() {
    let dir = tempfile::tempdir().unwrap();
    // SOF-ELK: one compressed AuditData object per line, then a blank line.
    let body = format!(
        "{}\r\n{}\r\n\r\n",
        audit(ID_1, "2026-09-01T10:20:00", "Set-Mailbox"),
        audit(ID_2, "2026-09-01T10:21:00", "New-InboxRule")
    );
    let rel = "UnifiedAuditLog/20260910-100000/UAL-20260901000000-20260902000000.json";
    fixtures::write(&dir.path().join("OUT"), rel, body.as_bytes());
    let (case, report) = ingest(dir.path());
    let f = row(&report, rel);
    assert_eq!((f.records_read, f.records_error), (2, 0), "{f:#?}");
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE data_completeness = 'full'"
        ),
        2
    );
}

#[test]
fn audit_data_only_csv_is_partial() {
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "{}{}",
        csv_line(&[
            "CreationTime",
            "Id",
            "Operation",
            "RecordType",
            "UserId",
            "Workload",
            "ClientIP",
            "Parameters"
        ]),
        csv_line(&[
            "2026-09-01T10:20:00",
            ID_1,
            "Set-Mailbox",
            "1",
            ALICE,
            "Exchange",
            "203.0.113.10",
            "System.Object[]"
        ])
    );
    let rel = "UnifiedAuditLog/20260910-100000/UAL-20260901000000-20260902000000.csv";
    fixtures::write(&dir.path().join("OUT"), rel, body.as_bytes());
    let (case, _report) = ingest(dir.path());
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT CAST(data_completeness AS VARCHAR) FROM ual_events WHERE record_id = '{ID_1}'"
            )
        ),
        "partial"
    );
}

#[test]
fn nested_mailbox_audit_log_window_loads() {
    let dir = tempfile::tempdir().unwrap();
    let rel = "Mailbox Audit Log/20260910-100500/UnifiedAuditLog/20260910-100501/UAL-20260901000000-20260902000000.csv";
    let body = format!(
        "{}{}",
        csv_line(RAW_HEADER),
        raw_row(&audit(ID_3, "2026-09-01T11:00:00", "HardDelete"))
    );
    fixtures::write(&dir.path().join("OUT"), rel, &utf8_bom(&body));
    let (case, report) = ingest(dir.path());
    assert_eq!(
        row(&report, rel).artifact_id.as_deref(),
        Some("inv.ual.window")
    );
    assert_eq!(
        count(
            &case,
            &format!("SELECT count(*) FROM ual_events WHERE record_id = '{ID_3}'")
        ),
        1
    );
}

#[test]
fn merged_combined_csv_adds_nothing_next_to_its_windows() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    let body = format!(
        "{}{}",
        csv_line(RAW_HEADER),
        raw_row(&audit(ID_1, "2026-09-01T10:20:00", "Set-Mailbox"))
    );
    fixtures::write(
        &out,
        "UnifiedAuditLog/20260910-100000/UAL-20260901000000-20260902000000.csv",
        &utf8_bom(&body),
    );
    fixtures::write(
        &out,
        "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv",
        &utf8_bom(&body),
    );
    let (case, report) = ingest(dir.path());
    assert_eq!(
        row(
            &report,
            "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv"
        )
        .status,
        FileStatus::SkippedSuperseded
    );
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 1);
}

#[test]
fn merged_combined_alone_loads_full_records() {
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "{}{}",
        csv_line(RAW_HEADER),
        raw_row(&audit(ID_1, "2026-09-01T10:20:00", "Set-Mailbox"))
    );
    fixtures::write(
        &dir.path().join("OUT"),
        "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv",
        &utf8_bom(&body),
    );
    let (case, _report) = ingest(dir.path());
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE data_completeness = 'full'"
        ),
        1
    );
}

#[test]
fn full_window_file_warns_of_truncation() {
    let w = truncation_warning("inv.ual.window", 5_000).expect("warning");
    assert!(w.contains("5000"), "{w}");
    assert_eq!(truncation_warning("inv.ual.window", 4_999), None);
    assert_eq!(truncation_warning("inv.ual.merged", 5_000), None);
}

#[test]
fn merged_combined_is_parsed_when_a_sibling_window_fails() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    let good = raw_row(&audit(ID_1, "2026-09-01T10:20:00", "Set-Mailbox"));
    let lost = raw_row(&audit(ID_2, "2026-09-01T10:21:00", "New-InboxRule"));
    let good_window = "UnifiedAuditLog/20260910-100000/UAL-20260901000000-20260902000000.csv";
    let bad_window = "UnifiedAuditLog/20260910-100000/UAL-20260902000000-20260903000000.csv";
    let merged = "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv";
    fixtures::write(
        &out,
        good_window,
        &utf8_bom(&format!("{}{good}", csv_line(RAW_HEADER))),
    );
    // Every record of this window is unreadable: its AuditData is not JSON.
    let broken = csv_line(&[
        "ExchangeAdmin",
        "9/2/2026 10:21:00 AM",
        ALICE,
        "New-InboxRule",
        "{not json",
        "1",
        "1",
        "",
        ID_2,
        "True",
        "Unchanged",
    ]);
    fixtures::write(
        &out,
        bad_window,
        &utf8_bom(&format!("{}{broken}", csv_line(RAW_HEADER))),
    );
    fixtures::write(
        &out,
        merged,
        &utf8_bom(&format!("{}{good}{lost}", csv_line(RAW_HEADER))),
    );
    let (case, report) = ingest(dir.path());
    assert_eq!(row(&report, good_window).records_loaded, 1);
    let bad = row(&report, bad_window);
    assert_eq!(bad.records_loaded + bad.records_duplicate, 0, "{bad:?}");
    let m = row(&report, merged);
    assert_eq!(m.status, FileStatus::Parsed, "{m:?}");
    assert_eq!((m.records_loaded, m.records_duplicate), (1, 1), "{m:?}");
    assert_eq!(
        count(
            &case,
            &format!("SELECT count(*) FROM ual_events WHERE record_id = '{ID_2}'")
        ),
        1
    );
}

/// A copy the supersede rules skip is hashed without being read whole: its stored sha256 is still the whole file's
/// (a re-ingest then reports it as already ingested), and a blank copy keeps its empty-file warning.
#[test]
fn a_skipped_merged_copy_keeps_its_whole_file_hash_and_blank_warning() {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    let mut body = csv_line(RAW_HEADER);
    let rec_row = raw_row(&audit(ID_1, "2026-09-01T10:20:00", "Set-Mailbox"));
    body.push_str(&rec_row);
    fixtures::write(
        &out,
        "UnifiedAuditLog/20260910-100000/UAL-20260901000000-20260902000000.csv",
        &utf8_bom(&body),
    );
    // Bigger than one 1 MiB read: the same row many times (all duplicates of the window's record).
    let mut merged = body.clone();
    while merged.len() < 3 * 1024 * 1024 {
        merged.push_str(&rec_row);
    }
    let merged = utf8_bom(&merged);
    fixtures::write(
        &out,
        "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv",
        &merged,
    );
    // A blank merged copy in a second run folder.
    fixtures::write(
        &out,
        "UnifiedAuditLog/20260911-100000/UAL-20260901000000-20260902000000.csv",
        &utf8_bom(&body),
    );
    fixtures::write(
        &out,
        "UnifiedAuditLog/20260911-100000/Merged/UAL-Combined.csv",
        b"\xEF\xBB\xBF\r\n",
    );
    let mut case = Case::in_memory().unwrap();
    let ingest_once = |case: &mut Case| {
        ingest_path(
            case,
            dir.path(),
            &ParserRegistry::builtin(),
            &IngestOptions::default(),
        )
        .unwrap()
    };
    let report = ingest_once(&mut case);
    let big = row(
        &report,
        "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv",
    );
    assert_eq!(big.status, FileStatus::SkippedSuperseded);
    let stored = text(
        &case,
        "SELECT sha256 FROM source_files WHERE rel_path = 'UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv'",
    );
    assert_eq!(stored, hex::encode(Sha256::digest(&merged)));
    let blank = row(
        &report,
        "UnifiedAuditLog/20260911-100000/Merged/UAL-Combined.csv",
    );
    assert_eq!(blank.status, FileStatus::SkippedSuperseded);
    assert!(
        blank
            .warnings
            .iter()
            .any(|w| w == sparrow_core::ingest::EMPTY_FILE_WARNING),
        "{:?}",
        blank.warnings
    );
    // Re-ingest: the same content is recognised by its stored hash.
    let again = ingest_once(&mut case);
    let big = row(
        &again,
        "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv",
    );
    assert_eq!(big.status, FileStatus::DuplicateFile);
    assert_eq!(big.warnings, ["already ingested"]);
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 1);
}
