use serde_json::json;
use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use std::path::{Path, PathBuf};

const ALICE: &str = "alice@contoso.example";
const TRACE: &str = "0e0e0e0e-0000-4000-8000-000000000003";
const SUMMARY: &str = "MTSummary_Message trace report - _2026-09-10T141500.000Z__7c9e6679-7425-40de-944b-e07fc1f90ae7.csv";

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

fn hawk_trace(id: Option<&str>, recipient: &str) -> serde_json::Value {
    json!({
        "Organization": "contoso.onmicrosoft.com", "MessageId": "<m3@contoso.example>",
        "Received": "2026-09-01T10:20:00.1234567", "SenderAddress": "Alice@contoso.example",
        "RecipientAddress": recipient, "Subject": "Updated bank details", "Status": "Delivered",
        "ToIP": null, "FromIP": "203.0.113.10", "Size": 2048, "MessageTraceId": id,
        "StartDate": "2026-08-01T00:00:00.0000000Z", "EndDate": "2026-09-10T00:00:00.0000000Z",
        "Index": 0
    })
}

const SUMMARY_HEADER: &[&str] = &[
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

fn summary_row(recipients: &str) -> String {
    csv_line(&[
        "2026-09-01T10:20:00.0000000Z",
        ALICE,
        recipients,
        "Updated bank details",
        "2048",
        "<m3@contoso.example>",
        TRACE,
        "203.0.113.10",
        "Originating",
        "",
        "Normal",
    ])
}

#[test]
fn hawk_message_trace_loads_one_row_per_recipient_record() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = format!("{ALICE}/Message_Trace_{ALICE}.json");
    fixtures::write(
        &root,
        &rel,
        fixtures::ps_json(&json!([
            hawk_trace(Some(&TRACE.to_uppercase()), "X@fabrikam.example"),
            hawk_trace(Some(&TRACE.to_uppercase()), "y@fabrikam.example")
        ]))
        .as_bytes(),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(row(&report, &rel).records_loaded, 2);
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT sender || '|' || recipient || '|' || subject || '|' || status || '|' || from_ip || '|' ||
                        size_bytes || '|' || internet_message_id || '|' || organization || '|' || time_tz_assumed
                 FROM message_trace WHERE record_key = '{TRACE}|x@fabrikam.example'"
            )
        ),
        "alice@contoso.example|x@fabrikam.example|Updated bank details|Delivered|203.0.113.10|2048|<m3@contoso.example>|contoso.onmicrosoft.com|true"
    );
    assert_eq!(
        count(
            &case,
            "SELECT min(epoch(received)::BIGINT) FROM message_trace"
        ),
        1788258000
    );
}

#[test]
fn portal_and_hawk_copies_of_a_message_are_one_row() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let hawk = format!("{ALICE}/Message_Trace_{ALICE}.json");
    fixtures::write(
        &root,
        &hawk,
        fixtures::ps_json(&json!([hawk_trace(Some(TRACE), "x@fabrikam.example")])).as_bytes(),
    );
    let portal = format!("{ALICE}/{SUMMARY}");
    let text_csv = csv_line(SUMMARY_HEADER) + &summary_row("x@fabrikam.example##Delivered");
    fixtures::write(&root, &portal, &fixtures::utf16le_no_bom(&text_csv));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        row(&report, &portal).artifact_id.as_deref(),
        Some("portal.message_trace")
    );
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace"), 1);
    assert_eq!(
        text(
            &case,
            "SELECT direction || '|' || organization FROM message_trace"
        ),
        "Originating|contoso.onmicrosoft.com"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'message_trace'"
        ),
        2
    );
}

#[test]
fn portal_summary_rows_split_per_recipient() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("exports");
    let csv = csv_line(SUMMARY_HEADER)
        + &summary_row("a@fabrikam.example##Delivered;b@fabrikam.example##Failed");
    fixtures::write(&root, SUMMARY, &fixtures::utf16le_no_bom(&csv));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let f = row(&report, SUMMARY);
    assert_eq!((f.records_read, f.records_loaded), (2, 2));
    assert_eq!(
        text(
            &case,
            "SELECT string_agg(recipient || ':' || status, ',' ORDER BY recipient) FROM message_trace"
        ),
        "a@fabrikam.example:Delivered,b@fabrikam.example:Failed"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(DISTINCT line_start) FROM record_sources WHERE table_name = 'message_trace'"
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT epoch(received)::BIGINT FROM message_trace LIMIT 1"
        ),
        1788258000
    );
}

#[test]
fn windows_1252_summary_loads_with_a_lossy_warning() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("exports");
    let mut bytes = SUMMARY_HEADER.join(",").into_bytes();
    bytes.extend_from_slice(b"\r\n2026-09-01T10:20:00.0000000Z,alice@contoso.example,x@fabrikam.example##Delivered,Factur");
    bytes.push(0xE9);
    bytes.extend_from_slice(
        format!(",2048,<m3@contoso.example>,{TRACE},203.0.113.10,Originating,,Normal\r\n")
            .as_bytes(),
    );
    fixtures::write(&root, SUMMARY, &bytes);
    let (case, report) = ingest(dir.path());
    let f = row(&report, SUMMARY);
    assert_eq!(
        (f.status, f.records_loaded),
        (FileStatus::Parsed, 1),
        "{f:#?}"
    );
    assert!(
        f.warnings.iter().any(|w| w.contains("lossy")),
        "{:?}",
        f.warnings
    );
    assert_eq!(text(&case, "SELECT subject FROM message_trace"), "Facturé");
}

#[test]
fn trace_without_an_id_is_a_parse_error_and_other_shapes_are_not_supported() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = format!("{ALICE}/Message_Trace_{ALICE}.json");
    fixtures::write(
        &root,
        &rel,
        fixtures::ps_json(&json!([
            hawk_trace(Some(TRACE), "x@fabrikam.example"),
            hawk_trace(None, "y@fabrikam.example")
        ]))
        .as_bytes(),
    );
    let (_case, report) = ingest(dir.path());
    let f = row(&report, &rel);
    assert_eq!((f.records_loaded, f.records_error), (1, 1));

    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, &rel, br#"[{"Foo": 1}]"#);
    let (_case, report) = ingest(dir.path());
    assert_eq!(row(&report, &rel).status, FileStatus::NotSupported);
}
