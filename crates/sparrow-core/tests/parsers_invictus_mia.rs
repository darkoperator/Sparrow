use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line, utf8_bom};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, IngestOptions, IngestReport, ingest_path};
use sparrow_core::verify::verify_record;
use std::path::Path;

const ALICE: &str = "alice@contoso.example";
const R1: &str = "44444444-4444-4444-8444-444444444444";
const R2: &str = "55555555-5555-4555-8555-555555555555";
const IP: &str = "2001:db8::10";
const UAL: &str = "UnifiedAuditLog/20260910-100000/UAL-20260801000000-20260901000000.csv";
const SESSIONS: &str = "MailItemsAccessed/20260910-100700/20260910-100700-Sessions.csv";
const MESSAGE_IDS: &str = "MailItemsAccessed/20260910-100800/20260910-100800-MessageIDs.csv";
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

fn mia(id: &str, count: i64, items: &[(&str, i64)]) -> Value {
    let items: Vec<Value> = items
        .iter()
        .map(|(m, s)| json!({"InternetMessageId": m, "SizeInBytes": s}))
        .collect();
    json!({
        "CreationTime": "2026-08-20T10:00:00", "Id": id, "Operation": "MailItemsAccessed",
        "OrganizationId": "0e0e0e0e-0000-4000-8000-00000000000a", "RecordType": 50,
        "ResultStatus": "Succeeded", "UserKey": "1003200000000001", "UserType": 0, "Version": 1,
        "Workload": "Exchange", "UserId": ALICE, "ClientIPAddress": IP, "ClientInfoString": "Client=OWA",
        "MailboxOwnerUPN": ALICE, "OperationCount": count,
        "OperationProperties": [{"Name": "MailAccessType", "Value": "Bind"}],
        "Folders": [{"Path": "\\Inbox", "FolderItems": items}]
    })
}

/// A raw UAL window holding two MailItemsAccessed records in the same second from the same
/// IP, told apart only by OperationCount (as in the real sample).
fn raw_ual() -> Vec<u8> {
    let row = |a: &Value| {
        csv_line(&[
            "ExchangeItemAggregated",
            "8/20/2026 10:00:00 AM",
            ALICE,
            "MailItemsAccessed",
            &a.to_string(),
            "1",
            "2",
            "{\n  \"moreRecordsAvailable\": false\n}",
            a["Id"].as_str().unwrap(),
            "True",
            "Unchanged",
        ])
    };
    utf8_bom(&format!(
        "{}{}{}",
        csv_line(RAW_HEADER),
        row(&mia(
            R1,
            2,
            &[
                ("<i1@contoso.example>", 1000),
                ("<i2@contoso.example>", 2000)
            ]
        )),
        row(&mia(R2, 1, &[("<i3@contoso.example>", 3000)]))
    ))
}

const SESSIONS_HEADER: &str = "\"TimeStamp\",\"User\",\"Action\",\"SessionId\",\"ClientIP\",\"MailAccessType\",\"IsThrottled\",\"OperationCount\"\r\n";

/// Get-Sessions rows (PS7: culture-formatted UTC time, empty fields unquoted).
fn sessions(rows: &[(&str, &str)]) -> Vec<u8> {
    let mut s = SESSIONS_HEADER.to_string();
    for (time, count) in rows {
        s.push_str(&format!(
            "\"{time}\",\"{ALICE}\",\"MailItemsAccessed\",,\"{IP}\",\"Bind\",,\"{count}\"\r\n"
        ));
    }
    utf8_bom(&s)
}

const IDS_HEADER: &str = "\"Timestamp\",\"User\",\"IPaddress\",\"SessionID\",\"MailAccessType\",\"FolderPath\",\"InternetMessageId\",\"SizeInBytes\"\r\n";

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

#[test]
fn sessions_rows_matching_raw_records_add_sightings() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    fixtures::write(&out, UAL, &raw_ual());
    fixtures::write(
        &out,
        SESSIONS,
        &sessions(&[
            ("8/20/2026 10:00:00 AM", "1"), // R2 (listed first: order must not matter)
            ("8/20/2026 10:00:00 AM", "2"), // R1
            ("8/20/2026 10:05:00 AM", "1"), // no raw record
        ]),
    );
    let (case, report) = ingest(dir.path());
    let f = row(&report, SESSIONS);
    assert_eq!(f.artifact_id.as_deref(), Some("inv.mia.sessions"));
    assert_eq!(
        (
            f.records_read,
            f.records_loaded,
            f.records_duplicate,
            f.records_error
        ),
        (3, 1, 2, 0),
        "{f:#?}"
    );
    for (id, line) in [(R1, 3), (R2, 2)] {
        assert_eq!(
            count(
                &case,
                &format!(
                    "SELECT rs.line_start FROM record_sources rs JOIN source_files sf USING (file_id)
                     WHERE rs.table_name = 'ual_events' AND rs.record_key = '{id}'
                       AND sf.artifact_type = 'inv.mia.sessions'"
                )
            ),
            line,
            "{id}"
        );
        assert!(verify_record(&case, "ual_events", id, None).unwrap().ok);
    }
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE operation = 'MailItemsAccessed'
               AND data_completeness = 'partial' AND synthetic_id
               AND epoch(event_time)::BIGINT = 1787220300 AND user_upn = 'alice@contoso.example'
               AND client_ip = '2001:db8::10'
               AND json_extract_string(audit_data, '$.SparrowDerivedFrom') IS NOT NULL"
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mail_items_accessed m JOIN ual_events e USING (record_id)
               WHERE e.data_completeness = 'partial' AND m.access_type = 'bind' AND m.operation_count = 1"
        ),
        1
    );
}

#[test]
fn a_second_sessions_file_with_the_same_rows_adds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    fixtures::write(&out, SESSIONS, &sessions(&[("8/20/2026 10:05:00 AM", "1")]));
    // The same row in another order and file (a later run) is the same synthetic record.
    fixtures::write(
        &out,
        "MailItemsAccessed/20260910-110700/20260910-110700-Sessions.csv",
        &sessions(&[
            ("8/20/2026 10:05:00 AM", "1"),
            ("8/21/2026 9:30:00 AM", "4"),
        ]),
    );
    let (case, _report) = ingest(dir.path());
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 2);
}

#[test]
fn message_ids_rows_matching_raw_items_add_sightings() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    fixtures::write(&out, UAL, &raw_ual());
    let mut body = IDS_HEADER.to_string();
    body.push_str(&format!(
        "\"8/20/2026 10:00:00 AM\",\"{ALICE}\",\"{IP}\",,\"Bind\",,\"<i1@contoso.example>\",\"1000\"\r\n"
    ));
    body.push_str(&format!(
        "\"8/20/2026 10:00:00 AM\",\"{ALICE}\",\"{IP}\",,\"Bind\",,\"<i3@contoso.example>\",\"3000\"\r\n"
    ));
    body.push_str(&format!(
        "\"8/20/2026 10:05:00 AM\",\"{ALICE}\",\"{IP}\",,\"Bind\",,\"<i9@contoso.example>\",\r\n"
    ));
    body.push_str(&format!(
        "\"8/20/2026 10:05:00 AM\",\"{ALICE}\",\"{IP}\",,\"Sync\",\"\\Archive\",\"N/A (Sync - entire folder)\",\r\n"
    ));
    fixtures::write(&out, MESSAGE_IDS, &utf8_bom(&body));
    let (case, report) = ingest(dir.path());
    let f = row(&report, MESSAGE_IDS);
    assert_eq!(f.artifact_id.as_deref(), Some("inv.mia.message_ids"));
    assert_eq!(
        (
            f.records_read,
            f.records_loaded,
            f.records_duplicate,
            f.records_error
        ),
        (4, 2, 2, 0),
        "{f:#?}"
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM record_sources rs JOIN source_files sf USING (file_id)
                 WHERE rs.table_name = 'ual_events' AND rs.record_key IN ('{R1}', '{R2}')
                   AND sf.artifact_type = 'inv.mia.message_ids'"
            )
        ),
        2
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mail_items_accessed WHERE record_id IS NULL AND item_key IS NOT NULL
               AND user_upn = 'alice@contoso.example' AND client_ip = '2001:db8::10'
               AND epoch(event_time)::BIGINT = 1787220300 AND time_tz_assumed"
        ),
        2
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mail_items_accessed WHERE record_id IS NULL
               AND access_type = 'sync' AND folder_path = '\\Archive' AND internet_message_id IS NULL"
        ),
        1
    );
    let key: String = case
        .conn()
        .query_row(
            "SELECT item_key FROM mail_items_accessed WHERE internet_message_id = '<i9@contoso.example>'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        verify_record(&case, "mail_items_accessed", &key, None)
            .unwrap()
            .ok
    );
    // Raw children are untouched: 3 items + 2 parent-less rows.
    assert_eq!(count(&case, "SELECT count(*) FROM mail_items_accessed"), 5);
}

#[test]
fn iso_sessions_times_load() {
    let dir = tempfile::tempdir().unwrap();
    // Windows PowerShell 5.1 keeps CreationTime as ISO text.
    fixtures::write(
        &dir.path().join("OUT"),
        SESSIONS,
        &sessions(&[("2026-08-20T10:05:00", "1")]),
    );
    let (case, _report) = ingest(dir.path());
    assert_eq!(
        count(
            &case,
            "SELECT epoch(event_time)::BIGINT FROM ual_events WHERE operation = 'MailItemsAccessed'"
        ),
        1_787_220_300
    );
}

#[test]
fn ambiguous_sessions_use_the_collection_order() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    // 8/9 could be either order; the message trace file proves month-first (8/15).
    fixtures::write(&out, SESSIONS, &sessions(&[("8/9/2026 10:00:00 AM", "1")]));
    fixtures::write(
        &out,
        "MessageTrace/20260910-100600/20260910-100600-MessageTrace.csv",
        format!(
            "{}{}",
            csv_line(&[
                "MessageTraceId",
                "MessageId",
                "Received",
                "SenderAddress",
                "RecipientAddress",
                "FromIP",
                "ToIP",
                "Subject",
                "Status",
                "Size"
            ]),
            csv_line(&[
                "0e0e0e0e-0000-4000-8000-000000000011",
                "<m1@contoso.example>",
                "8/15/2026 2:00:00 PM",
                "mallory@fabrikam.example",
                ALICE,
                "198.51.100.7",
                "",
                "Invoice",
                "Delivered",
                "2048"
            ])
        )
        .as_bytes(),
    );
    let (case, report) = ingest(dir.path());
    let f = row(&report, SESSIONS);
    assert!(
        f.warnings
            .iter()
            .any(|w| w.contains("other files of this collection")),
        "{:?}",
        f.warnings
    );
    // 2026-08-09T10:00:00Z
    assert_eq!(
        count(
            &case,
            "SELECT epoch(event_time)::BIGINT FROM ual_events WHERE operation = 'MailItemsAccessed'"
        ),
        1_786_269_600
    );
}

#[test]
fn files_without_session_columns_are_not_supported() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::write(
        &dir.path().join("OUT"),
        SESSIONS,
        b"\"Name\",\"Value\"\r\n\"a\",\"b\"\r\n",
    );
    let (_case, report) = ingest(dir.path());
    assert_eq!(
        row(&report, SESSIONS).status,
        sparrow_core::ingest::FileStatus::NotSupported
    );
}
