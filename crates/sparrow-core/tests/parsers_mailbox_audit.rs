use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use std::path::{Path, PathBuf};

const BOB: &str = "bob@contoso.example";

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

fn hard_delete() -> Value {
    json!({
        "Operation": "HardDelete", "OperationResult": "Succeeded", "LogonType": "Owner",
        "ExternalAccess": false, "FolderPathName": "\\Deleted Items",
        "ClientInfoString": "Client=OWA;Mozilla/5.0", "ClientIPAddress": "203.0.113.10",
        "ClientIP": "203.0.113.10:51000", "MailboxOwnerUPN": "Bob@contoso.example",
        "MailboxGuid": "99999999-9999-4999-8999-999999999999", "LogonUserDisplayName": "Bob",
        "LogonUserSid": "S-1-5-21-1-2-3-1001",
        "SourceItems": [{"Id": "RgAAAA1", "Subject": "Invoice 42",
                         "InternetMessageId": "<m1@fabrikam.example>", "FolderPathName": "\\Inbox"}],
        "ItemSubject": null, "SessionId": "s-1", "LastAccessed": "/Date(1788426000000)/",
        "Identity": {"x": 1}, "IsValid": true, "ObjectState": "Unchanged"
    })
}

fn send_as() -> Value {
    json!({
        "Operation": "SendAs", "OperationResult": "Succeeded", "LogonType": "Delegate",
        "ClientIPAddress": "198.51.100.7", "MailboxOwnerUPN": "Bob@contoso.example",
        "MailboxGuid": "99999999-9999-4999-8999-999999999999", "LogonUserDisplayName": "Mallory",
        "LogonUserSid": "S-1-5-21-1-2-3-1002", "ItemSubject": "Updated bank details",
        "ItemInternetMessageId": "<m2@contoso.example>", "SessionId": "s-2",
        "LastAccessed": "/Date(1788426060000)/"
    })
}

fn json_rel() -> String {
    format!("{BOB}/Exchange_Mailbox_Audit_{BOB}.json")
}

fn write_json(root: &Path, records: &[Value]) {
    fixtures::write(
        root,
        &json_rel(),
        &fixtures::utf16le_bom(&fixtures::ps51_dates(&fixtures::ps_json(&json!(records)))),
    );
}

#[test]
fn mailbox_audit_records_load_with_items_and_client() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    write_json(&root, &[hard_delete(), send_as(), hard_delete()]);
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let f = row(&report, &json_rel());
    assert_eq!((f.records_loaded, f.records_duplicate), (2, 1));
    assert_eq!(
        text(
            &case,
            "SELECT mailbox_upn || '|' || mailbox_guid || '|' || operation_result || '|' || logon_type || '|' ||
                    logon_user || '|' || client_ip || '|' || client_info || '|' || folder_path || '|' ||
                    array_to_string(subjects, ',') || '|' || array_to_string(internet_message_ids, ',') || '|' ||
                    external_access || '|' || time_tz_assumed || '|' || epoch(event_time)::BIGINT
             FROM mailbox_audit_legacy WHERE operation = 'HardDelete'"
        ),
        "bob@contoso.example|99999999-9999-4999-8999-999999999999|Succeeded|Owner|Bob|203.0.113.10|Client=OWA;Mozilla/5.0|\\Deleted Items|Invoice 42|<m1@fabrikam.example>|false|false|1788426000"
    );
    assert_eq!(
        text(
            &case,
            "SELECT array_to_string(subjects, ',') || '|' || array_to_string(internet_message_ids, ',')
             FROM mailbox_audit_legacy WHERE operation = 'SendAs'"
        ),
        "Updated bank details|<m2@contoso.example>"
    );
}

#[test]
fn csv_twin_is_superseded_and_a_lone_csv_keeps_what_it_can() {
    let csv = csv_line(&[
        "Operation",
        "OperationResult",
        "LogonType",
        "ClientIPAddress",
        "MailboxOwnerUPN",
        "SourceItems",
        "LastAccessed",
    ]) + &csv_line(&[
        "HardDelete",
        "Succeeded",
        "Owner",
        "203.0.113.10",
        BOB,
        "System.Object[]",
        "9/14/2026 9:00:00 AM",
    ]);
    let csv_rel = format!("{BOB}/Exchange_Mailbox_Audit_{BOB}.csv");

    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    write_json(&root, &[hard_delete()]);
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
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mailbox_audit_legacy WHERE subjects IS NULL AND time_tz_assumed
               AND epoch(event_time)::BIGINT = 1789376400"
        ),
        1
    );
}

#[test]
fn mailbox_comes_from_the_folder_when_the_record_has_none() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    write_json(
        &root,
        &[
            json!({"Operation": "HardDelete", "LogonType": "Owner", "LastAccessed": "/Date(1788336000000)/"}),
        ],
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        text(&case, "SELECT mailbox_upn FROM mailbox_audit_legacy"),
        BOB
    );
}

#[test]
fn record_without_a_time_is_a_parse_error_and_other_shapes_are_not_supported() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let mut no_time = send_as();
    no_time["LastAccessed"] = Value::Null;
    write_json(&root, &[hard_delete(), no_time]);
    let (_case, report) = ingest(dir.path());
    let f = row(&report, &json_rel());
    assert_eq!((f.records_loaded, f.records_error), (1, 1));

    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    write_json(&root, &[json!({"Foo": 1})]);
    let (_case, report) = ingest(dir.path());
    assert_eq!(row(&report, &json_rel()).status, FileStatus::NotSupported);
}
