use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::readers::time::DateOrder;
use std::path::{Path, PathBuf};

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

fn rows<'r>(report: &'r IngestReport, rel: &str) -> Vec<&'r FileReport> {
    report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .filter(|f| f.rel_path == rel)
        .collect()
}

fn row<'r>(report: &'r IngestReport, rel: &str) -> &'r FileReport {
    let found = rows(report, rel);
    assert_eq!(found.len(), 1, "{rel}: {found:#?}");
    found[0]
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

const USERS: &str = "Tenant/AzureADUsers.csv";

/// Hawk 3 user list whose only date (9/2) is ambiguous. Sorts before the evidence files.
fn ambiguous_users(root: &Path) {
    let csv = csv_line(&[
        "UserPrincipalname",
        "ObjectID",
        "UserType",
        "DateCreated",
        "UserStateChangedOn",
        "DirSyncEnabled",
    ]) + &csv_line(&[
        "alice@contoso.example",
        "11111111-1111-4111-8111-111111111111",
        "Member",
        "9/2/2026 8:00:00 AM",
        "",
        "",
    ]);
    fixtures::write(root, USERS, &fixtures::utf8_bom(&csv));
}

/// Hawk 3 eDiscovery summary: 9/15 proves month-first.
fn month_first_evidence(root: &Path) {
    let csv = csv_line(&[
        "CreationTime",
        "Id",
        "Operation",
        "Workload",
        "UserId",
        "Case",
        "CaseID",
        "Cmdlet",
    ]) + &csv_line(&[
        "9/15/2026 8:30:00 AM",
        "e2e2e2e2-0000-4000-8000-000000000002",
        "SearchExported",
        "SecurityComplianceCenter",
        "admin@contoso.example",
        "Case 1",
        "e1e1e1e1-0000-4000-8000-000000000001",
        "New-ComplianceSearchAction",
    ]);
    fixtures::write(root, "Tenant/eDiscoveryLogs.csv", &fixtures::utf8_bom(&csv));
}

/// Hawk 3 expanded UAL CSV in a user folder: 15/09 proves day-first.
fn day_first_evidence(root: &Path) {
    let csv = csv_line(&[
        "CreationTime",
        "Id",
        "Operation",
        "RecordType",
        "UserId",
        "Workload",
    ]) + &csv_line(&[
        "15/09/2026 08:30:00",
        "e3e3e3e3-0000-4000-8000-000000000003",
        "Update",
        "2",
        "bob@contoso.example",
        "Exchange",
    ]);
    fixtures::write(
        root,
        "bob@contoso.example/Exchange_UAL_Audit_bob@contoso.example.csv",
        &fixtures::utf8_bom(&csv),
    );
}

#[test]
fn ambiguous_file_uses_the_order_of_its_collection() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    ambiguous_users(&root);
    month_first_evidence(&root);
    let (case, report) = ingest(dir.path(), None);
    assert!(!report.has_errors(), "{report:#?}");
    let f = row(&report, USERS);
    assert_eq!((f.status, f.records_loaded), (FileStatus::Parsed, 1));
    assert!(
        f.warnings
            .iter()
            .any(|w| w.contains("month-first") && w.contains("other files of this collection")),
        "{:?}",
        f.warnings
    );
    assert_eq!(
        count(&case, "SELECT epoch(created)::BIGINT FROM users"),
        1788336000
    );
    // Hawk.log's ambiguous collection window (6/12 - 9/11) is read the same way.
    assert_eq!(
        count(&case, "SELECT epoch(window_start)::BIGINT FROM collections"),
        1781222400
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM source_files WHERE rel_path = 'Tenant/AzureADUsers.csv'"
        ),
        1
    );
}

#[test]
fn conflicting_orders_in_a_collection_still_fail() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    ambiguous_users(&root);
    month_first_evidence(&root);
    day_first_evidence(&root);
    let (_case, report) = ingest(dir.path(), None);
    let f = row(&report, USERS);
    assert_eq!(f.status, FileStatus::Error);
    assert!(
        f.warnings.iter().any(|w| w.contains("--culture")
            && w.contains("other files of this collection show both orders")),
        "{:?}",
        f.warnings
    );
}

#[test]
fn order_proved_by_an_earlier_run_resolves_a_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    month_first_evidence(&root);
    let mut case = Case::in_memory().unwrap();
    let opts = IngestOptions::default();
    let first = ingest_path(&mut case, dir.path(), &ParserRegistry::builtin(), &opts).unwrap();
    assert!(!first.has_errors(), "{first:#?}");
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM source_files WHERE rel_path = 'Tenant/eDiscoveryLogs.csv' AND date_order = 'month_first'"
        ),
        1
    );
    ambiguous_users(&root);
    let second = ingest_path(&mut case, dir.path(), &ParserRegistry::builtin(), &opts).unwrap();
    let f = row(&second, USERS);
    assert_eq!((f.status, f.records_loaded), (FileStatus::Parsed, 1));
    assert!(
        f.warnings
            .iter()
            .any(|w| w.contains("month-first") && w.contains("other files of this collection")),
        "{:?}",
        f.warnings
    );
    assert_eq!(
        count(&case, "SELECT epoch(created)::BIGINT FROM users"),
        1788336000
    );
}

#[test]
fn ambiguous_file_without_evidence_fails_naming_culture() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    ambiguous_users(&root);
    let (_case, report) = ingest(dir.path(), None);
    let f = row(&report, USERS);
    assert_eq!(f.status, FileStatus::Error);
    assert!(
        f.warnings.iter().any(|w| w.contains("--culture")),
        "{:?}",
        f.warnings
    );
}

#[test]
fn culture_flag_needs_no_second_pass() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    ambiguous_users(&root);
    let (case, report) = ingest(dir.path(), Some(DateOrder::MonthFirst));
    let f = row(&report, USERS);
    assert_eq!(f.status, FileStatus::Parsed);
    assert!(
        !f.warnings.iter().any(|w| w.contains("other files")),
        "{:?}",
        f.warnings
    );
    assert_eq!(
        count(&case, "SELECT epoch(created)::BIGINT FROM users"),
        1788336000
    );
}

#[test]
fn investigate_txt_uses_the_collection_order() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    month_first_evidence(&root);
    fixtures::write(
        &root,
        "_Investigate.txt",
        b"[9/2/2026 8:00:00 AM] - ## Inbox Rules ## - Found a forwarding rule\r\n",
    );
    let (case, report) = ingest(dir.path(), None);
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        count(
            &case,
            "SELECT epoch(flag_time)::BIGINT FROM collector_flags WHERE flag_type = 'investigate_note'"
        ),
        1788336000
    );
}

#[test]
fn raw_files_retried_for_their_dates_still_supersede_derived_ones() {
    // Get-UAL -Output CSV -AuditDataOnly on PowerShell 7 writes CreationTime in the host
    // culture. A window whose dates are all ambiguous waits for the order the collection
    // proves; the run's derived Merged copy (which holds a decisive date from another window)
    // must still be superseded by the windows (spec §6), not parsed before the retried one.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("Output");
    let header = csv_line(&[
        "CreationTime",
        "Id",
        "Operation",
        "RecordType",
        "UserId",
        "Workload",
    ]);
    let record = |time: &str, id: &str| {
        csv_line(&[time, id, "Update", "2", "alice@contoso.example", "Exchange"])
    };
    let r1 = record(
        "8/9/2026 10:00:00 AM",
        "e4e4e4e4-0000-4000-8000-000000000004",
    );
    let r2 = record(
        "8/15/2026 10:00:00 AM",
        "e5e5e5e5-0000-4000-8000-000000000005",
    );
    let run = "UnifiedAuditLog/20260910-100000";
    let ambiguous = format!("{run}/UAL-20260809000000-20260810000000.csv");
    let decisive = format!("{run}/UAL-20260815000000-20260816000000.csv");
    let merged = format!("{run}/Merged/UAL-Combined.csv");
    fixtures::write(&root, &ambiguous, format!("{header}{r1}").as_bytes());
    fixtures::write(&root, &decisive, format!("{header}{r2}").as_bytes());
    fixtures::write(&root, &merged, format!("{header}{r1}{r2}").as_bytes());
    let (case, report) = ingest(dir.path(), None);
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(row(&report, &ambiguous).status, FileStatus::Parsed);
    assert_eq!(row(&report, &decisive).status, FileStatus::Parsed);
    assert_eq!(row(&report, &merged).status, FileStatus::SkippedSuperseded);
    assert_eq!(
        count(
            &case,
            "SELECT min(epoch(event_time)::BIGINT) FROM ual_events"
        ),
        1_786_269_600
    );
}

#[test]
fn a_raw_file_can_take_its_order_from_a_derived_file() {
    // Only the derived Get-Sessions export (8/15) proves month-first; the raw window (8/9) is
    // retried after the derived stage with that order instead of failing.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("Output");
    let window = "UnifiedAuditLog/20260910-100000/UAL-20260809000000-20260810000000.csv";
    fixtures::write(
        &root,
        window,
        (csv_line(&[
            "CreationTime",
            "Id",
            "Operation",
            "RecordType",
            "UserId",
            "Workload",
        ]) + &csv_line(&[
            "8/9/2026 10:00:00 AM",
            "e6e6e6e6-0000-4000-8000-000000000006",
            "Update",
            "2",
            "alice@contoso.example",
            "Exchange",
        ]))
            .as_bytes(),
    );
    let sessions = "MailItemsAccessed/20260910-100700/20260910-100700-Sessions.csv";
    fixtures::write(
        &root,
        sessions,
        (csv_line(&[
            "TimeStamp",
            "User",
            "Action",
            "SessionId",
            "ClientIP",
            "MailAccessType",
            "IsThrottled",
            "OperationCount",
        ]) + &csv_line(&[
            "8/15/2026 10:05:00 AM",
            "alice@contoso.example",
            "MailItemsAccessed",
            "",
            "2001:db8::10",
            "Bind",
            "",
            "1",
        ]))
            .as_bytes(),
    );
    let (case, report) = ingest(dir.path(), None);
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(row(&report, window).status, FileStatus::Parsed);
    assert_eq!(row(&report, sessions).status, FileStatus::Parsed);
    assert_eq!(
        count(
            &case,
            "SELECT epoch(event_time)::BIGINT FROM ual_events WHERE operation = 'Update'"
        ),
        1_786_269_600
    );
}

#[test]
fn one_ual_file_whose_order_is_proved_only_by_its_last_row() {
    // The UAL parser reads a file twice (the date order first, then the records): rows before the deciding date
    // must be normalized with the order a later row proves, keep their own lines, and load once each.
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = "bob@contoso.example/Exchange_UAL_Audit_bob@contoso.example.csv";
    let header = csv_line(&[
        "CreationTime",
        "Id",
        "Operation",
        "RecordType",
        "UserId",
        "Workload",
    ]);
    let record = |time: &str, id: &str| {
        csv_line(&[time, id, "Update", "2", "bob@contoso.example", "Exchange"])
    };
    let csv = header
        + &record(
            "03/09/2026 08:30:00",
            "e6e6e6e6-0000-4000-8000-000000000001",
        )
        + &record(
            "04/09/2026 09:00:00",
            "e6e6e6e6-0000-4000-8000-000000000002",
        )
        + &record(
            "15/09/2026 08:30:00",
            "e6e6e6e6-0000-4000-8000-000000000003",
        );
    fixtures::write(&root, rel, &fixtures::utf8_bom(&csv));
    let (case, report) = ingest(dir.path(), None);
    let file = row(&report, rel);
    assert_eq!(file.status, FileStatus::Parsed, "{file:#?}");
    assert_eq!(
        (
            file.records_read,
            file.records_loaded,
            file.records_duplicate,
            file.records_error
        ),
        (3, 3, 0, 0)
    );
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT epoch(e.event_time)::BIGINT, s.line_start FROM ual_events e
             JOIN record_sources s ON s.table_name = 'ual_events' AND s.record_key = e.record_id::VARCHAR
             ORDER BY s.line_start",
        )
        .unwrap();
    let got: Vec<(i64, i64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    // Day first: 3 and 4 September, not 9 March and 9 April.
    assert_eq!(
        got,
        vec![(1_788_424_200, 2), (1_788_512_400, 3), (1_789_461_000, 4)]
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM source_files WHERE rel_path = '{rel}' AND date_order = 'day_first'"
            )
        ),
        1
    );
}
