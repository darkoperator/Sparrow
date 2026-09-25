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
        f.warnings.iter().any(|w| w.contains("--culture")),
        "{:?}",
        f.warnings
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
