use sparrow_core::Case;
use sparrow_core::discovery::Tool;
use sparrow_core::fixtures::invictus::*;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{
    EMPTY_FILE_WARNING, FileReport, FileStatus, IngestOptions, IngestReport, ingest_path,
};
use sparrow_core::verify::verify_record;
use std::path::Path;

fn ingest_into(case: &mut Case, path: &Path) -> IngestReport {
    ingest_path(
        case,
        path,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap()
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
fn invictus_sample_tree_loads_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    invictus_output_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_into(&mut case, dir.path());
    assert_eq!(report.collections.len(), 1);
    assert_eq!(report.collections[0].tool, Tool::Invictus);
    assert!(!report.has_errors(), "{report:#?}");

    // Statuses.
    for rel in [
        UAL_WINDOW,
        SIGNIN_PAGE,
        SP_PAGE,
        AUDIT_PAGE,
        STATUS_EARLY,
        STATUS_LATE,
        PERMS_1,
        TRACE_FILE_1,
        SESSIONS,
        MESSAGE_IDS,
        SECURITY_DEFAULTS,
        NESTED_UAL,
    ] {
        assert_eq!(row(&report, rel).status, FileStatus::Parsed, "{rel}");
    }
    assert_eq!(
        row(&report, UAL_MERGED).status,
        FileStatus::SkippedSuperseded
    );
    assert_eq!(row(&report, PERMS_2).status, FileStatus::DuplicateFile);
    assert_eq!(row(&report, TRACE_FILE_2).status, FileStatus::DuplicateFile);
    // Task 14 added the Users parser: a 0-byte export is parsed as "ran and found nothing".
    let f = row(&report, EMPTY_USERS);
    assert_eq!(f.status, FileStatus::Parsed, "{EMPTY_USERS}");
    assert_eq!(f.records_read, 0);
    assert!(
        f.warnings.iter().any(|w| w == EMPTY_FILE_WARNING),
        "{EMPTY_USERS}"
    );
    // Task 16 added the OAuthPermissions parser: a 0-byte export is parsed as "ran and found
    // nothing" too.
    let f = row(&report, EMPTY_OAUTH);
    assert_eq!(f.status, FileStatus::Parsed, "{EMPTY_OAUTH}");
    assert_eq!(f.records_read, 0);
    assert!(
        f.warnings.iter().any(|w| w == EMPTY_FILE_WARNING),
        "{EMPTY_OAUTH}"
    );
    // Every file reconciles.
    for f in report.collections.iter().flat_map(|c| &c.files) {
        assert_eq!(
            f.records_read,
            f.records_loaded + f.records_duplicate + f.records_error,
            "{}",
            f.rel_path
        );
    }

    // Rows.
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 5);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE data_completeness = 'partial'"
        ),
        1
    );
    assert_eq!(count(&case, "SELECT count(*) FROM signins"), 3);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM signins WHERE event_type = 'service_principal'"
        ),
        1
    );
    assert_eq!(count(&case, "SELECT count(*) FROM directory_audits"), 1);
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace"), 2);
    assert_eq!(count(&case, "SELECT count(*) FROM mailboxes"), 2);
    assert_eq!(count(&case, "SELECT count(*) FROM mailbox_permissions"), 1);
    // 2 raw children + 1 child of the partial session record + 1 parent-less MessageIDs row.
    assert_eq!(count(&case, "SELECT count(*) FROM mail_items_accessed"), 4);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mail_items_accessed WHERE record_id IS NULL"
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM tenant_settings WHERE source = 'entra_security_defaults'"
        ),
        4
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM audit_config WHERE audit_disabled = false AND security_defaults_enabled = false"
        ),
        1
    );
    // The later Audit Status run wins.
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM mailboxes WHERE record_key = '{BOB}' AND audit_bypass_enabled"
            )
        ),
        1
    );
    // The raw MailItemsAccessed record was seen in the UAL, Sessions and MessageIDs files.
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(DISTINCT file_id) FROM record_sources WHERE table_name = 'ual_events' AND record_key = '{MIA_1}'"
            )
        ),
        3
    );

    // Runs.
    for d in EMPTY_RUN_DIRS {
        assert_eq!(
            count(
                &case,
                &format!("SELECT count(*) FROM collector_runs WHERE rel_dir = '{d}' AND files = 0")
            ),
            1,
            "{d}"
        );
    }
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collector_runs WHERE empty_files > 0"
        ),
        2
    );
    assert_eq!(
        count(&case, "SELECT epoch(collected_at)::BIGINT FROM collections"),
        1_789_034_400
    );

    // Provenance verifies.
    assert!(verify_record(&case, "ual_events", ID_2, None).unwrap().ok);
    assert!(verify_record(&case, "signins", S2, None).unwrap().ok);
    assert!(
        verify_record(
            &case,
            "mailbox_permissions",
            &format!("{ALICE}|full_access||bob (bob@contoso.example)"),
            None
        )
        .unwrap()
        .ok
    );
}

#[test]
fn reingesting_the_tree_adds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    invictus_output_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let first = ingest_into(&mut case, dir.path());
    let tables = [
        "ual_events",
        "signins",
        "directory_audits",
        "message_trace",
        "mailboxes",
        "mailbox_permissions",
        "mail_items_accessed",
        "tenant_settings",
        "record_sources",
        "collector_runs",
    ];
    let before: Vec<i64> = tables
        .iter()
        .map(|t| count(&case, &format!("SELECT count(*) FROM {t}")))
        .collect();
    let second = ingest_into(&mut case, dir.path());
    let after: Vec<i64> = tables
        .iter()
        .map(|t| count(&case, &format!("SELECT count(*) FROM {t}")))
        .collect();
    assert_eq!(before, after);
    for f in first.collections.iter().flat_map(|c| &c.files) {
        if f.status == FileStatus::Parsed {
            assert_eq!(
                row(&second, &f.rel_path).status,
                FileStatus::DuplicateFile,
                "{}",
                f.rel_path
            );
        }
    }
}
