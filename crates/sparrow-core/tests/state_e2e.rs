use sparrow_core::Case;
use sparrow_core::fixtures::state::{
    ALICE, BOB, hawk3_state_tree, hawk4_state_tree, hawk4_state_tree_at,
};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
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

fn text(case: &Case, sql: &str) -> String {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn assert_counts(case: &Case, expected: &[(&str, i64)]) {
    for (table, n) in expected {
        assert_eq!(
            count(case, &format!("SELECT count(*) FROM {table}")),
            *n,
            "{table}"
        );
    }
}

fn assert_no_unsupported_or_error(report: &IngestReport) {
    let bad: Vec<_> = report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .filter(|f| matches!(f.status, FileStatus::NotSupported | FileStatus::Error))
        .map(|f| (&f.rel_path, f.status, &f.warnings))
        .collect();
    assert!(bad.is_empty(), "{bad:#?}");
    assert!(!report.has_errors(), "{report:#?}");
}

/// Every flag that names a state table points at an existing row.
fn assert_flags_resolve(case: &Case) {
    for table in [
        "inbox_rules",
        "oauth_grants",
        "risky_users",
        "risk_detections",
        "mobile_devices",
        "role_assignments",
    ] {
        assert_eq!(
            count(
                case,
                &format!(
                    "SELECT count(*) FROM collector_flags WHERE linked_table = '{table}' AND linked_key NOT IN (SELECT record_key FROM {table})"
                )
            ),
            0,
            "{table}"
        );
    }
    assert_eq!(
        count(
            case,
            "SELECT count(*) FROM collector_flags WHERE linked_table = 'ual_events' AND linked_key NOT IN (SELECT CAST(record_id AS VARCHAR) FROM ual_events)"
        ),
        0
    );
    assert_eq!(
        count(
            case,
            "SELECT count(*) FROM collector_flags WHERE linked_table = 'source_files' AND linked_key NOT IN (SELECT rel_path FROM source_files)"
        ),
        0
    );
}

#[test]
fn hawk4_state_capture_loads_every_table() {
    let dir = tempfile::tempdir().unwrap();
    let root = hawk4_state_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_into(&mut case, &root);
    assert_no_unsupported_or_error(&report);
    assert_eq!(
        row(&report, "Tenant/EntraIDUsers.csv").status,
        FileStatus::SkippedSuperseded
    );
    assert_eq!(
        row(&report, "Tenant/Risk_Detections.csv").status,
        FileStatus::SkippedSuperseded
    );
    assert_counts(
        &case,
        &[
            ("users", 2),
            ("role_assignments", 5),
            ("tenant_settings", 13),
            ("oauth_grants", 2),
            ("app_credentials", 2),
            ("risky_users", 1),
            ("risk_detections", 1),
            ("inbox_rules", 3),
            ("mailboxes", 1),
            ("audit_config", 1),
            ("transport_rules", 1),
            ("remote_domains", 1),
            ("mobile_devices", 1),
            ("collector_flags", 7),
            ("ual_events", 1),
        ],
    );
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT forwarding_smtp_address || '|' || auto_reply_state || '|' || pop_enabled || '|' || recipient_type FROM mailboxes WHERE record_key = '{ALICE}'"
            )
        ),
        "smtp:x@fabrikam.example|Enabled|true|UserMailbox"
    );
    assert_eq!(
        text(
            &case,
            "SELECT unified_audit_log_ingestion_enabled || '|' || audit_disabled FROM audit_config"
        ),
        "false|false"
    );
    assert_flags_resolve(&case);
}

#[test]
fn hawk3_state_capture_loads_every_table() {
    let dir = tempfile::tempdir().unwrap();
    let root = hawk3_state_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_into(&mut case, &root);
    assert_no_unsupported_or_error(&report);
    assert_eq!(
        row(&report, "Tenant/AzureADUsers.csv").status,
        FileStatus::SkippedSuperseded
    );
    assert_eq!(
        row(&report, "Tenant/_Investigate_Impersonation_Rights.csv").status,
        FileStatus::SkippedSuperseded
    );
    assert_counts(
        &case,
        &[
            ("users", 2),
            ("role_assignments", 3),
            ("tenant_settings", 9),
            ("oauth_grants", 2),
            ("app_credentials", 2),
            ("inbox_rules", 1),
            ("mailboxes", 1),
            ("mobile_devices", 1),
            ("audit_config", 1),
            ("collector_flags", 4),
        ],
    );
    assert_eq!(
        text(
            &case,
            "SELECT principal_upn || '|' || epoch(start_time)::BIGINT FROM role_assignments WHERE record_key = 'exchange_rbac|applicationimpersonation|svc-sync@contoso.example'"
        ),
        "svc-sync@contoso.example|1788433200"
    );
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT recipient_type || '|' || epoch(when_changed)::BIGINT FROM mailboxes WHERE record_key = '{BOB}'"
            )
        ),
        "SharedMailbox|1790236800"
    );
    assert_eq!(
        count(
            &case,
            &format!("SELECT count(*) FROM inbox_rules WHERE mailbox_upn = '{BOB}'")
        ),
        1
    );
    assert_flags_resolve(&case);
}

#[test]
fn latest_wins_whatever_the_ingest_order() {
    let new_dir = tempfile::tempdir().unwrap();
    let old_dir = tempfile::tempdir().unwrap();
    let new_root = hawk4_state_tree_at(
        new_dir.path(),
        "20260920_090000",
        "smtp:new@fabrikam.example",
    );
    let old_root = hawk4_state_tree_at(
        old_dir.path(),
        "20260910_090000",
        "smtp:old@fabrikam.example",
    );
    for order in [[&new_root, &old_root], [&old_root, &new_root]] {
        let mut case = Case::in_memory().unwrap();
        for root in order {
            assert!(!ingest_into(&mut case, root).has_errors());
        }
        assert_eq!(count(&case, "SELECT count(*) FROM mailboxes"), 1);
        assert_eq!(
            text(&case, "SELECT forwarding_smtp_address FROM mailboxes"),
            "smtp:new@fabrikam.example"
        );
        assert!(
            text(
                &case,
                "SELECT c.root_path FROM mailboxes m JOIN collections c USING (collection_id)"
            )
            .ends_with("Hawk_Contoso_Ltd_20260920_090000")
        );
        assert_eq!(count(&case, "SELECT count(*) FROM users"), 2);
        assert_eq!(
            count(
                &case,
                &format!(
                    "SELECT count(DISTINCT sf.collection_id) FROM record_sources rs JOIN source_files sf USING (file_id) WHERE rs.table_name = 'mailboxes' AND rs.record_key = '{ALICE}'"
                )
            ),
            2
        );
    }
}

#[test]
fn state_rows_verify_against_the_original_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = hawk4_state_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    ingest_into(&mut case, &root);
    let rep = verify_record(&case, "mailboxes", ALICE, None).unwrap();
    assert!(rep.ok, "{rep:?}");
    assert_eq!(rep.sightings.len(), 5, "{rep:?}");
    let rep = verify_record(
        &case,
        "tenant_settings",
        "admin_audit_log_config|unifiedauditlogingestionenabled",
        None,
    )
    .unwrap();
    assert!(rep.ok, "{rep:?}");
    assert!(
        rep.sightings[0]
            .excerpt
            .as_deref()
            .is_some_and(|e| e.contains("UnifiedAuditLogIngestionEnabled")),
        "{rep:?}"
    );
}
