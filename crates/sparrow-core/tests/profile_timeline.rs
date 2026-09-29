//! Task 9: operation catalog categories, `record_source_refs`, `timeline` and `auth_events`.

use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::fixtures::events::{AUDIT_1, SIGNIN_2, hawk4_events_tree};
use sparrow_core::fixtures::hawk4::hawk4_tree;
use sparrow_core::fixtures::invictus::{BOB as INV_BOB, invictus_output_tree};
use sparrow_core::fixtures::mmdb::{asn, city, write_mmdb};
use sparrow_core::fixtures::ual;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_core::profile::{ProfileOptions, refresh};
use sparrow_core::verify::verify_record;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Synthetic GeoIP dir (Task 7 pattern): 203.0.113.0/24 resolves to Lagos, NG on DigitalOcean.
fn geoip_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let city_db = write_mmdb(
        "GeoLite2-City",
        1_790_000_000,
        &[(
            ip("203.0.113.0"),
            24,
            city("NG", "Nigeria", "Lagos", 6.45, 3.39),
        )],
    );
    let asn_db = write_mmdb(
        "GeoLite2-ASN",
        1_790_100_000,
        &[(ip("203.0.113.0"), 24, asn(14061, "DIGITALOCEAN-ASN"))],
    );
    std::fs::write(dir.path().join("GeoLite2-City.mmdb"), city_db).unwrap();
    std::fs::write(dir.path().join("GeoLite2-ASN.mmdb"), asn_db).unwrap();
    dir
}

/// Ingests the Phase 2c Hawk 4 events tree and the Phase 2a Hawk 4 UAL tree into one in-memory
/// case. Returns the temp dir too: its files must stay on disk for `verify_record` to re-read.
fn case_with_events() -> (tempfile::TempDir, Case) {
    let dir = tempfile::tempdir().unwrap();
    hawk4_events_tree(dir.path());
    hawk4_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert!(!report.has_errors(), "{report:#?}");
    (dir, case)
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn text(case: &Case, sql: &str) -> String {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn timeline_has_one_row_per_event_record() {
    let (_dir, mut case) = case_with_events();
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let expected: i64 = [
        "SELECT count(*) FROM ual_events",
        "SELECT count(*) FROM mail_items_accessed WHERE record_id IS NULL",
        "SELECT count(*) FROM signins",
        "SELECT count(*) FROM directory_audits",
        "SELECT count(*) FROM message_trace",
        "SELECT count(*) FROM mailbox_audit_legacy",
        "SELECT count(*) FROM admin_audit_events",
        "SELECT count(*) FROM risk_detections",
        "SELECT count(*) FROM azure_activity",
        "SELECT count(*) FROM security_alerts",
    ]
    .iter()
    .map(|sql| count(&case, sql))
    .sum();
    assert!(expected > 0);
    assert_eq!(count(&case, "SELECT count(*) FROM timeline"), expected);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM timeline WHERE source_refs IS NULL OR len(source_refs) = 0"
        ),
        0
    );
}

/// Task 20: the two new timeline branches. `azure_activity` is a config_change with the caller
/// and client IP; `security_alerts` takes the affected user and IP and falls back to
/// `created_time` when `event_time` is NULL.
#[test]
fn timeline_includes_azure_activity_and_security_alerts() {
    let (_dir, case) = case_with_events();
    case.conn()
        .execute_batch(
            "INSERT INTO azure_activity (record_key, collection_id, event_data_id, event_time, time_tz_assumed,
                 caller, operation_name, category, level, status, sub_status, resource_id, resource_group,
                 resource_provider, subscription_id, tenant_id, ip, correlation_id)
             VALUES ('evt-1', 1, 'evt-1', '2026-09-01 10:00:00+00', false, 'admin@contoso.example',
                 'Microsoft.Compute/virtualMachines/start/action', 'Administrative', 'Informational', 'Succeeded', 'OK',
                 '/subscriptions/x/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm', 'rg',
                 'Microsoft.Compute', 'sub', 'tenant', '203.0.113.9', 'corr');
             INSERT INTO security_alerts (record_key, collection_id, alert_id, created_time, title, severity,
                 affected_users, affected_ips)
             VALUES ('alert-1', 1, 'alert-1', '2026-09-02 11:00:00+00', 'Test alert', 'informational',
                 ['alice@contoso.example'], ['203.0.113.9']);",
        )
        .unwrap();

    assert_eq!(
        text(
            &case,
            "SELECT CAST(category AS VARCHAR) FROM timeline WHERE source_table = 'azure_activity'"
        ),
        "config_change"
    );
    assert_eq!(
        text(
            &case,
            "SELECT actor_upn FROM timeline WHERE source_table = 'azure_activity'"
        ),
        "admin@contoso.example"
    );
    assert_eq!(
        text(
            &case,
            "SELECT ip FROM timeline WHERE source_table = 'azure_activity'"
        ),
        "203.0.113.9"
    );
    assert_eq!(
        text(
            &case,
            "SELECT operation FROM timeline WHERE source_table = 'azure_activity'"
        ),
        "Microsoft.Compute/virtualMachines/start/action"
    );
    assert_eq!(
        text(
            &case,
            "SELECT CAST(category AS VARCHAR) FROM timeline WHERE source_table = 'security_alerts'"
        ),
        "other"
    );
    assert_eq!(
        text(
            &case,
            "SELECT actor_upn FROM timeline WHERE source_table = 'security_alerts'"
        ),
        "alice@contoso.example"
    );
    assert_eq!(
        text(
            &case,
            "SELECT summary FROM timeline WHERE source_table = 'security_alerts'"
        ),
        "informational: Test alert"
    );
    assert_eq!(
        count(
            &case,
            "SELECT epoch(event_time)::BIGINT FROM timeline WHERE source_table = 'security_alerts'"
        ),
        1788346800 // 2026-09-02T11:00:00Z (event_time NULL -> created_time)
    );
}

#[test]
fn timeline_categories_come_from_the_catalog() {
    let (_dir, mut case) = case_with_events();
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let category = |sql: &str| -> String { text(&case, sql) };

    assert_eq!(
        category(&format!(
            "SELECT CAST(category AS VARCHAR) FROM timeline
             WHERE source_table = 'ual_events' AND record_key = '{}'",
            ual::ID_RULE
        )),
        "mail_rule"
    );
    assert_eq!(
        category(
            "SELECT CAST(category AS VARCHAR) FROM timeline WHERE source_table = 'signins' LIMIT 1"
        ),
        "auth"
    );
    assert_eq!(
        category(
            "SELECT CAST(category AS VARCHAR) FROM timeline WHERE source_table = 'message_trace' LIMIT 1"
        ),
        "mail_flow"
    );
    // SearchQueryInitiated (ual::search()) has no catalog entry (only the Exchange/SharePoint
    // suffixed variants do), so it falls back to the default category.
    assert_eq!(
        category(
            "SELECT CAST(category AS VARCHAR) FROM timeline
             WHERE source_table = 'ual_events' AND operation = 'SearchQueryInitiated'"
        ),
        "other"
    );
}

#[test]
fn source_refs_match_verify() {
    let (_dir, mut case) = case_with_events();
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let first_ref: String = case
        .conn()
        .query_row(
            &format!(
                "SELECT source_refs[1] FROM timeline
                 WHERE source_table = 'ual_events' AND record_key = '{}'",
                ual::ID_RULE
            ),
            [],
            |r| r.get(0),
        )
        .unwrap();
    let v = verify_record(&case, "ual_events", ual::ID_RULE, None).unwrap();
    assert_eq!(first_ref, v.sightings[0].source_ref);
}

#[test]
fn ip_columns_join_ip_intel() {
    let (_dir, mut case) = case_with_events();
    let geo = geoip_dir();
    refresh(
        &mut case,
        &ProfileOptions {
            geoip_dir: Some(geo.path().to_path_buf()),
            ..Default::default()
        },
    )
    .unwrap();
    let country = text(
        &case,
        "SELECT ip_country FROM timeline WHERE source_table = 'signins' AND ip = '203.0.113.10' LIMIT 1",
    );
    assert_eq!(country, "NG");
}

#[test]
fn auth_events_unions_signins_and_ual_logons() {
    let (_dir, mut case) = case_with_events();
    refresh(&mut case, &ProfileOptions::default()).unwrap();

    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM auth_events WHERE source_table = 'signins'"
        ),
        count(&case, "SELECT count(*) FROM signins")
    );

    let login_succeeded: bool = case
        .conn()
        .query_row(
            &format!(
                "SELECT succeeded FROM auth_events
                 WHERE source_table = 'ual_events' AND record_key = '{}'",
                ual::ID_LOGIN
            ),
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(login_succeeded);

    let signin2_succeeded: bool = case
        .conn()
        .query_row(
            &format!(
                "SELECT succeeded FROM auth_events
                 WHERE source_table = 'signins' AND record_key = '{}'",
                SIGNIN_2.to_lowercase()
            ),
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!signin2_succeeded);
}

#[test]
fn catalog_override_changes_a_category() {
    let (_dir, mut case) = case_with_events();
    let data_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        data_dir.path().join("operation_catalog.yaml"),
        "version: 1\noperations:\n  - {operation: New-InboxRule, workload: Exchange, category: config_change, description: overridden}\n",
    )
    .unwrap();
    let opts = ProfileOptions {
        dirs: DataDirs {
            data: Some(data_dir.path().to_path_buf()),
            rules: Vec::new(),
        },
        ..Default::default()
    };
    refresh(&mut case, &opts).unwrap();
    let category = text(
        &case,
        &format!(
            "SELECT CAST(category AS VARCHAR) FROM timeline
             WHERE source_table = 'ual_events' AND record_key = '{}'",
            ual::ID_RULE
        ),
    );
    assert_eq!(category, "config_change");
}

/// The catalog overlay merges an override entry by `(operation_key, lower(workload))`, so an
/// override spelled `workload: exchange` replaces the built-in `New-InboxRule`/`Exchange` entry
/// (whose stored `workload` column is then literally `exchange`). The timeline view must still
/// match it against `ual_events.workload = 'Exchange'` case-insensitively.
#[test]
fn catalog_override_workload_matches_case_insensitively() {
    let (_dir, mut case) = case_with_events();
    let data_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        data_dir.path().join("operation_catalog.yaml"),
        "version: 1\noperations:\n  - {operation: New-InboxRule, workload: exchange, category: config_change, description: overridden}\n",
    )
    .unwrap();
    let opts = ProfileOptions {
        dirs: DataDirs {
            data: Some(data_dir.path().to_path_buf()),
            rules: Vec::new(),
        },
        ..Default::default()
    };
    refresh(&mut case, &opts).unwrap();
    let category = text(
        &case,
        &format!(
            "SELECT CAST(category AS VARCHAR) FROM timeline
             WHERE source_table = 'ual_events' AND record_key = '{}'",
            ual::ID_RULE
        ),
    );
    assert_eq!(category, "config_change");
}

/// `directory_audits.targets` stores `TargetResources` verbatim: Hawk's Get-MgAuditLogDirectoryAudit
/// is PascalCase (`UserPrincipalName`/`DisplayName`), but Microsoft-Extractor-Suite's Graph REST
/// JSON is camelCase (`userPrincipalName`/`displayName`). The `timeline.target` expression must
/// resolve both, not just Hawk's.
#[test]
fn directory_audits_target_resolves_hawk_and_extractor_suite_casing() {
    // Hawk (PascalCase TargetResources): regression check, this already worked.
    let (_dir, mut hawk_case) = case_with_events();
    refresh(&mut hawk_case, &ProfileOptions::default()).unwrap();
    let hawk_target: Option<String> = hawk_case
        .conn()
        .query_row(
            &format!(
                "SELECT target FROM timeline
                 WHERE source_table = 'directory_audits' AND record_key = '{}'",
                AUDIT_1.to_lowercase()
            ),
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(hawk_target.is_some(), "Hawk directory_audits target");

    // Microsoft-Extractor-Suite (camelCase targetResources): the actual regression.
    let dir = tempfile::tempdir().unwrap();
    invictus_output_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert!(!report.has_errors(), "{report:#?}");
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let inv_target: Option<String> = case
        .conn()
        .query_row(
            "SELECT target FROM timeline WHERE source_table = 'directory_audits' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(inv_target.as_deref(), Some(INV_BOB));
}
