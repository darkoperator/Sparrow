//! Task 9: operation catalog categories, `record_source_refs`, `timeline` and `auth_events`.

use serde_json::json;
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::detect::test::insert_record;
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

/// A sign-in the user interrupted: `UserLoginFailed` with `ResultStatus` Success and a
/// `LogonError` (the credential prompt was cancelled). It is neither a success nor a failure,
/// so it must not be counted as one in `auth_events`.
#[test]
fn an_interrupted_signin_is_neither_a_success_nor_a_failure() {
    let (_dir, mut case) = case_with_events();
    // A real failure and an interrupt, next to the successes the fixture tree already holds.
    for (id, status, error) in [
        (
            ual::ID_LOGIN_INTERRUPT,
            "Success",
            "User interrupted the sign-in",
        ),
        (
            ual::ID_LOGIN_FAIL,
            "Failed",
            "Invalid user name or password",
        ),
    ] {
        insert_record(
            &case,
            "contoso.example",
            "ual_events",
            &json!({
                "record_id": id,
                "event_time": "2026-09-14T10:15:00Z",
                "operation": "UserLoginFailed",
                "workload": "AzureActiveDirectory",
                "record_type": 15,
                "result_status": status,
                "user_upn": "alice@contoso.example",
                "audit_data": format!(
                    "{{\"CreationTime\":\"2026-09-14T10:15:00\",\"Id\":\"{id}\",\
                      \"Operation\":\"UserLoginFailed\",\"ResultStatus\":\"{status}\",\
                      \"Workload\":\"AzureActiveDirectory\",\"LogonError\":\"{error}\",\
                      \"ErrorNumber\":0,\"ClientIP\":\"203.0.113.10\",\
                      \"UserId\":\"alice@contoso.example\"}}"
                ),
            }),
            "auth-interrupt",
        )
        .unwrap();
    }
    refresh(&mut case, &ProfileOptions::default()).unwrap();

    let of = |id: &str| {
        format!(
            "SELECT succeeded FROM auth_events WHERE source_table = 'ual_events' \
             AND record_key = '{id}'"
        )
    };
    // The interrupt is not a success, and not a failure either.
    let interrupt: i64 = count(
        &case,
        &format!(
            "SELECT count(*) FROM auth_events WHERE record_key = '{}'",
            ual::ID_LOGIN_INTERRUPT
        ),
    );
    assert_eq!(interrupt, 1, "the interrupt is not in auth_events");
    let succeeded: bool = case
        .conn()
        .query_row(&of(ual::ID_LOGIN_INTERRUPT), [], |r| r.get(0))
        .unwrap();
    assert!(
        !succeeded,
        "an interrupted sign-in was reported as a success"
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM auth_events WHERE interrupt \
                 AND record_key = '{}'",
                ual::ID_LOGIN_INTERRUPT
            )
        ),
        1,
        "the interrupt is not flagged"
    );
    // The real failure is still a failure, the successes still successes.
    let failed: bool = case
        .conn()
        .query_row(&of(ual::ID_LOGIN_FAIL), [], |r| r.get(0))
        .unwrap();
    assert!(!failed, "a real failure was reported as a success");
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM auth_events WHERE interrupt \
                 AND record_key = '{}'",
                ual::ID_LOGIN_FAIL
            )
        ),
        0,
        "a real failure was flagged as an interrupt"
    );
    let login: bool = case
        .conn()
        .query_row(&of(ual::ID_LOGIN), [], |r| r.get(0))
        .unwrap();
    assert!(login, "a successful logon changed");
    // Every row now says which of the three it is.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM auth_events WHERE result NOT IN ('success', 'failure', 'interrupt')"
        ),
        0,
        "a row has no result"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM auth_events WHERE (result = 'success') <> succeeded"
        ),
        0,
        "result and succeeded disagree"
    );
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

/// Task 4: the timeline counts the findings that cite each record.
#[test]
fn timeline_counts_findings_per_record() {
    let (_dir, mut case) = case_with_events();
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let (ual_key, signin_key): (String, String) = (
        text(
            &case,
            "SELECT CAST(record_id AS VARCHAR) FROM ual_events ORDER BY record_id LIMIT 1",
        ),
        text(
            &case,
            "SELECT record_key FROM signins ORDER BY record_key LIMIT 1",
        ),
    );
    // Before any finding every row has count 0 and no ids.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM timeline WHERE finding_count <> 0 OR len(finding_ids) <> 0"
        ),
        0
    );
    for (id, src, key) in [
        ("f1", "ual_events", &ual_key),
        ("f2", "ual_events", &ual_key),
        ("f2", "signins", &signin_key),
    ] {
        case.conn()
            .execute(
                "INSERT INTO finding_evidence (finding_id, source_table, record_key, role, added_run_id) \
                 VALUES (?, ?, ?, 'trigger', 1)",
                duckdb::params![id, src, key],
            )
            .unwrap();
    }
    // A repeated (finding, record) pair counts once.
    case.conn()
        .execute(
            "INSERT INTO finding_evidence (finding_id, source_table, record_key, role, added_run_id) \
             VALUES ('f1', 'ual_events', ?, 'trigger', 2)",
            duckdb::params![ual_key],
        )
        .unwrap();
    let row = |src: &str, key: &str| -> (i32, String) {
        case.conn()
            .query_row(
                "SELECT finding_count, array_to_string(finding_ids, ',') FROM timeline WHERE source_table = ? AND record_key = ?",
                duckdb::params![src, key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
    };
    assert_eq!(row("ual_events", &ual_key), (2, "f1,f2".to_string()));
    assert_eq!(row("signins", &signin_key), (1, "f2".to_string()));
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM timeline WHERE finding_count > 0"
        ),
        2
    );
    // The row count is unchanged by the join.
    assert_eq!(
        count(&case, "SELECT count(*) FROM timeline"),
        count(&case, "SELECT count(*) FROM (SELECT * FROM timeline)")
    );
}

/// The Task 4 view is 0008's definition plus the finding join, and its comments are re-issued.
#[test]
fn timeline_view_is_the_phase_5_definition_plus_findings() {
    let view = |sql: &str, from: &str| -> String {
        let start = sql.rfind(from).unwrap();
        let end = start + sql[start..].find(";\n").unwrap();
        sql[start..end].to_string()
    };
    let m8 = include_str!("../migrations/0008_synth_parsers.sql");
    let m9 = include_str!("../migrations/0009_detection.sql");
    let old = view(m8, "CREATE OR REPLACE VIEW timeline AS");
    let new = view(m9, "CREATE OR REPLACE VIEW timeline AS");
    let stripped = new
        .replace(
            ",\n       coalesce(f.finding_count, 0) AS finding_count, coalesce(f.finding_ids, CAST([] AS VARCHAR[])) AS finding_ids",
            "",
        )
        .replace(
            "\nLEFT JOIN (SELECT source_table, record_key, CAST(count(DISTINCT finding_id) AS INTEGER) AS finding_count, list(DISTINCT finding_id ORDER BY finding_id) AS finding_ids FROM finding_evidence GROUP BY source_table, record_key) f\n       ON f.source_table = ev.source_table AND f.record_key = ev.record_key",
            "",
        );
    assert_eq!(stripped, old);
    assert_ne!(new, old);
    // Every comment 0008 issued for the view is issued again.
    for line in m8
        .lines()
        .filter(|l| l.starts_with("COMMENT ON COLUMN timeline."))
    {
        let target = line.split(" IS ").next().unwrap();
        assert!(m9.contains(target), "{target} not re-issued");
    }
}

/// `auth_events` must never contradict itself: `succeeded` and `result` come from one
/// classification, so a row is a success exactly when its result is 'success'. The rows that
/// broke it are the ones the classification used to miss: a `UserLoggedIn` whose `ResultStatus`
/// is `Failed` (the operation says success, the result says failure), and an STS-logon row
/// admitted by `record_type_name` under an operation name that is neither `UserLoggedIn` nor
/// `UserLoginFailed`.
#[test]
fn auth_events_never_contradicts_itself() {
    let (_dir, mut case) = case_with_events();
    // (id, operation, result_status, LogonError)
    let rows = [
        // A UserLoggedIn that nevertheless carries ResultStatus Failed.
        (
            "b3333333-3333-4333-8333-333333333331",
            "UserLoggedIn",
            "Failed",
            "Invalid user name or password",
        ),
        // An STS-logon row admitted by its record type, under another operation name.
        (
            "b3333333-3333-4333-8333-333333333332",
            "StsLogonSomethingElse",
            "Failed",
            "Invalid user name or password",
        ),
        // The same, with a ResultStatus that is neither, to pin the "success otherwise" rule.
        (
            "b3333333-3333-4333-8333-333333333333",
            "StsLogonSomethingElse",
            "Weird",
            "Whatever",
        ),
    ];
    for (id, operation, status, error) in rows {
        insert_record(
            &case,
            "contoso.example",
            "ual_events",
            &json!({
                "record_id": id,
                "event_time": "2026-09-14T11:00:00Z",
                "operation": operation,
                "workload": "AzureActiveDirectory",
                "record_type": 15,
                "record_type_name": "AzureActiveDirectoryStsLogon",
                "result_status": status,
                "user_upn": "alice@contoso.example",
                "audit_data": format!(
                    "{{\"CreationTime\":\"2026-09-14T11:00:00\",\"Id\":\"{id}\",\
                      \"Operation\":\"{operation}\",\"ResultStatus\":\"{status}\",\
                      \"Workload\":\"AzureActiveDirectory\",\"LogonError\":\"{error}\",\
                      \"ErrorNumber\":50126,\"ClientIP\":\"203.0.113.10\",\
                      \"UserId\":\"alice@contoso.example\"}}"
                ),
            }),
            "auth-contradiction",
        )
        .unwrap();
    }
    refresh(&mut case, &ProfileOptions::default()).unwrap();

    // The invariant, over every row the view holds.
    let contradictions: Vec<String> = case
        .conn()
        .prepare(
            "SELECT source_table || ' ' || record_key || ' succeeded=' || succeeded \
                    || ' result=' || result || ' interrupt=' || interrupt \
             FROM auth_events WHERE (result = 'success') <> succeeded",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(
        contradictions.is_empty(),
        "auth_events contradicts itself: {contradictions:#?}"
    );

    // And the two rows Codex named, read directly.
    for (id, operation) in [
        ("b3333333-3333-4333-8333-333333333331", "UserLoggedIn"),
        (
            "b3333333-3333-4333-8333-333333333332",
            "StsLogonSomethingElse",
        ),
    ] {
        let (succeeded, result): (bool, String) = case
            .conn()
            .query_row(
                "SELECT succeeded, result FROM auth_events \
                 WHERE source_table = 'ual_events' AND record_key = $1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(
            !succeeded,
            "{operation} + ResultStatus Failed was a success"
        );
        assert_eq!(result, "failure", "{operation} + ResultStatus Failed");
    }
    // A result status that is neither 'Failed' nor 'Success' falls through to success.
    let (succeeded, result): (bool, String) = case
        .conn()
        .query_row(
            "SELECT succeeded, result FROM auth_events \
             WHERE source_table = 'ual_events' AND record_key = $1",
            ["b3333333-3333-4333-8333-333333333333"],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(
        succeeded,
        "an unknown ResultStatus should fall through to success"
    );
    assert_eq!(result, "success");
}
