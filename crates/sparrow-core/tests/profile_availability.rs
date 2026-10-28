use chrono::{DateTime, TimeZone, Utc};
use duckdb::params;
use sparrow_core::Case;
use sparrow_core::discovery::registry::Registry;
use sparrow_core::ingest::EMPTY_FILE_WARNING;
use sparrow_core::profile::availability::{AvailabilityRow, EVIDENCE, compute};
use sparrow_core::profile::{ProfileOptions, refresh};

const T1: &str = "c9c9c9c9-0000-4000-8000-000000000001";

fn as_of() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 25, 0, 0, 0).unwrap()
}

fn opts() -> ProfileOptions {
    ProfileOptions {
        as_of: Some(as_of()),
        ..Default::default()
    }
}

/// A collection of `tool` ('hawk', 'invictus', 'portal_export'); `window_end` optional.
fn collection(case: &Case, tool: &str, collected_at: &str, window_end: Option<&str>) -> i64 {
    case.conn()
        .query_row(
            "INSERT INTO collections (tool, root_path, collected_at, window_end, sparrow_version)
             VALUES (CAST(? AS collector_tool), '/x/' || ?, CAST(? AS TIMESTAMPTZ), CAST(? AS TIMESTAMPTZ), 't')
             RETURNING collection_id",
            params![tool, tool, collected_at, window_end],
            |r| r.get(0),
        )
        .unwrap()
}

/// A source file; `warnings` is a JSON array text or None.
fn file(
    case: &Case,
    c: i64,
    rel: &str,
    artifact: &str,
    status: &str,
    warnings: Option<&str>,
) -> i64 {
    case.conn()
        .query_row(
            "INSERT INTO source_files (collection_id, rel_path, artifact_type, size_bytes, sha256, status, warnings)
             VALUES (?, ?, ?, 1, 'h' || ?, CAST(? AS file_status), CAST(? AS JSON)) RETURNING file_id",
            params![c, rel, artifact, rel, status, warnings],
            |r| r.get(0),
        )
        .unwrap()
}

/// A UAL row of tenant T1 sighted in file `f`.
fn ual(case: &Case, c: i64, f: i64, id: &str, at: &str, operation: &str, upn: &str) {
    case.conn()
        .execute(
            "INSERT INTO ual_events (record_id, collection_id, event_time, time_tz_assumed, time_precision,
                 organization_id, workload, operation, user_upn, audit_data, data_completeness, synthetic_id)
             VALUES (CAST(? AS UUID), ?, CAST(? AS TIMESTAMPTZ), false, 'second', CAST(? AS UUID),
                 'Exchange', ?, ?, '{}', 'full', false)",
            params![id, c, at, T1, operation, upn],
        )
        .unwrap();
    case.conn()
        .execute(
            "INSERT INTO record_sources VALUES ('ual_events', ?, ?, 0, 1, 1, 0, 1, 'h')",
            params![id, f],
        )
        .unwrap();
}

fn mailbox(case: &Case, c: i64, upn: &str, audit_owner: &str) {
    case.conn()
        .execute(
            &format!(
                "INSERT INTO mailboxes (record_key, collection_id, upn, audit_owner)
                 VALUES (?, ?, ?, {audit_owner})"
            ),
            params![format!("{c}|{upn}"), c, upn],
        )
        .unwrap();
}

fn evaluate(case: &mut Case) -> Vec<AvailabilityRow> {
    refresh(case, &opts()).unwrap();
    compute(case.conn(), as_of()).unwrap()
}

fn row<'a>(rows: &'a [AvailabilityRow], evidence: &str) -> &'a AvailabilityRow {
    let tenants: std::collections::HashSet<&str> =
        rows.iter().map(|r| r.tenant_key.as_str()).collect();
    assert_eq!(tenants.len(), 1, "one tenant expected: {tenants:?}");
    rows.iter()
        .find(|r| r.evidence == evidence)
        .unwrap_or_else(|| panic!("no row for {evidence}"))
}

#[test]
fn collected_rows_report_times_and_users() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    let f = file(
        &case,
        c,
        "UnifiedAuditLog/a.csv",
        "inv.ual.window",
        "parsed",
        None,
    );
    ual(
        &case,
        c,
        f,
        "11111111-1111-4111-8111-111111111111",
        "2026-09-01 10:00:00+00",
        "MailItemsAccessed",
        "alice@contoso.example",
    );
    ual(
        &case,
        c,
        f,
        "22222222-2222-4222-8222-222222222222",
        "2026-09-02 11:00:00+00",
        "MailItemsAccessed",
        "bob@contoso.example",
    );
    let rows = evaluate(&mut case);
    let r = row(&rows, "mail_items_accessed");
    assert_eq!(r.status, "collected", "{r:?}");
    assert_eq!(r.rows, 2);
    assert_eq!(r.users_covered, Some(2));
    assert_eq!(r.min_time.as_deref(), Some("2026-09-01T10:00:00Z"));
    assert_eq!(r.max_time.as_deref(), Some("2026-09-02T11:00:00Z"));
    assert_eq!(r.remediation, None);
}

#[test]
fn invictus_run_with_empty_export_is_collected_with_no_rows() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    case.conn()
        .execute(
            "INSERT INTO collector_runs (collection_id, rel_dir, component, run_label, files, empty_files, bytes)
             VALUES (?, 'MessageTrace/20260910-100000', 'MessageTrace', NULL, 1, 1, 0)",
            params![c],
        )
        .unwrap();
    let rows = evaluate(&mut case);
    let r = row(&rows, "message_trace");
    assert_eq!(r.status, "collected", "{r:?}");
    assert_eq!(r.rows, 0);
    assert!(r.reason.contains("returned no records"), "{r:?}");
}

#[test]
fn hawk_log_line_means_the_step_ran() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "hawk", "2026-09-20 00:00:00+00", None);
    case.conn()
        .execute(
            "INSERT INTO collection_log (log_key, collection_id, file_id, record_ordinal, tz_assumed, level, message)
             VALUES ('k1', ?, 0, 0, false, 'ACTION',
                     'Initiating collection of Message Trace Data for alice@contoso.example from Exchange Online.')",
            params![c],
        )
        .unwrap();
    let rows = evaluate(&mut case);
    let r = row(&rows, "message_trace");
    assert_eq!(r.status, "collected", "{r:?}");
    assert_eq!(r.rows, 0);
}

#[test]
fn truncated_export_is_partial() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "portal_export", "2026-09-20 00:00:00+00", None);
    let f = file(
        &case,
        c,
        "audit.csv",
        "portal.ual",
        "parsed",
        Some(r#"["row count equals known export cap 50000 — results likely truncated"]"#),
    );
    ual(
        &case,
        c,
        f,
        "11111111-1111-4111-8111-111111111111",
        "2026-09-01 10:00:00+00",
        "Send",
        "alice@contoso.example",
    );
    let rows = evaluate(&mut case);
    let r = row(&rows, "ual");
    assert_eq!(r.status, "partial", "{r:?}");
    assert!(r.reason.contains("export cap"), "{r:?}");
}

#[test]
fn hawk_only_ual_is_partial() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "hawk", "2026-09-20 00:00:00+00", None);
    let f = file(
        &case,
        c,
        "Tenant/x.json",
        "hawk.tenant.raw_ual",
        "parsed",
        None,
    );
    ual(
        &case,
        c,
        f,
        "11111111-1111-4111-8111-111111111111",
        "2026-09-01 10:00:00+00",
        "New-InboxRule",
        "alice@contoso.example",
    );
    let rows = evaluate(&mut case);
    let r = row(&rows, "ual");
    assert_eq!(r.status, "partial", "{r:?}");
    assert!(r.reason.contains("selected operations"), "{r:?}");
}

#[test]
fn not_licensed_beats_everything_when_nothing_was_collected() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    case.conn()
        .execute(
            "INSERT INTO licenses (record_key, collection_id, source, sku_part_number, capability_status, service_plans, confidence)
             VALUES (?, ?, 'invictus_tenant_licenses', 'O365_BUSINESS_ESSENTIALS', 'Enabled', ['EXCHANGE_S_STANDARD'], 'high')",
            params![format!("{c}|invictus_tenant_licenses|x"), c],
        )
        .unwrap();
    let rows = evaluate(&mut case);
    let r = row(&rows, "risk_detections");
    assert_eq!(r.status, "not_licensed", "{r:?}");
    assert!(r.reason.contains("AAD_PREMIUM_P2"), "{r:?}");
    assert_eq!(r.remediation, None);
}

#[test]
fn audit_disabled_org_is_not_enabled() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "hawk", "2026-09-20 00:00:00+00", None);
    case.conn()
        .execute(
            "INSERT INTO audit_config (record_key, collection_id, audit_disabled, column_collections)
             VALUES (?, ?, true, json_object('audit_disabled', ?))",
            params![format!("{c}|org"), c, c],
        )
        .unwrap();
    let rows = evaluate(&mut case);
    let r = row(&rows, "mail_items_accessed");
    assert_eq!(r.status, "not_enabled", "{r:?}");
    assert!(r.reason.contains("AuditDisabled True"), "{r:?}");
    assert_eq!(r.remediation, None);
}

#[test]
fn mailboxes_without_the_action_are_not_enabled_or_partial() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    mailbox(
        &case,
        c,
        "alice@contoso.example",
        "['Update', 'HardDelete']",
    );
    mailbox(&case, c, "bob@contoso.example", "['Update']");
    let rows = evaluate(&mut case);
    let r = row(&rows, "mail_items_accessed");
    assert_eq!(r.status, "not_enabled", "{r:?}");
    assert!(r.reason.contains("none of the 2 mailboxes"), "{r:?}");

    let f = file(
        &case,
        c,
        "UnifiedAuditLog/a.csv",
        "inv.ual.window",
        "parsed",
        None,
    );
    ual(
        &case,
        c,
        f,
        "11111111-1111-4111-8111-111111111111",
        "2026-09-01 10:00:00+00",
        "MailItemsAccessed",
        "carol@contoso.example",
    );
    mailbox(
        &case,
        c,
        "carol@contoso.example",
        "['Update', 'mailitemsaccessed']",
    );
    let rows = evaluate(&mut case);
    let r = row(&rows, "mail_items_accessed");
    assert_eq!(r.status, "partial", "{r:?}");
    assert!(r.reason.contains("2 of 3 mailboxes"), "{r:?}");
}

#[test]
fn beyond_retention_when_the_window_is_older_than_retention() {
    let mut case = Case::in_memory().unwrap();
    collection(
        &case,
        "hawk",
        "2026-01-01 00:00:00+00",
        Some("2026-01-01 00:00:00+00"),
    );
    let rows = evaluate(&mut case);
    let r = row(&rows, "signins");
    assert_eq!(r.status, "beyond_retention", "{r:?}");
    assert_eq!(r.retention_days, Some(7));
    assert!(r.reason.contains("2026-01-01"), "{r:?}");
    assert!(r.remediation.is_some(), "{r:?}");
}

#[test]
fn available_not_collected_otherwise() {
    let mut case = Case::in_memory().unwrap();
    collection(
        &case,
        "invictus",
        "2026-09-24 00:00:00+00",
        Some("2026-09-24 00:00:00+00"),
    );
    let rows = evaluate(&mut case);
    let r = row(&rows, "signins");
    assert_eq!(r.status, "available_not_collected", "{r:?}");
    let rem = r.remediation.as_deref().unwrap();
    assert!(
        rem.contains("Get-GraphEntraSignInLogs -startDate 2026-09-18 -endDate 2026-09-25"),
        "{rem}"
    );
    assert!(
        rem.starts_with("Microsoft-Extractor-Suite"),
        "Invictus tenant: its tool first: {rem}"
    );
}

#[test]
fn mdo_evidence_is_unknown_without_licence_evidence() {
    let mut case = Case::in_memory().unwrap();
    collection(&case, "hawk", "2026-09-20 00:00:00+00", None);
    let rows = evaluate(&mut case);
    let r = row(&rows, "email_threat_events");
    assert_eq!(r.status, "unknown", "{r:?}");
    assert!(
        r.remediation
            .as_deref()
            .unwrap()
            .contains("Defender portal"),
        "{r:?}"
    );
}

#[test]
fn not_supported_files_are_partial() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    file(
        &case,
        c,
        "Users/20260910-100300/20260910-100300-Users.csv",
        "inv.users",
        "not_supported",
        None,
    );
    let rows = evaluate(&mut case);
    let r = row(&rows, "users");
    assert_eq!(r.status, "partial", "{r:?}");
    assert!(
        r.reason.contains("1 files collected but not parsed"),
        "{r:?}"
    );

    // An empty export: the collector ran and found nothing.
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    let warnings = serde_json::to_string(&[EMPTY_FILE_WARNING]).unwrap();
    file(
        &case,
        c,
        "Users/20260910-100300/20260910-100300-Users.csv",
        "inv.users",
        "not_supported",
        Some(&warnings),
    );
    let rows = evaluate(&mut case);
    let r = row(&rows, "users");
    assert_eq!(r.status, "collected", "{r:?}");
    assert!(r.reason.contains("returned no records"), "{r:?}");
}

#[test]
fn every_catalog_artifact_pattern_matches_a_registry_id() {
    let mut ids: Vec<&str> = Registry::builtin().defs().map(|d| d.id).collect();
    ids.extend([
        "portal.ual",
        "portal.entra_signins",
        "portal.entra_audit",
        "portal.message_trace",
    ]);
    for ev in EVIDENCE {
        for pat in ev.artifacts {
            let hit = match pat.strip_suffix('*') {
                Some(prefix) => ids.iter().any(|id| id.starts_with(prefix)),
                None => ids.contains(pat),
            };
            assert!(
                hit,
                "{}: artifact pattern {pat} matches no registry id",
                ev.id
            );
        }
    }
}

#[test]
fn catalog_ids_match_capability_evidence_lists() {
    let defs = sparrow_core::data::capabilities(&Default::default()).unwrap();
    let ids: Vec<&str> = EVIDENCE.iter().map(|e| e.id).collect();
    for d in &defs {
        for e in &d.evidence {
            assert!(
                ids.contains(&e.as_str()),
                "{}: evidence {e} not in EVIDENCE",
                d.id
            );
        }
    }
}

#[test]
fn snapshot_matches_compute() {
    let mut case = Case::in_memory().unwrap();
    collection(&case, "hawk", "2026-09-20 00:00:00+00", None);
    collection(&case, "invictus", "2026-09-21 00:00:00+00", None);
    let rows = evaluate(&mut case);
    let n: i64 = case
        .conn()
        .query_row("SELECT count(*) FROM evidence_availability", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(n as usize, rows.len());
    assert!(n >= EVIDENCE.len() as i64);
    let evaluated: i64 = case
        .conn()
        .query_row(
            "SELECT count(*) FROM evidence_availability WHERE epoch(evaluated_at)::BIGINT = ?",
            params![as_of().timestamp()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(evaluated, n);
}

fn run_folder(case: &Case, c: i64, rel_dir: &str, component: &str, files: i32) {
    case.conn()
        .execute(
            "INSERT INTO collector_runs (collection_id, rel_dir, component, run_label, files, empty_files, bytes)
             VALUES (?, ?, ?, NULL, ?, 0, 0)",
            params![c, rel_dir, component, files],
        )
        .unwrap();
}

#[test]
fn a_shared_run_folder_counts_only_for_the_evidence_its_files_belong_to() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    run_folder(&case, c, "Rules/20260910-101100", "Rules", 1);
    file(
        &case,
        c,
        "Rules/20260910-101100/20260910-101100-TransportRules.csv",
        "inv.transport_rules",
        "parsed",
        None,
    );
    let rows = evaluate(&mut case);
    let r = row(&rows, "inbox_rules");
    assert_ne!(
        r.status, "collected",
        "a Get-TransportRules folder says nothing about inbox rules: {r:?}"
    );
    assert_eq!(row(&rows, "transport_rules").status, "collected");
}

#[test]
fn an_empty_shared_run_folder_counts_for_every_evidence_of_its_component() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    run_folder(&case, c, "Rules/20260910-101100", "Rules", 0);
    let rows = evaluate(&mut case);
    for ev in ["inbox_rules", "transport_rules"] {
        let r = row(&rows, ev);
        assert_eq!(r.status, "collected", "{r:?}");
        assert!(r.reason.contains("run folder"), "{r:?}");
    }
}

#[test]
fn truncation_comes_from_the_files_that_sighted_the_rows() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "portal_export", "2026-09-20 00:00:00+00", None);
    let f = file(
        &case,
        c,
        "audit.csv",
        "portal.ual",
        "parsed",
        Some(r#"["row count equals known export cap 50000 — results likely truncated"]"#),
    );
    ual(
        &case,
        c,
        f,
        "11111111-1111-4111-8111-111111111111",
        "2026-09-01 10:00:00+00",
        "MailItemsAccessed",
        "alice@contoso.example",
    );
    let rows = evaluate(&mut case);
    let r = row(&rows, "mail_items_accessed");
    assert_eq!(r.status, "partial", "{r:?}");
    assert!(r.reason.contains("export cap"), "{r:?}");
    let r = row(&rows, "signins");
    assert!(!r.reason.contains("export cap"), "{r:?}");
}

/// Truncation is flagged for every grouped UAL-backed evidence type, not only `ual` and
/// `mail_items_accessed`: a file carrying the export-cap warning that sighted a `SendAs` row
/// and a `SearchQueryInitiatedSharePoint` row makes both `mail_send` and `search_queries`
/// partial (Task 26 review). Reserved values only.
#[test]
fn truncation_flags_mail_send_and_search_queries() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "portal_export", "2026-09-20 00:00:00+00", None);
    let f = file(
        &case,
        c,
        "audit.csv",
        "portal.ual",
        "parsed",
        Some(r#"["row count equals known export cap 50000 — results likely truncated"]"#),
    );
    ual(
        &case,
        c,
        f,
        "11111111-1111-4111-8111-111111111111",
        "2026-09-01 10:00:00+00",
        "SendAs",
        "alice@contoso.example",
    );
    ual(
        &case,
        c,
        f,
        "22222222-2222-4222-8222-222222222222",
        "2026-09-01 11:00:00+00",
        "SearchQueryInitiatedSharePoint",
        "alice@contoso.example",
    );
    let rows = evaluate(&mut case);
    for ev in ["mail_send", "search_queries"] {
        let r = row(&rows, ev);
        assert_eq!(r.status, "partial", "{ev}: {r:?}");
        assert!(r.reason.contains("export cap"), "{ev}: {r:?}");
    }
    // The same file must not leak the flag into another UAL-backed type.
    let r = row(&rows, "mail_items_accessed");
    assert!(!r.reason.contains("export cap"), "{r:?}");
}

#[test]
fn each_tenant_sees_only_its_own_evidence() {
    const T2: &str = "d8d8d8d8-0000-4000-8000-000000000002";
    let mut case = Case::in_memory().unwrap();
    let c1 = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    let f1 = file(
        &case,
        c1,
        "EntraID/x-SignInLogs.json",
        "inv.signins",
        "parsed",
        None,
    );
    case.conn()
        .execute_batch(&format!(
            "INSERT INTO signins (record_key, collection_id, event_time, user_upn, resource_tenant_id)
                 VALUES ('s1', {c1}, TIMESTAMPTZ '2026-09-01 10:00:00+00', 'alice@contoso.example', '{T1}');
             INSERT INTO record_sources VALUES ('signins', 's1', {f1}, 0, 1, 1, 0, 1, 'h');"
        ))
        .unwrap();
    let c2 = collection(&case, "hawk", "2026-09-21 00:00:00+00", None);
    let f2 = file(
        &case,
        c2,
        "Tenant/x.json",
        "hawk.tenant.raw_ual",
        "parsed",
        None,
    );
    case.conn()
        .execute(
            "INSERT INTO ual_events (record_id, collection_id, event_time, time_tz_assumed, time_precision,
                 organization_id, workload, operation, user_upn, audit_data, data_completeness, synthetic_id)
             VALUES ('22222222-2222-4222-8222-222222222222', ?, TIMESTAMPTZ '2026-09-02 10:00:00+00', false,
                 'second', CAST(? AS UUID), 'Exchange', 'Send', 'bob@fabrikam.example', '{}', 'full', false)",
            params![c2, T2],
        )
        .unwrap();
    case.conn()
        .execute(
            "INSERT INTO record_sources VALUES ('ual_events', '22222222-2222-4222-8222-222222222222', ?, 0, 1, 1, 0, 1, 'h')",
            params![f2],
        )
        .unwrap();
    let rows = evaluate(&mut case);
    let get = |tenant: &str, ev: &str| {
        rows.iter()
            .find(|r| r.tenant_key == tenant && r.evidence == ev)
            .unwrap_or_else(|| panic!("no row for {tenant} {ev}: {rows:?}"))
    };
    assert_eq!(get(T1, "signins").status, "collected");
    assert_eq!(get(T1, "signins").rows, 1);
    assert_ne!(get(T2, "signins").status, "collected");
    assert_eq!(get(T2, "signins").rows, 0);
    assert_eq!(get(T2, "ual").rows, 1);
    assert_eq!(get(T1, "ual").rows, 0);
}

#[test]
fn a_parsed_hawk_log_alone_does_not_mean_licences_were_collected() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "hawk", "2026-09-20 00:00:00+00", None);
    file(&case, c, "Hawk.log", "hawk.log", "parsed", None);
    let rows = evaluate(&mut case);
    let r = row(&rows, "licenses");
    assert_ne!(r.status, "collected", "{r:?}");
    case.conn()
        .execute(
            "INSERT INTO collection_log (log_key, collection_id, file_id, record_ordinal, tz_assumed, level, message)
             VALUES ('k1', ?, 0, 0, false, 'INFO', 'M365 License type detected: Unknown')",
            params![c],
        )
        .unwrap();
    let rows = evaluate(&mut case);
    assert_eq!(row(&rows, "licenses").status, "collected");
}

fn set_records_error(case: &Case, f: i64, n: i64) {
    case.conn()
        .execute(
            "UPDATE source_files SET records_error = ? WHERE file_id = ?",
            params![n, f],
        )
        .unwrap();
}

#[test]
fn failed_files_with_rows_are_partial() {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    let f = file(
        &case,
        c,
        "UnifiedAuditLog/a.csv",
        "inv.ual.window",
        "parsed",
        None,
    );
    set_records_error(&case, f, 3);
    ual(
        &case,
        c,
        f,
        "11111111-1111-4111-8111-111111111111",
        "2026-09-01 10:00:00+00",
        "New-InboxRule",
        "alice@contoso.example",
    );
    let rows = evaluate(&mut case);
    let r = row(&rows, "ual");
    assert_eq!(r.status, "partial", "{r:?}");
    assert_eq!(r.rows, 1);
    assert!(
        r.reason
            .contains("1 files failed to parse (see the ingest report / parse_errors)"),
        "{r:?}"
    );
    // A full-UAL file with parse errors may have lost MailItemsAccessed records too.
    let r = row(&rows, "mail_items_accessed");
    assert_eq!(r.status, "partial", "{r:?}");
    assert!(r.reason.contains("1 files failed to parse"), "{r:?}");
}

#[test]
fn failed_files_without_rows_are_partial_not_ran() {
    // A file with status error.
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    file(
        &case,
        c,
        "Users/20260910-100300/20260910-100300-Users.csv",
        "inv.users",
        "error",
        Some(r#"["unexpected header"]"#),
    );
    let rows = evaluate(&mut case);
    let r = row(&rows, "users");
    assert_eq!(r.status, "partial", "{r:?}");
    assert_eq!(r.rows, 0);
    assert!(
        r.reason
            .contains("1 files failed to parse (see the ingest report / parse_errors)"),
        "{r:?}"
    );
    assert!(!r.reason.contains("returned no records"), "{r:?}");

    // A parsed file whose every record failed: 0 rows, still not "ran, nothing found", even
    // with a run folder and a Hawk log line that would otherwise say so.
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    run_folder(&case, c, "MessageTrace/20260910-100000", "MessageTrace", 1);
    let f = file(
        &case,
        c,
        "MessageTrace/20260910-100000/trace.csv",
        "inv.message_trace",
        "parsed",
        None,
    );
    set_records_error(&case, f, 5);
    let rows = evaluate(&mut case);
    let r = row(&rows, "message_trace");
    assert_eq!(r.status, "partial", "{r:?}");
    assert!(r.reason.contains("1 files failed to parse"), "{r:?}");
    assert!(!r.reason.contains("returned no records"), "{r:?}");
    assert!(r.remediation.is_some(), "{r:?}");
}

/// A Hawk capture whose message trace was collected for alice only, with the tenant's user list
/// `upns`.
fn hawk_trace_for_alice(upns: &[&str]) -> Vec<AvailabilityRow> {
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "hawk", "2026-09-20 00:00:00+00", None);
    let f = file(
        &case,
        c,
        "alice@contoso.example/Message_Trace_alice.json",
        "hawk.user.message_trace",
        "parsed",
        None,
    );
    case.conn()
        .execute(
            "INSERT INTO message_trace (record_key, collection_id, received, sender, recipient)
             VALUES ('m1|x', ?, CAST('2026-09-19 10:00:00+00' AS TIMESTAMPTZ), 'alice@contoso.example', 'x@fabrikam.example')",
            params![c],
        )
        .unwrap();
    case.conn()
        .execute(
            "INSERT INTO record_sources VALUES ('message_trace', 'm1|x', ?, 0, 1, 1, 0, 1, 'h')",
            params![f],
        )
        .unwrap();
    case.conn()
        .execute(
            "INSERT INTO collection_log (log_key, collection_id, file_id, record_ordinal, tz_assumed, level, message)
             VALUES ('k1', ?, 0, 0, false, 'ACTION',
                     'Initiating collection of Message Trace Data for alice@contoso.example from Exchange Online.')",
            params![c],
        )
        .unwrap();
    for (i, upn) in upns.iter().enumerate() {
        case.conn()
            .execute(
                "INSERT INTO users (record_key, collection_id, upn) VALUES (?, ?, ?)",
                params![format!("u{i}"), c, upn],
            )
            .unwrap();
    }
    evaluate(&mut case)
}

#[test]
fn hawk_per_user_collection_is_partial_only_when_it_covers_some_users() {
    // Spec §7: `partial` e.g. Hawk per-user collection covering only some users.
    let rows = hawk_trace_for_alice(&["Alice@contoso.example"]);
    let r = row(&rows, "message_trace");
    assert_eq!(r.status, "collected", "{r:?}");
    let rows = hawk_trace_for_alice(&["alice@contoso.example", "bob@contoso.example"]);
    let r = row(&rows, "message_trace");
    assert_eq!(r.status, "partial", "{r:?}");
    assert!(r.reason.contains("for 1 users of 2"), "{r:?}");
    let rows = hawk_trace_for_alice(&[]);
    let r = row(&rows, "message_trace");
    assert_eq!(r.status, "partial", "unknown coverage: {r:?}");
}

/// A parse_errors row for file `f`.
fn parse_error(case: &Case, f: i64, ordinal: i64, msg: &str) {
    case.conn()
        .execute(
            "INSERT INTO parse_errors (file_id, record_ordinal, line_start, line_end, byte_offset, byte_length, error) \
             VALUES (?, ?, 1, 1, 0, 1, ?)",
            params![f, ordinal, msg],
        )
        .unwrap();
}

#[test]
fn records_the_collector_lost_are_not_parse_failures() {
    use sparrow_core::ingest::COLLECTOR_LOSS;
    let lost = format!(
        "{COLLECTOR_LOSS}Get-MgUser failed for this role member (the collector wrote 'Error retrieving data')"
    );
    // Only a collector-side rejection: partial, and said so, never "failed to parse".
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    let f = file(
        &case,
        c,
        "UnifiedAuditLog/a.csv",
        "inv.ual.window",
        "parsed",
        None,
    );
    set_records_error(&case, f, 1);
    parse_error(&case, f, 3, &lost);
    ual(
        &case,
        c,
        f,
        "11111111-1111-4111-8111-111111111111",
        "2026-09-01 10:00:00+00",
        "New-InboxRule",
        "alice@contoso.example",
    );
    let rows = evaluate(&mut case);
    let r = row(&rows, "ual");
    assert_eq!(r.status, "partial", "{r:?}");
    assert!(
        r.reason
            .contains("1 files lost records in the collector's own output"),
        "{r:?}"
    );
    assert!(!r.reason.contains("failed to parse"), "{r:?}");

    // A collector-side rejection plus a real parse failure in the same file: the file failed to parse.
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    let f = file(
        &case,
        c,
        "UnifiedAuditLog/a.csv",
        "inv.ual.window",
        "parsed",
        None,
    );
    set_records_error(&case, f, 2);
    parse_error(&case, f, 3, &lost);
    parse_error(&case, f, 4, "unterminated quote");
    ual(
        &case,
        c,
        f,
        "11111111-1111-4111-8111-111111111111",
        "2026-09-01 10:00:00+00",
        "New-InboxRule",
        "alice@contoso.example",
    );
    let r = row(&evaluate(&mut case), "ual").clone();
    assert!(r.reason.contains("1 files failed to parse"), "{r:?}");

    // A row that loaded but lost a value to a collector bug (the Role carry-over warning): collector loss too.
    let mut case = Case::in_memory().unwrap();
    let c = collection(&case, "invictus", "2026-09-20 00:00:00+00", None);
    let f = file(
        &case,
        c,
        "UnifiedAuditLog/a.csv",
        "inv.ual.window",
        "parsed",
        Some(r#"["1 rows lost their role name to the collector's Role carry-over"]"#),
    );
    ual(
        &case,
        c,
        f,
        "11111111-1111-4111-8111-111111111111",
        "2026-09-01 10:00:00+00",
        "New-InboxRule",
        "alice@contoso.example",
    );
    let r = row(&evaluate(&mut case), "ual").clone();
    assert_eq!(r.status, "partial", "{r:?}");
    assert!(
        r.reason
            .contains("1 files lost records in the collector's own output"),
        "{r:?}"
    );
    assert!(!r.reason.contains("failed to parse"), "{r:?}");
}
