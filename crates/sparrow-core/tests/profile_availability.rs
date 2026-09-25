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
    ids.extend(["portal.ual", "portal.entra_signins", "portal.message_trace"]);
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
