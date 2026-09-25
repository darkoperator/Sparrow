use duckdb::params;
use sparrow_core::Case;
use sparrow_core::profile::capabilities::tenant_capabilities;
use sparrow_core::profile::{ProfileOptions, refresh};

const T1: &str = "c9c9c9c9-0000-4000-8000-000000000001";

/// One Hawk collection of tenant T1 (a UAL row makes the tenant id known).
fn tenant_case() -> (Case, i64, i64) {
    let case = Case::in_memory().unwrap();
    let c: i64 = case
        .conn()
        .query_row(
            "INSERT INTO collections (tool, root_path, collected_at, sparrow_version)
             VALUES ('hawk', '/x/Hawk_Contoso_20260920_000000', TIMESTAMPTZ '2026-09-20 00:00:00+00', 't')
             RETURNING collection_id",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let f: i64 = case
        .conn()
        .query_row(
            "INSERT INTO source_files (collection_id, rel_path, artifact_type, size_bytes, sha256, status)
             VALUES (?, 'Tenant/x.json', 'hawk.tenant.raw_ual', 1, 'h', 'parsed') RETURNING file_id",
            params![c],
            |r| r.get(0),
        )
        .unwrap();
    ual(
        &case,
        c,
        f,
        "11111111-1111-4111-8111-111111111111",
        "2026-09-01 10:00:00+00",
        "Exchange",
    );
    (case, c, f)
}

fn ual(case: &Case, c: i64, f: i64, id: &str, at: &str, workload: &str) {
    case.conn()
        .execute(
            "INSERT INTO ual_events (record_id, collection_id, event_time, time_tz_assumed, time_precision,
                 organization_id, workload, audit_data, data_completeness, synthetic_id)
             VALUES (CAST(? AS UUID), ?, CAST(? AS TIMESTAMPTZ), false, 'second', CAST(? AS UUID), ?, '{}', 'full', false)",
            params![id, c, at, T1, workload],
        )
        .unwrap();
    case.conn()
        .execute(
            "INSERT INTO record_sources VALUES ('ual_events', ?, ?, 0, 1, 1, 0, 1, 'h')",
            params![id, f],
        )
        .unwrap();
}

fn status(case: &mut Case, cap: &str) -> String {
    refresh(case, &ProfileOptions::default()).unwrap();
    let caps = tenant_capabilities(case.conn(), T1).unwrap();
    let c = caps.iter().find(|c| c.capability_id == cap).unwrap();
    format!("{}/{}", c.status, c.confidence.clone().unwrap_or_default())
}

#[test]
fn baseline_capabilities_are_assumed_and_others_unknown_without_evidence() {
    let (mut case, _, _) = tenant_case();
    assert_eq!(status(&mut case, "ual_standard"), "licensed/low");
    assert_eq!(status(&mut case, "audit_premium"), "unknown/");
    assert_eq!(status(&mut case, "identity_protection"), "unknown/");
}

#[test]
fn a_high_confidence_licence_list_decides_both_ways() {
    let (mut case, c, _) = tenant_case();
    case.conn()
        .execute(
            "INSERT INTO licenses (record_key, collection_id, source, sku_part_number, capability_status, service_plans, confidence)
             VALUES (?, ?, 'invictus_tenant_licenses', 'SPB', 'Enabled', ['EXCHANGE_S_STANDARD', 'AAD_PREMIUM', 'ATP_ENTERPRISE '], 'high')",
            params![format!("{c}|invictus_tenant_licenses|spb"), c],
        )
        .unwrap();
    assert_eq!(status(&mut case, "entra_id_p1"), "licensed/high");
    assert_eq!(
        status(&mut case, "mdo_p1"),
        "licensed/high",
        "trailing space ignored"
    );
    assert_eq!(status(&mut case, "audit_premium"), "not_licensed/high");
    assert_eq!(
        status(&mut case, "identity_protection"),
        "not_licensed/high"
    );
}

#[test]
fn hawk_tier_is_a_low_confidence_hint() {
    let (mut case, c, _) = tenant_case();
    case.conn()
        .execute(
            "INSERT INTO licenses (record_key, collection_id, source, license_tier, confidence)
             VALUES (?, ?, 'hawk_log', 'E5', 'low')",
            params![format!("{c}|hawk_log|e5"), c],
        )
        .unwrap();
    assert_eq!(status(&mut case, "audit_premium"), "licensed/low");
    assert_eq!(
        status(&mut case, "entra_id_p1"),
        "unknown/",
        "Hawk E5 includes Office 365 E5, which has no P1"
    );
}

#[test]
fn evidence_signals_prove_or_disprove_premium_features() {
    let (mut case, c, f) = tenant_case();
    // A UAL record 200 days older than the collection: Audit (Premium) retention.
    ual(
        &case,
        c,
        f,
        "22222222-2222-4222-8222-222222222222",
        "2026-03-04 10:00:00+00",
        "Exchange",
    );
    // Sign-ins downloaded through Graph with risk hidden.
    case.conn()
        .execute_batch(&format!(
            "INSERT INTO source_files (file_id, collection_id, rel_path, artifact_type, size_bytes, sha256, status)
                 VALUES (900, {c}, 'u/Entra_Sign_In_Log.json', 'hawk.user.entra_signin', 1, 's', 'parsed');
             INSERT INTO signins (record_key, collection_id, risk_level_during, risk_level_aggregated)
                 VALUES ('s1', {c}, 'hidden', 'hidden');
             INSERT INTO record_sources VALUES ('signins', 's1', 900, 0, 1, 1, 0, 1, 'h');"
        ))
        .unwrap();
    assert_eq!(status(&mut case, "audit_premium"), "licensed/high");
    assert_eq!(status(&mut case, "entra_id_p1"), "licensed/high");
    assert_eq!(
        status(&mut case, "identity_protection"),
        "not_licensed/high"
    );
    case.conn()
        .execute("UPDATE signins SET risk_level_during = 'low'", [])
        .unwrap();
    assert_eq!(status(&mut case, "identity_protection"), "licensed/high");
}

#[test]
fn conflicting_high_signals_resolve_to_licensed_and_say_so() {
    let (mut case, c, _) = tenant_case();
    case.conn()
        .execute_batch(&format!(
            "INSERT INTO tenant_settings (record_key, collection_id, source, name, value)
                 VALUES ('{c}|entra_security_defaults|haspremiumlicense', {c}, 'entra_security_defaults', 'HasPremiumLicense', '\"No\"');
             INSERT INTO source_files (file_id, collection_id, rel_path, artifact_type, size_bytes, sha256, status)
                 VALUES (901, {c}, 'EntraID/x-SignInLogs.json', 'inv.signins', 1, 't', 'parsed');
             INSERT INTO signins (record_key, collection_id) VALUES ('s2', {c});
             INSERT INTO record_sources VALUES ('signins', 's2', 901, 0, 1, 1, 0, 1, 'h');"
        ))
        .unwrap();
    assert_eq!(status(&mut case, "entra_id_p1"), "licensed/high");
    let basis: String = case
        .conn()
        .query_row(
            "SELECT basis FROM tenant_capabilities WHERE capability_id = 'entra_id_p1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(basis.contains("HasPremiumLicense"), "{basis}");
}
