use duckdb::params;
use sparrow_core::Case;
use sparrow_core::Error;
use sparrow_core::profile::tenant::{DomainAction, list_domains, set_domain};
use sparrow_core::profile::{ProfileOptions, refresh};

const T1: &str = "c9c9c9c9-0000-4000-8000-000000000001";
const T2: &str = "d8d8d8d8-0000-4000-8000-000000000002";

fn collection(case: &Case, root: &str, name: Option<&str>, at: &str) -> i64 {
    case.conn()
        .query_row(
            "INSERT INTO collections (tool, root_path, tenant_name_reported, collected_at, sparrow_version)
             VALUES ('hawk', ?, ?, CAST(? AS TIMESTAMPTZ), 't') RETURNING collection_id",
            params![root, name, at],
            |r| r.get(0),
        )
        .unwrap()
}

fn file(case: &Case, c: i64) -> i64 {
    case.conn()
        .query_row(
            "INSERT INTO source_files (collection_id, rel_path, size_bytes, sha256, status)
             VALUES (?, 'f.json', 1, 'h' || ?, 'parsed') RETURNING file_id",
            params![c, c],
            |r| r.get(0),
        )
        .unwrap()
}

/// A UAL row of tenant `org` sighted in `file_id`.
fn ual(case: &Case, c: i64, file_id: i64, id: &str, org: &str, upn: &str) {
    case.conn()
        .execute(
            "INSERT INTO ual_events (record_id, collection_id, event_time, time_tz_assumed, time_precision,
                 organization_id, user_upn, audit_data, data_completeness, synthetic_id)
             VALUES (CAST(? AS UUID), ?, TIMESTAMPTZ '2026-09-01 10:00:00+00', false, 'second',
                 CAST(? AS UUID), ?, '{}', 'full', false)",
            params![id, c, org, upn],
        )
        .unwrap();
    case.conn()
        .execute(
            "INSERT INTO record_sources VALUES ('ual_events', ?, ?, 0, 1, 1, 0, 1, 'h')",
            params![id, file_id],
        )
        .unwrap();
}

fn text(case: &Case, sql: &str) -> String {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn collections_are_grouped_by_tenant_id_and_names_join_their_id() {
    let mut case = Case::in_memory().unwrap();
    let a = collection(
        &case,
        "/x/Hawk_Contoso_20260901_000000",
        Some("Contoso"),
        "2026-09-01T00:00:00Z",
    );
    let b = collection(
        &case,
        "/x/Hawk_Fabrikam_20260902_000000",
        Some("Fabrikam"),
        "2026-09-02T00:00:00Z",
    );
    let c = collection(
        &case,
        "/x/Hawk_Contoso_20260903_000000",
        Some("contoso"),
        "2026-09-03T00:00:00Z",
    );
    let d = collection(&case, "/x/Output", None, "2026-09-04T00:00:00Z");
    let (fa, fb) = (file(&case, a), file(&case, b));
    ual(
        &case,
        a,
        fa,
        "11111111-1111-4111-8111-111111111111",
        T1,
        "alice@contoso.example",
    );
    ual(
        &case,
        b,
        fb,
        "22222222-2222-4222-8222-222222222222",
        T2,
        "erin@fabrikam.example",
    );
    let report = refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(report.tenants, 3);
    let key = |id: i64| {
        text(
            &case,
            &format!("SELECT tenant_key FROM collections WHERE collection_id = {id}"),
        )
    };
    assert_eq!(key(a), T1);
    assert_eq!(key(b), T2);
    assert_eq!(key(c), T1, "same name as a collection with an id");
    assert_eq!(key(d), format!("collection:{d}"));
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT tenant_name || '|' || tenant_id_source FROM tenant WHERE tenant_key = '{T1}'"
            )
        ),
        "contoso|ual_organization_id",
        "name from the newest collection that reported one"
    );
}

#[test]
fn a_record_first_loaded_by_another_collection_still_counts_for_its_sighting_collection() {
    let mut case = Case::in_memory().unwrap();
    let a = collection(&case, "/x/A", None, "2026-09-01T00:00:00Z");
    let b = collection(&case, "/x/B", None, "2026-09-02T00:00:00Z");
    let (fa, fb) = (file(&case, a), file(&case, b));
    ual(
        &case,
        a,
        fa,
        "11111111-1111-4111-8111-111111111111",
        T1,
        "alice@contoso.example",
    );
    case.conn()
        .execute(
            "INSERT INTO record_sources VALUES ('ual_events', '11111111-1111-4111-8111-111111111111', ?, 0, 1, 1, 0, 1, 'h')",
            params![fb],
        )
        .unwrap();
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(
        count(
            &case,
            &format!("SELECT count(*) FROM collections WHERE tenant_key = '{T1}'")
        ),
        2
    );
}

#[test]
fn domains_are_derived_and_analyst_overrides_survive_a_refresh() {
    let mut case = Case::in_memory().unwrap();
    let a = collection(&case, "/x/A", Some("Contoso"), "2026-09-01T00:00:00Z");
    let fa = file(&case, a);
    ual(
        &case,
        a,
        fa,
        "11111111-1111-4111-8111-111111111111",
        T1,
        "alice@contoso.example",
    );
    case.conn()
        .execute_batch(&format!(
            "INSERT INTO users (record_key, collection_id, upn, user_type) VALUES
                 ('u1', {a}, 'alice@contoso.example', 'Member'),
                 ('u2', {a}, 'bob@contoso.onmicrosoft.example', NULL),
                 ('u3', {a}, 'guest_fabrikam.example#ext#@contoso.onmicrosoft.example', 'Guest');
             INSERT INTO message_trace (record_key, collection_id, organization) VALUES ('m1', {a}, 'contoso.onmicrosoft.example');"
        ))
        .unwrap();
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let domains = |case: &Case| {
        list_domains(case, None)
            .unwrap()
            .into_iter()
            .map(|d| format!("{}:{}", d.domain, d.source))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        domains(&case),
        vec![
            "contoso.example:derived_upn",
            "contoso.onmicrosoft.example:derived_upn"
        ]
    );
    set_domain(
        &mut case,
        None,
        "Contoso.Example",
        DomainAction::Remove,
        "analyst:test",
    )
    .unwrap();
    set_domain(
        &mut case,
        None,
        "contoso-legacy.example",
        DomainAction::Add,
        "analyst:test",
    )
    .unwrap();
    let expect = vec![
        "contoso-legacy.example:analyst",
        "contoso.onmicrosoft.example:derived_upn",
    ];
    assert_eq!(domains(&case), expect);
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(
        domains(&case),
        expect,
        "overrides survive a new profile run"
    );
}

/// Regression (fix round 1, critical): `resolve_tenants` used to only ever set a NULL
/// `tenant_key`, so a name-only collection's stale `name:<n>` key could never be revisited once
/// a later collection of the same tenant supplied id evidence.
#[test]
fn a_name_only_collection_moves_onto_id_evidence_a_later_collection_of_the_same_tenant_brings() {
    let mut case = Case::in_memory().unwrap();
    let a = collection(&case, "/x/A", Some("Contoso"), "2026-09-01T00:00:00Z");
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(
        text(
            &case,
            &format!("SELECT tenant_key FROM collections WHERE collection_id = {a}")
        ),
        "name:contoso"
    );

    let b = collection(&case, "/x/B", Some("Contoso"), "2026-09-02T00:00:00Z");
    let fb = file(&case, b);
    ual(
        &case,
        b,
        fb,
        "33333333-3333-4333-8333-333333333333",
        T1,
        "alice@contoso.example",
    );
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let key = |id: i64| {
        text(
            &case,
            &format!("SELECT tenant_key FROM collections WHERE collection_id = {id}"),
        )
    };
    assert_eq!(key(a), T1, "the stale name:contoso key is revisited");
    assert_eq!(key(b), T1);
    assert_eq!(
        count(&case, "SELECT count(*) FROM tenant"),
        1,
        "a and b merge into one tenant, not two"
    );
}

/// Regression (fix round 1, important — controller ruling): an override written while the
/// tenant only had a name:<n> key must not be orphaned once resolve_tenants replaces that key
/// with the tenant's Entra id; rebuild_domains remaps it by tenant_name instead.
#[test]
fn an_override_on_a_name_only_tenant_moves_with_it_once_evidence_resolves_an_id() {
    let mut case = Case::in_memory().unwrap();
    let a = collection(&case, "/x/A", Some("Contoso"), "2026-09-01T00:00:00Z");
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(
        text(
            &case,
            &format!("SELECT tenant_key FROM collections WHERE collection_id = {a}")
        ),
        "name:contoso"
    );

    set_domain(
        &mut case,
        None,
        "contoso-legacy.example",
        DomainAction::Add,
        "analyst:test",
    )
    .unwrap();
    assert_eq!(
        text(
            &case,
            "SELECT tenant_key FROM tenant_domain_overrides WHERE domain = 'contoso-legacy.example'"
        ),
        "name:contoso",
        "the override is recorded under the tenant's key at the time"
    );

    let fa = file(&case, a);
    ual(
        &case,
        a,
        fa,
        "44444444-4444-4444-8444-444444444444",
        T1,
        "alice@contoso.example",
    );
    let report = refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(
        text(
            &case,
            &format!("SELECT tenant_key FROM collections WHERE collection_id = {a}")
        ),
        T1
    );
    let domains = list_domains(&case, None)
        .unwrap()
        .into_iter()
        .map(|d| format!("{}:{}:{}", d.tenant_key, d.domain, d.source))
        .collect::<Vec<_>>();
    assert!(
        domains.contains(&format!("{T1}:contoso-legacy.example:analyst")),
        "{domains:?}"
    );
    assert!(
        report
            .warnings
            .iter()
            .all(|w| !w.contains("analyst domain decisions")),
        "the override resolved, so no orphan warning: {:?}",
        report.warnings
    );
}

/// Regression (fix round 1, important): an override whose tenant no longer exists at all (not
/// even by name) produces a profile warning instead of being silently dropped or applied nowhere.
#[test]
fn an_override_that_matches_no_tenant_by_key_or_name_produces_a_warning() {
    let mut case = Case::in_memory().unwrap();
    collection(&case, "/x/A", Some("Contoso"), "2026-09-01T00:00:00Z");
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    // Simulate a stale override from a tenant that has since vanished entirely (its case was
    // merged elsewhere, or the collection was removed): no current tenant has this key or
    // reports this name, so it can never be remapped.
    case.conn()
        .execute(
            "INSERT INTO tenant_domain_overrides (tenant_key, domain, action, actor)
             VALUES ('name:ghostco', 'ghost.example', 'add', 'analyst:test')",
            [],
        )
        .unwrap();
    let report = refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert!(
        report.warnings.iter().any(|w| {
            w.contains("1 analyst domain decisions refer to tenants no longer in the case")
                && w.contains("name:ghostco")
        }),
        "{:?}",
        report.warnings
    );
    assert!(
        !list_domains(&case, None)
            .unwrap()
            .iter()
            .any(|d| d.domain == "ghost.example"),
        "an unresolved override is never applied"
    );
}

/// Regression (fix round 1, minor): two decisions on the same domain sharing `changed_at`
/// (as two overrides recorded in one transaction can) must still resolve deterministically —
/// the later insertion wins, not an arbitrary tie.
#[test]
fn overrides_with_the_same_changed_at_break_ties_by_insertion_order() {
    let mut case = Case::in_memory().unwrap();
    collection(&case, "/x/A", Some("Contoso"), "2026-09-01T00:00:00Z");
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let key = text(&case, "SELECT tenant_key FROM tenant");
    case.conn()
        .execute_batch(&format!(
            "INSERT INTO tenant_domain_overrides (tenant_key, domain, action, actor, changed_at) VALUES
                 ('{key}', 'tie.example', 'add', 'analyst:test', TIMESTAMPTZ '2026-09-10 00:00:00+00'),
                 ('{key}', 'tie.example', 'remove', 'analyst:test', TIMESTAMPTZ '2026-09-10 00:00:00+00');"
        ))
        .unwrap();
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert!(
        !list_domains(&case, None)
            .unwrap()
            .iter()
            .any(|d| d.domain == "tie.example"),
        "the later-inserted decision (remove) wins the tie"
    );
}

/// Regression (fix round 1, minor): a zero-tenant case (no collections ingested yet, or none
/// with any evidence at all) should point the analyst at `sparrow profile`/`sparrow ingest`
/// rather than the nonsensical "the case has 0 tenants; pass --tenant (one of: )".
#[test]
fn set_domain_on_a_zero_tenant_case_names_profile_or_ingest() {
    let mut case = Case::in_memory().unwrap();
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM tenant"), 0);
    let err = set_domain(
        &mut case,
        None,
        "x.example",
        DomainAction::Add,
        "analyst:test",
    )
    .expect_err("no tenants yet");
    let Error::Invalid(msg) = err else {
        panic!("expected Error::Invalid, got {err:?}");
    };
    assert!(msg.contains("sparrow profile"), "{msg}");
    assert!(msg.contains("sparrow ingest"), "{msg}");
}

#[test]
fn tenant_audit_config_takes_each_column_from_the_newest_collection_that_provided_it() {
    let mut case = Case::in_memory().unwrap();
    let old = collection(
        &case,
        "/x/Hawk_Contoso_20260901_000000",
        Some("Contoso"),
        "2026-09-01T00:00:00Z",
    );
    let new = collection(
        &case,
        "/x/Hawk_Contoso_20260920_000000",
        Some("Contoso"),
        "2026-09-20T00:00:00Z",
    );
    // Old capture: OrgConfig (audit_disabled) and AdminAuditLogConfig. New capture: only
    // AdminAuditLogConfig, which leaves audit_disabled unclaimed.
    case.conn()
        .execute_batch(&format!(
            "INSERT INTO audit_config (record_key, collection_id, audit_disabled, unified_audit_log_ingestion_enabled, column_collections)
                 VALUES ('organization|{old}', {old}, true, true, '{{\"audit_disabled\": {old}, \"unified_audit_log_ingestion_enabled\": {old}}}');
             INSERT INTO audit_config (record_key, collection_id, unified_audit_log_ingestion_enabled, column_collections)
                 VALUES ('organization|{new}', {new}, false, '{{\"unified_audit_log_ingestion_enabled\": {new}}}');
             INSERT INTO tenant_settings (record_key, collection_id, source, name, value) VALUES
                 ('{old}|organization_config|name', {old}, 'organization_config', 'Name', '\"Old\"'),
                 ('{new}|organization_config|name', {new}, 'organization_config', 'Name', '\"New\"');"
        ))
        .unwrap();
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM tenant_audit_config"), 1);
    assert_eq!(
        text(
            &case,
            "SELECT audit_disabled || '|' || unified_audit_log_ingestion_enabled FROM tenant_audit_config"
        ),
        "true|false"
    );
    assert_eq!(
        text(
            &case,
            "SELECT value->>'$' FROM tenant_settings_current WHERE lower(name) = 'name'"
        ),
        "New"
    );
}
