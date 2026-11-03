use duckdb::params;
use sparrow_core::Case;
use sparrow_core::Error;
use sparrow_core::profile::tenant::{DomainAction, list_domains, set_domain};
use sparrow_core::profile::{ProfileOptions, refresh};

const T1: &str = "c9c9c9c9-0000-4000-8000-000000000001";
const T2: &str = "d8d8d8d8-0000-4000-8000-000000000002";

fn collection(case: &Case, root: &str, name: Option<&str>, at: &str) -> i64 {
    collection_maybe_at(case, root, name, Some(at))
}

/// Like `collection`, but `at` may be `None` (a collection whose collected_at is unknown, e.g. a
/// Hawk capture whose root folder does not carry a `Hawk_<tenant>_<timestamp>` name).
fn collection_maybe_at(case: &Case, root: &str, name: Option<&str>, at: Option<&str>) -> i64 {
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
    let standalone: Vec<&String> = report
        .warnings
        .iter()
        .filter(|w| w.contains("carries no tenant id or name"))
        .collect();
    assert_eq!(
        standalone,
        vec![&format!(
            "collection {d} (Output) carries no tenant id or name; it is profiled as its own tenant `collection:{d}`"
        )],
        "{:?}",
        report.warnings
    );
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

/// Regression (Task 11 review, fix round 1): `resolve_tenants`'s `names` CTE used to compute
/// `arg_max(name, collected_at)`, which DuckDB evaluates to NULL for a group whose every row has
/// a NULL `collected_at` - so a tenant known only from a collection whose root folder does not
/// carry a `Hawk_<tenant>_<timestamp>` name (collected_at unknown) never got a `tenant_name` at
/// all, even though its Hawk.log reported one.
#[test]
fn a_name_only_collection_with_unknown_collected_at_still_sets_the_tenant_name() {
    let mut case = Case::in_memory().unwrap();
    collection_maybe_at(&case, "/x/capture-events", Some("Contoso"), None);
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(
        text(
            &case,
            "SELECT tenant_name FROM tenant WHERE tenant_key = 'name:contoso'"
        ),
        "contoso"
    );
}

/// The fixed `names` CTE ranks by `collected_at DESC NULLS LAST, collection_id DESC`: a reported
/// name whose collection has a known `collected_at` always outranks one whose collection has
/// none, whatever the two collection_ids or the known date happen to be.
#[test]
fn a_named_collection_with_a_known_time_beats_one_with_an_unknown_time() {
    let mut case = Case::in_memory().unwrap();
    let a = collection_maybe_at(&case, "/x/A", Some("OldName"), None);
    let b = collection_maybe_at(&case, "/x/B", Some("NewName"), Some("2026-09-02T00:00:00Z"));
    let (fa, fb) = (file(&case, a), file(&case, b));
    ual(
        &case,
        a,
        fa,
        "44444444-4444-4444-8444-444444444441",
        T1,
        "alice@contoso.example",
    );
    ual(
        &case,
        b,
        fb,
        "44444444-4444-4444-8444-444444444442",
        T1,
        "alice@contoso.example",
    );
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(
        text(
            &case,
            &format!("SELECT tenant_name FROM tenant WHERE tenant_key = '{T1}'")
        ),
        "newname",
        "the collection with a known collected_at wins over the one with none"
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

/// Two tenants reporting the same name: an override keyed `name:<n>` resolves to the smallest
/// tenant_key, every run (the remap subquery is ordered).
#[test]
fn a_name_override_shared_by_two_tenants_resolves_to_the_smallest_key() {
    let mut case = Case::in_memory().unwrap();
    let a = collection(
        &case,
        "/x/Hawk_Contoso_20260901_000000",
        Some("Contoso"),
        "2026-09-01T00:00:00Z",
    );
    let b = collection(
        &case,
        "/x/Hawk_Contoso_20260902_000000",
        Some("Contoso"),
        "2026-09-02T00:00:00Z",
    );
    let (fa, fb) = (file(&case, a), file(&case, b));
    ual(
        &case,
        b,
        fb,
        "22222222-2222-4222-8222-222222222222",
        T2,
        "erin@contoso.example",
    );
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
            "INSERT INTO tenant_domain_overrides (tenant_key, domain, action, actor)
             VALUES ('name:contoso', 'extra.example', 'add', 'analyst:t')",
            [],
        )
        .unwrap();
    for _ in 0..3 {
        refresh(&mut case, &ProfileOptions::default()).unwrap();
        assert_eq!(
            text(
                &case,
                "SELECT string_agg(tenant_key, ',') FROM tenant_domains WHERE domain = 'extra.example'"
            ),
            T1
        );
    }
}

/// A `message_trace_events` row of `tenant` sighted in `file_id`.
fn trace_event(case: &Case, file_id: i64, key: &str, tenant: &str) {
    case.conn()
        .execute(
            "INSERT INTO message_trace_events (record_key, collection_id, tenant_id, raw)
             VALUES (?, 1, ?, '{}')",
            params![key, tenant],
        )
        .unwrap();
    case.conn()
        .execute(
            "INSERT INTO record_sources VALUES ('message_trace_events', ?, ?, 0, 1, 1, 0, 1, 'h')",
            params![key, file_id],
        )
        .unwrap();
}

/// A `directory_audits` row whose raw is `raw`, sighted in `file_id`.
fn audit(case: &Case, file_id: i64, key: &str, raw: &str) {
    case.conn()
        .execute(
            "INSERT INTO directory_audits (record_key, collection_id, raw) VALUES (?, 1, CAST(? AS JSON))",
            params![key, raw],
        )
        .unwrap();
    case.conn()
        .execute(
            "INSERT INTO record_sources VALUES ('directory_audits', ?, ?, 0, 1, 1, 0, 1, 'h')",
            params![key, file_id],
        )
        .unwrap();
}

#[test]
fn message_trace_detail_and_portal_entra_audit_collections_resolve_to_their_tenant() {
    let mut case = Case::in_memory().unwrap();
    let ual_c = collection(&case, "/a", None, "2026-09-10 00:00:00+00");
    let detail_c = collection(&case, "/b", None, "2026-09-10 00:00:00+00");
    let audit_c = collection(&case, "/c", None, "2026-09-10 00:00:00+00");
    let guest_c = collection(&case, "/d", None, "2026-09-10 00:00:00+00");
    let upper = T1.to_uppercase();
    ual(
        &case,
        ual_c,
        file(&case, ual_c),
        "00000000-0000-4000-8000-0000000000a1",
        T1,
        "a@contoso.example",
    );
    let detail_f = file(&case, detail_c);
    trace_event(&case, detail_f, "csvrow:1", &upper);
    trace_event(&case, detail_f, "csvrow:2", &upper);
    trace_event(&case, detail_f, "csvrow:3", "");
    let audit_f = file(&case, audit_c);
    portal_audit_file(&case, audit_f);
    // Key case differs from the CSV header's; a row without ActorType User, or without the cell, adds nothing.
    audit(
        &case,
        audit_f,
        "csvrow:a",
        &format!("{{\"actorhometenantid\":\"{upper}\",\"ActorType\":\"User\"}}"),
    );
    audit(
        &case,
        audit_f,
        "csvrow:b",
        &format!("{{\"ActorHomeTenantId\":\"{T2}\",\"ActorType\":\"Application\"}}"),
    );
    audit(&case, audit_f, "csvrow:c", "{\"ActorType\":\"User\"}");
    audit(&case, audit_f, "csvrow:d", "{\"Id\":\"x\"}");
    // A collection of audit rows whose only tenant evidence is a user actor from T2.
    let guest_f = file(&case, guest_c);
    portal_audit_file(&case, guest_f);
    audit(
        &case,
        guest_f,
        "csvrow:g",
        &format!("{{\"ActorHomeTenantId\":\"{T2}\",\"ActorType\":\"User\"}}"),
    );
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let key = |c: i64| {
        text(
            &case,
            &format!("SELECT tenant_key FROM collections WHERE collection_id = {c}"),
        )
    };
    assert_eq!(key(ual_c), T1);
    assert_eq!(key(detail_c), T1);
    assert_eq!(key(audit_c), T1);
    assert_eq!(key(guest_c), T2);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM tenant WHERE tenant_key LIKE 'collection:%'"
        ),
        0
    );
    assert_eq!(
        text(
            &case,
            &format!("SELECT tenant_id_source FROM tenant WHERE tenant_key = '{T1}'")
        ),
        "message_trace_tenant"
    );
    assert_eq!(
        count(
            &case,
            &format!("SELECT collections FROM tenant WHERE tenant_key = '{T1}'"),
        ),
        3
    );
}

/// Mark `file_id` as a portal Entra audit download (the audit fallback only counts those files).
fn portal_audit_file(case: &Case, file_id: i64) {
    case.conn()
        .execute(
            "UPDATE source_files SET artifact_type = 'portal.entra_audit' WHERE file_id = ?",
            params![file_id],
        )
        .unwrap();
}

#[test]
fn guest_actor_rows_never_outvote_other_tenant_evidence_and_only_portal_files_count() {
    let mut case = Case::in_memory().unwrap();
    // One UAL sighting for T1 and two portal user-actor rows from guests whose home tenant is T2: T1.
    let mixed = collection(&case, "/a", None, "2026-09-10 00:00:00+00");
    let mixed_ual = file(&case, mixed);
    ual(
        &case,
        mixed,
        mixed_ual,
        "00000000-0000-4000-8000-0000000000b1",
        T1,
        "a@contoso.example",
    );
    let mixed_audit = file(&case, mixed);
    portal_audit_file(&case, mixed_audit);
    for k in ["g1", "g2"] {
        audit(
            &case,
            mixed_audit,
            k,
            &format!("{{\"ActorHomeTenantId\":\"{T2}\",\"ActorType\":\"User\"}}"),
        );
    }
    // A collection with only portal audit rows still resolves from them.
    let only = collection(&case, "/b", None, "2026-09-10 00:00:00+00");
    let only_f = file(&case, only);
    portal_audit_file(&case, only_f);
    audit(
        &case,
        only_f,
        "o1",
        &format!("{{\"ActorHomeTenantId\":\"{T2}\",\"ActorType\":\"User\"}}"),
    );
    // A Hawk JSON audit carrying the same keys adds nothing: the collection stands alone.
    let hawk = collection(&case, "/c", None, "2026-09-10 00:00:00+00");
    let hawk_f = file(&case, hawk);
    case.conn()
        .execute(
            "UPDATE source_files SET artifact_type = 'hawk.tenant.entra_audit' WHERE file_id = ?",
            params![hawk_f],
        )
        .unwrap();
    audit(
        &case,
        hawk_f,
        "h1",
        &format!("{{\"ActorHomeTenantId\":\"{T1}\",\"ActorType\":\"User\"}}"),
    );
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let key = |c: i64| {
        text(
            &case,
            &format!("SELECT tenant_key FROM collections WHERE collection_id = {c}"),
        )
    };
    assert_eq!(key(mixed), T1);
    assert_eq!(key(only), T2);
    assert_eq!(key(hawk), format!("collection:{hawk}"));
}

/// A sign-in of `upn` in tenant `tenant` (home and resource), sighted in `file_id`.
fn signin(case: &Case, c: i64, file_id: i64, key: &str, tenant: &str, upn: &str) {
    case.conn()
        .execute(
            "INSERT INTO signins (record_key, collection_id, user_upn, home_tenant_id, resource_tenant_id)
             VALUES (?, ?, ?, ?, ?)",
            params![key, c, upn, tenant, tenant],
        )
        .unwrap();
    case.conn()
        .execute(
            "INSERT INTO record_sources VALUES ('signins', ?, ?, 0, 1, 1, 0, 1, 'h')",
            params![key, file_id],
        )
        .unwrap();
}

/// A portal-style `directory_audits` row with an actor UPN and target UPNs (no tenant id anywhere), sighted in
/// `file_id`.
fn audit_upns(case: &Case, file_id: i64, key: &str, actor: &str, targets: &[&str]) {
    let targets: Vec<serde_json::Value> = targets
        .iter()
        .map(|t| serde_json::json!({ "type": "User", "userPrincipalName": t }))
        .collect();
    case.conn()
        .execute(
            "INSERT INTO directory_audits (record_key, collection_id, initiated_by_upn, targets, raw)
             VALUES (?, 1, ?, CAST(? AS JSON), '{}')",
            params![key, actor, serde_json::Value::Array(targets).to_string()],
        )
        .unwrap();
    case.conn()
        .execute(
            "INSERT INTO record_sources VALUES ('directory_audits', ?, ?, 0, 1, 1, 0, 1, 'h')",
            params![key, file_id],
        )
        .unwrap();
}

#[test]
fn a_collection_with_no_tenant_id_or_name_joins_the_tenant_that_owns_most_of_its_upn_domains() {
    let mut case = Case::in_memory().unwrap();
    // Two identified tenants; shared.example is seen in both, so it tells them apart from neither.
    let t1 = collection(&case, "/t1", None, "2026-09-10 00:00:00+00");
    let t1_f = file(&case, t1);
    signin(&case, t1, t1_f, "s1", T1, "a@contoso.example");
    signin(&case, t1, t1_f, "s2", T1, "x@shared.example");
    let t2 = collection(&case, "/t2", None, "2026-09-10 00:00:00+00");
    let t2_f = file(&case, t2);
    signin(&case, t2, t2_f, "s3", T2, "b@fabrikam.example");
    signin(&case, t2, t2_f, "s4", T2, "y@shared.example");

    // Two of its three UPNs are on T1's domain (the actor's onmicrosoft domain is unknown): it joins T1.
    let joins = collection(&case, "/joins", None, "2026-09-10 00:00:00+00");
    let joins_f = file(&case, joins);
    audit_upns(
        &case,
        joins_f,
        "j1",
        "admin@unknown.onmicrosoft.example",
        &["Alice@Contoso.example"],
    );
    audit_upns(&case, joins_f, "j2", "", &["carol@contoso.example"]);
    // Only one of its three users (the actor does not vote): no majority, so it stands alone.
    let minority = collection(&case, "/minority", None, "2026-09-10 00:00:00+00");
    let minority_f = file(&case, minority);
    audit_upns(
        &case,
        minority_f,
        "m1",
        "admin@contoso.example",
        &[
            "alice@contoso.example",
            "z@unknown.example",
            "w@unknown.example",
        ],
    );
    // Only the domain both tenants have: no tenant owns it.
    let shared = collection(&case, "/shared", None, "2026-09-10 00:00:00+00");
    let shared_f = file(&case, shared);
    audit_upns(
        &case,
        shared_f,
        "h1",
        "p@shared.example",
        &["q@shared.example"],
    );
    // Guests of T1 (#EXT# UPNs on T1's domain) say nothing about which tenant this is.
    let guests = collection(&case, "/guests", None, "2026-09-10 00:00:00+00");
    let guests_f = file(&case, guests);
    audit_upns(
        &case,
        guests_f,
        "g1",
        "admin@unknown.example",
        &[
            "bob_fabrikam.example#EXT#@contoso.example",
            "eve_x.example#EXT#@contoso.example",
        ],
    );

    let report = refresh(&mut case, &ProfileOptions::default()).unwrap();
    let joined: Vec<_> = report
        .warnings
        .iter()
        .filter(|w| w.contains("it joined tenant"))
        .collect();
    assert_eq!(joined.len(), 1, "{:?}", report.warnings);
    assert!(
        joined[0].contains(&format!("collection {joins} (joins)"))
            && joined[0].contains(&format!(
                "tenant {T1} because 2 of the 2 users its rows are about"
            )),
        "{joined:?}"
    );
    let key = |c: i64| {
        text(
            &case,
            &format!("SELECT tenant_key FROM collections WHERE collection_id = {c}"),
        )
    };
    assert_eq!(key(t1), T1);
    assert_eq!(key(t2), T2);
    assert_eq!(key(joins), T1);
    assert_eq!(key(minority), format!("collection:{minority}"));
    assert_eq!(key(shared), format!("collection:{shared}"));
    assert_eq!(key(guests), format!("collection:{guests}"));
    assert_eq!(
        count(
            &case,
            &format!("SELECT collections FROM tenant WHERE tenant_key = '{T1}'")
        ),
        2
    );
}

#[test]
fn a_collection_with_a_reported_name_is_not_joined_by_domain() {
    let mut case = Case::in_memory().unwrap();
    let t1 = collection(&case, "/t1", None, "2026-09-10 00:00:00+00");
    let t1_f = file(&case, t1);
    signin(&case, t1, t1_f, "s1", T1, "a@contoso.example");
    let named = collection(&case, "/named", Some("Fabrikam"), "2026-09-10 00:00:00+00");
    let named_f = file(&case, named);
    audit_upns(
        &case,
        named_f,
        "n1",
        "a@contoso.example",
        &["b@contoso.example"],
    );
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(
        text(
            &case,
            &format!("SELECT tenant_key FROM collections WHERE collection_id = {named}")
        ),
        "name:fabrikam"
    );
}

/// An analyst domain override row, as `set_domain` writes it (on a key that may no longer name a tenant).
fn domain_override(case: &Case, tenant_key: &str, domain: &str, action: &str) {
    case.conn()
        .execute(
            "INSERT INTO tenant_domain_overrides (tenant_key, domain, action, actor) VALUES (?, ?, CAST(? AS domain_action), 'analyst:t')",
            params![tenant_key, domain, action],
        )
        .unwrap();
}

#[test]
fn the_domain_join_counts_distinct_users_not_actors_and_honours_domain_overrides() {
    let mut case = Case::in_memory().unwrap();
    // An MSP's own tenant (T1, msp.example) and a customer (T2) whose Hawk capture also reports its name.
    let msp = collection(&case, "/msp", None, "2026-09-10 00:00:00+00");
    let msp_f = file(&case, msp);
    signin(&case, msp, msp_f, "s1", T1, "tech@msp.example");
    let customer = collection(&case, "/cust", Some("Fabrikam"), "2026-09-10 00:00:00+00");
    let cust_f = file(&case, customer);
    signin(&case, customer, cust_f, "s2", T2, "x@fabrikam.example");

    // The customer's audit download: MSP technicians acting on many rows, on one customer user.
    let audit_c = collection(&case, "/audit", None, "2026-09-10 00:00:00+00");
    let audit_f = file(&case, audit_c);
    for i in 0..5 {
        audit_upns(&case, audit_f, &format!("a{i}"), "tech@msp.example", &[]);
    }
    audit_upns(
        &case,
        audit_f,
        "a9",
        "tech@msp.example",
        &["bob@fabrikam.example"],
    );
    // Exactly half (one user of two): not a majority.
    let half = collection(&case, "/half", None, "2026-09-10 00:00:00+00");
    let half_f = file(&case, half);
    audit_upns(
        &case,
        half_f,
        "h1",
        "",
        &["a@msp.example", "b@nowhere.example"],
    );
    // A domain the analyst added while the customer was still `name:fabrikam` counts for it now.
    let added = collection(&case, "/added", None, "2026-09-10 00:00:00+00");
    let added_f = file(&case, added);
    audit_upns(&case, added_f, "d1", "", &["c@fabrikam-legacy.example"]);
    domain_override(&case, "name:fabrikam", "fabrikam-legacy.example", "add");
    // A domain the analyst removed from the MSP tenant decides nothing.
    let removed = collection(&case, "/removed", None, "2026-09-10 00:00:00+00");
    let removed_f = file(&case, removed);
    audit_upns(&case, removed_f, "r1", "", &["d@msp.example"]);
    domain_override(&case, T1, "msp.example", "remove");

    for run in 0..2 {
        refresh(&mut case, &ProfileOptions::default()).unwrap();
        let key = |c: i64| {
            text(
                &case,
                &format!("SELECT tenant_key FROM collections WHERE collection_id = {c}"),
            )
        };
        assert_eq!(key(customer), T2, "run {run}");
        assert_eq!(
            key(audit_c),
            T2,
            "run {run}: the customer's user decides, not the MSP's technicians"
        );
        assert_eq!(key(half), format!("collection:{half}"), "run {run}");
        assert_eq!(key(added), T2, "run {run}");
        assert_eq!(key(removed), format!("collection:{removed}"), "run {run}");
    }
}
