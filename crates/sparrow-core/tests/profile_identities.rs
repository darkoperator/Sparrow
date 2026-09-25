use duckdb::params;
use sparrow_core::Case;
use sparrow_core::profile::identities::rebuild;
use sparrow_core::profile::{ProfileOptions, refresh};

const T1: &str = "c9c9c9c9-0000-4000-8000-000000000001";
const ALICE: &str = "11111111-1111-4111-8111-111111111111";
const ADMIN: &str = "99999999-9999-4999-8999-999999999999";

/// One collection (id 1) of tenant T1: a UAL row with organization_id makes the tenant id
/// known and a `users` row puts `contoso.example` into `tenant_domains`.
fn tenant_case() -> Case {
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
    assert_eq!(c, 1);
    case.conn()
        .execute_batch(&format!(
            "INSERT INTO source_files (file_id, collection_id, rel_path, artifact_type, size_bytes, sha256, status)
                 VALUES (100, 1, 'Tenant/x.json', 'hawk.tenant.raw_ual', 1, 'h', 'parsed');
             INSERT INTO ual_events (record_id, collection_id, event_time, time_tz_assumed, time_precision,
                 organization_id, workload, audit_data, data_completeness, synthetic_id)
             VALUES ('22222222-2222-4222-8222-222222222222', 1, TIMESTAMPTZ '2026-09-01 10:00:00+00', false,
                 'second', '{T1}', 'Exchange', '{{}}', 'full', false);
             INSERT INTO record_sources VALUES ('ual_events', '22222222-2222-4222-8222-222222222222', 100, 0, 1, 1, 0, 1, 'h');
             INSERT INTO users (record_key, collection_id, user_id, upn, display_name, user_type)
                 VALUES ('u-admin', 1, '{ADMIN}', 'admin@contoso.example', 'Admin', 'Member');"
        ))
        .unwrap();
    case
}

fn exec(case: &Case, sql: &str) {
    case.conn().execute_batch(sql).unwrap();
}

fn profile(case: &mut Case) {
    refresh(case, &ProfileOptions::default()).unwrap();
}

/// (kind, upn, object_id, puid, app_id, display_names, sources, aliases) of one identity.
fn identity(
    case: &Case,
    id: &str,
) -> (String, String, String, String, String, String, String, i64) {
    case.conn()
        .query_row(
            "SELECT CAST(kind AS VARCHAR), coalesce(upn, ''), coalesce(object_id, ''), coalesce(puid, ''),
                    coalesce(app_id, ''), CAST(display_names AS VARCHAR), CAST(sources AS VARCHAR), aliases
             FROM identities WHERE identity_id = ?",
            params![id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            },
        )
        .unwrap()
}

fn kind(case: &Case, id: &str) -> String {
    identity(case, id).0
}

fn aliases_of(case: &Case, id: &str) -> Vec<String> {
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT alias_type || ':' || alias FROM identity_aliases WHERE identity_id = ?
             ORDER BY alias_type, alias",
        )
        .unwrap();
    stmt.query_map(params![id], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn owner(case: &Case, alias_type: &str, alias: &str) -> String {
    case.conn()
        .query_row(
            "SELECT identity_id FROM identity_aliases WHERE alias_type = ? AND alias = ?",
            params![alias_type, alias],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn sources_that_share_an_identifier_become_one_identity() {
    let mut case = tenant_case();
    exec(
        &case,
        &format!(
            "INSERT INTO users (record_key, collection_id, user_id, upn, display_name, user_type)
                 VALUES ('u-alice', 1, '{ALICE}', 'Alice@Contoso.example', 'Alice', 'Member');
             INSERT INTO signins (record_key, collection_id, user_id, user_upn, event_type)
                 VALUES ('s1', 1, '{ALICE}', 'alice@contoso.example', 'interactive');
             INSERT INTO ual_events (record_id, collection_id, event_time, time_tz_assumed, time_precision,
                 user_upn, user_key, audit_data, data_completeness, synthetic_id)
             VALUES ('33333333-3333-4333-8333-333333333333', 1, TIMESTAMPTZ '2026-09-02 10:00:00+00', false,
                 'second', 'alice@contoso.example', '10032001ABCDEF12', '{{}}', 'full', false);"
        ),
    );
    profile(&mut case);
    let id = format!("object_id:{ALICE}");
    assert_eq!(
        identity(&case, &id),
        (
            "user".to_string(),
            "alice@contoso.example".to_string(),
            ALICE.to_string(),
            "10032001abcdef12".to_string(),
            String::new(),
            "[Alice]".to_string(),
            "[signins, ual_events, users]".to_string(),
            3
        )
    );
    assert_eq!(
        aliases_of(&case, &id),
        vec![
            format!("object_id:{ALICE}"),
            "puid:10032001abcdef12".to_string(),
            "upn:alice@contoso.example".to_string(),
        ]
    );
    let tenant: String = case
        .conn()
        .query_row(
            "SELECT tenant_key FROM identities WHERE identity_id = ?",
            params![id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tenant, T1);
    // Admin plus Alice: nothing else became an identity.
    let n: i64 = case
        .conn()
        .query_row("SELECT count(*) FROM identities", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 2);
}

#[test]
fn service_principals_and_apps_are_their_own_kinds() {
    let mut case = tenant_case();
    exec(
        &case,
        "INSERT INTO signins (record_key, collection_id, event_type, app_id, app_name)
             VALUES ('s1', 1, 'service_principal', '0e0e0e0e-0000-4000-8000-0000000000b1', 'Contoso App');
         INSERT INTO oauth_grants (record_key, collection_id, client_id, client_name)
             VALUES ('g1', 1, '0e0e0e0e-0000-4000-8000-0000000000b2', 'Other App');",
    );
    profile(&mut case);
    let sp = identity(&case, "app_id:0e0e0e0e-0000-4000-8000-0000000000b1");
    assert_eq!(sp.0, "service_principal");
    assert_eq!(sp.4, "0e0e0e0e-0000-4000-8000-0000000000b1");
    assert_eq!(sp.5, "[Contoso App]");
    assert_eq!(sp.6, "[signins]");
    let app = identity(&case, "app_id:0e0e0e0e-0000-4000-8000-0000000000b2");
    assert_eq!(app.0, "app");
    assert_eq!(app.6, "[oauth_grants]");
}

#[test]
fn guests_and_foreign_domains_are_external() {
    let mut case = tenant_case();
    exec(
        &case,
        "INSERT INTO users (record_key, collection_id, user_id, upn, user_type)
             VALUES ('u-guest', 1, '44444444-4444-4444-8444-444444444444',
                     'guest_fabrikam.example#ext#@contoso.onmicrosoft.example', 'Guest');
         INSERT INTO mailbox_permissions (record_key, collection_id, grantee_upn)
             VALUES ('p1', 1, 'x@fabrikam.example');",
    );
    profile(&mut case);
    assert_eq!(
        kind(&case, "object_id:44444444-4444-4444-8444-444444444444"),
        "external"
    );
    assert_eq!(kind(&case, "upn:x@fabrikam.example"), "external");
    assert_eq!(kind(&case, &format!("object_id:{ADMIN}")), "user");
}

#[test]
fn a_reused_upn_does_not_merge_two_object_ids() {
    let mut case = tenant_case();
    let a = "55555555-5555-4555-8555-555555555555";
    let b = "66666666-6666-4666-8666-666666666666";
    exec(
        &case,
        &format!(
            "INSERT INTO users (record_key, collection_id, user_id, upn) VALUES
                 ('u-b', 1, '{b}', 'bob@contoso.example'),
                 ('u-a', 1, '{a}', 'bob@contoso.example');"
        ),
    );
    profile(&mut case);
    assert_eq!(
        aliases_of(&case, &format!("object_id:{a}")),
        vec![
            format!("object_id:{a}"),
            "upn:bob@contoso.example".to_string()
        ]
    );
    assert_eq!(
        aliases_of(&case, &format!("object_id:{b}")),
        vec![format!("object_id:{b}")]
    );
    assert_eq!(
        owner(&case, "upn", "bob@contoso.example"),
        format!("object_id:{a}")
    );
    let out = rebuild(case.conn()).unwrap();
    assert_eq!(out.conflicts, 1);
    assert_eq!(out.identities, 3, "admin, A and B");
    assert_eq!(out.aliases, 5);
    let report = refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(report.identities, 3);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.starts_with("1 identifiers link to more than one Entra object id")),
        "{:?}",
        report.warnings
    );
}

#[test]
fn system_actors() {
    let mut case = tenant_case();
    exec(
        &case,
        "INSERT INTO ual_events (record_id, collection_id, event_time, time_tz_assumed, time_precision,
             user_upn, user_type, audit_data, data_completeness, synthetic_id)
         VALUES ('77777777-7777-4777-8777-777777777777', 1, TIMESTAMPTZ '2026-09-02 10:00:00+00', false,
             'second', 'NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)', 4, '{}', 'full', false);",
    );
    profile(&mut case);
    let id = "name:nt authority\\system (microsoft.exchange.servicehost)";
    assert_eq!(kind(&case, id), "system");
    assert_eq!(aliases_of(&case, id), vec![id.to_string()]);
}

#[test]
fn rebuild_is_repeatable() {
    let mut case = tenant_case();
    exec(
        &case,
        &format!(
            "INSERT INTO users (record_key, collection_id, user_id, upn, display_name)
                 VALUES ('u-alice', 1, '{ALICE}', 'alice@contoso.example', 'Alice');
             INSERT INTO signins (record_key, collection_id, user_id, user_upn, user_display_name, event_type)
                 VALUES ('s1', 1, '{ALICE}', 'alice@contoso.example', 'Alice Smith', 'noninteractive');
             INSERT INTO directory_audits (record_key, collection_id, initiated_by_app_id, initiated_by_app_name)
                 VALUES ('d1', 1, '0e0e0e0e-0000-4000-8000-0000000000b3', 'Sync');
             INSERT INTO admin_audit_events (record_key, collection_id, caller)
                 VALUES ('a1', 1, 'Admin@contoso.example');"
        ),
    );
    let dump = |case: &Case| -> String {
        case.conn()
            .query_row(
                "SELECT string_agg(CAST(i AS VARCHAR), chr(10) ORDER BY identity_id) FROM identities i",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    profile(&mut case);
    let first = dump(&case);
    profile(&mut case);
    assert_eq!(dump(&case), first);
    assert!(first.contains("Alice Smith"), "{first}");
    // admin_audit_events caller joined the admin user by UPN.
    assert_eq!(
        owner(&case, "upn", "admin@contoso.example"),
        format!("object_id:{ADMIN}")
    );
}
