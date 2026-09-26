//! Task 11: `sparrow_core::summary::summarize`.

use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures;
use sparrow_core::fixtures::events::hawk4_events_tree;
use sparrow_core::fixtures::mmdb::{asn, city, write_mmdb};
use sparrow_core::fixtures::state::{ALICE, hawk4_state_tree_at};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_core::profile::{ProfileOptions, refresh};
use sparrow_core::summary::summarize;
use std::path::Path;

/// Ingests the Hawk 4 events tree alone (no UAL, no state) into an in-memory case and profiles
/// it, as the task-11 brief specifies.
fn case_with_hawk4_events() -> (tempfile::TempDir, Case) {
    let dir = tempfile::tempdir().unwrap();
    hawk4_events_tree(dir.path());
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
    (dir, case)
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn ingest(case: &mut Case, path: &Path) {
    let report = ingest_path(
        case,
        path,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert!(!report.has_errors(), "{report:#?}");
}

/// Synthetic GeoIP dir (same construction as `profile_timeline.rs`'s `geoip_dir()`): 203.0.113.0/24
/// resolves to Lagos, NG on DigitalOcean (a known hosting ASN), and `hawk4_events_tree`'s sign-ins
/// use 203.0.113.10.
fn geoip_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let city_db = write_mmdb(
        "GeoLite2-City",
        1_790_000_000,
        &[(
            "203.0.113.0".parse().unwrap(),
            24,
            city("NG", "Nigeria", "Lagos", 6.45, 3.39),
        )],
    );
    let asn_db = write_mmdb(
        "GeoLite2-ASN",
        1_790_100_000,
        &[(
            "203.0.113.0".parse().unwrap(),
            24,
            asn(14061, "DIGITALOCEAN-ASN"),
        )],
    );
    std::fs::write(dir.path().join("GeoLite2-City.mmdb"), city_db).unwrap();
    std::fs::write(dir.path().join("GeoLite2-ASN.mmdb"), asn_db).unwrap();
    dir
}

const OLD_STAMP: &str = "20260910_090000";
const NEW_STAMP: &str = "20260920_090000";
const FORWARDING: &str = "smtp:x@fabrikam.example";

/// A Get-InboxRule object shaped like `fixtures::state`'s private helper of the same name
/// (copied from `profile_absent.rs`, Task 10's own test of this exact fixture).
fn inbox_rule(owner: &str, identity: u64, name: &str) -> Value {
    json!({
        "Description": "desc", "Enabled": true, "Identity": format!("{owner}\\{identity}"),
        "InError": false, "Name": name, "Priority": 1, "RuleIdentity": identity,
        "BodyContainsWords": [], "From": null, "HasAttachment": false, "SubjectContainsWords": [],
        "SubjectOrBodyContainsWords": [], "CopyToFolder": null, "DeleteMessage": false,
        "ForwardAsAttachmentTo": null, "ForwardTo": null, "MarkAsRead": false, "MoveToFolder": null,
        "RedirectTo": null, "SoftDeleteMessage": false, "StopProcessingRules": false,
        "MailboxOwnerId": owner
    })
}

fn write_rules(root: &Path, subject: &str, file_stem: &str, rules: &[Value]) {
    fixtures::write(
        root,
        &format!("{subject}/InboxRules_{file_stem}.json"),
        &fixtures::utf8_bom(&fixtures::ps_json(&json!(rules))),
    );
}

/// Older capture (both the "." and "Newsletters" inbox rules Alice's default fixture ships),
/// then a newer one whose `InboxRules_alice.json` drops "Newsletters": `state_absent_in_newer`
/// lists it (Task 10's own fixture/pattern, reused here for `summary`'s `absent_in_newer` count).
fn case_with_a_removed_inbox_rule() -> (tempfile::TempDir, tempfile::TempDir, Case) {
    let old_dir = tempfile::tempdir().unwrap();
    let new_dir = tempfile::tempdir().unwrap();
    let old_root = hawk4_state_tree_at(old_dir.path(), OLD_STAMP, FORWARDING);
    let new_root = hawk4_state_tree_at(new_dir.path(), NEW_STAMP, FORWARDING);
    write_rules(&new_root, ALICE, "alice", &[inbox_rule("alice", 1111, ".")]);

    let mut case = Case::in_memory().unwrap();
    ingest(&mut case, &old_root);
    ingest(&mut case, &new_root);
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    (old_dir, new_dir, case)
}

#[test]
fn one_tenant_with_name_and_hawk_licence() {
    let (_dir, case) = case_with_hawk4_events();
    let summary = summarize(&case).unwrap();
    assert_eq!(summary.tenants.len(), 1, "{summary:#?}");
    let t = &summary.tenants[0];
    assert_eq!(t.tenant_name.as_deref(), Some("contoso_ltd"));
    assert!(
        t.licenses.contains(&"E5 (low, Hawk.log)".to_string()),
        "{:?}",
        t.licenses
    );
}

#[test]
fn coverage_signins_rows_match_the_table() {
    let (_dir, case) = case_with_hawk4_events();
    let summary = summarize(&case).unwrap();
    let t = &summary.tenants[0];
    let signins = t
        .coverage
        .iter()
        .find(|c| c.source_table == "signins")
        .unwrap_or_else(|| panic!("no signins coverage entry: {:?}", t.coverage));
    assert_eq!(signins.rows, count(&case, "SELECT count(*) FROM signins"));
    assert!(signins.first.is_some());
    assert!(signins.last.is_some());
}

#[test]
fn top_actor_is_alice() {
    let (_dir, case) = case_with_hawk4_events();
    let summary = summarize(&case).unwrap();
    let t = &summary.tenants[0];
    assert!(!t.top_actors.is_empty(), "{summary:#?}");
    assert_eq!(
        t.top_actors[0].actor, "alice@contoso.example",
        "{:?}",
        t.top_actors
    );
}

#[test]
fn tables_lists_ual_events_row_count() {
    let (_dir, case) = case_with_hawk4_events();
    let summary = summarize(&case).unwrap();
    let ual = summary
        .tables
        .iter()
        .find(|t| t.table == "ual_events")
        .unwrap_or_else(|| panic!("no ual_events table entry: {:?}", summary.tables));
    assert_eq!(ual.rows, count(&case, "SELECT count(*) FROM ual_events"));
}

#[test]
fn gaps_lists_every_uncollected_evidence_id() {
    let (_dir, case) = case_with_hawk4_events();
    let summary = summarize(&case).unwrap();
    let t = &summary.tenants[0];

    let expected: Vec<String> = {
        let mut stmt = case
            .conn()
            .prepare(
                "SELECT evidence FROM evidence_availability
                 WHERE tenant_key = ? AND CAST(status AS VARCHAR) <> 'collected'
                 ORDER BY evidence",
            )
            .unwrap();
        stmt.query_map(duckdb::params![t.tenant_key], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert!(!expected.is_empty(), "fixture should have evidence gaps");
    assert_eq!(t.gaps, expected);
}

#[test]
fn profile_evaluated_at_is_set() {
    let (_dir, case) = case_with_hawk4_events();
    let summary = summarize(&case).unwrap();
    assert!(summary.profile_evaluated_at.is_some());
}

#[test]
fn hosting_ips_counts_a_hosting_address_seen_in_a_sign_in() {
    let dir = tempfile::tempdir().unwrap();
    hawk4_events_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    ingest(&mut case, dir.path());
    let geo = geoip_dir();
    refresh(
        &mut case,
        &ProfileOptions {
            geoip_dir: Some(geo.path().to_path_buf()),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ip_intel WHERE ip = '203.0.113.10' AND is_hosting"
        ),
        1,
        "sanity: 203.0.113.10 should resolve to a known hosting ASN"
    );

    let summary = summarize(&case).unwrap();
    assert_eq!(summary.tenants.len(), 1, "{summary:#?}");
    assert_eq!(summary.tenants[0].hosting_ips, 1, "{summary:#?}");
}

#[test]
fn absent_in_newer_counts_a_removed_inbox_rule() {
    let (_old_dir, _new_dir, case) = case_with_a_removed_inbox_rule();

    let expected = count(&case, "SELECT count(*) FROM state_absent_in_newer");
    assert_eq!(
        expected, 1,
        "sanity: the fixture should produce exactly one absent row"
    );

    let summary = summarize(&case).unwrap();
    assert_eq!(summary.tenants.len(), 1, "{summary:#?}");
    assert_eq!(summary.tenants[0].absent_in_newer, expected);
}

/// A bare collection with no reported tenant id or name (`resolve_tenants` pass 4 gives it its
/// own `collection:<id>` key), one signins row and the provenance rows `timeline`'s tenant
/// attribution needs.
fn tenant_with_a_signin(case: &Case, tool_literal: &str, root: &str, actor: &str, at: &str) -> i64 {
    let collection_id: i64 = case
        .conn()
        .query_row(
            &format!(
                "INSERT INTO collections (tool, root_path, sparrow_version)
                 VALUES ({tool_literal}, ?, 't') RETURNING collection_id"
            ),
            duckdb::params![root],
            |r| r.get(0),
        )
        .unwrap();
    let file_id: i64 = case
        .conn()
        .query_row(
            "INSERT INTO source_files (collection_id, rel_path, size_bytes, sha256, status)
             VALUES (?, 'signins.json', 1, 'h' || ?, 'parsed') RETURNING file_id",
            duckdb::params![collection_id, collection_id],
            |r| r.get(0),
        )
        .unwrap();
    let record_key = format!("s{collection_id}");
    case.conn()
        .execute(
            "INSERT INTO signins (record_key, collection_id, event_time, user_upn)
             VALUES (?, ?, CAST(? AS TIMESTAMPTZ), ?)",
            duckdb::params![record_key, collection_id, at, actor],
        )
        .unwrap();
    case.conn()
        .execute(
            "INSERT INTO record_sources VALUES ('signins', ?, ?, 0, 1, 1, 0, 1, 'h')",
            duckdb::params![record_key, file_id],
        )
        .unwrap();
    collection_id
}

/// Two tenants in one case, each with its own collection and its own sign-in, and nothing
/// (no reported name or id) linking them together, so `resolve_tenants` gives each a distinct
/// `collection:<id>` key. `timeline` carries no tenant column, so this exercises the
/// record_sources -> source_files -> collections attribution across more than one tenant, not
/// just the single-tenant case every other test here uses: each tenant's coverage and top actors
/// must come only from its own collection, never the other's.
#[test]
fn two_tenants_get_their_own_coverage_and_top_actors() {
    let mut case = Case::in_memory().unwrap();
    let a = tenant_with_a_signin(
        &case,
        "'hawk'",
        "/x/A",
        "alice@contoso.example",
        "2026-09-01T09:00:00Z",
    );
    // A second sign-in for A, so its top actor has more than one row (alice still wins).
    case.conn()
        .execute(
            "INSERT INTO signins (record_key, collection_id, event_time, user_upn)
             VALUES ('s-a2', ?, TIMESTAMPTZ '2026-09-01 10:00:00+00', 'alice@contoso.example')",
            duckdb::params![a],
        )
        .unwrap();
    case.conn()
        .execute(
            "INSERT INTO record_sources VALUES ('signins', 's-a2', ?, 0, 1, 1, 0, 1, 'h')",
            duckdb::params![
                case.conn()
                    .query_row(
                        "SELECT file_id FROM source_files WHERE collection_id = ?",
                        duckdb::params![a],
                        |r| r.get::<_, i64>(0)
                    )
                    .unwrap()
            ],
        )
        .unwrap();
    let b = tenant_with_a_signin(
        &case,
        "'invictus'",
        "/x/B",
        "erin@fabrikam.example",
        "2026-09-02T09:00:00Z",
    );

    refresh(&mut case, &ProfileOptions::default()).unwrap();

    let summary = summarize(&case).unwrap();
    assert_eq!(summary.tenants.len(), 2, "{summary:#?}");

    let tenant_a = summary
        .tenants
        .iter()
        .find(|t| t.tenant_key == format!("collection:{a}"))
        .unwrap_or_else(|| panic!("no tenant collection:{a}: {summary:#?}"));
    let tenant_b = summary
        .tenants
        .iter()
        .find(|t| t.tenant_key == format!("collection:{b}"))
        .unwrap_or_else(|| panic!("no tenant collection:{b}: {summary:#?}"));

    let signins_of = |t: &sparrow_core::summary::TenantSummary| {
        t.coverage
            .iter()
            .find(|c| c.source_table == "signins")
            .map(|c| c.rows)
            .unwrap_or(0)
    };
    assert_eq!(signins_of(tenant_a), 2, "{:?}", tenant_a.coverage);
    assert_eq!(signins_of(tenant_b), 1, "{:?}", tenant_b.coverage);

    assert_eq!(tenant_a.top_actors.len(), 1, "{:?}", tenant_a.top_actors);
    assert_eq!(tenant_a.top_actors[0].actor, "alice@contoso.example");
    assert_eq!(tenant_a.top_actors[0].rows, 2);

    assert_eq!(tenant_b.top_actors.len(), 1, "{:?}", tenant_b.top_actors);
    assert_eq!(tenant_b.top_actors[0].actor, "erin@fabrikam.example");
    assert_eq!(tenant_b.top_actors[0].rows, 1);
}
