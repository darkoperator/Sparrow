//! Task 11: `sparrow_core::summary::summarize`.

use sparrow_core::Case;
use sparrow_core::fixtures::events::hawk4_events_tree;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_core::profile::{ProfileOptions, refresh};
use sparrow_core::summary::summarize;

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
