//! The built-in notebook: twelve titled queries that run on any case, empty or not.

#[path = "common/synth.rs"]
mod synth;

use sparrow_core::Case;
use sparrow_core::case::notebooks::{builtin, placeholders, title};
use sparrow_core::case::query;
use sparrow_synth::options::PsEdition;

/// `sql` with `[account]` as `account` and `[ip]` as `ip`.
fn filled(sql: &str, account: &str, ip: &str) -> String {
    sql.replace("[account]", account).replace("[ip]", ip)
}

#[test]
fn there_are_twelve_with_titles_and_unique_ids() {
    let qs = builtin::queries();
    assert_eq!(qs.len(), 12);
    let mut ids: Vec<&str> = qs.iter().map(|q| q.id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 12);
    for q in qs {
        assert!(q.id.starts_with("builtin:"), "{}", q.id);
        let t = title(q.sql);
        assert!(!t.is_empty() && t != "(untitled)", "{}", q.id);
        let p = placeholders(q.sql);
        match q.id {
            "builtin:signins-by-country" => assert_eq!(p, ["account"]),
            "builtin:what-an-ip-touched" => assert_eq!(p, ["ip"]),
            _ => assert!(p.is_empty(), "{}: {p:?}", q.id),
        }
    }
}

#[test]
fn every_builtin_runs_on_an_empty_case() {
    let dir = tempfile::tempdir().unwrap();
    let c = Case::create_or_open(&dir.path().join("case.duckdb")).unwrap();
    c.lock_down().unwrap();
    for q in builtin::queries() {
        let r = query::run_on(&c, &filled(q.sql, "*", "203.0.113.7"), 100, 0);
        assert!(r.is_ok(), "{}: {:?}", q.id, r.err());
    }
}

#[test]
fn every_builtin_runs_on_a_synthetic_case() {
    let g = synth::builtin_detected("bec-aitm", PsEdition::Ps7);
    let ip: String = g
        .case
        .conn()
        .query_row(
            "SELECT ip FROM events WHERE ip IS NOT NULL GROUP BY ip ORDER BY count(*) DESC, ip LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    g.case.lock_down().unwrap();
    for q in builtin::queries() {
        let r = query::run_on(&g.case, &filled(q.sql, "*", &ip), 100, 0);
        let r = r.unwrap_or_else(|e| panic!("{}: {e}", q.id));
        if matches!(
            q.id,
            "builtin:signins-by-country"
                | "builtin:operations-by-workload"
                | "builtin:what-an-ip-touched"
        ) {
            assert!(!r.rows.is_empty(), "{} found nothing", q.id);
        }
    }
}
