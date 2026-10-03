//! The audited-write timing check, alone in its test binary: cargo runs test binaries one at a time, so no other
//! test of this binary (an ingest, a detection run) competes with it for the CPU.

use sparrow_core::Case;
use sparrow_core::case::actor::Actor;
use sparrow_core::case::audit;
use sparrow_core::case::write::{self, FindingStatus as S};

fn case_with_finding() -> Case {
    let c = Case::in_memory().unwrap();
    c.conn()
        .execute_batch(
            "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, \
             title, created_by, created_at, updated_at)
             VALUES ('f1', 'fp1', 't1', 'SPW-ID-004', 1, 'x', 'high', 'AiTM', 'rule', now(), now());",
        )
        .unwrap();
    c
}

fn agent() -> Actor {
    Actor::agent("claude", Some("carlos")).unwrap()
}

#[test]
fn thousand_appends_stay_fast() {
    let c = case_with_finding();
    let t = std::time::Instant::now();
    for i in 0..1000 {
        let s = if i % 2 == 0 {
            S::InReview
        } else {
            S::NeedsMoreData
        };
        write::set_finding_status(c.conn(), &agent(), "f1", s, None).unwrap();
    }
    let elapsed = t.elapsed();
    let r = audit::verify(c.conn()).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(r.entries, 1000);
    assert!(elapsed.as_secs() < 5, "{elapsed:?}");
}
