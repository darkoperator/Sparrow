//! Detection results are a function of the case only: findings, their evidence, and the
//! detection_runs rows (everything but the wall-clock `duration_ms`) hash to a pinned value.
//! The digests were recorded before the run path was optimised (Task 12 performance work) and
//! must not change with it; a rule change re-records them on purpose.

use sha2::{Digest, Sha256};
use sparrow_core::Case;
use sparrow_synth::cache::{Cache, Stage};
use sparrow_synth::options::{Collector, GenerateOptions};

static CACHE: std::sync::LazyLock<Cache> =
    std::sync::LazyLock::new(|| sparrow_synth::test_cache!());

fn dump(case: &Case, sql: &str) -> String {
    let mut st = case.conn().prepare(sql).unwrap();
    let rows = st
        .query_map([], |r| {
            let mut cells = Vec::new();
            for i in 0..r.as_ref().column_count() {
                let v: Option<String> = r.get(i)?;
                cells.push(v.unwrap_or_else(|| "\u{0}NULL".to_string()));
            }
            Ok(cells.join("\u{1f}"))
        })
        .unwrap();
    rows.collect::<Result<Vec<_>, _>>().unwrap().join("\n")
}

fn digest(scenario: &str, c: Collector) -> String {
    let case = CACHE
        .builtin_case(scenario, &GenerateOptions::new(c, 1), Stage::Detected)
        .case;
    let mut h = Sha256::new();
    for sql in [
        "SELECT finding_id, fingerprint, tenant_key, rule_id, CAST(rule_version AS VARCHAR), rule_sha256, severity, title, actor_upn, \
         CAST(first_seen AS VARCHAR), CAST(last_seen AS VARCHAR), CAST(status AS VARCHAR), disposition_reason, CAST(created_by AS VARCHAR), \
         assigned_to, CAST(rule_updated AS VARCHAR), CAST(created_at AS VARCHAR), CAST(updated_at AS VARCHAR) \
         FROM findings ORDER BY finding_id",
        "SELECT finding_id, source_table, record_key, CAST(event_time AS VARCHAR), CAST(role AS VARCHAR), CAST(context AS VARCHAR), \
         CAST(added_run_id AS VARCHAR) FROM finding_evidence ORDER BY finding_id, source_table, record_key, CAST(role AS VARCHAR)",
        "SELECT CAST(run_id AS VARCHAR), tenant_key, rule_id, CAST(rule_version AS VARCHAR), rule_sha256, CAST(status AS VARCHAR), reason, \
         CAST(hits AS VARCHAR), CAST(started_at AS VARCHAR) FROM detection_runs ORDER BY run_id, tenant_key, rule_id",
    ] {
        h.update(dump(&case, sql).as_bytes());
        h.update(b"\n--\n");
    }
    hex::encode(h.finalize())
}

#[test]
fn detection_results_are_stable() {
    let mut bad = Vec::new();
    for (scenario, c, want) in [
        (
            "bec-aitm",
            Collector::Hawk4,
            "0b541fa5ff196eb5837d90e06f7dacce2620b79d7953b8874929f466f0996ed1",
        ),
        (
            "audit-tamper",
            Collector::Invictus,
            "27e9ed4da7790d1218d79c2f7fefda766b86b408c54e6d102acbec99f725ff6c",
        ),
        (
            "hawk-investigate",
            Collector::Hawk3,
            "e4cc2773a59375811ce27e2e24d6fb89eb4c4bb71ca021d7be010a3c83d76660",
        ),
    ] {
        let got = digest(scenario, c);
        if got != want {
            bad.push(format!("{scenario} {c:?}: {got}"));
        }
    }
    assert!(bad.is_empty(), "digests changed:\n{}", bad.join("\n"));
}
