//! Detection results are a function of the case only: findings, their evidence, and the
//! detection_runs rows (everything but the wall-clock `duration_ms`) hash to a pinned value.
//! The digests were recorded before the run path was optimised (Task 12 performance work) and
//! must not change with it; a rule change re-records them on purpose.

use sha2::{Digest, Sha256};
use sparrow_core::Case;
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::options::{Collector, GenerateOptions};
use sparrow_synth::scenario::load;
use sparrow_synth::testing::ingest_generated_detected;

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
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(
        &load(scenario).unwrap(),
        &GenerateOptions::new(c, 1),
        dir.path(),
    )
    .unwrap();
    let case = ingest_generated_detected(dir.path(), &m);
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
            "dca841a4ee409807e93ad0d5ceec47a9325936b37c60b65432808d3e5a1dcd4c",
        ),
        (
            "audit-tamper",
            Collector::Invictus,
            "e5aa29c3fa7db7c99ab374fedfb1b4d130836abe9f18dc7e3d1b062fedb396cd",
        ),
        (
            "hawk-investigate",
            Collector::Hawk3,
            "b6461b06f8e434d7375a1947614751bef5a32b84760c40141abbe095184a4dcd",
        ),
    ] {
        let got = digest(scenario, c);
        if got != want {
            bad.push(format!("{scenario} {c:?}: {got}"));
        }
    }
    assert!(bad.is_empty(), "digests changed:\n{}", bad.join("\n"));
}
