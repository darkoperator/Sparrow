//! Task 26 equivalence: the set-based MailItemsAccessed matching must land exactly as the
//! per-row version, and the grouped availability pass must return the same rows.

#[path = "common/synth.rs"]
mod synth;

use chrono::Duration;
use sparrow_core::profile::availability::compute;
use sparrow_synth::options::PsEdition;
use sparrow_synth::scenario::load;
use synth::*;

/// Sessions and MessageIDs rows land exactly as before: every row either sights a raw record
/// or becomes one parent-less row, and the manifest (independent of Sparrow) agrees.
#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn mia_exports_match_raw_records_at_volume() {
    let mut s = load("volume").unwrap();
    s.scale.ual_rows = 40_000;
    let g = invictus(&s, PsEdition::Ps7, 4);
    assert!(
        count(
            &g.case,
            "SELECT count(*) FROM record_sources rs JOIN source_files sf USING (file_id) WHERE sf.artifact_type IN ('inv.mia.sessions', 'inv.mia.message_ids')"
        ) > 1000
    );
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM mail_items_accessed WHERE record_id IS NULL"
        ),
        0
    );
    check_green(&g);
}

/// The grouped availability pass returns the same rows as the per-evidence queries did.
#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn availability_is_unchanged_by_the_grouped_pass() {
    for name in ["bec-aitm", "bec-e3-audit-gaps", "audit-tamper"] {
        let g = builtin(name, PsEdition::Ps7);
        let as_of = g.manifest.collected_at + Duration::days(1);
        let rows = compute(g.case.conn(), as_of).unwrap();
        let golden = serde_json::to_string_pretty(&rows).unwrap();
        // Recorded before the change (Step 2) under tests/golden/availability_<name>.json.
        let path = format!(
            "{}/tests/golden/availability_{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let expected =
            std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("record {path} first"));
        assert_eq!(golden, expected, "{name}");
    }
}
