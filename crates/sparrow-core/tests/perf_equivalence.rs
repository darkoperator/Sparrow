//! The set-based MailItemsAccessed matching at volume, and the availability rows of three scenarios against their
//! goldens.

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

/// The availability rows are exactly the recorded ones; `profile_availability` and the `check` gate only assert the
/// statuses a row may have.
#[test]
fn availability_matches_the_goldens() {
    for name in ["bec-aitm", "bec-e3-audit-gaps", "audit-tamper"] {
        let g = builtin(name, PsEdition::Ps7);
        let as_of = g.manifest.collected_at + Duration::days(1);
        let rows = compute(g.case.conn(), as_of).unwrap();
        let golden = serde_json::to_string_pretty(&rows).unwrap();
        let path = format!(
            "{}/tests/golden/availability_{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        // SPARROW_RECORD_GOLDEN=1 re-records the goldens: a deliberate step whose diff is reviewed
        // and whose reason goes in the commit message.
        if std::env::var_os("SPARROW_RECORD_GOLDEN").is_some() {
            std::fs::write(&path, &golden).unwrap();
            continue;
        }
        let expected =
            std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("record {path} first"));
        assert_eq!(golden, expected, "{name}");
    }
}
