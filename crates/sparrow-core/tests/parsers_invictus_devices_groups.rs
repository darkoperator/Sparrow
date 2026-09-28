#[path = "common/synth.rs"]
mod synth;

use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::options::{Collector, GenerateOptions, PsEdition};
use sparrow_synth::scenario::load;
use sparrow_synth::testing::ingest_generated;
use synth::*;

#[test]
fn devices_and_groups_load() {
    for ps in [PsEdition::Ps7, PsEdition::Ps51] {
        let g = builtin("bec-aitm", ps);
        // One laptop per user and a phone for every second user (12 users).
        assert_eq!(count(&g.case, "SELECT count(*) FROM devices"), 18);
        assert_eq!(count(&g.case, "SELECT count(*) FROM groups"), 3);
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM groups WHERE is_dynamic AND membership_rule LIKE '%Sales%'"
            ),
            1
        );
        assert_eq!(
            text(
                &g.case,
                "SELECT array_to_string(group_types, ',') FROM groups WHERE display_name = 'All Staff'"
            ),
            "Unified"
        );
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM group_members WHERE group_name = 'Finance'"
            ),
            3
        );
        check_green(&g);
    }
}

#[test]
fn json_written_to_a_csv_path_is_read_as_json() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = GenerateOptions::new(Collector::Invictus, 5);
    o.invictus_devices_json = true;
    let m = generate_to_dir(&load("bec-aitm").unwrap(), &o, dir.path()).unwrap();
    let case = ingest_generated(dir.path(), &m);
    assert_eq!(count(&case, "SELECT count(*) FROM devices"), 18);
    let r = sparrow_synth::check::check(&m, &case).unwrap();
    assert!(r.ok, "{:#?}", r.problems);
}
