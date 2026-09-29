//! Task 25: scale knobs and the performance harness. The fast test checks the filler is exact
//! and the tree stays checkable; the ignored one prints the generate/ingest/profile timings.

use sparrow_synth::check::check;
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::options::{Collector, GenerateOptions};
use sparrow_synth::scale::run_perf;
use sparrow_synth::scenario::load;
use sparrow_synth::testing::ingest_generated;

#[test]
fn scale_knobs_add_exact_filler_and_stay_checkable() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = GenerateOptions::new(Collector::Invictus, 2);
    o.ual_rows = Some(60_000);
    o.signins = Some(20_000);
    let s = load("volume").unwrap();
    let base = {
        let d = tempfile::tempdir().unwrap();
        generate_to_dir(&s, &GenerateOptions::new(Collector::Invictus, 2), d.path()).unwrap()
    };
    let m = generate_to_dir(&s, &o, dir.path()).unwrap();
    assert_eq!(
        m.tables["ual_events"].rows,
        base.tables["ual_events"].rows + 60_000
    );
    assert_eq!(
        m.tables["signins"].rows,
        base.tables["signins"].rows + 20_000
    );
    assert!(
        m.tables["ual_events"].keys.is_empty(),
        "keys are listed only up to 5000"
    );
    let r = check(&m, &ingest_generated(dir.path(), &m)).unwrap();
    assert!(r.ok, "{:#?}", r.problems);
}

/// Run with: cargo test -p sparrow-synth --release --test perf -- --ignored --nocapture
#[test]
#[ignore]
fn perf_large_invictus_tree() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = GenerateOptions::new(Collector::Invictus, 3);
    o.ual_rows = Some(1_000_000);
    o.signins = Some(200_000);
    let t = run_perf(&load("volume").unwrap(), &o, dir.path()).unwrap();
    println!("{}", t.to_text());
}
