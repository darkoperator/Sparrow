//! m2-wb-perf: the XLSX workbook and `finding show` on a large case (100k sign-ins, 150k UAL rows). Both used to
//! aggregate every record sighting of the case once per finding (about 26 s for 31 findings). A wall-clock
//! measurement, so it is ignored (and heavy: a ~2 GB tree, removed afterwards); the bounds apply to a release build:
//! cargo test -p sparrow-core --release --test export_perf -- --ignored --nocapture
//! `SPARROW_PERF_CASE=<case.duckdb>` times a copy of that case instead of generating one.
//! The default suite guards the lookup itself
//! (`read::tests::the_source_refs_lookup_aggregates_only_its_own_keys`).

use chrono::Utc;
use sparrow_core::Case;
use sparrow_core::case::read;
use sparrow_core::data::DataDirs;
use sparrow_core::export::workbook_xlsx;
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::options::{Collector, GenerateOptions};
use sparrow_synth::scenario::load;
use sparrow_synth::testing::ingest_generated_detected;
use std::time::Instant;

#[test]
#[ignore = "heavy, wall-clock: run with --release -- --ignored"]
fn workbook_and_finding_show_stay_fast_on_a_large_case() {
    let dir = tempfile::tempdir().unwrap();
    let case = match std::env::var_os("SPARROW_PERF_CASE") {
        Some(p) => {
            let copy = dir.path().join("case.duckdb");
            std::fs::copy(p, &copy).unwrap();
            Case::create_or_open(&copy).unwrap()
        }
        None => {
            let tree = dir.path().join("tree");
            let mut o = GenerateOptions::new(Collector::Invictus, 1);
            o.signins = Some(100_000);
            o.ual_rows = Some(150_000);
            let m = generate_to_dir(&load("bec-aitm").unwrap(), &o, &tree).unwrap();
            ingest_generated_detected(&tree, &m)
        }
    };
    let ids: Vec<String> = read::finding_list(case.conn(), &read::FindingFilter::default())
        .unwrap()
        .into_iter()
        .map(|f| f.finding_id)
        .collect();
    assert!(ids.len() >= 10, "the case has findings to show");

    let t = Instant::now();
    workbook_xlsx::write(
        case.conn(),
        &dir.path().join("w.xlsx"),
        Utc::now(),
        &DataDirs::default(),
    )
    .unwrap();
    let workbook = t.elapsed();

    let rules =
        sparrow_core::export::facts_text::FactRules::for_case(case.conn(), &DataDirs::default())
            .unwrap();
    let t = Instant::now();
    for id in &ids {
        read::finding_show(case.conn(), id, &rules.set).unwrap();
    }
    let per_show = t.elapsed() / ids.len() as u32;
    println!(
        "{} findings: workbook {workbook:?}, finding_show {per_show:?} each",
        ids.len()
    );
    if cfg!(not(debug_assertions)) {
        assert!(workbook.as_secs_f64() < 2.0, "workbook {workbook:?}");
        assert!(per_show.as_millis() < 250, "finding_show {per_show:?}");
    }
}
