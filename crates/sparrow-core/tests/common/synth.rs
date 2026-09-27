//! Shared helper for the parser tasks (13-22): generate a built-in or inline scenario into a
//! temporary Microsoft-Extractor-Suite tree, ingest and profile it, and compare it with the
//! manifest. General on purpose: later tasks generate other collectors with it too.

#![allow(dead_code)]

use sparrow_core::Case;
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::manifest::Manifest;
use sparrow_synth::options::{Collector, GenerateOptions, PsEdition};
use sparrow_synth::scenario::{Scenario, load};
use sparrow_synth::testing::ingest_generated;

pub struct Generated {
    pub dir: tempfile::TempDir,
    pub manifest: Manifest,
    pub case: Case,
}

pub fn invictus(scenario: &Scenario, ps: PsEdition, seed: u64) -> Generated {
    let dir = tempfile::tempdir().unwrap();
    let mut o = GenerateOptions::new(Collector::Invictus, seed);
    o.ps = ps;
    let manifest = generate_to_dir(scenario, &o, dir.path()).unwrap();
    let case = ingest_generated(dir.path(), &manifest);
    Generated {
        dir,
        manifest,
        case,
    }
}

pub fn builtin(name: &str, ps: PsEdition) -> Generated {
    invictus(&load(name).unwrap(), ps, 17)
}

pub fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

pub fn text(case: &Case, sql: &str) -> String {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

pub fn check_green(g: &Generated) {
    let r = sparrow_synth::check::check(&g.manifest, &g.case).unwrap();
    assert!(r.ok, "{:#?}", r.problems);
}
