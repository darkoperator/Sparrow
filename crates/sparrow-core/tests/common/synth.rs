//! Shared helper for the parser tasks (13-22): generate a built-in or inline scenario into a
//! temporary Microsoft-Extractor-Suite tree, ingest and profile it, and compare it with the
//! manifest. General on purpose: later tasks generate other collectors with it too.
//!
//! A built-in `(scenario, edition)` is served by the cross-binary test cache
//! (`sparrow_synth::cache`, under `<CARGO_TARGET_TMPDIR>/sparrow-cache/`): its tree is generated
//! and its pristine ingested + profiled case file is built once for the whole run, whichever test
//! binary asks first; each call gets its own COPY of that case, so a test may mutate it. The
//! cached tree is read-only and shared. `SPARROW_NO_CACHE=1` makes every call generate and ingest
//! afresh, as before the cache. Inline scenarios (`invictus`) are never cached; they live under
//! `<CARGO_TARGET_TMPDIR>/synth-<test binary>/`.

#![allow(dead_code)]

use sparrow_core::Case;
use sparrow_synth::cache::{Cache, CachedTree, Stage};
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::manifest::Manifest;
use sparrow_synth::options::{Collector, GenerateOptions, PsEdition};
use sparrow_synth::scenario::{Scenario, load};
use sparrow_synth::testing::ingest_generated;
use std::path::PathBuf;
use std::sync::LazyLock;

pub struct Generated {
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub case: Case,
    /// A custom tree's `TempDir`, kept alive until the `Generated` drops.
    _tree: Option<tempfile::TempDir>,
    /// With `SPARROW_NO_CACHE=1` the tree is private and goes with this value.
    _owned: Option<CachedTree>,
}

/// The per-test-binary root for inline trees under Cargo's target tmp dir. Cargo sets
/// `CARGO_TARGET_TMPDIR` and `CARGO_CRATE_NAME` for integration test targets. It is created, never
/// wiped: every inline tree owns a `TempDir` that removes itself, and a wipe at first use would
/// delete the trees of another test process running at the same time (cargo-nextest runs each
/// test in its own process).
static TREES: LazyLock<PathBuf> = LazyLock::new(|| {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("synth-{}", env!("CARGO_CRATE_NAME")));
    std::fs::create_dir_all(&root).expect("create synth test tree root");
    root
});

static CACHE: LazyLock<Cache> = LazyLock::new(|| sparrow_synth::test_cache!());

/// A built-in scenario's tree and case: from the cache (a private copy of the pristine case).
pub fn builtin(name: &str, ps: PsEdition) -> Generated {
    let mut o = GenerateOptions::new(Collector::Invictus, 17);
    o.ps = ps;
    let got = CACHE
        .case(&load(name).unwrap(), &o, Stage::Profiled)
        .unwrap_or_else(|e| panic!("cached case of {name}: {e}"));
    Generated {
        dir: got.tree.dir.clone(),
        manifest: got.tree.manifest.clone(),
        case: got.case,
        _tree: None,
        _owned: Some(got.tree),
    }
}

/// Any scenario and options through the cache (keyed by the whole scenario and every option):
/// the tree plus a private profiled case.
pub fn cached(scenario: &Scenario, o: &GenerateOptions) -> sparrow_synth::cache::CachedCase {
    CACHE
        .case(scenario, o, Stage::Profiled)
        .unwrap_or_else(|e| panic!("cached case: {e}"))
}

/// The custom-scenario variant, never cached: each call generates a fresh tree that the
/// returned `Generated` owns.
pub fn invictus(scenario: &Scenario, ps: PsEdition, seed: u64) -> Generated {
    let dir = tempfile::Builder::new()
        .prefix("invictus-")
        .tempdir_in(&*TREES)
        .unwrap();
    let mut o = GenerateOptions::new(Collector::Invictus, seed);
    o.ps = ps;
    let manifest = generate_to_dir(scenario, &o, dir.path()).unwrap();
    let case = ingest_generated(dir.path(), &manifest);
    Generated {
        dir: dir.path().to_path_buf(),
        manifest,
        case,
        _tree: Some(dir),
        _owned: None,
    }
}

pub fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

pub fn text(case: &Case, sql: &str) -> String {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

pub fn check_green(g: &Generated) {
    let r = sparrow_synth::check::check_without_detection(&g.manifest, &g.case).unwrap();
    assert!(r.ok, "{:#?}", r.problems);
}
