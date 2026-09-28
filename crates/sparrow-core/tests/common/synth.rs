//! Shared helper for the parser tasks (13-22): generate a built-in or inline scenario into a
//! temporary Microsoft-Extractor-Suite tree, ingest and profile it, and compare it with the
//! manifest. General on purpose: later tasks generate other collectors with it too.
//!
//! Every tree lives under `<CARGO_TARGET_TMPDIR>/synth-<test binary>/`, wiped once at first use
//! in the process, so a run leaves nothing in the system temp dir. A built-in `(scenario,
//! edition)` tree is generated once per test binary and cached on disk; each call re-ingests it
//! into its own `Case`, so a test may mutate it. Inline scenarios (`invictus`) are never cached
//! and own their `TempDir` again.

#![allow(dead_code)]

use sparrow_core::Case;
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::manifest::Manifest;
use sparrow_synth::options::{Collector, GenerateOptions, PsEdition};
use sparrow_synth::scenario::{Scenario, load};
use sparrow_synth::testing::ingest_generated;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex, MutexGuard};

pub struct Generated {
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub case: Case,
    /// A custom tree's `TempDir`, kept alive until the `Generated` drops; cached built-in trees
    /// live under `TREES` and need none.
    _tree: Option<tempfile::TempDir>,
}

/// The per-test-binary root under Cargo's target tmp dir, wiped once at first use. Cargo sets
/// `CARGO_TARGET_TMPDIR` and `CARGO_CRATE_NAME` for integration test targets.
static TREES: LazyLock<PathBuf> = LazyLock::new(|| {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("synth-{}", env!("CARGO_CRATE_NAME")));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create synth test tree root");
    root
});

#[derive(Clone)]
struct Cached {
    dir: PathBuf,
    manifest: Manifest,
}

static CACHE: LazyLock<Mutex<BTreeMap<(String, PsEdition), Cached>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// The cache lock, recovering from poisoning so a panicking generation does not cascade into
/// unrelated tests.
fn lock_cache() -> MutexGuard<'static, BTreeMap<(String, PsEdition), Cached>> {
    CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A built-in scenario's tree: generated once per `(name, ps)`, ingested freshly per call.
pub fn builtin(name: &str, ps: PsEdition) -> Generated {
    let key = (name.to_string(), ps);
    let cached = {
        let mut cache = lock_cache();
        match cache.get(&key) {
            Some(c) => c.clone(),
            None => {
                let dir = TREES.join(format!("{name}-{}", ps.as_str()));
                let mut o = GenerateOptions::new(Collector::Invictus, 17);
                o.ps = ps;
                let manifest = generate_to_dir(&load(name).unwrap(), &o, &dir).unwrap();
                let c = Cached { dir, manifest };
                cache.insert(key, c.clone());
                c
            }
        }
    };
    let case = ingest_generated(&cached.dir, &cached.manifest);
    Generated {
        dir: cached.dir,
        manifest: cached.manifest,
        case,
        _tree: None,
    }
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
    }
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
