//! Shared helper for the parser tasks (13-22): generate a built-in or inline scenario into a
//! temporary Microsoft-Extractor-Suite tree, ingest and profile it, and compare it with the
//! manifest. General on purpose: later tasks generate other collectors with it too.
//!
//! A built-in `(scenario, edition)` tree is generated once per test binary and cached on disk
//! (`LazyLock` + `Mutex<BTreeMap>`); each call re-ingests it into its own `Case`, so a test may
//! mutate it freely. Inline scenarios (`invictus`) are never cached.

#![allow(dead_code)]

use sparrow_core::Case;
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::manifest::Manifest;
use sparrow_synth::options::{Collector, GenerateOptions, PsEdition};
use sparrow_synth::scenario::{Scenario, load};
use sparrow_synth::testing::ingest_generated;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

pub struct Generated {
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub case: Case,
}

/// The generated built-in trees live for the whole test process, under this leaked root.
static TREES: LazyLock<tempfile::TempDir> =
    LazyLock::new(|| tempfile::tempdir().expect("cache temp dir"));

#[derive(Clone)]
struct Cached {
    dir: PathBuf,
    manifest: Manifest,
}

static CACHE: LazyLock<Mutex<BTreeMap<(String, PsEdition), Cached>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// A built-in scenario's tree: generated once per `(name, ps)`, ingested freshly per call.
pub fn builtin(name: &str, ps: PsEdition) -> Generated {
    let key = (name.to_string(), ps);
    let cached = {
        let mut cache = CACHE.lock().unwrap();
        match cache.get(&key) {
            Some(c) => c.clone(),
            None => {
                let dir = TREES.path().join(format!("{name}-{}", ps.as_str()));
                let mut o = GenerateOptions::new(Collector::Invictus, 17);
                o.ps = ps;
                let manifest = generate_to_dir(&load(name).unwrap(), &o, &dir).unwrap();
                let c = Cached {
                    dir: dir.clone(),
                    manifest: manifest.clone(),
                };
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
    }
}

/// The custom-scenario variant, never cached: each call generates a fresh tree.
pub fn invictus(scenario: &Scenario, ps: PsEdition, seed: u64) -> Generated {
    let dir = tempfile::tempdir().unwrap();
    let mut o = GenerateOptions::new(Collector::Invictus, seed);
    o.ps = ps;
    let manifest = generate_to_dir(scenario, &o, dir.path()).unwrap();
    let case = ingest_generated(dir.path(), &manifest);
    let path = dir.path().to_path_buf();
    // Keep the tree alive for `Generated.dir`; removed when the process exits.
    KEEPALIVE.lock().unwrap().push(dir);
    Generated {
        dir: path,
        manifest,
        case,
    }
}

static KEEPALIVE: LazyLock<Mutex<Vec<tempfile::TempDir>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

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
