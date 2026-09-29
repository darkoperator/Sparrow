//! Task 25: scale knobs and the performance harness. The fast test checks the filler is exact
//! and the tree stays checkable; the ignored one prints the generate/ingest/profile timings.

use sha2::{Digest, Sha256};
use sparrow_synth::check::check;
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::options::{Collector, GenerateOptions};
use sparrow_synth::scale::run_perf;
use sparrow_synth::scenario::load;
use sparrow_synth::testing::ingest_generated;
use std::path::{Path, PathBuf};

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

/// A digest of every file under `dir`, relative paths included, sorted by path.
fn tree_digest(dir: &Path) -> String {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(dir, &mut files);
    let mut rels: Vec<(String, PathBuf)> = files
        .into_iter()
        .map(|p| {
            (
                p.strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                p,
            )
        })
        .collect();
    rels.sort();
    let mut hasher = Sha256::new();
    for (rel, p) in &rels {
        hasher.update(rel.as_bytes());
        hasher.update(b"\0");
        hasher.update(std::fs::read(p).unwrap());
        hasher.update(b"\0");
    }
    hex::encode(hasher.finalize())
}

/// The day-by-day streaming rewrite is byte-identical to the code before it: the same small
/// scaled tree (20k filler UAL rows, default CSV) hashes to the value recorded at the old
/// commit. (The other UAL formats were checked the same way while developing.)
///
/// Re-recorded for Task F7: world users 2 and 5 now carry "Last, First" display names, so the
/// volume tree's bytes change. The parent commit's value was
/// `16764b6baf9619b698b7ac0c03889906b6d46c4cd079ada6ddc42aa661f99827`; re-running this same test
/// at the parent plus the F7 change gives the value below.
///
/// Re-recorded again for Task F6: UserApplications now carries Assignment rows (plus the new
/// alert/risk fields and service-principal creation dates). The value after F7 was
/// `02d2ce9d5f67b1e628540af5c6fbcb6755068556ad036b9c9a7048e32b7c9bb7`.
#[test]
fn scaled_tree_is_byte_identical_to_the_streaming_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = GenerateOptions::new(Collector::Invictus, 7);
    o.ual_rows = Some(20_000);
    o.signins = Some(5_000);
    generate_to_dir(&load("volume").unwrap(), &o, dir.path()).unwrap();
    assert_eq!(
        tree_digest(dir.path()),
        "0b121ea0ed6234f4c23375c009d0671c3c08712a224c338e4436cd378320a34c"
    );
}

/// Measurement aid: generation only, to attribute peak RSS to the generate phase.
#[test]
#[ignore]
fn perf_generate_only() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = GenerateOptions::new(Collector::Invictus, 3);
    o.ual_rows = Some(1_000_000);
    o.signins = Some(200_000);
    let t = std::time::Instant::now();
    generate_to_dir(&load("volume").unwrap(), &o, dir.path()).unwrap();
    println!("generate only: {:.2}s", t.elapsed().as_secs_f64());
}
