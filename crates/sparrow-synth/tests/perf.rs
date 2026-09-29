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
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
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
/// Re-recorded for Task F6: UserApplications now carries Assignment rows (plus the new
/// alert/risk fields and service-principal creation dates). The value after F7 was
/// `02d2ce9d5f67b1e628540af5c6fbcb6755068556ad036b9c9a7048e32b7c9bb7`.
///
/// Re-recorded again for Task F8: a user now runs an occasional `New-MailboxSearch`, so the
/// volume tree gains `ExchangeAdmin` rows and the bytes change. The value after F6 was
/// `0b121ea0ed6234f4c23375c009d0671c3c08712a224c338e4436cd378320a34c`. The streaming ==
/// non-streaming equivalence was established at `a900fb1`; re-recording here follows the F6/F7
/// precedent above, because the pre-streaming reference commit `0477080` predates the F4/F6/F7
/// world changes and can no longer serve as the byte reference.
///
/// Re-recorded again for the Task F8 fix: the out-of-office baseline event is now
/// `Set-MailboxAutoReplyConfiguration` at rate 0.02 with service-rendered parameter strings,
/// which changes the volume tree's bytes. The value after the first F8 commit was
/// `0ce824fc22d5b1de43c5a05de2ba072c39993db7872de9dbc681076f2a7ae9ac`.
///
/// Re-recorded again for Task F3: admins now assign the built-in eDiscovery roles, which adds
/// `ExchangeAdmin` `New-ManagementRoleAssignment` rows to every tree including the volume one.
/// The value after the F8 fix was
/// `10936fc24658043797a2b7ad6084bad3c00db89e5c8911b307247c7e12144552`.
///
/// Re-recorded again for Task F4: the `AzureActiveDirectoryStsLogon` AuditData now carries
/// `KeepMeSignedIn`, `UserAuthenticationMethod` and `ZipCode`, the sign-in session properties
/// the Management Activity API records and the real `Converted_Authentication_Logs` captures
/// hold, so every UAL row of the volume tree changes. The parent commit's value was
/// `0b121ea0ed6234f4c23375c009d0671c3c08712a224c338e4436cd378320a34c`; re-running this same
/// test at the parent plus the F4 change gives the value below.
///
/// Re-recorded again for Task F9: the internal mail now holds one subject with a non-ASCII
/// character ("Re: Café supplies"), so the UAL and message-trace rows of the volume tree change
/// with it.
///
/// Re-recorded again for the F3 fix: each role assignment is now created once on its own
/// day instead of re-issued at random, so the volume tree's `ExchangeAdmin` rows differ. The
/// value after the F3 commit was
/// `34ecc6540381e3acc3d0bdacf5ff461587d1f60e331d950f2e02d20a104fe815`.
///
/// Re-recorded again for F4 part B: the flattened AuditData now carries the token / app-access
/// context, the client detail, the item and folder-item properties and the MIA/discovery
/// property lists the real captures hold, so every Exchange record's bytes change. The value
/// after the F3 fix was
/// `8c46a8aba1ed0cafd2abfa66b73fc2d9e8451d5ad475264b8158e0620afb47aa`.
///
/// Re-recorded by the architect after merging the parallel fidelity lanes (F4a + fixes, F9 part 1,
/// F3 fix, F4b) onto one branch: each lane had recorded its own value against its own parent, so
/// the combined tree has a new value. The last single-lane value on this branch was
///
/// Re-recorded again for the F3 fix 2: the benign RBAC change is now one new CUSTOM role
/// assignment at the admin's own sign-in time on a seed-chosen day, so the volume tree's
/// ExchangeAdmin rows differ. The value after F4 part B was
/// `92660857d6e02546fe0494fea809d7336e4c5b0bbace901eff9d46cb4175b979`.
#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn scaled_tree_is_byte_identical_to_the_streaming_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = GenerateOptions::new(Collector::Invictus, 7);
    o.ual_rows = Some(20_000);
    o.signins = Some(5_000);
    generate_to_dir(&load("volume").unwrap(), &o, dir.path()).unwrap();
    assert_eq!(
        tree_digest(dir.path()),
        "bb718ce5f01b8d2f146118974230936e48c00034eade65025baca2727787f276"
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
