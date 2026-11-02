//! scripts/sweep-target.sh: keeps the newest artifact per crate name in deps/, removes old
//! incremental entries, leaves recent files alone, and `--dry-run` removes nothing. Unix only: a bash script
//! and `touch`.
#![cfg(unix)]

use chrono::{Duration, Utc};
use std::path::Path;
use std::process::Command;

fn script() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/sweep-target.sh")
}

fn touch_days_ago(p: &Path, days: i64) {
    touch_ago(p, Duration::days(days));
}

fn touch_ago(p: &Path, ago: Duration) {
    let stamp = (Utc::now() - ago).format("%Y%m%d%H%M").to_string();
    let ok = Command::new("touch")
        .args(["-t", &stamp])
        .arg(p)
        .status()
        .unwrap()
        .success();
    assert!(ok, "touch {}", p.display());
}

fn make(root: &Path, rel: &str, days_ago: i64) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, rel).unwrap();
    touch_days_ago(&p, days_ago);
}

fn make_dir(root: &Path, rel: &str, days_ago: i64) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.join("inner")).unwrap();
    std::fs::write(p.join("inner/data"), "x").unwrap();
    touch_days_ago(&p, days_ago);
}

fn sweep(target: &Path, args: &[&str]) -> String {
    let out = Command::new("bash")
        .arg(script())
        .args(args)
        .arg(target)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

const H1: &str = "00000000000000a1";
const H2: &str = "00000000000000b2";
const H3: &str = "00000000000000c3";

fn fixture(root: &Path) {
    // Three builds of one test binary and of one library, the middle one the newest.
    for (h, age) in [(H1, 20), (H2, 5), (H3, 10)] {
        make(root, &format!("debug/deps/cache-{h}"), age);
        make(root, &format!("debug/deps/cache-{h}.d"), age);
        make(root, &format!("debug/deps/libsparrow_core-{h}.rlib"), age);
        make_dir(root, &format!("debug/deps/cache-{h}.dSYM"), age);
    }
    // A name with a single build is untouched; a file that is not <name>-<hash> too.
    make(root, "debug/deps/portal-00000000000000d4", 30);
    make(root, "debug/deps/notes.txt", 30);
    // Two builds both touched within the last hour (one may be running): the older one is not
    // the newest, but it is too recent to remove.
    for (hash, minutes) in [("00000000000000e5", 1), ("00000000000000e6", 10)] {
        let rel = format!("debug/deps/fresh-{hash}");
        make(root, &rel, 0);
        touch_ago(&root.join(rel), Duration::minutes(minutes));
    }
    // Another profile dir is swept independently.
    make(root, "release/deps/cache-00000000000000f7", 9);
    make(root, "release/deps/cache-00000000000000f8", 8);
    // Incremental entries: old ones go, recent ones stay.
    make_dir(root, "debug/incremental/old-crate-1abc", 9);
    make_dir(root, "debug/incremental/new-crate-2def", 1);
}

#[test]
fn it_keeps_the_newest_artifact_per_crate_and_drops_old_incremental_data() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    fixture(t);
    let out = sweep(t, &["--days", "3"]);
    let has = |rel: &str| t.join(rel).exists();
    // The newest build (H2) of the test binary and of the library stays, in every kind.
    for kept in [
        format!("debug/deps/cache-{H2}"),
        format!("debug/deps/cache-{H2}.d"),
        format!("debug/deps/libsparrow_core-{H2}.rlib"),
        format!("debug/deps/cache-{H2}.dSYM"),
    ] {
        assert!(has(&kept), "{kept} was removed\n{out}");
    }
    for gone in [H1, H3] {
        for rel in [
            format!("debug/deps/cache-{gone}"),
            format!("debug/deps/cache-{gone}.d"),
            format!("debug/deps/libsparrow_core-{gone}.rlib"),
            format!("debug/deps/cache-{gone}.dSYM"),
        ] {
            assert!(!has(&rel), "{rel} was kept\n{out}");
        }
    }
    assert!(has("debug/deps/portal-00000000000000d4"), "single build");
    assert!(has("debug/deps/notes.txt"), "not an artifact name");
    assert!(
        has("debug/deps/fresh-00000000000000e5") && has("debug/deps/fresh-00000000000000e6"),
        "a stale artifact touched in the last hour is left alone"
    );
    assert!(has("release/deps/cache-00000000000000f8"));
    assert!(!has("release/deps/cache-00000000000000f7"));
    assert!(!has("debug/incremental/old-crate-1abc"), "{out}");
    assert!(has("debug/incremental/new-crate-2def"));
    assert!(out.contains("freed"), "{out}");
}

#[test]
fn a_dry_run_removes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    fixture(t);
    let before: Vec<_> = walk(t);
    let out = sweep(t, &["--dry-run"]);
    assert_eq!(before, walk(t));
    assert!(out.contains("would remove"), "{out}");
    assert!(out.contains("would free"), "{out}");
}

fn walk(dir: &Path) -> Vec<String> {
    let mut v = Vec::new();
    fn go(d: &Path, root: &Path, v: &mut Vec<String>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            v.push(e.path().strip_prefix(root).unwrap().display().to_string());
            if e.path().is_dir() {
                go(&e.path(), root, v);
            }
        }
    }
    go(dir, dir, &mut v);
    v.sort();
    v
}
