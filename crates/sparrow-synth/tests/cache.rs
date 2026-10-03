//! The generated-tree / pristine-case cache: keys, fail-closed reads, concurrent builders,
//! private mutable copies, and equivalence with the uncached helpers.

use sha2::{Digest, Sha256};
use sparrow_synth::cache::{BUILD_FINGERPRINT, Cache, KeyContext, Stage};
use sparrow_synth::fingerprint::fingerprint;
use sparrow_synth::options::{Collector, Culture, GenerateOptions, PsEdition};
use sparrow_synth::scenario::{Scenario, load};
use sparrow_synth::testing::{ingest_generated, ingest_generated_detected};
use std::path::Path;

fn write(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

fn opts(seed: u64) -> GenerateOptions {
    GenerateOptions::new(Collector::Invictus, seed)
}

fn small() -> Scenario {
    load("business-basic").unwrap()
}

/// Make everything under `path` writable again (directories too) so a test can tamper with an
/// entry or a temp directory holding read-only entries can be removed. Best effort.
fn unlock(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if path.is_dir() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
        if let Ok(rd) = std::fs::read_dir(path) {
            for e in rd.flatten() {
                unlock(&e.path());
            }
        }
    } else {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
    }
}

/// A temp directory that can hold cache entries: their files and directories are read-only, which
/// a plain `TempDir` can not delete (it would leak the entries into the system temp dir), so it
/// is made writable first when the test ends, a panic included.
struct TmpDir(tempfile::TempDir);

impl TmpDir {
    fn path(&self) -> &Path {
        self.0.path()
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        unlock(self.0.path());
    }
}

fn tmpdir() -> TmpDir {
    TmpDir(tempfile::tempdir().unwrap())
}

fn digest_of_file(p: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(p).unwrap()))
}

fn count(case: &sparrow_core::Case, table: &str) -> i64 {
    case.conn()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn a_changed_parser_source_changes_the_build_fingerprint() {
    let repo = tmpdir();
    let r = repo.path();
    write(r, "Cargo.toml", "[workspace]");
    write(r, "Cargo.lock", "lock");
    write(r, "rules/mail/SPW-MAIL-001.yaml", "id: SPW-MAIL-001");
    write(
        r,
        "crates/sparrow-core/src/normalize/ual.rs",
        "fn parse() {}",
    );
    write(
        r,
        "crates/sparrow-core/migrations/0001.sql",
        "create table t(a int);",
    );
    write(r, "crates/sparrow-synth/src/lib.rs", "// gen");
    write(r, "crates/sparrow-synth/scenarios/a.yaml", "name: a");
    write(r, "crates/sparrow-synth/tests/helper.rs", "// test code");
    let base = fingerprint(r, "rustc 1.0");
    assert_eq!(base.len(), 64);
    assert_eq!(base, fingerprint(r, "rustc 1.0"), "deterministic");
    // Test code does not shape the data.
    write(
        r,
        "crates/sparrow-synth/tests/helper.rs",
        "// edited test code",
    );
    assert_eq!(base, fingerprint(r, "rustc 1.0"), "tests/ is not hashed");
    for (rel, text) in [
        (
            "crates/sparrow-core/src/normalize/ual.rs",
            "fn parse() { 1; }",
        ),
        (
            "crates/sparrow-core/migrations/0001.sql",
            "create table t(b int);",
        ),
        (
            "rules/mail/SPW-MAIL-001.yaml",
            "id: SPW-MAIL-001\nseverity: low",
        ),
        ("crates/sparrow-synth/scenarios/a.yaml", "name: b"),
        ("crates/sparrow-synth/src/lib.rs", "// gen 2"),
        ("Cargo.lock", "lock 2"),
    ] {
        let before = std::fs::read_to_string(r.join(rel)).unwrap();
        write(r, rel, text);
        assert_ne!(
            base,
            fingerprint(r, "rustc 1.0"),
            "{rel} must change the key"
        );
        write(r, rel, &before);
        assert_eq!(base, fingerprint(r, "rustc 1.0"), "{rel} restored");
    }
    assert_ne!(
        base,
        fingerprint(r, "rustc 2.0"),
        "the compiler is part of it"
    );
    // A new file in a hashed directory counts too.
    write(r, "crates/sparrow-core/src/normalize/new.rs", "fn x() {}");
    assert_ne!(base, fingerprint(r, "rustc 1.0"));
}

#[test]
fn the_embedded_fingerprint_is_a_sha256() {
    assert_eq!(BUILD_FINGERPRINT.len(), 64);
    assert!(BUILD_FINGERPRINT.bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn every_input_of_a_tree_is_part_of_its_key() {
    let tmp = tmpdir();
    let c = Cache::always(tmp.path(), &"a".repeat(64));
    let s = small();
    let base = c.tree_entry(&s, &opts(1)).unwrap();
    assert_eq!(base, c.tree_entry(&s, &opts(1)).unwrap());
    let mut keys = vec![base.clone()];
    keys.push(c.tree_entry(&s, &opts(2)).unwrap());
    let mut o = opts(1);
    o.ps = PsEdition::Ps51;
    keys.push(c.tree_entry(&s, &o).unwrap());
    let mut o = opts(1);
    o.culture = Culture::DeDe;
    keys.push(c.tree_entry(&s, &o).unwrap());
    keys.push(
        c.tree_entry(&s, &GenerateOptions::new(Collector::Portal, 1))
            .unwrap(),
    );
    let mut edited = s.clone();
    edited.description.push('!');
    keys.push(c.tree_entry(&edited, &opts(1)).unwrap());
    keys.push(c.tree_entry(&load("bec-aitm").unwrap(), &opts(1)).unwrap());
    let other = Cache::always(tmp.path(), &"b".repeat(64));
    keys.push(other.tree_entry(&s, &opts(1)).unwrap());
    let unique: std::collections::BTreeSet<_> = keys.iter().collect();
    assert_eq!(unique.len(), keys.len(), "{keys:#?}");
    // The stage is part of a case's key.
    assert_ne!(
        c.case_entry(&s, &opts(1), Stage::Profiled).unwrap(),
        c.case_entry(&s, &opts(1), Stage::Detected).unwrap()
    );
}

#[test]
fn an_entry_of_another_build_is_never_read() {
    let tmp = tmpdir();
    let s = small();
    let a = Cache::always(tmp.path(), &"a".repeat(64));
    let b = Cache::always(tmp.path(), &"b".repeat(64));
    let ta = a.tree(&s, &opts(1)).unwrap();
    assert!(a.tree_entry(&s, &opts(1)).unwrap().join("DONE").is_file());
    assert!(!b.tree_entry(&s, &opts(1)).unwrap().exists());
    let tb = b.tree(&s, &opts(1)).unwrap();
    assert_ne!(ta.dir, tb.dir);
    assert_eq!(ta.manifest, tb.manifest);
}

#[test]
fn a_partial_or_damaged_tree_entry_is_rebuilt() {
    let tmp = tmpdir();
    let c = Cache::always(tmp.path(), &"c".repeat(64));
    let s = small();
    let good = c.tree(&s, &opts(1)).unwrap();
    let entry = c.tree_entry(&s, &opts(1)).unwrap();
    assert!(entry.join("DONE").is_file());
    // The files are published read-only.
    let some_file = std::fs::read_dir(&good.dir)
        .unwrap()
        .flatten()
        .find(|e| e.path().is_file())
        .map(|e| e.path())
        .or_else(|| Some(entry.join("manifest.json")))
        .unwrap();
    assert!(
        std::fs::metadata(&some_file)
            .unwrap()
            .permissions()
            .readonly()
    );
    unlock(&entry);

    type Damage = (&'static str, fn(&Path));
    let damages: [Damage; 5] = [
        ("no completion marker", |e| {
            std::fs::remove_file(e.join("DONE")).unwrap()
        }),
        ("truncated manifest", |e| {
            std::fs::write(e.join("manifest.json"), "{\"root\":").unwrap()
        }),
        ("a file added to the tree", |e| {
            std::fs::write(e.join("tree").join("stray.txt"), "x").unwrap()
        }),
        ("a file removed from the tree", |e| {
            let victim = walk_first_file(&e.join("tree"));
            std::fs::remove_file(victim).unwrap()
        }),
        ("another build's marker", |e| {
            std::fs::write(
                e.join("DONE"),
                "{\"key\":\"x\",\"fingerprint\":\"y\",\"manifest_sha256\":null,\"files\":null,\"case_len\":null}",
            )
            .unwrap()
        }),
    ];
    for (what, damage) in damages {
        damage(&entry);
        let again = c.tree(&s, &opts(1)).unwrap();
        assert_eq!(again.manifest, good.manifest, "{what}");
        assert!(entry.join("DONE").is_file(), "{what}: repaired in place");
        assert!(
            !entry.join("tree").join("stray.txt").exists(),
            "{what}: the damaged entry is replaced, not patched"
        );
        unlock(&entry);
    }
    // An entry directory with nothing in it at all.
    unlock(&entry);
    std::fs::remove_dir_all(&entry).unwrap();
    std::fs::create_dir_all(&entry).unwrap();
    assert_eq!(c.tree(&s, &opts(1)).unwrap().manifest, good.manifest);
}

fn walk_first_file(dir: &Path) -> std::path::PathBuf {
    let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().collect();
    entries.sort_by_key(|e| e.path());
    let first = entries
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no file under {}", dir.display()));
    if first.path().is_dir() {
        walk_first_file(&first.path())
    } else {
        first.path()
    }
}

#[test]
fn an_empty_directory_added_to_a_cached_tree_forces_a_rebuild() {
    let tmp = tmpdir();
    let c = Cache::always(tmp.path(), &"d".repeat(64));
    let s = small();
    c.tree(&s, &opts(1)).unwrap();
    let entry = c.tree_entry(&s, &opts(1)).unwrap();
    let built = |c: &Cache| c.builds().iter().filter(|l| l.starts_with("tree ")).count();
    assert_eq!(built(&c), 1);
    // Discovery reads empty stamped run directories, so an extra one changes what a test sees.
    let stray = entry.join("tree").join("empty-run-dir");
    std::fs::create_dir(&stray).unwrap();
    // A fresh Cache, so this is the first (hashing) read of the entry.
    let t = Cache::always(tmp.path(), &"d".repeat(64));
    let again = t.tree(&s, &opts(1)).unwrap();
    assert_eq!(built(&t), 2, "the extra directory made the entry rebuild");
    assert!(
        !again.dir.join("empty-run-dir").exists(),
        "the rebuilt tree has no stray directory"
    );
}

#[test]
fn a_partial_or_damaged_case_entry_is_rebuilt() {
    let tmp = tmpdir();
    let c = Cache::always(tmp.path(), &"d".repeat(64));
    let s = small();
    let good = c.case(&s, &opts(1), Stage::Profiled).unwrap();
    let rows = count(&good.case, "ual_events");
    assert!(rows > 0, "the case has sign-ins");
    let entry = c.case_entry(&s, &opts(1), Stage::Profiled).unwrap();
    unlock(&entry);
    type Damage = (&'static str, fn(&Path));
    let damages: [Damage; 4] = [
        ("no completion marker", |e| {
            std::fs::remove_file(e.join("DONE")).unwrap()
        }),
        ("truncated database", |e| {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(e.join("case.duckdb"))
                .unwrap();
            f.set_len(4096).unwrap();
        }),
        ("a leftover write-ahead log", |e| {
            std::fs::write(e.join("case.duckdb.wal"), "x").unwrap()
        }),
        ("empty database file", |e| {
            std::fs::write(e.join("case.duckdb"), "").unwrap()
        }),
    ];
    for (what, damage) in damages {
        damage(&entry);
        let again = c.case(&s, &opts(1), Stage::Profiled).unwrap();
        assert_eq!(count(&again.case, "ual_events"), rows, "{what}");
        assert!(!entry.join("case.duckdb.wal").exists(), "{what}");
        unlock(&entry);
    }
}

#[test]
fn concurrent_builders_publish_one_valid_entry() {
    let tmp = tmpdir();
    let c = std::sync::Arc::new(Cache::always(tmp.path(), &"e".repeat(64)));
    let s = small();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let (c, s, b) = (c.clone(), s.clone(), barrier.clone());
            std::thread::spawn(move || {
                b.wait();
                let got = c.case(&s, &opts(1), Stage::Profiled).unwrap();
                (got.tree.manifest.clone(), count(&got.case, "ual_events"))
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(results.iter().all(|r| r == &results[0]), "{results:?}");
    assert!(results[0].1 > 0);
    // One entry per artifact, complete, and no half-built directory left behind.
    let leftovers = std::fs::read_dir(c.root().join("tmp"))
        .map(|rd| rd.flatten().count())
        .unwrap_or(0);
    assert_eq!(leftovers, 0, "temp build directories are removed");
    assert_eq!(
        std::fs::read_dir(c.root().join("trees")).unwrap().count(),
        1
    );
    assert_eq!(
        std::fs::read_dir(c.root().join("cases")).unwrap().count(),
        1
    );
}

#[test]
fn a_test_that_mutates_its_copy_does_not_touch_the_next_copy() {
    let tmp = tmpdir();
    let c = Cache::always(tmp.path(), &"f".repeat(64));
    let s = small();
    let first = c.case(&s, &opts(1), Stage::Profiled).unwrap();
    let rows = count(&first.case, "ual_events");
    let entry = c.case_entry(&s, &opts(1), Stage::Profiled).unwrap();
    let pristine = entry.join("case.duckdb");
    let before = digest_of_file(&pristine);
    // The cached file is read-only, the copy is not.
    assert!(
        std::fs::metadata(&pristine)
            .unwrap()
            .permissions()
            .readonly()
    );
    assert!(!first.case.path().is_some_and(|p| p == pristine));
    first
        .case
        .conn()
        .execute_batch("DELETE FROM ual_events; CREATE TABLE scratch(a INT)")
        .unwrap();
    assert_eq!(count(&first.case, "ual_events"), 0);
    let second = c.case(&s, &opts(1), Stage::Profiled).unwrap();
    assert_eq!(
        count(&second.case, "ual_events"),
        rows,
        "the next copy is pristine"
    );
    assert!(
        second
            .case
            .conn()
            .query_row("SELECT count(*) FROM scratch", [], |r| r.get::<_, i64>(0))
            .is_err(),
        "the first test's table does not exist in the next copy"
    );
    assert_eq!(
        digest_of_file(&pristine),
        before,
        "the cached file is untouched"
    );
    // A copy's directory goes with it.
    let dir = first.case.path().unwrap().parent().unwrap().to_path_buf();
    assert!(dir.is_dir());
    drop(first);
    assert!(!dir.exists(), "the copy is removed when the case drops");
    // Nothing can write into the cached tree's files.
    let f = walk_first_file(&second.tree.dir);
    assert!(std::fs::OpenOptions::new().append(true).open(f).is_err());
}

fn table_counts(case: &sparrow_core::Case) -> Vec<(String, i64)> {
    let mut st = case
        .conn()
        .prepare("SELECT table_name FROM information_schema.tables WHERE table_schema = 'main' AND table_type = 'BASE TABLE' ORDER BY table_name")
        .unwrap();
    let names: Vec<String> = st
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    names
        .into_iter()
        .map(|n| {
            let c = count(case, &n);
            (n, c)
        })
        .collect()
}

fn detection_digest(case: &sparrow_core::Case) -> String {
    let mut h = Sha256::new();
    for sql in [
        "SELECT finding_id, fingerprint, rule_id, severity, title, actor_upn, CAST(first_seen AS VARCHAR) FROM findings ORDER BY finding_id",
        "SELECT finding_id, source_table, record_key FROM finding_evidence ORDER BY finding_id, source_table, record_key",
        "SELECT tenant_key, rule_id, CAST(status AS VARCHAR), CAST(hits AS VARCHAR) FROM detection_runs ORDER BY tenant_key, rule_id",
    ] {
        let mut st = case.conn().prepare(sql).unwrap();
        let rows = st
            .query_map([], |r| {
                let mut cells = Vec::new();
                for i in 0..r.as_ref().column_count() {
                    let v: Option<String> = r.get(i)?;
                    cells.push(v.unwrap_or_default());
                }
                Ok(cells.join("|"))
            })
            .unwrap();
        for row in rows {
            h.update(row.unwrap().as_bytes());
            h.update(b"\n");
        }
        h.update(b"--");
    }
    hex::encode(h.finalize())
}

#[test]
fn a_cached_case_equals_the_uncached_helper() {
    let tmp = tmpdir();
    let c = Cache::always(tmp.path(), &"9".repeat(64));
    let s = small();
    let o = opts(3);
    let dir = tmpdir();
    let manifest = sparrow_synth::generate::generate_to_dir(&s, &o, dir.path()).unwrap();

    let cached = c.case(&s, &o, Stage::Profiled).unwrap();
    assert_eq!(cached.tree.manifest, manifest, "the same tree");
    let plain = ingest_generated(dir.path(), &manifest);
    let (a, b) = (table_counts(&cached.case), table_counts(&plain));
    assert_eq!(a, b);
    assert!(a.iter().map(|(_, n)| n).sum::<i64>() > 0);

    let cached = c.case(&s, &o, Stage::Detected).unwrap();
    let plain = ingest_generated_detected(dir.path(), &manifest);
    assert_eq!(table_counts(&cached.case), table_counts(&plain));
    // The digest includes timestamps rendered as text: a copy of a cached case must show them in
    // the same session time zone as a case ingested in this process (see `Cache::case`).
    assert_eq!(detection_digest(&cached.case), detection_digest(&plain));
    assert!(count(&cached.case, "detection_runs") > 0, "detection ran");
}

/// `SPARROW_NO_CACHE=1`: nothing is stored, the tree is private and goes with its value, and the
/// case is the in-memory one the helpers always made.
#[test]
fn the_bypass_stores_nothing_and_ingests_in_memory() {
    let tmp = tmpdir();
    let c = Cache::bypassed(tmp.path(), &"7".repeat(64));
    let s = small();
    let dir;
    {
        let got = c.case(&s, &opts(1), Stage::Profiled).unwrap();
        assert!(got.case.path().is_none(), "an in-memory case");
        assert!(count(&got.case, "ual_events") > 0);
        dir = got.tree.dir.clone();
        assert!(dir.is_dir());
        assert!(!c.root().join("trees").exists() && !c.root().join("cases").exists());
    }
    assert!(!dir.exists(), "the private tree is removed with its value");
}

// ---- build locks, pruning of other builds, clean-up ----------------------------------------

use sparrow_synth::cache::{EntryLock, prune_other_builds};

fn dead_pid() -> u32 {
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let pid = child.id();
    child.wait().unwrap();
    pid
}

#[test]
fn the_entry_lock_excludes_a_second_holder_until_it_is_released() {
    let tmp = tmpdir();
    let path = tmp.path().join("locks/k.lock");
    let first = EntryLock::acquire(&path, &|| false).expect("first holder");
    assert!(path.is_file());
    // A second acquirer waits; it is released when the entry becomes ready.
    let ready = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|s| {
        let waiter = s.spawn(|| EntryLock::acquire(&path, &|| ready.load(Ordering::SeqCst)));
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!waiter.is_finished(), "the second acquirer must wait");
        ready.store(true, Ordering::SeqCst);
        assert!(waiter.join().unwrap().is_none(), "the entry became ready");
    });
    // Dropping the holder removes the file, and the lock can be taken again.
    drop(first);
    assert!(!path.exists());
    assert!(EntryLock::acquire(&path, &|| false).is_some());
}

use std::sync::atomic::Ordering;

#[test]
fn a_lock_left_by_a_crashed_holder_is_taken_over() {
    let tmp = tmpdir();
    // The owner is a process that no longer exists.
    let path = tmp.path().join("locks/dead.lock");
    write(tmp.path(), "locks/dead.lock", &dead_pid().to_string());
    let t = std::time::Instant::now();
    let got = EntryLock::acquire(&path, &|| false);
    assert!(got.is_some() && t.elapsed().as_secs() < 5, "stolen at once");
    drop(got);
    // Garbage in the lock file, long untouched.
    let path = tmp.path().join("locks/garbage.lock");
    write(tmp.path(), "locks/garbage.lock", "not a pid");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(old)
        .unwrap();
    assert!(EntryLock::acquire(&path, &|| false).is_some());
    // A live owner (this process) that has held it for over the limit is also overridden.
    let path = tmp.path().join("locks/wedged.lock");
    write(
        tmp.path(),
        "locks/wedged.lock",
        &std::process::id().to_string(),
    );
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3 * 3600);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(old)
        .unwrap();
    assert!(EntryLock::acquire(&path, &|| false).is_some());
}

/// Child half of `cold_builders_in_separate_processes_build_each_entry_once`: builds one case in
/// the cache directory named by the environment, then exits. Does nothing in a normal run.
#[test]
fn cache_child_builder() {
    let Some(dir) = std::env::var_os("SPARROW_CACHE_TEST_DIR") else {
        return;
    };
    let c = Cache::always(Path::new(&dir), &"5".repeat(64));
    let got = c.case(&small(), &opts(1), Stage::Profiled).unwrap();
    assert!(count(&got.case, "ual_events") > 0);
}

#[test]
fn cold_builders_in_separate_processes_build_each_entry_once() {
    let tmp = tmpdir();
    let exe = std::env::current_exe().unwrap();
    let children: Vec<_> = (0..3)
        .map(|_| {
            std::process::Command::new(&exe)
                .args(["--exact", "cache_child_builder", "--nocapture"])
                .env("SPARROW_CACHE_TEST_DIR", tmp.path())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    for mut ch in children {
        assert!(ch.wait().unwrap().success());
    }
    let c = Cache::always(tmp.path(), &"5".repeat(64));
    let builds = c.builds();
    let trees = builds.iter().filter(|l| l.starts_with("tree ")).count();
    let cases = builds.iter().filter(|l| l.starts_with("case ")).count();
    assert_eq!((trees, cases), (1, 1), "each entry built once: {builds:?}");
    assert!(
        std::fs::read_dir(c.root().join("locks")).unwrap().count() == 0,
        "no lock file is left behind"
    );
}

#[test]
fn only_the_current_builds_cache_is_kept() {
    let tmp = tmpdir();
    let t = tmp.path();
    let keep = "a".repeat(64);
    let stale = Cache::always(t, &"b".repeat(64));
    let current = Cache::always(t, &keep);
    stale.tree(&small(), &opts(1)).unwrap();
    current.tree(&small(), &opts(2)).unwrap();
    // A half-built entry of the current build is exactly what another process may be publishing.
    write(
        t,
        "sparrow-cache/aaaaaaaaaaaaaaaa/tmp/building/partial",
        "x",
    );
    // Old helper trees are cleared too, but not a recent one.
    write(t, "synth-old/x", "x");
    write(t, "synth-new/x", "x");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
    std::fs::File::open(t.join("synth-old"))
        .unwrap()
        .set_modified(old)
        .ok();
    prune_other_builds(t, &keep);
    assert!(!stale.root().exists(), "another build's cache is removed");
    assert!(current.root().join("trees").is_dir());
    assert!(
        current.root().join("tmp/building/partial").is_file(),
        "the current build's directory is never touched"
    );
    assert!(t.join("synth-new").is_dir(), "a recent directory stays");
}

#[test]
fn another_builds_cache_with_a_live_owner_survives_pruning_and_a_dead_one_does_not() {
    let tmp = tmpdir();
    let t = tmp.path();
    let keep = "a".repeat(64);
    let base = t.join("sparrow-cache");
    let live = std::process::id();
    let dead = dead_pid();
    for (fp, sub, name) in [
        ("1111111111111111", "runs", format!("case-{live}-0")),
        ("2222222222222222", "tmp", format!("abc-{live}-1")),
        ("3333333333333333", "fresh", format!("tree-{live}-2")),
        ("4444444444444444", "runs", format!("case-{dead}-0")),
        ("5555555555555555", "tmp", format!("abc-{dead}-1")),
    ] {
        write(&base.join(fp), &format!("{sub}/{name}/file"), "x");
        write(&base.join(fp), "trees/k/DONE", "x");
    }
    for fp in ["6666666666666666", "7777777777777777"] {
        write(&base.join(fp), "trees/k/DONE", "x");
    }
    // A live lock file keeps a build alive too; a dead one does not.
    write(
        &base.join("6666666666666666"),
        "locks/k.lock",
        &live.to_string(),
    );
    write(
        &base.join("7777777777777777"),
        "locks/k.lock",
        &dead.to_string(),
    );
    prune_other_builds(t, &keep);
    for fp in [
        "1111111111111111",
        "2222222222222222",
        "3333333333333333",
        "6666666666666666",
    ] {
        assert!(
            base.join(fp).join("trees/k/DONE").is_file(),
            "{fp} has a live owner"
        );
    }
    for fp in ["4444444444444444", "5555555555555555", "7777777777777777"] {
        assert!(!base.join(fp).exists(), "{fp} has only dead owners");
    }
}

#[test]
fn a_build_that_panics_leaves_no_temp_directory_or_lock() {
    let tmp = tmpdir();
    let c = Cache::always(tmp.path(), &"3".repeat(64));
    let mut bad = small();
    // A storyline for a user that does not exist: generation panics (index out of bounds).
    bad.storylines.push(sparrow_synth::scenario::StorySpec {
        kind: sparrow_synth::scenario::StoryKind::AitmSignin,
        id: "s-bad".into(),
        actor: Some(999),
        target: None,
        at: sparrow_synth::scenario::At::Day {
            day: 1,
            hour: 1,
            minute: 0,
        },
    });
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.tree(&bad, &opts(1))));
    assert!(
        r.is_err() || r.unwrap().is_err(),
        "the broken scenario must not produce a tree"
    );
    let left = |sub: &str| {
        std::fs::read_dir(c.root().join(sub))
            .map(|rd| rd.flatten().count())
            .unwrap_or(0)
    };
    assert_eq!(left("tmp"), 0, "the build's temp directory is removed");
    assert_eq!(left("locks"), 0, "the entry lock is released");
    assert_eq!(left("trees"), 0, "nothing was published");
}

// ---- the key context, hashes, dead owners, full-content equivalence ------------------------

#[test]
fn keys_that_differ_only_in_the_build_profile_features_or_time_zone_differ() {
    let tmp = tmpdir();
    let fp = "6".repeat(64);
    let base = KeyContext {
        build: "core[profile=debug;opt=1;features=TEST_FIXTURES] synth[profile=debug] overflow[true,true]".into(),
        timezone: "TZ=;zone=/usr/share/zoneinfo/America/Puerto_Rico".into(),
    };
    let s = small();
    let entry = |ctx: &KeyContext| {
        let c = Cache::always_with(tmp.path(), &fp, ctx.clone());
        (
            c.tree_entry(&s, &opts(1)).unwrap(),
            c.case_entry(&s, &opts(1), Stage::Profiled).unwrap(),
        )
    };
    let variants = [
        ("the same context", base.clone(), false),
        (
            "a release profile",
            KeyContext {
                build: base
                    .build
                    .replace("profile=debug;opt=1", "profile=release;opt=3"),
                ..base.clone()
            },
            true,
        ),
        (
            "an optimisation level",
            KeyContext {
                build: base.build.replace("opt=1", "opt=2"),
                ..base.clone()
            },
            true,
        ),
        (
            "another feature set",
            KeyContext {
                build: base.build.replace("TEST_FIXTURES", "TEST_FIXTURES,OTHER"),
                ..base.clone()
            },
            true,
        ),
        (
            "overflow checks off",
            KeyContext {
                build: base
                    .build
                    .replace("overflow[true,true]", "overflow[false,false]"),
                ..base.clone()
            },
            true,
        ),
        (
            "the TZ variable",
            KeyContext {
                timezone: base.timezone.replace("TZ=;", "TZ=UTC;"),
                ..base.clone()
            },
            true,
        ),
        (
            "the machine zone",
            KeyContext {
                timezone: base.timezone.replace("Puerto_Rico", "Berlin"),
                ..base.clone()
            },
            true,
        ),
    ];
    let reference = entry(&base);
    for (what, ctx, differs) in variants {
        let got = entry(&ctx);
        assert_eq!(got != reference, differs, "{what}");
        if differs {
            assert_ne!(got.0, reference.0, "{what}: tree key");
            assert_ne!(got.1, reference.1, "{what}: case key");
        }
    }
    // The context of this process is itself recorded in the key.
    let now = KeyContext::current();
    assert!(
        !now.build.is_empty() && now.build.contains("profile="),
        "{now:?}"
    );
    assert!(now.timezone.starts_with("TZ="), "{now:?}");
}

#[test]
fn a_tree_file_changed_behind_the_cache_is_detected_by_hash_and_rebuilt() {
    let tmp = tmpdir();
    let fp = "4".repeat(64);
    let s = small();
    let c = Cache::always(tmp.path(), &fp);
    let good = c.tree(&s, &opts(1)).unwrap();
    let entry = c.tree_entry(&s, &opts(1)).unwrap();
    let victim = walk_first_file(&good.dir);
    let before = std::fs::read(&victim).unwrap();
    assert!(!before.is_empty());
    // Same size and same modification time: only the hash can tell.
    let meta = std::fs::metadata(&victim).unwrap();
    let mtime = meta.modified().unwrap();
    unlock(&entry);
    let mut changed = before.clone();
    changed[0] = changed[0].wrapping_add(1);
    std::fs::write(&victim, &changed).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&victim)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    assert_eq!(std::fs::metadata(&victim).unwrap().len(), meta.len());
    // A new `Cache` over the same directory (a new process) re-hashes and rebuilds the entry.
    let again = Cache::always(tmp.path(), &fp).tree(&s, &opts(1)).unwrap();
    assert_eq!(std::fs::read(walk_first_file(&again.dir)).unwrap(), before);
    assert_eq!(again.manifest, good.manifest);
    // A different size or time is caught by the cheap stat check on any read.
    unlock(&entry);
    std::fs::write(&victim, b"short").unwrap();
    let third = c.tree(&s, &opts(1)).unwrap();
    assert_eq!(std::fs::read(walk_first_file(&third.dir)).unwrap(), before);
}

#[test]
fn a_case_file_changed_behind_the_cache_is_rebuilt() {
    let tmp = tmpdir();
    let fp = "2".repeat(64);
    let s = small();
    let c = Cache::always(tmp.path(), &fp);
    let rows = count(
        &c.case(&s, &opts(1), Stage::Profiled).unwrap().case,
        "ual_events",
    );
    let entry = c.case_entry(&s, &opts(1), Stage::Profiled).unwrap();
    let file = entry.join("case.duckdb");
    let meta = std::fs::metadata(&file).unwrap();
    let mtime = meta.modified().unwrap();
    unlock(&entry);
    let mut bytes = std::fs::read(&file).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] = bytes[mid].wrapping_add(1);
    std::fs::write(&file, &bytes).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    let again = Cache::always(tmp.path(), &fp)
        .case(&s, &opts(1), Stage::Profiled)
        .unwrap();
    assert_eq!(count(&again.case, "ual_events"), rows);
    assert_eq!(digest_of_file(&file), {
        let fresh = std::fs::read(&file).unwrap();
        hex::encode(Sha256::digest(fresh))
    });
}

#[test]
fn private_directories_of_dead_processes_are_removed_and_live_ones_kept() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tmpdir();
    let fp = "1".repeat(64);
    let root = tmp.path().join("sparrow-cache").join(&fp[..16]);
    let dead = dead_pid();
    let live = std::process::id();
    for (sub, name) in [
        ("runs", format!("case-{dead}-0")),
        ("tmp", format!("abc-{dead}-3")),
        ("fresh", format!("tree-{dead}-1")),
        ("runs", format!("case-{live}-7")),
        ("tmp", format!("abc-{live}-9")),
    ] {
        write(&root, &format!("{sub}/{name}/inner/file"), "x");
    }
    // A read-only dead directory (a half-published entry) goes too.
    std::fs::set_permissions(
        root.join(format!("tmp/abc-{dead}-3/inner")),
        std::fs::Permissions::from_mode(0o555),
    )
    .unwrap();
    let _ = Cache::always(tmp.path(), &fp);
    for (sub, name) in [
        ("runs", format!("case-{dead}-0")),
        ("tmp", format!("abc-{dead}-3")),
        ("fresh", format!("tree-{dead}-1")),
    ] {
        assert!(!root.join(sub).join(name).exists(), "{sub}");
    }
    assert!(root.join(format!("runs/case-{live}-7")).is_dir());
    assert!(root.join(format!("tmp/abc-{live}-9")).is_dir());
}

/// Every column of every table of the case as text, ordered, minus what legitimately differs
/// between two ingests of the same tree: when the rows were loaded or migrated, how long a rule took, and where the tree lives.
fn full_digest(case: &sparrow_core::Case) -> std::collections::BTreeMap<String, String> {
    const SKIP: [&str; 6] = [
        "ingested_at",
        "changed_at",
        "applied_at",
        "duration_ms",
        "root_path",
        "resolved_path",
    ];
    let mut names = case
        .conn()
        .prepare("SELECT table_name FROM information_schema.tables WHERE table_schema = 'main' AND table_type = 'BASE TABLE' ORDER BY table_name")
        .unwrap();
    let tables: Vec<String> = names
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut per_table = std::collections::BTreeMap::new();
    let mut rows_total = 0usize;
    for t in tables {
        let mut cols = case
            .conn()
            .prepare("SELECT column_name FROM information_schema.columns WHERE table_schema = 'main' AND table_name = ? ORDER BY ordinal_position")
            .unwrap();
        let cols: Vec<String> = cols
            .query_map([&t], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let kept: Vec<&String> = cols
            .iter()
            .filter(|c| !SKIP.contains(&c.as_str()))
            .collect();
        if kept.is_empty() {
            continue;
        }
        let select = kept
            .iter()
            .map(|c| format!("coalesce(CAST(\"{c}\" AS VARCHAR), '<null>')"))
            .collect::<Vec<_>>()
            .join(" || '|' || ");
        let sql = format!("SELECT {select} AS row FROM \"{t}\" ORDER BY row");
        let mut st = case.conn().prepare(&sql).unwrap();
        let mut h = Sha256::new();
        let rows = st.query_map([], |r| r.get::<_, String>(0)).unwrap();
        for row in rows {
            h.update(row.unwrap().as_bytes());
            h.update(b"\n");
            rows_total += 1;
        }
        per_table.insert(t, hex::encode(h.finalize()));
    }
    assert!(
        rows_total > 100,
        "the digest covers real data: {rows_total} rows"
    );
    per_table
}

/// The tables whose content differs between two digests.
fn differing(
    a: &std::collections::BTreeMap<String, String>,
    b: &std::collections::BTreeMap<String, String>,
) -> Vec<String> {
    let names: std::collections::BTreeSet<_> = a.keys().chain(b.keys()).collect();
    names
        .into_iter()
        .filter(|n| a.get(*n) != b.get(*n))
        .cloned()
        .collect()
}

/// A cached case equals the case ingested in this process, table by table and cell by cell, for
/// a default point, a non-default edition and culture, and another collector; and a second
/// (warm) read of each equals the first.
#[test]
fn cached_cases_equal_uncached_ones_in_full() {
    let tmp = tmpdir();
    let c = Cache::always(tmp.path(), &"0".repeat(64));
    let points: Vec<(&str, GenerateOptions)> = vec![
        ("business-basic", opts(3)),
        ("bec-aitm", {
            let mut o = GenerateOptions::new(Collector::Invictus, 4);
            o.ps = PsEdition::Ps51;
            o.culture = Culture::EnGb;
            o
        }),
        (
            "hawk-investigate",
            GenerateOptions::new(Collector::Hawk4, 5),
        ),
    ];
    for (name, o) in points {
        let scenario = load(name).unwrap();
        let dir = tmpdir();
        let manifest = sparrow_synth::generate::generate_to_dir(&scenario, &o, dir.path()).unwrap();
        let plain = full_digest(&ingest_generated(dir.path(), &manifest));
        let cold = c.case(&scenario, &o, Stage::Profiled).unwrap();
        assert_eq!(cold.tree.manifest, manifest, "{name}: the same tree");
        assert_eq!(
            differing(&full_digest(&cold.case), &plain),
            Vec::<String>::new(),
            "{name} cold"
        );
        let warm = c.case(&scenario, &o, Stage::Profiled).unwrap();
        assert_eq!(
            differing(&full_digest(&warm.case), &plain),
            Vec::<String>::new(),
            "{name} warm"
        );
        let detected = c.case(&scenario, &o, Stage::Detected).unwrap();
        let plain_detected = full_digest(&ingest_generated_detected(dir.path(), &manifest));
        assert_eq!(
            full_digest(&detected.case),
            plain_detected,
            "{name} detected"
        );
    }
}
