//! The generated-tree / pristine-case cache: keys, fail-closed reads, concurrent builders,
//! private mutable copies, and equivalence with the uncached helpers.

use sha2::{Digest, Sha256};
use sparrow_synth::cache::{BUILD_FINGERPRINT, Cache, Stage};
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

/// Make everything under `path` writable again so a test can tamper with an entry.
fn unlock(path: &Path) {
    if path.is_dir() {
        for e in std::fs::read_dir(path).unwrap().flatten() {
            unlock(&e.path());
        }
    } else {
        let mut perm = std::fs::metadata(path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        std::fs::set_permissions(path, perm).unwrap();
    }
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
    let repo = tempfile::tempdir().unwrap();
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
    let tmp = tempfile::tempdir().unwrap();
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
    let tmp = tempfile::tempdir().unwrap();
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
    let tmp = tempfile::tempdir().unwrap();
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
fn a_partial_or_damaged_case_entry_is_rebuilt() {
    let tmp = tempfile::tempdir().unwrap();
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
    let tmp = tempfile::tempdir().unwrap();
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
    let tmp = tempfile::tempdir().unwrap();
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
    let tmp = tempfile::tempdir().unwrap();
    let c = Cache::always(tmp.path(), &"9".repeat(64));
    let s = small();
    let o = opts(3);
    let dir = tempfile::tempdir().unwrap();
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
    let tmp = tempfile::tempdir().unwrap();
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
