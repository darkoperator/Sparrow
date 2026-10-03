//! A cross-binary, cross-process cache of generated trees and of pristine ingested + profiled
//! case files, for the test suites (CARGO_TARGET_TMPDIR/sparrow-cache/).
//!
//! * **Keyed by everything that can change the content.** A tree's key is the SHA-256 of the
//!   whole scenario (serialized) and every generation option; a case's key adds the stage
//!   (profiled, or profiled + detected with the built-in rules). The cache directory itself is
//!   named by the build fingerprint (`BUILD_FINGERPRINT`: generator, parsers, profile, schema,
//!   rules, scenarios, lock file, compiler), so an edit to any of them starts a new directory and
//!   old entries are never read again.
//! * **Pristine, shared, read-only.** An entry's files are published read-only. A test never
//!   opens a cached case: it gets its own COPY (a private directory removed when the `Case`
//!   drops), so it may mutate it freely; a mutation can not reach the next test's copy.
//! * **Concurrency-safe.** An entry is built in a private temp directory and published with one
//!   atomic `rename`; a process that loses the race discards its build and uses the winner's.
//! * **Fail closed.** Every read validates the entry (completion marker, key, fingerprint,
//!   manifest hash, file count / length); anything missing, partial or mismatched is rebuilt in
//!   place from the same key. There is no fallback to another key.
//! * `SPARROW_NO_CACHE=1` bypasses it: trees are generated fresh and cases are ingested into an
//!   in-memory case, exactly as the helpers did before the cache.

use crate::generate::generate_to_dir;
use crate::manifest::Manifest;
use crate::options::GenerateOptions;
use crate::scenario::Scenario;
use crate::testing::{detect_into, ingest_generated, ingest_generated_detected, ingest_into};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// The build fingerprint this library was compiled with (see `fingerprint`).
pub const BUILD_FINGERPRINT: &str = env!("SPARROW_BUILD_FINGERPRINT");

/// The test cache under the calling test target's `CARGO_TARGET_TMPDIR`.
#[macro_export]
macro_rules! test_cache {
    () => {
        $crate::cache::Cache::new(::std::path::Path::new(env!("CARGO_TARGET_TMPDIR")))
    };
}

/// How far a cached case has been taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Ingested and profiled (`ingest_generated`).
    Profiled,
    /// Ingested, profiled and detected with the built-in rules (`ingest_generated_detected`).
    Detected,
}

impl Stage {
    fn tag(self) -> &'static str {
        match self {
            Stage::Profiled => "profiled",
            Stage::Detected => "detected",
        }
    }
}

/// Removes its directory when dropped.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A generated tree: `dir` holds what `generate_to_dir` wrote (the collector root, `geoip/`).
/// A cached tree is shared and read-only: do not write into it.
pub struct CachedTree {
    pub dir: PathBuf,
    pub manifest: Manifest,
    _fresh: Option<Scratch>,
}

/// A private, mutable case plus the tree it was made from.
pub struct CachedCase {
    pub tree: CachedTree,
    pub case: Case,
}

/// What a finished entry records, written last.
#[derive(Debug, Serialize, Deserialize)]
struct Done {
    key: String,
    fingerprint: String,
    /// A tree: sha256 of manifest.json and the number of files under `tree/`.
    manifest_sha256: Option<String>,
    files: Option<u64>,
    /// A case: the length of case.duckdb.
    case_len: Option<u64>,
}

pub struct Cache {
    root: PathBuf,
    fingerprint: String,
    /// `SPARROW_NO_CACHE=1` (read when the cache is created): generate and ingest afresh.
    bypass: bool,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// One lock per entry key, so the tests of one process that need the same entry build it once
/// (the others wait and then read it) instead of each building a copy to lose the rename race.
/// Other processes still race on the rename; the loser discards its build.
fn build_lock(key: &str) -> std::sync::Arc<std::sync::Mutex<()>> {
    static LOCKS: std::sync::LazyLock<
        std::sync::Mutex<std::collections::BTreeMap<String, std::sync::Arc<std::sync::Mutex<()>>>>,
    > = std::sync::LazyLock::new(Default::default);
    let mut m = LOCKS.lock().unwrap_or_else(|p| p.into_inner());
    m.entry(key.to_string()).or_default().clone()
}

fn unique(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn sha_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
        h.update([0]);
    }
    hex::encode(h.finalize())
}

fn io<T>(path: &Path, r: std::io::Result<T>) -> Result<T> {
    r.map_err(|e| Error::io(path, e))
}

fn count_files(dir: &Path) -> u64 {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                n += count_files(&p);
            } else {
                n += 1;
            }
        }
    }
    n
}

/// Make every file under `path` read-only (directories stay writable so entries can be removed).
fn make_read_only(path: &Path) {
    if path.is_dir() {
        if let Ok(rd) = std::fs::read_dir(path) {
            for e in rd.flatten() {
                make_read_only(&e.path());
            }
        }
    } else if let Ok(meta) = std::fs::metadata(path) {
        let mut perm = meta.permissions();
        perm.set_readonly(true);
        let _ = std::fs::set_permissions(path, perm);
    }
}

fn older_than(path: &Path, age: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|d| d > age)
}

impl Cache {
    /// The cache of the current build under `target_tmp` (`CARGO_TARGET_TMPDIR`).
    pub fn new(target_tmp: &Path) -> Cache {
        Cache::with_fingerprint(target_tmp, BUILD_FINGERPRINT)
    }

    /// A cache for an explicit fingerprint (the key-change tests); honours `SPARROW_NO_CACHE`.
    pub fn with_fingerprint(target_tmp: &Path, fingerprint: &str) -> Cache {
        let mut c = Cache::always(target_tmp, fingerprint);
        c.bypass = !Cache::enabled();
        c
    }

    /// A cache that always bypasses itself, as under `SPARROW_NO_CACHE=1` (for its test).
    pub fn bypassed(target_tmp: &Path, fingerprint: &str) -> Cache {
        let mut c = Cache::always(target_tmp, fingerprint);
        c.bypass = true;
        c
    }

    /// Like [`Cache::with_fingerprint`] but never bypassed: the tests of the cache itself must
    /// exercise it whatever `SPARROW_NO_CACHE` says.
    pub fn always(target_tmp: &Path, fingerprint: &str) -> Cache {
        let base = target_tmp.join("sparrow-cache");
        let root = base.join(&fingerprint[..fingerprint.len().min(16)]);
        // Best-effort housekeeping: caches of other builds not touched for two days, and
        // abandoned private directories of killed runs.
        if let Ok(rd) = std::fs::read_dir(&base) {
            for e in rd.flatten() {
                if e.path() != root && older_than(&e.path(), Duration::from_secs(2 * 86_400)) {
                    let _ = std::fs::remove_dir_all(e.path());
                }
            }
        }
        for sub in ["runs", "tmp", "fresh"] {
            if let Ok(rd) = std::fs::read_dir(root.join(sub)) {
                for e in rd.flatten() {
                    if older_than(&e.path(), Duration::from_secs(6 * 3600)) {
                        let _ = std::fs::remove_dir_all(e.path());
                    }
                }
            }
        }
        Cache {
            root,
            fingerprint: fingerprint.to_string(),
            bypass: false,
        }
    }

    /// False when `SPARROW_NO_CACHE=1`.
    pub fn enabled() -> bool {
        std::env::var("SPARROW_NO_CACHE").as_deref() != Ok("1")
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn tree_key(&self, scenario: &Scenario, opts: &GenerateOptions) -> Result<String> {
        let s = serde_json::to_vec(scenario)?;
        let o = serde_json::to_vec(opts)?;
        Ok(sha_hex(&[
            b"sparrow-cache-tree-v1",
            self.fingerprint.as_bytes(),
            &s,
            &o,
        ]))
    }

    fn case_key(&self, tree_key: &str, stage: Stage) -> String {
        sha_hex(&[
            b"sparrow-cache-case-v1",
            self.fingerprint.as_bytes(),
            tree_key.as_bytes(),
            stage.tag().as_bytes(),
        ])
    }

    /// Where the tree for `scenario`/`opts` lives (or would).
    pub fn tree_entry(&self, scenario: &Scenario, opts: &GenerateOptions) -> Result<PathBuf> {
        Ok(self.root.join("trees").join(self.tree_key(scenario, opts)?))
    }

    /// Where the case for `scenario`/`opts` at `stage` lives (or would).
    pub fn case_entry(
        &self,
        scenario: &Scenario,
        opts: &GenerateOptions,
        stage: Stage,
    ) -> Result<PathBuf> {
        let tk = self.tree_key(scenario, opts)?;
        Ok(self.root.join("cases").join(self.case_key(&tk, stage)))
    }

    fn read_done(&self, entry: &Path, key: &str) -> Option<Done> {
        let text = std::fs::read_to_string(entry.join("DONE")).ok()?;
        let d: Done = serde_json::from_str(&text).ok()?;
        (d.key == key && d.fingerprint == self.fingerprint).then_some(d)
    }

    /// The tree of a finished, intact entry, else `None`.
    fn read_tree(&self, entry: &Path, key: &str) -> Option<(PathBuf, Manifest)> {
        let d = self.read_done(entry, key)?;
        let text = std::fs::read(entry.join("manifest.json")).ok()?;
        if d.manifest_sha256.as_deref() != Some(sha_hex(&[&text]).as_str()) {
            return None;
        }
        let dir = entry.join("tree");
        if d.files != Some(count_files(&dir)) {
            return None;
        }
        let manifest = Manifest::from_json(std::str::from_utf8(&text).ok()?).ok()?;
        Some((dir, manifest))
    }

    fn read_case(&self, entry: &Path, key: &str) -> Option<PathBuf> {
        let d = self.read_done(entry, key)?;
        let file = entry.join("case.duckdb");
        let len = std::fs::metadata(&file).ok()?.len();
        let settled = !entry.join("case.duckdb.wal").exists();
        (d.case_len == Some(len) && settled).then_some(file)
    }

    /// Publish `tmp` as `entry` with one atomic rename. A concurrent builder that won the race
    /// keeps its entry; an invalid entry in the way is removed and replaced.
    fn publish(&self, tmp: &Path, entry: &Path, valid: impl Fn() -> bool) -> Result<()> {
        if let Some(parent) = entry.parent() {
            io(parent, std::fs::create_dir_all(parent))?;
        }
        if std::fs::rename(tmp, entry).is_ok() {
            return Ok(());
        }
        if valid() {
            let _ = std::fs::remove_dir_all(tmp);
            return Ok(());
        }
        let _ = std::fs::remove_dir_all(entry);
        if std::fs::rename(tmp, entry).is_ok() || valid() {
            let _ = std::fs::remove_dir_all(tmp);
            return Ok(());
        }
        Err(Error::Invalid(format!(
            "cache entry {} could not be published",
            entry.display()
        )))
    }

    fn fresh_dir(&self) -> Result<Scratch> {
        let dir = self.root.join("fresh").join(unique("tree"));
        io(&dir, std::fs::create_dir_all(&dir))?;
        Ok(Scratch(dir))
    }

    /// The tree for `scenario`/`opts`: read from the cache, or generated and published.
    pub fn tree(&self, scenario: &Scenario, opts: &GenerateOptions) -> Result<CachedTree> {
        if self.bypass {
            let fresh = self.fresh_dir()?;
            let manifest = generate_to_dir(scenario, opts, &fresh.0)?;
            return Ok(CachedTree {
                dir: fresh.0.clone(),
                manifest,
                _fresh: Some(fresh),
            });
        }
        let key = self.tree_key(scenario, opts)?;
        let entry = self.root.join("trees").join(&key);
        if let Some((dir, manifest)) = self.read_tree(&entry, &key) {
            return Ok(CachedTree {
                dir,
                manifest,
                _fresh: None,
            });
        }
        let lock = build_lock(&key);
        let _building = lock.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((dir, manifest)) = self.read_tree(&entry, &key) {
            return Ok(CachedTree {
                dir,
                manifest,
                _fresh: None,
            });
        }
        // Build privately, then publish atomically.
        let tmp = self.root.join("tmp").join(unique(&key[..12]));
        io(&tmp, std::fs::create_dir_all(&tmp))?;
        let built = (|| -> Result<()> {
            let manifest = generate_to_dir(scenario, opts, &tmp.join("tree"))?;
            let text = manifest.to_json_pretty();
            io(&tmp, std::fs::write(tmp.join("manifest.json"), &text))?;
            let done = Done {
                key: key.clone(),
                fingerprint: self.fingerprint.clone(),
                manifest_sha256: Some(sha_hex(&[text.as_bytes()])),
                files: Some(count_files(&tmp.join("tree"))),
                case_len: None,
            };
            io(
                &tmp,
                std::fs::write(tmp.join("DONE"), serde_json::to_string(&done)?),
            )?;
            make_read_only(&tmp);
            Ok(())
        })();
        if let Err(e) = built {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(e);
        }
        self.publish(&tmp, &entry, || self.read_tree(&entry, &key).is_some())?;
        match self.read_tree(&entry, &key) {
            Some((dir, manifest)) => Ok(CachedTree {
                dir,
                manifest,
                _fresh: None,
            }),
            None => Err(Error::Invalid(format!(
                "cache entry {} is not valid after publishing",
                entry.display()
            ))),
        }
    }

    /// [`Cache::case`] for a built-in scenario by name; panics with the cause on failure (the
    /// shape every test helper wants).
    pub fn builtin_case(&self, name: &str, opts: &GenerateOptions, stage: Stage) -> CachedCase {
        let scenario =
            crate::scenario::load(name).unwrap_or_else(|e| panic!("scenario {name}: {e}"));
        self.case(&scenario, opts, stage)
            .unwrap_or_else(|e| panic!("cached case of {name}: {e}"))
    }

    /// A private, mutable case for `scenario`/`opts` taken to `stage`: a copy of the pristine
    /// cached case file (built and published on first use). With `SPARROW_NO_CACHE=1` it is the
    /// in-memory case the helpers always made.
    pub fn case(
        &self,
        scenario: &Scenario,
        opts: &GenerateOptions,
        stage: Stage,
    ) -> Result<CachedCase> {
        let mut tree = self.tree(scenario, opts)?;
        if self.bypass {
            let case = match stage {
                Stage::Profiled => ingest_generated(&tree.dir, &tree.manifest),
                Stage::Detected => ingest_generated_detected(&tree.dir, &tree.manifest),
            };
            // The case remembers the files it was ingested from (`verify` reads them back), so
            // the private tree must live as long as the case does, not as long as `tree`.
            let case = match tree._fresh.take() {
                Some(fresh) => {
                    let dir = fresh.0.clone();
                    std::mem::forget(fresh);
                    case.with_scratch_dir(dir)
                }
                None => case,
            };
            return Ok(CachedCase { tree, case });
        }
        let tkey = self.tree_key(scenario, opts)?;
        let key = self.case_key(&tkey, stage);
        let entry = self.root.join("cases").join(&key);
        let lock = build_lock(&key);
        let _building = lock.lock().unwrap_or_else(|p| p.into_inner());
        let pristine = match self.read_case(&entry, &key) {
            Some(f) => f,
            None => {
                let tmp = self.root.join("tmp").join(unique(&key[..12]));
                io(&tmp, std::fs::create_dir_all(&tmp))?;
                let built = (|| -> Result<()> {
                    let file = tmp.join("case.duckdb");
                    let mut case =
                        Case::create_or_open(&file).map_err(|e| Error::Core(e.to_string()))?;
                    ingest_into(&mut case, &tree.dir, &tree.manifest);
                    if stage == Stage::Detected {
                        let set = sparrow_core::detect::load::load_rules(&DataDirs::default())
                            .map_err(|e| Error::Core(e.to_string()))?;
                        detect_into(&mut case, &tree.manifest, &set);
                    }
                    case.conn()
                        .execute_batch("CHECKPOINT")
                        .map_err(|e| Error::Core(e.to_string()))?;
                    drop(case);
                    let done = Done {
                        key: key.clone(),
                        fingerprint: self.fingerprint.clone(),
                        manifest_sha256: None,
                        files: None,
                        case_len: Some(io(&file, std::fs::metadata(&file))?.len()),
                    };
                    io(
                        &tmp,
                        std::fs::write(tmp.join("DONE"), serde_json::to_string(&done)?),
                    )?;
                    make_read_only(&tmp);
                    Ok(())
                })();
                if let Err(e) = built {
                    let _ = std::fs::remove_dir_all(&tmp);
                    return Err(e);
                }
                self.publish(&tmp, &entry, || self.read_case(&entry, &key).is_some())?;
                self.read_case(&entry, &key).ok_or_else(|| {
                    Error::Invalid(format!(
                        "cache entry {} is not valid after publishing",
                        entry.display()
                    ))
                })?
            }
        };
        drop(_building);
        // The test's own copy, in a directory that goes with the Case.
        let run = self.root.join("runs").join(unique("case"));
        io(&run, std::fs::create_dir_all(&run))?;
        let copy = run.join("case.duckdb");
        io(&copy, std::fs::copy(&pristine, &copy))?;
        let mut perm = io(&copy, std::fs::metadata(&copy))?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        io(&copy, std::fs::set_permissions(&copy, perm))?;
        let case = Case::create_or_open(&copy)
            .map_err(|e| Error::Core(e.to_string()))?
            .with_scratch_dir(run);
        // A case ingested in this process has loaded DuckDB's ICU extension by the time it is
        // profiled, which sets the session time zone to the machine's; a freshly opened file has
        // not, and would render `TIMESTAMPTZ` text in UTC. Read the setting so both behave alike.
        let _ = case
            .conn()
            .query_row("SELECT current_setting('TimeZone')", [], |r| {
                r.get::<_, String>(0)
            });
        Ok(CachedCase { tree, case })
    }
}
