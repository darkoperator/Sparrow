//! A cross-binary, cross-process cache of generated trees and of pristine ingested + profiled
//! case files, for the test suites (CARGO_TARGET_TMPDIR/sparrow-cache/).
//!
//! * **Keyed by everything that can change the content.** A tree's key is the SHA-256 of the
//!   whole scenario (serialized), every generation option and a [`KeyContext`] (the build
//!   profile and optimisation settings, the enabled features of sparrow-core and sparrow-synth,
//!   overflow checks, and the effective time zone); a case's key adds the stage (profiled, or
//!   profiled + detected with the built-in rules). The cache directory itself is named by the
//!   build fingerprint (`BUILD_FINGERPRINT`: generator, parsers, profile, schema, rules,
//!   scenarios, lock file, compiler), so an edit to any of them starts a new directory.
//! * **Only the current build is kept.** The first `Cache::new` in a process deletes the cache
//!   directories of every other build fingerprint, and any private directory (`tmp/`, `runs/`,
//!   `fresh/`) whose owning process is gone.
//! * **Pristine, shared, read-only.** An entry's files are published read-only (directories stay
//!   writable so `rm -rf` and `cargo clean` can remove the cache), and `DONE` records every
//!   file's size, modification time and SHA-256, and the list of files itself.
//!   Each read compares sizes and times (a stat walk); the first read of an entry through a
//!   `Cache` also re-hashes it. Any mismatch rebuilds the entry. A test never opens a cached
//!   case: it gets its own COPY (a copy-on-write clone where the filesystem has one, so it costs
//!   no disk writes until a test changes a page), removed when the `Case` drops. A mutation can
//!   not reach the next test's copy. Cached cases carry the `ingested_at` of the build that made
//!   them, not of the test run that reads them.
//! * **Concurrency-safe.** An entry is built in a private temp directory and published with one
//!   atomic `rename`; a process that loses the race discards its build and uses the winner's.
//!   A per-entry lock file (`EntryLock`) makes the other processes wait for the builder instead
//!   of building a copy to lose the race; it is an optimisation only (a stale or broken lock is
//!   stolen, and correctness never depends on it).
//! * **Fail closed.** Every read validates the entry (completion marker, key, fingerprint,
//!   manifest hash, file list, sizes, times, hashes); anything missing, partial or mismatched is
//!   rebuilt in place from the same key. There is no fallback to another key.
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
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// The build fingerprint this library was compiled with (see `fingerprint`).
pub const BUILD_FINGERPRINT: &str = env!("SPARROW_BUILD_FINGERPRINT");

/// How this library itself was compiled (profile, optimisation, features, rustflags).
const SYNTH_BUILD_CONFIG: &str = env!("SPARROW_SYNTH_BUILD_CONFIG");

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

/// What, beyond the scenario, the options and the sources, can change an entry's content: how the
/// crates were compiled and the time zone the text rendering of timestamps follows. Part of every
/// key, so two builds that differ in any of it never share an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyContext {
    /// Build profile, optimisation level, debug assertions, overflow checks, enabled features and
    /// rustflags of sparrow-core and sparrow-synth.
    pub build: String,
    /// The `TZ` environment variable and the machine's zone.
    pub timezone: String,
}

fn overflow_checks_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        // Probe once, with the panic message silenced for the moment it takes.
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let on = std::panic::catch_unwind(|| {
            let x: u8 = std::hint::black_box(255);
            std::hint::black_box(x + 1)
        })
        .is_err();
        std::panic::set_hook(hook);
        on
    })
}

/// The machine's time zone: `TZ`, else the target of `/etc/localtime` (or `/etc/timezone`).
fn effective_timezone() -> String {
    let tz = std::env::var("TZ").unwrap_or_default();
    let zone = std::fs::read_link("/etc/localtime")
        .map(|p| p.display().to_string())
        .or_else(|_| std::fs::read_to_string("/etc/timezone").map(|t| t.trim().to_string()))
        .unwrap_or_default();
    format!("TZ={tz};zone={zone}")
}

impl KeyContext {
    /// The context of this process.
    pub fn current() -> KeyContext {
        KeyContext {
            build: format!(
                "core[{}] synth[{}] overflow[{},{}]",
                sparrow_core::BUILD_CONFIG,
                SYNTH_BUILD_CONFIG,
                sparrow_core::overflow_checks_on(),
                overflow_checks_on(),
            ),
            timezone: effective_timezone(),
        }
    }
}

/// Removes its directory when dropped (read-only entries included).
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        remove_entry(&self.0);
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

/// One file of a tree entry: path relative to `tree/`, size, modification time and SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FileSig {
    rel: String,
    size: u64,
    mtime_ns: u64,
    sha256: String,
}

/// What a finished entry records, written last.
#[derive(Debug, Serialize, Deserialize)]
struct Done {
    key: String,
    fingerprint: String,
    /// A tree: sha256 of manifest.json, and every file under `tree/`.
    manifest_sha256: Option<String>,
    tree_files: Option<Vec<FileSig>>,
    /// A case: the signature of case.duckdb, and the session time zone the build ingested under.
    case_file: Option<FileSig>,
    time_zone: Option<String>,
}

/// An advisory per-entry lock: a file created with `create_new` that holds its owner's pid.
/// Dropping it removes the file. A lock whose owner is gone (its process no longer exists) or
/// that is older than [`LOCK_MAX_AGE`] is stale and is taken over, so a crashed builder never
/// blocks anyone; a waiter also stops waiting as soon as the entry it wants has been published.
/// Two waiters stealing the same stale lock may both build: the atomic publish makes that
/// harmless, so the lock only avoids duplicate work.
pub struct EntryLock {
    path: Option<PathBuf>,
}

/// A lock this old is taken over whatever its owner is doing.
const LOCK_MAX_AGE: Duration = Duration::from_secs(30 * 60);

fn process_alive(pid: u32) -> bool {
    if !cfg!(unix) || pid == std::process::id() {
        return true;
    }
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(true)
}

fn lock_is_stale(path: &Path) -> bool {
    if older_than(path, LOCK_MAX_AGE) {
        return true;
    }
    match std::fs::read_to_string(path)
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok())
    {
        Some(pid) => !process_alive(pid),
        // No pid (yet, or garbage): it may be mid-creation; give it a minute.
        None => older_than(path, Duration::from_secs(60)),
    }
}

impl EntryLock {
    /// Take the lock at `path`. Returns `None` when `ready()` turned true while waiting (the
    /// entry was built by whoever held the lock); otherwise a guard. If the lock can not be
    /// created at all, or is waited for longer than [`LOCK_MAX_AGE`], the guard is lock-less
    /// and the caller builds anyway.
    pub fn acquire(path: &Path, ready: &dyn Fn() -> bool) -> Option<EntryLock> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let start = Instant::now();
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(mut f) => {
                    use std::io::Write;
                    let _ = write!(f, "{}", std::process::id());
                    return Some(EntryLock {
                        path: Some(path.to_path_buf()),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if ready() {
                        return None;
                    }
                    if lock_is_stale(path) {
                        let _ = std::fs::remove_file(path);
                        continue;
                    }
                    if start.elapsed() > LOCK_MAX_AGE {
                        return Some(EntryLock { path: None });
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => return Some(EntryLock { path: None }),
            }
        }
    }
}

impl Drop for EntryLock {
    fn drop(&mut self) {
        if let Some(p) = &self.path {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Delete the cache directories of every build fingerprint other than `keep` under
/// `target_tmp/sparrow-cache`, and the `synth-*` tree directories an older test helper left in
/// `target_tmp`. The current fingerprint's directory (where other processes may be publishing)
/// is never touched.
pub fn prune_other_builds(target_tmp: &Path, keep_fingerprint: &str) {
    let base = target_tmp.join("sparrow-cache");
    let keep = &keep_fingerprint[..keep_fingerprint.len().min(16)];
    if let Ok(rd) = std::fs::read_dir(&base) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy() != keep {
                remove_entry(&e.path());
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(target_tmp) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("synth-") && older_than(&e.path(), Duration::from_secs(3600)) {
                remove_entry(&e.path());
            }
        }
    }
}

/// The pid in a private directory's name (`<prefix>-<pid>-<n>`, see `unique`).
fn owner_pid(name: &str) -> Option<u32> {
    let mut parts = name.rsplit('-');
    parts.next()?;
    parts.next()?.parse().ok()
}

/// Remove the private directories (`tmp/`, `runs/`, `fresh/`) of `root` whose owning process no
/// longer exists. A directory of a live process (a build in progress, a running test) stays.
pub fn reap_dead_owners(root: &Path) {
    for sub in ["runs", "tmp", "fresh"] {
        let Ok(rd) = std::fs::read_dir(root.join(sub)) else {
            continue;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let dead = match owner_pid(&name) {
                Some(pid) => !process_alive(pid),
                // Not one of ours to judge by pid: only when it has been idle for a long time.
                None => older_than(&e.path(), Duration::from_secs(6 * 3600)),
            };
            if dead {
                remove_entry(&e.path());
            }
        }
    }
}

pub struct Cache {
    root: PathBuf,
    fingerprint: String,
    ctx: KeyContext,
    /// `SPARROW_NO_CACHE=1` (read when the cache is created): generate and ingest afresh.
    bypass: bool,
    /// Entries whose contents this `Cache` has already re-hashed (later reads only stat them).
    verified: Mutex<BTreeSet<PathBuf>>,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// One lock per entry key, so the tests of one process that need the same entry build it once
/// (the others wait and then read it) instead of each building a copy to lose the rename race.
/// Other processes still race on the rename; the loser discards its build.
fn build_lock(key: &str) -> std::sync::Arc<Mutex<()>> {
    static LOCKS: std::sync::LazyLock<
        Mutex<std::collections::BTreeMap<String, std::sync::Arc<Mutex<()>>>>,
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

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_mode(path: &Path, mode: u32) {
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perm = meta.permissions();
        perm.set_readonly(mode & 0o200 == 0);
        let _ = std::fs::set_permissions(path, perm);
    }
}

/// Make every file under `path` read-only (0444). Directories stay writable on purpose: a
/// read-only directory can not be emptied, so `rm -rf` and `cargo clean` would leave the
/// cache behind. An added or removed file is caught by the file-list check on every read.
fn make_read_only(path: &Path) {
    if path.is_dir() {
        if let Ok(rd) = std::fs::read_dir(path) {
            for e in rd.flatten() {
                make_read_only(&e.path());
            }
        }
    } else {
        set_mode(path, 0o444);
    }
}

/// Make everything under `path` writable again, so it can be deleted.
fn make_writable(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        set_mode(path, 0o755);
        if let Ok(rd) = std::fs::read_dir(path) {
            for e in rd.flatten() {
                make_writable(&e.path());
            }
        }
    } else {
        set_mode(path, 0o644);
    }
}

/// Delete a directory tree that may be read-only (a published entry).
fn remove_entry(path: &Path) {
    make_writable(path);
    let _ = std::fs::remove_dir_all(path);
}

fn older_than(path: &Path, age: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|d| d > age)
}

fn mtime_ns(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos() as u64)
}

/// Every file under `dir` as (relative path, size, mtime), sorted; hashes are filled when `hash`.
fn file_sigs(dir: &Path, hash: bool) -> Option<Vec<FileSig>> {
    fn go(root: &Path, d: &Path, hash: bool, out: &mut Vec<FileSig>) -> Option<()> {
        for e in std::fs::read_dir(d).ok()? {
            let p = e.ok()?.path();
            if p.is_dir() {
                go(root, &p, hash, out)?;
            } else {
                let meta = std::fs::metadata(&p).ok()?;
                let sha256 = if hash {
                    hex::encode(Sha256::digest(std::fs::read(&p).ok()?))
                } else {
                    String::new()
                };
                out.push(FileSig {
                    rel: p
                        .strip_prefix(root)
                        .ok()?
                        .to_string_lossy()
                        .replace('\\', "/"),
                    size: meta.len(),
                    mtime_ns: mtime_ns(&meta),
                    sha256,
                });
            }
        }
        Some(())
    }
    let mut out = Vec::new();
    go(dir, dir, hash, &mut out)?;
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Some(out)
}

fn file_sig(path: &Path, hash: bool) -> Option<FileSig> {
    let meta = std::fs::metadata(path).ok()?;
    let sha256 = if hash {
        hex::encode(Sha256::digest(std::fs::read(path).ok()?))
    } else {
        String::new()
    };
    Some(FileSig {
        rel: String::new(),
        size: meta.len(),
        mtime_ns: mtime_ns(&meta),
        sha256,
    })
}

impl Cache {
    /// The cache of the current build under `target_tmp` (`CARGO_TARGET_TMPDIR`). The first call
    /// in a process deletes the caches of every other build.
    pub fn new(target_tmp: &Path) -> Cache {
        static PRUNED: std::sync::Once = std::sync::Once::new();
        PRUNED.call_once(|| prune_other_builds(target_tmp, BUILD_FINGERPRINT));
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
        Cache::always_with(target_tmp, fingerprint, KeyContext::current())
    }

    /// [`Cache::always`] with an explicit key context (the tests that vary one part of it).
    pub fn always_with(target_tmp: &Path, fingerprint: &str, ctx: KeyContext) -> Cache {
        let root = target_tmp
            .join("sparrow-cache")
            .join(&fingerprint[..fingerprint.len().min(16)]);
        reap_dead_owners(&root);
        Cache {
            root,
            fingerprint: fingerprint.to_string(),
            ctx,
            bypass: false,
            verified: Mutex::new(BTreeSet::new()),
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
            b"sparrow-cache-tree-v2",
            self.fingerprint.as_bytes(),
            self.ctx.build.as_bytes(),
            self.ctx.timezone.as_bytes(),
            &s,
            &o,
        ]))
    }

    fn case_key(&self, tree_key: &str, stage: Stage) -> String {
        sha_hex(&[
            b"sparrow-cache-case-v2",
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

    /// Whether `entry` was already re-hashed through this `Cache`.
    fn is_verified(&self, entry: &Path) -> bool {
        self.verified
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(entry)
    }

    fn mark_verified(&self, entry: &Path) {
        self.verified
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(entry.to_path_buf());
    }

    /// The tree of a finished, intact entry, else `None`. Intact: the manifest hash matches, the
    /// files are exactly the recorded ones with their sizes and times, and (first read through
    /// this `Cache`) their contents hash to the recorded values.
    fn read_tree(&self, entry: &Path, key: &str) -> Option<(PathBuf, Manifest)> {
        let d = self.read_done(entry, key)?;
        let text = std::fs::read(entry.join("manifest.json")).ok()?;
        if d.manifest_sha256.as_deref() != Some(sha_hex(&[&text]).as_str()) {
            return None;
        }
        let dir = entry.join("tree");
        let want = d.tree_files.as_ref()?;
        let hash = !self.is_verified(entry);
        let got = file_sigs(&dir, hash)?;
        if got.len() != want.len()
            || got.iter().zip(want).any(|(g, w)| {
                g.rel != w.rel
                    || g.size != w.size
                    || g.mtime_ns != w.mtime_ns
                    || (hash && g.sha256 != w.sha256)
            })
        {
            return None;
        }
        self.mark_verified(entry);
        let manifest = Manifest::from_json(std::str::from_utf8(&text).ok()?).ok()?;
        Some((dir, manifest))
    }

    /// The pristine case file and the time zone it was ingested under, of an intact entry.
    fn read_case(&self, entry: &Path, key: &str) -> Option<(PathBuf, String)> {
        let d = self.read_done(entry, key)?;
        let file = entry.join("case.duckdb");
        let want = d.case_file.as_ref()?;
        let hash = !self.is_verified(entry);
        let got = file_sig(&file, hash)?;
        let settled = !entry.join("case.duckdb.wal").exists();
        if got.size != want.size
            || got.mtime_ns != want.mtime_ns
            || (hash && got.sha256 != want.sha256)
            || !settled
        {
            return None;
        }
        self.mark_verified(entry);
        Some((file, d.time_zone.clone()?))
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
            remove_entry(tmp);
            return Ok(());
        }
        remove_entry(entry);
        if std::fs::rename(tmp, entry).is_ok() || valid() {
            remove_entry(tmp);
            return Ok(());
        }
        Err(Error::Invalid(format!(
            "cache entry {} could not be published",
            entry.display()
        )))
    }

    /// One line per entry actually built (not read), for diagnostics and the lock test.
    fn log_build(&self, what: &str, key: &str) {
        use std::io::Write;
        let _ = std::fs::create_dir_all(&self.root);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("builds.log"))
        {
            // One write call, so lines of concurrent processes never interleave.
            let line = format!("{what} {} pid {}\n", &key[..12], std::process::id());
            let _ = f.write_all(line.as_bytes());
        }
    }

    /// The entries this cache directory has had built so far (`tree <key12> pid <pid>` lines).
    pub fn builds(&self) -> Vec<String> {
        std::fs::read_to_string(self.root.join("builds.log"))
            .map(|t| t.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn entry_lock(&self, key: &str, ready: &dyn Fn() -> bool) -> Option<EntryLock> {
        EntryLock::acquire(
            &self.root.join("locks").join(format!("{}.lock", &key[..16])),
            ready,
        )
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
        let read = || {
            self.read_tree(&entry, &key)
                .map(|(dir, manifest)| CachedTree {
                    dir,
                    manifest,
                    _fresh: None,
                })
        };
        if let Some(t) = read() {
            return Ok(t);
        }
        let lock = build_lock(&key);
        let _building = lock.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(t) = read() {
            return Ok(t);
        }
        let ready = || self.read_tree(&entry, &key).is_some();
        let _file_lock = self.entry_lock(&key, &ready);
        // Whoever held the lock may have built the entry just before we took it.
        if let Some(t) = read() {
            return Ok(t);
        }
        self.log_build("tree", &key);
        // Build privately (removed on any exit, a panic included), then publish atomically.
        let tmp = self.root.join("tmp").join(unique(&key[..12]));
        io(&tmp, std::fs::create_dir_all(&tmp))?;
        let _tmp_guard = Scratch(tmp.clone());
        let manifest = generate_to_dir(scenario, opts, &tmp.join("tree"))?;
        let text = manifest.to_json_pretty();
        io(&tmp, std::fs::write(tmp.join("manifest.json"), &text))?;
        let files = file_sigs(&tmp.join("tree"), true)
            .ok_or_else(|| Error::Invalid(format!("cannot read {}", tmp.display())))?;
        let done = Done {
            key: key.clone(),
            fingerprint: self.fingerprint.clone(),
            manifest_sha256: Some(sha_hex(&[text.as_bytes()])),
            tree_files: Some(files),
            case_file: None,
            time_zone: None,
        };
        io(
            &tmp,
            std::fs::write(tmp.join("DONE"), serde_json::to_string(&done)?),
        )?;
        make_read_only(&tmp);
        self.publish(&tmp, &entry, ready)?;
        read().ok_or_else(|| {
            Error::Invalid(format!(
                "cache entry {} is not valid after publishing",
                entry.display()
            ))
        })
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
        let building = lock.lock().unwrap_or_else(|p| p.into_inner());
        let pristine = match self.read_case(&entry, &key) {
            Some(f) => f,
            None => {
                let ready = || self.read_case(&entry, &key).is_some();
                let _file_lock = self.entry_lock(&key, &ready);
                // Whoever held the lock may have built the entry just before we took it.
                match self.read_case(&entry, &key) {
                    Some(f) => f,
                    None => {
                        self.log_build("case", &key);
                        self.build_case(&tree, &entry, &key, stage, ready)?;
                        self.read_case(&entry, &key).ok_or_else(|| {
                            Error::Invalid(format!(
                                "cache entry {} is not valid after publishing",
                                entry.display()
                            ))
                        })?
                    }
                }
            }
        };
        drop(building);
        self.copy_case(tree, pristine)
    }

    /// Ingest (and profile, and for `Detected` detect) `tree` into a case file in a private
    /// directory and publish it as `entry`.
    fn build_case(
        &self,
        tree: &CachedTree,
        entry: &Path,
        key: &str,
        stage: Stage,
        ready: impl Fn() -> bool,
    ) -> Result<()> {
        let tmp = self.root.join("tmp").join(unique(&key[..12]));
        io(&tmp, std::fs::create_dir_all(&tmp))?;
        let _tmp_guard = Scratch(tmp.clone());
        let file = tmp.join("case.duckdb");
        let mut case = Case::create_or_open(&file).map_err(|e| Error::Core(e.to_string()))?;
        ingest_into(&mut case, &tree.dir, &tree.manifest);
        if stage == Stage::Detected {
            let set = sparrow_core::detect::load::load_rules(&DataDirs::default())
                .map_err(|e| Error::Core(e.to_string()))?;
            detect_into(&mut case, &tree.manifest, &set);
        }
        // The session time zone an in-process ingest ends up with (ICU is loaded by profiling).
        let time_zone: String = case
            .conn()
            .query_row("SELECT current_setting('TimeZone')", [], |r| r.get(0))
            .map_err(|e| Error::Core(e.to_string()))?;
        case.conn()
            .execute_batch("CHECKPOINT")
            .map_err(|e| Error::Core(e.to_string()))?;
        drop(case);
        let done = Done {
            key: key.to_string(),
            fingerprint: self.fingerprint.clone(),
            manifest_sha256: None,
            tree_files: None,
            case_file: Some(
                file_sig(&file, true)
                    .ok_or_else(|| Error::Invalid(format!("cannot read {}", file.display())))?,
            ),
            time_zone: Some(time_zone),
        };
        io(
            &tmp,
            std::fs::write(tmp.join("DONE"), serde_json::to_string(&done)?),
        )?;
        make_read_only(&tmp);
        self.publish(&tmp, entry, ready)
    }

    /// The test's own copy of a pristine case file, in a directory that goes with the `Case`.
    fn copy_case(&self, tree: CachedTree, pristine: (PathBuf, String)) -> Result<CachedCase> {
        let (pristine, time_zone) = pristine;
        let run = self.root.join("runs").join(unique("case"));
        io(&run, std::fs::create_dir_all(&run))?;
        let scratch = Scratch(run.clone());
        let copy = run.join("case.duckdb");
        clone_file(&pristine, &copy)?;
        set_mode(&copy, 0o644);
        let case = Case::create_or_open(&copy)
            .map_err(|e| Error::Core(e.to_string()))?
            .with_scratch_dir(run);
        std::mem::forget(scratch);
        // A case ingested in this process has loaded DuckDB's ICU extension by the time it is
        // profiled, which sets the session time zone to the machine's; a freshly opened file has
        // not, and would render `TIMESTAMPTZ` text in UTC. Set the zone the build ingested under
        // (the machine's, and part of the key) explicitly.
        case.conn()
            .execute_batch(&format!(
                "SET TimeZone = '{}'",
                time_zone.replace('\'', "''")
            ))
            .map_err(|e| Error::Core(e.to_string()))?;
        Ok(CachedCase { tree, case })
    }
}

/// Copy `from` to `to`, as a copy-on-write clone where the filesystem has one (APFS `cp -c`,
/// Linux `cp --reflink=auto`): no data blocks are written until a test changes a page, which
/// keeps the hundreds of per-test copies off the SSD. Falls back to a plain copy.
fn clone_file(from: &Path, to: &Path) -> Result<()> {
    let cloner = if cfg!(target_os = "macos") {
        Some("-c")
    } else if cfg!(target_os = "linux") {
        Some("--reflink=auto")
    } else {
        None
    };
    if let Some(arg) = cloner {
        let ok = std::process::Command::new("cp")
            .arg(arg)
            .arg(from)
            .arg(to)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok && to.is_file() {
            return Ok(());
        }
        let _ = std::fs::remove_file(to);
    }
    io(to, std::fs::copy(from, to)).map(|_| ())
}
