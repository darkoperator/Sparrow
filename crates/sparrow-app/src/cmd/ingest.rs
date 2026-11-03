//! Import from the window: preview what discovery finds under a folder (nothing is written), then ingest it into
//! the open case or into a new case file, as `sparrow ingest` does (profile, then detection), with progress events
//! and a Cancel that stops after the file being loaded.
//!
//! The import runs on the app's own open [`Case`] while holding the open-case lock, so no second connection is opened
//! on the file. While it runs `AppState::importing` is set: writes, case switches and reads that queued meanwhile are
//! refused `busy` instead of running after it, and a running events/SQL query is cancelled first so the lock frees
//! up. A native window close during an import is held back until the current file and the profile are done.

use crate::error::{CmdError, CmdResult};
use crate::state::{AppState, check_query_id, query_cancel, with_case};
use serde::{Deserialize, Serialize};
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::detect::DetectOptions;
use sparrow_core::discovery::{
    DiscoveredCollection, Registry, Tool, canonical_root_string, discover_collections,
    list_collection_files,
};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{
    FileReport, IngestOptions, IngestProgress, IngestReport, XLSX_MAX_BYTES,
    ingest_collections_partial, no_collections_error, release_lock_down, restore_lock_down,
};
use sparrow_core::profile::{ProfileOptions, refresh, unprofiled_collections};
use sparrow_core::readers::time::parse_culture;
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Receives each [`ProgressEvent`] (the Tauri command emits `ingest-progress`; tests collect them).
pub type Emit = Arc<dyn Fn(&ProgressEvent) + Send + Sync>;

/// Managed next to [`AppState`]: whether an import runs and which runs the analyst cancelled. Kept apart from the
/// open-case lock, which the import holds, so a cancel never waits for it.
#[derive(Default)]
pub struct IngestState {
    running: AtomicBool,
    shared: Arc<Shared>,
}

#[derive(Default)]
struct Shared {
    /// Run ids cancelled, newest last. A cancel names its run, so one that arrives before the run has started (the
    /// dialog's Cancel pressed at startup) still stops it and never leaks into a later run.
    cancelled: Mutex<VecDeque<String>>,
    /// The window is closing: stop the running import after the current file.
    closing: AtomicBool,
}

/// How many cancelled run ids are remembered.
const MAX_CANCELLED: usize = 64;

impl Shared {
    fn stop_requested(&self, run_id: &str) -> bool {
        self.closing.load(Ordering::SeqCst)
            || self
                .cancelled
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .any(|i| i == run_id)
    }
}

/// Holds the case for an import or profile run: `running` and `AppState::importing` are set while it lives and
/// cleared, in that order, when it ends on every path.
struct RunGuard<'a> {
    ing: &'a IngestState,
    state: &'a AppState,
}

impl<'a> RunGuard<'a> {
    fn claim(ing: &'a IngestState, state: &'a AppState) -> CmdResult<RunGuard<'a>> {
        if ing
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(CmdError::new("invalid", "an import is already running"));
        }
        state.importing.store(true, Ordering::SeqCst);
        // The agent bridge stops for the import (its connections must not hold the file) and comes back after it.
        crate::bridge::stop(state);
        Ok(RunGuard { ing, state })
    }
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        // The bridge comes back while `importing` still refuses closes, switches and a second import.
        crate::bridge::restart(self.state);
        self.state.importing.store(false, Ordering::SeqCst);
        self.ing.shared.closing.store(false, Ordering::SeqCst);
        self.ing.running.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PreviewFile {
    pub rel_path: String,
    pub artifact_id: Option<String>,
    pub derived: bool,
    pub size: u64,
    /// `recognised`, `unrecognised`, `too_large` (over the size limit: ingest refuses it) or `unreadable`.
    pub status: &'static str,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreviewCollection {
    pub tool: Tool,
    pub root: String,
    pub tenant_hint: Option<String>,
    pub started_hint: Option<String>,
    pub files: Vec<PreviewFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryPreview {
    pub path: String,
    pub collections: Vec<PreviewCollection>,
    pub recognised: usize,
    pub unrecognised: usize,
    pub too_large: usize,
    pub unreadable: usize,
    pub max_file_bytes: u64,
}

/// What discovery finds under `path`: collections and each file's classification. Nothing is written.
pub fn ingest_discover(path: &Path) -> CmdResult<DiscoveryPreview> {
    ingest_discover_with(path, &|p| std::fs::metadata(p))
}

/// [`ingest_discover`] reading each file's metadata through `meta` (a test seam for a size that cannot be read).
#[doc(hidden)]
pub fn ingest_discover_with(
    path: &Path,
    meta: &dyn Fn(&Path) -> std::io::Result<std::fs::Metadata>,
) -> CmdResult<DiscoveryPreview> {
    if !path.is_dir() {
        return Err(CmdError::new(
            "invalid",
            format!("{} is not a folder", path.display()),
        ));
    }
    let reg = Registry::builtin();
    let mut preview = DiscoveryPreview {
        path: path.display().to_string(),
        collections: Vec::new(),
        recognised: 0,
        unrecognised: 0,
        too_large: 0,
        unreadable: 0,
        max_file_bytes: XLSX_MAX_BYTES,
    };
    for dc in discover_collections(path)? {
        let listing = list_collection_files(&dc.root, dc.shallow)?;
        let mut files = Vec::new();
        for f in listing.files {
            let class = reg.classify_file(dc.tool, &f.rel, &f.abs);
            let (size, meta_error) = match meta(&f.abs) {
                Ok(m) => (m.len(), None),
                Err(e) => (0, Some(format!("cannot read the file's size: {e}"))),
            };
            let status = if meta_error.is_some() {
                preview.unreadable += 1;
                "unreadable"
            } else if size > XLSX_MAX_BYTES {
                preview.too_large += 1;
                "too_large"
            } else if class.is_some() {
                preview.recognised += 1;
                "recognised"
            } else {
                preview.unrecognised += 1;
                "unrecognised"
            };
            files.push(PreviewFile {
                rel_path: f.rel,
                artifact_id: class.as_ref().map(|c| c.artifact_id.to_string()),
                derived: class.as_ref().is_some_and(|c| c.derived),
                size,
                status,
                error: meta_error,
            });
        }
        for e in listing.errors {
            preview.unreadable += 1;
            files.push(PreviewFile {
                rel_path: e.rel,
                artifact_id: None,
                derived: false,
                size: 0,
                status: "unreadable",
                error: Some(e.message),
            });
        }
        preview.collections.push(PreviewCollection {
            tool: dc.tool,
            root: dc.root.display().to_string(),
            tenant_hint: dc.tenant_hint,
            started_hint: dc.started_hint,
            files,
        });
    }
    Ok(preview)
}

/// Where the evidence goes: the open case, or a new case file at this path (which must not exist yet).
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Open,
    NewCase(PathBuf),
}

/// The `ingest-progress` event payload.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum ProgressEvent {
    Discover,
    Collection {
        index: usize,
        count: usize,
        root: String,
    },
    File {
        collection: usize,
        collections: usize,
        index: usize,
        files: usize,
        rel_path: String,
    },
    Profile,
    Detect,
}

impl From<&IngestProgress> for ProgressEvent {
    fn from(p: &IngestProgress) -> Self {
        match p {
            IngestProgress::Collection { index, count, root } => ProgressEvent::Collection {
                index: *index,
                count: *count,
                root: root.clone(),
            },
            IngestProgress::File {
                collection,
                collections,
                index,
                files,
                rel_path,
            } => ProgressEvent::File {
                collection: *collection,
                collections: *collections,
                index: *index,
                files: *files,
                rel_path: rel_path.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SourceRows {
    pub source: String,
    pub files: usize,
    pub rows: u64,
}

/// A file the analyst should look at: failed, rejected records or warnings (the CLI report's notes).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FileNote {
    pub root: String,
    pub rel_path: String,
    pub status: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct NotLoaded {
    pub root: String,
    pub rel_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectSummary {
    pub findings_new: u64,
    pub findings_updated: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IngestResult {
    pub case_path: String,
    /// True when Cancel (or closing the window) was asked for: detection did not run, and `not_loaded` lists any
    /// file left.
    pub cancelled: bool,
    /// The hard error that stopped the import after the files in `report` had committed (those stay loaded; the
    /// profile ran over them).
    pub error: Option<String>,
    pub report: IngestReport,
    pub files_loaded: usize,
    pub files_total: usize,
    pub rows_by_source: Vec<SourceRows>,
    pub file_notes: Vec<FileNote>,
    pub not_loaded: Vec<NotLoaded>,
    /// The profile step failed after the evidence loaded (run `sparrow profile`).
    pub profile_error: Option<String>,
    pub profile_warnings: Vec<String>,
    /// `None` when detection was skipped (asked, or the import was cancelled) or failed (`detect_error`).
    pub detect: Option<DetectSummary>,
    pub detect_error: Option<String>,
}

/// The CLI's note for a file's rejected records.
fn rejected_note(f: &FileReport) -> Option<String> {
    let records = |n: u64| format!("{n} record{}", if n == 1 { "" } else { "s" });
    let (error, lost) = (f.records_error, f.records_collector_lost);
    match (error, lost) {
        (0, _) => None,
        (e, 0) => Some(format!("{} rejected", records(e))),
        (e, l) if l >= e => Some(format!("{} lost by the collector", records(l))),
        (e, l) => Some(format!(
            "{} rejected ({l} lost by the collector)",
            records(e)
        )),
    }
}

/// `p` made absolute the way the CLI does for a file that may not exist yet: its parent canonicalised.
fn absolute_file_path(p: &Path) -> PathBuf {
    let parent = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    match p.file_name() {
        Some(name) => parent.join(name),
        None => parent,
    }
}

fn refuse_inside_evidence(case_path: &Path, collections: &[DiscoveredCollection]) -> CmdResult<()> {
    let case_abs = absolute_file_path(case_path);
    for c in collections {
        let root = std::fs::canonicalize(&c.root).unwrap_or_else(|_| c.root.clone());
        if case_abs.starts_with(&root) {
            return Err(CmdError::new(
                "invalid",
                format!(
                    "the case file {} is inside the evidence folder {}; keep the case outside the evidence",
                    case_path.display(),
                    c.root.display()
                ),
            ));
        }
    }
    Ok(())
}

enum ProfileOutcome {
    Done(Vec<String>),
    Failed(String),
}

enum DetectOutcome {
    Done(DetectSummary),
    Failed(String),
}

/// Detection runs only when asked for, not stopped, with the ingest whole and the profile it reads from done.
fn detect_wanted(detect: bool, stopped: bool, ingest_failed: bool, profile_ok: bool) -> bool {
    detect && !stopped && !ingest_failed && profile_ok
}

/// The profile step, then detection when [`detect_wanted`]. `stopped` is asked again after the profile, so a Cancel
/// that came during it spares the detection run.
fn profile_and_detect(
    case: &mut Case,
    detect: bool,
    ingest_failed: bool,
    stopped: &dyn Fn() -> bool,
    emit: &Emit,
) -> (ProfileOutcome, Option<DetectOutcome>) {
    let opts = ProfileOptions {
        dirs: DataDirs::from_env(),
        geoip_dir: None,
        as_of: None,
    };
    emit(&ProgressEvent::Profile);
    let profile = match refresh(case, &opts) {
        Ok(r) => ProfileOutcome::Done(r.warnings),
        Err(e) => ProfileOutcome::Failed(format!("{e:#}")),
    };
    let profile_ok = matches!(profile, ProfileOutcome::Done(_));
    if !detect_wanted(detect, stopped(), ingest_failed, profile_ok) {
        return (profile, None);
    }
    emit(&ProgressEvent::Detect);
    let detected =
        match sparrow_core::detect::run::run_with_dirs(case, &opts.dirs, &DetectOptions::default())
        {
            Ok(r) => DetectOutcome::Done(DetectSummary {
                findings_new: r.findings_new,
                findings_updated: r.findings_updated,
                warnings: r.warnings,
            }),
            Err(e) => DetectOutcome::Failed(format!("{e:#}")),
        };
    (profile, Some(detected))
}

/// What the pipeline did, before the result card is built.
struct Piped {
    report: IngestReport,
    stopped: bool,
    error: Option<String>,
    profile: ProfileOutcome,
    detected: Option<DetectOutcome>,
}

/// Ingest `collections` into `case`, then profile (always, over whatever committed) and detect. A hard ingest error
/// after at least one committed file is kept beside the report; with nothing committed it is returned.
fn run_pipeline(
    case: &mut Case,
    collections: &[DiscoveredCollection],
    opts: &IngestOptions,
    detect: bool,
    emit: &Emit,
) -> CmdResult<Piped> {
    let run = ingest_collections_partial(case, collections, &ParserRegistry::builtin(), opts)?;
    let committed = run.report.collections.iter().any(|c| !c.files.is_empty());
    let ingest_failed = run.error.is_some();
    if let Some(e) = run.error {
        if !committed {
            return Err(e.into());
        }
        let stop = || run.stopped || opts.cancelled_now();
        let (profile, _) = profile_and_detect(case, false, true, &stop, emit);
        return Ok(Piped {
            report: run.report,
            stopped: stop(),
            error: Some(format!("{e:#}")),
            profile,
            detected: None,
        });
    }
    let stop = || run.stopped || opts.cancelled_now();
    let (profile, detected) = profile_and_detect(case, detect, ingest_failed, &stop, emit);
    Ok(Piped {
        stopped: stop(),
        report: run.report,
        error: None,
        profile,
        detected,
    })
}

/// The files each collection listed before the import, to say afterwards which ones it did not reach.
fn listing_snapshot(collections: &[DiscoveredCollection]) -> Vec<(String, Vec<String>)> {
    collections
        .iter()
        .map(|dc| {
            let rels = list_collection_files(&dc.root, dc.shallow)
                .map(|l| l.files.into_iter().map(|f| f.rel).collect())
                .unwrap_or_default();
            (canonical_root_string(&dc.root), rels)
        })
        .collect()
}

fn not_loaded(snapshot: &[(String, Vec<String>)], report: &IngestReport) -> Vec<NotLoaded> {
    let mut out = Vec::new();
    for (root, rels) in snapshot {
        let handled: HashSet<&str> = report
            .collections
            .iter()
            .filter(|c| &c.root == root)
            .flat_map(|c| c.files.iter().map(|f| f.rel_path.as_str()))
            .collect();
        out.extend(
            rels.iter()
                .filter(|r| !handled.contains(r.as_str()))
                .map(|r| NotLoaded {
                    root: root.clone(),
                    rel_path: r.clone(),
                }),
        );
    }
    out
}

fn summarise(case_path: String, snapshot: &[(String, Vec<String>)], piped: Piped) -> IngestResult {
    let Piped {
        report,
        stopped,
        error,
        profile,
        detected,
    } = piped;
    let not_loaded = not_loaded(snapshot, &report);
    let files = || report.collections.iter().flat_map(|c| c.files.iter());
    let files_total = files().count() + not_loaded.len();
    let files_loaded = files()
        .filter(|f| f.status == sparrow_core::ingest::FileStatus::Parsed)
        .count();
    let mut by_source: std::collections::BTreeMap<String, (usize, u64)> = Default::default();
    for f in files().filter(|f| f.records_loaded > 0) {
        let e = by_source
            .entry(f.artifact_id.clone().unwrap_or_else(|| "unknown".into()))
            .or_default();
        e.0 += 1;
        e.1 += f.records_loaded;
    }
    let mut file_notes = Vec::new();
    for c in &report.collections {
        for f in &c.files {
            let notes: Vec<String> = rejected_note(f)
                .into_iter()
                .chain(f.warnings.iter().cloned())
                .collect();
            if f.has_problems() || !notes.is_empty() {
                file_notes.push(FileNote {
                    root: c.root.clone(),
                    rel_path: f.rel_path.clone(),
                    status: f.status.as_str().to_string(),
                    notes,
                });
            }
        }
    }
    let (profile_error, profile_warnings) = match profile {
        ProfileOutcome::Failed(e) => (Some(e), Vec::new()),
        ProfileOutcome::Done(w) => (None, w),
    };
    let (detect, detect_error) = match detected {
        Some(DetectOutcome::Done(d)) => (Some(d), None),
        Some(DetectOutcome::Failed(e)) => (None, Some(e)),
        None => (None, None),
    };
    IngestResult {
        case_path,
        cancelled: stopped,
        error,
        files_loaded,
        files_total,
        rows_by_source: by_source
            .into_iter()
            .map(|(source, (files, rows))| SourceRows {
                source,
                files,
                rows,
            })
            .collect(),
        file_notes,
        not_loaded,
        profile_error,
        profile_warnings,
        detect,
        detect_error,
        report,
    }
}

/// Close the open case: its connection can no longer be vouched for as locked down.
fn close_unlocked(state: &AppState, slot: &mut Option<crate::state::OpenCase>) -> CmdError {
    *slot = None;
    state.generation.fetch_add(1, Ordering::SeqCst);
    CmdError::new(
        "internal",
        "the import ended but the case's read-only lock-down could not be restored, so the case was closed; reopen \
         it (data loaded before this point is kept)",
    )
}

/// The open case's connection must be locked down again before the lock is released: the import and the profile and
/// detection runs leave it unlocked. A case that cannot be locked down again is closed.
fn ensure_locked(state: &AppState, slot: &mut Option<crate::state::OpenCase>) -> CmdResult<()> {
    let Some(open) = slot.as_mut() else {
        return Ok(());
    };
    let locked =
        restore_lock_down(&open.case).is_ok() && open.case.is_locked_down().unwrap_or(false);
    if locked {
        Ok(())
    } else {
        Err(close_unlocked(state, slot))
    }
}

/// Run `f` on the open case, then lock its writer down again or close the case, whatever `f` did: return a value, an
/// error, or panic (the panic goes on after the writer is safe, and before the caller's `importing` flag clears).
fn with_relock<T>(
    state: &AppState,
    slot: &mut Option<crate::state::OpenCase>,
    f: impl FnOnce(&mut crate::state::OpenCase) -> CmdResult<T>,
) -> CmdResult<T> {
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match slot.as_mut() {
        Some(open) => f(open),
        None => Err(CmdError::new("no_case", "no case is open")),
    }));
    let locked = ensure_locked(state, slot);
    match out {
        Ok(result) => {
            locked?;
            result
        }
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Import the collections under `path` into `target`. `run_id` names this run for [`ingest_cancel`] (a cancel for it
/// that arrived before the run started still stops it). `culture` is the CLI's `--culture`; `detect` false is
/// `--no-detect`. `emit` gets each stage.
#[allow(clippy::too_many_arguments)]
pub fn ingest_run(
    state: &AppState,
    ing: &IngestState,
    path: &Path,
    target: &Target,
    culture: Option<&str>,
    detect: bool,
    run_id: &str,
    emit: &Emit,
) -> CmdResult<IngestResult> {
    check_query_id(run_id)?;
    let _run = RunGuard::claim(ing, state)?;
    // The case this request saw, before anything is read: the lock check below refuses a different one.
    let generation = state.generation.load(Ordering::SeqCst);
    let date_order = culture
        .filter(|c| !c.trim().is_empty())
        .map(parse_culture)
        .transpose()
        .map_err(|m| CmdError::new("invalid", m))?;
    emit(&ProgressEvent::Discover);
    let collections = discover_collections(path)?;
    if collections.is_empty() {
        return Err(no_collections_error(path).into());
    }
    let snapshot = listing_snapshot(&collections);
    let opts = {
        let shared = ing.shared.clone();
        let id = run_id.to_string();
        let emit = emit.clone();
        IngestOptions {
            date_order,
            progress: Some(Arc::new(move |p: &IngestProgress| {
                emit(&ProgressEvent::from(p))
            })),
            cancel: Some(Arc::new(move || shared.stop_requested(&id))),
            // Profile and detection follow on the same writer and cannot run locked.
            keep_unlocked: true,
            ..IngestOptions::default()
        }
    };
    match target {
        Target::Open => {
            // A running events/SQL query holds the case lock: cancel it so the lock frees up. Reads queued behind
            // it see `importing` once they get the lock and return `busy` at once.
            let running = state
                .active
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .map(|q| q.id.clone());
            if let Some(id) = running {
                let _ = query_cancel(state, &id);
            }
            let mut slot = state.open.lock().unwrap_or_else(|p| p.into_inner());
            if state.generation.load(Ordering::SeqCst) != generation {
                return Err(CmdError::new(
                    "no_case",
                    "the case changed while this request was waiting; reload",
                ));
            }
            let open = slot
                .as_mut()
                .ok_or_else(|| CmdError::new("no_case", "no case is open"))?;
            if let Some(reason) = &open.read_only_reason {
                return Err(CmdError::new("read_only", reason.clone()));
            }
            open.case.ensure_usable()?;
            refuse_inside_evidence(&open.path, &collections)?;
            let case_path = open.path.display().to_string();
            // Detection reopens the writer unlocked: it is locked again, or the case closed, however this ends.
            let piped = with_relock(state, &mut slot, |open| {
                run_pipeline(&mut open.case, &collections, &opts, detect, emit)
            })?;
            Ok(summarise(case_path, &snapshot, piped))
        }
        Target::NewCase(new_path) => {
            if new_path.exists() {
                return Err(CmdError::new(
                    "invalid",
                    format!(
                        "{} already exists; pick a new file name",
                        new_path.display()
                    ),
                ));
            }
            refuse_inside_evidence(new_path, &collections)?;
            let mut case = Case::create_or_open(new_path)?;
            let out = run_pipeline(&mut case, &collections, &opts, detect, emit);
            // Closing the case folds its WAL in; an import that loaded nothing leaves no case file behind.
            drop(case);
            match out {
                Ok(piped) => Ok(summarise(new_path.display().to_string(), &snapshot, piped)),
                Err(e) => {
                    let _ = std::fs::remove_file(new_path);
                    let mut wal = new_path.as_os_str().to_owned();
                    wal.push(".wal");
                    let _ = std::fs::remove_file(PathBuf::from(wal));
                    Err(e)
                }
            }
        }
    }
}

/// Ask the import `run_id` to stop after the file it is loading. Safe to call before the run has started, or after it
/// ended (then it only costs one remembered id).
pub fn ingest_cancel(ing: &IngestState, run_id: &str) -> CmdResult<()> {
    check_query_id(run_id)?;
    let mut ids = ing
        .shared
        .cancelled
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if !ids.iter().any(|i| i == run_id) {
        ids.push_back(run_id.to_string());
        while ids.len() > MAX_CANCELLED {
            ids.pop_front();
        }
    }
    Ok(())
}

/// The window asked to close. While an import runs this asks it to stop after the current file and returns true: the
/// caller keeps the window open until [`wait_idle`] returns, then closes it. Otherwise false.
pub fn window_close_requested(ing: &IngestState) -> bool {
    if ing.running.load(Ordering::SeqCst) {
        ing.shared.closing.store(true, Ordering::SeqCst);
        // It may have ended between the two statements.
        return ing.running.load(Ordering::SeqCst);
    }
    false
}

/// Block until no import runs.
pub fn wait_idle(ing: &IngestState) {
    while ing.running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Collections the profile has not covered (an import that was killed before its profile step): their ids.
pub fn ingest_unprofiled(state: &AppState) -> CmdResult<Vec<i64>> {
    with_case(state, state.ticket(), |open| {
        Ok(unprofiled_collections(open.case.conn())?)
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileRun {
    pub profile_error: Option<String>,
    pub profile_warnings: Vec<String>,
    pub detect: Option<DetectSummary>,
    pub detect_error: Option<String>,
}

/// "Run profile now": the profile step and detection over the open case, as `sparrow profile` does. Analyst-started
/// only; a read-only case is refused.
pub fn ingest_profile(
    state: &AppState,
    ing: &IngestState,
    run_id: &str,
    emit: &Emit,
) -> CmdResult<ProfileRun> {
    check_query_id(run_id)?;
    let _run = RunGuard::claim(ing, state)?;
    let generation = state.generation.load(Ordering::SeqCst);
    let mut slot = state.open.lock().unwrap_or_else(|p| p.into_inner());
    if state.generation.load(Ordering::SeqCst) != generation {
        return Err(CmdError::new(
            "no_case",
            "the case changed while this request was waiting; reload",
        ));
    }
    let open = slot
        .as_mut()
        .ok_or_else(|| CmdError::new("no_case", "no case is open"))?;
    if let Some(reason) = &open.read_only_reason {
        return Err(CmdError::new("read_only", reason.clone()));
    }
    open.case.ensure_usable()?;
    let shared = ing.shared.clone();
    let id = run_id.to_string();
    let stop = move || shared.stop_requested(&id);
    let (profile, detected) = with_relock(state, &mut slot, |open| {
        release_lock_down(&mut open.case)?;
        Ok(profile_and_detect(&mut open.case, true, false, &stop, emit))
    })?;
    let (profile_error, profile_warnings) = match profile {
        ProfileOutcome::Failed(e) => (Some(e), Vec::new()),
        ProfileOutcome::Done(w) => (None, w),
    };
    let (detect, detect_error) = match detected {
        Some(DetectOutcome::Done(d)) => (Some(d), None),
        Some(DetectOutcome::Failed(e)) => (None, Some(e)),
        None => (None, None),
    };
    Ok(ProfileRun {
        profile_error,
        profile_warnings,
        detect,
        detect_error,
    })
}

#[cfg(test)]
mod tests {
    use super::detect_wanted;

    #[test]
    fn detection_needs_to_be_asked_for_unstopped_whole_and_profiled() {
        assert!(detect_wanted(true, false, false, true));
        assert!(!detect_wanted(false, false, false, true), "skip detection");
        assert!(
            !detect_wanted(true, true, false, true),
            "stopped (cancel during the profile)"
        );
        assert!(!detect_wanted(true, false, true, true), "the ingest failed");
        assert!(
            !detect_wanted(true, false, false, false),
            "the profile failed"
        );
    }
}

pub mod commands {
    use super::*;
    use tauri::{AppHandle, Emitter, State};

    #[tauri::command(async)]
    pub fn ingest_discover(path: PathBuf) -> CmdResult<DiscoveryPreview> {
        super::ingest_discover(&path)
    }

    #[tauri::command(async)]
    #[allow(clippy::too_many_arguments)]
    pub fn ingest_run(
        app: AppHandle,
        state: State<'_, AppState>,
        ing: State<'_, IngestState>,
        path: PathBuf,
        target: Target,
        culture: Option<String>,
        detect: bool,
        run_id: String,
    ) -> CmdResult<IngestResult> {
        let emit: Emit = Arc::new(move |e: &ProgressEvent| {
            let _ = app.emit("ingest-progress", e);
        });
        super::ingest_run(
            &state,
            &ing,
            &path,
            &target,
            culture.as_deref(),
            detect,
            &run_id,
            &emit,
        )
    }

    #[tauri::command(async)]
    pub fn ingest_cancel(ing: State<'_, IngestState>, run_id: String) -> CmdResult<()> {
        super::ingest_cancel(&ing, &run_id)
    }

    #[tauri::command(async)]
    pub fn ingest_unprofiled(state: State<'_, AppState>) -> CmdResult<Vec<i64>> {
        super::ingest_unprofiled(&state)
    }

    #[tauri::command(async)]
    pub fn ingest_profile(
        app: AppHandle,
        state: State<'_, AppState>,
        ing: State<'_, IngestState>,
        run_id: String,
    ) -> CmdResult<ProfileRun> {
        let emit: Emit = Arc::new(move |e: &ProgressEvent| {
            let _ = app.emit("ingest-progress", e);
        });
        super::ingest_profile(&state, &ing, &run_id, &emit)
    }
}
