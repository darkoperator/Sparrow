//! Ingest: discover collections, register every file with its hash, and run parsers
//! inside one transaction per file.

pub mod bulk;
pub mod context;
pub mod parser;
pub mod state;
pub mod supersede;
pub mod timing;

use crate::discovery::runs::run_dirs;
use crate::discovery::{
    Classification, CollectionFile, DiscoveredCollection, FileFormat, Registry, Tool,
    canonical_root_string, discover_collections, format_from_path, list_collection_files,
};
use crate::ingest::context::{FileSource, FileStats, ParseContext, RecordSource, WholeText};
use crate::ingest::parser::{InputMode, ParserRegistry};
use crate::ingest::supersede::{Handled, processing_key, truncation_warning};
use crate::readers::stream::{Admitted, CHUNK_BYTES};
use crate::readers::text::{DecodedText, LineIndex, decode, lossy_warning};
use crate::readers::time::{DateOrder, ParsedTime, parse_timestamp};
use crate::{Case, Error, Result, VERSION};
use duckdb::{Connection, OptionalExt, params};
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;

/// Largest XLSX workbook ingest reads: a workbook is a zip, read whole into memory. `--max-file-size`, when smaller,
/// wins.
pub const XLSX_MAX_BYTES: u64 = 1 << 30;

/// Largest file a parser that reads its file whole (`InputMode::Whole`, a Format-List `.txt` file) is given: such a
/// file is held in memory as bytes, text and line index. CSV and JSON files read as streams have no limit.
pub const WHOLE_FILE_MAX_BYTES: u64 = 256 << 20;

/// Warning on a file with no content (0 bytes, or a byte-order mark and whitespace only).
pub const EMPTY_FILE_WARNING: &str = "file is empty: the collector ran and wrote no records";

/// Prefix of a `parse_errors.error` for a record the COLLECTOR lost (it wrote a failure placeholder instead of the
/// data), as opposed to one Sparrow could not parse. Availability reports the two differently.
pub const COLLECTOR_LOSS: &str = "collector lost the record: ";

/// The warning of a file whose rows loaded but lost their role name to Get-Roles.ps1's Role carry-over (a
/// collector defect): availability counts it as collector loss.
pub const ROLE_CARRY_OVER_WARNING: &str = "lost their role name to the collector's Role carry-over";

/// Replace this collection's `collector_runs` rows with the run folders now on disk.
fn record_collector_runs(case: &mut Case, collection_id: i64, root: &Path) -> Result<()> {
    let runs = run_dirs(root);
    let tx = case.conn_mut().transaction()?;
    tx.execute(
        "DELETE FROM collector_runs WHERE collection_id = ?",
        params![collection_id],
    )?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO collector_runs (collection_id, rel_dir, component, run_stamp, run_stamp_tz_assumed,
                                         run_label, files, empty_files, bytes)
             VALUES (?, ?, ?, CAST(? AS TIMESTAMPTZ), true, ?, ?, ?, ?)",
        )?;
        for r in &runs {
            let stamp = parse_timestamp(&r.stamp.replace('-', "_"), None)
                .ok()
                .map(|t| t.rfc3339());
            stmt.execute(params![
                collection_id,
                r.rel_dir,
                r.component,
                stamp,
                r.label,
                r.files as i64,
                r.empty_files as i64,
                r.bytes as i64
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// What an ingest is about to do, for a caller that shows progress ([`IngestOptions::progress`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum IngestProgress {
    /// A collection is starting; `index` counts from 1 in ingest order (oldest first).
    Collection {
        index: usize,
        count: usize,
        root: String,
    },
    /// A file is about to be handled. `index` is the number of files of the collection finished so far plus one;
    /// `files` is the number the collection lists.
    File {
        collection: usize,
        collections: usize,
        index: usize,
        files: usize,
        rel_path: String,
    },
}

/// Called with each [`IngestProgress`], on the ingesting thread, so it must be quick.
pub type ProgressFn = Arc<dyn Fn(&IngestProgress) + Send + Sync>;

/// Asked before each collection and each file, and while a file is read (each read and each loaded batch): true
/// stops the ingest there. A file stopped midway is rolled back (it leaves no rows, as if it was never tried); the
/// files loaded before it stay loaded and the rest are not touched.
pub type CancelFn = Arc<dyn Fn() -> bool + Send + Sync>;

/// Which read of a file a [`ReadHook`] sees. Test seam.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadPhase {
    /// The admission read (hash, head, encoding).
    Admit,
    /// The n-th record pass of the parser, counting from 1.
    Pass(usize),
}

/// One read of a file, for a [`ReadHook`]. Test seam.
#[doc(hidden)]
#[derive(Debug)]
pub struct ReadEvent<'a> {
    pub rel_path: &'a str,
    pub phase: ReadPhase,
    /// Bytes this read returned; 0 when the read is opened, before its first byte.
    pub bytes: u64,
}

/// Called when a streamed read of a file opens and after each read from it; an error fails that read with it (never
/// `ErrorKind::Interrupted`, which readers retry). Test seam: cancel at a chosen point, inject a read error, change
/// the file between passes.
#[doc(hidden)]
pub type ReadHook = Arc<dyn Fn(&ReadEvent) -> std::io::Result<()> + Send + Sync>;

#[derive(Clone)]
pub struct IngestOptions {
    pub date_order: Option<DateOrder>,
    /// Files larger than this are recorded as errors (`--max-file-size`); `None`, the default, sets no limit. XLSX
    /// workbooks are always limited to [`XLSX_MAX_BYTES`], files read whole to [`WHOLE_FILE_MAX_BYTES`].
    pub max_file_bytes: Option<u64>,
    pub progress: Option<ProgressFn>,
    pub cancel: Option<CancelFn>,
    /// When the writer was locked down (the review app's), leave it unlocked after the ingest for the caller's
    /// profile and detection steps, which cannot run locked; the caller then calls [`restore_lock_down`].
    pub keep_unlocked: bool,
    /// Records the streaming parsers (UAL, sign-ins, message trace detail) normalize and stage per load inside a file's
    /// transaction ([`DEFAULT_BATCH_ROWS`]); such a file is never held whole as records. Tests set small values to
    /// cross batch boundaries.
    pub batch_rows: usize,
    /// Raw bytes per read of a streamed file; `None` is [`CHUNK_BYTES`]. Tests set small values so small files span
    /// many reads.
    pub chunk_bytes: Option<usize>,
    /// Test override of [`WHOLE_FILE_MAX_BYTES`].
    #[doc(hidden)]
    pub whole_max_bytes: Option<u64>,
    /// Test seam: sees every streamed read of every file ([`ReadHook`]).
    #[doc(hidden)]
    pub read_hook: Option<ReadHook>,
}

/// Default [`IngestOptions::batch_rows`].
pub const DEFAULT_BATCH_ROWS: usize = 20_000;

impl std::fmt::Debug for IngestOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngestOptions")
            .field("date_order", &self.date_order)
            .field("max_file_bytes", &self.max_file_bytes)
            .field("progress", &self.progress.as_ref().map(|_| "<fn>"))
            .field("cancel", &self.cancel.as_ref().map(|_| "<fn>"))
            .field("keep_unlocked", &self.keep_unlocked)
            .field("batch_rows", &self.batch_rows)
            .field("chunk_bytes", &self.chunk_bytes)
            .field("whole_max_bytes", &self.whole_max_bytes)
            .field("read_hook", &self.read_hook.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

impl Default for IngestOptions {
    fn default() -> Self {
        IngestOptions {
            date_order: None,
            max_file_bytes: None,
            progress: None,
            cancel: None,
            keep_unlocked: false,
            batch_rows: DEFAULT_BATCH_ROWS,
            chunk_bytes: None,
            whole_max_bytes: None,
            read_hook: None,
        }
    }
}

impl IngestOptions {
    fn report(&self, p: impl FnOnce() -> IngestProgress) {
        if let Some(f) = &self.progress {
            f(&p());
        }
    }

    /// Asks the cancel check now (for a caller that decides what to do after the ingest).
    pub fn cancelled_now(&self) -> bool {
        self.cancelled()
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.cancel.as_ref().is_some_and(|f| f())
    }

    /// Raw bytes per read of a streamed file.
    pub(crate) fn chunk(&self) -> usize {
        self.chunk_bytes.unwrap_or(CHUNK_BYTES).max(1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Parsed,
    DuplicateFile,
    Unrecognized,
    NotSupported,
    SkippedSuperseded,
    Error,
}

impl FileStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            FileStatus::Parsed => "parsed",
            FileStatus::DuplicateFile => "duplicate_file",
            FileStatus::Unrecognized => "unrecognized",
            FileStatus::NotSupported => "not_supported",
            FileStatus::SkippedSuperseded => "skipped_superseded",
            FileStatus::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub file_id: Option<i64>,
    pub rel_path: String,
    pub artifact_id: Option<String>,
    pub status: FileStatus,
    pub records_read: u64,
    pub records_loaded: u64,
    pub records_duplicate: u64,
    pub records_error: u64,
    /// Of `records_error`, records the collector lost (placeholder or error rows it wrote instead of data).
    pub records_collector_lost: u64,
    pub warnings: Vec<String>,
}

impl FileReport {
    /// True when the file failed, a record failed to parse for a reason other than the collector losing it, or the
    /// record counts did not reconcile.
    pub fn has_problems(&self) -> bool {
        self.status == FileStatus::Error
            || self.records_error > self.records_collector_lost
            || self
                .warnings
                .iter()
                .any(|w| w.starts_with("reconciliation mismatch"))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CollectionReport {
    pub collection_id: i64,
    pub tool: Tool,
    pub root: String,
    pub files: Vec<FileReport>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct IngestReport {
    pub collections: Vec<CollectionReport>,
}

/// How an ingest ended, for its exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    /// Every record read was loaded or a duplicate.
    Clean,
    /// The only records not loaded are ones the collector lost (exit code 6).
    CollectorLossOnly,
    /// A file failed, a record failed to parse, or record counts did not reconcile (exit code 2).
    Problems,
}

impl IngestReport {
    /// True when any file failed, any record was rejected (the collector's losses included), or a file's record
    /// counts did not reconcile.
    pub fn has_errors(&self) -> bool {
        self.outcome() != IngestOutcome::Clean
    }

    /// [`IngestOutcome::Problems`] when any file [has problems](FileReport::has_problems), else
    /// [`IngestOutcome::CollectorLossOnly`] when the collector lost a record, else [`IngestOutcome::Clean`].
    pub fn outcome(&self) -> IngestOutcome {
        let files = || self.collections.iter().flat_map(|c| &c.files);
        if files().any(FileReport::has_problems) {
            IngestOutcome::Problems
        } else if files().any(|f| f.records_collector_lost > 0) {
            IngestOutcome::CollectorLossOnly
        } else {
            IngestOutcome::Clean
        }
    }
}

/// The error for a path under which discovery found no collection.
pub fn no_collections_error(path: &Path) -> Error {
    Error::Invalid(format!(
        "no Hawk, Microsoft-Extractor-Suite or portal export output found under {}",
        path.display()
    ))
}

/// Discover the collections under `path` and ingest them.
pub fn ingest_path(
    case: &mut Case,
    path: &Path,
    parsers: &ParserRegistry,
    opts: &IngestOptions,
) -> Result<IngestReport> {
    let collections = discover_collections(path)?;
    if collections.is_empty() {
        return Err(no_collections_error(path));
    }
    ingest_collections(case, &collections, parsers, opts)
}

/// Ingest already-discovered collections, oldest first (collection time ascending, unknown
/// times first, then root path) so a single run merges state in collection order. The
/// report lists the collections in the given order.
pub fn ingest_collections(
    case: &mut Case,
    collections: &[DiscoveredCollection],
    parsers: &ParserRegistry,
    opts: &IngestOptions,
) -> Result<IngestReport> {
    let run = ingest_collections_partial(case, collections, parsers, opts)?;
    match run.error {
        Some(e) => Err(e),
        None => Ok(run.report),
    }
}

/// What an ingest did, including when it stopped early.
#[derive(Debug)]
pub struct IngestRun {
    /// Every file handled before it stopped; each of them is committed.
    pub report: IngestReport,
    /// True when [`IngestOptions::cancel`] asked it to stop and some work was left.
    pub stopped: bool,
    /// The hard error that ended it (a database error, not a file that failed to parse), after the files in `report`
    /// had committed.
    pub error: Option<Error>,
}

/// [`ingest_collections`] that keeps what loaded when a hard error stops it: the files committed before the error are
/// in the report and the error comes back beside them. `Err` only when nothing could start (the case is unusable, the
/// writer could not be released, or the lock-down could not be put back).
pub fn ingest_collections_partial(
    case: &mut Case,
    collections: &[DiscoveredCollection],
    parsers: &ParserRegistry,
    opts: &IngestOptions,
) -> Result<IngestRun> {
    case.ensure_usable()?;
    // The review app locks its writer's configuration, which refuses the ingest's checkpoint setting: reopen the
    // writer unlocked (the file is released and reopened by this very `Case`, never a second open) and lock it
    // again afterwards, whatever the outcome.
    let was_locked = case.is_locked_down()?;
    if was_locked {
        case.with_file_released(|_| Ok(()))?;
    }
    let out = with_ingest_checkpointing(case, |case| {
        Ok(ingest_collections_in_order(
            case,
            collections,
            parsers,
            opts,
        ))
    });
    if was_locked && !opts.keep_unlocked {
        // The caller must not keep using a writer it cannot verify as locked: the error says so.
        restore_lock_down(case)?;
    }
    out
}

/// Unlock a locked-down writer for a profile or detection run (the review app's "profile now"): the file is released
/// and reopened by this very `Case`. Call [`restore_lock_down`] afterwards.
pub fn release_lock_down(case: &mut Case) -> Result<()> {
    if case.is_locked_down()? {
        case.with_file_released(|_| Ok(()))?;
    }
    Ok(())
}

/// Lock the case's writer down again after an ingest, profile or detection run left it unlocked (see
/// [`IngestOptions::keep_unlocked`]).
pub fn restore_lock_down(case: &Case) -> Result<()> {
    #[cfg(any(test, feature = "test-fixtures"))]
    if let Some(e) = fault::relock_fails(case) {
        return Err(e);
    }
    case.lock_down()
}

/// Failure injection for tests: a file whose ingest fails hard, and a lock-down that cannot be put back, each keyed
/// by the case file so parallel tests do not see each other's.
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fault {
    use super::{Case, Error};
    use std::path::PathBuf;
    use std::sync::Mutex;

    static FAIL_FILE: Mutex<Vec<(PathBuf, String)>> = Mutex::new(Vec::new());
    static FAIL_RELOCK: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    static FAIL_PROFILE: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    /// The profile step of the case at `case_path` fails (once).
    pub fn fail_profile(case_path: PathBuf) {
        FAIL_PROFILE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(case_path);
    }

    pub(crate) fn profile_fails(case: &Case) -> bool {
        let Some(path) = case.path() else {
            return false;
        };
        let mut v = FAIL_PROFILE.lock().unwrap_or_else(|p| p.into_inner());
        match v.iter().position(|p| p == path) {
            Some(i) => {
                v.remove(i);
                true
            }
            None => false,
        }
    }

    /// The ingest of `rel_path` into the case at `case_path` fails hard (once), after earlier files committed.
    pub fn fail_file(case_path: PathBuf, rel_path: &str) {
        FAIL_FILE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((case_path, rel_path.to_string()));
    }

    /// Putting the lock-down back after an ingest of the case at `case_path` fails (once).
    pub fn fail_relock(case_path: PathBuf) {
        FAIL_RELOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(case_path);
    }

    pub(super) fn file_fails(case: &Case, rel: &str) -> bool {
        let Some(path) = case.path() else {
            return false;
        };
        let mut v = FAIL_FILE.lock().unwrap_or_else(|p| p.into_inner());
        match v.iter().position(|(p, r)| p == path && r == rel) {
            Some(i) => {
                v.remove(i);
                true
            }
            None => false,
        }
    }

    pub(super) fn relock_fails(case: &Case) -> Option<Error> {
        let path = case.path()?;
        let mut v = FAIL_RELOCK.lock().unwrap_or_else(|p| p.into_inner());
        let i = v.iter().position(|p| p == path)?;
        v.remove(i);
        Some(Error::Invalid("injected: the lock-down failed".into()))
    }
}

/// The highest `checkpoint_threshold` an ingest uses. DuckDB checkpoints automatically inside a COMMIT once the WAL
/// passes the threshold (default 16 MiB), and each checkpoint costs more as the case grows: on the 1M-row Invictus
/// perf tree the per-file commits took 89 of 180 s. With 1 GB the ingest took 104 s and the case was identical, but
/// peak memory grew by 1-2 GB on a 32 GB machine (docs: reports/ingest-profile.md, experiment E2; with no threshold
/// at all, by 4.5 GB for no further gain). Each file still commits its own transaction to the WAL. Under the case's
/// default memory cap ([`crate::db::DEFAULT_MEMORY_LIMIT`], 2 GB) the threshold is 250 MB, below this maximum.
pub const INGEST_CHECKPOINT_MAX: u64 = 1_000_000_000;

/// The ingest threshold is the writer's `memory_limit` divided by this, capped at [`INGEST_CHECKPOINT_MAX`]: the
/// increase in peak memory stays bounded on a small machine (a 2 GiB limit gives 256 MiB).
pub const INGEST_CHECKPOINT_MEMORY_SHARE: u64 = 8;

/// DuckDB's own default `checkpoint_threshold`, which an ingest never goes below.
pub const DUCKDB_DEFAULT_CHECKPOINT: u64 = 16 * 1024 * 1024;

/// Environment variable overriding the ingest threshold: a DuckDB size (`256MB`, `1GiB`, ...) or `default` (keep
/// DuckDB's own value).
pub const CHECKPOINT_ENV: &str = "SPARROW_INGEST_CHECKPOINT";

/// The `checkpoint_threshold` (bytes) an ingest sets on the writer, or `None` to keep DuckDB's current value.
/// Without an override: `memory_limit` / [`INGEST_CHECKPOINT_MEMORY_SHARE`], capped at [`INGEST_CHECKPOINT_MAX`],
/// and `None` when that is not above [`DUCKDB_DEFAULT_CHECKPOINT`] or the limit does not parse (never raised on a
/// guess). An override ([`CHECKPOINT_ENV`]) is a size above zero or `default`; anything else is an error.
fn ingest_checkpoint_threshold(memory_limit: &str, override_: Option<&str>) -> Result<Option<u64>> {
    if let Some(v) = override_ {
        if v.trim().eq_ignore_ascii_case("default") {
            return Ok(None);
        }
        return match crate::db::parse_size(v) {
            Some(bytes) if bytes > 0 => Ok(Some(bytes)),
            _ => Err(Error::Invalid(format!(
                "{CHECKPOINT_ENV}={v:?} is not a size: use a DuckDB size such as 256MB or 1GiB, or `default` to keep DuckDB's own checkpoint threshold"
            ))),
        };
    }
    Ok(crate::db::parse_size(memory_limit)
        .map(|limit| (limit / INGEST_CHECKPOINT_MEMORY_SHARE).min(INGEST_CHECKPOINT_MAX))
        .filter(|&t| t > DUCKDB_DEFAULT_CHECKPOINT))
}

/// [`with_ingest_checkpointing_using`] with the override from [`CHECKPOINT_ENV`].
fn with_ingest_checkpointing<T>(
    case: &mut Case,
    load: impl FnOnce(&mut Case) -> Result<T>,
) -> Result<T> {
    let over = std::env::var(CHECKPOINT_ENV).ok();
    with_ingest_checkpointing_using(case, over.as_deref(), load)
}

/// Run `load` with the ingest threshold ([`ingest_checkpoint_threshold`] of the writer's `memory_limit` and
/// `override_`) on the writer, then put the previous threshold back, whether `load` returns, fails or panics, and on
/// success fold the WAL in with one `CHECKPOINT`. An invalid override fails before `load` runs; an error of `load`
/// is the one returned; a panic goes on after the restore.
fn with_ingest_checkpointing_using<T>(
    case: &mut Case,
    override_: Option<&str>,
    load: impl FnOnce(&mut Case) -> Result<T>,
) -> Result<T> {
    let setting = |case: &Case, name: &str| -> Result<String> {
        Ok(case
            .conn()
            .query_row(&format!("SELECT current_setting('{name}')"), [], |r| {
                r.get(0)
            })?)
    };
    let previous = setting(case, "checkpoint_threshold")?;
    let target = ingest_checkpoint_threshold(&setting(case, "memory_limit")?, override_)?;
    if let Some(bytes) = target {
        case.conn()
            .execute_batch(&format!("SET checkpoint_threshold = '{bytes} bytes'"))?;
    }
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| load(&mut *case)));
    let restored = case.conn().execute_batch(&format!(
        "SET checkpoint_threshold = '{}'",
        previous.replace('\'', "''")
    ));
    let value = match out {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    restored?;
    let _t = timing::span("ingest: final CHECKPOINT");
    case.conn().execute_batch("CHECKPOINT")?;
    Ok(value)
}

/// [`ingest_collections`] without the checkpoint setting: the collections oldest first.
fn ingest_collections_in_order(
    case: &mut Case,
    collections: &[DiscoveredCollection],
    parsers: &ParserRegistry,
    opts: &IngestOptions,
) -> IngestRun {
    let mut order: Vec<usize> = (0..collections.len()).collect();
    order.sort_by_cached_key(|&i| {
        let dc = &collections[i];
        (started_at(dc).map(|t| t.utc), dc.root.clone())
    });
    let mut done: Vec<Option<CollectionReport>> = vec![None; collections.len()];
    let count = collections.len();
    let (mut stopped, mut error) = (false, None);
    for (n, i) in order.into_iter().enumerate() {
        if opts.cancelled() {
            stopped = true;
            break;
        }
        match ingest_collection(
            case,
            &collections[i],
            parsers,
            opts,
            (n + 1, count),
            &mut stopped,
        ) {
            Ok(report) => done[i] = Some(report),
            Err(halt) => {
                done[i] = halt.report;
                error = Some(halt.error);
                break;
            }
        }
        if stopped {
            break;
        }
    }
    IngestRun {
        report: IngestReport {
            collections: done.into_iter().flatten().collect(),
        },
        stopped,
        error,
    }
}

/// An ingest of one collection that ended on a hard error: what committed before it, and the error.
struct Halt {
    report: Option<CollectionReport>,
    error: Error,
}

impl From<Error> for Box<Halt> {
    fn from(error: Error) -> Self {
        Box::new(Halt {
            report: None,
            error,
        })
    }
}

/// Collection time from the collection's folder name, when it has one.
fn started_at(dc: &DiscoveredCollection) -> Option<ParsedTime> {
    dc.started_hint
        .as_deref()
        .and_then(|s| parse_timestamp(s, None).ok())
}

struct FileJob<'a> {
    collection_id: i64,
    tool: Tool,
    abs: &'a Path,
    rel: &'a str,
    /// True when a path component is not valid UTF-8 (rel shows U+FFFD).
    lossy_name: bool,
    /// Already-handled file that makes this one redundant.
    superseded_by: Option<String>,
    /// Day/month order proved by the rest of the collection (retry pass).
    date_hint: Option<DateOrder>,
    /// Defer the file when all its culture dates are ambiguous (first pass).
    defer: bool,
    /// The rest of the collection proved both orders (retry pass).
    orders_conflict: bool,
}

/// Result of handling one file: done (with the day/month orders its dates proved), or
/// deferred to the collection's retry pass.
enum Outcome {
    Done(FileReport, Vec<DateOrder>),
    Deferred,
    /// The ingest was cancelled while the file was read; it was rolled back and left no rows.
    Cancelled,
}

impl Outcome {
    fn plain(report: FileReport) -> Self {
        Outcome::Done(report, Vec::new())
    }
}

fn ingest_collection(
    case: &mut Case,
    dc: &DiscoveredCollection,
    parsers: &ParserRegistry,
    opts: &IngestOptions,
    (position, collections): (usize, usize),
    stopped: &mut bool,
) -> std::result::Result<CollectionReport, Box<Halt>> {
    let root = canonical_root_string(&dc.root);
    opts.report(|| IngestProgress::Collection {
        index: position,
        count: collections,
        root: root.clone(),
    });
    let collection_id = upsert_collection(case.conn(), dc, &root)?;
    if dc.tool == Tool::Invictus {
        let _t = timing::span("collection: collector_runs");
        record_collector_runs(case, collection_id, &dc.root)?;
    }
    let listing = {
        let _t = timing::span("collection: list files");
        list_collection_files(&dc.root, dc.shallow)?
    };
    let _classify = timing::span("collection: classify + order");
    let reg = Registry::builtin();
    let mut keyed: Vec<(&CollectionFile, bool, bool, Option<&'static str>, i16)> = listing
        .files
        .iter()
        .map(|f| {
            let class = reg.classify(dc.tool, &f.rel);
            let derived = class.as_ref().is_some_and(|c| c.derived);
            let flag = class
                .as_ref()
                .is_some_and(|c| c.artifact_id == "hawk.investigate_file");
            let artifact = class.as_ref().map(|c| c.artifact_id);
            let priority = class.as_ref().map_or(0, |c| c.priority);
            (f, derived, flag, artifact, priority)
        })
        .collect();
    // Collector flags last: their links look up rows the other files load.
    keyed.sort_by_cached_key(|(f, derived, flag, _, priority)| {
        (*flag, processing_key(&f.rel, *derived, *priority))
    });
    drop(_classify);
    let total_files = keyed.len();
    let mut handled = Handled::default();
    // Note every listed file's artifact up front: the supersede rules need to know which files
    // are QuickUAL per-operation exports even before any of them is handled.
    for (f, _, _, artifact, _) in &keyed {
        if let Some(a) = artifact {
            handled.note_artifact(&f.rel, a);
        }
    }
    // Raw files, then derived files and collector flags, each stage with its own retry pass:
    // a raw file deferred for its ambiguous dates is handled before any derived file when the
    // raw files proved the order, so the raw records still supersede the derived copies
    // (spec §6); otherwise it waits for the derived files' proof.
    let (raw, rest): (Vec<_>, Vec<_>) = keyed
        .into_iter()
        .partition(|(_, derived, flag, _, _)| !derived && !flag);
    let mut files = Vec::new();
    // Orders proved by files of this collection parsed in earlier runs count too.
    let mut proved = orders_proved_earlier(case.conn(), collection_id)?;
    // Raw files the raw stage could not order (no proof yet, no conflict): a derived file may
    // still prove the order, so they are retried with the derived stage's deferred files.
    let mut carried: Vec<(&CollectionFile, bool, Option<&'static str>)> = Vec::new();
    for (i, stage) in [raw, rest].into_iter().enumerate() {
        let last = i == 1;
        let mut deferred: Vec<(&CollectionFile, bool, Option<&'static str>)> = Vec::new();
        for (f, derived, _, artifact, _) in stage {
            if opts.cancelled() {
                *stopped = true;
                // Entries discovery could not read are still recorded as errors, never lost in a cancel.
                record_listing_errors(case, collection_id, &listing, &mut files)?;
                return Ok(CollectionReport {
                    collection_id,
                    tool: dc.tool,
                    root,
                    files,
                });
            }
            opts.report(|| IngestProgress::File {
                collection: position,
                collections,
                index: files.len() + 1,
                files: total_files,
                rel_path: f.rel.clone(),
            });
            let job = FileJob {
                collection_id,
                tool: dc.tool,
                abs: &f.abs,
                rel: &f.rel,
                lossy_name: f.lossy_name,
                superseded_by: handled.superseded_by(&f.rel, derived),
                date_hint: None,
                defer: true,
                orders_conflict: false,
            };
            let outcome = match ingest_file(case, &job, parsers, opts) {
                Ok(o) => o,
                Err(error) => {
                    return Err(Box::new(Halt {
                        report: Some(CollectionReport {
                            collection_id,
                            tool: dc.tool,
                            root,
                            files,
                        }),
                        error,
                    }));
                }
            };
            if matches!(outcome, Outcome::Cancelled) {
                // Cancelled mid-file (rolled back): the ingest stops as a cancel between files does.
                *stopped = true;
                record_listing_errors(case, collection_id, &listing, &mut files)?;
                return Ok(CollectionReport {
                    collection_id,
                    tool: dc.tool,
                    root,
                    files,
                });
            }
            match outcome {
                Outcome::Deferred => {
                    handled.insert_failed(&f.rel);
                    deferred.push((f, derived, artifact));
                }
                Outcome::Cancelled => unreachable!("handled above"),
                Outcome::Done(report, orders) => {
                    mark_handled(&mut handled, &f.rel, &report);
                    for o in orders {
                        if !proved.contains(&o) {
                            proved.push(o);
                        }
                    }
                    files.push(report);
                }
            }
        }
        // Files whose culture dates were all ambiguous: retry them with the order the
        // collection proved so far, when it proved exactly one.
        let hint = match proved.as_slice() {
            [only] => Some(*only),
            _ => None,
        };
        if !last && proved.is_empty() {
            carried.append(&mut deferred);
            continue;
        }
        let retry = if last {
            std::mem::take(&mut carried)
                .into_iter()
                .chain(deferred)
                .collect()
        } else {
            deferred
        };
        for (f, derived, _) in retry {
            if opts.cancelled() {
                *stopped = true;
                // Entries discovery could not read are still recorded as errors, never lost in a cancel.
                record_listing_errors(case, collection_id, &listing, &mut files)?;
                return Ok(CollectionReport {
                    collection_id,
                    tool: dc.tool,
                    root,
                    files,
                });
            }
            opts.report(|| IngestProgress::File {
                collection: position,
                collections,
                index: files.len() + 1,
                files: total_files,
                rel_path: f.rel.clone(),
            });
            let job = FileJob {
                collection_id,
                tool: dc.tool,
                abs: &f.abs,
                rel: &f.rel,
                lossy_name: f.lossy_name,
                superseded_by: handled.superseded_by(&f.rel, derived),
                date_hint: hint,
                defer: false,
                orders_conflict: proved.len() > 1,
            };
            let outcome = match ingest_file(case, &job, parsers, opts) {
                Ok(o) => o,
                Err(error) => {
                    return Err(Box::new(Halt {
                        report: Some(CollectionReport {
                            collection_id,
                            tool: dc.tool,
                            root,
                            files,
                        }),
                        error,
                    }));
                }
            };
            if matches!(outcome, Outcome::Cancelled) {
                // Cancelled mid-file (rolled back): the ingest stops as a cancel between files does.
                *stopped = true;
                record_listing_errors(case, collection_id, &listing, &mut files)?;
                return Ok(CollectionReport {
                    collection_id,
                    tool: dc.tool,
                    root,
                    files,
                });
            }
            match outcome {
                Outcome::Done(report, _) => {
                    mark_handled(&mut handled, &f.rel, &report);
                    files.push(report);
                }
                Outcome::Cancelled => unreachable!("handled above"),
                Outcome::Deferred => {
                    return Err(Error::Invalid(format!(
                        "{} was deferred again on the retry pass",
                        f.rel
                    ))
                    .into());
                }
            }
        }
    }
    record_listing_errors(case, collection_id, &listing, &mut files)?;
    Ok(CollectionReport {
        collection_id,
        tool: dc.tool,
        root,
        files,
    })
}

/// Record each entry discovery could not read as an error file.
fn record_listing_errors(
    case: &mut Case,
    collection_id: i64,
    listing: &crate::discovery::CollectionListing,
    files: &mut Vec<FileReport>,
) -> Result<()> {
    for err in &listing.errors {
        let nf = NewFile {
            collection_id,
            rel_path: &err.rel,
            artifact_id: None,
            subject: None,
            format: FileFormat::Unknown,
            encoding: None,
            size: 0,
            sha256: "",
        };
        files.push(record_simple(
            case,
            &nf,
            FileStatus::Error,
            vec![err.message.clone()],
        )?);
    }
    Ok(())
}

fn date_order_str(o: DateOrder) -> &'static str {
    match o {
        DateOrder::MonthFirst => "month_first",
        DateOrder::DayFirst => "day_first",
    }
}

/// Distinct day/month orders proved by this collection's already-parsed files.
fn orders_proved_earlier(conn: &Connection, collection_id: i64) -> Result<Vec<DateOrder>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT date_order FROM source_files
         WHERE collection_id = ? AND status = 'parsed' AND date_order IS NOT NULL
         ORDER BY date_order",
    )?;
    let names = stmt
        .query_map(params![collection_id], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(names
        .iter()
        .filter_map(|n| match n.as_str() {
            "month_first" => Some(DateOrder::MonthFirst),
            "day_first" => Some(DateOrder::DayFirst),
            _ => None,
        })
        .collect())
}

/// A file makes its CSV twin / derived counterpart redundant only when it was already
/// ingested or actually yielded records; a file whose every record failed does not
/// (spec A.4: "if the JSON is missing or fails").
fn supersedes_counterparts(report: &FileReport) -> bool {
    match report.status {
        FileStatus::DuplicateFile => true,
        FileStatus::Parsed => {
            report.records_read == 0 || report.records_loaded + report.records_duplicate > 0
        }
        _ => false,
    }
}

/// Record a file's outcome for the supersede rules: a success makes its counterparts
/// redundant; a failure (error, not supported, every record failed) keeps a `Merged` copy
/// of its folder from being skipped.
fn mark_handled(handled: &mut Handled, rel: &str, report: &FileReport) {
    if supersedes_counterparts(report) {
        handled.insert(rel);
    } else if matches!(
        report.status,
        FileStatus::Parsed | FileStatus::NotSupported | FileStatus::Error
    ) {
        handled.insert_failed(rel);
    }
}

fn upsert_collection(conn: &Connection, dc: &DiscoveredCollection, root: &str) -> Result<i64> {
    let existing: Option<i64> = conn
        .query_row(
            "SELECT collection_id FROM collections WHERE tool = ? AND root_path = ?",
            params![dc.tool.as_str(), root],
            |r| r.get(0),
        )
        .optional()?;
    let collected_at = started_at(dc).map(|t| t.rfc3339());
    if let Some(id) = existing {
        // A collection first ingested before its time was known (e.g. an Extractor Suite
        // root from before run stamps were read) gains it now.
        if let Some(at) = &collected_at {
            conn.execute(
                "UPDATE collections SET collected_at = CAST(? AS TIMESTAMPTZ), collected_at_tz_assumed = true
                 WHERE collection_id = ? AND collected_at IS NULL",
                params![at, id],
            )?;
        }
        return Ok(id);
    }
    let id = conn.query_row(
        "INSERT INTO collections (tool, root_path, tenant_name_reported, collected_at, collected_at_tz_assumed, sparrow_version)
         VALUES (?, ?, ?, CAST(? AS TIMESTAMPTZ), ?, ?) RETURNING collection_id",
        params![dc.tool.as_str(), root, dc.tenant_hint, collected_at, collected_at.is_some(), VERSION],
        |r| r.get(0),
    )?;
    Ok(id)
}

struct NewFile<'a> {
    collection_id: i64,
    rel_path: &'a str,
    artifact_id: Option<&'static str>,
    /// User UPN / IP / message / operation taken from the path, if the artifact has one.
    subject: Option<&'a str>,
    format: FileFormat,
    encoding: Option<&'static str>,
    size: u64,
    sha256: &'a str,
}

fn insert_file_row(
    conn: &Connection,
    nf: &NewFile,
    status: FileStatus,
    warnings: &[String],
) -> Result<i64> {
    let warnings_json = if warnings.is_empty() {
        None
    } else {
        Some(serde_json::to_string(warnings).expect("strings serialize"))
    };
    let id = conn.query_row(
        "INSERT INTO source_files (collection_id, rel_path, artifact_type, subject, format, encoding, size_bytes, sha256, status, warnings)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON)) RETURNING file_id",
        params![
            nf.collection_id,
            nf.rel_path,
            nf.artifact_id,
            nf.subject,
            nf.format.as_str(),
            nf.encoding,
            nf.size as i64,
            nf.sha256,
            status.as_str(),
            warnings_json
        ],
        |r| r.get(0),
    )?;
    Ok(id)
}

fn report_for(
    nf: &NewFile,
    file_id: Option<i64>,
    status: FileStatus,
    stats: FileStats,
    warnings: Vec<String>,
) -> FileReport {
    FileReport {
        file_id,
        rel_path: nf.rel_path.to_string(),
        artifact_id: nf.artifact_id.map(str::to_string),
        status,
        records_read: stats.read,
        records_loaded: stats.loaded,
        records_duplicate: stats.duplicate,
        records_error: stats.error,
        records_collector_lost: stats.collector_lost,
        warnings,
    }
}

/// Delete rows of earlier ingests of this collection + rel_path that never gained (or lost
/// through rollback) their provenance, so the file's new outcome replaces them: every
/// `error` row (whatever its sha256, which is empty when the file could not be read or was
/// too large), and `not_supported` / `unrecognized` rows for the same content.
fn delete_stale_rows(conn: &Connection, nf: &NewFile) -> Result<()> {
    const STALE: &str = "collection_id = ? AND rel_path = ?
        AND (status = 'error' OR (status IN ('not_supported', 'unrecognized') AND sha256 = ?))";
    conn.execute(
        &format!(
            "DELETE FROM parse_errors WHERE file_id IN (SELECT file_id FROM source_files WHERE {STALE})"
        ),
        params![nf.collection_id, nf.rel_path, nf.sha256],
    )?;
    conn.execute(
        &format!("DELETE FROM source_files WHERE {STALE}"),
        params![nf.collection_id, nf.rel_path, nf.sha256],
    )?;
    Ok(())
}

/// Replace stale rows with one status row, in one transaction.
fn record_simple(
    case: &mut Case,
    nf: &NewFile,
    status: FileStatus,
    warnings: Vec<String>,
) -> Result<FileReport> {
    let _t = timing::span("file: record_simple (status row + commit)");
    let tx = case.conn_mut().transaction()?;
    delete_stale_rows(&tx, nf)?;
    let id = insert_file_row(&tx, nf, status, &warnings)?;
    tx.commit()?;
    Ok(report_for(
        nf,
        Some(id),
        status,
        FileStats::default(),
        warnings,
    ))
}

fn with_pre(pre: &[String], warnings: Vec<String>) -> Vec<String> {
    pre.iter().cloned().chain(warnings).collect()
}

/// A file read that reports to the test [`ReadHook`]: once when it opens (0 bytes) and after each read that returns
/// bytes; a hook error fails the open or the read with it.
pub(crate) struct HookedRead<R> {
    inner: R,
    hook: Option<ReadHook>,
    rel_path: String,
    phase: ReadPhase,
}

impl<R: std::io::Read> HookedRead<R> {
    pub(crate) fn open(
        inner: R,
        hook: Option<ReadHook>,
        rel_path: &str,
        phase: ReadPhase,
    ) -> std::io::Result<Self> {
        let r = HookedRead {
            inner,
            hook,
            rel_path: rel_path.to_string(),
            phase,
        };
        r.report(0)?;
        Ok(r)
    }

    fn report(&self, bytes: u64) -> std::io::Result<()> {
        match &self.hook {
            Some(h) => h(&ReadEvent {
                rel_path: &self.rel_path,
                phase: self.phase,
                bytes,
            }),
            None => Ok(()),
        }
    }
}

impl<R: std::io::Read> std::io::Read for HookedRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.report(n as u64)?;
        }
        Ok(n)
    }
}

/// [`admit`](crate::readers::stream::admit) `abs` in reads of the ingest's chunk size, honouring its cancel check
/// (a cancel fails the read with `ErrorKind::Interrupted`) and its test read hook.
fn admit_file(abs: &Path, rel: &str, opts: &IngestOptions) -> std::io::Result<Admitted> {
    let file = std::fs::File::open(abs)?;
    let modified = file.metadata()?.modified().ok();
    let mut reader = HookedRead::open(file, opts.read_hook.clone(), rel, ReadPhase::Admit)?;
    crate::readers::stream::admit_from(&mut reader, abs, modified, opts.chunk(), &mut |_| {
        !opts.cancelled()
    })
}

/// The size limit `size` breaks before the file is read, if any: `--max-file-size`, then the XLSX guard.
fn size_guard(size: u64, format: FileFormat, opts: &IngestOptions) -> Option<String> {
    if let Some(max) = opts.max_file_bytes
        && size > max
    {
        return Some(format!(
            "file is {size} bytes, above the {max} byte limit set by --max-file-size; raise --max-file-size to ingest it"
        ));
    }
    if format == FileFormat::Xlsx && size > XLSX_MAX_BYTES {
        return Some(format!(
            "file is {size} bytes, above the {XLSX_MAX_BYTES} byte limit for XLSX workbooks (read whole into memory); export the data as CSV to ingest it"
        ));
    }
    None
}

/// The warning of a file whose size or modification time changed between its admission and the end of its parse.
pub const FILE_CHANGED_WARNING: &str = "file changed while it was read (its size or modification time differs from when it was admitted); nothing was loaded from it";
/// [`ingest_file_inner`], timed per file when [`timing`] is on.
fn ingest_file(
    case: &mut Case,
    job: &FileJob,
    parsers: &ParserRegistry,
    opts: &IngestOptions,
) -> Result<Outcome> {
    #[cfg(any(test, feature = "test-fixtures"))]
    if fault::file_fails(case, job.rel) {
        return Err(Error::Invalid(format!("injected: {} failed", job.rel)));
    }
    if !timing::enabled() {
        return ingest_file_inner(case, job, parsers, opts);
    }
    let start = std::time::Instant::now();
    let out = ingest_file_inner(case, job, parsers, opts);
    let elapsed = start.elapsed();
    let bytes = std::fs::metadata(job.abs).map_or(0, |m| m.len());
    let (status, artifact, records) = match &out {
        Ok(Outcome::Done(r, _)) => (
            r.status.as_str().to_string(),
            r.artifact_id.clone(),
            r.records_read,
        ),
        Ok(Outcome::Deferred) => ("deferred".to_string(), None, 0),
        Ok(Outcome::Cancelled) => ("cancelled".to_string(), None, 0),
        Err(_) => ("failed".to_string(), None, 0),
    };
    timing::add(&format!("status: {status}"), elapsed);
    timing::file(timing::FileTiming {
        rel_path: job.rel.to_string(),
        artifact,
        status,
        bytes,
        records,
        elapsed,
    });
    out
}

fn ingest_file_inner(
    case: &mut Case,
    job: &FileJob,
    parsers: &ParserRegistry,
    opts: &IngestOptions,
) -> Result<Outcome> {
    let (collection_id, tool, abs, rel) = (job.collection_id, job.tool, job.abs, job.rel);
    let reg = Registry::builtin();
    let path_class: Option<Classification> = reg.classify_with_head(tool, rel, None);
    let mut nf = NewFile {
        collection_id,
        rel_path: rel,
        artifact_id: path_class.as_ref().map(|c| c.artifact_id),
        subject: path_class.as_ref().and_then(|c| c.subject.as_deref()),
        format: format_from_path(rel),
        encoding: None,
        size: 0,
        sha256: "",
    };
    let mut pre: Vec<String> = Vec::new();
    if job.lossy_name {
        pre.push(
            "file name is not valid UTF-8; rel_path shows replacement characters and verify cannot reopen the file".into(),
        );
    }
    let t_stat = timing::span("file: stat");
    let size = match std::fs::metadata(abs) {
        Ok(m) => m.len(),
        Err(e) => {
            return record_simple(
                case,
                &nf,
                FileStatus::Error,
                with_pre(&pre, vec![format!("cannot stat file: {e}")]),
            )
            .map(Outcome::plain);
        }
    };
    drop(t_stat);
    nf.size = size;
    // A copy the supersede rules already skip is never size-checked, decoded or parsed: it is only hashed (its stored
    // sha256 is the same) for the duplicate checks, the 1.9 GB merged UAL export of a large Invictus tree included.
    let superseded = job.superseded_by.is_some();
    if !superseded && let Some(msg) = size_guard(size, nf.format, opts) {
        return record_simple(case, &nf, FileStatus::Error, with_pre(&pre, vec![msg]))
            .map(Outcome::plain);
    }
    // XLSX is classified from the whole workbook, so one up to the XLSX guard is read whole once; every other file
    // is admitted in reads of the chunk size (hash, head, blank, encoding), honouring a cancel.
    let workbook = nf.format == FileFormat::Xlsx && size <= XLSX_MAX_BYTES;
    let t_read = timing::span(if workbook {
        "file: sha256 + read (workbook, whole)"
    } else {
        "file: sha256 + encoding (admit, streamed)"
    });
    let content = if workbook {
        std::fs::read(abs).map(|raw| {
            let admitted = Admitted::from_bytes(abs, &raw);
            (Some(raw), admitted)
        })
    } else {
        admit_file(abs, rel, opts).map(|admitted| (None, admitted))
    };
    let (mut raw, admitted) = match content {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => return Ok(Outcome::Cancelled),
        Err(e) => {
            return record_simple(
                case,
                &nf,
                FileStatus::Error,
                with_pre(&pre, vec![format!("cannot read file: {e}")]),
            )
            .map(Outcome::plain);
        }
    };
    drop(t_read);
    if admitted.blank {
        pre.push(EMPTY_FILE_WARNING.into());
    }
    let sha = admitted.sha256.clone();
    nf.sha256 = &sha;
    let t_lookup = timing::span("file: db lookups (changed, already, identical)");
    let changed: bool = case.conn().query_row(
        "SELECT count(*) > 0 FROM source_files
         WHERE collection_id = ? AND rel_path = ? AND sha256 <> ? AND sha256 <> ''
           AND status IN ('parsed', 'duplicate_file', 'skipped_superseded')",
        params![collection_id, rel, &sha],
        |r| r.get(0),
    )?;
    if changed {
        pre.push("file content changed since an earlier ingest of this collection (different SHA-256); records from both versions are kept".into());
    }
    let head: &[u8] = raw.as_deref().unwrap_or(&admitted.head);
    let class: Option<Classification> = {
        let _t = timing::span("file: classify with head");
        reg.classify_with_head(tool, rel, Some(head))
    };
    nf.artifact_id = class.as_ref().map(|c| c.artifact_id);
    nf.subject = class.as_ref().and_then(|c| c.subject.as_deref());

    // A row for this exact collection + rel_path + sha256 with status `parsed`,
    // `duplicate_file` or `skipped_superseded` means this content was already handled
    // successfully: report it as a duplicate (and drop any stale error rows left by
    // failed attempts). Otherwise the file is (re)tried from scratch; stale rows of earlier
    // attempts (see `delete_stale_rows`) are replaced in the same transaction as the new row.
    let already: Option<i64> = case
        .conn()
        .query_row(
            "SELECT file_id FROM source_files
             WHERE collection_id = ? AND rel_path = ? AND sha256 = ?
               AND status IN ('parsed', 'duplicate_file', 'skipped_superseded')
             ORDER BY file_id LIMIT 1",
            params![collection_id, rel, &sha],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(existing_id) = already {
        let tx = case.conn_mut().transaction()?;
        delete_stale_rows(&tx, &nf)?;
        tx.commit()?;
        return Ok(Outcome::plain(report_for(
            &nf,
            Some(existing_id),
            FileStatus::DuplicateFile,
            FileStats::default(),
            vec!["already ingested".into()],
        )));
    }
    // Byte-identical content already parsed for the same artifact and subject (e.g. a moved
    // copy of the collection) adds nothing. Identical files for different subjects (e.g. two
    // users' header-only CSVs) are each parsed: each is that subject's coverage.
    if size > 0 {
        let first: Option<i64> = case
            .conn()
            .query_row(
                "SELECT file_id FROM source_files
                 WHERE sha256 = ? AND status = 'parsed'
                   AND artifact_type IS NOT DISTINCT FROM ? AND subject IS NOT DISTINCT FROM ?
                 ORDER BY file_id LIMIT 1",
                params![&sha, nf.artifact_id, nf.subject],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(first) = first {
            let msg = format!("identical to already-ingested file_id {first}");
            return record_simple(
                case,
                &nf,
                FileStatus::DuplicateFile,
                with_pre(&pre, vec![msg]),
            )
            .map(Outcome::plain);
        }
    }
    drop(t_lookup);
    if let Some(other) = &job.superseded_by {
        return record_simple(
            case,
            &nf,
            FileStatus::SkippedSuperseded,
            with_pre(&pre, vec![format!("superseded by {other}")]),
        )
        .map(Outcome::plain);
    }
    let Some(class) = class.as_ref() else {
        return record_simple(case, &nf, FileStatus::Unrecognized, with_pre(&pre, vec![]))
            .map(Outcome::plain);
    };
    let Some(parser) = parsers.get(class.artifact_id) else {
        return record_simple(case, &nf, FileStatus::NotSupported, with_pre(&pre, vec![]))
            .map(Outcome::plain);
    };

    // The whole text is read and decoded only for a parser that reads it whole, a workbook and a Format-List file;
    // other parsers read the records in passes over the file on disk.
    let whole_mode = parser.input() == InputMode::Whole
        || matches!(nf.format, FileFormat::Xlsx | FileFormat::Txt);
    if whole_mode && raw.is_none() {
        let limit = opts.whole_max_bytes.unwrap_or(WHOLE_FILE_MAX_BYTES);
        if size > limit {
            let msg = format!(
                "file is {size} bytes, above the {limit} byte limit for files read whole ({} reads its file whole into memory)",
                class.artifact_id
            );
            return record_simple(case, &nf, FileStatus::Error, with_pre(&pre, vec![msg]))
                .map(Outcome::plain);
        }
        let t_read = timing::span("file: read whole");
        let read = std::fs::read(abs);
        drop(t_read);
        match read {
            Ok(bytes) if bytes.len() as u64 == admitted.raw_len => raw = Some(bytes),
            Ok(_) => {
                return record_simple(
                    case,
                    &nf,
                    FileStatus::Error,
                    with_pre(&pre, vec![FILE_CHANGED_WARNING.into()]),
                )
                .map(Outcome::plain);
            }
            Err(e) => {
                return record_simple(
                    case,
                    &nf,
                    FileStatus::Error,
                    with_pre(&pre, vec![format!("cannot read file: {e}")]),
                )
                .map(Outcome::plain);
            }
        }
    }
    let raw: &[u8] = raw.as_deref().unwrap_or(&[]);
    // XLSX is a zip: parsers read it from the raw bytes, so it is not decoded.
    let t_decode = timing::span("file: decode");
    let decoded = if !whole_mode {
        None
    } else if nf.format == FileFormat::Xlsx {
        Some(DecodedText::binary())
    } else {
        Some(decode(raw))
    };
    drop(t_decode);
    nf.encoding = (nf.format != FileFormat::Xlsx).then(|| admitted.encoding.as_str());
    let decode_warning = if nf.format == FileFormat::Xlsx {
        None
    } else {
        lossy_warning(admitted.encoding, admitted.lossy)
    };
    let index = decoded.as_ref().map(|d| {
        let _t = timing::span("file: line index");
        LineIndex::new(&d.text)
    });
    let whole = match (&decoded, &index) {
        (Some(text), Some(index)) => Some(WholeText { raw, text, index }),
        _ => None,
    };
    let source = FileSource::new(rel, opts);
    let t_row = timing::span("file: begin + stale rows + source_files row");
    let tx = case.conn_mut().transaction()?;
    delete_stale_rows(&tx, &nf)?;
    let file_id = insert_file_row(&tx, &nf, FileStatus::Parsed, &[])?;
    drop(t_row);
    let mut ctx = ParseContext::new(
        &tx,
        collection_id,
        file_id,
        rel,
        class.subject.as_deref(),
        &admitted,
        RecordSource::File(&source),
        whole,
        opts,
    );
    ctx.date_hint = job.date_hint;
    ctx.defer_ambiguous_dates = job.defer;
    ctx.collection_orders_conflict = job.orders_conflict;
    ctx.portal_export = class.artifact_id.starts_with("portal.");
    // A parser that queued sightings and did not flush them loses none. (That covers loss, not order relative to the
    // parser's own later writes: a parser that reads `record_sources` mid-parse must flush before it reads. The
    // parsers that flush themselves, logs and Sessions, make this second flush a no-op.)
    let parsed = {
        let _t = timing::span(&format!("parse+load: {}", class.artifact_id));
        let _all = timing::span("file: parse+load (all parsers)");
        parser.parse(&mut ctx)
    }
    .and_then(|()| {
        let _t = timing::span("file: final flush_sources");
        ctx.flush_sources()
    });
    // A file whose size or modification time moved while it was read may have been read in parts of two versions:
    // nothing of it is kept.
    let changed_while_read = || !admitted.unchanged().unwrap_or(false);
    match parsed {
        Ok(()) if changed_while_read() => {
            drop(ctx);
            tx.rollback()?;
            let warnings = with_pre(&pre, vec![FILE_CHANGED_WARNING.into()]);
            record_simple(case, &nf, FileStatus::Error, warnings).map(Outcome::plain)
        }
        Ok(()) => {
            let orders = ctx.orders_seen().to_vec();
            // One proved order is stored; a file that proved both stores NULL.
            let date_order = match orders.as_slice() {
                [only] => Some(date_order_str(*only)),
                _ => None,
            };
            let (stats, parser_warnings) = ctx.finish();
            let warnings: Vec<String> = pre
                .iter()
                .cloned()
                .chain(decode_warning)
                .chain(parser_warnings)
                .chain(truncation_warning(class.artifact_id, stats.read))
                .collect();
            let warnings_json = if warnings.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&warnings).expect("strings serialize"))
            };
            let t_commit = timing::span("file: counts row + commit (incl. auto checkpoint)");
            tx.execute(
                "UPDATE source_files SET records_read = ?, records_loaded = ?, records_duplicate = ?, records_error = ?,
                        warnings = CAST(? AS JSON), date_order = ? WHERE file_id = ?",
                params![stats.read as i64, stats.loaded as i64, stats.duplicate as i64, stats.error as i64, warnings_json, date_order, file_id],
            )?;
            tx.commit()?;
            drop(t_commit);
            Ok(Outcome::Done(
                report_for(&nf, Some(file_id), FileStatus::Parsed, stats, warnings),
                orders,
            ))
        }
        Err(Error::Interrupted) => {
            // Cancelled mid-file: the file leaves no rows, as if it was never tried.
            drop(ctx);
            tx.rollback()?;
            Ok(Outcome::Cancelled)
        }
        Err(Error::DateOrderDeferred) => {
            drop(ctx);
            tx.rollback()?;
            Ok(Outcome::Deferred)
        }
        Err(e) => {
            drop(ctx);
            tx.rollback()?;
            let changed = changed_while_read();
            let (status, msg) = match e {
                Error::UnsupportedShape(why) if !changed => (
                    FileStatus::NotSupported,
                    format!("{}: {why}", class.artifact_id),
                ),
                other => (
                    FileStatus::Error,
                    format!("parser {} failed: {other}", class.artifact_id),
                ),
            };
            let first = changed.then(|| FILE_CHANGED_WARNING.to_string());
            let warnings = with_pre(
                &pre,
                first
                    .into_iter()
                    .chain(std::iter::once(msg))
                    .chain(decode_warning)
                    .collect(),
            );
            record_simple(case, &nf, status, warnings).map(Outcome::plain)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn threshold(case: &Case) -> String {
        case.conn()
            .query_row("SELECT current_setting('checkpoint_threshold')", [], |r| {
                r.get(0)
            })
            .unwrap()
    }

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    #[test]
    fn the_threshold_follows_the_memory_limit_within_its_bounds() {
        let auto = |limit: &str| ingest_checkpoint_threshold(limit, None).unwrap();
        // memory_limit / 8, at most 1 GB (DuckDB's 1GB: 10^9 bytes).
        assert_eq!(auto("32 GiB"), Some(INGEST_CHECKPOINT_MAX));
        // The case's default cap (crate::db::DEFAULT_MEMORY_LIMIT, 2 GB) gives 250 MB, not the 1 GB maximum.
        assert_eq!(
            auto(&format!("{} bytes", crate::db::DEFAULT_MEMORY_LIMIT)),
            Some(250_000_000)
        );
        assert_eq!(auto("3.7 GiB"), Some(496_605_593));
        assert_eq!(auto("29.8 GiB"), Some(INGEST_CHECKPOINT_MAX));
        assert_eq!(auto("2 GiB"), Some(256 * MIB));
        assert_eq!(auto("2.0 GiB"), Some(256 * MIB));
        assert_eq!(auto("2GB"), Some(250_000_000));
        // Never below DuckDB's default: a small limit keeps it.
        assert_eq!(auto("64 MiB"), None);
        assert_eq!(auto("128 MiB"), None);
        assert_eq!(auto("136 MiB"), Some(17 * MIB));
        // Unlimited (DuckDB shows -1 as 16383.9 PiB): the cap.
        assert_eq!(auto("16383.9 PiB"), Some(INGEST_CHECKPOINT_MAX));
        // A limit that does not parse never raises the threshold.
        for bad in ["", "lots", "1e9", "GiB", "-1 GiB", "1.5.2 MiB"] {
            assert_eq!(auto(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_override_sets_a_size_keeps_the_default_or_fails_clearly() {
        let over = |v: &str| ingest_checkpoint_threshold("32 GiB", Some(v));
        assert_eq!(over("256MB").unwrap(), Some(256_000_000));
        assert_eq!(over(" 256 MiB ").unwrap(), Some(256 * MIB));
        assert_eq!(over("2GiB").unwrap(), Some(2 * GIB));
        assert_eq!(over("default").unwrap(), None);
        assert_eq!(over("DEFAULT").unwrap(), None);
        for bad in ["", "lots", "0", "0MB", "-5MB", "12 parsecs"] {
            let e = over(bad).unwrap_err().to_string();
            assert!(
                e.contains(CHECKPOINT_ENV) && e.contains("default"),
                "{bad:?}: {e}"
            );
        }
    }

    #[test]
    fn the_ingest_threshold_applies_inside_and_the_previous_one_comes_back_on_every_exit() {
        let dir = tempfile::tempdir().unwrap();
        let mut case = Case::create_or_open(&dir.path().join("c.duckdb")).unwrap();
        let default = threshold(&case);
        // An override of 256 MiB applies inside.
        let inside =
            with_ingest_checkpointing_using(&mut case, Some("256MiB"), |c| Ok(threshold(c)))
                .unwrap();
        assert_eq!(inside, "256.0 MiB");
        assert_eq!(threshold(&case), default);
        // `default` keeps DuckDB's own value inside.
        let inside =
            with_ingest_checkpointing_using(&mut case, Some("default"), |c| Ok(threshold(c)))
                .unwrap();
        assert_eq!(inside, default);
        // An invalid override fails before the load runs, and changes nothing.
        let mut ran = false;
        let e = with_ingest_checkpointing_using(&mut case, Some("huge"), |_| {
            ran = true;
            Ok(())
        })
        .unwrap_err();
        assert!(!ran && e.to_string().contains(CHECKPOINT_ENV), "{e}");
        assert_eq!(threshold(&case), default);
        // A non-default previous value is restored as it was.
        case.conn()
            .execute_batch("SET checkpoint_threshold = '64MiB'")
            .unwrap();
        let custom = threshold(&case);
        with_ingest_checkpointing_using(&mut case, Some("256MiB"), |_| Ok(())).unwrap();
        assert_eq!(threshold(&case), custom);
        // Err: restored, and the ingest's error is the one returned.
        let e = with_ingest_checkpointing_using::<()>(&mut case, Some("256MiB"), |_| {
            Err(Error::Invalid("boom".into()))
        })
        .unwrap_err();
        assert!(e.to_string().contains("boom"), "{e}");
        assert_eq!(threshold(&case), custom);
        // Panic: restored, and the panic goes on.
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = with_ingest_checkpointing_using::<()>(&mut case, Some("256MiB"), |_| {
                panic!("parser bug")
            });
        }));
        assert!(caught.is_err());
        assert_eq!(threshold(&case), custom);
    }

    #[test]
    fn a_memory_constrained_ingest_succeeds_with_a_bounded_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::fixtures::hawk_tree(dir.path());
        let mut case = Case::create_or_open(&dir.path().join("case.duckdb")).unwrap();
        case.conn()
            .execute_batch("SET memory_limit = '1GB'")
            .unwrap();
        let limit: String = case
            .conn()
            .query_row("SELECT current_setting('memory_limit')", [], |r| r.get(0))
            .unwrap();
        // 953.6 MiB / 8: about 119 MiB, far below the 1 GB cap.
        let want = ingest_checkpoint_threshold(&limit, None).unwrap().unwrap();
        assert!(want > 100 * MIB && want < 125 * MIB, "{want}");
        let inside =
            with_ingest_checkpointing_using(&mut case, None, |c| Ok(threshold(c))).unwrap();
        assert!(
            inside.ends_with("MiB") && inside.starts_with("11"),
            "{inside}"
        );
        let default = threshold(&case);
        let report = ingest_path(
            &mut case,
            &root,
            &ParserRegistry::builtin(),
            &IngestOptions::default(),
        )
        .unwrap();
        assert!(!report.has_errors());
        assert!(
            report
                .collections
                .iter()
                .flat_map(|c| &c.files)
                .any(|f| f.status == FileStatus::Parsed && f.records_loaded > 0)
        );
        assert_eq!(threshold(&case), default);
    }

    #[test]
    fn an_ingest_folds_its_wal_in_and_restores_the_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::fixtures::hawk_tree(dir.path());
        let path = dir.path().join("case.duckdb");
        let mut case = Case::create_or_open(&path).unwrap();
        let default = threshold(&case);
        ingest_path(
            &mut case,
            &root,
            &ParserRegistry::builtin(),
            &IngestOptions::default(),
        )
        .unwrap();
        assert_eq!(threshold(&case), default);
        // The one CHECKPOINT at the end leaves nothing in the WAL.
        let wal = dir.path().join("case.duckdb.wal");
        let wal_len = std::fs::metadata(&wal).map_or(0, |m| m.len());
        assert_eq!(wal_len, 0, "WAL still holds {wal_len} bytes");
    }
}
