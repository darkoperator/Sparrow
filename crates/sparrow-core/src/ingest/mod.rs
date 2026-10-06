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
    Classification, CollectionFile, DiscoveredCollection, FileFormat, Registry, SNIFF_BYTES, Tool,
    canonical_root_string, discover_collections, format_from_path, list_collection_files,
};
use crate::ingest::context::{FileStats, ParseContext};
use crate::ingest::parser::ParserRegistry;
use crate::ingest::supersede::{Handled, processing_key, truncation_warning};
use crate::readers::text::{DecodedText, LineIndex, decode, is_blank_content};
use crate::readers::time::{DateOrder, ParsedTime, parse_timestamp};
use crate::{Case, Error, Result, VERSION};
use duckdb::{Connection, OptionalExt, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

pub const DEFAULT_MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

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

#[derive(Debug, Clone)]
pub struct IngestOptions {
    pub date_order: Option<DateOrder>,
    pub max_file_bytes: u64,
}

impl Default for IngestOptions {
    fn default() -> Self {
        IngestOptions {
            date_order: None,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
        }
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
    pub warnings: Vec<String>,
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

impl IngestReport {
    /// True when any file failed, any record failed to parse, or a file's record counts
    /// did not reconcile (spec §11: exit code 2).
    pub fn has_errors(&self) -> bool {
        self.collections.iter().flat_map(|c| &c.files).any(|f| {
            f.status == FileStatus::Error
                || f.records_error > 0
                || f.warnings
                    .iter()
                    .any(|w| w.starts_with("reconciliation mismatch"))
        })
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
    case.ensure_usable()?;
    let mut order: Vec<usize> = (0..collections.len()).collect();
    order.sort_by_cached_key(|&i| {
        let dc = &collections[i];
        (started_at(dc).map(|t| t.utc), dc.root.clone())
    });
    let mut done: Vec<Option<CollectionReport>> = vec![None; collections.len()];
    for i in order {
        done[i] = Some(ingest_collection(case, &collections[i], parsers, opts)?);
    }
    Ok(IngestReport {
        collections: done.into_iter().flatten().collect(),
    })
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
) -> Result<CollectionReport> {
    let root = canonical_root_string(&dc.root);
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
            match ingest_file(case, &job, parsers, opts)? {
                Outcome::Deferred => {
                    handled.insert_failed(&f.rel);
                    deferred.push((f, derived, artifact));
                }
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
            match ingest_file(case, &job, parsers, opts)? {
                Outcome::Done(report, _) => {
                    mark_handled(&mut handled, &f.rel, &report);
                    files.push(report);
                }
                Outcome::Deferred => {
                    return Err(Error::Invalid(format!(
                        "{} was deferred again on the retry pass",
                        f.rel
                    )));
                }
            }
        }
    }
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
    Ok(CollectionReport {
        collection_id,
        tool: dc.tool,
        root,
        files,
    })
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

/// [`ingest_file_inner`], timed per file when [`timing`] is on.
fn ingest_file(
    case: &mut Case,
    job: &FileJob,
    parsers: &ParserRegistry,
    opts: &IngestOptions,
) -> Result<Outcome> {
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
    if size > opts.max_file_bytes {
        let msg = format!(
            "file is {size} bytes, above the {} byte limit; raise --max-file-size to ingest it",
            opts.max_file_bytes
        );
        return record_simple(case, &nf, FileStatus::Error, with_pre(&pre, vec![msg]))
            .map(Outcome::plain);
    }
    let t_read = timing::span("file: read");
    let raw = match std::fs::read(abs) {
        Ok(b) => b,
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
    if is_blank_content(&raw) {
        pre.push(EMPTY_FILE_WARNING.into());
    }
    let sha = {
        let _t = timing::span("file: sha256");
        hex::encode(Sha256::digest(&raw))
    };
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
    let head: &[u8] = if nf.format == FileFormat::Xlsx {
        &raw
    } else {
        &raw[..raw.len().min(SNIFF_BYTES)]
    };
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

    // XLSX is a zip: parsers read it from the raw bytes, so it is not decoded.
    let t_decode = timing::span("file: decode");
    let decoded = if nf.format == FileFormat::Xlsx {
        DecodedText::binary()
    } else {
        decode(&raw)
    };
    drop(t_decode);
    nf.encoding = (nf.format != FileFormat::Xlsx).then(|| decoded.encoding.as_str());
    let decode_warning = decoded.lossy_warning();
    let index = {
        let _t = timing::span("file: line index");
        LineIndex::new(&decoded.text)
    };
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
        &raw,
        &decoded,
        &index,
        opts,
    );
    ctx.date_hint = job.date_hint;
    ctx.defer_ambiguous_dates = job.defer;
    ctx.collection_orders_conflict = job.orders_conflict;
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
    match parsed {
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
        Err(Error::DateOrderDeferred) => {
            drop(ctx);
            tx.rollback()?;
            Ok(Outcome::Deferred)
        }
        Err(e) => {
            drop(ctx);
            tx.rollback()?;
            let (status, msg) = match e {
                Error::UnsupportedShape(why) => (
                    FileStatus::NotSupported,
                    format!("{}: {why}", class.artifact_id),
                ),
                other => (
                    FileStatus::Error,
                    format!("parser {} failed: {other}", class.artifact_id),
                ),
            };
            let warnings = with_pre(&pre, std::iter::once(msg).chain(decode_warning).collect());
            record_simple(case, &nf, status, warnings).map(Outcome::plain)
        }
    }
}
