//! Ingest: discover collections, register every file with its hash, and run parsers
//! inside one transaction per file.

pub mod context;
pub mod parser;

use crate::discovery::{
    Classification, DiscoveredCollection, FileFormat, Registry, Tool, canonical_root_string,
    discover_collections, format_from_path, list_collection_files,
};
use crate::ingest::context::{FileStats, ParseContext};
use crate::ingest::parser::ParserRegistry;
use crate::readers::text::{LineIndex, decode};
use crate::readers::time::{DateOrder, parse_timestamp};
use crate::{Case, Error, Result, VERSION};
use duckdb::{Connection, OptionalExt, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

pub const DEFAULT_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

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
    pub fn has_errors(&self) -> bool {
        self.collections
            .iter()
            .flat_map(|c| &c.files)
            .any(|f| f.status == FileStatus::Error)
    }
}

pub fn ingest_path(
    case: &mut Case,
    path: &Path,
    parsers: &ParserRegistry,
    opts: &IngestOptions,
) -> Result<IngestReport> {
    let collections = discover_collections(path)?;
    if collections.is_empty() {
        return Err(Error::Invalid(format!(
            "no Hawk or Microsoft-Extractor-Suite output found under {}",
            path.display()
        )));
    }
    let mut report = IngestReport::default();
    for dc in &collections {
        report
            .collections
            .push(ingest_collection(case, dc, parsers, opts)?);
    }
    Ok(report)
}

fn ingest_collection(
    case: &mut Case,
    dc: &DiscoveredCollection,
    parsers: &ParserRegistry,
    opts: &IngestOptions,
) -> Result<CollectionReport> {
    let root = canonical_root_string(&dc.root);
    let collection_id = upsert_collection(case.conn(), dc, &root)?;
    let mut files = Vec::new();
    for f in list_collection_files(&dc.root)? {
        files.push(ingest_file(
            case,
            collection_id,
            dc.tool,
            &f.abs,
            &f.rel,
            parsers,
            opts,
        )?);
    }
    Ok(CollectionReport {
        collection_id,
        tool: dc.tool,
        root,
        files,
    })
}

fn upsert_collection(conn: &Connection, dc: &DiscoveredCollection, root: &str) -> Result<i64> {
    let existing: Option<i64> = conn
        .query_row(
            "SELECT collection_id FROM collections WHERE tool = ? AND root_path = ?",
            params![dc.tool.as_str(), root],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(id) = existing {
        return Ok(id);
    }
    let collected_at = dc
        .started_hint
        .as_deref()
        .and_then(|s| parse_timestamp(s, None).ok())
        .map(|t| t.rfc3339());
    let id = conn.query_row(
        "INSERT INTO collections (tool, root_path, tenant_name_reported, collected_at, sparrow_version)
         VALUES (?, ?, ?, CAST(? AS TIMESTAMPTZ), ?) RETURNING collection_id",
        params![dc.tool.as_str(), root, dc.tenant_hint, collected_at, VERSION],
        |r| r.get(0),
    )?;
    Ok(id)
}

struct NewFile<'a> {
    collection_id: i64,
    rel_path: &'a str,
    artifact_id: Option<&'static str>,
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
        "INSERT INTO source_files (collection_id, rel_path, artifact_type, format, encoding, size_bytes, sha256, status, warnings)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON)) RETURNING file_id",
        params![
            nf.collection_id,
            nf.rel_path,
            nf.artifact_id,
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

fn record_simple(
    conn: &Connection,
    nf: &NewFile,
    status: FileStatus,
    warnings: Vec<String>,
) -> Result<FileReport> {
    let id = insert_file_row(conn, nf, status, &warnings)?;
    Ok(report_for(
        nf,
        Some(id),
        status,
        FileStats::default(),
        warnings,
    ))
}

#[allow(clippy::too_many_arguments)]
fn ingest_file(
    case: &mut Case,
    collection_id: i64,
    tool: Tool,
    abs: &Path,
    rel: &str,
    parsers: &ParserRegistry,
    opts: &IngestOptions,
) -> Result<FileReport> {
    let class: Option<Classification> = Registry::builtin().classify(tool, rel);
    let mut nf = NewFile {
        collection_id,
        rel_path: rel,
        artifact_id: class.as_ref().map(|c| c.artifact_id),
        format: format_from_path(rel),
        encoding: None,
        size: 0,
        sha256: "",
    };
    let size = match std::fs::metadata(abs) {
        Ok(m) => m.len(),
        Err(e) => {
            return record_simple(
                case.conn(),
                &nf,
                FileStatus::Error,
                vec![format!("cannot stat file: {e}")],
            );
        }
    };
    nf.size = size;
    if size > opts.max_file_bytes {
        let msg = format!(
            "file is {size} bytes, above the {} byte limit; raise --max-file-size to ingest it",
            opts.max_file_bytes
        );
        return record_simple(case.conn(), &nf, FileStatus::Error, vec![msg]);
    }
    let raw = match std::fs::read(abs) {
        Ok(b) => b,
        Err(e) => {
            return record_simple(
                case.conn(),
                &nf,
                FileStatus::Error,
                vec![format!("cannot read file: {e}")],
            );
        }
    };
    let sha = hex::encode(Sha256::digest(&raw));
    nf.sha256 = &sha;

    // Rows already recorded for this exact collection + rel_path + sha256. A row with status
    // `parsed`, `duplicate_file` or `skipped_superseded` means this content was already handled
    // successfully: report it as a duplicate. A row with status `error`, `not_supported` or
    // `unrecognized` never gained provenance (or, for `error`, its provenance was rolled back),
    // so it is stale and this file is retried from scratch: the stale row (and any of its
    // parse_errors, though those statuses never produce any) is deleted first.
    let existing_rows: Vec<(i64, String)> = {
        let mut stmt = case.conn().prepare(
            "SELECT file_id, CAST(status AS VARCHAR) FROM source_files
             WHERE collection_id = ? AND rel_path = ? AND sha256 = ? ORDER BY file_id",
        )?;
        stmt.query_map(params![collection_id, rel, &sha], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };
    if let Some((existing_id, _)) = existing_rows.iter().find(|(_, status)| {
        matches!(
            status.as_str(),
            "parsed" | "duplicate_file" | "skipped_superseded"
        )
    }) {
        return Ok(report_for(
            &nf,
            Some(*existing_id),
            FileStatus::DuplicateFile,
            FileStats::default(),
            vec!["already ingested".into()],
        ));
    }
    for (stale_id, _) in &existing_rows {
        case.conn().execute(
            "DELETE FROM parse_errors WHERE file_id = ?",
            params![stale_id],
        )?;
        case.conn().execute(
            "DELETE FROM source_files WHERE file_id = ?",
            params![stale_id],
        )?;
    }
    if size > 0 {
        let first: Option<i64> = case
            .conn()
            .query_row(
                "SELECT file_id FROM source_files WHERE sha256 = ? AND status = 'parsed' ORDER BY file_id LIMIT 1",
                params![&sha],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(first) = first {
            let msg = format!("identical to already-ingested file_id {first}");
            return record_simple(case.conn(), &nf, FileStatus::DuplicateFile, vec![msg]);
        }
    }
    let Some(class) = class else {
        return record_simple(case.conn(), &nf, FileStatus::Unrecognized, vec![]);
    };
    let Some(parser) = parsers.get(class.artifact_id) else {
        return record_simple(case.conn(), &nf, FileStatus::NotSupported, vec![]);
    };

    let decoded = decode(&raw);
    nf.encoding = Some(decoded.encoding.as_str());
    let decode_warning = decoded.lossy_warning();
    let index = LineIndex::new(&decoded.text);
    let tx = case.conn_mut().transaction()?;
    let file_id = insert_file_row(&tx, &nf, FileStatus::Parsed, &[])?;
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
    match parser.parse(&mut ctx) {
        Ok(()) => {
            let (stats, parser_warnings) = ctx.finish();
            let warnings: Vec<String> = decode_warning.into_iter().chain(parser_warnings).collect();
            let warnings_json = if warnings.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&warnings).expect("strings serialize"))
            };
            tx.execute(
                "UPDATE source_files SET records_read = ?, records_loaded = ?, records_duplicate = ?, records_error = ?,
                        warnings = CAST(? AS JSON) WHERE file_id = ?",
                params![stats.read as i64, stats.loaded as i64, stats.duplicate as i64, stats.error as i64, warnings_json, file_id],
            )?;
            tx.commit()?;
            Ok(report_for(
                &nf,
                Some(file_id),
                FileStatus::Parsed,
                stats,
                warnings,
            ))
        }
        Err(e) => {
            drop(ctx);
            tx.rollback()?;
            let msg = format!("parser {} failed: {e}", class.artifact_id);
            let warnings = std::iter::once(msg).chain(decode_warning).collect();
            record_simple(case.conn(), &nf, FileStatus::Error, warnings)
        }
    }
}
