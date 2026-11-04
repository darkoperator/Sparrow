//! Re-validate evidence records against the original collector files.

use crate::hash::{Sha256Stream, sha256_hex};
use crate::readers::text::{TextEncoding, decode};
use crate::readers::xlsx::read_xlsx;
use crate::{Case, Error, Result};
use duckdb::params;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const EXCERPT_LIMIT: usize = 10_000;

/// Raw bytes hashed per read, so memory does not grow with the file.
const CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// Raw bytes kept from a record for its excerpt: the longest encoding takes 4 bytes per char.
const EXCERPT_BYTES: usize = EXCERPT_LIMIT * 4 + 8;

/// A source file opened for verification.
pub trait SourceReader: Read + Seek {}
impl<T: Read + Seek> SourceReader for T {}

/// Opens a source file; the production opener is `File::open`.
pub type Opener<'a> = &'a dyn Fn(&Path) -> std::io::Result<Box<dyn SourceReader>>;

fn open_file(path: &Path) -> std::io::Result<Box<dyn SourceReader>> {
    Ok(Box::new(std::fs::File::open(path)?))
}

#[derive(Debug, Clone, Serialize)]
pub struct SightingCheck {
    pub rel_path: String,
    pub resolved_path: String,
    pub source_ref: String,
    pub line_start: u32,
    pub line_end: u32,
    pub file_found: bool,
    pub file_hash_ok: bool,
    pub record_hash_ok: bool,
    pub excerpt: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub table: String,
    pub record_key: String,
    pub ok: bool,
    pub sightings: Vec<SightingCheck>,
}

pub fn source_ref(root_name: &str, rel_path: &str, line_start: u32, line_end: u32) -> String {
    if line_start == line_end {
        format!("{root_name}/{rel_path}:{line_start}")
    } else {
        format!("{root_name}/{rel_path}:{line_start}-{line_end}")
    }
}

struct Sighting {
    rel_path: String,
    file_sha: String,
    root_path: String,
    line_start: u32,
    line_end: u32,
    byte_offset: u64,
    byte_length: u64,
    raw_sha: String,
    /// `source_files.encoding`; None for XLSX.
    encoding: Option<String>,
}

pub fn verify_record(
    case: &Case,
    table: &str,
    record_key: &str,
    root_override: Option<&Path>,
) -> Result<VerifyReport> {
    verify_record_with(case, table, record_key, root_override, &open_file)
}

/// [`verify_record`] opening source files through `open`.
#[doc(hidden)]
pub fn verify_record_with(
    case: &Case,
    table: &str,
    record_key: &str,
    root_override: Option<&Path>,
    open: Opener<'_>,
) -> Result<VerifyReport> {
    let mut stmt = case.conn().prepare(
        "SELECT sf.rel_path, sf.sha256, c.root_path, rs.line_start, rs.line_end, rs.byte_offset, rs.byte_length, rs.raw_sha256, sf.encoding
         FROM record_sources rs
         JOIN source_files sf ON sf.file_id = rs.file_id
         JOIN collections c ON c.collection_id = sf.collection_id
         WHERE rs.table_name = ? AND rs.record_key = ?
         ORDER BY rs.file_id, rs.record_ordinal",
    )?;
    let sightings: Vec<Sighting> = stmt
        .query_map(params![table, record_key], |r| {
            Ok(Sighting {
                rel_path: r.get(0)?,
                file_sha: r.get(1)?,
                root_path: r.get(2)?,
                line_start: r.get::<_, i64>(3)? as u32,
                line_end: r.get::<_, i64>(4)? as u32,
                byte_offset: r.get::<_, i64>(5)? as u64,
                byte_length: r.get::<_, i64>(6)? as u64,
                raw_sha: r.get(7)?,
                encoding: r.get(8)?,
            })
        })?
        .collect::<std::result::Result<_, _>>()?;
    if sightings.is_empty() {
        return Err(Error::NotFound(format!("{table} record {record_key}")));
    }
    let single_collection = sightings
        .iter()
        .map(|s| s.root_path.as_str())
        .collect::<HashSet<_>>()
        .len()
        == 1;
    // A record seen several times in one (possibly multi-GB) file: that file is hashed once.
    let mut file_hashes = HashMap::new();
    let checks: Vec<SightingCheck> = sightings
        .iter()
        .map(|s| {
            check(
                s,
                relocated(s, root_override, single_collection),
                open,
                &mut file_hashes,
            )
        })
        .collect();
    let ok = checks
        .iter()
        .all(|c| c.file_found && c.file_hash_ok && c.record_hash_ok);
    Ok(VerifyReport {
        table: table.to_string(),
        record_key: record_key.to_string(),
        ok,
        sightings: checks,
    })
}

/// `--root` relocates one moved collection: it applies to sightings whose recorded
/// collection root has the override's folder name, or to all sightings when they all come
/// from one collection (moved and possibly renamed).
fn relocated<'p>(
    s: &Sighting,
    root_override: Option<&'p Path>,
    single_collection: bool,
) -> Option<&'p Path> {
    let o = root_override?;
    if single_collection {
        return Some(o);
    }
    let recorded = PathBuf::from(&s.root_path);
    (recorded.file_name().is_some() && recorded.file_name() == o.file_name()).then_some(o)
}

/// One sighting's check. `file_hashes` holds the whole-file hash of each resolved path hashed so far in this verify
/// (`None` when it could not be read).
fn check(
    s: &Sighting,
    root_override: Option<&Path>,
    open: Opener<'_>,
    file_hashes: &mut HashMap<PathBuf, Option<String>>,
) -> SightingCheck {
    let recorded_root = PathBuf::from(&s.root_path);
    let root = root_override
        .map(Path::to_path_buf)
        .unwrap_or_else(|| recorded_root.clone());
    let path = s.rel_path.split('/').fold(root, |p, part| p.join(part));
    let root_name = recorded_root
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut result = SightingCheck {
        rel_path: s.rel_path.clone(),
        resolved_path: path.display().to_string(),
        source_ref: source_ref(&root_name, &s.rel_path, s.line_start, s.line_end),
        line_start: s.line_start,
        line_end: s.line_end,
        file_found: false,
        file_hash_ok: false,
        record_hash_ok: false,
        excerpt: None,
    };
    let Ok(mut file) = open(&path) else {
        return result;
    };
    result.file_found = true;
    if s.rel_path.to_ascii_lowercase().ends_with(".xlsx") {
        let mut raw = Vec::new();
        if file.read_to_end(&mut raw).is_ok() {
            result.file_hash_ok = sha256_hex(&raw) == s.file_sha;
            check_sheet_row(s, &raw, &mut result);
        }
        return result;
    }
    if let Ok((hash, head)) = read_record(&mut *file, s.byte_offset, s.byte_length) {
        result.record_hash_ok = hash == s.raw_sha;
        let text = decode_excerpt(&head, s.encoding.as_deref(), s.byte_offset);
        result.excerpt = Some(text);
    }
    let hash = file_hashes
        .entry(path)
        .or_insert_with(|| hash_whole(&mut *file).ok());
    result.file_hash_ok = hash.as_deref() == Some(s.file_sha.as_str());
    result
}

/// Seek to the record, hash its `length` bytes in chunks and keep the first bytes for the excerpt.
/// Fails when the file ends before the record does (an empty record past the end included).
fn read_record(
    file: &mut dyn SourceReader,
    offset: u64,
    length: u64,
) -> std::io::Result<(String, Vec<u8>)> {
    let size = file.seek(SeekFrom::End(0))?;
    if offset.checked_add(length).is_none_or(|end| end > size) {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut hash = Sha256Stream::new();
    let mut head = Vec::new();
    let mut buf = vec![0u8; CHUNK_BYTES.min(length.max(1) as usize)];
    let mut left = length;
    while left > 0 {
        let want = buf.len().min(left as usize);
        let n = match file.read(&mut buf[..want]) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hash.update(&buf[..n]);
        let room = EXCERPT_BYTES.saturating_sub(head.len());
        head.extend_from_slice(&buf[..n.min(room)]);
        left -= n as u64;
    }
    Ok((hash.finish_hex(), head))
}

/// SHA-256 of the whole file, read in chunks from the start.
fn hash_whole(file: &mut dyn SourceReader) -> std::io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256Stream::new();
    let mut buf = vec![0u8; CHUNK_BYTES];
    loop {
        match file.read(&mut buf) {
            Ok(0) => return Ok(hash.finish_hex()),
            Ok(n) => hash.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// The record's own bytes as text in the file's recorded encoding, without its line terminator, capped.
fn decode_excerpt(bytes: &[u8], encoding: Option<&str>, offset: u64) -> String {
    let codec = match encoding {
        Some(e) if e == TextEncoding::Utf16Le.as_str() => Some(encoding_rs::UTF_16LE),
        Some(e) if e == TextEncoding::Utf16Be.as_str() => Some(encoding_rs::UTF_16BE),
        Some(e) if e == TextEncoding::Windows1252.as_str() => Some(encoding_rs::WINDOWS_1252),
        Some(_) => None,
        // No stored encoding: decide from the record's bytes (offset 0 is where a BOM would be).
        None if offset == 0 => return trimmed(&decode(bytes).text),
        None => None,
    };
    let text = match codec {
        Some(c) => c.decode_without_bom_handling(bytes).0,
        None => String::from_utf8_lossy(bytes),
    };
    trimmed(&text)
}

fn trimmed(text: &str) -> String {
    text.trim_end_matches(['\r', '\n'])
        .chars()
        .take(EXCERPT_LIMIT)
        .collect()
}

/// XLSX sighting: re-read sheet row `line_start`, re-hash its tab-joined cell texts and show
/// the row as `header: value` lines.
fn check_sheet_row(s: &Sighting, raw: &[u8], result: &mut SightingCheck) {
    let Ok(table) = read_xlsx(raw) else {
        return;
    };
    let Some(row) = table.rows.iter().find(|r| r.row == s.line_start) else {
        return;
    };
    result.record_hash_ok = sha256_hex(row.text().as_bytes()) == s.raw_sha;
    let lines: Vec<String> = row
        .fields
        .iter()
        .enumerate()
        .filter(|(_, v)| !v.is_empty())
        .map(|(i, v)| format!("{}: {v}", table.headers.get(i).map_or("", String::as_str)))
        .collect();
    result.excerpt = Some(lines.join("\n").chars().take(EXCERPT_LIMIT).collect());
}
