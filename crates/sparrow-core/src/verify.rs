//! Re-validate evidence records against the original collector files.

use crate::hash::sha256_hex;
use crate::readers::text::{LineIndex, decode};
use crate::readers::xlsx::read_xlsx;
use crate::{Case, Error, Result};
use duckdb::params;
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const EXCERPT_LIMIT: usize = 10_000;

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
}

pub fn verify_record(
    case: &Case,
    table: &str,
    record_key: &str,
    root_override: Option<&Path>,
) -> Result<VerifyReport> {
    let mut stmt = case.conn().prepare(
        "SELECT sf.rel_path, sf.sha256, c.root_path, rs.line_start, rs.line_end, rs.byte_offset, rs.byte_length, rs.raw_sha256
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
    let checks: Vec<SightingCheck> = sightings
        .iter()
        .map(|s| check(s, relocated(s, root_override, single_collection)))
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

fn check(s: &Sighting, root_override: Option<&Path>) -> SightingCheck {
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
    let Ok(raw) = std::fs::read(&path) else {
        return result;
    };
    result.file_found = true;
    result.file_hash_ok = sha256_hex(&raw) == s.file_sha;
    if s.rel_path.to_ascii_lowercase().ends_with(".xlsx") {
        check_sheet_row(s, &raw, &mut result);
        return result;
    }
    let start = s.byte_offset as usize;
    let end = start.saturating_add(s.byte_length as usize);
    if end <= raw.len() {
        result.record_hash_ok = sha256_hex(&raw[start..end]) == s.raw_sha;
    }
    let decoded = decode(&raw);
    let index = LineIndex::new(&decoded.text);
    if (s.line_start as usize) <= index.line_count() {
        let text = index.line_text(&decoded.text, s.line_start, s.line_end);
        result.excerpt = Some(text.chars().take(EXCERPT_LIMIT).collect());
    }
    result
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
