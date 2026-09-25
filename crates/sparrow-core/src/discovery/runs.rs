//! Run folders of a Microsoft-Extractor-Suite Output root. Every cmdlet run writes its own
//! `<Component>/<yyyyMMdd-HHmmss>[-Label]/` folder (Init-OutputDir, local time), so one root
//! holds many runs. An empty run folder or an empty export means the cmdlet ran and found
//! nothing, which `collector_runs` keeps visible.

use crate::discovery::files::is_os_junk;
use crate::readers::text::is_blank_content;
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

/// A directory at or below a run folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDir {
    /// Path relative to the root, components joined with `/`.
    pub rel_dir: String,
    /// Path component before the first run-stamp folder (the Invictus component).
    pub component: Option<String>,
    /// `yyyyMMdd-HHmmss` of the nearest run folder at or above `rel_dir`.
    pub stamp: String,
    /// That run folder's suffix after the stamp (`SignInLogs`, `Legacy`, ...).
    pub label: Option<String>,
    /// Regular files directly in the folder, OS junk excluded.
    pub files: u32,
    /// Of those, files with no content (`is_blank_content`).
    pub empty_files: u32,
    pub bytes: u64,
}

fn re_stamp() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^(\d{8}-\d{6})(?:-(.+))?$").expect("valid regex"))
}

/// Largest file examined for blank content (a BOM plus a line break is 5 bytes).
const BLANK_PROBE_BYTES: u64 = 64;

/// Every directory under `root` at or below a run folder, sorted by path. Unreadable
/// entries are skipped.
pub fn run_dirs(root: &Path) -> Vec<RunDir> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .min_depth(1)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_dir() {
            continue;
        }
        let Ok(rel) = entry.path().strip_prefix(root) else {
            continue;
        };
        let parts: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let Some(first) = parts.iter().position(|p| re_stamp().is_match(p)) else {
            continue;
        };
        let last = parts
            .iter()
            .rposition(|p| re_stamp().is_match(p))
            .unwrap_or(first);
        let Some(caps) = re_stamp().captures(&parts[last]) else {
            continue;
        };
        let (files, empty_files, bytes) = dir_files(entry.path());
        out.push(RunDir {
            rel_dir: parts.join("/"),
            component: first.checked_sub(1).map(|i| parts[i].clone()),
            stamp: caps[1].to_string(),
            label: caps.get(2).map(|m| m.as_str().to_string()),
            files,
            empty_files,
            bytes,
        });
    }
    out
}

fn dir_files(dir: &Path) -> (u32, u32, u64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (0, 0, 0);
    };
    let (mut files, mut empty, mut bytes) = (0u32, 0u32, 0u64);
    for e in entries.filter_map(|e| e.ok()) {
        if is_os_junk(&e.file_name().to_string_lossy()) {
            continue;
        }
        let Ok(meta) = e.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        files += 1;
        bytes += meta.len();
        if meta.len() <= BLANK_PROBE_BYTES
            && std::fs::read(e.path()).is_ok_and(|b| is_blank_content(&b))
        {
            empty += 1;
        }
    }
    (files, empty, bytes)
}

/// Earliest run stamp under `root`, as `yyyyMMdd_HHmmss` (the collection-time hint format
/// Hawk folder names use).
pub fn earliest_run_stamp(root: &Path) -> Option<String> {
    run_dirs(root)
        .into_iter()
        .map(|r| r.stamp)
        .min()
        .map(|s| s.replace('-', "_"))
}
