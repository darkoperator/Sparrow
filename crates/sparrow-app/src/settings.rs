//! The app's local settings: the analyst name and the recently opened case paths, as JSON in the app config
//! directory. Never case data.

use crate::error::{CmdError, CmdResult};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use sparrow_core::case::actor::Reviewer;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::MutexGuard;
use std::sync::atomic::{AtomicU64, Ordering};

const FILE: &str = "settings.json";
/// How many recent case paths are kept.
pub const MAX_RECENT: usize = 10;

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq)]
#[serde(default)]
pub struct Settings {
    /// The analyst's name, without the `analyst:` prefix.
    pub analyst: Option<String>,
    /// Most recent first, no duplicates, at most [`MAX_RECENT`].
    pub recent: Vec<String>,
}

impl Settings {
    /// Put `path` first in the recent list.
    pub fn push_recent(&mut self, path: &str) {
        self.recent.retain(|p| p != path);
        self.recent.insert(0, path.to_string());
        self.recent.truncate(MAX_RECENT);
    }
}

/// The settings in `dir`; defaults when the file is missing or unreadable (settings are a convenience, never a
/// reason the app cannot start).
pub fn load(dir: &Path) -> Settings {
    std::fs::read(dir.join(FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Write the settings to `dir` (created if needed) through a temporary file of its own and a rename, so two
/// writers never share a temporary file.
pub fn save(dir: &Path, s: &Settings) -> std::io::Result<()> {
    static N: AtomicU64 = AtomicU64::new(0);
    std::fs::create_dir_all(dir)?;
    let n = N.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!("{FILE}.{}.{n}.partial", std::process::id()));
    let out = std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(s).map_err(std::io::Error::other)?,
    )
    .and_then(|()| std::fs::rename(&tmp, dir.join(FILE)));
    if out.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    out
}

/// The settings directory, locked: every load-modify-save runs under this one lock, so concurrent updates of
/// different fields never lose each other. Lock order: the open case first, then the settings.
fn locked(state: &AppState) -> CmdResult<(MutexGuard<'_, Option<PathBuf>>, PathBuf)> {
    let guard = state.settings_dir.lock().unwrap_or_else(|p| p.into_inner());
    let dir = guard
        .clone()
        .ok_or_else(|| CmdError::new("internal", "the settings directory is not set"))?;
    Ok((guard, dir))
}

fn save_or_err(dir: &Path, s: &Settings) -> CmdResult<()> {
    save(dir, s).map_err(|e| CmdError::new("internal", format!("cannot save the settings: {e}")))
}

pub fn settings_get(state: &AppState) -> CmdResult<Settings> {
    let (_guard, dir) = locked(state)?;
    Ok(load(&dir))
}

/// Store the analyst name, validated as core validates an analyst (`Reviewer::analyst`).
pub fn settings_set_analyst(state: &AppState, name: &str) -> CmdResult<Settings> {
    Reviewer::analyst(name)?;
    let (_guard, dir) = locked(state)?;
    let mut s = load(&dir);
    s.analyst = Some(name.trim().to_string());
    save_or_err(&dir, &s)?;
    Ok(s)
}

/// Remember `path` as the most recently opened case. No settings directory (tests) means nothing to remember.
pub fn record_recent(state: &AppState, path: &str) -> CmdResult<()> {
    let guard = state.settings_dir.lock().unwrap_or_else(|p| p.into_inner());
    let Some(dir) = guard.clone() else {
        return Ok(());
    };
    let mut s = load(&dir);
    s.push_recent(path);
    save_or_err(&dir, &s)
}

// ---------------------------------------------------------------- highlights

const HIGHLIGHTS_FILE: &str = "highlights.json";
/// Highlight sets per case, rules per set, bytes per value, cases remembered at all.
pub const MAX_SETS: usize = 50;
pub const MAX_RULES: usize = 100;
pub const MAX_VALUE_BYTES: usize = 1024;
pub const MAX_CASES: usize = 500;
const MAX_NAME_CHARS: usize = 100;
const MAX_COLUMN_CHARS: usize = 128;
const OPS: [&str; 2] = ["eq", "contains"];
const COLOURS: [&str; 5] = ["red", "amber", "green", "blue", "purple"];

/// One highlight: a row whose `column` (any column when `None`) equals / contains `value` is coloured.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HighlightRule {
    pub column: Option<String>,
    pub op: String,
    pub value: String,
    pub colour: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HighlightSet {
    pub name: String,
    pub rules: Vec<HighlightRule>,
}

/// Local highlight sets keyed by case id: case data the analyst chose to keep on this machine, in a file of its own
/// next to the settings. Never written to the case, never audited, never in a bundle.
type HighlightStore = BTreeMap<String, Vec<HighlightSet>>;

/// The stored highlights. Only a missing file means "none yet"; a file that cannot be read or parsed is an error
/// (naming the file) and is left untouched, so a later save never overwrites what the analyst had.
fn load_highlights(dir: &Path) -> CmdResult<HighlightStore> {
    let path = dir.join(HIGHLIGHTS_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HighlightStore::new()),
        Err(e) => {
            return Err(CmdError::new(
                "internal",
                format!("cannot read {}: {e}", path.display()),
            ));
        }
    };
    serde_json::from_slice(&bytes).map_err(|e| {
        CmdError::new(
            "internal",
            format!(
                "{} is damaged ({e}); fix or delete it to use highlights again",
                path.display()
            ),
        )
    })
}

fn save_highlights(dir: &Path, h: &HighlightStore) -> std::io::Result<()> {
    static N: AtomicU64 = AtomicU64::new(0);
    std::fs::create_dir_all(dir)?;
    let n = N.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(
        "{HIGHLIGHTS_FILE}.{}.{n}.partial",
        std::process::id()
    ));
    let out = std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(h).map_err(std::io::Error::other)?,
    )
    .and_then(|()| std::fs::rename(&tmp, dir.join(HIGHLIGHTS_FILE)));
    if out.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    out
}

fn bad(msg: String) -> CmdError {
    CmdError::new("invalid", msg)
}

fn plain(what: &str, s: &str, max_chars: usize) -> CmdResult<()> {
    if s.trim().is_empty() {
        return Err(bad(format!("{what} is empty")));
    }
    if s.chars().count() > max_chars {
        return Err(bad(format!("{what} is longer than {max_chars} characters")));
    }
    if s.chars().any(char::is_control) {
        return Err(bad(format!("{what} holds control characters")));
    }
    Ok(())
}

fn check_case_id(case_id: &str) -> CmdResult<()> {
    plain("the case id", case_id, 200)
}

/// The caps and enums of the contract. Names and columns are plain text; a value may hold anything up to 1 KiB (it
/// is shown escaped and matched raw).
pub fn validate_highlights(sets: &[HighlightSet]) -> CmdResult<()> {
    if sets.len() > MAX_SETS {
        return Err(bad(format!(
            "at most {MAX_SETS} highlight sets per case (got {})",
            sets.len()
        )));
    }
    for set in sets {
        plain("a highlight set name", &set.name, MAX_NAME_CHARS)?;
        if set.rules.len() > MAX_RULES {
            return Err(bad(format!(
                "at most {MAX_RULES} rules per highlight set (set has {})",
                set.rules.len()
            )));
        }
        for r in &set.rules {
            if let Some(c) = &r.column {
                plain("a highlight column", c, MAX_COLUMN_CHARS)?;
            }
            if !OPS.contains(&r.op.as_str()) {
                return Err(bad(format!("unknown highlight operator {:?}", r.op)));
            }
            if !COLOURS.contains(&r.colour.as_str()) {
                return Err(bad(format!("unknown highlight colour {:?}", r.colour)));
            }
            if r.value.len() > MAX_VALUE_BYTES {
                return Err(bad(format!(
                    "a highlight value is longer than {MAX_VALUE_BYTES} bytes"
                )));
            }
        }
    }
    Ok(())
}

pub fn highlights_get(state: &AppState, case_id: &str) -> CmdResult<Vec<HighlightSet>> {
    check_case_id(case_id)?;
    let (_guard, dir) = locked(state)?;
    Ok(load_highlights(&dir)?.remove(case_id).unwrap_or_default())
}

/// Replace the case's sets (validated, capped); returns what was stored.
pub fn highlights_set(
    state: &AppState,
    case_id: &str,
    sets: Vec<HighlightSet>,
) -> CmdResult<Vec<HighlightSet>> {
    check_case_id(case_id)?;
    validate_highlights(&sets)?;
    let (_guard, dir) = locked(state)?;
    let mut all = load_highlights(&dir)?;
    if !all.contains_key(case_id) && all.len() >= MAX_CASES {
        return Err(bad(format!(
            "highlights are kept for at most {MAX_CASES} cases; clear the highlights of another case first"
        )));
    }
    all.insert(case_id.to_string(), sets.clone());
    save_highlights(&dir, &all)
        .map_err(|e| CmdError::new("internal", format!("cannot save the highlights: {e}")))?;
    Ok(sets)
}

pub fn highlights_clear(state: &AppState, case_id: &str) -> CmdResult<()> {
    check_case_id(case_id)?;
    let (_guard, dir) = locked(state)?;
    let mut all = load_highlights(&dir)?;
    if all.remove(case_id).is_some() {
        save_highlights(&dir, &all)
            .map_err(|e| CmdError::new("internal", format!("cannot save the highlights: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_paths_are_most_recent_first_deduplicated_and_capped() {
        let mut s = Settings::default();
        for i in 0..12 {
            s.push_recent(&format!("/c{i}.duckdb"));
        }
        assert_eq!(s.recent.len(), MAX_RECENT);
        assert_eq!(s.recent[0], "/c11.duckdb");
        assert_eq!(s.recent[MAX_RECENT - 1], "/c2.duckdb");
        s.push_recent("/c5.duckdb");
        assert_eq!(s.recent[0], "/c5.duckdb");
        assert_eq!(s.recent.iter().filter(|p| *p == "/c5.duckdb").count(), 1);
        assert_eq!(s.recent.len(), MAX_RECENT);
    }
}
