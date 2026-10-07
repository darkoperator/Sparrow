//! The app's local settings: the analyst name and the recently opened case paths, as JSON in the app config
//! directory. Never case data.

use crate::error::{CmdError, CmdResult};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use sparrow_core::case::actor::Reviewer;
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
