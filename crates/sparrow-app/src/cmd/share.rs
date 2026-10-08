//! The share screen's commands: export my work as a bundle file, preview a bundle (nothing stored), import the
//! previewed bytes. The import is bound to the SHA-256 the preview showed, so the file cannot change in between.

use crate::cmd::export::atomic;
use crate::error::{CmdError, CmdResult};
use crate::state::{AppState, Ticket, analyst, with_case, with_writable};
use serde::Serialize;
use sparrow_core::case::share::{self, ImportSummary, MAX_BUNDLE_BYTES};
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ExportResult {
    pub sha256: String,
    pub items: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SharePreview {
    pub sha256: String,
    pub summary: ImportSummary,
    /// `analyst:<name>`, as in the bundle.
    pub analyst: String,
    /// RFC 3339, as in the bundle.
    pub exported_at: String,
    pub items: usize,
}

/// The bundle file's bytes, refusing a file over the import limit before reading it all.
fn read_bundle(path: &Path) -> CmdResult<Vec<u8>> {
    let io = |e: std::io::Error| {
        CmdError::new(
            if e.kind() == std::io::ErrorKind::NotFound {
                "not_found"
            } else {
                "invalid"
            },
            format!("cannot read {}: {e}", path.display()),
        )
    };
    let file = std::fs::File::open(path).map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() {
        return Err(CmdError::new(
            "invalid",
            format!("{} is not a file", path.display()),
        ));
    }
    let too_big = || {
        CmdError::new(
            "invalid",
            format!("a share bundle is limited to 16 MiB ({MAX_BUNDLE_BYTES} bytes)"),
        )
    };
    if meta.len() > MAX_BUNDLE_BYTES as u64 {
        return Err(too_big());
    }
    // Bounded again while reading: the file may grow after the check.
    let mut bytes = Vec::new();
    file.take(MAX_BUNDLE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(too_big());
    }
    Ok(bytes)
}

/// Export the open case's reviewed work as the analyst, written atomically like the other exports.
pub fn share_export(state: &AppState, path: &Path) -> CmdResult<ExportResult> {
    let ticket = state.ticket();
    let me = analyst(state)?;
    with_case(state, ticket, |open| {
        let bundle = share::export(open.case.conn(), &me)?;
        let items = bundle.items.len();
        let (bytes, sha256) = share::to_bytes(&bundle)?;
        atomic(open, path, |tmp| {
            std::fs::write(tmp, &bytes).map_err(|e| {
                CmdError::new("internal", format!("cannot write {}: {e}", tmp.display()))
            })
        })?;
        Ok(ExportResult { sha256, items })
    })
}

/// What importing the file would do; nothing is stored.
pub fn share_preview(state: &AppState, path: &Path) -> CmdResult<SharePreview> {
    share_preview_at(state, state.ticket(), path)
}

/// [`share_preview`] for a request submitted at `ticket`: the file is read first, and the request is still refused
/// if the case was switched meanwhile.
pub fn share_preview_at(state: &AppState, ticket: Ticket, path: &Path) -> CmdResult<SharePreview> {
    let bytes = read_bundle(path)?;
    with_case(state, ticket, |open| {
        let (bundle, sha256) = share::parse(&bytes)?;
        let summary = share::preview(open.case.conn(), &bytes)?;
        Ok(SharePreview {
            sha256,
            summary,
            analyst: bundle.analyst,
            exported_at: bundle.exported_at,
            items: bundle.items.len(),
        })
    })
}

/// Import the file as proposals, only when its bytes still hash to `sha256` (the preview's).
pub fn share_import(state: &AppState, path: &Path, sha256: &str) -> CmdResult<ImportSummary> {
    share_import_at(state, state.ticket(), path, sha256)
}

/// [`share_import`] for a request submitted at `ticket` (see [`share_preview_at`]).
pub fn share_import_at(
    state: &AppState,
    ticket: Ticket,
    path: &Path,
    sha256: &str,
) -> CmdResult<ImportSummary> {
    let me = analyst(state)?;
    let bytes = read_bundle(path)?;
    with_writable(state, ticket, |open| {
        let (_, now) = share::parse(&bytes)?;
        if !now.eq_ignore_ascii_case(sha256.trim()) {
            return Err(CmdError::new(
                "invalid",
                "the file changed since the preview; preview it again before importing",
            ));
        }
        Ok(share::import(open.case.conn(), &me, &bytes)?)
    })
}

pub mod commands {
    use super::*;
    use std::path::PathBuf;
    use tauri::State;

    #[tauri::command(async)]
    pub fn share_export(state: State<'_, AppState>, path: PathBuf) -> CmdResult<ExportResult> {
        super::share_export(&state, &path)
    }

    #[tauri::command(async)]
    pub fn share_preview(state: State<'_, AppState>, path: PathBuf) -> CmdResult<SharePreview> {
        super::share_preview(&state, &path)
    }

    #[tauri::command(async)]
    pub fn share_import(
        state: State<'_, AppState>,
        path: PathBuf,
        sha256: String,
    ) -> CmdResult<ImportSummary> {
        super::share_import(&state, &path, &sha256)
    }
}
