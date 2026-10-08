//! The export menu's commands: the report, the Timeline Explorer CSV and the workbook, written where the analyst
//! chose in the save dialog. They only read the case. A file is written inside a private work folder beside its
//! target and renamed over it when complete, so a failed export never leaves a half-written deliverable.

use crate::error::{CmdError, CmdResult};
use crate::state::{AppState, OpenCase, with_case};
use chrono::Utc;
use sparrow_core::data::DataDirs;
use sparrow_core::export::timeline_csv::{self, CsvOpts, Scope};
use sparrow_core::export::{report_md, workbook_xlsx};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use tauri::State;

/// Where the export will land: the canonical parent plus the chosen file name.
struct Target {
    dir: PathBuf,
    file: std::ffi::OsString,
}

impl Target {
    fn path(&self) -> PathBuf {
        self.dir.join(&self.file)
    }
}

fn invalid(msg: String) -> CmdError {
    CmdError::new("invalid", msg)
}

#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_: &std::fs::Metadata, _: &std::fs::Metadata) -> bool {
    false
}

/// The target must be a file name in a folder that exists, and must not be, or alias, the open case or its
/// write-ahead log. Checked before writing and again right before the rename.
fn check_target(open: &OpenCase, target: &Target) -> CmdResult<()> {
    let case = open.path.canonicalize().map_err(|e| {
        CmdError::new(
            "internal",
            format!("cannot resolve the case {}: {e}", open.path.display()),
        )
    })?;
    let case_dir = case.parent().map(Path::to_path_buf).unwrap_or_default();
    let case_name = case.file_name().map(|n| n.to_string_lossy().to_lowercase());
    // By name, whatever the filesystem: a different spelling may be the same file on a case-insensitive volume, and
    // the write-ahead log may not exist yet.
    if let Some(case_name) = case_name {
        let name = target.file.to_string_lossy().to_lowercase();
        if target.dir == case_dir && (name == case_name || name == format!("{case_name}.wal")) {
            return Err(invalid(format!(
                "refusing to write the export over the case ({}); choose another file",
                target.path().display()
            )));
        }
    }
    let path = target.path();
    match std::fs::symlink_metadata(&path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(invalid(format!(
                    "{} is a symbolic link; choose a regular file name",
                    path.display()
                )));
            }
            let mut wal = case.clone().into_os_string();
            wal.push(".wal");
            for protected in [case.as_path(), Path::new(&wal)] {
                if let Ok(p) = std::fs::metadata(protected) {
                    if same_file(&meta, &p) {
                        return Err(invalid(format!(
                            "refusing to write the export over the case ({}); choose another file",
                            path.display()
                        )));
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(invalid(format!("cannot inspect {}: {e}", path.display())));
        }
    }
    Ok(())
}

fn resolve_target(path: &Path) -> CmdResult<Target> {
    let file = path
        .file_name()
        .ok_or_else(|| invalid(format!("{} is not a file name", path.display())))?
        .to_owned();
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let dir = dir
        .canonicalize()
        .ok()
        .filter(|d| d.is_dir())
        .ok_or_else(|| invalid(format!("the folder {} does not exist", dir.display())))?;
    Ok(Target { dir, file })
}

/// Run `write` on a file inside a fresh private directory (random name, created exclusively, mode 0700) beside the
/// target, then rename it onto the target. Nobody else can plant or swap a link inside the private directory, and a
/// pre-existing `<name>.partial` is never touched. Only the private directory is removed, on success or failure.
fn atomic(
    open: &OpenCase,
    path: &Path,
    write: impl FnOnce(&Path) -> CmdResult<()>,
) -> CmdResult<()> {
    let target = resolve_target(path)?;
    check_target(open, &target)?;
    let private = tempfile::Builder::new()
        .prefix(".sparrow-export-")
        .tempdir_in(&target.dir)
        .map_err(|e| {
            CmdError::new(
                "internal",
                format!(
                    "cannot create a work folder in {}: {e}",
                    target.dir.display()
                ),
            )
        })?;
    let tmp = private.path().join(&target.file);
    write(&tmp)?;
    check_target(open, &target)?;
    std::fs::rename(&tmp, target.path()).map_err(|e| {
        CmdError::new(
            "internal",
            format!("cannot write {}: {e}", target.path().display()),
        )
    })
}

/// Run `write` on a buffered file at `tmp`, flushed before it returns.
fn to_file(tmp: &Path, write: impl FnOnce(&mut dyn Write) -> CmdResult<()>) -> CmdResult<()> {
    let file = File::create(tmp)
        .map_err(|e| CmdError::new("internal", format!("cannot create {}: {e}", tmp.display())))?;
    let mut w = BufWriter::new(file);
    write(&mut w)?;
    w.flush()
        .map_err(|e| CmdError::new("internal", format!("cannot write {}: {e}", tmp.display())))
}

/// The Markdown report; `reviewed_only` keeps accepted decisions only (analyst decisions are accepted as made).
pub fn export_report(state: &AppState, path: &Path, reviewed_only: bool) -> CmdResult<()> {
    with_case(state, |open| {
        atomic(open, path, |tmp| {
            let opts = report_md::ReportOpts {
                reviewed_only,
                generated_at: Utc::now(),
                dirs: DataDirs::from_env(),
            };
            to_file(tmp, |w| Ok(report_md::write(open.case.conn(), w, &opts)?))
        })
    })
}

/// The Timeline Explorer CSV of the verified entries (the CLI's default scope).
pub fn export_timeline_csv(state: &AppState, path: &Path) -> CmdResult<()> {
    with_case(state, |open| {
        atomic(open, path, |tmp| {
            let opts = CsvOpts {
                scope: Scope::Verified,
                from: None,
                to: None,
                user: None,
                generated_at: Utc::now(),
            };
            to_file(tmp, |w| {
                timeline_csv::write(open.case.conn(), w, &opts)?;
                Ok(())
            })
        })
    })
}

pub fn export_workbook(state: &AppState, path: &Path) -> CmdResult<()> {
    with_case(state, |open| {
        atomic(open, path, |tmp| {
            Ok(workbook_xlsx::write(
                open.case.conn(),
                tmp,
                Utc::now(),
                &DataDirs::from_env(),
            )?)
        })
    })
}

pub mod commands {
    use super::*;

    #[tauri::command(async)]
    pub fn export_report(
        state: State<'_, AppState>,
        path: String,
        reviewed_only: bool,
    ) -> CmdResult<()> {
        super::export_report(&state, Path::new(&path), reviewed_only)
    }

    #[tauri::command(async)]
    pub fn export_timeline_csv(state: State<'_, AppState>, path: String) -> CmdResult<()> {
        super::export_timeline_csv(&state, Path::new(&path))
    }

    #[tauri::command(async)]
    pub fn export_workbook(state: State<'_, AppState>, path: String) -> CmdResult<()> {
        super::export_workbook(&state, Path::new(&path))
    }
}
