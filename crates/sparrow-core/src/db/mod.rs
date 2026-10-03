//! The per-case DuckDB database.

pub mod describe;
pub mod migrations;
pub mod state_tables;

pub use describe::{ColumnInfo, TableInfo, describe};

use crate::{Error, Result};
use duckdb::{AccessMode, Config, Connection};
use std::path::{Path, PathBuf};

/// An empty database file opened READ_ONLY: the stand-in connection while a case's file is
/// lent out, and for good when it cannot be reopened. Every write on it fails, so nothing
/// written to a placeholder can vanish silently.
fn read_only_placeholder() -> Result<Connection> {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sparrow-placeholder-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
    let file = dir.join("placeholder.duckdb");
    drop(Connection::open(&file)?);
    let conn =
        Connection::open_with_flags(&file, Config::default().access_mode(AccessMode::ReadOnly)?);
    // The open handle keeps the data readable on Unix; the file itself is not needed any more.
    let _ = std::fs::remove_dir_all(&dir);
    Ok(conn?)
}

/// The case files this process holds a writer on, by file identity. DuckDB's file lock refuses a writer in another
/// process, but a second handle in the same process is not refused cleanly (it replays the first one's WAL and fails
/// with an internal error), so `Case` refuses it here first.
static WRITERS: std::sync::Mutex<Vec<FileKey>> = std::sync::Mutex::new(Vec::new());

/// A file's identity, the same through every path that reaches it (symlinks, hard links, `..`): (device, inode) on
/// Unix, the canonical path elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileKey {
    #[cfg(unix)]
    Inode(u64, u64),
    #[cfg(not(unix))]
    Path(PathBuf),
}

impl FileKey {
    fn of(path: &Path) -> Result<FileKey> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata(path).map_err(|e| Error::io(path, e))?;
            Ok(FileKey::Inode(m.dev(), m.ino()))
        }
        #[cfg(not(unix))]
        {
            Ok(FileKey::Path(
                std::fs::canonicalize(path).map_err(|e| Error::io(path, e))?,
            ))
        }
    }
}

/// This process's writer registration on a case file; released on drop.
struct WriterGuard(FileKey);

impl Drop for WriterGuard {
    fn drop(&mut self) {
        let mut w = WRITERS.lock().unwrap_or_else(|e| e.into_inner());
        w.retain(|k| k != &self.0);
    }
}

fn another_writer(path: &Path, detail: &str) -> Error {
    Error::Invalid(format!(
        "case is open by another writer: {} ({detail})",
        path.display()
    ))
}

/// Open `path` for writing: one writer per file, in this process (`WRITERS`) and across processes (DuckDB's lock,
/// whose error becomes "case is open by another writer"). The registry lock is held across the open, so a file that
/// does not exist yet is keyed right after DuckDB creates it, before any other open in this process can run.
fn open_writer(path: &Path) -> Result<(Connection, WriterGuard)> {
    let mut w = WRITERS.lock().unwrap_or_else(|e| e.into_inner());
    if path.exists() {
        let key = FileKey::of(path)?;
        if w.contains(&key) {
            return Err(another_writer(path, "already open in this process"));
        }
    }
    let conn = Connection::open(path).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("Could not set lock") || msg.contains("Conflicting lock") {
            another_writer(path, &msg)
        } else {
            e.into()
        }
    })?;
    let key = FileKey::of(path)?;
    if w.contains(&key) {
        return Err(another_writer(path, "already open in this process"));
    }
    w.push(key.clone());
    Ok((conn, WriterGuard(key)))
}

/// A directory removed when the `Case` that owns it is dropped (see [`Case::with_scratch_dir`]).
struct ScratchDir(PathBuf);

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub struct Case {
    conn: Connection,
    path: Option<PathBuf>,
    read_only: bool,
    /// Set when the file could not be reopened after `with_file_released`: `conn` is then an
    /// read-only, empty placeholder database that cannot take writes.
    poisoned: Option<String>,
    /// Held while this `Case` is the file's writer; declared after `conn` so it is released after the connection.
    _writer: Option<WriterGuard>,
    /// Declared last so it drops after `conn`: the database is closed (and its WAL settled)
    /// before the directory that holds the file goes.
    scratch: Option<ScratchDir>,
}

impl Case {
    /// Open (creating if needed) a case database for writing and bring its schema up to date.
    pub fn create_or_open(path: &Path) -> Result<Case> {
        let (conn, writer) = open_writer(path)?;
        migrations::migrate(&conn)?;
        Ok(Case {
            conn,
            path: Some(path.to_path_buf()),
            read_only: false,
            poisoned: None,
            _writer: Some(writer),
            scratch: None,
        })
    }

    /// Remove `dir` when this case is dropped, after its database is closed. For test helpers
    /// that hand out a private copy of a cached case file.
    #[doc(hidden)]
    pub fn with_scratch_dir(mut self, dir: PathBuf) -> Case {
        self.scratch = Some(ScratchDir(dir));
        self
    }

    /// Bring an existing case database's schema up to date. Never creates a new file.
    /// Returns the schema version before and after.
    pub fn upgrade(path: &Path) -> Result<(u32, u32)> {
        if !path.is_file() {
            return Err(Error::NotFound(format!("case database {}", path.display())));
        }
        let (conn, writer) = open_writer(path)?;
        let out = Self::upgrade_conn(&conn);
        // Close the connection before releasing the writer registration.
        drop(conn);
        drop(writer);
        out
    }

    fn upgrade_conn(conn: &Connection) -> Result<(u32, u32)> {
        let from = migrations::current_version(conn)?;
        let to = migrations::migrate(conn)?;
        // The upgrade to the Phase 7 schema starts the audit chain (Addendum D.3).
        if from < migrations::ANALYST_VERSION && to >= migrations::ANALYST_VERSION {
            conn.execute_batch("BEGIN TRANSACTION")?;
            let appended = crate::case::audit::case_id(conn).and_then(|case_id| {
                crate::case::audit::append_system(
                    conn,
                    crate::case::audit::SYSTEM_UPGRADE,
                    "schema_upgrade",
                    "case",
                    &case_id,
                    Some(&serde_json::json!({ "schema_version": from })),
                    Some(&serde_json::json!({ "schema_version": to })),
                )
            });
            match appended {
                Ok(_) => conn.execute_batch("COMMIT")?,
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    return Err(e);
                }
            }
        }
        Ok((from, to))
    }

    /// Open an existing case database read-only. The schema must match this build exactly.
    pub fn open_read_only(path: &Path) -> Result<Case> {
        if !path.is_file() {
            return Err(Error::NotFound(format!("case database {}", path.display())));
        }
        let config = Config::default().access_mode(AccessMode::ReadOnly)?;
        let conn = Connection::open_with_flags(path, config)?;
        migrations::check_readable(&conn)?;
        Ok(Case {
            conn,
            path: Some(path.to_path_buf()),
            read_only: true,
            poisoned: None,
            _writer: None,
            scratch: None,
        })
    }

    pub fn in_memory() -> Result<Case> {
        let conn = Connection::open_in_memory()?;
        migrations::migrate(&conn)?;
        Ok(Case {
            conn,
            path: None,
            read_only: false,
            poisoned: None,
            _writer: None,
            scratch: None,
        })
    }

    /// Lend the case's data to `f` as a database file, with this case's writer connection
    /// released meanwhile: a file case is checkpointed and its connection closed (DuckDB will not
    /// open a second instance on a file a writer holds), then reopened; an in-memory case is
    /// copied to a temporary file that is removed afterwards. `f` must open the file read-only
    /// (the detection rule connection). The writer is restored even when `f` fails.
    pub(crate) fn with_file_released<T>(
        &mut self,
        f: impl FnOnce(&Path) -> Result<T>,
    ) -> Result<T> {
        self.ensure_usable()?;
        if self.read_only {
            return Err(Error::Invalid("the case database is open read-only".into()));
        }
        if let Some(path) = self.path.clone() {
            let t = std::time::Instant::now();
            self.conn.execute_batch("CHECKPOINT")?;
            crate::detect::phase::record("release: checkpoint", t);
            let t = std::time::Instant::now();
            let placeholder = read_only_placeholder()?;
            drop(std::mem::replace(&mut self.conn, placeholder));
            crate::detect::phase::record("release: close writer", t);
            let out = f(&path);
            let t = std::time::Instant::now();
            // Fail closed: if the file cannot be reopened (or is no longer this schema), the
            // placeholder must never take writes that would vanish silently.
            let reopened = Connection::open(&path)
                .map_err(Error::from)
                .and_then(|c| migrations::check_readable(&c).map(|_| c));
            crate::detect::phase::record("release: reopen writer", t);
            return match reopened {
                Ok(conn) => {
                    self.conn = conn;
                    out
                }
                Err(e) => {
                    let msg = format!(
                        "the case database {} could not be reopened after the detection run: {e}; \
                         this Case is unusable, open the case again",
                        path.display()
                    );
                    self.poisoned = Some(msg.clone());
                    Err(Error::Invalid(msg))
                }
            };
        }
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sparrow-snapshot-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
        let file = dir.join("case.duckdb");
        let name: String = self
            .conn
            .query_row("SELECT current_database()", [], |r| r.get(0))?;
        let copied = self.conn.execute_batch(&format!(
            "ATTACH '{}' AS rule_snapshot; COPY FROM DATABASE \"{name}\" TO rule_snapshot; DETACH rule_snapshot;",
            file.display().to_string().replace('\'', "''")
        ));
        let out = match copied {
            Ok(()) => f(&file),
            Err(e) => Err(e.into()),
        };
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    /// Fails when the case file could not be reopened after `with_file_released` (see
    /// `poisoned`). The entry points that write (`ingest`, `profile`, `detect`) call it first;
    /// the placeholder connection behind a poisoned case is a read-only, empty database, so every
    /// write fails (and any read finds no tables);
    ///     /// fails as well.
    pub fn ensure_usable(&self) -> Result<()> {
        match &self.poisoned {
            Some(msg) => Err(Error::Invalid(msg.clone())),
            None => Ok(()),
        }
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn schema_version(&self) -> Result<u32> {
        migrations::current_version(&self.conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_case_that_cannot_be_reopened_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("case.duckdb");
        let mut case = Case::create_or_open(&path).unwrap();
        case.conn()
            .execute_batch("INSERT INTO collections (tool, root_path, sparrow_version) VALUES ('hawk', '/x', 't')")
            .unwrap();
        // The closure succeeds but leaves a directory where the case file was.
        let out = case.with_file_released(|p| {
            std::fs::remove_file(p).unwrap();
            let _ = std::fs::remove_file(format!("{}.wal", p.display()));
            std::fs::create_dir(p).unwrap();
            Ok(())
        });
        let msg = out.unwrap_err().to_string();
        assert!(msg.contains("could not be reopened"), "{msg}");
        // Every later entry point errors with that message; nothing can write to the placeholder.
        assert!(
            case.ensure_usable()
                .unwrap_err()
                .to_string()
                .contains("could not be reopened")
        );
        assert!(case.with_file_released(|_| Ok(())).is_err());
        let set = crate::detect::load::load_rules(&crate::data::DataDirs::default()).unwrap();
        let run = crate::detect::run::run(&mut case, &set, &Default::default());
        assert!(
            run.unwrap_err()
                .to_string()
                .contains("could not be reopened")
        );
        let profile = crate::profile::refresh(&mut case, &Default::default());
        assert!(
            profile
                .unwrap_err()
                .to_string()
                .contains("could not be reopened")
        );
        assert!(case
            .conn()
            .execute_batch("INSERT INTO collections (tool, root_path, sparrow_version) VALUES ('hawk', '/y', 't')")
            .is_err());
        // Nothing can be created or written on the placeholder either.
        assert!(
            case.conn()
                .execute_batch("CREATE TABLE x (id INTEGER)")
                .is_err()
        );
        let actor = crate::case::actor::Actor::agent("sam", None).unwrap();
        let ind = crate::case::indicators::add_indicator(
            case.conn(),
            &actor,
            None,
            crate::case::indicators::IndicatorType::Ip,
            "203.0.113.7",
            crate::case::indicators::Verdict::Malicious,
            None,
        );
        assert!(ind.is_err());
    }

    #[test]
    fn a_reopen_failure_is_reported_even_when_the_closure_failed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("case.duckdb");
        let mut case = Case::create_or_open(&path).unwrap();
        let out: Result<()> = case.with_file_released(|p| {
            std::fs::remove_file(p).unwrap();
            let _ = std::fs::remove_file(format!("{}.wal", p.display()));
            std::fs::create_dir(p).unwrap();
            Err(Error::Invalid("closure failed".into()))
        });
        assert!(
            out.unwrap_err()
                .to_string()
                .contains("could not be reopened")
        );
        assert!(case.ensure_usable().is_err());
    }

    #[test]
    fn a_healthy_reopen_keeps_the_case_usable() {
        let dir = tempfile::tempdir().unwrap();
        let mut case = Case::create_or_open(&dir.path().join("case.duckdb")).unwrap();
        let out: Result<()> =
            case.with_file_released(|_| Err(Error::Invalid("closure failed".into())));
        assert!(out.unwrap_err().to_string().contains("closure failed"));
        case.ensure_usable().unwrap();
        case.conn()
            .execute_batch("INSERT INTO collections (tool, root_path, sparrow_version) VALUES ('hawk', '/x', 't')")
            .unwrap();
    }
}
