//! The per-case DuckDB database.

pub mod describe;
pub mod migrations;
pub mod state_tables;

pub use describe::{ColumnInfo, TableInfo, describe};

use crate::{Error, Result};
use duckdb::{AccessMode, Config, Connection, OptionalExt};
use std::path::{Path, PathBuf};

/// Bytes of a DuckDB size string: a non-negative decimal number and an optional unit (B / byte(s), KB..PB in
/// powers of 1000, KiB..PiB in powers of 1024; any case; spaces allowed), as DuckDB writes `memory_limit`
/// ("25.5 GiB") and accepts sizes. `None` for anything else.
pub(crate) fn parse_size(text: &str) -> Option<u64> {
    let t = text.trim();
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    if num.is_empty() || num.matches('.').count() > 1 || num.starts_with('.') || num.ends_with('.')
    {
        return None;
    }
    let value: f64 = num.parse().ok()?;
    let unit = unit.trim().to_ascii_lowercase();
    let scale: f64 = match unit.as_str() {
        "" | "b" | "byte" | "bytes" => 1.0,
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        "pb" => 1e15,
        "kib" => 1024f64,
        "mib" => 1024f64.powi(2),
        "gib" => 1024f64.powi(3),
        "tib" => 1024f64.powi(4),
        "pib" => 1024f64.powi(5),
        _ => return None,
    };
    let bytes = value * scale;
    (bytes.is_finite() && bytes < u64::MAX as f64).then(|| bytes.round() as u64)
}

/// Environment variable overriding the memory cap of every DuckDB instance Sparrow opens on a case (the writer,
/// read-only opens, the rule and query instances): a DuckDB size (`2GB`, `8GiB`, ...) or `default` (DuckDB's own,
/// 80% of RAM).
pub const MEMORY_LIMIT_ENV: &str = "SPARROW_MEMORY_LIMIT";

/// The cap without an override (DuckDB's `4GB`), never above DuckDB's own default. Uncapped, DuckDB's cache grows
/// toward 80% of RAM: on the 3.47M-event jbeets case `detect` peaked at 17.0 GB RSS and 4.0 GB brought it to 6.2 GB
/// (20 s -> 24 s); a 1.13M-row ingest in 23 files went from 8.2 GB to 6.5 GB RSS for 4% more time (2 GB: 5.0 GB,
/// 23% more). Measured 2026-10-29 (docs: reports/ingest-memory.md).
pub const DEFAULT_MEMORY_LIMIT: u64 = 4_000_000_000;

/// The `memory_limit` (bytes) to set on an instance whose current limit is `current`, or `None` to keep it. Without
/// an override: [`DEFAULT_MEMORY_LIMIT`] when `current` is above it or does not parse, else `None` (a smaller
/// machine keeps DuckDB's 80%). An override ([`MEMORY_LIMIT_ENV`]) is a size above zero or `default`; anything
/// else is an error.
fn memory_limit_target(current: &str, override_: Option<&str>) -> Result<Option<u64>> {
    if let Some(v) = override_ {
        if v.trim().eq_ignore_ascii_case("default") {
            return Ok(None);
        }
        return match parse_size(v) {
            Some(bytes) if bytes > 0 => Ok(Some(bytes)),
            _ => Err(Error::Invalid(format!(
                "{MEMORY_LIMIT_ENV}={v:?} is not a size: use a DuckDB size such as 2GB or 8GiB, or `default` to keep DuckDB's own memory limit (80% of RAM)"
            ))),
        };
    }
    Ok(match parse_size(current) {
        Some(limit) if limit <= DEFAULT_MEMORY_LIMIT => None,
        _ => Some(DEFAULT_MEMORY_LIMIT),
    })
}

/// Cap `conn`'s instance at [`memory_limit_target`] of its current limit and [`MEMORY_LIMIT_ENV`]. Call it before
/// any lockdown (`lock_configuration`). An in-memory instance spills to a private directory under the system temp
/// directory (DuckDB's default for one is `.tmp` in the working directory); a file's spills stay beside it.
pub(crate) fn cap_memory(conn: &Connection, in_memory: bool) -> Result<()> {
    let over = memory_override(std::env::var(MEMORY_LIMIT_ENV))?;
    cap_memory_using(conn, in_memory, over.as_deref())
}

/// The override [`MEMORY_LIMIT_ENV`] gives: unset is `None`; a value that is not UTF-8 is an error (never read as
/// unset, which would run with the default instead of what was asked for).
fn memory_override(var: std::result::Result<String, std::env::VarError>) -> Result<Option<String>> {
    match var {
        Ok(v) => Ok(Some(v)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(v)) => Err(Error::Invalid(format!(
            "{MEMORY_LIMIT_ENV}={v:?} is not valid UTF-8: use a DuckDB size such as 2GB or 8GiB, or `default`"
        ))),
    }
}

fn cap_memory_using(conn: &Connection, in_memory: bool, override_: Option<&str>) -> Result<()> {
    let current: String =
        conn.query_row("SELECT current_setting('memory_limit')", [], |r| r.get(0))?;
    if let Some(bytes) = memory_limit_target(&current, override_)? {
        conn.execute_batch(&format!("SET memory_limit = '{bytes} bytes'"))?;
    }
    if in_memory {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sparrow-spill-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let dir = dir.display().to_string().replace('\'', "''");
        conn.execute_batch(&format!("SET temp_directory = '{dir}'"))?;
    }
    Ok(())
}

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
    Error::WriterBusy(format!("{} ({detail})", path.display()))
}

/// DuckDB's error opening or attaching `path`: its file-lock conflict (another process holds the case as writer)
/// becomes `Error::WriterBusy`; any other error stays a database error.
pub(crate) fn lock_error(path: &Path, e: duckdb::Error) -> Error {
    let msg = e.to_string();
    if msg.contains("Could not set lock") || msg.contains("Conflicting lock") {
        another_writer(path, &msg)
    } else {
        e.into()
    }
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
    let conn = Connection::open(path).map_err(|e| lock_error(path, e))?;
    cap_memory(&conn, false)?;
    let key = FileKey::of(path)?;
    if w.contains(&key) {
        return Err(another_writer(path, "already open in this process"));
    }
    w.push(key.clone());
    Ok((conn, WriterGuard(key)))
}

/// `case_meta` key: present while a migrated case still owes its post-migration step ([`post_migration`]); the
/// value is the schema version the case had before it was migrated. The migration runner writes it in the same
/// transaction as the migrations, and the step deletes it in its own, so a failed step is retried by every later
/// writable open until it succeeds. Read-only commands warn while it exists.
pub const POST_MIGRATION_PENDING: &str = "post_migration_pending";

/// `case_meta` key: the credential-failure codes (a JSON array of integers) the last profile run derived
/// `spray_sources` and `cloud_services` with. The post-migration rebuild reuses them, so an upgrade never swaps a
/// case's custom `credential_failure_codes` list for the environment's.
pub const CREDENTIAL_FAILURE_CODES: &str = "credential_failure_codes";

/// `case_meta` key: the first-party application ids (a JSON array of strings) the last profile run built
/// `cloud_services` with; reused like [`CREDENTIAL_FAILURE_CODES`].
pub const FIRST_PARTY_APPS: &str = "first_party_apps";

/// Apply pending migrations, then run the post-migration step if one is pending; the ONLY way a case is migrated,
/// and every writable open goes through it. Returns the schema version before and after: when a pending step ran,
/// "before" is the version the marker recorded (the upgrade completed now), else the version this open found.
fn migrate_recorded(conn: &Connection) -> Result<(u32, u32)> {
    let found = migrations::current_version(conn)?;
    let to = migrations::migrate(conn)?;
    match pending_post_migration(conn)? {
        Some(from) => {
            post_migration(conn, from, to)?;
            Ok((from, to))
        }
        None => Ok((found, to)),
    }
}

/// The pending post-migration step's "before" version ([`POST_MIGRATION_PENDING`]), if one is pending.
fn pending_post_migration(conn: &Connection) -> Result<Option<u32>> {
    if migrations::current_version(conn)? < migrations::ANALYST_VERSION {
        return Ok(None);
    }
    let v: Option<String> = conn
        .query_row(
            "SELECT value FROM case_meta WHERE key = ?",
            [POST_MIGRATION_PENDING],
            |r| r.get(0),
        )
        .optional()?;
    v.map(|v| {
        v.parse().map_err(|_| {
            Error::Invalid(format!(
                "case_meta {POST_MIGRATION_PENDING}: {v:?} is not a schema version"
            ))
        })
    })
    .transpose()
}

/// The post-migration step of a case migrated from schema `from` to `to`, in ONE transaction that also deletes the
/// marker: rebuild the derived relations (`rebuild_derived`) and, when the case crossed the analyst version, record
/// the upgrade in the audit trail (Addendum D.3): a `schema_upgrade` entry, then one `legacy_decision` per
/// indicator. Any error rolls all of it back and leaves the marker for the next writable open.
fn post_migration(conn: &Connection, from: u32, to: u32) -> Result<()> {
    let crossed_analyst = from < migrations::ANALYST_VERSION && to >= migrations::ANALYST_VERSION;
    conn.execute_batch("BEGIN TRANSACTION")?;
    let done = rebuild_derived(conn).and_then(|_| {
        if crossed_analyst {
            let case_id = crate::case::audit::case_id(conn)?;
            crate::case::audit::append_system(
                conn,
                crate::case::audit::SYSTEM_UPGRADE,
                "schema_upgrade",
                "case",
                &case_id,
                Some(&serde_json::json!({ "schema_version": from })),
                Some(&serde_json::json!({ "schema_version": to })),
            )?;
            legacy_indicator_decisions(conn)?;
        }
        conn.execute(
            "DELETE FROM case_meta WHERE key = ?",
            [POST_MIGRATION_PENDING],
        )?;
        Ok(())
    });
    match done {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    }
    Ok(())
}

/// Rewrite the derived relations whose definition a migration may have changed (`spray_sources`, then
/// `cloud_services`, which reads it) from the case's own sign-ins, so a migrated case never keeps rows computed
/// under an older definition. The credential-failure codes are the ones the last profile run stored
/// ([`CREDENTIAL_FAILURE_CODES`]); a case never profiled since that was recorded falls back to `$SPARROW_DATA` /
/// `$SPARROW_RULES` or the built-in list.
fn rebuild_derived(conn: &Connection) -> Result<()> {
    #[cfg(any(test, feature = "test-fixtures"))]
    if test_hooks::FAIL_POST_MIGRATION.with(std::cell::Cell::get) {
        return Err(Error::Invalid(
            "test hook: post-migration step failed".into(),
        ));
    }
    let stored: Option<String> = conn
        .query_row(
            "SELECT value FROM case_meta WHERE key = ?",
            [CREDENTIAL_FAILURE_CODES],
            |r| r.get(0),
        )
        .optional()?;
    let codes = match stored {
        Some(v) => serde_json::from_str::<Vec<i64>>(&v)
            .map_err(|e| Error::Invalid(format!("case_meta {CREDENTIAL_FAILURE_CODES}: {e}")))?,
        None => {
            crate::profile::spray::credential_failure_codes(&crate::data::DataDirs::from_env())?
        }
    };
    let stored: Option<String> = conn
        .query_row(
            "SELECT value FROM case_meta WHERE key = ?",
            [FIRST_PARTY_APPS],
            |r| r.get(0),
        )
        .optional()?;
    let first_party = match stored {
        Some(v) => serde_json::from_str::<Vec<String>>(&v)
            .map_err(|e| Error::Invalid(format!("case_meta {FIRST_PARTY_APPS}: {e}")))?,
        None => {
            crate::profile::cloud_services::first_party_apps(&crate::data::DataDirs::from_env())?
        }
    };
    crate::profile::spray::rebuild(conn, &codes)?;
    crate::profile::cloud_services::rebuild(conn, &codes, &first_party)?;
    Ok(())
}

/// Record `apps` as the first-party application ids `cloud_services` was built with ([`FIRST_PARTY_APPS`]).
pub fn store_first_party_apps(conn: &Connection, apps: &[String]) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO case_meta (key, value) VALUES (?, ?)",
        duckdb::params![
            FIRST_PARTY_APPS,
            serde_json::to_string(apps).map_err(|e| Error::Invalid(e.to_string()))?
        ],
    )?;
    Ok(())
}

/// Record `codes` as the credential-failure codes the derived relations were built with
/// ([`CREDENTIAL_FAILURE_CODES`]); the profile step calls it in its own transaction.
pub fn store_credential_failure_codes(conn: &Connection, codes: &[i64]) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO case_meta (key, value) VALUES (?, ?)",
        duckdb::params![
            CREDENTIAL_FAILURE_CODES,
            serde_json::to_string(codes).map_err(|e| Error::Invalid(e.to_string()))?
        ],
    )?;
    Ok(())
}

/// Test-only failure injection (never compiled into a normal build).
#[cfg(any(test, feature = "test-fixtures"))]
#[doc(hidden)]
pub mod test_hooks {
    thread_local! {
        pub(super) static FAIL_POST_MIGRATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Make every post-migration step on this thread fail before it changes anything.
    pub fn fail_post_migration(on: bool) {
        FAIL_POST_MIGRATION.with(|c| c.set(on));
    }
}

/// One reviewable `legacy_decision` audit entry per indicator that predates the audit trail, by its original
/// author (`added_by`), with its current state as `after` and no `before`: accepting it keeps the indicator,
/// discarding it soft-deletes it. Runs inside the upgrade's transaction, after the `schema_upgrade` entry.
fn legacy_indicator_decisions(conn: &Connection) -> Result<()> {
    let rows: Vec<(String, String)> = {
        let mut stmt = conn
            .prepare("SELECT indicator_id, added_by FROM case_indicators ORDER BY indicator_id")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    for (id, added_by) in rows {
        let state = crate::case::indicators::indicator_state(conn, &id)?;
        crate::case::audit::append_at(
            conn,
            crate::case::audit::now(),
            &added_by,
            None,
            "legacy_decision",
            "indicator",
            &id,
            None,
            state.as_ref(),
            None,
        )?;
    }
    Ok(())
}

/// A directory removed when the `Case` that owns it is dropped (see [`Case::with_scratch_dir`]).
struct ScratchDir(PathBuf);

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What [`Case::inspect`] found.
#[derive(Debug, Clone)]
pub struct CaseInspection {
    /// The file's schema version.
    pub schema_version: u32,
    /// This build's schema version.
    pub latest: u32,
    /// The audit chain's state; `None` when the schema predates the audit trail (migration 16).
    pub audit: Option<crate::case::audit::ChainReport>,
}

/// What [`Case::open_verified`] decided, on the writer connection, before anything was written.
pub enum VerifiedOpen {
    /// Open for writing: the chain is intact (and an older schema has been migrated, as allowed).
    Writable(Case),
    /// Current schema, broken chain: the writer is released and nothing was written; open it read-only.
    BrokenChain(crate::case::audit::ChainReport),
    /// Older schema whose chain is broken or could not be verified: the writer is released and nothing was
    /// written. `sparrow audit verify --acknowledge` and `sparrow upgrade` come first.
    NeedsAcknowledge {
        schema_version: u32,
        first_bad_seq: Option<i64>,
        problem: String,
    },
    /// Older schema, intact chain, upgrade not allowed: the writer is released and nothing was written.
    NeedsUpgrade { schema_version: u32, latest: u32 },
}

pub struct Case {
    conn: Connection,
    path: Option<PathBuf>,
    read_only: bool,
    /// Set when the file could not be reopened after `with_file_released`: `conn` is then an
    /// read-only, empty placeholder database that cannot take writes.
    poisoned: std::cell::RefCell<Option<String>>,
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
        migrate_recorded(&conn)?;
        Ok(Case {
            conn,
            path: Some(path.to_path_buf()),
            read_only: false,
            poisoned: Default::default(),
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
        let out = migrate_recorded(&conn);
        // Close the connection before releasing the writer registration.
        drop(conn);
        drop(writer);
        out
    }

    /// Open an existing case database read-only. The schema must match this build exactly.
    pub fn open_read_only(path: &Path) -> Result<Case> {
        if !path.is_file() {
            return Err(Error::NotFound(format!("case database {}", path.display())));
        }
        let config = Config::default().access_mode(AccessMode::ReadOnly)?;
        let conn = Connection::open_with_flags(path, config).map_err(|e| lock_error(path, e))?;
        cap_memory(&conn, false)?;
        migrations::check_readable(&conn)?;
        Ok(Case {
            conn,
            path: Some(path.to_path_buf()),
            read_only: true,
            poisoned: Default::default(),
            _writer: None,
            scratch: None,
        })
    }

    /// Open an existing case for writing only after its audit chain checks out, deciding on the writer connection
    /// itself so nothing can change the file between the check and the writes: the writer is acquired (this
    /// process's registry and DuckDB's lock) WITHOUT migrating, the schema version is read and, from the audit
    /// trail's migration on, the chain is verified on that connection. Only an intact chain is migrated, and an
    /// older schema only when `allow_upgrade`; every other outcome releases the writer with nothing written. A
    /// schema before the audit trail has no chain to break and follows the upgrade path.
    pub fn open_verified(path: &Path, allow_upgrade: bool) -> Result<VerifiedOpen> {
        if !path.is_file() {
            return Err(Error::NotFound(format!("case database {}", path.display())));
        }
        let (conn, writer) = open_writer(path)?;
        // A `Case` from here on, so every early return closes the connection before releasing the writer.
        let case = Case {
            conn,
            path: Some(path.to_path_buf()),
            read_only: false,
            poisoned: Default::default(),
            _writer: Some(writer),
            scratch: None,
        };
        let schema_version = migrations::current_version(&case.conn)?;
        let latest = migrations::latest_version();
        if schema_version > latest {
            return Err(Error::SchemaTooNew {
                db: schema_version,
                supported: latest,
            });
        }
        let has_trail = schema_version >= migrations::ANALYST_VERSION;
        if schema_version == latest {
            let report = crate::case::audit::verify(&case.conn)?;
            if !report.ok {
                return Ok(VerifiedOpen::BrokenChain(report));
            }
            // Completes an interrupted upgrade's post-migration step, as any writable open does.
            migrate_recorded(&case.conn)?;
            return Ok(VerifiedOpen::Writable(case));
        }
        if has_trail {
            match crate::case::audit::verify(&case.conn) {
                Ok(r) if r.ok => {}
                Ok(r) => {
                    return Ok(VerifiedOpen::NeedsAcknowledge {
                        schema_version,
                        first_bad_seq: r.first_bad_seq,
                        problem: r.problem.unwrap_or_else(|| "unknown problem".into()),
                    });
                }
                Err(e) => {
                    return Ok(VerifiedOpen::NeedsAcknowledge {
                        schema_version,
                        first_bad_seq: None,
                        problem: format!("the audit chain could not be verified: {e}"),
                    });
                }
            }
        }
        if !allow_upgrade {
            return Ok(VerifiedOpen::NeedsUpgrade {
                schema_version,
                latest,
            });
        }
        migrate_recorded(&case.conn)?;
        let report = crate::case::audit::verify(&case.conn)?;
        if !report.ok {
            return Ok(VerifiedOpen::BrokenChain(report));
        }
        Ok(VerifiedOpen::Writable(case))
    }

    /// Look at a case file before deciding how to open it: its schema version and, from the audit trail's migration
    /// on, its audit chain. Opened read-only without the schema-match check, so an older case is reported, never
    /// migrated; nothing is written. A file this process already holds as writer is `WriterBusy`, as is one another
    /// process holds (DuckDB's lock).
    pub fn inspect(path: &Path) -> Result<CaseInspection> {
        if !path.is_file() {
            return Err(Error::NotFound(format!("case database {}", path.display())));
        }
        {
            let w = WRITERS.lock().unwrap_or_else(|e| e.into_inner());
            if w.contains(&FileKey::of(path)?) {
                return Err(another_writer(path, "already open in this process"));
            }
        }
        let config = Config::default().access_mode(AccessMode::ReadOnly)?;
        let conn = Connection::open_with_flags(path, config).map_err(|e| lock_error(path, e))?;
        cap_memory(&conn, false)?;
        let schema_version = migrations::current_version(&conn)?;
        let audit = if schema_version >= migrations::ANALYST_VERSION {
            Some(crate::case::audit::verify(&conn)?)
        } else {
            None
        };
        Ok(CaseInspection {
            schema_version,
            latest: migrations::latest_version(),
            audit,
        })
    }

    /// The schema version recorded by a post-migration step that has not completed yet
    /// ([`POST_MIGRATION_PENDING`]): `sparrow upgrade` (or any writable open) runs it.
    pub fn pending_post_migration(&self) -> Result<Option<u32>> {
        pending_post_migration(&self.conn)
    }

    pub fn in_memory() -> Result<Case> {
        let conn = Connection::open_in_memory()?;
        cap_memory(&conn, true)?;
        migrate_recorded(&conn)?;
        Ok(Case {
            conn,
            path: None,
            read_only: false,
            poisoned: Default::default(),
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
                .and_then(|c| cap_memory(&c, false).map(|_| c))
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
                    *self.poisoned.borrow_mut() = Some(msg.clone());
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
        match &*self.poisoned.borrow() {
            Some(msg) => Err(Error::Invalid(msg.clone())),
            None => Ok(()),
        }
    }

    /// Lock this instance down for good (the review app, which queries the case it holds open): no extension
    /// install/load, no file, network or environment access, and the configuration can no longer be changed.
    /// Probed like the `query` connection; `Error::Invalid` when a probe gets through. Writes through
    /// [`Case::conn`] (transactions, audit rows, checkpoint) are unaffected; there is no way back short of
    /// reopening the case.
    pub fn lock_down(&self) -> Result<()> {
        self.ensure_usable()?;
        self.conn.execute_batch(
            "SET autoinstall_known_extensions = false; SET autoload_known_extensions = false; \
             SET allow_community_extensions = false; SET enable_external_access = false; \
             SET lock_configuration = true;",
        )?;
        crate::case::query::probe_lockdown(&self.conn)
    }

    /// True when [`Case::lock_down`] has been applied: external access off and the configuration locked.
    pub fn is_locked_down(&self) -> Result<bool> {
        let (ext, lock): (String, String) = self.conn.query_row(
            "SELECT current_setting('enable_external_access')::VARCHAR, \
                    current_setting('lock_configuration')::VARCHAR",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(ext == "false" && lock == "true")
    }

    /// Make this case unusable (see [`Case::ensure_usable`]) because its connection is in a state the caller cannot
    /// vouch for, e.g. a transaction that would not roll back.
    pub(crate) fn poison(&self, msg: String) {
        *self.poisoned.borrow_mut() = Some(msg);
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

    fn memory_limit(conn: &Connection) -> u64 {
        let v: String = conn
            .query_row("SELECT current_setting('memory_limit')", [], |r| r.get(0))
            .unwrap();
        parse_size(&v).unwrap()
    }

    #[test]
    fn the_memory_limit_is_capped_unless_overridden() {
        let gb = 1_000_000_000;
        let target = |cur: &str, o: Option<&str>| memory_limit_target(cur, o).unwrap();
        // DuckDB's 80% of a 32 GB machine is lowered to the cap; a smaller limit is kept.
        assert_eq!(target("25.5 GiB", None), Some(DEFAULT_MEMORY_LIMIT));
        assert_eq!(target("3.0 GiB", None), None);
        assert_eq!(target("4GB", None), None);
        assert_eq!(target("not a size", None), Some(DEFAULT_MEMORY_LIMIT));
        assert_eq!(target("1 GiB", Some("8GB")), Some(8 * gb));
        assert_eq!(target("25.5 GiB", Some(" Default ")), None);
        for bad in ["0", "lots", "-1GB", ""] {
            let msg = memory_limit_target("25.5 GiB", Some(bad))
                .unwrap_err()
                .to_string();
            assert!(msg.contains(MEMORY_LIMIT_ENV), "{bad}: {msg}");
        }
    }

    #[test]
    fn every_case_instance_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("case.duckdb");
        let case = Case::create_or_open(&path).unwrap();
        let writer = memory_limit(case.conn());
        assert!(writer > 0 && writer <= DEFAULT_MEMORY_LIMIT, "{writer}");
        drop(case);
        let ro = Case::open_read_only(&path).unwrap();
        let read_only = memory_limit(ro.conn());
        assert!(
            read_only > 0 && read_only <= DEFAULT_MEMORY_LIMIT,
            "{read_only}"
        );
        // The locked query instance (its own in-memory DuckDB) reports its own setting.
        let q = crate::case::query::run(&path, "SELECT current_setting('memory_limit') AS m", 1)
            .unwrap();
        let text = q.rows[0][0].as_str().unwrap().to_string();
        let query = parse_size(&text).unwrap();
        assert!(query > 0 && query <= DEFAULT_MEMORY_LIMIT, "{text}");
        drop(ro);
        let mut case = Case::create_or_open(&path).unwrap();
        case.with_file_released(|_| Ok(())).unwrap();
        let reopened = memory_limit(case.conn());
        assert!(
            reopened > 0 && reopened <= DEFAULT_MEMORY_LIMIT,
            "{reopened}"
        );
        let mem = Case::in_memory().unwrap();
        let in_memory = memory_limit(mem.conn());
        assert!(
            in_memory > 0 && in_memory <= DEFAULT_MEMORY_LIMIT,
            "{in_memory}"
        );
        let spill: String = mem
            .conn()
            .query_row("SELECT current_setting('temp_directory')", [], |r| r.get(0))
            .unwrap();
        assert!(spill.contains("sparrow-spill-"), "{spill}");
    }

    #[test]
    fn the_override_is_read_from_the_environment_failing_closed() {
        use std::env::VarError;
        assert_eq!(memory_override(Err(VarError::NotPresent)).unwrap(), None);
        assert_eq!(
            memory_override(Ok("2GB".into())).unwrap().as_deref(),
            Some("2GB")
        );
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let bad = std::ffi::OsString::from_vec(vec![b'2', 0xff, b'G']);
            let msg = memory_override(Err(VarError::NotUnicode(bad)))
                .unwrap_err()
                .to_string();
            assert!(
                msg.contains(MEMORY_LIMIT_ENV) && msg.contains("UTF-8"),
                "{msg}"
            );
        }
    }

    #[test]
    fn an_override_sets_the_limit_and_default_keeps_duckdbs() {
        let conn = Connection::open_in_memory().unwrap();
        let duckdb_own = memory_limit(&conn);
        cap_memory_using(&conn, true, Some("default")).unwrap();
        assert_eq!(memory_limit(&conn), duckdb_own);
        cap_memory_using(&conn, true, Some("300MB")).unwrap();
        // DuckDB stores the limit rounded to its own unit.
        let set = memory_limit(&conn);
        assert!((280_000_000..=300_000_000).contains(&set), "{set}");
        assert!(cap_memory_using(&conn, true, Some("lots")).is_err());
    }

    /// A capped, locked-down in-memory instance (the rule and query instances) can still spill to its private temp
    /// directory, which DuckDB removes when the instance closes: the same sort fails without one, so the query
    /// really needs it.
    #[test]
    fn a_capped_locked_instance_spills_instead_of_failing() {
        let sort = "SELECT count(*) FROM (SELECT md5(range::VARCHAR) || md5((range + 1)::VARCHAR) AS m \
                    FROM range(3000000) ORDER BY m)";
        let lock = "SET enable_external_access = false; SET lock_configuration = true;";
        let no_spill = Connection::open_in_memory().unwrap();
        cap_memory_using(&no_spill, false, Some("256MB")).unwrap();
        no_spill.execute_batch("SET temp_directory = ''").unwrap();
        no_spill.execute_batch(lock).unwrap();
        let err = no_spill
            .query_row(sort, [], |r| r.get::<_, i64>(0))
            .unwrap_err();
        assert!(err.to_string().contains("Out of Memory"), "{err}");
        let conn = Connection::open_in_memory().unwrap();
        cap_memory_using(&conn, true, Some("256MB")).unwrap();
        let spill: String = conn
            .query_row("SELECT current_setting('temp_directory')", [], |r| r.get(0))
            .unwrap();
        assert!(spill.contains("sparrow-spill-"), "{spill}");
        conn.execute_batch(lock).unwrap();
        let n: i64 = conn.query_row(sort, [], |r| r.get(0)).unwrap();
        assert_eq!(n, 3_000_000);
        assert!(Path::new(&spill).exists(), "the sort spilled nothing");
        drop(conn);
        assert!(!Path::new(&spill).exists(), "{spill} left behind");
    }

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
