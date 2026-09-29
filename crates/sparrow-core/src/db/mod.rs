//! The per-case DuckDB database.

pub mod describe;
pub mod migrations;
pub mod state_tables;

pub use describe::{ColumnInfo, TableInfo, describe};

use crate::{Error, Result};
use duckdb::{AccessMode, Config, Connection};
use std::path::{Path, PathBuf};

pub struct Case {
    conn: Connection,
    path: Option<PathBuf>,
    read_only: bool,
}

impl Case {
    /// Open (creating if needed) a case database for writing and bring its schema up to date.
    pub fn create_or_open(path: &Path) -> Result<Case> {
        let conn = Connection::open(path)?;
        migrations::migrate(&conn)?;
        Ok(Case {
            conn,
            path: Some(path.to_path_buf()),
            read_only: false,
        })
    }

    /// Bring an existing case database's schema up to date. Never creates a new file.
    /// Returns the schema version before and after.
    pub fn upgrade(path: &Path) -> Result<(u32, u32)> {
        if !path.is_file() {
            return Err(Error::NotFound(format!("case database {}", path.display())));
        }
        let conn = Connection::open(path)?;
        let from = migrations::current_version(&conn)?;
        let to = migrations::migrate(&conn)?;
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
        })
    }

    pub fn in_memory() -> Result<Case> {
        let conn = Connection::open_in_memory()?;
        migrations::migrate(&conn)?;
        Ok(Case {
            conn,
            path: None,
            read_only: false,
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
        if self.read_only {
            return Err(Error::Invalid("the case database is open read-only".into()));
        }
        if let Some(path) = self.path.clone() {
            self.conn.execute_batch("CHECKPOINT")?;
            let placeholder = Connection::open_in_memory()?;
            drop(std::mem::replace(&mut self.conn, placeholder));
            let out = f(&path);
            self.conn = Connection::open(&path)?;
            return out;
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
