//! The per-case DuckDB database.

pub mod describe;
pub mod migrations;

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
