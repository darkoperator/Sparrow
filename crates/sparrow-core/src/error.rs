use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database error: {0}")]
    Db(#[from] duckdb::Error),
    #[error("I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "case database schema v{db} is newer than this sparrow supports (v{supported}); upgrade sparrow"
    )]
    SchemaTooNew { db: u32, supported: u32 },
    #[error(
        "case database schema v{db} is older than v{supported}; run `sparrow upgrade --case <file>` to upgrade it"
    )]
    SchemaOutdated { db: u32, supported: u32 },
    #[error("migration {version} failed: {source}")]
    Migration {
        version: u32,
        #[source]
        source: duckdb::Error,
    },
    #[error("not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    /// Another writer holds the case file (another process, or another `Case` in this process).
    #[error("case is open by another writer: {0}")]
    WriterBusy(String),
    /// An agent decision or review that cannot be applied: a bad status or verdict, a missing reason, an unknown
    /// object, a bad evidence reference, a stale or out-of-order review. Nothing was written.
    #[error("{0}")]
    Decision(String),
    /// The audit chain has an unacknowledged break, so no entry may be appended.
    #[error("{0}")]
    ChainBroken(String),
    /// The file's records have a shape this version cannot load. Ingest records the file as
    /// `not_supported` (retried by later versions) instead of `error`.
    #[error("unsupported record shape: {0}")]
    UnsupportedShape(String),
    /// Every culture-formatted date in the file is ambiguous. Ingest retries the file after
    /// the rest of its collection, with the day/month order the other files show.
    #[error("ambiguous day/month order; retried after the other files of the collection")]
    DateOrderDeferred,
}

impl Error {
    pub fn io(path: &Path, source: std::io::Error) -> Self {
        Error::Io {
            path: path.display().to_string(),
            source,
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
