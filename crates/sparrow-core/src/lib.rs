//! Sparrow core: ingest M365 collector output (Hawk, Microsoft-Extractor-Suite) into a DuckDB case database.

pub mod data;
pub mod db;
pub mod discovery;
pub mod error;
#[cfg(any(test, feature = "test-fixtures"))]
#[doc(hidden)]
pub mod fixtures;
pub mod ingest;
pub mod normalize;
pub mod parsers;
pub mod profile;
pub mod readers;
pub mod verify;

pub use db::Case;
pub use error::{Error, Result};

/// Version of this sparrow build (recorded on every collection).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
