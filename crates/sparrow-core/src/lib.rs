//! Sparrow core: ingest M365 collector output (Hawk, Microsoft-Extractor-Suite) into a DuckDB case database.

pub mod case;
pub mod data;
pub mod db;
pub mod detect;
pub mod discovery;
pub mod enrich;
pub mod error;
pub mod export;
#[cfg(any(test, feature = "test-fixtures"))]
#[doc(hidden)]
pub mod fixtures;
pub mod ingest;
pub mod normalize;
pub mod parsers;
pub mod profile;
pub mod readers;
pub mod summary;
pub mod verify;

pub use db::Case;
pub use error::{Error, Result};

/// Version of this sparrow build (recorded on every collection).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How sparrow-core was compiled (profile, optimisation, features, rustflags): part of the test
/// cache's key.
#[doc(hidden)]
pub const BUILD_CONFIG: &str = env!("SPARROW_CORE_BUILD_CONFIG");

/// Whether integer overflow panics in this crate's build (it follows the profile): part of the
/// test cache's key. Probed once, with the panic message silenced for the moment it takes.
#[doc(hidden)]
pub fn overflow_checks_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let on = std::panic::catch_unwind(|| {
            let x: u8 = std::hint::black_box(255);
            std::hint::black_box(x + 1)
        })
        .is_err();
        std::panic::set_hook(hook);
        on
    })
}
