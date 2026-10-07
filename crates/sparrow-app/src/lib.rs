//! Sparrow review app backend: each screen action is a plain function over the app state (testable without a
//! window), wrapped by a thin Tauri command in `main.rs`. All logic stays in `sparrow-core`.

pub mod error;

pub use error::{CmdError, CmdResult};
