//! Sparrow review app backend: each screen action is a plain function over the app state (testable without a
//! window), wrapped by a thin Tauri command in `cmd`. All logic stays in `sparrow-core`.

pub mod cmd;
pub mod error;
pub mod settings;
pub mod state;

pub use error::{CmdError, CmdResult};
