//! Thin `#[tauri::command]` wrappers over the plain functions, one module per screen. They run off the main
//! thread (`async`), so opening or verifying a large case does not freeze the window.

pub mod accounts;
pub mod browse;
pub mod case;
pub mod devices;
pub mod export;
pub mod highlights;
pub mod indicators;
pub mod pivot;
pub mod review;
pub mod share;
pub mod sql;
pub mod timeline;
