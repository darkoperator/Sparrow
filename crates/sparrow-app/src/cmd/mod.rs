//! Thin `#[tauri::command]` wrappers over the plain functions, one module per screen. They run off the main
//! thread (`async`), so opening or verifying a large case does not freeze the window.

pub mod case;
pub mod review;
pub mod timeline;
