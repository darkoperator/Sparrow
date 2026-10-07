// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use sparrow_app::cmd;
use sparrow_app::state::AppState;
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .setup(|app| {
            let dir = app.path().app_config_dir()?;
            *app.state::<AppState>()
                .settings_dir
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(dir);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            cmd::case::settings_get,
            cmd::case::settings_set_analyst,
            cmd::case::case_open,
            cmd::case::case_close,
            cmd::review::commands::review_queue,
            cmd::review::commands::finding_detail,
            cmd::review::commands::review_accept,
            cmd::review::commands::review_discard,
            cmd::review::commands::proposal_accept,
            cmd::review::commands::proposal_discard,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Sparrow review app");
}
