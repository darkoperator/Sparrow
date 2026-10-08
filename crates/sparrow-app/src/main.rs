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
            cmd::timeline::commands::timeline_list,
            cmd::timeline::commands::timeline_propose,
            cmd::timeline::commands::timeline_edit,
            cmd::timeline::commands::timeline_verify,
            cmd::timeline::commands::timeline_reject,
            cmd::accounts::commands::accounts_list,
            cmd::export::commands::export_report,
            cmd::export::commands::export_timeline_csv,
            cmd::export::commands::export_workbook,
            cmd::pivot::commands::pivot_ip,
            cmd::pivot::commands::pivot_user,
            cmd::browse::commands::browse_tables,
            cmd::browse::commands::browse_page,
            cmd::sql::commands::sql_schema,
            cmd::sql::commands::sql_run,
            cmd::sql::commands::query_cancel,
            cmd::indicators::commands::indicators_active,
            cmd::share::commands::share_export,
            cmd::share::commands::share_preview,
            cmd::share::commands::share_import,
            cmd::highlights::commands::highlights_get,
            cmd::highlights::commands::highlights_set,
            cmd::highlights::commands::highlights_clear,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Sparrow review app");
}
