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
            cmd::timeline::commands::timeline_add_events,
            cmd::timeline::commands::timeline_verify,
            cmd::timeline::commands::timeline_reject,
            cmd::accounts::commands::accounts_list,
            cmd::devices::commands::devices_list,
            cmd::export::commands::export_report,
            cmd::export::commands::export_timeline_csv,
            cmd::export::commands::export_workbook,
            cmd::events::commands::events_page,
            cmd::events::commands::events_summary,
            cmd::events::commands::events_histogram,
            cmd::events::commands::events_detail,
            cmd::events::commands::events_suggest,
            cmd::events::commands::events_export_csv,
            cmd::entity::commands::entity_summary,
            cmd::entity::commands::entity_pivot,
            cmd::entity::commands::entity_findings,
            cmd::marks::commands::marks_flag_rows,
            cmd::marks::commands::marks_flag_value,
            cmd::marks::commands::marks_tag_rows,
            cmd::marks::commands::marks_list_tags,
            cmd::marks::commands::marks_review,
            cmd::marks::commands::notes_add_rows,
            cmd::browse::commands::browse_tables,
            cmd::browse::commands::browse_page,
            cmd::browse::commands::evidence_filter,
            cmd::sql::commands::sql_schema,
            cmd::sql::commands::sql_run,
            cmd::sql::commands::sql_check,
            cmd::sql::commands::sql_export_csv,
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
