// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use sparrow_app::state::AppState;
use sparrow_app::{bridge, cmd};
use tauri::{Emitter, Manager};

/// The bridge's view of the running app.
struct TauriHost(tauri::AppHandle);

impl bridge::BridgeHost for TauriHost {
    fn state(&self) -> &AppState {
        self.0.state::<AppState>().inner()
    }

    fn emit(&self, event: &str, payload: serde_json::Value) {
        let _ = self.0.emit(event, payload);
    }
}

fn main() {
    let builder = tauri::Builder::default();
    // Debug builds only: the Tauri MCP server drives the window over a loopback WebSocket.
    #[cfg(debug_assertions)]
    let builder = builder.plugin(
        tauri_plugin_mcp_bridge::Builder::new()
            .bind_address("127.0.0.1")
            .build(),
    );
    builder
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .manage(cmd::ingest::IngestState::default())
        .setup(|app| {
            let dir = app.path().app_config_dir()?;
            *app.state::<AppState>()
                .settings_dir
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(dir);
            // The agent bridge serves every case the window opens (see `sparrow_app::bridge`).
            if let Some(dir) = sparrow_cli::bridge::discovery_dir() {
                let host = std::sync::Arc::new(TauriHost(app.handle().clone()));
                bridge::enable(&app.state::<AppState>(), host, dir);
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // A close during an import waits for the current file and the profile (see `cmd::ingest`).
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let ing = window.state::<cmd::ingest::IngestState>();
                if cmd::ingest::window_close_requested(&ing) {
                    api.prevent_close();
                    let _ = window.emit("ingest-closing", ());
                    let window = window.clone();
                    std::thread::spawn(move || {
                        cmd::ingest::wait_idle(&window.state::<cmd::ingest::IngestState>());
                        let _ = window.close();
                    });
                }
            }
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
            cmd::devices::commands::devices_set_analyst_status,
            cmd::export::commands::export_report,
            cmd::export::commands::export_timeline_csv,
            cmd::export::commands::export_workbook,
            cmd::access::commands::access_report,
            cmd::access::commands::access_accounts,
            cmd::access::commands::export_access_csv,
            cmd::access::commands::export_access_summary,
            cmd::events::commands::events_page,
            cmd::events::commands::events_summary,
            cmd::events::commands::events_histogram,
            cmd::events::commands::events_detail,
            cmd::events::commands::events_suggest,
            cmd::events::commands::events_export_csv,
            cmd::events::commands::events_values,
            cmd::entity::commands::entity_summary,
            cmd::entity::commands::entity_pivot,
            cmd::entity::commands::entity_findings,
            cmd::entity::commands::entity_coverage,
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
            cmd::ingest::commands::ingest_discover,
            cmd::ingest::commands::ingest_run,
            cmd::ingest::commands::ingest_cancel,
            cmd::ingest::commands::ingest_unprofiled,
            cmd::ingest::commands::ingest_profile,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Sparrow review app");
}
