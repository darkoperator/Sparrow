use crate::error::CmdResult;
use crate::settings::{self, GeoipStatus, Settings};
use crate::state::{self, AppState, CaseInfo};
use std::path::PathBuf;
use tauri::State;

#[tauri::command(async)]
pub fn settings_get(state: State<'_, AppState>) -> CmdResult<Settings> {
    settings::settings_get(&state)
}

#[tauri::command(async)]
pub fn settings_set_analyst(state: State<'_, AppState>, name: String) -> CmdResult<Settings> {
    settings::settings_set_analyst(&state, &name)
}

#[tauri::command(async)]
pub fn settings_geoip(state: State<'_, AppState>) -> CmdResult<GeoipStatus> {
    Ok(settings::geoip_status(&state))
}

#[tauri::command(async)]
pub fn settings_set_geoip_dir(
    state: State<'_, AppState>,
    dir: Option<String>,
) -> CmdResult<GeoipStatus> {
    settings::settings_set_geoip_dir(&state, dir.as_deref())
}

#[tauri::command(async)]
pub fn case_open(
    state: State<'_, AppState>,
    path: PathBuf,
    allow_upgrade: Option<bool>,
) -> CmdResult<CaseInfo> {
    state::case_open(&state, &path, allow_upgrade.unwrap_or(false))
}

#[tauri::command(async)]
pub fn case_close(state: State<'_, AppState>) -> CmdResult<()> {
    state::case_close(&state)
}
