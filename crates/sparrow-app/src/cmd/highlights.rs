//! Highlight sets, kept in the app's local settings per case id (never in the case).

use crate::error::CmdResult;
use crate::settings::{self, HighlightSet};

pub use crate::settings::{highlights_clear, highlights_get, highlights_set};

pub mod commands {
    use super::*;
    use crate::state::AppState;
    use tauri::State;

    #[tauri::command(async)]
    pub fn highlights_get(
        state: State<'_, AppState>,
        case_id: String,
    ) -> CmdResult<Vec<HighlightSet>> {
        settings::highlights_get(&state, &case_id)
    }

    #[tauri::command(async)]
    pub fn highlights_set(
        state: State<'_, AppState>,
        case_id: String,
        sets: Vec<HighlightSet>,
    ) -> CmdResult<Vec<HighlightSet>> {
        settings::highlights_set(&state, &case_id, sets)
    }

    #[tauri::command(async)]
    pub fn highlights_clear(state: State<'_, AppState>, case_id: String) -> CmdResult<()> {
        settings::highlights_clear(&state, &case_id)
    }
}
