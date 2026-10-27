//! The devices screen's command: the devices to contain, computed from the case tables on every call.

use crate::error::CmdResult;
use crate::state::{AppState, with_case};
use sparrow_core::case::devices::{self, SuspectDevice};
use tauri::State;

/// The suspect devices of `tenant` (all tenants when `None`), in core's order: status, confidence, last active.
pub fn devices_list(state: &AppState, tenant: Option<&str>) -> CmdResult<Vec<SuspectDevice>> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(devices::suspect_devices(open.case.conn(), tenant)?)
    })
}

pub mod commands {
    use super::*;

    #[tauri::command(async)]
    pub fn devices_list(
        state: State<'_, AppState>,
        tenant: Option<String>,
    ) -> CmdResult<Vec<SuspectDevice>> {
        super::devices_list(&state, tenant.as_deref())
    }
}
