//! The devices screen's commands: the devices to contain, computed from the case tables on every call, and the
//! analyst's own status of a device (an analyst decision: a read-only case refuses it before core runs).

use crate::error::CmdResult;
use crate::state::{AppState, analyst, with_case, with_writable};
use sparrow_core::case::audit::AuditEntry;
use sparrow_core::case::device_status::{self, AnalystStatus};
use sparrow_core::case::devices::{self, SuspectDevice};
use tauri::State;

/// The suspect devices of `tenant` (all tenants when `None`), in core's order: status, confidence, last active.
pub fn devices_list(state: &AppState, tenant: Option<&str>) -> CmdResult<Vec<SuspectDevice>> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(devices::suspect_devices(open.case.conn(), tenant)?)
    })
}

/// Set (`Some`, one of `removed`, `disabled`, `confirmed_attacker`, `benign`) or clear (`None`) the analyst's status
/// of a device, with an optional note: one audit row.
pub fn devices_set_analyst_status(
    state: &AppState,
    device_id: &str,
    status: Option<&str>,
    note: Option<&str>,
) -> CmdResult<AuditEntry> {
    let status = status.map(AnalystStatus::parse).transpose()?;
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        Ok(device_status::set_status(
            open.case.conn(),
            &actor,
            device_id,
            status,
            note,
        )?)
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

    #[tauri::command(async)]
    pub fn devices_set_analyst_status(
        state: State<'_, AppState>,
        device_id: String,
        status: Option<String>,
        note: Option<String>,
    ) -> CmdResult<AuditEntry> {
        super::devices_set_analyst_status(&state, &device_id, status.as_deref(), note.as_deref())
    }
}
