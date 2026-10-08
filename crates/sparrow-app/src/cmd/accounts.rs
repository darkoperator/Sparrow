//! The accounts screen's command: the account roll-up, the analyst's starting point.

use crate::error::CmdResult;
use crate::state::{AppState, with_case};
use sparrow_core::case::read::{self, AccountPage};
use tauri::State;

/// The roll-up of `tenant` (all tenants when `None`). A roll-up that is not current comes back empty with a warning
/// saying why (core's rule): the screen shows the warning, never a silently empty table.
pub fn accounts_list(state: &AppState, tenant: Option<&str>) -> CmdResult<AccountPage> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(read::accounts(open.case.conn(), tenant, None)?)
    })
}

pub mod commands {
    use super::*;

    #[tauri::command(async)]
    pub fn accounts_list(
        state: State<'_, AppState>,
        tenant: Option<String>,
    ) -> CmdResult<AccountPage> {
        super::accounts_list(&state, tenant.as_deref())
    }
}
