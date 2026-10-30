//! The access report (`case::access`): the Access section of an account tab and the access exports of the export menu.
//! They only read the case, so they work on a read-only one; the exports are written atomically like the others.

use super::export::{atomic, to_file};
use crate::error::CmdResult;
use crate::state::{AppState, with_case};
use sparrow_core::case::access::{self, AccessReport};
use sparrow_core::export::access::{write_csv, write_summary};
use std::path::Path;
use tauri::State;

/// The report of `account` (any case), or of every account with accepted malicious activity.
pub fn access_report(state: &AppState, account: Option<&str>) -> CmdResult<AccessReport> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(access::report(open.case.conn(), account)?)
    })
}

/// The accounts the report lists (for the account list's badge).
pub fn access_accounts(state: &AppState) -> CmdResult<Vec<String>> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(access::flagged_accounts(open.case.conn())?)
    })
}

/// The access CSV of every account, or of `account` alone.
pub fn export_access_csv(state: &AppState, path: &Path, account: Option<&str>) -> CmdResult<()> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        let report = access::report(open.case.conn(), account)?;
        atomic(open, path, |tmp| {
            to_file(tmp, |w| Ok(write_csv(&report, w)?))
        })
    })
}

/// The Markdown summary of every account.
pub fn export_access_summary(state: &AppState, path: &Path) -> CmdResult<()> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        let report = access::report(open.case.conn(), None)?;
        atomic(open, path, |tmp| {
            to_file(tmp, |w| Ok(write_summary(&report, w)?))
        })
    })
}

pub mod commands {
    use super::*;

    #[tauri::command(async)]
    pub fn access_report(
        state: State<'_, AppState>,
        account: Option<String>,
    ) -> CmdResult<AccessReport> {
        super::access_report(&state, account.as_deref())
    }

    #[tauri::command(async)]
    pub fn access_accounts(state: State<'_, AppState>) -> CmdResult<Vec<String>> {
        super::access_accounts(&state)
    }

    #[tauri::command(async)]
    pub fn export_access_csv(
        state: State<'_, AppState>,
        path: String,
        account: Option<String>,
    ) -> CmdResult<()> {
        super::export_access_csv(&state, Path::new(&path), account.as_deref())
    }

    #[tauri::command(async)]
    pub fn export_access_summary(state: State<'_, AppState>, path: String) -> CmdResult<()> {
        super::export_access_summary(&state, Path::new(&path))
    }
}
