//! The access report (`case::access`): the Access tabs, the account tab's summary line and the access exports of the
//! export menu.
//! They only read the case, so they work on a read-only one; the exports are written atomically like the others.
//! The Access section can preview the report with pending agent flags or a what-if value ([`PreviewArgs`]); the export
//! menu's exports never do.

use super::export::{atomic, to_file};
use crate::error::{CmdError, CmdResult};
use crate::state::{AppState, with_case};
use serde::Deserialize;
use sparrow_core::case::access::{self, AccessReport, ScopeSource, Tile};
use sparrow_core::case::marks::ValueKind;
use sparrow_core::export::access::{write_csv, write_summary};
use std::path::Path;
use tauri::State;

/// An Access tab's preview: pending agent flags too, and what-if values (as if flagged malicious and accepted). With
/// `without_accepted`, the case's accepted flags are left out: a device or IP tab's what-if counts its value alone.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PreviewArgs {
    #[serde(default)]
    pub include_pending: bool,
    #[serde(default)]
    pub adhoc: Vec<AdhocArg>,
    #[serde(default)]
    pub without_accepted: bool,
}

/// One what-if value: `kind` is ip, ip_prefix, session or device.
#[derive(Debug, Clone, Deserialize)]
pub struct AdhocArg {
    pub kind: String,
    pub value: String,
}

impl PreviewArgs {
    /// The flags the report counts; a kind or value that is not one is `invalid`.
    fn source(&self) -> CmdResult<ScopeSource> {
        let mut adhoc = Vec::new();
        for a in &self.adhoc {
            let kind = ValueKind::parse(&a.kind)?;
            if !matches!(
                kind,
                ValueKind::Ip | ValueKind::IpPrefix | ValueKind::Session | ValueKind::Device
            ) {
                return Err(CmdError::new(
                    "invalid",
                    format!(
                        "a what-if value is an ip, ip_prefix, session or device, not {}",
                        a.kind
                    ),
                ));
            }
            kind.normalize(&a.value)?;
            adhoc.push((kind, a.value.clone()));
        }
        Ok(ScopeSource {
            include_pending: self.include_pending,
            adhoc,
            without_accepted: self.without_accepted,
            ..ScopeSource::accepted()
        })
    }
}

fn source(preview: Option<&PreviewArgs>) -> CmdResult<ScopeSource> {
    preview.map_or(Ok(ScopeSource::accepted()), PreviewArgs::source)
}

/// The report of `account` (any case), or of every account with accepted malicious activity; a preview with
/// `preview`.
pub fn access_report(
    state: &AppState,
    account: Option<&str>,
    preview: Option<&PreviewArgs>,
) -> CmdResult<AccessReport> {
    let ticket = state.ticket();
    let src = source(preview)?;
    with_case(state, ticket, |open| {
        Ok(access::report_with(open.case.conn(), account, &src)?)
    })
}

/// The reviewed report's seven tiles of `account` (any case), without its items: the account tab's one-line summary,
/// so a long attacker dwell does not ship thousands of rows just to be counted.
pub fn access_tiles(state: &AppState, account: &str) -> CmdResult<Vec<Tile>> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        let r = access::report(open.case.conn(), Some(account))?;
        Ok(r.accounts
            .into_iter()
            .next()
            .map(|a| a.tiles)
            .unwrap_or_default())
    })
}

/// The accounts the report lists (for the account list's badge).
pub fn access_accounts(state: &AppState) -> CmdResult<Vec<String>> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(access::flagged_accounts(open.case.conn())?)
    })
}

/// The access CSV of every account, or of `account` alone; the Access section's preview with `preview` (its `basis`
/// column says what each row rests on).
pub fn export_access_csv(
    state: &AppState,
    path: &Path,
    account: Option<&str>,
    preview: Option<&PreviewArgs>,
) -> CmdResult<()> {
    let ticket = state.ticket();
    let src = source(preview)?;
    with_case(state, ticket, |open| {
        let report = access::report_with(open.case.conn(), account, &src)?;
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
        preview: Option<PreviewArgs>,
    ) -> CmdResult<AccessReport> {
        super::access_report(&state, account.as_deref(), preview.as_ref())
    }

    #[tauri::command(async)]
    pub fn access_tiles(state: State<'_, AppState>, account: String) -> CmdResult<Vec<Tile>> {
        super::access_tiles(&state, &account)
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
        preview: Option<PreviewArgs>,
    ) -> CmdResult<()> {
        super::export_access_csv(
            &state,
            Path::new(&path),
            account.as_deref(),
            preview.as_ref(),
        )
    }

    #[tauri::command(async)]
    pub fn export_access_summary(state: State<'_, AppState>, path: String) -> CmdResult<()> {
        super::export_access_summary(&state, Path::new(&path))
    }
}
