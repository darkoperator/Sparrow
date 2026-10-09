//! The table browser's commands: the browsable tables and server-side pages with typed filters. A page can be
//! cancelled with `query_cancel`.

use crate::error::CmdResult;
use crate::state::{AppState, with_cancellable, with_case};
use sparrow_core::case::browse::{self, BrowsePage, Filter, Sort};

pub fn browse_tables(state: &AppState) -> CmdResult<Vec<String>> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| Ok(browse::tables(open.case.conn())?))
}

/// One page of `table`. Core allow-lists the table, validates every column and binds every value; a cancelled
/// page is `interrupted` and the case stays usable.
pub fn browse_page(
    state: &AppState,
    table: &str,
    filters: &[Filter],
    sort: Option<&Sort>,
    offset: usize,
    limit: usize,
    query_id: &str,
) -> CmdResult<BrowsePage> {
    let ticket = state.ticket();
    with_cancellable(state, ticket, query_id, |open| {
        Ok(browse::page(
            open.case.conn(),
            table,
            filters,
            sort,
            offset,
            limit,
        )?)
    })
}

/// Where an evidence reference opens in the table browser: the table and the filters that select exactly its record.
/// The key column differs per table, so core decides it; an unknown table is `invalid`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EvidenceTarget {
    pub table: String,
    pub filters: Vec<Filter>,
}

pub fn evidence_filter(state: &AppState, table: &str, key: &str) -> CmdResult<EvidenceTarget> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(EvidenceTarget {
            table: table.to_string(),
            filters: browse::evidence_filter(open.case.conn(), table, key)?,
        })
    })
}

pub mod commands {
    use super::*;
    use tauri::State;

    #[tauri::command(async)]
    pub fn browse_tables(state: State<'_, AppState>) -> CmdResult<Vec<String>> {
        super::browse_tables(&state)
    }

    #[tauri::command(async)]
    pub fn browse_page(
        state: State<'_, AppState>,
        table: String,
        filters: Vec<Filter>,
        sort: Option<Sort>,
        offset: usize,
        limit: usize,
        query_id: String,
    ) -> CmdResult<BrowsePage> {
        super::browse_page(
            &state,
            &table,
            &filters,
            sort.as_ref(),
            offset,
            limit,
            &query_id,
        )
    }

    #[tauri::command(async)]
    pub fn evidence_filter(
        state: State<'_, AppState>,
        table: String,
        key: String,
    ) -> CmdResult<EvidenceTarget> {
        super::evidence_filter(&state, &table, &key)
    }
}
