//! The table browser's commands: the browsable tables and server-side pages with typed filters. A page can be
//! cancelled with `query_cancel`.

use crate::error::CmdResult;
use crate::state::{AppState, with_cancellable, with_case};
use sparrow_core::case::browse::{self, BrowsePage, Filter, Sort};

pub fn browse_tables(state: &AppState) -> CmdResult<Vec<String>> {
    with_case(state, |open| Ok(browse::tables(open.case.conn())?))
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
    with_cancellable(state, query_id, |open| {
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
}
