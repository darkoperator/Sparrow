//! The SQL screen's commands: the case's schema and one read-only SELECT on the app's own locked-down connection,
//! cancellable with `query_cancel`.

use crate::error::{CmdError, CmdResult};
use crate::state::{self, AppState, with_cancellable, with_case};
use sparrow_core::case::query::{self, QueryResult};
use sparrow_core::db::TableInfo;

pub const DEFAULT_LIMIT: usize = 1000;
pub const MAX_LIMIT: usize = 10_000;
/// The longest statement accepted (the parser would take more; an analyst never types it).
pub const MAX_SQL_BYTES: usize = 1024 * 1024;

pub fn sql_schema(state: &AppState, table: Option<&str>) -> CmdResult<Vec<TableInfo>> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(query::schema_on(&open.case, table)?)
    })
}

/// One SELECT, at most `limit` rows (default 1000, clamped to 1..=10000). Core refuses anything but one SELECT; an
/// interrupted query is `interrupted` and the case stays usable.
pub fn sql_run(
    state: &AppState,
    sql: &str,
    limit: Option<usize>,
    query_id: &str,
) -> CmdResult<QueryResult> {
    let ticket = state.ticket();
    if sql.len() > MAX_SQL_BYTES {
        return Err(CmdError::new(
            "invalid",
            format!("a query is limited to {MAX_SQL_BYTES} bytes"),
        ));
    }
    let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    with_cancellable(state, ticket, query_id, |open| {
        Ok(query::run_on(&open.case, sql, limit)?)
    })
}

/// Interrupt the running `sql_run` / `browse_page` whose `query_id` this is; a no-op for any other id.
pub fn query_cancel(state: &AppState, query_id: &str) -> CmdResult<()> {
    state::query_cancel(state, query_id)
}

pub mod commands {
    use super::*;
    use tauri::State;

    #[tauri::command(async)]
    pub fn sql_schema(
        state: State<'_, AppState>,
        table: Option<String>,
    ) -> CmdResult<Vec<TableInfo>> {
        super::sql_schema(&state, table.as_deref())
    }

    #[tauri::command(async)]
    pub fn sql_run(
        state: State<'_, AppState>,
        sql: String,
        limit: Option<usize>,
        query_id: String,
    ) -> CmdResult<QueryResult> {
        super::sql_run(&state, &sql, limit, &query_id)
    }

    #[tauri::command(async)]
    pub fn query_cancel(state: State<'_, AppState>, query_id: String) -> CmdResult<()> {
        super::query_cancel(&state, &query_id)
    }
}
