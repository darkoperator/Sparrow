//! The SQL screen's commands: the case's schema, one read-only SELECT (a page of it) on the app's own locked-down
//! connection, a check that marks the wrong part of a query without running it, and a CSV export of the whole result;
//! the run and the export are cancellable with `query_cancel`.

use crate::cmd::export::{atomic_then, to_file};
use crate::error::{CmdError, CmdResult};
use crate::state::{self, AppState, with_cancellable, with_cancellable_commit, with_case};
use sparrow_core::case::query::{self, Check, Exported, QueryResult};
use sparrow_core::db::TableInfo;
use std::path::Path;

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
    sql_run_page(state, sql, limit, query_id, None)
}

/// [`sql_run`] from row `offset` (default 0, at most `query::MAX_OFFSET`): the "next 1000" of the SQL screen. Pages
/// are slices of one order only when the result says `ordered`.
pub fn sql_run_page(
    state: &AppState,
    sql: &str,
    limit: Option<usize>,
    query_id: &str,
    offset: Option<usize>,
) -> CmdResult<QueryResult> {
    let ticket = state.ticket();
    check_size(sql)?;
    let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = offset.unwrap_or(0);
    with_cancellable(state, ticket, query_id, |open| {
        Ok(query::run_on(&open.case, sql, limit, offset)?)
    })
}

fn check_size(sql: &str) -> CmdResult<()> {
    if sql.len() > MAX_SQL_BYTES {
        return Err(CmdError::new(
            "invalid",
            format!("a query is limited to {MAX_SQL_BYTES} bytes"),
        ));
    }
    Ok(())
}

/// Check one SELECT without running it (core `check_on`): `ok`, or the error with UTF-16 offsets into `sql` and
/// DuckDB's suggestions. Not cancellable (binding is fast).
pub fn sql_check(state: &AppState, sql: &str) -> CmdResult<Check> {
    let ticket = state.ticket();
    check_size(sql)?;
    with_case(state, ticket, |open| Ok(query::check_on(&open.case, sql)?))
}

/// The whole result of one SELECT as CSV at `path`, at most `query::EXPORT_CAP` rows (`capped` when more existed);
/// cancellable like [`sql_run`]. Written through the export menu's private work folder and renamed into place only
/// when complete and not cancelled, so a failed or cancelled export leaves no file; the case and its WAL are refused.
pub fn sql_export_csv(
    state: &AppState,
    sql: &str,
    path: &Path,
    query_id: &str,
) -> CmdResult<Exported> {
    sql_export_csv_capped(state, sql, path, query_id, query::EXPORT_CAP)
}

/// [`sql_export_csv`] with another row cap (tests).
#[doc(hidden)]
pub fn sql_export_csv_capped(
    state: &AppState,
    sql: &str,
    path: &Path,
    query_id: &str,
    cap: u64,
) -> CmdResult<Exported> {
    let ticket = state.ticket();
    check_size(sql)?;
    with_cancellable_commit(state, ticket, query_id, |open, commit| {
        let mut exported = None;
        atomic_then(
            open,
            path,
            |tmp| {
                to_file(tmp, |w| {
                    exported = Some(query::export_csv_on(&open.case, sql, w, cap)?);
                    Ok(())
                })
            },
            |finish| commit.commit(finish),
        )?;
        exported.ok_or_else(|| CmdError::new("internal", "the export wrote nothing"))
    })
}

/// Interrupt the running `sql_run` / `sql_export_csv` / `browse_page` whose `query_id` this is; a no-op for any other id.
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
        offset: Option<usize>,
    ) -> CmdResult<QueryResult> {
        super::sql_run_page(&state, &sql, limit, &query_id, offset)
    }

    #[tauri::command(async)]
    pub fn sql_check(state: State<'_, AppState>, sql: String) -> CmdResult<Check> {
        super::sql_check(&state, &sql)
    }

    #[tauri::command(async)]
    pub fn sql_export_csv(
        state: State<'_, AppState>,
        sql: String,
        path: String,
        query_id: String,
    ) -> CmdResult<Exported> {
        super::sql_export_csv(&state, &sql, Path::new(&path), &query_id)
    }

    #[tauri::command(async)]
    pub fn query_cancel(state: State<'_, AppState>, query_id: String) -> CmdResult<()> {
        super::query_cancel(&state, &query_id)
    }
}
