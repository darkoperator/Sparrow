//! The SQL screen's notebooks: the built-in one and the case's, saved queries loaded into the editor, and notebook
//! files for sharing. Every write is the analyst's own (a read-only case refuses it); agents write through the CLI.

use crate::cmd::export::atomic;
use crate::error::{CmdError, CmdResult};
use crate::state::{AppState, analyst, with_case, with_writable};
use sparrow_core::case::notebooks::{
    self, CaseValueHit, NotebookSummary, SavedQuery, store::MAX_IMPORT_BYTES,
};
use std::io::Read;
use std::path::Path;

pub fn notebook_list(state: &AppState) -> CmdResult<Vec<NotebookSummary>> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| Ok(notebooks::list(open.case.conn())?))
}

/// One query: `notebook` an id or a name, `query` an id or a 1-based position.
pub fn notebook_query(state: &AppState, notebook: &str, query: &str) -> CmdResult<SavedQuery> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(notebooks::find_query(open.case.conn(), notebook, query)?)
    })
}

pub fn notebook_create(state: &AppState, name: &str) -> CmdResult<String> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        Ok(notebooks::create_notebook(open.case.conn(), &actor, name)?.0)
    })
}

pub fn notebook_add_query(state: &AppState, notebook_id: &str, sql: &str) -> CmdResult<String> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        Ok(notebooks::add_query(open.case.conn(), &actor, notebook_id, sql)?.0)
    })
}

pub fn notebook_rename(state: &AppState, notebook_id: &str, name: &str) -> CmdResult<()> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        notebooks::rename_notebook(open.case.conn(), &actor, notebook_id, name)?;
        Ok(())
    })
}

pub fn notebook_delete(state: &AppState, notebook_id: &str) -> CmdResult<()> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        notebooks::delete_notebook(open.case.conn(), &actor, notebook_id)?;
        Ok(())
    })
}

pub fn notebook_delete_query(state: &AppState, query_id: &str) -> CmdResult<()> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        notebooks::delete_query(open.case.conn(), &actor, query_id)?;
        Ok(())
    })
}

/// Move a query to `position` (1-based, clamped).
pub fn notebook_move_query(state: &AppState, query_id: &str, position: u32) -> CmdResult<()> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        notebooks::move_query(open.case.conn(), &actor, query_id, position)?;
        Ok(())
    })
}

/// The case values in a notebook's queries: what the export warns about.
pub fn notebook_case_values(state: &AppState, notebook_id: &str) -> CmdResult<Vec<CaseValueHit>> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        let conn = open.case.conn();
        let (_, _, qs) = notebooks::notebook_queries(conn, notebook_id)?;
        let pairs: Vec<(String, String)> = qs
            .into_iter()
            .map(|q| (q.summary.query_id, q.sql))
            .collect();
        Ok(notebooks::case_values_in(conn, &pairs)?)
    })
}

/// Write a notebook file at `path` (renamed into place when complete; the case and its WAL are refused).
pub fn notebook_export(state: &AppState, notebook_id: &str, path: &Path) -> CmdResult<()> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        let text = notebooks::export_text(open.case.conn(), notebook_id, sparrow_core::VERSION)?;
        atomic(open, path, |tmp| {
            std::fs::write(tmp, &text)
                .map_err(|e| CmdError::new("io", format!("could not write {}: {e}", tmp.display())))
        })
    })
}

/// Import a notebook file as a new case notebook; its id.
pub fn notebook_import(state: &AppState, path: &Path) -> CmdResult<String> {
    let ticket = state.ticket();
    let text = read_capped(path)?;
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        Ok(notebooks::import_text(open.case.conn(), &actor, &text)?.0)
    })
}

/// The file at `path` as text, refused past [`MAX_IMPORT_BYTES`] without reading the rest.
fn read_capped(path: &Path) -> CmdResult<String> {
    let io =
        |e: std::io::Error| CmdError::new("io", format!("could not read {}: {e}", path.display()));
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(io)?
        .take(MAX_IMPORT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(CmdError::new(
            "invalid",
            "an import file is limited to 4 MiB",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| CmdError::new("invalid", "a notebook file must be UTF-8 text"))
}

pub mod commands {
    use super::*;
    use tauri::State;

    #[tauri::command(async)]
    pub fn notebook_list(state: State<'_, AppState>) -> CmdResult<Vec<NotebookSummary>> {
        super::notebook_list(&state)
    }

    #[tauri::command(async)]
    pub fn notebook_query(
        state: State<'_, AppState>,
        notebook: String,
        query: String,
    ) -> CmdResult<SavedQuery> {
        super::notebook_query(&state, &notebook, &query)
    }

    #[tauri::command(async)]
    pub fn notebook_create(state: State<'_, AppState>, name: String) -> CmdResult<String> {
        super::notebook_create(&state, &name)
    }

    #[tauri::command(async)]
    pub fn notebook_add_query(
        state: State<'_, AppState>,
        notebook_id: String,
        sql: String,
    ) -> CmdResult<String> {
        super::notebook_add_query(&state, &notebook_id, &sql)
    }

    #[tauri::command(async)]
    pub fn notebook_rename(
        state: State<'_, AppState>,
        notebook_id: String,
        name: String,
    ) -> CmdResult<()> {
        super::notebook_rename(&state, &notebook_id, &name)
    }

    #[tauri::command(async)]
    pub fn notebook_delete(state: State<'_, AppState>, notebook_id: String) -> CmdResult<()> {
        super::notebook_delete(&state, &notebook_id)
    }

    #[tauri::command(async)]
    pub fn notebook_delete_query(state: State<'_, AppState>, query_id: String) -> CmdResult<()> {
        super::notebook_delete_query(&state, &query_id)
    }

    #[tauri::command(async)]
    pub fn notebook_move_query(
        state: State<'_, AppState>,
        query_id: String,
        position: u32,
    ) -> CmdResult<()> {
        super::notebook_move_query(&state, &query_id, position)
    }

    #[tauri::command(async)]
    pub fn notebook_case_values(
        state: State<'_, AppState>,
        notebook_id: String,
    ) -> CmdResult<Vec<CaseValueHit>> {
        super::notebook_case_values(&state, &notebook_id)
    }

    #[tauri::command(async)]
    pub fn notebook_export(
        state: State<'_, AppState>,
        notebook_id: String,
        path: String,
    ) -> CmdResult<()> {
        super::notebook_export(&state, &notebook_id, Path::new(&path))
    }

    #[tauri::command(async)]
    pub fn notebook_import(state: State<'_, AppState>, path: String) -> CmdResult<String> {
        super::notebook_import(&state, Path::new(&path))
    }
}
