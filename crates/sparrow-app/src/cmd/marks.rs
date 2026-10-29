//! The marking commands of the Events grid: flag or tag event rows, flag a value for the whole case or one entity, add
//! notes, and confirm or remove an agent's marks. Every one is the analyst's own decision, so a read-only case refuses it
//! before core runs and writes no audit row; each call appends one audit row per action, never one per event.

use crate::cmd::events::EntityArg;
use crate::error::{CmdError, CmdResult};
use crate::state::{AppState, analyst, with_case, with_writable};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sparrow_core::case::audit::AuditEntry;
use sparrow_core::case::marks::{self, FlagLevel, IndicatorChange, RowRef, TagInfo, ValueKind};
use sparrow_core::case::notes::{self, NoteTarget};
use std::collections::BTreeSet;

/// Rows one `notes_add_rows` call writes a note on (it writes one note and one audit row for each).
pub const MAX_NOTE_ROWS: usize = 200;
/// Event rows per statement when looking rows up.
const CHUNK: usize = 400;

/// An event row as the timeline commands need it.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedRow {
    pub row: RowRef,
    pub event_time: Option<DateTime<Utc>>,
    pub category: String,
    pub operation: Option<String>,
    pub summary: Option<String>,
    pub tenant_key: Option<String>,
}

/// The distinct `rows`, each looked up in `events`; refused when empty or when one is not an event of the case.
pub(crate) fn resolve_rows(
    conn: &duckdb::Connection,
    rows: &[RowRef],
) -> CmdResult<Vec<ResolvedRow>> {
    let set: BTreeSet<&RowRef> = rows.iter().collect();
    if set.is_empty() {
        return Err(CmdError::new("invalid", "no event rows given"));
    }
    let rows: Vec<&RowRef> = set.into_iter().collect();
    let mut out = Vec::with_capacity(rows.len());
    for chunk in rows.chunks(CHUNK) {
        let values = vec!["(CAST(? AS VARCHAR), CAST(? AS VARCHAR))"; chunk.len()].join(", ");
        let params: Vec<duckdb::types::Value> = chunk
            .iter()
            .flat_map(|r| {
                [
                    duckdb::types::Value::Text(r.source_table.clone()),
                    duckdb::types::Value::Text(r.record_key.clone()),
                ]
            })
            .collect();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT e.source_table, e.record_key, epoch_us(e.event_time), CAST(e.category AS VARCHAR), \
                        e.operation, e.summary, e.tenant_key \
                 FROM events e JOIN (VALUES {values}) v(t, k) ON e.source_table = v.t AND e.record_key = v.k \
                 ORDER BY e.source_table, e.record_key"
            ))
            .map_err(sparrow_core::Error::from)?;
        let mut found = stmt
            .query(duckdb::params_from_iter(params.iter()))
            .map_err(sparrow_core::Error::from)?;
        let mut got = Vec::new();
        while let Some(r) = found.next().map_err(sparrow_core::Error::from)? {
            let g = |e: duckdb::Error| CmdError::from(sparrow_core::Error::from(e));
            got.push(ResolvedRow {
                row: RowRef::new(
                    &r.get::<_, String>(0).map_err(g)?,
                    &r.get::<_, String>(1).map_err(g)?,
                ),
                event_time: r
                    .get::<_, Option<i64>>(2)
                    .map_err(g)?
                    .and_then(DateTime::from_timestamp_micros),
                category: r.get(3).map_err(g)?,
                operation: r.get(4).map_err(g)?,
                summary: r.get(5).map_err(g)?,
                tenant_key: r.get(6).map_err(g)?,
            });
        }
        if got.len() != chunk.len() {
            let known: BTreeSet<&RowRef> = got.iter().map(|g| &g.row).collect();
            let missing = chunk.iter().find(|r| !known.contains(**r));
            return Err(CmdError::new(
                "decision",
                match missing {
                    Some(m) => format!("unknown event {}:{}", m.source_table, m.record_key),
                    None => "unknown event".to_string(),
                },
            ));
        }
        out.extend(got);
    }
    Ok(out)
}

/// Set (`Some`) or clear (`None`) the flag of event rows: one audit row.
pub fn marks_flag_rows(
    state: &AppState,
    rows: &[RowRef],
    level: Option<FlagLevel>,
) -> CmdResult<AuditEntry> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        Ok(marks::flag_rows(open.case.conn(), &actor, rows, level)?)
    })
}

/// What `marks_flag_value` did: the audit row of the flag, and the indicators a Malicious flag on an IP or account added
/// or updated (empty when it made none).
#[derive(Debug, Clone, Serialize)]
pub struct ValueFlagged {
    pub audit: AuditEntry,
    pub indicators: Vec<IndicatorChange>,
}

/// Set or clear a standing flag on a value (every event with it, including ones ingested later), case-wide or limited
/// to one entity. Malicious on an IP or an account also records an indicator.
pub fn marks_flag_value(
    state: &AppState,
    kind: ValueKind,
    value: &str,
    scope: Option<&EntityArg>,
    level: Option<FlagLevel>,
) -> CmdResult<ValueFlagged> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        let scope = scope.map(EntityArg::entity);
        let (audit, indicators) = marks::flag_value_with_indicators(
            open.case.conn(),
            &actor,
            kind,
            value,
            scope.as_ref(),
            level,
        )?;
        Ok(ValueFlagged { audit, indicators })
    })
}

/// Add (`add`) or remove a tag on event rows: one audit row.
pub fn marks_tag_rows(
    state: &AppState,
    rows: &[RowRef],
    tag: &str,
    add: bool,
) -> CmdResult<AuditEntry> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        Ok(marks::tag_rows(open.case.conn(), &actor, rows, tag, add)?)
    })
}

/// Every tag in use with its row count and its agent tags awaiting review.
pub fn marks_list_tags(state: &AppState) -> CmdResult<Vec<TagInfo>> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(marks::list_tags(open.case.conn())?)
    })
}

/// Confirm (`accept`) or remove the agent marks pending on `rows`, as the reviewing analyst. This also reviews every
/// pending standing value flag that covers any of the rows (the UI warns). Returns the audit rows, none when nothing
/// was pending.
pub fn marks_review(state: &AppState, rows: &[RowRef], accept: bool) -> CmdResult<Vec<AuditEntry>> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let who = analyst(state)?;
        Ok(marks::review_marks(open.case.conn(), &who, rows, accept)?)
    })
}

/// One note with `text` on each of the distinct `rows` (at most [`MAX_NOTE_ROWS`]), through `notes::add_note`; returns
/// the audit rows in row order. The rows and the text are checked first, so a bad row adds none.
pub fn notes_add_rows(state: &AppState, rows: &[RowRef], text: &str) -> CmdResult<Vec<AuditEntry>> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        if text.trim().is_empty() {
            return Err(CmdError::new("decision", "a note must not be empty"));
        }
        let distinct = rows.iter().collect::<BTreeSet<_>>().len();
        if distinct > MAX_NOTE_ROWS {
            return Err(CmdError::new(
                "invalid",
                format!(
                    "{distinct} event rows in one call; a note is written on at most {MAX_NOTE_ROWS}"
                ),
            ));
        }
        let resolved = resolve_rows(open.case.conn(), rows)?;
        let mut out = Vec::with_capacity(resolved.len());
        for r in &resolved {
            let target = NoteTarget::Evidence {
                table: r.row.source_table.clone(),
                key: r.row.record_key.clone(),
            };
            let (_, audit) = notes::add_note(open.case.conn(), &actor, target, text)?;
            out.push(audit);
        }
        Ok(out)
    })
}

pub mod commands {
    use super::*;
    use tauri::State;

    #[tauri::command(async)]
    pub fn marks_flag_rows(
        state: State<'_, AppState>,
        rows: Vec<RowRef>,
        level: Option<FlagLevel>,
    ) -> CmdResult<AuditEntry> {
        super::marks_flag_rows(&state, &rows, level)
    }

    #[tauri::command(async)]
    pub fn marks_flag_value(
        state: State<'_, AppState>,
        kind: ValueKind,
        value: String,
        scope: Option<EntityArg>,
        level: Option<FlagLevel>,
    ) -> CmdResult<ValueFlagged> {
        super::marks_flag_value(&state, kind, &value, scope.as_ref(), level)
    }

    #[tauri::command(async)]
    pub fn marks_tag_rows(
        state: State<'_, AppState>,
        rows: Vec<RowRef>,
        tag: String,
        add: bool,
    ) -> CmdResult<AuditEntry> {
        super::marks_tag_rows(&state, &rows, &tag, add)
    }

    #[tauri::command(async)]
    pub fn marks_list_tags(state: State<'_, AppState>) -> CmdResult<Vec<TagInfo>> {
        super::marks_list_tags(&state)
    }

    #[tauri::command(async)]
    pub fn marks_review(
        state: State<'_, AppState>,
        rows: Vec<RowRef>,
        accept: bool,
    ) -> CmdResult<Vec<AuditEntry>> {
        super::marks_review(&state, &rows, accept)
    }

    #[tauri::command(async)]
    pub fn notes_add_rows(
        state: State<'_, AppState>,
        rows: Vec<RowRef>,
        text: String,
    ) -> CmdResult<Vec<AuditEntry>> {
        super::notes_add_rows(&state, &rows, &text)
    }
}
