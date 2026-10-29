//! The Events grid's commands: one page, the summary bar, the histogram, one row's detail, filter suggestions and the
//! CSV of everything a query matches. They only read the case. A raw-text `search` scans every record and can take
//! seconds, so a query with one runs through the cancellable path and needs a `query_id` (`query_cancel` stops it).
//! Times cross the IPC as RFC 3339 text; the core types have no serde for them on the way in.

use crate::cmd::export::{atomic, atomic_then};
use crate::error::{CmdError, CmdResult};
use crate::state::{AppState, OpenCase, with_cancellable, with_cancellable_commit, with_case};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sparrow_core::case::browse::Sort;
use sparrow_core::case::events::{
    self, AiFilter, Entity, EventDetail, EventQuery, EventsPage, EventsSummary, Field, FieldValues,
    FlagFilter, Histogram, HistogramGroup,
};
use std::path::Path;

/// The most buckets a histogram call may ask for (the chart is a few hundred pixels wide); more is clamped to this.
pub const MAX_BUCKETS: usize = 500;

/// Suggestions per call (core's own cap).
pub const SUGGEST_LIMIT: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Account,
    Ip,
    Device,
    Session,
}

/// The entity of a tab, as the UI holds it: `{ kind, value }`. The value may be in any spelling; core normalizes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityArg {
    pub kind: EntityKind,
    pub value: String,
}

impl EntityArg {
    /// A core entity as the UI holds it: `{ kind, value }`, the value in its stored spelling.
    pub fn from_entity(e: &Entity) -> EntityArg {
        let (kind, value) = match e {
            Entity::Account(v) => (EntityKind::Account, v),
            Entity::Ip(v) => (EntityKind::Ip, v),
            Entity::Device(v) => (EntityKind::Device, v),
            Entity::Session(v) => (EntityKind::Session, v),
        };
        EntityArg {
            kind,
            value: value.clone(),
        }
    }

    pub fn entity(&self) -> Entity {
        let v = self.value.clone();
        match self.kind {
            EntityKind::Account => Entity::Account(v),
            EntityKind::Ip => Entity::Ip(v),
            EntityKind::Device => Entity::Device(v),
            EntityKind::Session => Entity::Session(v),
        }
    }
}

/// `{ entity?, fields: [[field, text], ...], search?, from?, to?, flag, ai }`; an absent field is no filter.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EventQueryArgs {
    pub entity: Option<EntityArg>,
    pub fields: Vec<(Field, String)>,
    pub search: Option<String>,
    /// RFC 3339, inclusive.
    pub from: Option<String>,
    /// RFC 3339, inclusive.
    pub to: Option<String>,
    pub flag: FlagFilter,
    pub ai: AiFilter,
}

/// RFC 3339 text to a UTC time.
pub fn parse_time(s: &str) -> CmdResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| {
            CmdError::new(
                "invalid",
                format!("{s:?} is not an RFC 3339 time (for example 2026-03-01T10:00:00Z)"),
            )
        })
}

/// An optional inclusive range.
pub type Range = (Option<DateTime<Utc>>, Option<DateTime<Utc>>);

pub fn parse_range(from: Option<&str>, to: Option<&str>) -> CmdResult<Range> {
    Ok((
        from.map(parse_time).transpose()?,
        to.map(parse_time).transpose()?,
    ))
}

impl EventQueryArgs {
    pub fn to_query(&self) -> CmdResult<EventQuery> {
        let (from, to) = parse_range(self.from.as_deref(), self.to.as_deref())?;
        Ok(EventQuery {
            entity: self.entity.as_ref().map(EntityArg::entity),
            fields: self.fields.clone(),
            search: self.search.clone(),
            from,
            to,
            flag: self.flag,
            ai: self.ai,
        })
    }
}

/// Run `f` as a plain read, or, when `q` has a raw `search`, as the cancellable query `query_id` names. A search with
/// no id is refused: the UI could not cancel it.
fn read<T>(
    state: &AppState,
    q: &EventQuery,
    query_id: Option<&str>,
    f: impl FnOnce(&OpenCase) -> CmdResult<T>,
) -> CmdResult<T> {
    let ticket = state.ticket();
    match (&q.search, query_id) {
        (Some(_), Some(id)) => with_cancellable(state, ticket, id, f),
        (Some(_), None) => Err(no_query_id()),
        (None, _) => with_case(state, ticket, f),
    }
}

fn no_query_id() -> CmdError {
    CmdError::new(
        "invalid",
        "a raw-text search needs a query id so that it can be cancelled",
    )
}

/// One page of the events the query matches (default order: newest first).
pub fn events_page(
    state: &AppState,
    query: &EventQueryArgs,
    sort: Option<&Sort>,
    offset: usize,
    limit: usize,
    query_id: Option<&str>,
) -> CmdResult<EventsPage> {
    let q = query.to_query()?;
    read(state, &q, query_id, |open| {
        Ok(events::page(open.case.conn(), &q, sort, offset, limit)?)
    })
}

pub fn events_summary(
    state: &AppState,
    query: &EventQueryArgs,
    query_id: Option<&str>,
) -> CmdResult<EventsSummary> {
    let q = query.to_query()?;
    read(state, &q, query_id, |open| {
        Ok(events::summary(open.case.conn(), &q)?)
    })
}

/// The histogram of the query in at most `max_buckets` buckets, stacked by `group`: 0 is refused, and more than
/// [`MAX_BUCKETS`] is clamped to it (core also never returns more than its own hard cap, whatever the range).
pub fn events_histogram(
    state: &AppState,
    query: &EventQueryArgs,
    max_buckets: usize,
    group: HistogramGroup,
    query_id: Option<&str>,
) -> CmdResult<Histogram> {
    if max_buckets == 0 {
        return Err(CmdError::new(
            "invalid",
            "a histogram needs at least 1 bucket",
        ));
    }
    let max_buckets = max_buckets.min(MAX_BUCKETS);
    let q = query.to_query()?;
    read(state, &q, query_id, |open| {
        Ok(events::histogram_by(
            open.case.conn(),
            &q,
            max_buckets,
            group,
        )?)
    })
}

pub fn events_detail(
    state: &AppState,
    source_table: &str,
    record_key: &str,
) -> CmdResult<EventDetail> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(events::detail(open.case.conn(), source_table, record_key)?)
    })
}

pub fn events_suggest(state: &AppState, field: Field, prefix: &str) -> CmdResult<Vec<String>> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(events::suggest(
            open.case.conn(),
            field,
            prefix,
            SUGGEST_LIMIT,
        )?)
    })
}

/// The values of `field` with their event counts among the events the query matches, the field's own filter left out
/// (the column filter's list): most events first, at most `limit` (core caps it at 200), `prefix` a case-insensitive
/// start (`*` wildcard). A `limit` of 0 is refused. Cancellable like [`events_page`] when the query has a `search`.
pub fn events_values(
    state: &AppState,
    query: &EventQueryArgs,
    field: Field,
    prefix: &str,
    limit: usize,
    query_id: Option<&str>,
) -> CmdResult<FieldValues> {
    if limit < 1 {
        return Err(CmdError::new(
            "invalid",
            "a values list needs a limit of at least 1",
        ));
    }
    let q = query.to_query()?;
    read(state, &q, query_id, |open| {
        Ok(events::values(open.case.conn(), &q, field, prefix, limit)?)
    })
}

/// Every event the query matches, newest first, as CSV at `path`; returns the rows written. Written through the export
/// menu's private work folder and renamed into place when complete, so a failed or cancelled export leaves no file; the
/// open case and its WAL are refused. With a `search`, cancellable like [`events_page`].
pub fn events_export_csv(
    state: &AppState,
    query: &EventQueryArgs,
    path: &Path,
    query_id: Option<&str>,
) -> CmdResult<u64> {
    let q = query.to_query()?;
    let ticket = state.ticket();
    match (&q.search, query_id) {
        (None, None) => with_case(state, ticket, |open| {
            let mut rows = 0;
            atomic(open, path, |tmp| {
                rows = events::export_csv(open.case.conn(), &q, tmp)?;
                Ok(())
            })?;
            Ok(rows)
        }),
        (Some(_), None) => Err(no_query_id()),
        (_, Some(id)) => with_cancellable_commit(state, ticket, id, |open, commit| {
            let mut rows = 0;
            atomic_then(
                open,
                path,
                |tmp| {
                    rows = events::export_csv(open.case.conn(), &q, tmp)?;
                    Ok(())
                },
                |finish| commit.commit(finish),
            )?;
            Ok(rows)
        }),
    }
}

pub mod commands {
    use super::*;
    use tauri::State;

    #[tauri::command(async)]
    pub fn events_page(
        state: State<'_, AppState>,
        query: EventQueryArgs,
        sort: Option<Sort>,
        offset: usize,
        limit: usize,
        query_id: Option<String>,
    ) -> CmdResult<EventsPage> {
        super::events_page(
            &state,
            &query,
            sort.as_ref(),
            offset,
            limit,
            query_id.as_deref(),
        )
    }

    #[tauri::command(async)]
    pub fn events_summary(
        state: State<'_, AppState>,
        query: EventQueryArgs,
        query_id: Option<String>,
    ) -> CmdResult<EventsSummary> {
        super::events_summary(&state, &query, query_id.as_deref())
    }

    #[tauri::command(async)]
    pub fn events_histogram(
        state: State<'_, AppState>,
        query: EventQueryArgs,
        max_buckets: usize,
        group: HistogramGroup,
        query_id: Option<String>,
    ) -> CmdResult<Histogram> {
        super::events_histogram(&state, &query, max_buckets, group, query_id.as_deref())
    }

    #[tauri::command(async)]
    pub fn events_detail(
        state: State<'_, AppState>,
        source_table: String,
        record_key: String,
    ) -> CmdResult<EventDetail> {
        super::events_detail(&state, &source_table, &record_key)
    }

    #[tauri::command(async)]
    pub fn events_suggest(
        state: State<'_, AppState>,
        field: Field,
        prefix: String,
    ) -> CmdResult<Vec<String>> {
        super::events_suggest(&state, field, &prefix)
    }

    #[tauri::command(async)]
    pub fn events_values(
        state: State<'_, AppState>,
        query: EventQueryArgs,
        field: Field,
        prefix: String,
        limit: usize,
        query_id: Option<String>,
    ) -> CmdResult<FieldValues> {
        super::events_values(&state, &query, field, &prefix, limit, query_id.as_deref())
    }

    #[tauri::command(async)]
    pub fn events_export_csv(
        state: State<'_, AppState>,
        query: EventQueryArgs,
        path: String,
        query_id: Option<String>,
    ) -> CmdResult<u64> {
        super::events_export_csv(&state, &query, Path::new(&path), query_id.as_deref())
    }
}
