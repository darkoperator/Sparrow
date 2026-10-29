//! The timeline screen's commands: list every entry, and the analyst's propose / edit / verify / reject. Every write
//! is the analyst's own decision (reviewed as made); core refuses an edit over a pending agent decision.

use crate::cmd::events::{EventQueryArgs, parse_time};
use crate::cmd::marks::{ResolvedRow, resolve_rows};
use crate::error::{CmdError, CmdResult};
use crate::state::{AppState, analyst, with_case, with_writable};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use sparrow_core::case::audit::AuditEntry;
use sparrow_core::case::events;
use sparrow_core::case::marks::RowRef;
use sparrow_core::case::timeline_entries::{self, Entry, EntryEdit, EvidenceRef, NewEntry, Phase};
use std::collections::BTreeSet;
use tauri::State;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewEntryArgs {
    /// RFC 3339.
    pub event_time: String,
    pub title: String,
    pub narrative: Option<String>,
    pub phase: String,
    /// `<table>:<record_key>` references.
    pub evidence: Vec<String>,
    pub tenant_key: Option<String>,
}

/// The fields an edit changes; an absent field keeps the current value. `narrative: null` clears it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EntryEditArgs {
    pub event_time: Option<String>,
    pub title: Option<String>,
    #[serde(deserialize_with = "present")]
    pub narrative: Option<Option<String>>,
    pub phase: Option<String>,
    /// Replaces the whole evidence list.
    pub evidence: Option<Vec<String>>,
}

/// `Some(None)` for an explicit `null`, `Some(Some(s))` for a string; `default` supplies `None` when absent.
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryWritten {
    pub entry_id: String,
    pub audit: AuditEntry,
}

fn time(s: &str) -> CmdResult<DateTime<Utc>> {
    parse_time(s)
}

/// Core's phase and evidence parsers report `Decision`; at this boundary they are bad arguments.
fn invalid(e: sparrow_core::Error) -> CmdError {
    match e {
        sparrow_core::Error::Decision(m) => CmdError::new("invalid", m),
        other => other.into(),
    }
}

fn phase(s: &str) -> CmdResult<Phase> {
    Phase::parse(s).map_err(invalid)
}

fn evidence(refs: &[String]) -> CmdResult<Vec<EvidenceRef>> {
    refs.iter()
        .map(|r| EvidenceRef::parse(r).map_err(invalid))
        .collect()
}

pub fn timeline_list(state: &AppState) -> CmdResult<Vec<Entry>> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(timeline_entries::list(open.case.conn(), None, None)?)
    })
}

pub fn timeline_propose(state: &AppState, args: NewEntryArgs) -> CmdResult<EntryWritten> {
    let ticket = state.ticket();
    // Arguments first: a malformed one is refused without touching the case.
    let entry = NewEntry {
        end_time: None,
        event_count: None,
        tenant_key: args.tenant_key,
        event_time: time(&args.event_time)?,
        title: args.title,
        narrative: args.narrative,
        phase: phase(&args.phase)?,
        evidence: evidence(&args.evidence)?,
    };
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        let (entry_id, audit) = timeline_entries::propose(open.case.conn(), &actor, entry)?;
        Ok(EntryWritten { entry_id, audit })
    })
}

/// Editing a verified entry proposes a successor; `entry_id` is then the successor's id.
pub fn timeline_edit(
    state: &AppState,
    entry_id: &str,
    args: EntryEditArgs,
) -> CmdResult<EntryWritten> {
    let ticket = state.ticket();
    let edit = EntryEdit {
        end_time: None,
        event_count: None,
        event_time: args.event_time.as_deref().map(time).transpose()?,
        title: args.title,
        narrative: args.narrative,
        phase: args.phase.as_deref().map(phase).transpose()?,
        evidence: args.evidence.as_deref().map(evidence).transpose()?,
    };
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        let (entry_id, audit) = timeline_entries::edit(open.case.conn(), &actor, entry_id, edit)?;
        Ok(EntryWritten { entry_id, audit })
    })
}

/// Core's verify takes no reason: the audit row says what was verified.
pub fn timeline_verify(state: &AppState, entry_id: &str) -> CmdResult<AuditEntry> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        Ok(timeline_entries::verify(
            open.case.conn(),
            &actor,
            entry_id,
        )?)
    })
}

/// A reason is required (core refuses an empty one).
pub fn timeline_reject(
    state: &AppState,
    entry_id: &str,
    reason: Option<&str>,
) -> CmdResult<AuditEntry> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let actor = analyst(state)?.as_actor();
        Ok(timeline_entries::reject(
            open.case.conn(),
            &actor,
            entry_id,
            reason.unwrap_or(""),
        )?)
    })
}

/// How `timeline_add_events` turns events into entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddMode {
    /// One verified entry per event (at most [`EACH_MAX`] events).
    Each,
    /// One verified entry that spans the events and cites all of them.
    Group,
}

/// The most events `each` turns into entries in one call.
pub const EACH_MAX: usize = 200;
/// The most events one call resolves from a query (the marks limit of one call).
pub const QUERY_MAX: usize = sparrow_core::case::marks::MAX_ROWS;

/// `rows` or `query` (exactly one): the events to add. `title` and `phase` apply to every entry made; without a phase
/// each entry's comes from the events' categories (`default_phase`), without a title from the event, or for a group
/// from its size and span.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddEventsArgs {
    pub rows: Option<Vec<RowRef>>,
    pub query: Option<EventQueryArgs>,
    pub mode: AddMode,
    pub title: Option<String>,
    pub phase: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EventsAdded {
    pub entry_ids: Vec<String>,
    /// One line for the toast.
    pub outcome: String,
}

/// The events a query matches, looked up as timeline rows in one scan; refused when none match or more than `max`.
fn rows_of_query(
    conn: &duckdb::Connection,
    q: &events::EventQuery,
    max: usize,
    what: &str,
) -> CmdResult<Vec<ResolvedRow>> {
    let (refs, capped) = events::matching_rows(conn, q, max)?;
    if capped {
        return Err(CmdError::new(
            "invalid",
            format!("more than {max} events match; {what} (narrow the query)"),
        ));
    }
    if refs.is_empty() {
        return Err(CmdError::new("invalid", "no event matches the query"));
    }
    resolve_rows(conn, &refs)
}

fn iso(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Add events to the timeline as verified entries, as the analyst: `each` makes one entry per event (refused over
/// [`EACH_MAX`]), `group` one entry from the first to the last event with the count, citing every event. The events are
/// all looked up first, so an unknown row or a row without a time (for `each`) adds nothing; `each` then makes every
/// entry in one transaction, so a failure part-way leaves none of them (nor their audit rows).
pub fn timeline_add_events(state: &AppState, args: AddEventsArgs) -> CmdResult<EventsAdded> {
    let ticket = state.ticket();
    // Arguments first: a malformed one is refused without touching the case.
    let query = match (&args.rows, &args.query) {
        (Some(_), None) => None,
        (None, Some(q)) => Some(q.to_query()?),
        _ => {
            return Err(CmdError::new(
                "invalid",
                "give either rows or a query to add to the timeline, not both and not neither",
            ));
        }
    };
    let phase_given = args.phase.as_deref().map(phase).transpose()?;
    let title_given = args
        .title
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string);
    with_writable(state, ticket, |open| {
        let who = analyst(state)?;
        let conn = open.case.conn();
        let mut resolved = match (&args.rows, &query) {
            (Some(rows), _) => {
                let distinct = rows.iter().collect::<BTreeSet<_>>().len();
                if args.mode == AddMode::Each && distinct > EACH_MAX {
                    return Err(each_cap(distinct as u64, false));
                }
                resolve_rows(conn, rows)?
            }
            (None, Some(q)) => match args.mode {
                AddMode::Each => rows_of_query(
                    conn,
                    q,
                    EACH_MAX,
                    &format!(
                        "one entry per event is limited to {EACH_MAX}; add them as one grouped entry"
                    ),
                )?,
                AddMode::Group => {
                    rows_of_query(conn, q, QUERY_MAX, "a group cites at most that many")?
                }
            },
            (None, None) => unreachable!("checked above"),
        };
        match args.mode {
            AddMode::Each => {
                resolved.sort_by(|a, b| a.event_time.cmp(&b.event_time).then(a.row.cmp(&b.row)));
                let mut entries = Vec::with_capacity(resolved.len());
                for r in &resolved {
                    let Some(at) = r.event_time else {
                        return Err(CmdError::new(
                            "invalid",
                            format!(
                                "event {}:{} has no time, so it cannot be an entry of its own (add it in a group)",
                                r.row.source_table, r.row.record_key
                            ),
                        ));
                    };
                    entries.push(NewEntry {
                        tenant_key: r.tenant_key.clone(),
                        event_time: at,
                        end_time: None,
                        event_count: None,
                        title: title_given.clone().unwrap_or_else(|| {
                            r.summary
                                .clone()
                                .or_else(|| r.operation.clone())
                                .unwrap_or_else(|| r.row.source_table.clone())
                        }),
                        narrative: None,
                        phase: phase_given.unwrap_or_else(|| {
                            timeline_entries::default_phase(std::slice::from_ref(&r.category))
                        }),
                        evidence: vec![evidence_of(r)],
                    });
                }
                // All or nothing: one transaction for every entry and its audit rows.
                let ids = sparrow_core::case::write::in_tx(conn, |tx| {
                    entries
                        .into_iter()
                        .map(|e| Ok(timeline_entries::create_verified_in(tx, &who, e)?.0))
                        .collect::<sparrow_core::Result<Vec<String>>>()
                })?;
                let n = ids.len();
                Ok(EventsAdded {
                    outcome: format!(
                        "Added {n} timeline {}",
                        if n == 1 { "entry" } else { "entries" }
                    ),
                    entry_ids: ids,
                })
            }
            AddMode::Group => {
                let times = resolved.iter().filter_map(|r| r.event_time);
                let (Some(start), Some(end)) = (times.clone().min(), times.max()) else {
                    return Err(CmdError::new(
                        "invalid",
                        "none of these events has a time, so they have no span to group",
                    ));
                };
                let n = resolved.len();
                let categories: Vec<String> = resolved
                    .iter()
                    .map(|r| r.category.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let tenants: BTreeSet<Option<&String>> =
                    resolved.iter().map(|r| r.tenant_key.as_ref()).collect();
                let tenant_key = match tenants.iter().next() {
                    Some(Some(t)) if tenants.len() == 1 => Some((*t).clone()),
                    _ => None,
                };
                let entry = NewEntry {
                    tenant_key,
                    event_time: start,
                    end_time: Some(end),
                    event_count: Some(n as u64),
                    title: title_given.unwrap_or_else(|| {
                        format!(
                            "{n} event{} {} to {}",
                            if n == 1 { "" } else { "s" },
                            iso(&start),
                            iso(&end)
                        )
                    }),
                    narrative: None,
                    phase: phase_given
                        .unwrap_or_else(|| timeline_entries::default_phase(&categories)),
                    evidence: resolved.iter().map(evidence_of).collect(),
                };
                let (id, _) = timeline_entries::create_verified(conn, &who, entry)?;
                Ok(EventsAdded {
                    outcome: format!(
                        "Added 1 grouped timeline entry covering {n} event{}",
                        if n == 1 { "" } else { "s" }
                    ),
                    entry_ids: vec![id],
                })
            }
        }
    })
}

fn each_cap(n: u64, capped: bool) -> CmdError {
    CmdError::new(
        "invalid",
        format!(
            "{n}{} events: one entry per event is limited to {EACH_MAX}; add them as one grouped entry",
            if capped { "+" } else { "" }
        ),
    )
}

fn evidence_of(r: &ResolvedRow) -> EvidenceRef {
    EvidenceRef {
        source_table: r.row.source_table.clone(),
        record_key: r.row.record_key.clone(),
    }
}

// The wrappers keep the contract's command names: Tauri registers the function name, so each wrapper lives in
// `commands` under the plain name and the module's plain functions keep theirs.
pub mod commands {
    use super::*;

    #[tauri::command(async)]
    pub fn timeline_list(state: State<'_, AppState>) -> CmdResult<Vec<Entry>> {
        super::timeline_list(&state)
    }

    #[tauri::command(async)]
    pub fn timeline_propose(
        state: State<'_, AppState>,
        args: NewEntryArgs,
    ) -> CmdResult<EntryWritten> {
        super::timeline_propose(&state, args)
    }

    #[tauri::command(async)]
    pub fn timeline_edit(
        state: State<'_, AppState>,
        entry_id: String,
        args: EntryEditArgs,
    ) -> CmdResult<EntryWritten> {
        super::timeline_edit(&state, &entry_id, args)
    }

    #[tauri::command(async)]
    pub fn timeline_add_events(
        state: State<'_, AppState>,
        args: AddEventsArgs,
    ) -> CmdResult<EventsAdded> {
        super::timeline_add_events(&state, args)
    }

    #[tauri::command(async)]
    pub fn timeline_verify(state: State<'_, AppState>, entry_id: String) -> CmdResult<AuditEntry> {
        super::timeline_verify(&state, &entry_id)
    }

    #[tauri::command(async)]
    pub fn timeline_reject(
        state: State<'_, AppState>,
        entry_id: String,
        reason: Option<String>,
    ) -> CmdResult<AuditEntry> {
        super::timeline_reject(&state, &entry_id, reason.as_deref())
    }
}
