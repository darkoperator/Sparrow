//! The timeline screen's commands: list every entry, and the analyst's propose / edit / verify / reject. Every write
//! is the analyst's own decision (reviewed as made); core refuses an edit over a pending agent decision.

use crate::error::{CmdError, CmdResult};
use crate::state::{AppState, analyst, with_case, with_writable};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use sparrow_core::case::audit::AuditEntry;
use sparrow_core::case::timeline_entries::{self, Entry, EntryEdit, EvidenceRef, NewEntry, Phase};
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
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| {
            CmdError::new(
                "invalid",
                format!("{s:?} is not an RFC 3339 time (for example 2026-03-01T10:00:00Z)"),
            )
        })
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
    with_case(state, |open| {
        Ok(timeline_entries::list(open.case.conn(), None, None)?)
    })
}

pub fn timeline_propose(state: &AppState, args: NewEntryArgs) -> CmdResult<EntryWritten> {
    // Arguments first: a malformed one is refused without touching the case.
    let entry = NewEntry {
        tenant_key: args.tenant_key,
        event_time: time(&args.event_time)?,
        title: args.title,
        narrative: args.narrative,
        phase: phase(&args.phase)?,
        evidence: evidence(&args.evidence)?,
    };
    with_writable(state, |open| {
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
    let edit = EntryEdit {
        event_time: args.event_time.as_deref().map(time).transpose()?,
        title: args.title,
        narrative: args.narrative,
        phase: args.phase.as_deref().map(phase).transpose()?,
        evidence: args.evidence.as_deref().map(evidence).transpose()?,
    };
    with_writable(state, |open| {
        let actor = analyst(state)?.as_actor();
        let (entry_id, audit) = timeline_entries::edit(open.case.conn(), &actor, entry_id, edit)?;
        Ok(EntryWritten { entry_id, audit })
    })
}

/// Core's verify takes no reason: the audit row says what was verified.
pub fn timeline_verify(state: &AppState, entry_id: &str) -> CmdResult<AuditEntry> {
    with_writable(state, |open| {
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
    with_writable(state, |open| {
        let actor = analyst(state)?.as_actor();
        Ok(timeline_entries::reject(
            open.case.conn(),
            &actor,
            entry_id,
            reason.unwrap_or(""),
        )?)
    })
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
