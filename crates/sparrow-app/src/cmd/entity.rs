//! The entity tabs' commands (an account, an IP, a device or an Entra session): the tiles, the pivot tables and the
//! open findings over a time range. They only read the case. The entity may be in any spelling; core opens one tab's
//! worth of events for all of them.

use crate::cmd::events::{EntityArg, parse_range};
use crate::error::CmdResult;
use crate::state::{AppState, with_case};
use serde::Serialize;
use sparrow_core::case::audit::ts_text;
use sparrow_core::case::entity::{self, EntitySummary, FindingRef, PivotOf, PivotPage};
use std::collections::BTreeMap;

/// [`EntitySummary`] for the UI: the same fields, with the entity as `{ kind, value }` (core's own serde form is an
/// externally tagged enum) so the app holds one entity shape everywhere.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EntitySummaryView {
    /// The entity in its stored spelling.
    pub entity: EntityArg,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub events: u64,
    pub distinct: BTreeMap<String, u64>,
    pub open_findings: BTreeMap<String, u64>,
    pub roles_matched: Vec<String>,
    pub ip_intel: Option<serde_json::Value>,
    pub device: Option<serde_json::Value>,
}

impl From<EntitySummary> for EntitySummaryView {
    fn from(s: EntitySummary) -> Self {
        EntitySummaryView {
            entity: EntityArg::from_entity(&s.entity),
            first_seen: s.first_seen.as_ref().map(ts_text),
            last_seen: s.last_seen.as_ref().map(ts_text),
            events: s.events,
            distinct: s.distinct,
            open_findings: s.open_findings,
            roles_matched: s.roles_matched,
            ip_intel: s.ip_intel,
            device: s.device,
        }
    }
}

pub fn entity_summary(
    state: &AppState,
    entity: &EntityArg,
    from: Option<&str>,
    to: Option<&str>,
) -> CmdResult<EntitySummaryView> {
    let ticket = state.ticket();
    let (from, to) = parse_range(from, to)?;
    with_case(state, ticket, |open| {
        Ok(entity::summary(open.case.conn(), &entity.entity(), from, to)?.into())
    })
}

/// One pivot table, at most `limit` rows (core's default 500, at most 5000) and the table's full `total`.
pub fn entity_pivot(
    state: &AppState,
    entity: &EntityArg,
    of: PivotOf,
    from: Option<&str>,
    to: Option<&str>,
    limit: Option<usize>,
) -> CmdResult<PivotPage> {
    let ticket = state.ticket();
    let (from, to) = parse_range(from, to)?;
    with_case(state, ticket, |open| {
        Ok(entity::pivot(
            open.case.conn(),
            &entity.entity(),
            of,
            from,
            to,
            limit,
        )?)
    })
}

pub fn entity_findings(
    state: &AppState,
    entity: &EntityArg,
    from: Option<&str>,
    to: Option<&str>,
) -> CmdResult<Vec<FindingRef>> {
    let ticket = state.ticket();
    let (from, to) = parse_range(from, to)?;
    with_case(state, ticket, |open| {
        Ok(entity::findings(
            open.case.conn(),
            &entity.entity(),
            from,
            to,
        )?)
    })
}

pub mod commands {
    use super::*;
    use tauri::State;

    #[tauri::command(async)]
    pub fn entity_summary(
        state: State<'_, AppState>,
        entity: EntityArg,
        from: Option<String>,
        to: Option<String>,
    ) -> CmdResult<EntitySummaryView> {
        super::entity_summary(&state, &entity, from.as_deref(), to.as_deref())
    }

    #[tauri::command(async)]
    pub fn entity_pivot(
        state: State<'_, AppState>,
        entity: EntityArg,
        of: PivotOf,
        from: Option<String>,
        to: Option<String>,
        limit: Option<usize>,
    ) -> CmdResult<PivotPage> {
        super::entity_pivot(&state, &entity, of, from.as_deref(), to.as_deref(), limit)
    }

    #[tauri::command(async)]
    pub fn entity_findings(
        state: State<'_, AppState>,
        entity: EntityArg,
        from: Option<String>,
        to: Option<String>,
    ) -> CmdResult<Vec<FindingRef>> {
        super::entity_findings(&state, &entity, from.as_deref(), to.as_deref())
    }
}
