//! The entity tabs' commands (an account, an IP, a device or an Entra session): the tiles, the pivot tables and the
//! open findings over a time range. They only read the case. The entity may be in any spelling; core opens one tab's
//! worth of events for all of them.

use crate::cmd::events::{EntityArg, parse_range};
use crate::error::CmdResult;
use crate::state::{AppState, with_case};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use sparrow_core::case::audit::ts_text;
use sparrow_core::case::coverage::{SourceState, coverage_for_range};
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

/// One tenant's section of the coverage strip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TenantCoverage {
    pub tenant_key: String,
    /// The accounts judged in this tenant: those in the entity's events in the range, or in the whole case when none
    /// of its events fall in the range. An account tab's own account is always among them.
    pub accounts: Vec<String>,
    /// Every source, in coverage's order; the strip keeps the ones that are not covered.
    pub sources: Vec<SourceState>,
}

/// The coverage strip's data: the UTC days judged and one section per tenant the entity's events are in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntityCoverage {
    /// `YYYY-MM-DD`, UTC: coverage works in whole days.
    pub from: Option<String>,
    pub to: Option<String>,
    pub tenants: Vec<TenantCoverage>,
}

fn day(t: DateTime<Utc>) -> NaiveDate {
    t.date_naive()
}

/// For the tab's range (the entity's own first to last event where a bound is missing), each source's state per tenant
/// for the accounts in the entity's events in that range. A range with none of the entity's events is judged all the
/// same, for the accounts in its events in the whole case: that is where a missing source must not be read as nothing
/// having happened. An entity with no events at all has no sections.
pub fn entity_coverage(
    state: &AppState,
    entity: &EntityArg,
    from: Option<&str>,
    to: Option<&str>,
) -> CmdResult<EntityCoverage> {
    let ticket = state.ticket();
    let (from, to) = parse_range(from, to)?;
    with_case(state, ticket, |open| {
        let conn = open.case.conn();
        let scope = entity::coverage_scope(conn, &entity.entity(), from, to)?;
        let (Some(first), Some(last)) = (scope.first, scope.last) else {
            return Ok(EntityCoverage {
                from: None,
                to: None,
                tenants: Vec::new(),
            });
        };
        // The asked range, else the events' own; whole UTC days.
        let (lo, hi) = (day(from.unwrap_or(first)), day(to.unwrap_or(last)));
        let mut tenants = Vec::new();
        for (tenant, accounts) in scope.tenants {
            let range = coverage_for_range(conn, Some(&tenant), &accounts, lo, hi.max(lo))?;
            tenants.push(TenantCoverage {
                tenant_key: tenant,
                accounts,
                sources: range.sources,
            });
        }
        Ok(EntityCoverage {
            from: Some(lo.to_string()),
            to: Some(hi.max(lo).to_string()),
            tenants,
        })
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

    #[tauri::command(async)]
    pub fn entity_coverage(
        state: State<'_, AppState>,
        entity: EntityArg,
        from: Option<String>,
        to: Option<String>,
    ) -> CmdResult<EntityCoverage> {
        super::entity_coverage(&state, &entity, from.as_deref(), to.as_deref())
    }
}
