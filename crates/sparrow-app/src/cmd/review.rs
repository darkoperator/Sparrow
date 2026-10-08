//! The review queue: pending agent decisions and open imported proposals, reviewed as the analyst.

use crate::error::CmdResult;
use crate::state::{AppState, analyst, with_case, with_writable};
use serde::Serialize;
use sparrow_core::case::audit::AuditEntry;
use sparrow_core::case::read::{self, FindingDetail};
use sparrow_core::case::review::{self, PendingDecision};
use sparrow_core::case::share::{self, Proposal};

/// One row of the queue, tagged `source: decision | proposal` over core's own shape.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum QueueItem {
    Decision(PendingDecision),
    Proposal(Proposal),
}

/// Pending agent decisions (oldest first), then open proposals (oldest bundle first).
pub fn review_queue(state: &AppState) -> CmdResult<Vec<QueueItem>> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        let conn = open.case.conn();
        let mut items: Vec<QueueItem> = review::pending(conn)?
            .into_iter()
            .map(QueueItem::Decision)
            .collect();
        items.extend(share::proposals(conn)?.into_iter().map(QueueItem::Proposal));
        Ok(items)
    })
}

pub fn finding_detail(state: &AppState, finding_id: &str) -> CmdResult<FindingDetail> {
    let ticket = state.ticket();
    with_case(state, ticket, |open| {
        Ok(read::finding_show(
            open.case.conn(),
            finding_id,
            &open.rules,
        )?)
    })
}

pub fn review_accept(
    state: &AppState,
    object_type: &str,
    object_id: &str,
    decision_seq: i64,
    comment: Option<&str>,
) -> CmdResult<AuditEntry> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let who = analyst(state)?;
        Ok(review::review_accept(
            open.case.conn(),
            &who,
            object_type,
            object_id,
            decision_seq,
            comment,
        )?)
    })
}

pub fn review_discard(
    state: &AppState,
    object_type: &str,
    object_id: &str,
    decision_seq: i64,
    comment: Option<&str>,
) -> CmdResult<AuditEntry> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let who = analyst(state)?;
        Ok(review::review_discard(
            open.case.conn(),
            &who,
            object_type,
            object_id,
            decision_seq,
            comment,
        )?)
    })
}

pub fn proposal_accept(
    state: &AppState,
    bundle_sha256: &str,
    item_key: &str,
) -> CmdResult<Vec<AuditEntry>> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let who = analyst(state)?;
        Ok(share::accept(
            open.case.conn(),
            &who,
            bundle_sha256,
            item_key,
        )?)
    })
}

pub fn proposal_discard(
    state: &AppState,
    bundle_sha256: &str,
    item_key: &str,
    comment: Option<&str>,
) -> CmdResult<AuditEntry> {
    let ticket = state.ticket();
    with_writable(state, ticket, |open| {
        let who = analyst(state)?;
        Ok(share::discard(
            open.case.conn(),
            &who,
            bundle_sha256,
            item_key,
            comment,
        )?)
    })
}

/// The `#[tauri::command]` wrappers (arguments arrive in camelCase: `objectType`, `decisionSeq`, ...).
pub mod commands {
    use super::QueueItem;
    use crate::error::CmdResult;
    use crate::state::AppState;
    use sparrow_core::case::audit::AuditEntry;
    use sparrow_core::case::read::FindingDetail;
    use tauri::State;

    #[tauri::command(async)]
    pub fn review_queue(state: State<'_, AppState>) -> CmdResult<Vec<QueueItem>> {
        super::review_queue(&state)
    }

    #[tauri::command(async)]
    pub fn finding_detail(
        state: State<'_, AppState>,
        finding_id: String,
    ) -> CmdResult<FindingDetail> {
        super::finding_detail(&state, &finding_id)
    }

    #[tauri::command(async)]
    pub fn review_accept(
        state: State<'_, AppState>,
        object_type: String,
        object_id: String,
        decision_seq: i64,
        comment: Option<String>,
    ) -> CmdResult<AuditEntry> {
        super::review_accept(
            &state,
            &object_type,
            &object_id,
            decision_seq,
            comment.as_deref(),
        )
    }

    #[tauri::command(async)]
    pub fn review_discard(
        state: State<'_, AppState>,
        object_type: String,
        object_id: String,
        decision_seq: i64,
        comment: Option<String>,
    ) -> CmdResult<AuditEntry> {
        super::review_discard(
            &state,
            &object_type,
            &object_id,
            decision_seq,
            comment.as_deref(),
        )
    }

    #[tauri::command(async)]
    pub fn proposal_accept(
        state: State<'_, AppState>,
        bundle_sha256: String,
        item_key: String,
    ) -> CmdResult<Vec<AuditEntry>> {
        super::proposal_accept(&state, &bundle_sha256, &item_key)
    }

    #[tauri::command(async)]
    pub fn proposal_discard(
        state: State<'_, AppState>,
        bundle_sha256: String,
        item_key: String,
        comment: Option<String>,
    ) -> CmdResult<AuditEntry> {
        super::proposal_discard(&state, &bundle_sha256, &item_key, comment.as_deref())
    }
}
