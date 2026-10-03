//! Review of agent decisions, for a future UI or other tool (Addendum D.4). No CLI command calls these in Phase 7.
//!
//! A review names the decision it reviewed by its audit seq, which must still be the object's latest decision.
//! Order: accept only from `pending_review`; discard from `pending_review` or `accepted`; `discarded` is final until
//! a new decision. Each review is one transaction with its own audit row (actor `analyst:<name>`).

use crate::case::actor::Reviewer;
use crate::case::audit::{self, AuditEntry};
use crate::case::write::{finding_state, in_tx};
use crate::case::{indicators, revert, timeline_entries};
use crate::{Error, Result};
use duckdb::{Connection, params};
use serde_json::{Value, json};

/// The audit actions that are agent decisions (reviews are not).
pub const DECISION_ACTIONS: &[&str] = &[
    "set_status",
    "assign",
    "ack_rule_update",
    "add_ioc",
    "set_ioc_verdict",
    "remove_ioc",
    "legacy_decision",
    "propose_entry",
    "verify_entry",
    "reject_entry",
    "edit_entry",
];

/// The newest audit entry that made a decision on the object (not a review).
pub fn latest_decision_seq(
    conn: &Connection,
    object_type: &str,
    object_id: &str,
) -> Result<Option<i64>> {
    let list = DECISION_ACTIONS
        .iter()
        .map(|a| format!("'{a}'"))
        .collect::<Vec<_>>()
        .join(",");
    Ok(conn.query_row(
        &format!(
            "SELECT max(seq) FROM audit_trail WHERE object_type = ? AND object_id = ? AND action IN ({list})"
        ),
        params![object_type, object_id],
        |r| r.get::<_, Option<i64>>(0),
    )?)
}

/// The object's state (its audit JSON); an error when the type is not reviewable or the object does not exist.
fn state(conn: &Connection, object_type: &str, object_id: &str) -> Result<Value> {
    match object_type {
        "finding" => finding_state(conn, object_id),
        "indicator" => indicators::indicator_state(conn, object_id)?
            .ok_or_else(|| Error::Decision(format!("unknown indicator {object_id}"))),
        "timeline_entry" => timeline_entries::entry_state(conn, object_id)?
            .ok_or_else(|| Error::Decision(format!("unknown timeline entry {object_id}"))),
        other => Err(Error::Decision(format!("cannot review a {other}"))),
    }
}

fn table(object_type: &str) -> (&'static str, &'static str) {
    match object_type {
        "finding" => ("findings", "finding_id"),
        "indicator" => ("case_indicators", "indicator_id"),
        _ => ("timeline_entries", "entry_id"),
    }
}

/// The decision `decision_seq` if it is still the object's latest; its review state must be one of `allowed`.
fn check_fresh(
    conn: &Connection,
    object_type: &str,
    object_id: &str,
    decision_seq: i64,
    allowed: &[&str],
) -> Result<(AuditEntry, Value)> {
    let current = state(conn, object_type, object_id)?;
    let latest = latest_decision_seq(conn, object_type, object_id)?.ok_or_else(|| {
        Error::Decision(format!(
            "{object_type} {object_id} has no agent decision to review"
        ))
    })?;
    if latest != decision_seq {
        return Err(Error::Decision(format!(
            "{object_type} {object_id} changed since decision {decision_seq} (latest is {latest}); reload and review again"
        )));
    }
    if object_type == "timeline_entry" && current["status"] == "superseded" {
        return Err(Error::Decision(format!(
            "timeline entry {object_id} is superseded; review the entry that superseded it"
        )));
    }
    let review_state = current["review_state"].as_str().unwrap_or("none");
    if !allowed.contains(&review_state) {
        return Err(Error::Decision(format!(
            "decision {decision_seq} on {object_type} {object_id} is {review_state}; this review needs {}",
            allowed.join(" or ")
        )));
    }
    let d = audit::log(conn, Some((object_type, object_id)))?
        .into_iter()
        .find(|e| e.seq == decision_seq)
        .ok_or_else(|| Error::Decision(format!("no audit entry {decision_seq}")))?;
    Ok((d, current))
}

fn mark(
    tx: &Connection,
    object_type: &str,
    object_id: &str,
    review_state: &str,
    reviewer: &Reviewer,
    ts: &str,
    comment: Option<&str>,
) -> Result<()> {
    let (t, k) = table(object_type);
    tx.execute(
        &format!(
            "UPDATE {t} SET review_state = CAST(? AS review_state), reviewed_by = ?, \
             reviewed_at = CAST(? AS TIMESTAMPTZ), review_comment = ? WHERE {k} = ?"
        ),
        params![review_state, reviewer.as_str(), ts, comment, object_id],
    )?;
    Ok(())
}

/// Accept the pending decision `decision_seq` on the object.
pub fn review_accept(
    conn: &Connection,
    reviewer: &Reviewer,
    object_type: &str,
    object_id: &str,
    decision_seq: i64,
    comment: Option<&str>,
) -> Result<AuditEntry> {
    let comment = comment.map(str::trim).filter(|c| !c.is_empty());
    if let Some(c) = comment {
        crate::case::text::check_text("a review comment", c)?;
    }
    in_tx(conn, |tx| {
        check_fresh(
            tx,
            object_type,
            object_id,
            decision_seq,
            &["pending_review"],
        )?;
        let ts = audit::now();
        mark(
            tx,
            object_type,
            object_id,
            "accepted",
            reviewer,
            &audit::ts_text(&ts),
            comment,
        )?;
        audit::append_at(
            tx,
            ts,
            reviewer.as_str(),
            None,
            "review_accept",
            object_type,
            object_id,
            None,
            Some(&json!({ "decision_seq": decision_seq })),
            comment,
        )
    })
}

/// Discard the decision `decision_seq` (pending or accepted): restore the fields it changed to their value before
/// it, then mark it discarded.
pub fn review_discard(
    conn: &Connection,
    reviewer: &Reviewer,
    object_type: &str,
    object_id: &str,
    decision_seq: i64,
    comment: Option<&str>,
) -> Result<AuditEntry> {
    let comment = comment.map(str::trim).filter(|c| !c.is_empty());
    if let Some(c) = comment {
        crate::case::text::check_text("a review comment", c)?;
    }
    in_tx(conn, |tx| {
        let (d, before) = check_fresh(
            tx,
            object_type,
            object_id,
            decision_seq,
            &["pending_review", "accepted"],
        )?;
        let ts = audit::now();
        let ts_text = audit::ts_text(&ts);
        let restored = revert::apply(tx, object_type, object_id, &d, reviewer, &ts_text)?;
        mark(
            tx,
            object_type,
            object_id,
            "discarded",
            reviewer,
            &ts_text,
            comment,
        )?;
        audit::append_at(
            tx,
            ts,
            reviewer.as_str(),
            None,
            "review_discard",
            object_type,
            object_id,
            Some(&before),
            Some(&json!({ "decision_seq": decision_seq, "restored": restored })),
            comment,
        )
    })
}
