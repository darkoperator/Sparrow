//! Review of agent decisions, for a future UI or other tool (Addendum D.4). No CLI command calls these in Phase 7.
//!
//! Reviewable objects: findings, indicators, timeline entries and, for the events grid, marks: a `value_flag`, and the
//! rows one agent call set as `event_flag` / `event_tag` (the object is the call; a review may name a subset of its
//! rows, see [`accept_in`]). Marks are reviewed here but never listed by [`pending`], so the queue stays about
//! findings, indicators and timeline proposals.
//!
//! A review names the decision it reviewed by its audit seq, which must still be the object's latest decision.
//! Order: accept only from `pending_review`; discard from `pending_review` or `accepted`; `discarded` is final until
//! a new decision. Each review is one transaction with its own audit row (actor `analyst:<name>`).

use crate::case::actor::Reviewer;
use crate::case::audit::{self, AuditEntry};
use crate::case::marks::{self, RowRef};
use crate::case::write::{finding_state, in_tx};
use crate::case::{indicators, revert, timeline_entries};
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::{Connection, params, params_from_iter};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

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
    "flag_rows",
    "flag_value",
    "tag_rows",
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
        "value_flag" | "event_flag" | "event_tag" => marks::state(conn, object_type, object_id),
        other => Err(Error::Decision(format!("cannot review a {other}"))),
    }
}

fn table(object_type: &str) -> (&'static str, &'static str) {
    match object_type {
        "finding" => ("findings", "finding_id"),
        "indicator" => ("case_indicators", "indicator_id"),
        "value_flag" => ("value_flags", "flag_id"),
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
    in_tx(conn, |tx| {
        accept_in(
            tx,
            reviewer,
            object_type,
            object_id,
            decision_seq,
            comment,
            None,
        )
    })
}

/// [`review_accept`] inside the caller's transaction. `only` limits a review of an `event_flag` / `event_tag` decision
/// to those of its rows (the grid confirms the rows a selection holds); the object's other rows stay pending. Ignored
/// for every other object.
pub(crate) fn accept_in(
    tx: &Connection,
    reviewer: &Reviewer,
    object_type: &str,
    object_id: &str,
    decision_seq: i64,
    comment: Option<&str>,
    only: Option<&[RowRef]>,
) -> Result<AuditEntry> {
    let comment = comment.map(str::trim).filter(|c| !c.is_empty());
    if let Some(c) = comment {
        crate::case::text::check_text("a review comment", c)?;
    }
    check_fresh(
        tx,
        object_type,
        object_id,
        decision_seq,
        &["pending_review"],
    )?;
    let ts = audit::now();
    let ts_text = audit::ts_text(&ts);
    let batch = matches!(object_type, "event_flag" | "event_tag");
    // The rows this review touches, before it touches them.
    let rows = if batch {
        Some(marks::reviewed_rows(tx, object_type, object_id, only)?)
    } else {
        None
    };
    if batch {
        marks::accept_batch(
            tx,
            object_type,
            object_id,
            reviewer,
            &ts_text,
            comment,
            only,
        )?;
    } else {
        mark(
            tx,
            object_type,
            object_id,
            "accepted",
            reviewer,
            &ts_text,
            comment,
        )?;
    }
    let mut after = json!({ "decision_seq": decision_seq });
    if let Some(rows) = rows {
        after["rows"] = rows;
    }
    audit::append_at(
        tx,
        ts,
        reviewer.as_str(),
        None,
        "review_accept",
        object_type,
        object_id,
        None,
        Some(&after),
        comment,
    )
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
    in_tx(conn, |tx| {
        discard_in(
            tx,
            reviewer,
            object_type,
            object_id,
            decision_seq,
            comment,
            None,
        )
    })
}

/// [`review_discard`] inside the caller's transaction, with `only` as for [`accept_in`]. A discard of an
/// `event_flag` / `event_tag` decision removes the pending rows it set (and puts back the flags it changed); it needs
/// at least one pending row.
pub(crate) fn discard_in(
    tx: &Connection,
    reviewer: &Reviewer,
    object_type: &str,
    object_id: &str,
    decision_seq: i64,
    comment: Option<&str>,
    only: Option<&[RowRef]>,
) -> Result<AuditEntry> {
    let comment = comment.map(str::trim).filter(|c| !c.is_empty());
    if let Some(c) = comment {
        crate::case::text::check_text("a review comment", c)?;
    }
    let (d, before) = check_fresh(
        tx,
        object_type,
        object_id,
        decision_seq,
        &["pending_review", "accepted"],
    )?;
    let ts = audit::now();
    let ts_text = audit::ts_text(&ts);
    let batch = matches!(object_type, "event_flag" | "event_tag");
    let rows = if batch {
        Some(marks::reviewed_rows(tx, object_type, object_id, only)?)
    } else {
        None
    };
    let restored = revert::apply(
        tx,
        object_type,
        object_id,
        &d,
        reviewer,
        &ts_text,
        only.filter(|_| batch),
    )?;
    // A reviewed batch has no row left to mark: its rows were deleted or put back as they were.
    if !batch {
        mark(
            tx,
            object_type,
            object_id,
            "discarded",
            reviewer,
            &ts_text,
            comment,
        )?;
    }
    audit::append_at(
        tx,
        ts,
        reviewer.as_str(),
        None,
        "review_discard",
        object_type,
        object_id,
        Some(&before),
        Some(&{
            let mut after = json!({ "decision_seq": decision_seq, "restored": restored });
            if let Some(rows) = rows {
                after["rows"] = rows;
            }
            after
        }),
        comment,
    )
}

/// One object waiting for review, with the agent decision to review (its latest).
#[derive(Debug, Clone, Serialize)]
pub struct PendingDecision {
    /// finding, indicator or timeline_entry.
    pub object_type: String,
    pub object_id: String,
    /// The audit seq a review names (`latest_decision_seq`).
    pub decision_seq: i64,
    pub action: String,
    pub actor: String,
    pub on_behalf_of: Option<String>,
    #[serde(serialize_with = "audit::ts_serialize")]
    pub decided_at: DateTime<Utc>,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub reason: Option<String>,
    /// The account the item is about: the finding's actor_upn; an indicator's value when its type is upn; a
    /// timeline entry's user when every evidence row names the same user (see `USER_SOURCES`); else None.
    pub account: Option<String>,
    /// The finding title, `<type> <value>` for an indicator, the entry title.
    pub title: String,
}

/// Every object whose review_state is pending_review (timeline entries: not superseded), with its latest decision;
/// oldest decision first.
pub fn pending(conn: &Connection) -> Result<Vec<PendingDecision>> {
    let objects: Vec<(String, String, String, Option<String>)> = {
        let mut stmt = conn.prepare(
            "SELECT 'finding', finding_id, title, actor_upn FROM findings WHERE review_state = 'pending_review' \
             UNION ALL \
             SELECT 'indicator', indicator_id, CAST(type AS VARCHAR) || ' ' || value, \
                    CASE WHEN CAST(type AS VARCHAR) = 'upn' THEN value END \
             FROM case_indicators WHERE review_state = 'pending_review' \
             UNION ALL \
             SELECT 'timeline_entry', entry_id, title, NULL FROM timeline_entries \
             WHERE review_state = 'pending_review' AND status <> 'superseded'",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    let pending_entries: Vec<&str> = objects
        .iter()
        .filter(|o| o.0 == "timeline_entry")
        .map(|o| o.1.as_str())
        .collect();
    let entry_accounts = entry_accounts(conn, &pending_entries)?;
    let mut out = Vec::with_capacity(objects.len());
    for (object_type, object_id, title, account) in objects {
        let seq = latest_decision_seq(conn, &object_type, &object_id)?.ok_or_else(|| {
            Error::Decision(format!(
                "{object_type} {object_id} is pending review but has no decision in the audit trail"
            ))
        })?;
        let d = audit::log(conn, Some((&object_type, &object_id)))?
            .into_iter()
            .find(|e| e.seq == seq)
            .ok_or_else(|| Error::Decision(format!("no audit entry {seq}")))?;
        let account = match object_type.as_str() {
            "timeline_entry" => entry_accounts.get(&object_id).cloned(),
            _ => account,
        };
        out.push(PendingDecision {
            object_type,
            object_id,
            decision_seq: seq,
            action: d.action,
            actor: d.actor,
            on_behalf_of: d.on_behalf_of,
            decided_at: d.ts,
            before: d.before,
            after: d.after,
            reason: d.reason,
            account,
            title,
        });
    }
    out.sort_by_key(|p| p.decision_seq);
    Ok(out)
}

/// Evidence tables whose rows name a user: (table, key column as a parameter match, user column, extra filter).
/// A row's user is its column when that looks like a UPN (`@`); application, service and display-name columns are
/// never users (signins.app_name, directory_audits.initiated_by_app_name, mailbox_audit_legacy.logon_user,
/// message_trace.sender, which can be external), and an evidence row in any other table has no user.
const USER_SOURCES: &[(&str, &str, &str, &str)] = &[
    ("signins", "record_key", "user_upn", ""),
    // UserType 0 Regular, 1 Reseller, 2 Admin, 3 DcAdmin, 10 Guest: not System, Application or ServicePrincipal.
    (
        "ual_events",
        "CAST(record_id AS VARCHAR)",
        "user_upn",
        "AND (user_type IS NULL OR user_type IN (0, 1, 2, 3, 10))",
    ),
    (
        "mail_items_accessed",
        "item_key",
        "user_upn",
        "AND record_id IS NULL",
    ),
    ("directory_audits", "record_key", "initiated_by_upn", ""),
    ("risk_detections", "record_key", "user_upn", ""),
    ("admin_audit_events", "record_key", "caller", ""),
    ("azure_activity", "record_key", "caller", ""),
];

/// For each of `entries` (pending, not superseded) whose evidence rows all name the same user (case-insensitive):
/// that user. One query for the entries' evidence, then one per evidence table that can name a user; nothing when
/// `entries` is empty.
fn entry_accounts(conn: &Connection, entries: &[&str]) -> Result<BTreeMap<String, String>> {
    if entries.is_empty() {
        return Ok(BTreeMap::new());
    }
    let marks = vec!["?"; entries.len()].join(", ");
    let evidence: Vec<(String, String, String)> = {
        let mut stmt = conn.prepare(&format!(
            "SELECT entry_id, source_table, record_key FROM timeline_entry_evidence WHERE entry_id IN ({marks})"
        ))?;
        let rows = stmt.query_map(params_from_iter(entries.iter()), |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    let mut keys: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (_, table, key) in &evidence {
        keys.entry(table.as_str()).or_default().insert(key.as_str());
    }
    let mut users: BTreeMap<(String, String), String> = BTreeMap::new();
    for (table, key_col, user_col, extra) in USER_SOURCES {
        let Some(wanted) = keys.get(table) else {
            continue;
        };
        let marks = vec!["?"; wanted.len()].join(", ");
        let mut stmt = conn.prepare(&format!(
            "SELECT {key_col}, lower({user_col}) FROM {table} \
             WHERE {key_col} IN ({marks}) AND {user_col} LIKE '%@%' {extra}"
        ))?;
        let rows = stmt.query_map(params_from_iter(wanted.iter()), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (key, user) = row?;
            users.insert((table.to_string(), key), user);
        }
    }
    // Per entry: Some(user) while every row so far names that user; None once a row has none or another one.
    let mut per_entry: BTreeMap<&str, Option<&String>> = BTreeMap::new();
    for (entry, table, key) in &evidence {
        let user = users.get(&(table.clone(), key.clone()));
        per_entry
            .entry(entry.as_str())
            .and_modify(|seen| {
                if *seen != user {
                    *seen = None;
                }
            })
            .or_insert(user);
    }
    Ok(per_entry
        .into_iter()
        .filter_map(|(entry, user)| user.map(|u| (entry.to_string(), u.clone())))
        .collect())
}
