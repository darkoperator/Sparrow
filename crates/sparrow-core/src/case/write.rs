//! The only writer of agent decisions on findings (Addendum D.4), and the transaction helper every decision and
//! review uses. Each write: read `before`, validate, apply with the provenance tags, append the audit row, commit;
//! any error rolls everything back.

use crate::case::actor::Actor;
use crate::case::audit::{self, AuditEntry};
use crate::{Error, Result};
use duckdb::{Connection, OptionalExt, params};
use serde_json::{Value, json};

/// Run `f` in its own transaction: BEGIN, `f`, COMMIT; ROLLBACK on any error. Fails (writing nothing) when a
/// transaction is already open, since the change and its audit row must commit together.
pub fn in_tx<T>(conn: &Connection, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
    conn.execute_batch("BEGIN TRANSACTION")?;
    match f(conn) {
        Ok(v) => match conn.execute_batch("COMMIT") {
            Ok(()) => Ok(v),
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e.into())
            }
        },
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    InReview,
    Confirmed,
    FalsePositive,
    Benign,
    NeedsMoreData,
}

impl FindingStatus {
    pub const ALL: [FindingStatus; 6] = [
        Self::New,
        Self::InReview,
        Self::Confirmed,
        Self::FalsePositive,
        Self::Benign,
        Self::NeedsMoreData,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::InReview => "in_review",
            Self::Confirmed => "confirmed",
            Self::FalsePositive => "false_positive",
            Self::Benign => "benign",
            Self::NeedsMoreData => "needs_more_data",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == s)
            .ok_or_else(|| {
                Error::Decision(format!(
                    "unknown finding status {s:?} (new, in_review, confirmed, false_positive, benign or needs_more_data)"
                ))
            })
    }

    /// A closing status needs a reason.
    pub fn closes(self) -> bool {
        matches!(self, Self::Confirmed | Self::FalsePositive | Self::Benign)
    }
}

/// The decision-bearing state of a finding plus its provenance tags, as JSON: the audit `before`/`after`, and what
/// a discard restores (`case::revert`).
pub(crate) fn finding_state(conn: &Connection, id: &str) -> Result<Value> {
    conn.prepare_cached(
        "SELECT CAST(status AS VARCHAR), disposition_reason, assigned_to, rule_updated, decided_by, on_behalf_of, \
                CAST(review_state AS VARCHAR) FROM findings WHERE finding_id = ?",
    )?
    .query_row(params![id], |r| {
            Ok(json!({
                "status": r.get::<_, String>(0)?,
                "disposition_reason": r.get::<_, Option<String>>(1)?,
                "assigned_to": r.get::<_, Option<String>>(2)?,
                "rule_updated": r.get::<_, bool>(3)?,
                "decided_by": r.get::<_, Option<String>>(4)?,
                "on_behalf_of": r.get::<_, Option<String>>(5)?,
                "review_state": r.get::<_, Option<String>>(6)?,
            }))
    })
    .optional()?
    .ok_or_else(|| Error::Decision(format!("unknown finding {id}")))
}

/// The SET clause of a new agent decision: the D.2 tags, review reset to pending. Binds decided_by, decided_at
/// (the audit ts) and on_behalf_of.
pub(crate) const DECISION_TAGS: &str = "decided_by = ?, decided_at = CAST(? AS TIMESTAMPTZ), on_behalf_of = ?, \
     review_state = 'pending_review', reviewed_by = NULL, reviewed_at = NULL, review_comment = NULL";

/// One finding decision: before, `apply` (the decision's own columns), the tags, after, the audit row; one
/// transaction.
fn decide(
    conn: &Connection,
    actor: &Actor,
    id: &str,
    action: &str,
    reason: Option<&str>,
    check: impl FnOnce(&Value) -> Result<()>,
    apply: impl FnOnce(&Connection) -> Result<()>,
) -> Result<AuditEntry> {
    in_tx(conn, |tx| {
        let before = finding_state(tx, id)?;
        check(&before)?;
        let ts = audit::now();
        apply(tx)?;
        tx.prepare_cached(&format!(
            "UPDATE findings SET {DECISION_TAGS}, updated_at = now() WHERE finding_id = ?"
        ))?
        .execute(params![
            actor.as_str(),
            audit::ts_text(&ts),
            actor.on_behalf_of(),
            id
        ])?;
        let after = finding_state(tx, id)?;
        audit::append_at(
            tx,
            ts,
            actor.as_str(),
            actor.on_behalf_of(),
            action,
            "finding",
            id,
            Some(&before),
            Some(&after),
            reason,
        )
    })
}

/// Set a finding's status. Confirmed, false_positive and benign need a reason; the reason becomes the
/// `disposition_reason` (NULL when none is given).
pub fn set_finding_status(
    conn: &Connection,
    actor: &Actor,
    id: &str,
    status: FindingStatus,
    reason: Option<&str>,
) -> Result<AuditEntry> {
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());
    if status.closes() && reason.is_none() {
        return Err(Error::Decision(format!(
            "a reason is required to set {}",
            status.as_str()
        )));
    }
    decide(
        conn,
        actor,
        id,
        "set_status",
        reason,
        |_| Ok(()),
        |tx| {
            tx.prepare_cached(
                "UPDATE findings SET status = CAST(? AS finding_status), disposition_reason = ? WHERE finding_id = ?",
            )?
            .execute(params![status.as_str(), reason, id])?;
            Ok(())
        },
    )
}

/// Assign a finding to an analyst (a name without control characters).
pub fn assign_finding(
    conn: &Connection,
    actor: &Actor,
    id: &str,
    analyst: &str,
) -> Result<AuditEntry> {
    let analyst = analyst.trim();
    if analyst.is_empty() || analyst.chars().any(char::is_control) {
        return Err(Error::Decision(
            "an assignee must be non-empty text without control characters".into(),
        ));
    }
    decide(
        conn,
        actor,
        id,
        "assign",
        None,
        |_| Ok(()),
        |tx| {
            tx.execute(
                "UPDATE findings SET assigned_to = ? WHERE finding_id = ?",
                params![analyst, id],
            )?;
            Ok(())
        },
    )
}

/// Acknowledge that the rule (or the indicators it reads) changed since the finding was raised: clears
/// `rule_updated`. Fails when it is not set.
pub fn ack_rule_update(conn: &Connection, actor: &Actor, id: &str) -> Result<AuditEntry> {
    decide(
        conn,
        actor,
        id,
        "ack_rule_update",
        None,
        |before| {
            if before["rule_updated"] == Value::Bool(true) {
                Ok(())
            } else {
                Err(Error::Decision(format!(
                    "finding {id} has no rule update to acknowledge"
                )))
            }
        },
        |tx| {
            tx.execute(
                "UPDATE findings SET rule_updated = false WHERE finding_id = ?",
                params![id],
            )?;
            Ok(())
        },
    )
}
