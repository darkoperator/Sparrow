//! Case indicators (ip, upn, ...): the verdicts that detection rules read through `@list:case_iocs.<type>`. All
//! writes go through here: each is an agent decision ([`Actor`]) with the D.2 tags and an audit row, in one
//! transaction. Removal is a soft delete; rules read active rows only.

use crate::case::audit::{self, AuditEntry};
use crate::case::write::{DECISION_TAGS, in_tx, refuse_if_pending_agent, self_review};
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::{Connection, OptionalExt, params};
use serde::{Serialize, Serializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub use super::actor::Actor;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Ip,
    Upn,
    AppId,
    Domain,
    UserAgent,
    RuleName,
    Email,
    Url,
    Hash,
}

impl IndicatorType {
    pub const ALL: [IndicatorType; 9] = [
        IndicatorType::Ip,
        IndicatorType::Upn,
        IndicatorType::AppId,
        IndicatorType::Domain,
        IndicatorType::UserAgent,
        IndicatorType::RuleName,
        IndicatorType::Email,
        IndicatorType::Url,
        IndicatorType::Hash,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            IndicatorType::Ip => "ip",
            IndicatorType::Upn => "upn",
            IndicatorType::AppId => "app_id",
            IndicatorType::Domain => "domain",
            IndicatorType::UserAgent => "user_agent",
            IndicatorType::RuleName => "rule_name",
            IndicatorType::Email => "email",
            IndicatorType::Url => "url",
            IndicatorType::Hash => "hash",
        }
    }

    pub fn parse(s: &str) -> Result<IndicatorType> {
        IndicatorType::ALL
            .into_iter()
            .find(|t| t.as_str() == s)
            .ok_or_else(|| Error::Invalid(format!("unknown indicator type {s:?}")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Malicious,
    Suspicious,
    Benign,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Malicious => "malicious",
            Verdict::Suspicious => "suspicious",
            Verdict::Benign => "benign",
        }
    }

    pub fn parse(s: &str) -> Result<Verdict> {
        [Verdict::Malicious, Verdict::Suspicious, Verdict::Benign]
            .into_iter()
            .find(|v| v.as_str() == s)
            .ok_or_else(|| Error::Invalid(format!("unknown indicator verdict {s:?}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Indicator {
    pub indicator_id: String,
    pub tenant_key: Option<String>,
    #[serde(rename = "type")]
    pub ty: IndicatorType,
    pub value: String,
    pub verdict: Verdict,
    pub note: Option<String>,
    pub added_by: String,
    #[serde(serialize_with = "rfc3339")]
    pub added_at: DateTime<Utc>,
    pub decided_by: Option<String>,
    pub on_behalf_of: Option<String>,
    pub review_state: Option<String>,
    #[serde(serialize_with = "rfc3339_opt")]
    pub removed_at: Option<DateTime<Utc>>,
    pub removed_by: Option<String>,
}

fn rfc3339<S: Serializer>(t: &DateTime<Utc>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
}

fn rfc3339_opt<S: Serializer>(
    t: &Option<DateTime<Utc>>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    match t {
        Some(t) => rfc3339(t, s),
        None => s.serialize_none(),
    }
}

pub(crate) fn indicator_id(tenant_key: Option<&str>, ty: IndicatorType, value: &str) -> String {
    let mut h = Sha256::new();
    h.update(tenant_key.unwrap_or("").as_bytes());
    h.update([0x1f]);
    h.update(ty.as_str().as_bytes());
    h.update([0x1f]);
    h.update(value.to_lowercase().as_bytes());
    hex::encode(h.finalize())[..16].to_string()
}

/// The decision-bearing state of an indicator plus its provenance tags, as JSON (the audit `before`/`after`, and
/// what a discard restores); `None` when it does not exist.
pub(crate) fn indicator_state(conn: &Connection, id: &str) -> Result<Option<Value>> {
    Ok(conn
        .query_row(
            "SELECT CAST(type AS VARCHAR), value, tenant_key, CAST(verdict AS VARCHAR), note, epoch_us(removed_at), \
                    removed_by, decided_by, on_behalf_of, CAST(review_state AS VARCHAR) \
             FROM case_indicators WHERE indicator_id = ?",
            params![id],
            |r| {
                let removed_at = r
                    .get::<_, Option<i64>>(5)?
                    .and_then(DateTime::from_timestamp_micros)
                    .map(|t| audit::ts_text(&t));
                Ok(json!({
                    "type": r.get::<_, String>(0)?,
                    "value": r.get::<_, String>(1)?,
                    "tenant_key": r.get::<_, Option<String>>(2)?,
                    "verdict": r.get::<_, String>(3)?,
                    "note": r.get::<_, Option<String>>(4)?,
                    "removed_at": removed_at,
                    "removed_by": r.get::<_, Option<String>>(6)?,
                    "decided_by": r.get::<_, Option<String>>(7)?,
                    "on_behalf_of": r.get::<_, Option<String>>(8)?,
                    "review_state": r.get::<_, Option<String>>(9)?,
                }))
            },
        )
        .optional()?)
}

/// One indicator decision in its own transaction: `apply` (given the decision ts), the D.2 tags, the audit row
/// with the state before (None for a new indicator) and after.
fn decide(
    conn: &Connection,
    actor: &Actor,
    id: &str,
    action: &str,
    reason: Option<&str>,
    apply: impl FnOnce(&Connection, Option<&Value>, &str) -> Result<()>,
) -> Result<AuditEntry> {
    in_tx(conn, |tx| {
        let before = indicator_state(tx, id)?;
        let latest = crate::case::review::latest_decision_seq(tx, "indicator", id)?;
        refuse_if_pending_agent(actor, "indicator", id, before.as_ref(), latest)?;
        let ts = audit::now();
        let ts_text = audit::ts_text(&ts);
        apply(tx, before.as_ref(), &ts_text)?;
        tx.execute(
            &format!("UPDATE case_indicators SET {DECISION_TAGS} WHERE indicator_id = ?"),
            params![actor.as_str(), ts_text, actor.on_behalf_of(), id],
        )?;
        self_review(tx, "case_indicators", "indicator_id", id, actor)?;
        let after = indicator_state(tx, id)?;
        audit::append_at(
            tx,
            ts,
            actor.as_str(),
            actor.on_behalf_of(),
            action,
            "indicator",
            id,
            before.as_ref(),
            after.as_ref(),
            reason,
        )
    })
}

/// Add an indicator, or update the verdict and note of the same tenant/type/value (bringing it back when it was
/// removed). Returns its id.
pub fn add_indicator(
    conn: &Connection,
    actor: &Actor,
    tenant_key: Option<&str>,
    ty: IndicatorType,
    value: &str,
    verdict: Verdict,
    note: Option<&str>,
) -> Result<String> {
    add_indicator_from(conn, actor, tenant_key, ty, value, verdict, note, None)
}

/// [`add_indicator`] with an audit reason (an accepted share proposal names its source).
#[allow(clippy::too_many_arguments)]
pub(crate) fn add_indicator_from(
    conn: &Connection,
    actor: &Actor,
    tenant_key: Option<&str>,
    ty: IndicatorType,
    value: &str,
    verdict: Verdict,
    note: Option<&str>,
    reason: Option<&str>,
) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::Decision(
            "an indicator value must not be empty".into(),
        ));
    }
    if let Some(n) = note {
        crate::case::text::check_text("a note", n)?;
    }
    let id = indicator_id(tenant_key, ty, value);
    decide(conn, actor, &id, "add_ioc", reason, |tx, before, ts| {
        if before.is_some() {
            tx.execute(
                "UPDATE case_indicators SET verdict = CAST(? AS indicator_verdict), note = ?, added_by = ?, \
                 added_at = CAST(? AS TIMESTAMPTZ), removed_at = NULL, removed_by = NULL WHERE indicator_id = ?",
                params![verdict.as_str(), note, actor.as_str(), ts, id],
            )?;
        } else {
            tx.execute(
                "INSERT INTO case_indicators (indicator_id, tenant_key, type, value, verdict, note, added_by, added_at) \
                 VALUES (?, ?, CAST(? AS indicator_type), ?, CAST(? AS indicator_verdict), ?, ?, CAST(? AS TIMESTAMPTZ))",
                params![id, tenant_key, ty.as_str(), value, verdict.as_str(), note, actor.as_str(), ts],
            )?;
        }
        Ok(())
    })?;
    Ok(id)
}

/// Change the verdict of an active indicator; `note` replaces the note when given and keeps it otherwise.
pub fn set_verdict(
    conn: &Connection,
    actor: &Actor,
    indicator_id: &str,
    verdict: Verdict,
    note: Option<&str>,
) -> Result<AuditEntry> {
    if let Some(n) = note {
        crate::case::text::check_text("a note", n)?;
    }
    decide(
        conn,
        actor,
        indicator_id,
        "set_ioc_verdict",
        None,
        |tx, before, _| {
            match before {
                None => {
                    return Err(Error::Decision(format!("unknown indicator {indicator_id}")));
                }
                Some(b) if !b["removed_at"].is_null() => {
                    return Err(Error::Decision(format!(
                        "indicator {indicator_id} was removed; add it again instead"
                    )));
                }
                Some(_) => {}
            }
            tx.execute(
                "UPDATE case_indicators SET verdict = CAST(? AS indicator_verdict), note = coalesce(?, note) \
                 WHERE indicator_id = ?",
                params![verdict.as_str(), note, indicator_id],
            )?;
            Ok(())
        },
    )
}

/// Remove an indicator (soft delete: `removed_at`/`removed_by`; rules stop reading it). Returns whether it was
/// active; removing an unknown or already removed indicator changes and records nothing.
pub fn remove_indicator(conn: &Connection, actor: &Actor, indicator_id: &str) -> Result<bool> {
    remove_indicator_from(conn, actor, indicator_id, None)
}

/// [`remove_indicator`] with an audit reason (an accepted share proposal names its source).
pub(crate) fn remove_indicator_from(
    conn: &Connection,
    actor: &Actor,
    indicator_id: &str,
    reason: Option<&str>,
) -> Result<bool> {
    let active: bool = conn.query_row(
        "SELECT count(*) > 0 FROM case_indicators WHERE indicator_id = ? AND removed_at IS NULL",
        params![indicator_id],
        |r| r.get(0),
    )?;
    if !active {
        return Ok(false);
    }
    decide(
        conn,
        actor,
        indicator_id,
        "remove_ioc",
        reason,
        |tx, before, ts| {
            if before.is_none_or(|b| !b["removed_at"].is_null()) {
                return Err(Error::Decision(format!(
                    "indicator {indicator_id} is not active"
                )));
            }
            tx.execute(
                "UPDATE case_indicators SET removed_at = CAST(? AS TIMESTAMPTZ), removed_by = ? WHERE indicator_id = ?",
                params![ts, actor.as_str(), indicator_id],
            )?;
            Ok(())
        },
    )?;
    Ok(true)
}

/// The indicators of `tenant_key` plus the case-wide ones (`tenant_key` NULL); every indicator when `tenant_key`
/// is `None`. Removed indicators only with `include_removed`. Ordered by type, value, id.
pub fn list_indicators(
    conn: &Connection,
    tenant_key: Option<&str>,
    include_removed: bool,
) -> Result<Vec<Indicator>> {
    let mut stmt = conn.prepare(
        "SELECT indicator_id, tenant_key, CAST(type AS VARCHAR), value, CAST(verdict AS VARCHAR), note, \
                added_by, epoch_us(added_at), decided_by, on_behalf_of, CAST(review_state AS VARCHAR), \
                epoch_us(removed_at), removed_by \
         FROM case_indicators \
         WHERE (?::VARCHAR IS NULL OR tenant_key IS NULL OR tenant_key = ?::VARCHAR) \
           AND (? OR removed_at IS NULL) \
         ORDER BY type, value, indicator_id",
    )?;
    let rows = stmt.query_map(params![tenant_key, tenant_key, include_removed], |r| {
        Ok((
            (
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, String>(6)?,
            ),
            (
                r.get::<_, i64>(7)?,
                r.get::<_, Option<String>>(8)?,
                r.get::<_, Option<String>>(9)?,
                r.get::<_, Option<String>>(10)?,
                r.get::<_, Option<i64>>(11)?,
                r.get::<_, Option<String>>(12)?,
            ),
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (
            (indicator_id, tenant_key, ty, value, verdict, note, added_by),
            (us, decided_by, on_behalf_of, review_state, removed_us, removed_by),
        ) = row?;
        out.push(Indicator {
            indicator_id,
            tenant_key,
            ty: IndicatorType::parse(&ty)?,
            value,
            verdict: Verdict::parse(&verdict)?,
            note,
            added_by,
            added_at: DateTime::from_timestamp_micros(us).unwrap_or_default(),
            decided_by,
            on_behalf_of,
            review_state,
            removed_at: removed_us.and_then(DateTime::from_timestamp_micros),
            removed_by,
        });
    }
    Ok(out)
}
