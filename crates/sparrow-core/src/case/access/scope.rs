//! Which records are the attacker's. A record is attributed directly when an accepted, not removed, malicious flag
//! matches it: a `session` flag on its Entra session or its UAL session id, a flag on the row itself, a `device` flag,
//! an `ip` or `ip_prefix` flag, or an `asn` flag scoped to an account. A flag's scope limits it as in the events grid,
//! except that an account scope matches the actor only: the report files a record under its actor, so a flag scoped to
//! Alice must not make Bob's reads of Alice's mailbox Bob's attacker activity.
//! An `account` flag attributes nothing (it would claim all of the user's own activity). A UAL record that shares its
//! Exchange session id with a directly attributed UAL record of the same account is attributed `session` too.

use super::Attribution;
use crate::Result;
use chrono::{DateTime, Utc};
use duckdb::Connection;
use serde::Serialize;

/// One attributed `events` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Attributed {
    pub source_table: String,
    pub record_key: String,
    /// The compromised account (lower-cased `actor_upn`).
    pub account: String,
    pub attribution: Attribution,
    pub event_time: DateTime<Utc>,
}

const ACCEPTED: &str =
    "vf.removed_at IS NULL AND vf.level = 'malicious' AND vf.review_state = 'accepted'";

/// `events e` joined to its UAL record `u`.
const WITH_UAL: &str = "events e JOIN ual_events u ON e.source_table = 'ual_events' \
     AND e.record_key = CAST(u.record_id AS VARCHAR)";

/// `vf` has no scope, or its scope names the row's actor (account), IP, device or Entra session.
const SCOPE: &str = "(vf.scope_kind IS NULL \
     OR (vf.scope_kind = 'account' AND e.actor_upn = vf.scope_value) \
     OR (vf.scope_kind = 'ip' AND e.ip = vf.scope_value) \
     OR (vf.scope_kind = 'device' AND (e.device_id = vf.scope_value OR e.device_object_id = vf.scope_value)) \
     OR (vf.scope_kind = 'session' AND e.entra_session_id = vf.scope_value))";

/// The directly attributed rows: `(source_table, record_key, account, attribution, event_time)`, one per row, the
/// strongest attribution kept (session, row, device, ip).
pub(crate) fn direct_sql() -> String {
    let hit = |rank: u8, from: &str, kind: &str, col: &str| {
        format!(
            "SELECT e.source_table, e.record_key, {rank} AS rank FROM {from} \
             JOIN value_flags vf ON vf.kind = '{kind}' AND vf.value = {col} AND {ACCEPTED} AND {SCOPE}"
        )
    };
    let hit = |rank, kind, col| hit(rank, "events e", kind, col);
    let hits = [
        hit(1, "session", "e.entra_session_id"),
        format!(
            "SELECT e.source_table, e.record_key, 1 FROM {WITH_UAL} JOIN value_flags vf ON vf.kind = 'session' \
             AND vf.value = lower(u.session_id) AND {ACCEPTED} AND {SCOPE}"
        ),
        "SELECT ef.source_table, ef.record_key, 2 FROM event_flags ef \
         WHERE ef.level = 'malicious' AND ef.review_state = 'accepted'"
            .to_string(),
        hit(3, "device", "e.device_id"),
        hit(3, "device", "e.device_object_id"),
        hit(4, "ip", "e.ip"),
        hit(4, "ip_prefix", "e.ip_prefix"),
        format!(
            "SELECT e.source_table, e.record_key, 4 FROM events e JOIN value_flags vf ON vf.kind = 'asn' \
             AND vf.value = CAST(e.asn AS VARCHAR) AND vf.scope_kind = 'account' AND {ACCEPTED} AND {SCOPE}"
        ),
    ]
    .join(" UNION ALL ");
    format!(
        "(WITH hits AS ({hits}), \
         best AS (SELECT source_table, record_key, min(rank) AS rank FROM hits GROUP BY ALL), \
         direct AS (SELECT e.source_table, e.record_key, lower(e.actor_upn) AS account, \
             CASE b.rank WHEN 1 THEN 'session' WHEN 2 THEN 'row' WHEN 3 THEN 'device' ELSE 'ip' END AS attribution, \
             e.event_time FROM best b JOIN events e USING (source_table, record_key) \
             WHERE e.actor_upn IS NOT NULL AND e.event_time IS NOT NULL), \
         xs AS (SELECT DISTINCT d.account, lower(u.session_id) AS sid FROM direct d JOIN ual_events u \
             ON d.source_table = 'ual_events' AND d.record_key = CAST(u.record_id AS VARCHAR) \
             WHERE coalesce(u.session_id, '') <> '') \
         SELECT * FROM direct UNION ALL \
         SELECT e.source_table, e.record_key, lower(e.actor_upn), 'session', e.event_time FROM {WITH_UAL} \
             JOIN xs ON xs.sid = lower(u.session_id) AND xs.account = lower(e.actor_upn) \
             WHERE e.event_time IS NOT NULL \
             AND (e.source_table, e.record_key) NOT IN (SELECT source_table, record_key FROM direct))"
    )
}

/// The attributed rows, of one account (any case) or of every account, by account and time.
pub fn attributed(conn: &Connection, account: Option<&str>) -> Result<Vec<Attributed>> {
    let sql = format!(
        "SELECT source_table, record_key, account, attribution, epoch_us(event_time) FROM {} a \
         WHERE ? IS NULL OR account = lower(?) ORDER BY account, event_time, source_table, record_key",
        direct_sql()
    );
    let mut st = conn.prepare(&sql)?;
    let rows = st.query_map(duckdb::params![account, account], |r| {
        let a: String = r.get(3)?;
        Ok(Attributed {
            source_table: r.get(0)?,
            record_key: r.get(1)?,
            account: r.get(2)?,
            attribution: Attribution::parse(&a).unwrap_or(Attribution::Ip),
            event_time: DateTime::from_timestamp_micros(r.get(4)?).unwrap_or_default(),
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// Malicious flags (on values or rows) still waiting for review: they attribute nothing until accepted.
pub fn pending_flags(conn: &Connection) -> Result<u64> {
    let n: i64 = conn.query_row(
        "SELECT (SELECT count(*) FROM value_flags WHERE removed_at IS NULL AND level = 'malicious' \
             AND review_state = 'pending_review') \
         + (SELECT count(*) FROM event_flags WHERE level = 'malicious' AND review_state = 'pending_review')",
        [],
        |r| r.get(0),
    )?;
    Ok(n as u64)
}
