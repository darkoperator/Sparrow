//! Which records are the attacker's. A record is attributed directly when an accepted, not removed, malicious flag
//! (or, for a preview ([`ScopeSource`]), a pending one or an ad-hoc value) matches it: a `session` flag on its Entra session or its UAL session id, a flag on the row itself, a `device` flag,
//! an `ip` or `ip_prefix` flag, or an `asn` flag scoped to an account. A flag's scope limits it as in the events grid,
//! except that an account scope matches the actor only: the report files a record under its actor, so a flag scoped to
//! Alice must not make Bob's reads of Alice's mailbox Bob's attacker activity.
//! An `account` flag attributes nothing (it would claim all of the user's own activity). A UAL record that shares its
//! Exchange session id with a directly attributed UAL record of the same account is attributed `session` too.

use super::{Attribution, Basis, ScopeSource};
use crate::Result;
use crate::case::marks::ValueKind;
use chrono::{DateTime, Utc};
use duckdb::Connection;
use duckdb::types::Value;
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
    /// What ties it: the strongest basis among the flags (or ad-hoc values) that attribute it.
    pub basis: Basis,
}

/// An hour in microseconds: the gap that splits a burst, and the tail added after its last sighting.
const HOUR_US: i64 = 3_600_000_000;

/// The malicious value flags in play, `flagv (kind, value, scope_kind, scope_value, basis)` (basis 1 accepted, 2
/// pending, 3 ad-hoc), and its bound parameters (the ad-hoc values, never inlined).
fn flag_values(src: &ScopeSource) -> (String, Vec<Value>) {
    let of = |state: &str, basis: u8| {
        format!(
            "SELECT kind::VARCHAR AS kind, value, scope_kind::VARCHAR AS scope_kind, scope_value, {basis} AS basis \
             FROM value_flags WHERE removed_at IS NULL AND level = 'malicious' AND review_state = '{state}'"
        )
    };
    let mut arms = Vec::new();
    if !src.without_accepted {
        arms.push(of("accepted", 1));
    }
    if src.include_pending {
        arms.push(of("pending_review", 2));
    }
    let mut params = Vec::new();
    if !src.adhoc.is_empty() {
        let rows = vec!["(CAST(? AS VARCHAR), CAST(? AS VARCHAR))"; src.adhoc.len()].join(", ");
        arms.push(format!(
            "SELECT k AS kind, v AS value, NULL::VARCHAR AS scope_kind, NULL::VARCHAR AS scope_value, 3 AS basis \
             FROM (VALUES {rows}) adhoc(k, v)"
        ));
        for (kind, value) in &src.adhoc {
            params.push(Value::Text(kind.as_str().to_string()));
            params.push(Value::Text(adhoc_value(*kind, value)));
        }
    }
    if arms.is_empty() {
        arms.push(
            "SELECT NULL::VARCHAR AS kind, NULL::VARCHAR AS value, NULL::VARCHAR AS scope_kind, \
             NULL::VARCHAR AS scope_value, 1 AS basis WHERE FALSE"
                .to_string(),
        );
    }
    (format!("flagv AS ({})", arms.join(" UNION ALL ")), params)
}

/// An ad-hoc value in the spelling flags store, as `marks` would normalise it; text that is not one is kept as
/// typed (it then matches nothing).
fn adhoc_value(kind: ValueKind, value: &str) -> String {
    kind.normalize(value)
        .unwrap_or_else(|_| value.trim().to_string())
}

/// `events e` joined to its UAL record `u`.
const WITH_UAL: &str = "events e JOIN ual_events u ON e.source_table = 'ual_events' \
     AND e.record_key = CAST(u.record_id AS VARCHAR)";

/// `vf` has no scope, or its scope names the row's actor (account), IP, device or Entra session.
const SCOPE: &str = "(vf.scope_kind IS NULL \
     OR (vf.scope_kind = 'account' AND e.actor_upn = vf.scope_value) \
     OR (vf.scope_kind = 'ip' AND e.ip = vf.scope_value) \
     OR (vf.scope_kind = 'device' AND (e.device_id = vf.scope_value OR e.device_object_id = vf.scope_value)) \
     OR (vf.scope_kind = 'session' AND e.entra_session_id = vf.scope_value))";

/// The CTEs of the attribution, ending in `attributed (source_table, record_key, account, attribution, event_time)`
/// and `windows (account, kind, value, start, "end")`:
///
/// - `hits`: every flag match (`rank` 1 session, 2 row, 3 device, 4 ip; the flag's `kind` and `value`).
/// - `direct`: one row per matched event with an actor, the strongest attribution kept; `prop`: the UAL records sharing
///   an Exchange session id with a direct UAL record of the same account, when they carry no identity of their own
///   (no Entra session, and no IP or the IP of a direct record of that session). Exchange session ids can live for
///   weeks: a record from another, unflagged IP in the same session is the real user's client and stays out.
/// - `windows` (times in epoch microseconds): per account and flagged value (`row` for row flags; propagated records
///   never open a window), the
///   bursts of its sightings split at gaps over an hour, each from its first sighting to its last plus an hour.
/// - `timed`: the events the account performed (its actor; never as mailbox owner, which would claim mail it
///   received and other people's reads of it) with no IP and no Entra session, not direct, inside one of its windows.
///
/// The attribution's CTEs for the flags `src` puts in play, with the parameters they bind (first in the statement:
/// a caller's own `?` come after them).
pub(crate) fn ctes(src: &ScopeSource) -> (String, Vec<Value>) {
    let (flagv, mut params) = flag_values(src);
    // A window (`investigate`) keeps the records of `[from, to)` before anything is made of them: a message's
    // sighting outside the window can then never stand in for one inside it. Bound last: it ends the CTEs' text.
    let window = match src.window {
        Some((from, to)) => {
            params.push(Value::BigInt(from.timestamp_micros()));
            params.push(Value::BigInt(to.timestamp_micros()));
            "WHERE epoch_us(event_time) >= ? AND epoch_us(event_time) < ?"
        }
        None => "",
    };
    let hit = |rank: u8, kind: &str, col: &str| {
        format!(
            "SELECT e.source_table, e.record_key, {rank} AS rank, vf.kind, vf.value, vf.basis FROM events e \
             JOIN flagv vf ON vf.kind = '{kind}' AND vf.value = {col} AND {SCOPE}"
        )
    };
    let row_states = match (src.without_accepted, src.include_pending) {
        (false, true) => "ef.review_state IN ('accepted', 'pending_review')",
        (false, false) => "ef.review_state = 'accepted'",
        (true, true) => "ef.review_state = 'pending_review'",
        (true, false) => "FALSE",
    };
    let hits = [
        hit(1, "session", "e.entra_session_id"),
        format!(
            "SELECT e.source_table, e.record_key, 1, 'session', vf.value, vf.basis FROM {WITH_UAL} JOIN flagv vf \
             ON vf.kind = 'session' AND vf.value = lower(u.session_id) AND {SCOPE}"
        ),
        format!(
            "SELECT ef.source_table, ef.record_key, 2, 'row', 'flagged rows', \
             CASE WHEN ef.review_state = 'accepted' THEN 1 ELSE 2 END FROM event_flags ef \
             WHERE ef.level = 'malicious' AND {row_states}"
        ),
        hit(3, "device", "e.device_id"),
        hit(3, "device", "e.device_object_id"),
        hit(4, "ip", "e.ip"),
        hit(4, "ip_prefix", "e.ip_prefix"),
        format!(
            "SELECT e.source_table, e.record_key, 4, 'asn', vf.value, vf.basis FROM events e JOIN flagv vf \
             ON vf.kind = 'asn' AND vf.value = CAST(e.asn AS VARCHAR) AND vf.scope_kind = 'account' AND {SCOPE}"
        ),
    ]
    .join(" UNION ALL ");
    let sql = format!(
        "{flagv}, \
         hits AS ({hits}), \
         best AS (SELECT source_table, record_key, min(rank) AS rank, min(basis) AS basis FROM hits GROUP BY ALL), \
         direct AS (SELECT e.source_table, e.record_key, lower(e.actor_upn) AS account, \
             CASE b.rank WHEN 1 THEN 'session' WHEN 2 THEN 'row' WHEN 3 THEN 'device' ELSE 'ip' END AS attribution, \
             e.event_time, b.basis FROM best b JOIN events e USING (source_table, record_key) \
             WHERE e.actor_upn IS NOT NULL AND e.event_time IS NOT NULL), \
         xs AS (SELECT d.account, lower(u.session_id) AS sid, e.ip, min(d.basis) AS basis FROM direct d \
             JOIN ual_events u ON d.source_table = 'ual_events' AND d.record_key = CAST(u.record_id AS VARCHAR) \
             JOIN events e USING (source_table, record_key) \
             WHERE coalesce(u.session_id, '') <> '' GROUP BY ALL), \
         prop AS (SELECT e.source_table, e.record_key, lower(e.actor_upn) AS account, \
             'session' AS attribution, e.event_time, min(xs.basis) AS basis FROM {WITH_UAL} \
             JOIN xs ON xs.sid = lower(u.session_id) AND xs.account = lower(e.actor_upn) \
             WHERE e.event_time IS NOT NULL AND e.entra_session_id IS NULL \
             AND (e.ip IS NULL OR e.ip = xs.ip) \
             AND (e.source_table, e.record_key) NOT IN (SELECT source_table, record_key FROM direct) GROUP BY ALL), \
         sightings AS (SELECT d.account, h.kind, h.value, epoch_us(d.event_time) AS t, h.basis FROM direct d \
                 JOIN hits h USING (source_table, record_key)), \
         breaks AS (SELECT *, CASE WHEN t - lag(t) OVER (PARTITION BY account, kind, value ORDER BY t) \
             > {HOUR_US} THEN 1 ELSE 0 END AS brk FROM sightings), \
         islands AS (SELECT *, sum(brk) OVER (PARTITION BY account, kind, value ORDER BY t \
             ROWS UNBOUNDED PRECEDING) AS island FROM breaks), \
         windows AS (SELECT account, kind, value, min(t) AS start, max(t) + {HOUR_US} AS \"end\", \
             min(basis) AS basis FROM islands GROUP BY account, kind, value, island), \
         dir AS (SELECT * FROM direct UNION ALL \
             SELECT source_table, record_key, account, attribution, event_time, basis FROM prop), \
         cand AS (SELECT e.source_table, e.record_key, lower(e.actor_upn) AS account, e.event_time, \
             epoch_us(e.event_time) AS t FROM events e \
             WHERE e.ip IS NULL AND e.entra_session_id IS NULL AND e.event_time IS NOT NULL \
             AND lower(e.actor_upn) IN (SELECT DISTINCT account FROM windows)), \
         timed AS (SELECT c.source_table, c.record_key, c.account, 'time' AS attribution, c.event_time, \
             min(w.basis) AS basis \
             FROM cand c JOIN windows w ON w.account = c.account AND c.t BETWEEN w.start AND w.\"end\" \
             WHERE (c.source_table, c.record_key) NOT IN (SELECT source_table, record_key FROM dir) GROUP BY ALL), \
         attributed AS MATERIALIZED (SELECT * FROM (SELECT * FROM dir UNION ALL SELECT * FROM timed) \
             {window})"
    );
    (sql, params)
}

/// A flagged value seen for an account, with the windows of its sightings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopeValue {
    /// The flag kind (`session`, `ip`, `ip_prefix`, `device`, `asn`), or `row` for rows flagged one by one.
    pub kind: String,
    pub value: String,
    pub windows: Vec<Window>,
    /// The strongest basis among the flags (or ad-hoc values) on it.
    pub basis: Basis,
}

/// From the first sighting of a burst to its last plus an hour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Window {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// The flagged values seen for `account` (any case), by kind and value, each with its windows in time order.
pub fn scope(conn: &Connection, account: &str) -> Result<Vec<ScopeValue>> {
    scope_with(conn, account, &ScopeSource::accepted())
}

/// [`scope`] with the flags `src` puts in play.
pub fn scope_with(conn: &Connection, account: &str, src: &ScopeSource) -> Result<Vec<ScopeValue>> {
    let (ctes, mut params) = ctes(src);
    let sql = format!(
        "WITH {ctes} SELECT kind, value, start, \"end\", basis FROM windows WHERE account = lower(?) \
         ORDER BY kind, value, start"
    );
    params.push(Value::Text(account.to_string()));
    let mut st = conn.prepare(&sql)?;
    let rows = st.query_map(duckdb::params_from_iter(params.iter()), |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, i64>(4)?,
        ))
    })?;
    let mut out: Vec<ScopeValue> = Vec::new();
    for row in rows {
        let (kind, value, start, end, basis) = row?;
        let basis = Basis::from_rank(basis);
        let w = Window {
            start: DateTime::from_timestamp_micros(start).unwrap_or_default(),
            end: DateTime::from_timestamp_micros(end).unwrap_or_default(),
        };
        match out.last_mut() {
            Some(v) if v.kind == kind && v.value == value => {
                v.windows.push(w);
                v.basis = v.basis.min(basis);
            }
            _ => out.push(ScopeValue {
                kind,
                value,
                windows: vec![w],
                basis,
            }),
        }
    }
    Ok(out)
}

/// The attributed rows, of one account (any case) or of every account, by account and time.
pub fn attributed(conn: &Connection, account: Option<&str>) -> Result<Vec<Attributed>> {
    attributed_with(conn, account, &ScopeSource::accepted())
}

/// [`attributed`] with the flags `src` puts in play.
pub fn attributed_with(
    conn: &Connection,
    account: Option<&str>,
    src: &ScopeSource,
) -> Result<Vec<Attributed>> {
    let (ctes, mut params) = ctes(src);
    let sql = format!(
        "WITH {ctes} SELECT source_table, record_key, account, attribution, epoch_us(event_time), basis \
         FROM attributed WHERE ? IS NULL OR account = lower(?) \
         ORDER BY account, event_time, source_table, record_key"
    );
    let account = account.map(str::to_string);
    params.push(account.clone().map_or(Value::Null, Value::Text));
    params.push(account.map_or(Value::Null, Value::Text));
    let mut st = conn.prepare(&sql)?;
    let rows = st.query_map(duckdb::params_from_iter(params.iter()), |r| {
        let a: String = r.get(3)?;
        Ok(Attributed {
            source_table: r.get(0)?,
            record_key: r.get(1)?,
            account: r.get(2)?,
            attribution: Attribution::parse(&a).unwrap_or(Attribution::Ip),
            event_time: DateTime::from_timestamp_micros(r.get(4)?).unwrap_or_default(),
            basis: Basis::from_rank(r.get(5)?),
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
