//! Entity tabs: the summary tiles, the pivot tables and the findings of one account, IP, device or Entra session.
//!
//! Everything reads the `events` table through the scope of [`crate::case::events`] (`scope_where`), the same SQL the
//! Events grid uses, so a tile and the grid next to it always agree: an entity matches the same rows in every spelling,
//! and the `message_trace_event` rows the grid hides by default are left out here too. The only other tables read are
//! `findings` / `finding_evidence`, `ip_intel` (IP tab) and the `signins` device struct (device tab).

use crate::case::events::{Entity, EventQuery, Where, scope_where};
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::types::Value;
use duckdb::{Connection, params_from_iter};
use serde::Serialize;
use std::collections::BTreeMap;

/// Microseconds in a UTC day: `epoch_us // DAY` is the day number, so "first day" needs no time zone support.
const DAY_US: i64 = 86_400_000_000;

fn ts_opt<S: serde::Serializer>(
    t: &Option<DateTime<Utc>>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    match t {
        Some(t) => s.serialize_str(&crate::case::audit::ts_text(t)),
        None => s.serialize_none(),
    }
}

fn ts_utc<S: serde::Serializer>(t: &DateTime<Utc>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&crate::case::audit::ts_text(t))
}

fn at(us: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(us).unwrap_or_default()
}

/// The tiles of an entity tab.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EntitySummary {
    /// The entity in its stored spelling.
    pub entity: Entity,
    #[serde(serialize_with = "ts_opt")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(serialize_with = "ts_opt")]
    pub last_seen: Option<DateTime<Utc>>,
    /// Events of the entity in range, as the Events grid counts them (`message_trace_event` rows are not in it).
    pub events: u64,
    /// Always the six keys `accounts`, `ips`, `countries`, `asns`, `devices`, `sessions` (0 when none). `accounts`
    /// counts the actors and the owners (mailbox owner, message recipient) of the events, the entity itself included
    /// for an account tab. `devices` counts `device_id`, else the directory object id, of each event.
    pub distinct: BTreeMap<String, u64>,
    /// Severity (as the finding stores it) to the number of open findings citing the entity's events in range. Open is
    /// every status except `false_positive` and `benign`; a severity with none is absent.
    pub open_findings: BTreeMap<String, u64>,
    /// Account tab only, in this order: `actor`, `mailbox owner`, `message sender`, `message recipient`; the ones the
    /// events in range show. Empty for the other kinds.
    pub roles_matched: Vec<String>,
    /// IP tab: the `ip_intel` row (its columns, plus `ip_kind` as the events carry it). `None` for the other kinds and
    /// for an address without a row. Not narrowed by the range.
    pub ip_intel: Option<serde_json::Value>,
    /// Device tab: the `device` struct of the latest sign-in in range (`device_id`, `display_name`, `os`, `browser`,
    /// `is_compliant`, `is_managed`, `trust_type`). `None` for the other kinds and when no sign-in names the device.
    pub device: Option<serde_json::Value>,
}

/// What a pivot table lists. `DeviceChanges` is for the device tab only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PivotOf {
    Accounts,
    Ips,
    Devices,
    Sessions,
    DeviceChanges,
}

/// One row of a pivot table.
///
/// For `Accounts`, `Ips`, `Devices` and `Sessions`: `value` is the account (lower-cased), IP, device (id, else directory
/// object id) or Entra session id, and `count`, `first_seen` and `last_seen` cover the entity's events in range that
/// carry it. `extra` holds, for Ips `country`, `asn`, `asn_org`, `ip_kind`; for Sessions `first_ip`; for Devices
/// `device_name` (also the `label`). A key whose value is unknown is left out.
///
/// For `DeviceChanges`, one row per `entra_audit` event: `value` is the operation, `label` the one-line summary,
/// `count` 1, both times the event time, `is_new` false; `extra` holds `source_table`, `record_key`, `actor`, `result`
/// and `target`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PivotRow {
    pub value: String,
    pub label: Option<String>,
    pub count: u64,
    #[serde(serialize_with = "ts_utc")]
    pub first_seen: DateTime<Utc>,
    #[serde(serialize_with = "ts_utc")]
    pub last_seen: DateTime<Utc>,
    /// The value's first UTC day (among the entity's events in the whole case, whatever the range) is later than the
    /// entity's own first day.
    pub is_new: bool,
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// A finding that cites an event of the entity.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FindingRef {
    pub finding_id: String,
    pub rule_id: Option<String>,
    pub title: String,
    pub severity: String,
    pub status: String,
    /// The finding's `first_seen`, else the first of its cited events that is in the entity's scope.
    #[serde(serialize_with = "ts_opt")]
    pub first_seen: Option<DateTime<Utc>>,
}

/// Findings that are closed for the tabs: not open.
const CLOSED: &str = "f.status NOT IN ('false_positive', 'benign')";

/// The entity's events in `[from, to]` (both inclusive, either optional), with the entity in its stored spelling.
fn scope(
    e: &Entity,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Result<(Entity, Where)> {
    let e = e.clone().normalized()?;
    let q = EventQuery {
        entity: Some(e.clone()),
        from,
        to,
        ..EventQuery::default()
    };
    let w = scope_where(&q, false)?;
    Ok((e, w))
}

/// `sql` with `extra` ANDed on (the scope always has the entity clause, so it always has a WHERE).
fn and(w: &Where, extra: &str) -> String {
    format!("{} AND {extra}", w.sql())
}

fn bound(w: &Where) -> impl Iterator<Item = &Value> {
    w.params.iter()
}

/// The tiles for `e` over `[from, to]`.
pub fn summary(
    conn: &Connection,
    e: &Entity,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Result<EntitySummary> {
    let (entity, w) = scope(e, from, to)?;

    let (events, first, last, ips, countries, asns, devices, sessions): (
        i64,
        Option<i64>,
        Option<i64>,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = conn.query_row(
        &format!(
            "SELECT count(*), epoch_us(min(e.event_time)), epoch_us(max(e.event_time)), count(DISTINCT e.ip), \
                    count(DISTINCT e.ip_country), count(DISTINCT e.asn), \
                    count(DISTINCT coalesce(e.device_id, e.device_object_id)), count(DISTINCT e.entra_session_id) \
             FROM events e{}",
            w.sql()
        ),
        params_from_iter(bound(&w)),
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        },
    )?;
    let accounts: i64 = conn.query_row(
        &format!(
            "WITH s AS (SELECT e.actor_upn, e.owner_upn FROM events e{}) \
             SELECT count(DISTINCT a) FROM (SELECT actor_upn AS a FROM s UNION ALL SELECT owner_upn FROM s)",
            w.sql()
        ),
        params_from_iter(bound(&w)),
        |r| r.get(0),
    )?;
    let distinct = BTreeMap::from([
        ("accounts".to_string(), accounts as u64),
        ("ips".to_string(), ips as u64),
        ("countries".to_string(), countries as u64),
        ("asns".to_string(), asns as u64),
        ("devices".to_string(), devices as u64),
        ("sessions".to_string(), sessions as u64),
    ]);

    let mut open_findings = BTreeMap::new();
    {
        let mut stmt = conn.prepare(&format!(
            "SELECT f.severity, count(DISTINCT f.finding_id) FROM findings f \
             JOIN finding_evidence fe ON fe.finding_id = f.finding_id \
             JOIN events e ON e.source_table = fe.source_table AND e.record_key = fe.record_key{} GROUP BY 1",
            and(&w, CLOSED)
        ))?;
        let mut rows = stmt.query(params_from_iter(bound(&w)))?;
        while let Some(r) = rows.next()? {
            open_findings.insert(r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64);
        }
    }

    let roles_matched = match &entity {
        Entity::Account(v) => roles(conn, &w, v)?,
        _ => Vec::new(),
    };
    let ip_intel = match &entity {
        Entity::Ip(v) => ip_intel_of(conn, v)?,
        _ => None,
    };
    let device = match &entity {
        Entity::Device(_) => latest_signin_device(conn, &w)?,
        _ => None,
    };
    Ok(EntitySummary {
        entity,
        first_seen: first.map(at),
        last_seen: last.map(at),
        events: events as u64,
        distinct,
        open_findings,
        roles_matched,
        ip_intel,
        device,
    })
}

/// The roles `account` plays in the rows of `w`. The actor of a message trace row is its sender and its owner its
/// recipient; the owner of the other sources is the mailbox owner.
fn roles(conn: &Connection, w: &Where, account: &str) -> Result<Vec<String>> {
    const MAIL: &str = "e.source IN ('message_trace', 'message_trace_event')";
    const MAILBOX: &str = "e.source IN ('ual', 'mail_items_accessed', 'mailbox_audit')";
    let flags: [bool; 4] = conn.query_row(
        &format!(
            "SELECT coalesce(bool_or(e.actor_upn = ? AND NOT ({MAIL})), false), \
                    coalesce(bool_or(e.owner_upn = ? AND {MAILBOX}), false), \
                    coalesce(bool_or(e.actor_upn = ? AND {MAIL}), false), \
                    coalesce(bool_or(e.owner_upn = ? AND {MAIL}), false) \
             FROM events e{}",
            w.sql()
        ),
        params_from_iter(
            std::iter::repeat_n(Value::Text(account.to_string()), 4)
                .chain(w.params.iter().cloned()),
        ),
        |r| Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?]),
    )?;
    let names = [
        "actor",
        "mailbox owner",
        "message sender",
        "message recipient",
    ];
    Ok(names
        .iter()
        .zip(flags)
        .filter(|(_, hit)| *hit)
        .map(|(n, _)| n.to_string())
        .collect())
}

/// A query_row result where "no row" is `None` and any other error stays an error.
fn no_rows_is_none<T>(r: std::result::Result<T, duckdb::Error>) -> Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(duckdb::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The `ip_intel` row of `ip` as JSON, with `ip_kind` as the events carry it (private, else microsoft, else hosting).
fn ip_intel_of(conn: &Connection, ip: &str) -> Result<Option<serde_json::Value>> {
    let text: Option<String> = no_rows_is_none(conn.query_row(
        "SELECT CAST(to_json(i) AS VARCHAR) FROM ip_intel i WHERE i.ip = ? LIMIT 1",
        [ip],
        |r| r.get(0),
    ))?;
    let Some(text) = text else { return Ok(None) };
    let mut v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| Error::Invalid(format!("ip_intel row is not JSON: {e}")))?;
    let flag = |k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
    let kind = if flag("is_private") {
        Some("private")
    } else if flag("is_microsoft") {
        Some("microsoft")
    } else if flag("is_hosting") {
        Some("hosting")
    } else {
        None
    };
    if let Some(o) = v.as_object_mut() {
        o.insert("ip_kind".into(), kind.into());
    }
    Ok(Some(v))
}

/// The `device` struct of the newest sign-in among the rows of `w`.
fn latest_signin_device(conn: &Connection, w: &Where) -> Result<Option<serde_json::Value>> {
    let text: Option<String> = no_rows_is_none(conn.query_row(
        &format!(
            "SELECT CAST(to_json(s.device) AS VARCHAR) FROM events e \
             JOIN signins s ON s.record_key = e.record_key{} \
             ORDER BY e.event_time DESC NULLS LAST, e.record_key LIMIT 1",
            and(w, "e.source_table = 'signins'")
        ),
        params_from_iter(bound(w)),
        |r| r.get(0),
    ))?
    .flatten();
    text.map(|t| {
        serde_json::from_str(&t)
            .map_err(|e| Error::Invalid(format!("signin device is not JSON: {e}")))
    })
    .transpose()
}

/// Which pivots an entity tab has: never its own kind, and device changes only on a device.
fn allowed(e: &Entity, of: PivotOf) -> bool {
    use PivotOf::*;
    match e {
        Entity::Account(_) => matches!(of, Ips | Devices | Sessions),
        Entity::Ip(_) => matches!(of, Accounts | Devices | Sessions),
        Entity::Device(_) => matches!(of, Accounts | Ips | Sessions | DeviceChanges),
        Entity::Session(_) => matches!(of, Accounts | Ips | Devices),
    }
}

/// The pivot tables an entity of this kind has, in `PivotOf` order.
pub fn pivots_of(e: &Entity) -> Vec<PivotOf> {
    use PivotOf::*;
    [Accounts, Ips, Devices, Sessions, DeviceChanges]
        .into_iter()
        .filter(|of| allowed(e, *of))
        .collect()
}

fn kind_name(e: &Entity) -> &'static str {
    match e {
        Entity::Account(_) => "account",
        Entity::Ip(_) => "IP",
        Entity::Device(_) => "device",
        Entity::Session(_) => "session",
    }
}

/// Rows a pivot returns when the caller gives no limit.
pub const PIVOT_DEFAULT_LIMIT: usize = 500;
/// The most rows one pivot call returns.
pub const PIVOT_MAX_LIMIT: usize = 5000;

/// One page of a pivot table: the first `rows` of `total`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PivotPage {
    pub rows: Vec<PivotRow>,
    /// Distinct values the table has in range (events for `DeviceChanges`), whatever the limit cut.
    pub total: u64,
}

/// One pivot table of `e` over `[from, to]`: at most `limit` rows (default `PIVOT_DEFAULT_LIMIT`, capped at
/// `PIVOT_MAX_LIMIT`; 0 is refused), by count (most events first), then value; `total` is every value the table has. A value none of
/// whose events has a time is left out (it has no first or last seen to show), from `total` too. `DeviceChanges` lists
/// its events oldest first, cut to the limit the same way.
pub fn pivot(
    conn: &Connection,
    e: &Entity,
    of: PivotOf,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    limit: Option<usize>,
) -> Result<PivotPage> {
    if limit == Some(0) {
        return Err(Error::Invalid("a pivot needs a limit of at least 1".into()));
    }
    let limit = limit.unwrap_or(PIVOT_DEFAULT_LIMIT).min(PIVOT_MAX_LIMIT);
    let (entity, w) = scope(e, from, to)?;
    if !allowed(&entity, of) {
        return Err(Error::Invalid(format!(
            "a {} tab has no {of:?} table",
            kind_name(&entity)
        )));
    }
    if of == PivotOf::DeviceChanges {
        return device_changes(conn, &w, limit);
    }
    // The same rows with no range, for "new".
    let (_, w_all) = scope(&entity, None, None)?;
    let (rows_all, mut params) = value_rows(of, &w_all);
    let (rows_rng, params_rng) = value_rows(of, &w);
    params.extend(params_rng);

    let key = "struct_pack(t := r.t, k := r.sk || r.rk)";
    let mut stmt = conn.prepare(&format!(
        "WITH a AS ({rows_all}), r AS ({rows_rng}), \
              fd AS (SELECT v, min(t) // {DAY_US} AS day FROM a WHERE v IS NOT NULL AND t IS NOT NULL GROUP BY 1), \
              ed AS (SELECT min(t) // {DAY_US} AS day FROM a) \
         SELECT r.v, count(*), min(r.t), max(r.t), coalesce(any_value(fd.day) > (SELECT day FROM ed), false), \
                max(r.ip_country), max(r.asn), max(r.asn_org), max(r.ip_kind), \
                arg_max(r.device_name, {key}) FILTER (WHERE r.device_name IS NOT NULL), \
                arg_min(r.ip, {key}) FILTER (WHERE r.ip IS NOT NULL), count(*) OVER () \
         FROM r LEFT JOIN fd ON fd.v = r.v WHERE r.v IS NOT NULL \
         GROUP BY r.v HAVING min(r.t) IS NOT NULL ORDER BY 2 DESC, 1 LIMIT {limit}"
    ))?;
    let mut out = Vec::new();
    let mut total = 0;
    let mut rows = stmt.query(params_from_iter(params.iter()))?;
    while let Some(r) = rows.next()? {
        total = r.get::<_, i64>(11)? as u64;
        let mut extra = serde_json::Map::new();
        let mut put = |k: &str, v: Option<serde_json::Value>| {
            if let Some(v) = v {
                extra.insert(k.into(), v);
            }
        };
        let (country, asn, asn_org, kind): (
            Option<String>,
            Option<i32>,
            Option<String>,
            Option<String>,
        ) = (r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?);
        let (device_name, first_ip): (Option<String>, Option<String>) = (r.get(9)?, r.get(10)?);
        let mut label = None;
        match of {
            PivotOf::Ips => {
                put("country", country.map(Into::into));
                put("asn", asn.map(Into::into));
                put("asn_org", asn_org.map(Into::into));
                put("ip_kind", kind.map(Into::into));
            }
            PivotOf::Sessions => put("first_ip", first_ip.map(Into::into)),
            PivotOf::Devices => {
                label = device_name.clone();
                put("device_name", device_name.map(Into::into));
            }
            _ => {}
        }
        out.push(PivotRow {
            value: r.get(0)?,
            label,
            count: r.get::<_, i64>(1)? as u64,
            first_seen: at(r.get(2)?),
            last_seen: at(r.get(3)?),
            is_new: r.get(4)?,
            extra,
        });
    }
    Ok(PivotPage { rows: out, total })
}

/// The rows `of` is counted over, one per (event, value): `v` the value, `t` the event time in microseconds, `sk`/`rk`
/// the event key, and what the extras need. For accounts an event counts for its actor and for its owner (once when
/// they are the same account).
fn value_rows(of: PivotOf, w: &Where) -> (String, Vec<Value>) {
    let cols = |v: &str, guard: &str| {
        format!(
            "SELECT {v} AS v, epoch_us(e.event_time) AS t, e.source_table AS sk, e.record_key AS rk, e.ip, \
                    e.ip_country, e.asn, e.asn_org, e.ip_kind, e.device_name FROM events e{}{guard}",
            w.sql()
        )
    };
    let once = |v: &str| (cols(v, ""), w.params.clone());
    match of {
        PivotOf::Accounts => {
            let mut params = w.params.clone();
            params.extend(w.params.iter().cloned());
            (
                format!(
                    "{} UNION ALL {}",
                    cols("e.actor_upn", ""),
                    cols(
                        "e.owner_upn",
                        " AND e.owner_upn IS DISTINCT FROM e.actor_upn"
                    )
                ),
                params,
            )
        }
        PivotOf::Ips => once("e.ip"),
        PivotOf::Devices => once("coalesce(e.device_id, e.device_object_id)"),
        PivotOf::Sessions => once("e.entra_session_id"),
        PivotOf::DeviceChanges => unreachable!("device changes are listed, not pivoted"),
    }
}

/// The directory audit events that name the device, oldest first.
fn device_changes(conn: &Connection, w: &Where, limit: usize) -> Result<PivotPage> {
    let mut stmt = conn.prepare(&format!(
        "SELECT e.operation, e.summary, epoch_us(e.event_time), e.source_table, e.record_key, e.actor_upn, e.result, \
                e.target, count(*) OVER () \
         FROM events e{} ORDER BY e.event_time, e.record_key LIMIT {limit}",
        and(w, "e.source = 'entra_audit' AND e.event_time IS NOT NULL")
    ))?;
    let mut out = Vec::new();
    let mut total = 0;
    let mut rows = stmt.query(params_from_iter(bound(w)))?;
    while let Some(r) = rows.next()? {
        total = r.get::<_, i64>(8)? as u64;
        let time = at(r.get(2)?);
        let mut extra = serde_json::Map::new();
        extra.insert("source_table".into(), r.get::<_, String>(3)?.into());
        extra.insert("record_key".into(), r.get::<_, String>(4)?.into());
        for (i, k) in [(5, "actor"), (6, "result"), (7, "target")] {
            if let Some(v) = r.get::<_, Option<String>>(i)? {
                extra.insert(k.into(), v.into());
            }
        }
        out.push(PivotRow {
            value: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
            label: r.get(1)?,
            count: 1,
            first_seen: time,
            last_seen: time,
            is_new: false,
            extra,
        });
    }
    Ok(PivotPage { rows: out, total })
}

/// The open findings (every status but `false_positive` and `benign`) that cite an event of `e` in `[from, to]`, oldest
/// first, then by id.
pub fn findings(
    conn: &Connection,
    e: &Entity,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Result<Vec<FindingRef>> {
    let (_, w) = scope(e, from, to)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT f.finding_id, f.rule_id, f.title, f.severity, CAST(f.status AS VARCHAR), \
                epoch_us(coalesce(f.first_seen, m.mn)) \
         FROM findings f \
         JOIN (SELECT fe.finding_id, min(e.event_time) AS mn FROM finding_evidence fe \
               JOIN events e ON e.source_table = fe.source_table AND e.record_key = fe.record_key{} \
               GROUP BY 1) m ON m.finding_id = f.finding_id \
         WHERE {CLOSED} ORDER BY 6 NULLS LAST, f.finding_id",
        w.sql()
    ))?;
    let mut out = Vec::new();
    let mut rows = stmt.query(params_from_iter(bound(&w)))?;
    while let Some(r) = rows.next()? {
        out.push(FindingRef {
            finding_id: r.get(0)?,
            rule_id: r.get(1)?,
            title: r.get(2)?,
            severity: r.get(3)?,
            status: r.get(4)?,
            first_seen: r.get::<_, Option<i64>>(5)?.map(at),
        });
    }
    Ok(out)
}

/// What the coverage strip needs of an entity: when its events start and end in the whole case, and for each tenant
/// the accounts in them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageScope {
    /// The entity's first and last event in the whole case (the default days of the strip).
    pub first: Option<DateTime<Utc>>,
    pub last: Option<DateTime<Utc>>,
    /// Tenant key -> lower-cased accounts (actor and mailbox owner / recipient), sorted. They come from the entity's
    /// events in `[from, to]`; when none of its events fall in the range, from its events in the whole case, since
    /// the strip judges that range all the same. An account entity's own account is always among them. A tenant whose
    /// events name no account (a spray IP) has an empty list. Events with no tenant are left out.
    pub tenants: BTreeMap<String, Vec<String>>,
}

/// The tenants and accounts of the entity's events matched by `w`.
fn tenant_accounts(conn: &Connection, w: &Where) -> Result<BTreeMap<String, Vec<String>>> {
    let mut tenants: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut stmt = conn.prepare(&format!(
        "WITH s AS (SELECT e.tenant_key, e.actor_upn, e.owner_upn FROM events e{} AND e.tenant_key IS NOT NULL) \
         SELECT DISTINCT tenant_key, a FROM (SELECT tenant_key, actor_upn AS a FROM s \
                                             UNION ALL SELECT tenant_key, owner_upn FROM s) ORDER BY 1, 2",
        w.sql()
    ))?;
    let mut rows = stmt.query(params_from_iter(bound(w)))?;
    while let Some(r) = rows.next()? {
        let list = tenants.entry(r.get::<_, String>(0)?).or_default();
        if let Some(a) = r
            .get::<_, Option<String>>(1)?
            .filter(|a| !a.trim().is_empty())
        {
            list.push(a);
        }
    }
    Ok(tenants)
}

/// The entity's first and last event in the whole case and its tenants and accounts, from `[from, to]` or, when no
/// event of the entity falls there, from the whole case.
pub fn coverage_scope(
    conn: &Connection,
    e: &Entity,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Result<CoverageScope> {
    let (e, whole) = scope(e, None, None)?;
    let (first, last): (Option<i64>, Option<i64>) = conn.query_row(
        &format!(
            "SELECT epoch_us(min(e.event_time)), epoch_us(max(e.event_time)) FROM events e{}",
            whole.sql()
        ),
        params_from_iter(bound(&whole)),
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let mut tenants = if from.is_some() || to.is_some() {
        let (_, w) = scope(&e, from, to)?;
        let in_range: i64 = conn.query_row(
            &format!("SELECT count(*) FROM events e{}", w.sql()),
            params_from_iter(bound(&w)),
            |r| r.get(0),
        )?;
        tenant_accounts(conn, if in_range > 0 { &w } else { &whole })?
    } else {
        tenant_accounts(conn, &whole)?
    };
    if let Entity::Account(own) = &e {
        let own = own.trim().to_lowercase();
        for list in tenants.values_mut() {
            if !list.contains(&own) {
                list.push(own.clone());
                list.sort();
            }
        }
    }
    Ok(CoverageScope {
        first: first.map(at),
        last: last.map(at),
        tenants,
    })
}
