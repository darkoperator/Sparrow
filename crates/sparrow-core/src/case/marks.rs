//! Analyst and agent marks on events: flags (Suspicious / Malicious) on single rows and as standing flags on a value,
//! and free-text tags. Marks live in their own tables keyed by `(source_table, record_key)` or by value, never in the
//! derived `events` table, so they survive an events rebuild and a re-ingest; evidence tables are never written.
//!
//! - **Effective flag.** A row's flag is the strongest of its own `event_flags` row and every active `value_flags` row
//!   whose value matches the row's column and whose scope, if it has one, matches the row (the entity rule of an entity
//!   tab). A value flag therefore covers events ingested after it was made.
//! - **Who and review.** An analyst's mark is `accepted` when made; an agent's is `pending_review`. Confirm and remove
//!   go through `case::review` like every other decision ([`review_marks`] for the rows of a grid selection,
//!   `review::review_accept` / `review_discard` for one decision): a discard removes the flag or tag the agent added
//!   and restores a flag it changed, from the audit entry of its decision. Agent marks are **not** Review-queue items
//!   (`review::pending` lists findings, indicators and timeline entries only).
//! - **Audit.** One `audit_trail` row per call, never per event. Object types: `event_flag` and `event_tag` (the object
//!   is the call: `object_id` is a batch id stored on the rows it set) and `value_flag` (the object is the flag). The
//!   row list goes in `after`; above [`INLINE_ROWS`] rows only their count and a SHA-256 of the sorted keys are stored.
//!   An agent call is limited to [`MAX_AGENT_ROWS`] rows, so what a discard restores is always in the audit entry;
//!   a standing value flag covers any number.
//! - **Indicators.** Malicious by value on an `ip` adds or updates an `ip` indicator, on an `account` a `upn`
//!   indicator, one per tenant of the matching events, in the same transaction and by the same actor (so an agent's is
//!   pending review in the Review queue, as for any indicator). `ip_prefix`, `asn`, `device` and `session` make none:
//!   `IndicatorType` has no such kinds. Clearing a flag never removes an indicator; Suspicious never creates one.

use crate::case::actor::{Actor, Reviewer};
use crate::case::audit::{self, AuditEntry};
use crate::case::events::{Entity, prefix_of};
use crate::case::indicators::{self, IndicatorType, Verdict};
use crate::case::review;
use crate::case::write::{DECISION_TAGS, in_tx, self_review};
use crate::normalize::net::normalize_ip;
use crate::{Error, Result};
use duckdb::types::Value;
use duckdb::{Connection, OptionalExt, params, params_from_iter};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// Rows of one agent call: the audit entry of an agent decision holds every row and what it replaced, which a discard
/// restores from. Use a standing value flag for more.
pub const MAX_AGENT_ROWS: usize = 1000;
/// Rows of one analyst call.
pub const MAX_ROWS: usize = 100_000;
/// Up to this many rows are listed in an audit entry; more are stored as a count and a SHA-256 of their sorted keys.
pub const INLINE_ROWS: usize = 1000;
/// Rows per statement when a call touches many.
const CHUNK: usize = 400;
/// Longest tag name, in characters.
pub const MAX_TAG_CHARS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagLevel {
    Suspicious,
    Malicious,
}

impl FlagLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            FlagLevel::Suspicious => "suspicious",
            FlagLevel::Malicious => "malicious",
        }
    }

    pub fn parse(s: &str) -> Result<FlagLevel> {
        match s {
            "suspicious" => Ok(FlagLevel::Suspicious),
            "malicious" => Ok(FlagLevel::Malicious),
            other => Err(Error::Invalid(format!(
                "unknown flag level {other:?} (suspicious or malicious)"
            ))),
        }
    }
}

/// An event row: the key of `events`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RowRef {
    pub source_table: String,
    pub record_key: String,
}

impl RowRef {
    pub fn new(source_table: &str, record_key: &str) -> RowRef {
        RowRef {
            source_table: source_table.into(),
            record_key: record_key.into(),
        }
    }
}

/// What a standing value flag matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueKind {
    Ip,
    IpPrefix,
    Account,
    Asn,
    Device,
    Session,
}

impl ValueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ValueKind::Ip => "ip",
            ValueKind::IpPrefix => "ip_prefix",
            ValueKind::Account => "account",
            ValueKind::Asn => "asn",
            ValueKind::Device => "device",
            ValueKind::Session => "session",
        }
    }

    pub fn parse(s: &str) -> Result<ValueKind> {
        [
            ValueKind::Ip,
            ValueKind::IpPrefix,
            ValueKind::Account,
            ValueKind::Asn,
            ValueKind::Device,
            ValueKind::Session,
        ]
        .into_iter()
        .find(|k| k.as_str() == s)
        .ok_or_else(|| {
            Error::Invalid(format!(
                "unknown flag value kind {s:?} (ip, ip_prefix, account, asn, device or session)"
            ))
        })
    }

    /// The stored spelling of `value`, or an error when it is not one.
    pub fn normalize(self, value: &str) -> Result<String> {
        let v = value.trim();
        let bad = |what: &str| Error::Invalid(format!("{v:?} is not {what}"));
        match self {
            ValueKind::Ip => Ok(Entity::Ip(v.into()).normalized()?.value().to_string()),
            ValueKind::IpPrefix => {
                // The prefix of the address, or of the network text itself, in the spelling of `events.ip_prefix`.
                let net = v.split_once('/').map_or(v, |(net, _)| net);
                normalize_ip(net)
                    .filter(|n| n.parse::<IpAddr>().is_ok())
                    .and_then(|n| prefix_of(&n))
                    .ok_or_else(|| bad("an IP address or network"))
            }
            ValueKind::Asn => v
                .trim_start_matches("AS")
                .trim_start_matches("as")
                .parse::<u32>()
                .map(|n| n.to_string())
                .map_err(|_| bad("an ASN number")),
            ValueKind::Account => Ok(Entity::Account(v.into()).normalized()?.value().to_string()),
            ValueKind::Device => Ok(Entity::Device(v.into()).normalized()?.value().to_string()),
            ValueKind::Session => Ok(Entity::Session(v.into()).normalized()?.value().to_string()),
        }
    }
}

/// A tag on an event row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagRef {
    pub name: String,
    /// An agent's tag that no analyst has confirmed yet.
    #[serde(default)]
    pub ai: bool,
}

/// A tag name in use: how many rows carry it and how many of those are agent tags awaiting review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TagInfo {
    pub name: String,
    pub count: u64,
    pub agent_unreviewed: u64,
}

// ---------------------------------------------------------------------------------------------------------------
// helpers

fn is_agent(actor: &Actor) -> bool {
    !actor.is_analyst()
}

fn sha_hex(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0x1f]);
    }
    hex::encode(h.finalize())
}

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

fn opt(s: Option<&str>) -> Value {
    s.map_or(Value::Null, text)
}

/// `(VALUES (CAST(? AS VARCHAR), CAST(? AS VARCHAR)), ...) v(t, k)` for `n` rows and the parameters of `rows`.
fn values_of(rows: &[RowRef]) -> (String, Vec<Value>) {
    let one = "(CAST(? AS VARCHAR), CAST(? AS VARCHAR))";
    let sql = format!("(VALUES {}) v(t, k)", vec![one; rows.len()].join(", "));
    let params = rows
        .iter()
        .flat_map(|r| [text(&r.source_table), text(&r.record_key)])
        .collect();
    (sql, params)
}

/// `rows` sorted and without repeats; refused when empty, over `limit`, or naming a table that is not an event table.
fn clean_rows(rows: &[RowRef], limit: usize) -> Result<Vec<RowRef>> {
    let set: BTreeSet<RowRef> = rows.iter().cloned().collect();
    if set.is_empty() {
        return Err(Error::Invalid("no event rows given".into()));
    }
    if set.len() > limit {
        return Err(Error::Invalid(format!(
            "{} event rows in one call; the limit is {limit}{}",
            set.len(),
            if limit == MAX_AGENT_ROWS {
                " for an agent (flag a value instead of rows)"
            } else {
                ""
            }
        )));
    }
    for r in &set {
        if r.source_table.is_empty() || r.record_key.is_empty() {
            return Err(Error::Invalid(
                "an event row needs a source table and a record key".into(),
            ));
        }
    }
    Ok(set.into_iter().collect())
}

fn row_limit(actor: &Actor) -> usize {
    if is_agent(actor) {
        MAX_AGENT_ROWS
    } else {
        MAX_ROWS
    }
}

/// Every row is an event of the case.
fn check_events_exist(tx: &Connection, rows: &[RowRef]) -> Result<()> {
    for chunk in rows.chunks(CHUNK) {
        let (values, params) = values_of(chunk);
        let mut stmt = tx.prepare(&format!(
            "SELECT v.t, v.k FROM {values} WHERE NOT EXISTS \
             (SELECT 1 FROM events e WHERE e.source_table = v.t AND e.record_key = v.k) ORDER BY 1, 2 LIMIT 1"
        ))?;
        let mut r = stmt.query(params_from_iter(params.iter()))?;
        if let Some(row) = r.next()? {
            return Err(Error::Decision(format!(
                "unknown event {}:{}",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?
            )));
        }
    }
    Ok(())
}

/// The id of one marking call: its actor, kind, time and rows.
fn batch_id(actor: &Actor, what: &str, ts_us: i64, rows: &[RowRef]) -> String {
    let mut parts = vec![
        actor.as_str().to_string(),
        what.to_string(),
        ts_us.to_string(),
    ];
    parts.extend(
        rows.iter()
            .map(|r| format!("{}:{}", r.source_table, r.record_key)),
    );
    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    sha_hex(&refs)[..16].to_string()
}

/// The rows as audit JSON: listed up to [`INLINE_ROWS`], else a count and a SHA-256 of their sorted keys.
fn rows_json(rows: &[RowRef]) -> Json {
    if rows.len() <= INLINE_ROWS {
        json!({ "rows": rows.iter().map(|r| json!([r.source_table, r.record_key])).collect::<Vec<_>>() })
    } else {
        let lines: Vec<String> = rows
            .iter()
            .map(|r| format!("{}\x1f{}\n", r.source_table, r.record_key))
            .collect();
        let mut h = Sha256::new();
        for l in &lines {
            h.update(l.as_bytes());
        }
        json!({ "row_count": rows.len(), "rows_sha256": hex::encode(h.finalize()) })
    }
}

/// A mark row as stored (flags and tags share these columns).
#[derive(Debug, Clone)]
struct Mark {
    row: RowRef,
    level: Option<String>,
    decided_by: String,
    decided_at: i64,
    on_behalf_of: Option<String>,
    review_state: String,
    reviewed_by: Option<String>,
    reviewed_at: Option<i64>,
    review_comment: Option<String>,
    batch_id: String,
}

fn ts_json(us: Option<i64>) -> Json {
    us.and_then(chrono::DateTime::from_timestamp_micros)
        .map_or(Json::Null, |t| Json::String(audit::ts_text(&t)))
}

impl Mark {
    fn json(&self) -> Json {
        json!({
            "source_table": self.row.source_table, "record_key": self.row.record_key, "level": self.level,
            "decided_by": self.decided_by, "decided_at": ts_json(Some(self.decided_at)),
            "on_behalf_of": self.on_behalf_of, "review_state": self.review_state,
            "reviewed_by": self.reviewed_by, "reviewed_at": ts_json(self.reviewed_at),
            "review_comment": self.review_comment, "batch_id": self.batch_id,
        })
    }
}

const MARK_COLUMNS: &str = "m.source_table, m.record_key, {level}, m.decided_by, epoch_us(m.decided_at), \
     m.on_behalf_of, CAST(m.review_state AS VARCHAR), m.reviewed_by, epoch_us(m.reviewed_at), m.review_comment, m.batch_id";

fn mark_of(r: &duckdb::Row) -> duckdb::Result<Mark> {
    Ok(Mark {
        row: RowRef {
            source_table: r.get(0)?,
            record_key: r.get(1)?,
        },
        level: r.get(2)?,
        decided_by: r.get(3)?,
        decided_at: r.get(4)?,
        on_behalf_of: r.get(5)?,
        review_state: r.get(6)?,
        reviewed_by: r.get(7)?,
        reviewed_at: r.get(8)?,
        review_comment: r.get(9)?,
        batch_id: r.get(10)?,
    })
}

/// The flags of `rows` that exist.
fn flags_of(tx: &Connection, rows: &[RowRef]) -> Result<BTreeMap<RowRef, Mark>> {
    let mut out = BTreeMap::new();
    for chunk in rows.chunks(CHUNK) {
        let (values, params) = values_of(chunk);
        let mut stmt = tx.prepare(&format!(
            "SELECT {} FROM event_flags m WHERE (m.source_table, m.record_key) IN (SELECT t, k FROM {values})",
            MARK_COLUMNS.replace("{level}", "CAST(m.level AS VARCHAR)")
        ))?;
        for m in stmt.query_map(params_from_iter(params.iter()), mark_of)? {
            let m = m?;
            out.insert(m.row.clone(), m);
        }
    }
    Ok(out)
}

/// The rows of `rows` that carry tag `tag_id`.
fn tags_of(tx: &Connection, tag_id: &str, rows: &[RowRef]) -> Result<BTreeMap<RowRef, Mark>> {
    let mut out = BTreeMap::new();
    for chunk in rows.chunks(CHUNK) {
        let (values, mut params) = values_of(chunk);
        params.insert(0, text(tag_id));
        let mut stmt = tx.prepare(&format!(
            "SELECT {} FROM event_tags m WHERE m.tag_id = ? \
             AND (m.source_table, m.record_key) IN (SELECT t, k FROM {values})",
            MARK_COLUMNS.replace("{level}", "CAST(NULL AS VARCHAR)")
        ))?;
        for m in stmt.query_map(params_from_iter(params.iter()), mark_of)? {
            let m = m?;
            out.insert(m.row.clone(), m);
        }
    }
    Ok(out)
}

/// The decision tags of a new mark by `actor` at `ts`: its state, reviewer and review time.
struct Decision {
    decided_by: String,
    ts: String,
    on_behalf_of: Option<String>,
    review_state: &'static str,
    reviewed_by: Option<String>,
    batch: String,
}

impl Decision {
    fn new(actor: &Actor, ts: &chrono::DateTime<chrono::Utc>, batch: &str) -> Decision {
        let analyst = actor.is_analyst();
        Decision {
            decided_by: actor.as_str().to_string(),
            ts: audit::ts_text(ts),
            on_behalf_of: actor.on_behalf_of().map(str::to_string),
            review_state: if analyst {
                "accepted"
            } else {
                "pending_review"
            },
            // An analyst's decision is reviewed when made, by the same analyst.
            reviewed_by: analyst.then(|| actor.as_str().to_string()),
            batch: batch.to_string(),
        }
    }

    /// Parameters after the leading ones: decided_by, decided_at, on_behalf_of, review_state, reviewed_by, reviewed_at,
    /// batch_id.
    fn params(&self) -> Vec<Value> {
        vec![
            text(&self.decided_by),
            text(&self.ts),
            opt(self.on_behalf_of.as_deref()),
            text(self.review_state),
            opt(self.reviewed_by.as_deref()),
            self.reviewed_by
                .as_ref()
                .map_or(Value::Null, |_| text(&self.ts)),
            text(&self.batch),
        ]
    }
}

fn insert_flags(tx: &Connection, rows: &[RowRef], level: FlagLevel, d: &Decision) -> Result<()> {
    for chunk in rows.chunks(CHUNK / 4) {
        let one = "(?, ?, CAST(? AS flag_level), ?, CAST(? AS TIMESTAMPTZ), ?, CAST(? AS review_state), ?, \
                   CAST(? AS TIMESTAMPTZ), ?)";
        let mut params = Vec::new();
        for r in chunk {
            params.extend([
                text(&r.source_table),
                text(&r.record_key),
                text(level.as_str()),
            ]);
            params.extend(d.params());
        }
        tx.execute(
            &format!(
                "INSERT INTO event_flags (source_table, record_key, level, decided_by, decided_at, on_behalf_of, \
                 review_state, reviewed_by, reviewed_at, batch_id) VALUES {}",
                vec![one; chunk.len()].join(", ")
            ),
            params_from_iter(params.iter()),
        )?;
    }
    Ok(())
}

fn update_flags(tx: &Connection, rows: &[RowRef], level: FlagLevel, d: &Decision) -> Result<()> {
    for chunk in rows.chunks(CHUNK) {
        let (values, vparams) = values_of(chunk);
        let mut params = vec![text(level.as_str())];
        params.extend(d.params());
        params.extend(vparams);
        tx.execute(
            &format!(
                "UPDATE event_flags SET level = CAST(? AS flag_level), decided_by = ?, decided_at = CAST(? AS TIMESTAMPTZ), \
                 on_behalf_of = ?, review_state = CAST(? AS review_state), reviewed_by = ?, \
                 reviewed_at = CAST(? AS TIMESTAMPTZ), review_comment = NULL, batch_id = ? \
                 WHERE (source_table, record_key) IN (SELECT t, k FROM {values})"
            ),
            params_from_iter(params.iter()),
        )?;
    }
    Ok(())
}

fn delete_rows(
    tx: &Connection,
    table: &str,
    extra: &str,
    extra_params: &[Value],
    rows: &[RowRef],
) -> Result<()> {
    for chunk in rows.chunks(CHUNK) {
        let (values, vparams) = values_of(chunk);
        let mut params = extra_params.to_vec();
        params.extend(vparams);
        tx.execute(
            &format!(
                "DELETE FROM {table} WHERE {extra}(source_table, record_key) IN (SELECT t, k FROM {values})"
            ),
            params_from_iter(params.iter()),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// flags on rows

/// Set (`Some`) or clear (`None`) the flag of event rows, in one transaction with one audit row (`flag_rows`, object
/// `event_flag`). A row already carrying exactly that flag, confirmed, is left alone; the call fails when that leaves
/// nothing to do.
///
/// - An analyst's flag is accepted; an agent's is pending review. An analyst replaces a pending agent flag (the call
///   both decides and reviews it); an agent may change any flag, and a discard restores what it changed.
/// - Clearing deletes the rows' flags; the audit entry's `before` keeps what was removed. An agent may clear only its
///   own pending flags.
pub fn flag_rows(
    conn: &Connection,
    actor: &Actor,
    rows: &[RowRef],
    level: Option<FlagLevel>,
) -> Result<AuditEntry> {
    let rows = clean_rows(rows, row_limit(actor))?;
    in_tx(conn, |tx| {
        check_events_exist(tx, &rows)?;
        let existing = flags_of(tx, &rows)?;
        let ts = audit::now();
        let batch = batch_id(
            actor,
            level.map_or("clear", FlagLevel::as_str),
            ts.timestamp_micros(),
            &rows,
        );
        let d = Decision::new(actor, &ts, &batch);
        let (before, after) = match level {
            Some(level) => {
                let mut insert = Vec::new();
                let mut update = Vec::new();
                let mut replaced = Vec::new();
                for r in &rows {
                    match existing.get(r) {
                        Some(m)
                            if m.level.as_deref() == Some(level.as_str())
                                && m.review_state == "accepted" => {}
                        Some(m) => {
                            update.push(r.clone());
                            replaced.push(m.json());
                        }
                        None => insert.push(r.clone()),
                    }
                }
                if insert.is_empty() && update.is_empty() {
                    return Err(Error::Decision(format!(
                        "{} of these rows already carry the {} flag",
                        rows.len(),
                        level.as_str()
                    )));
                }
                insert_flags(tx, &insert, level, &d)?;
                update_flags(tx, &update, level, &d)?;
                let mut changed: Vec<RowRef> =
                    insert.iter().chain(update.iter()).cloned().collect();
                changed.sort();
                let mut after = rows_json(&changed);
                after["level"] = json!(level.as_str());
                (marks_before(replaced), Some(after))
            }
            None => {
                let mut gone = Vec::new();
                let mut not_own = 0;
                for r in &rows {
                    let Some(m) = existing.get(r) else { continue };
                    if is_agent(actor)
                        && !(m.decided_by == actor.as_str() && m.review_state == "pending_review")
                    {
                        not_own += 1;
                    }
                    gone.push(m);
                }
                if gone.is_empty() {
                    return Err(Error::Decision(
                        "none of these rows has a flag of its own".into(),
                    ));
                }
                if not_own > 0 {
                    return Err(Error::Decision(format!(
                        "{} of these flags were not made by this agent or were reviewed; an agent clears only its \
                         own pending flags",
                        not_own
                    )));
                }
                let keys: Vec<RowRef> = gone.iter().map(|m| m.row.clone()).collect();
                let before = marks_before(gone.iter().map(|m| m.json()).collect());
                // An agent undoing its own pending change puts back what its decision replaced (an analyst's
                // flag stays); only a flag it added is deleted. An analyst's clear removes the flag.
                let prior = if is_agent(actor) {
                    prior_flags(tx, &gone)?
                } else {
                    BTreeMap::new()
                };
                let (back, remove): (Vec<&RowRef>, Vec<&RowRef>) =
                    keys.iter().partition(|k| prior.contains_key(*k));
                let mut restored = Vec::new();
                for k in &back {
                    let m = &prior[*k];
                    restore_flag_row(tx, k, m)?;
                    restored.push(json!([k.source_table, k.record_key, m["level"]]));
                }
                let remove: Vec<RowRef> = remove.into_iter().cloned().collect();
                delete_rows(tx, "event_flags", "", &[], &remove)?;
                let mut after = rows_json(&keys);
                after["level"] = Json::Null;
                if !restored.is_empty() {
                    after["restored"] = Json::Array(restored);
                }
                (before, Some(after))
            }
        };
        audit::append_at(
            tx,
            ts,
            actor.as_str(),
            actor.on_behalf_of(),
            "flag_rows",
            "event_flag",
            &batch,
            before.as_ref(),
            after.as_ref(),
            None,
        )
    })
}

/// The `before` of a marking call: the mark rows it replaced or removed (listed up to [`INLINE_ROWS`], else counted
/// and hashed), or `None` when there were none.
fn marks_before(prior: Vec<Json>) -> Option<Json> {
    if prior.is_empty() {
        return None;
    }
    if prior.len() <= INLINE_ROWS {
        return Some(json!({ "marks": prior }));
    }
    let mut lines: Vec<String> = prior.iter().map(audit::canonical).collect();
    lines.sort();
    let mut h = Sha256::new();
    for l in &lines {
        h.update(l.as_bytes());
        h.update(b"\n");
    }
    Some(json!({ "mark_count": prior.len(), "marks_sha256": hex::encode(h.finalize()) }))
}

// ---------------------------------------------------------------------------------------------------------------
// standing flags on a value

fn flag_id(kind: ValueKind, value: &str, scope: Option<&Entity>) -> String {
    sha_hex(&[
        kind.as_str(),
        value,
        scope.map_or("", Entity::kind_name),
        scope.map_or("", Entity::value),
    ])[..16]
        .to_string()
}

/// The decision-bearing state of a value flag as JSON (the audit `before` / `after`, and what a discard restores);
/// `None` when it does not exist.
pub(crate) fn value_flag_state(conn: &Connection, id: &str) -> Result<Option<Json>> {
    Ok(conn
        .query_row(
            "SELECT CAST(kind AS VARCHAR), value, scope_kind, scope_value, CAST(level AS VARCHAR), epoch_us(removed_at), \
                    removed_by, decided_by, on_behalf_of, CAST(review_state AS VARCHAR) \
             FROM value_flags WHERE flag_id = ?",
            params![id],
            |r| {
                Ok(json!({
                    "kind": r.get::<_, String>(0)?,
                    "value": r.get::<_, String>(1)?,
                    "scope_kind": r.get::<_, Option<String>>(2)?,
                    "scope_value": r.get::<_, Option<String>>(3)?,
                    "level": r.get::<_, String>(4)?,
                    "removed_at": ts_json(r.get::<_, Option<i64>>(5)?),
                    "removed_by": r.get::<_, Option<String>>(6)?,
                    "decided_by": r.get::<_, String>(7)?,
                    "on_behalf_of": r.get::<_, Option<String>>(8)?,
                    "review_state": r.get::<_, String>(9)?,
                }))
            },
        )
        .optional()?)
}

/// The tenants of the events a value flag covers (`None`: matching events without one), for the indicator it makes.
/// No matching event gives no tenant, so no indicator: an unseen value is not attributed to every tenant.
fn tenants_of(
    tx: &Connection,
    kind: ValueKind,
    value: &str,
    scope: Option<&Entity>,
) -> Result<Vec<Option<String>>> {
    let entity = match kind {
        ValueKind::Ip => Entity::Ip(value.into()),
        _ => Entity::Account(value.into()),
    };
    let (mut sql, mut params) = entity.clause();
    if let Some(s) = scope {
        let (s_sql, s_params) = s.clause();
        sql = format!("{sql} AND {s_sql}");
        params.extend(s_params);
    }
    let mut stmt = tx.prepare(&format!(
        "SELECT DISTINCT e.tenant_key FROM events e WHERE {sql} ORDER BY 1 NULLS FIRST"
    ))?;
    let found = stmt
        .query_map(params_from_iter(params.iter()), |r| {
            r.get::<_, Option<String>>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(found)
}

/// Set (`Some`) or clear (`None`) a standing flag on a value, in one transaction with one audit row (`flag_value`,
/// object `value_flag`). Every event whose column matches the value is flagged, including events ingested later; with
/// a `scope` only that entity's events are. Clearing sets `removed_at` and leaves direct row flags alone.
///
/// Malicious on an `ip` or an `account` also adds or updates an `ip` / `upn` indicator (module docs). An analyst
/// cannot flag a value whose indicator an agent has pending: the indicator step refuses and nothing is written.
pub fn flag_value(
    conn: &Connection,
    actor: &Actor,
    kind: ValueKind,
    value: &str,
    scope: Option<&Entity>,
    level: Option<FlagLevel>,
) -> Result<AuditEntry> {
    flag_value_with_indicators(conn, actor, kind, value, scope, level).map(|(entry, _)| entry)
}

/// An indicator [`flag_value_with_indicators`] added or updated (one per tenant of the matching events).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndicatorChange {
    pub tenant_key: Option<String>,
    pub indicator_id: String,
    /// The indicator did not exist before this flag.
    pub created: bool,
}

/// [`flag_value`], also returning the indicators a Malicious flag on an IP or account added or updated. Empty when the
/// flag makes none: another level or kind, or no event matches the value so there is no tenant to attach one to.
pub fn flag_value_with_indicators(
    conn: &Connection,
    actor: &Actor,
    kind: ValueKind,
    value: &str,
    scope: Option<&Entity>,
    level: Option<FlagLevel>,
) -> Result<(AuditEntry, Vec<IndicatorChange>)> {
    let value = kind.normalize(value)?;
    let scope = scope.cloned().map(Entity::normalized).transpose()?;
    let id = flag_id(kind, &value, scope.as_ref());
    in_tx(conn, |tx| {
        let before = value_flag_state(tx, &id)?;
        let active = before.as_ref().is_some_and(|b| b["removed_at"].is_null());
        let ts = audit::now();
        let ts_text = audit::ts_text(&ts);
        match level {
            None => {
                if !active {
                    return Err(Error::Decision(format!(
                        "no active {} flag on {value:?}{}",
                        kind.as_str(),
                        scope.as_ref().map_or(String::new(), |s| format!(
                            " in {} {}",
                            s.kind_name(),
                            s.value()
                        ))
                    )));
                }
                tx.execute(
                    "UPDATE value_flags SET removed_at = CAST(? AS TIMESTAMPTZ), removed_by = ? WHERE flag_id = ?",
                    params![ts_text, actor.as_str(), id],
                )?;
            }
            Some(level) if before.is_none() => {
                tx.execute(
                    "INSERT INTO value_flags (flag_id, kind, value, level, scope_kind, scope_value, decided_by, decided_at, \
                     review_state) VALUES (?, CAST(? AS flag_value_kind), ?, CAST(? AS flag_level), ?, ?, ?, \
                     CAST(? AS TIMESTAMPTZ), 'pending_review')",
                    params![
                        id,
                        kind.as_str(),
                        value,
                        level.as_str(),
                        scope.as_ref().map(Entity::kind_name),
                        scope.as_ref().map(Entity::value),
                        actor.as_str(),
                        ts_text
                    ],
                )?;
            }
            Some(level) => {
                // The same flag, already confirmed: nothing to change, and an agent must not turn an analyst's
                // confirmed flag back into a pending one.
                if active
                    && before.as_ref().is_some_and(|b| {
                        b["level"] == level.as_str() && b["review_state"] == "accepted"
                    })
                {
                    return Err(Error::Decision(format!(
                        "{} {value:?} is already flagged {}",
                        kind.as_str(),
                        level.as_str()
                    )));
                }
                tx.execute(
                    "UPDATE value_flags SET level = CAST(? AS flag_level), removed_at = NULL, removed_by = NULL \
                     WHERE flag_id = ?",
                    params![level.as_str(), id],
                )?;
            }
        }
        tx.execute(
            &format!("UPDATE value_flags SET {DECISION_TAGS} WHERE flag_id = ?"),
            params![actor.as_str(), ts_text, actor.on_behalf_of(), id],
        )?;
        self_review(tx, "value_flags", "flag_id", &id, actor)?;
        let after = value_flag_state(tx, &id)?;
        let mut changed = Vec::new();
        if level == Some(FlagLevel::Malicious) {
            let ty = match kind {
                ValueKind::Ip => Some(IndicatorType::Ip),
                ValueKind::Account => Some(IndicatorType::Upn),
                _ => None,
            };
            if let Some(ty) = ty {
                for tenant in tenants_of(tx, kind, &value, scope.as_ref())? {
                    // An indicator that exists keeps its note.
                    let iid = indicators::indicator_id(tenant.as_deref(), ty, &value);
                    let existing = indicators::indicator_state(tx, &iid)?;
                    let created = existing.is_none();
                    let note = existing
                        .and_then(|s| s["note"].as_str().map(str::to_string))
                        .unwrap_or_else(|| "flagged malicious in the events grid".into());
                    indicators::add_indicator_in(
                        tx,
                        actor,
                        tenant.as_deref(),
                        ty,
                        &value,
                        Verdict::Malicious,
                        Some(&note),
                        None,
                    )?;
                    changed.push(IndicatorChange {
                        tenant_key: tenant,
                        indicator_id: iid,
                        created,
                    });
                }
            }
        }
        let entry = audit::append_at(
            tx,
            ts,
            actor.as_str(),
            actor.on_behalf_of(),
            "flag_value",
            "value_flag",
            &id,
            before.as_ref(),
            after.as_ref(),
            None,
        )?;
        Ok((entry, changed))
    })
}

// ---------------------------------------------------------------------------------------------------------------
// tags

/// A tag name in its stored spelling: trimmed and lower-cased, 1 to [`MAX_TAG_CHARS`] characters, no control
/// characters.
fn tag_name(raw: &str) -> Result<String> {
    let n = raw.trim().to_lowercase();
    let chars = n.chars().count();
    if chars == 0 || chars > MAX_TAG_CHARS || n.chars().any(char::is_control) {
        return Err(Error::Invalid(format!(
            "a tag name is 1 to {MAX_TAG_CHARS} characters without control characters"
        )));
    }
    Ok(n)
}

fn tag_id(name: &str) -> String {
    sha_hex(&[name])[..16].to_string()
}

/// Delete tag names no event carries any more.
fn prune_tags(tx: &Connection) -> Result<()> {
    tx.execute(
        "DELETE FROM tags WHERE NOT EXISTS (SELECT 1 FROM event_tags et WHERE et.tag_id = tags.tag_id)",
        [],
    )?;
    Ok(())
}

/// Add (`add`) or remove a tag on event rows, in one transaction with one audit row (`tag_rows`, object `event_tag`).
/// The name is stored trimmed and lower-cased.
///
/// - An analyst's tag is accepted; an agent's is pending review. An analyst adding a tag an agent has pending confirms
///   it as their own; removing it deletes it.
/// - An agent may create only names starting `ai:`, or use a tag already in use; anything else is `Error::Decision`.
///   It may remove only its own pending tags.
/// - A call that changes no row fails.
pub fn tag_rows(
    conn: &Connection,
    actor: &Actor,
    rows: &[RowRef],
    tag: &str,
    add: bool,
) -> Result<AuditEntry> {
    let name = tag_name(tag)?;
    let rows = clean_rows(rows, row_limit(actor))?;
    let id = tag_id(&name);
    in_tx(conn, |tx| {
        check_events_exist(tx, &rows)?;
        let known: bool = tx.query_row(
            "SELECT count(*) > 0 FROM tags WHERE tag_id = ?",
            params![id],
            |r| r.get(0),
        )?;
        if add && is_agent(actor) && !known && !name.starts_with("ai:") {
            return Err(Error::Decision(format!(
                "an agent may create only tags starting \"ai:\" (got {name:?}); it can use a tag already in use"
            )));
        }
        let existing = tags_of(tx, &id, &rows)?;
        let ts = audit::now();
        let batch = batch_id(
            actor,
            &format!("tag:{}:{name}", if add { "add" } else { "remove" }),
            ts.timestamp_micros(),
            &rows,
        );
        let d = Decision::new(actor, &ts, &batch);
        let (before, after) = if add {
            let mut changed = Vec::new();
            let mut replaced = Vec::new();
            for r in &rows {
                match existing.get(r) {
                    None => changed.push(r.clone()),
                    // An analyst confirms an agent's pending tag by applying it themselves.
                    Some(m) if actor.is_analyst() && m.review_state == "pending_review" => {
                        changed.push(r.clone());
                        replaced.push(m.json());
                    }
                    Some(_) => {}
                }
            }
            if changed.is_empty() {
                return Err(Error::Decision(format!(
                    "these rows already carry the tag {name:?}"
                )));
            }
            if !known {
                tx.execute(
                    "INSERT INTO tags (tag_id, name, created_by, created_at) VALUES (?, ?, ?, CAST(? AS TIMESTAMPTZ))",
                    params![id, name, actor.as_str(), d.ts],
                )?;
            }
            let fresh: Vec<RowRef> = changed
                .iter()
                .filter(|r| !existing.contains_key(*r))
                .cloned()
                .collect();
            let superseded: Vec<RowRef> = changed
                .iter()
                .filter(|r| existing.contains_key(*r))
                .cloned()
                .collect();
            insert_tags(tx, &id, &fresh, &d)?;
            update_tags(tx, &id, &superseded, &d)?;
            let mut after = rows_json(&changed);
            after["tag"] = json!(name);
            after["add"] = json!(true);
            (marks_before(replaced), Some(after))
        } else {
            let mut gone = Vec::new();
            let mut not_own = 0;
            for r in &rows {
                let Some(m) = existing.get(r) else { continue };
                if is_agent(actor)
                    && !(m.decided_by == actor.as_str() && m.review_state == "pending_review")
                {
                    not_own += 1;
                }
                gone.push(m);
            }
            if gone.is_empty() {
                return Err(Error::Decision(format!(
                    "none of these rows carries the tag {name:?}"
                )));
            }
            if not_own > 0 {
                return Err(Error::Decision(format!(
                    "{not_own} of these tags were not made by this agent or were reviewed; an agent removes only its \
                     own pending tags"
                )));
            }
            let keys: Vec<RowRef> = gone.iter().map(|m| m.row.clone()).collect();
            let before = marks_before(gone.iter().map(|m| m.json()).collect());
            delete_rows(tx, "event_tags", "tag_id = ? AND ", &[text(&id)], &keys)?;
            prune_tags(tx)?;
            let mut after = rows_json(&keys);
            after["tag"] = json!(name);
            after["add"] = json!(false);
            (before, Some(after))
        };
        audit::append_at(
            tx,
            ts,
            actor.as_str(),
            actor.on_behalf_of(),
            "tag_rows",
            "event_tag",
            &batch,
            before.as_ref(),
            after.as_ref(),
            None,
        )
    })
}

fn insert_tags(tx: &Connection, tag_id: &str, rows: &[RowRef], d: &Decision) -> Result<()> {
    for chunk in rows.chunks(CHUNK / 4) {
        let one = "(?, ?, ?, ?, CAST(? AS TIMESTAMPTZ), ?, CAST(? AS review_state), ?, CAST(? AS TIMESTAMPTZ), ?)";
        let mut params = Vec::new();
        for r in chunk {
            params.extend([text(tag_id), text(&r.source_table), text(&r.record_key)]);
            params.extend(d.params());
        }
        tx.execute(
            &format!(
                "INSERT INTO event_tags (tag_id, source_table, record_key, decided_by, decided_at, on_behalf_of, \
                 review_state, reviewed_by, reviewed_at, batch_id) VALUES {}",
                vec![one; chunk.len()].join(", ")
            ),
            params_from_iter(params.iter()),
        )?;
    }
    Ok(())
}

fn update_tags(tx: &Connection, tag_id: &str, rows: &[RowRef], d: &Decision) -> Result<()> {
    for chunk in rows.chunks(CHUNK) {
        let (values, vparams) = values_of(chunk);
        let mut params = d.params();
        params.push(text(tag_id));
        params.extend(vparams);
        tx.execute(
            &format!(
                "UPDATE event_tags SET decided_by = ?, decided_at = CAST(? AS TIMESTAMPTZ), on_behalf_of = ?, \
                 review_state = CAST(? AS review_state), reviewed_by = ?, reviewed_at = CAST(? AS TIMESTAMPTZ), \
                 review_comment = NULL, batch_id = ? \
                 WHERE tag_id = ? AND (source_table, record_key) IN (SELECT t, k FROM {values})"
            ),
            params_from_iter(params.iter()),
        )?;
    }
    Ok(())
}

/// Every tag in use, by name, with how many rows carry it and how many of those are agent tags awaiting review.
pub fn list_tags(conn: &Connection) -> Result<Vec<TagInfo>> {
    let mut stmt = conn.prepare(
        "SELECT t.name, count(et.tag_id), \
                count(et.tag_id) FILTER (WHERE et.decided_by LIKE 'agent:%' AND et.review_state = 'pending_review') \
         FROM tags t LEFT JOIN event_tags et ON et.tag_id = t.tag_id GROUP BY t.name ORDER BY t.name",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(TagInfo {
            name: r.get(0)?,
            count: r.get::<_, i64>(1)? as u64,
            agent_unreviewed: r.get::<_, i64>(2)? as u64,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

// ---------------------------------------------------------------------------------------------------------------
// review

/// Confirm (`accept`) or remove every agent mark still pending on `rows`, in one transaction, through `case::review`.
///
/// The marks reviewed are the pending row flags and tags of those rows and the pending standing value flags that cover
/// them. **Confirming or removing from rows therefore also reviews every pending value flag that covers any of them,
/// and that changes every row such a flag covers, not only the selected ones** (a row shown flagged by an agent's value
/// flag cannot otherwise be confirmed or removed from the grid). The UI must warn.
/// Removing deletes the flag or tag the agent added, restores a flag it changed, and soft-removes a value flag it
/// created. Analyst marks and marks already reviewed are untouched. Returns one audit row per decision touched (one
/// agent call, or one value flag), never per event; empty when nothing was pending.
pub fn review_marks(
    conn: &Connection,
    reviewer: &Reviewer,
    rows: &[RowRef],
    accept: bool,
) -> Result<Vec<AuditEntry>> {
    let rows = clean_rows(rows, MAX_ROWS)?;
    in_tx(conn, |tx| {
        let mut out = Vec::new();
        for (object_type, table) in [("event_flag", "event_flags"), ("event_tag", "event_tags")] {
            let mut by_batch: BTreeMap<String, Vec<RowRef>> = BTreeMap::new();
            for chunk in rows.chunks(CHUNK) {
                let (values, params) = values_of(chunk);
                let mut stmt = tx.prepare(&format!(
                    "SELECT m.batch_id, m.source_table, m.record_key FROM {table} m \
                     WHERE m.review_state = 'pending_review' \
                     AND (m.source_table, m.record_key) IN (SELECT t, k FROM {values})"
                ))?;
                for r in stmt.query_map(params_from_iter(params.iter()), |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        RowRef {
                            source_table: r.get(1)?,
                            record_key: r.get(2)?,
                        },
                    ))
                })? {
                    let (batch, row) = r?;
                    by_batch.entry(batch).or_default().push(row);
                }
            }
            for (batch, mut subset) in by_batch {
                subset.sort();
                subset.dedup();
                let seq = review::latest_decision_seq(tx, object_type, &batch)?.ok_or_else(|| {
                    Error::Decision(format!("{object_type} {batch} is pending review but has no decision in the audit trail"))
                })?;
                out.push(if accept {
                    review::accept_in(tx, reviewer, object_type, &batch, seq, None, Some(&subset))?
                } else {
                    review::discard_in(tx, reviewer, object_type, &batch, seq, None, Some(&subset))?
                });
            }
        }
        for id in covering_pending_value_flags(tx, &rows)? {
            let seq = review::latest_decision_seq(tx, "value_flag", &id)?.ok_or_else(|| {
                Error::Decision(format!(
                    "value_flag {id} is pending review but has no decision in the audit trail"
                ))
            })?;
            out.push(if accept {
                review::accept_in(tx, reviewer, "value_flag", &id, seq, None, None)?
            } else {
                review::discard_in(tx, reviewer, "value_flag", &id, seq, None, None)?
            });
        }
        Ok(out)
    })
}

/// The ids of the active, pending value flags that match at least one of `rows`, sorted.
fn covering_pending_value_flags(tx: &Connection, rows: &[RowRef]) -> Result<Vec<String>> {
    /// (flag_id, kind, value, scope_kind, scope_value)
    type Pending = (String, String, String, Option<String>, Option<String>);
    let pending: Vec<Pending> = {
        let mut stmt = tx.prepare(
            "SELECT flag_id, CAST(kind AS VARCHAR), value, scope_kind, scope_value FROM value_flags \
             WHERE removed_at IS NULL AND review_state = 'pending_review' ORDER BY flag_id",
        )?;
        stmt.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<std::result::Result<_, _>>()?
    };
    let mut out = Vec::new();
    for (id, kind, value, scope_kind, scope_value) in pending {
        let cols = crate::case::events::value_columns(&kind);
        let mut sql = format!(
            "({})",
            cols.iter()
                .map(|c| format!("{c} = ?"))
                .collect::<Vec<_>>()
                .join(" OR ")
        );
        let mut base: Vec<Value> = cols.iter().map(|_| text(&value)).collect();
        if let (Some(sk), Some(sv)) = (&scope_kind, &scope_value) {
            sql = format!(
                "{sql} AND {}",
                crate::case::events::entity_predicate(sk, "?")
            );
            base.extend(
                crate::case::events::entity_columns(sk)
                    .iter()
                    .map(|_| text(sv)),
            );
        }
        for chunk in rows.chunks(CHUNK) {
            let (values, vparams) = values_of(chunk);
            let mut params = vparams;
            params.extend(base.iter().cloned());
            let hit: bool = tx.query_row(
                &format!(
                    "SELECT count(*) > 0 FROM events e JOIN {values} ON e.source_table = v.t AND e.record_key = v.k \
                     WHERE {sql}"
                ),
                params_from_iter(params.iter()),
                |r| r.get(0),
            )?;
            if hit {
                out.push(id.clone());
                break;
            }
        }
    }
    Ok(out)
}

/// The state of a mark decision for `case::review`: for a value flag its audit JSON; for a call that marked rows
/// (`event_flag`, `event_tag`) the rows still set by it and their review states. `review_state` is `pending_review`
/// while any of its rows is, `accepted` when all are reviewed, null when it has no rows left.
pub(crate) fn state(conn: &Connection, object_type: &str, id: &str) -> Result<Json> {
    if object_type == "value_flag" {
        return value_flag_state(conn, id)?
            .ok_or_else(|| Error::Decision(format!("unknown value flag {id}")));
    }
    let table = batch_table(object_type)?;
    let (pending, accepted): (i64, i64) = conn.query_row(
        &format!(
            "SELECT count(*) FILTER (WHERE review_state = 'pending_review'), \
                    count(*) FILTER (WHERE review_state = 'accepted') FROM {table} WHERE batch_id = ?"
        ),
        params![id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let review_state = if pending > 0 {
        json!("pending_review")
    } else if accepted > 0 {
        json!("accepted")
    } else {
        Json::Null
    };
    Ok(json!({ "rows_pending": pending, "rows_accepted": accepted, "review_state": review_state }))
}

fn batch_table(object_type: &str) -> Result<&'static str> {
    match object_type {
        "event_flag" => Ok("event_flags"),
        "event_tag" => Ok("event_tags"),
        other => Err(Error::Decision(format!("cannot review a {other}"))),
    }
}

/// Accept the pending rows of the call `batch` (only `only`, when given).
pub(crate) fn accept_batch(
    tx: &Connection,
    object_type: &str,
    batch: &str,
    reviewer: &Reviewer,
    ts: &str,
    comment: Option<&str>,
    only: Option<&[RowRef]>,
) -> Result<()> {
    let table = batch_table(object_type)?;
    let keys = pending_rows(tx, table, batch, only)?;
    for chunk in keys.chunks(CHUNK) {
        let (values, vparams) = values_of(chunk);
        let mut params = vec![text(reviewer.as_str()), text(ts), opt(comment), text(batch)];
        params.extend(vparams);
        tx.execute(
            &format!(
                "UPDATE {table} SET review_state = 'accepted', reviewed_by = ?, reviewed_at = CAST(? AS TIMESTAMPTZ), \
                 review_comment = ? WHERE batch_id = ? AND review_state = 'pending_review' \
                 AND (source_table, record_key) IN (SELECT t, k FROM {values})"
            ),
            params_from_iter(params.iter()),
        )?;
    }
    Ok(())
}

/// The rows a review of the call `batch` touches now: its pending rows, limited to `only`. For the review audit entry.
pub(crate) fn reviewed_rows(
    tx: &Connection,
    object_type: &str,
    batch: &str,
    only: Option<&[RowRef]>,
) -> Result<Json> {
    let rows = pending_rows(tx, batch_table(object_type)?, batch, only)?;
    Ok(json!(
        rows.iter()
            .map(|r| json!([r.source_table, r.record_key]))
            .collect::<Vec<_>>()
    ))
}

/// The rows of `table` still set by call `batch` and pending (limited to `only`).
fn pending_rows(
    tx: &Connection,
    table: &str,
    batch: &str,
    only: Option<&[RowRef]>,
) -> Result<Vec<RowRef>> {
    let mut stmt = tx.prepare(&format!(
        "SELECT source_table, record_key FROM {table} WHERE batch_id = ? AND review_state = 'pending_review' \
         ORDER BY 1, 2"
    ))?;
    let all = stmt
        .query_map(params![batch], |r| {
            Ok(RowRef {
                source_table: r.get(0)?,
                record_key: r.get(1)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(match only {
        Some(only) => {
            let only: BTreeSet<&RowRef> = only.iter().collect();
            all.into_iter().filter(|r| only.contains(r)).collect()
        }
        None => all,
    })
}

/// Put row `k` back as the mark JSON `m` (a `Mark::json` recorded in an audit `before`) was.
fn restore_flag_row(tx: &Connection, k: &RowRef, m: &Json) -> Result<()> {
    tx.execute(
        "UPDATE event_flags SET level = CAST(? AS flag_level), decided_by = ?, \
         decided_at = CAST(? AS TIMESTAMPTZ), on_behalf_of = ?, review_state = CAST(? AS review_state), \
         reviewed_by = ?, reviewed_at = CAST(? AS TIMESTAMPTZ), review_comment = ?, batch_id = ? \
         WHERE source_table = ? AND record_key = ?",
        params![
            m["level"].as_str(),
            m["decided_by"].as_str(),
            m["decided_at"].as_str(),
            m["on_behalf_of"].as_str(),
            m["review_state"].as_str(),
            m["reviewed_by"].as_str(),
            m["reviewed_at"].as_str(),
            m["review_comment"].as_str(),
            m["batch_id"].as_str(),
            k.source_table,
            k.record_key
        ],
    )?;
    Ok(())
}

/// For the flags `gone` (pending flags of agent calls), what each row was before the call that set it: the mark its
/// decision recorded in the audit `before`. Rows that decision added are absent.
fn prior_flags(tx: &Connection, gone: &[&Mark]) -> Result<BTreeMap<RowRef, Json>> {
    let batches: BTreeSet<&str> = gone.iter().map(|m| m.batch_id.as_str()).collect();
    let mut out = BTreeMap::new();
    for batch in batches {
        let decision = audit::log(tx, Some(("event_flag", batch)))?
            .into_iter()
            .rev()
            .find(|e| e.action == "flag_rows");
        let marks = decision
            .as_ref()
            .and_then(|e| e.before.as_ref())
            .and_then(|b| b["marks"].as_array());
        for m in marks.into_iter().flatten() {
            if let (Some(t), Some(k)) = (m["source_table"].as_str(), m["record_key"].as_str()) {
                out.insert(RowRef::new(t, k), m.clone());
            }
        }
    }
    Ok(out)
}

/// Undo the decision `d` on the pending rows of its call (only `only`, when given): a row the decision added is
/// deleted; a row it changed is put back as `d.before` recorded it. Returns what was removed and restored.
pub(crate) fn revert_batch(
    tx: &Connection,
    object_type: &str,
    batch: &str,
    d: &AuditEntry,
    only: Option<&[RowRef]>,
) -> Result<Map<String, Json>> {
    let table = batch_table(object_type)?;
    let keys = pending_rows(tx, table, batch, only)?;
    if keys.is_empty() {
        return Err(Error::Decision(format!(
            "{object_type} {batch} has no pending mark to remove; clear the mark instead"
        )));
    }
    let prior: BTreeMap<RowRef, &Json> = d
        .before
        .as_ref()
        .and_then(|b| b["marks"].as_array())
        .map(|a| {
            a.iter()
                .filter_map(|m| {
                    Some((
                        RowRef::new(m["source_table"].as_str()?, m["record_key"].as_str()?),
                        m,
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let mut removed = Vec::new();
    let mut restored = Vec::new();
    let tag = d.after.as_ref().and_then(|a| a["tag"].as_str()).map(tag_id);
    for k in &keys {
        match prior.get(k) {
            Some(m) if object_type == "event_flag" => {
                restore_flag_row(tx, k, m)?;
                restored.push(json!([k.source_table, k.record_key, m["level"]]));
            }
            _ => {
                if object_type == "event_flag" {
                    tx.execute(
                        "DELETE FROM event_flags WHERE source_table = ? AND record_key = ?",
                        params![k.source_table, k.record_key],
                    )?;
                } else {
                    tx.execute(
                        "DELETE FROM event_tags WHERE tag_id = ? AND source_table = ? AND record_key = ?",
                        params![tag.as_deref(), k.source_table, k.record_key],
                    )?;
                }
                removed.push(json!([k.source_table, k.record_key]));
            }
        }
    }
    if object_type == "event_tag" {
        prune_tags(tx)?;
    }
    let mut out = Map::new();
    out.insert("removed".into(), Json::Array(removed));
    out.insert("restored".into(), Json::Array(restored));
    Ok(out)
}

/// One reason a row is flagged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlagSource {
    /// `row` for the row's own flag, `value` for a standing flag on a value that matches it.
    pub origin: String,
    pub level: FlagLevel,
    /// A value flag's kind and value (`ip` and `203.0.113.45`); `None` for the row's own.
    pub kind: Option<String>,
    pub value: Option<String>,
    /// The entity a value flag is limited to (`session` and its id); `None` when case-wide.
    pub scope_kind: Option<String>,
    pub scope_value: Option<String>,
    pub decided_by: String,
    pub review_state: String,
}

/// The flags that make row `(source_table, record_key)` flagged: its own, then each matching active value flag, the
/// stronger first.
pub fn flag_sources(
    conn: &Connection,
    source_table: &str,
    record_key: &str,
) -> Result<Vec<FlagSource>> {
    let mut out = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT CAST(level AS VARCHAR), decided_by, CAST(review_state AS VARCHAR) FROM event_flags \
         WHERE source_table = ? AND record_key = ?",
    )?;
    for r in stmt.query_map(params![source_table, record_key], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })? {
        let (level, decided_by, review_state) = r?;
        out.push(FlagSource {
            origin: "row".into(),
            level: FlagLevel::parse(&level)?,
            kind: None,
            value: None,
            scope_kind: None,
            scope_value: None,
            decided_by,
            review_state,
        });
    }
    let mut stmt = conn.prepare(&format!(
        "SELECT CAST(vf.level AS VARCHAR), CAST(vf.kind AS VARCHAR), vf.value, vf.scope_kind, vf.scope_value, \
                vf.decided_by, CAST(vf.review_state AS VARCHAR) \
         FROM value_flags vf, events e WHERE e.source_table = ? AND e.record_key = ? AND vf.removed_at IS NULL \
         AND {} ORDER BY vf.level DESC, vf.kind, vf.value, vf.flag_id",
        crate::case::events::value_flag_matches()
    ))?;
    for r in stmt.query_map(params![source_table, record_key], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
        ))
    })? {
        let (level, kind, value, scope_kind, scope_value, decided_by, review_state) = r?;
        out.push(FlagSource {
            origin: "value".into(),
            level: FlagLevel::parse(&level)?,
            kind: Some(kind),
            value: Some(value),
            scope_kind,
            scope_value,
            decided_by,
            review_state,
        });
    }
    out.sort_by_key(|s| std::cmp::Reverse(s.level));
    Ok(out)
}
