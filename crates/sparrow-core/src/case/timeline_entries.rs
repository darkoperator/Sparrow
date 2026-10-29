//! Curated timeline entries (Addendum D.3): every entry and every status change is an agent decision with the D.2
//! tags and an audit row, in one transaction.
//!
//! Lifecycle: `proposed` -> `verified` (needs evidence that exists in `record_sources`) or `rejected`. A proposed
//! entry is edited in place; editing a verified entry proposes a successor that `supersedes` it, and the old entry
//! becomes `superseded` only when the successor is verified. `rejected` and `superseded` are final.

use crate::case::actor::{Actor, Reviewer};
use crate::case::audit::{self, AuditEntry};
use crate::case::text::{check_text, check_title};
use crate::case::write::{DECISION_TAGS, in_tx, refuse_if_pending_agent, self_review};
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::{Connection, OptionalExt, params};
use serde::{Serialize, Serializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// An evidence row: `table:record_key` (the table is everything before the first ':').
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct EvidenceRef {
    pub source_table: String,
    pub record_key: String,
}

impl EvidenceRef {
    pub fn parse(s: &str) -> Result<EvidenceRef> {
        match s.split_once(':') {
            Some((t, k)) if !t.trim().is_empty() && !k.is_empty() => Ok(EvidenceRef {
                source_table: t.trim().to_string(),
                record_key: k.to_string(),
            }),
            _ => Err(Error::Decision(format!(
                "an evidence reference is <table>:<record_key>, got {s:?}"
            ))),
        }
    }

    pub fn text(&self) -> String {
        format!("{}:{}", self.source_table, self.record_key)
    }
}

/// Fails unless every reference has a `record_sources` row (the record exists as evidence). Set-based: the refs go
/// to a temporary staging table through an appender and one anti-join finds the first missing one, so 50,000 refs
/// cost one query, not 50,000. The first missing reference in (table, key) order is named.
pub(crate) fn check_evidence_exists(conn: &Connection, refs: &[EvidenceRef]) -> Result<()> {
    let missing: Option<(String, String)> = match refs {
        [] => return Ok(()),
        // Not cached: DuckDB keeps a cached plan's statistics (see audit::head).
        [r] => conn
            .query_row(
                "SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM record_sources WHERE table_name = ? AND record_key = ?)",
                params![r.source_table, r.record_key, r.source_table, r.record_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?,
        _ => {
            conn.execute_batch(
                "CREATE OR REPLACE TEMP TABLE _evidence_check (source_table VARCHAR, record_key VARCHAR)",
            )?;
            let found = (|| -> Result<Option<(String, String)>> {
                {
                    let mut app = conn.appender("_evidence_check")?;
                    for r in refs {
                        app.append_row(params![r.source_table, r.record_key])?;
                    }
                    app.flush()?;
                }
                Ok(conn
                    .query_row(
                        "SELECT c.source_table, c.record_key FROM _evidence_check c \
                         WHERE NOT EXISTS (SELECT 1 FROM record_sources r \
                                           WHERE r.table_name = c.source_table AND r.record_key = c.record_key) \
                         ORDER BY 1, 2 LIMIT 1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?)
            })();
            conn.execute_batch("DROP TABLE IF EXISTS _evidence_check")?;
            found?
        }
    };
    match missing {
        None => Ok(()),
        Some((source_table, record_key)) => Err(Error::Decision(format!(
            "no evidence record {} (not in record_sources)",
            EvidenceRef {
                source_table,
                record_key
            }
            .text()
        ))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    InitialAccess,
    Persistence,
    DefenseEvasion,
    Recon,
    Collection,
    Exfiltration,
    Impact,
    Remediation,
}

impl Phase {
    pub const ALL: [Phase; 8] = [
        Phase::InitialAccess,
        Phase::Persistence,
        Phase::DefenseEvasion,
        Phase::Recon,
        Phase::Collection,
        Phase::Exfiltration,
        Phase::Impact,
        Phase::Remediation,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Phase::InitialAccess => "initial_access",
            Phase::Persistence => "persistence",
            Phase::DefenseEvasion => "defense_evasion",
            Phase::Recon => "recon",
            Phase::Collection => "collection",
            Phase::Exfiltration => "exfiltration",
            Phase::Impact => "impact",
            Phase::Remediation => "remediation",
        }
    }

    pub fn parse(s: &str) -> Result<Phase> {
        Phase::ALL
            .into_iter()
            .find(|p| p.as_str() == s)
            .ok_or_else(|| {
                Error::Decision(format!(
                    "unknown phase {s:?} (initial_access, persistence, defense_evasion, recon, collection, \
                     exfiltration, impact or remediation)"
                ))
            })
    }
}

const STATUSES: &[&str] = &["proposed", "verified", "rejected", "superseded"];
const REVIEW_STATES: &[&str] = &["pending_review", "accepted", "discarded"];

/// The phase an add-to-timeline dialog proposes for events of these `event_category` values (the analyst can change
/// it). The first rule that matches any of the categories wins; a category no rule names falls to `Recon`.
pub fn default_phase(categories: &[String]) -> Phase {
    let any = |names: &[&str]| categories.iter().any(|c| names.contains(&c.as_str()));
    if any(&["auth"]) {
        Phase::InitialAccess
    } else if any(&["audit_tamper"]) {
        Phase::DefenseEvasion
    } else if any(&[
        "mail_rule",
        "forwarding",
        "config_change",
        "app_consent",
        "app_credential",
        "mfa_change",
        "role_change",
        "permission",
    ]) {
        Phase::Persistence
    } else if any(&["mail_read", "file_access", "file_download", "ediscovery"]) {
        Phase::Collection
    } else if any(&["mail_flow", "mail_send", "file_share"]) {
        Phase::Exfiltration
    } else {
        Phase::Recon
    }
}

pub struct NewEntry {
    pub tenant_key: Option<String>,
    pub event_time: DateTime<Utc>,
    /// The end of the span a grouped entry covers (`event_time` is the start); `None` for a single moment.
    pub end_time: Option<DateTime<Utc>>,
    /// How many events a grouped entry covers; `None` when not grouped.
    pub event_count: Option<u64>,
    pub title: String,
    pub narrative: Option<String>,
    pub phase: Phase,
    pub evidence: Vec<EvidenceRef>,
}

/// A span ends at or after it starts, and a group covers at least one event.
fn check_group(
    start: &DateTime<Utc>,
    end: Option<&DateTime<Utc>>,
    count: Option<u64>,
) -> Result<()> {
    if end.is_some_and(|e| e < start) {
        return Err(Error::Decision(format!(
            "a grouped entry cannot end ({}) before it starts ({})",
            end.map(audit::ts_text).unwrap_or_default(),
            audit::ts_text(start)
        )));
    }
    if count == Some(0) {
        return Err(Error::Decision(
            "a grouped entry covers at least one event".into(),
        ));
    }
    if count.is_some_and(|c| i64::try_from(c).is_err()) {
        return Err(Error::Decision("the event count is too large".into()));
    }
    Ok(())
}

/// The fields an edit changes; `None` keeps the current value. `evidence` replaces the whole list.
#[derive(Debug, Clone, Default)]
pub struct EntryEdit {
    pub event_time: Option<DateTime<Utc>>,
    /// `Some(None)` clears the end of the span.
    pub end_time: Option<Option<DateTime<Utc>>>,
    /// `Some(None)` clears the event count.
    pub event_count: Option<Option<u64>>,
    pub title: Option<String>,
    /// `Some(None)` clears the narrative.
    pub narrative: Option<Option<String>>,
    pub phase: Option<Phase>,
    pub evidence: Option<Vec<EvidenceRef>>,
}

fn ts<S: Serializer>(t: &DateTime<Utc>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&audit::ts_text(t))
}

fn ts_opt<S: Serializer>(t: &Option<DateTime<Utc>>, s: S) -> std::result::Result<S::Ok, S::Error> {
    match t {
        Some(t) => ts(t, s),
        None => s.serialize_none(),
    }
}

/// A timeline entry with its evidence (ordered by table, key).
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub entry_id: String,
    pub tenant_key: Option<String>,
    #[serde(serialize_with = "ts")]
    pub event_time: DateTime<Utc>,
    #[serde(serialize_with = "ts_opt")]
    pub end_time: Option<DateTime<Utc>>,
    pub event_count: Option<u64>,
    pub title: String,
    pub narrative: Option<String>,
    pub phase: String,
    pub status: String,
    pub supersedes: Option<String>,
    #[serde(serialize_with = "ts")]
    pub created_at: DateTime<Utc>,
    #[serde(serialize_with = "ts")]
    pub updated_at: DateTime<Utc>,
    pub decided_by: String,
    #[serde(serialize_with = "ts")]
    pub decided_at: DateTime<Utc>,
    pub on_behalf_of: Option<String>,
    pub review_state: String,
    pub reviewed_by: Option<String>,
    #[serde(serialize_with = "ts_opt")]
    pub reviewed_at: Option<DateTime<Utc>>,
    pub review_comment: Option<String>,
    pub evidence: Vec<EvidenceRef>,
}

fn evidence_of(conn: &Connection, id: &str) -> Result<Vec<EvidenceRef>> {
    let mut stmt = conn.prepare(
        "SELECT source_table, record_key FROM timeline_entry_evidence WHERE entry_id = ? \
         ORDER BY source_table, record_key",
    )?;
    let rows = stmt.query_map(params![id], |r| {
        Ok(EvidenceRef {
            source_table: r.get(0)?,
            record_key: r.get(1)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

fn set_evidence(conn: &Connection, id: &str, refs: &[EvidenceRef]) -> Result<()> {
    conn.execute(
        "DELETE FROM timeline_entry_evidence WHERE entry_id = ?",
        params![id],
    )?;
    #[cfg(any(test, feature = "test-fixtures"))]
    if test_hooks::FAIL_AFTER_EVIDENCE_DELETE.with(std::cell::Cell::get) {
        return Err(Error::Invalid(
            "injected failure after the evidence delete".into(),
        ));
    }
    let mut refs = refs.to_vec();
    refs.sort();
    refs.dedup();
    if refs.is_empty() {
        return Ok(());
    }
    let mut app = conn.appender("timeline_entry_evidence")?;
    for r in &refs {
        app.append_row(params![id, r.source_table, r.record_key])?;
    }
    app.flush()?;
    Ok(())
}

/// The decision-bearing state of an entry plus its provenance tags, as JSON (the audit `before`/`after`, and what a
/// discard restores); `None` when it does not exist.
pub(crate) fn entry_state(conn: &Connection, id: &str) -> Result<Option<Value>> {
    let row = conn
        .query_row(
            "SELECT CAST(status AS VARCHAR), title, narrative, CAST(phase AS VARCHAR), epoch_us(event_time), \
                    supersedes, tenant_key, decided_by, on_behalf_of, CAST(review_state AS VARCHAR), \
                    epoch_us(end_time), event_count \
             FROM timeline_entries WHERE entry_id = ?",
            params![id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, Option<i64>>(10)?,
                    r.get::<_, Option<i64>>(11)?,
                ))
            },
        )
        .optional()?;
    let Some((
        status,
        title,
        narrative,
        phase,
        us,
        supersedes,
        tenant_key,
        decided_by,
        on_behalf_of,
        review_state,
        end_us,
        event_count,
    )) = row
    else {
        return Ok(None);
    };
    let evidence: Vec<String> = evidence_of(conn, id)?
        .iter()
        .map(EvidenceRef::text)
        .collect();
    let mut state = json!({
        "status": status,
        "title": title,
        "narrative": narrative,
        "phase": phase,
        "event_time": audit::ts_text(&DateTime::from_timestamp_micros(us).unwrap_or_default()),
        "evidence": evidence,
        "supersedes": supersedes,
        "tenant_key": tenant_key,
        "decided_by": decided_by,
        "on_behalf_of": on_behalf_of,
        "review_state": review_state,
    });
    // Only a grouped entry carries these, so the state (and the audit rows holding it) of an ordinary entry is
    // unchanged.
    if let Some(m) = state.as_object_mut() {
        if let Some(us) = end_us {
            m.insert(
                "end_time".into(),
                json!(audit::ts_text(
                    &DateTime::from_timestamp_micros(us).unwrap_or_default()
                )),
            );
        }
        if let Some(n) = event_count {
            m.insert("event_count".into(), json!(n));
        }
    }
    Ok(Some(state))
}

fn existing(conn: &Connection, id: &str) -> Result<Value> {
    entry_state(conn, id)?.ok_or_else(|| Error::Decision(format!("unknown timeline entry {id}")))
}

fn status_of(state: &Value) -> &str {
    state["status"].as_str().unwrap_or("")
}

/// Stamp the D.2 tags (decision at `ts`) and `updated_at` on the entry; an analyst's decision is reviewed as made.
fn tag(conn: &Connection, actor: &Actor, id: &str, ts: &str) -> Result<()> {
    conn.execute(
        &format!(
            "UPDATE timeline_entries SET {DECISION_TAGS}, updated_at = CAST(? AS TIMESTAMPTZ) WHERE entry_id = ?"
        ),
        params![actor.as_str(), ts, actor.on_behalf_of(), ts, id],
    )?;
    self_review(conn, "timeline_entries", "entry_id", id, actor)
}

/// The analyst guard on an existing entry's `before` state (see [`refuse_if_pending_agent`]).
fn refuse_if_pending(tx: &Connection, actor: &Actor, id: &str, before: &Value) -> Result<()> {
    let latest = crate::case::review::latest_decision_seq(tx, "timeline_entry", id)?;
    refuse_if_pending_agent(actor, "timeline entry", id, Some(before), latest)
}

fn non_empty(what: &str, s: &str) -> Result<()> {
    if s.trim().is_empty() {
        return Err(Error::Decision(format!("{what} must not be empty")));
    }
    Ok(())
}

/// Insert a proposed entry (inside a transaction) and append its `propose_entry` row.
fn insert_proposed(
    tx: &Connection,
    actor: &Actor,
    e: &NewEntry,
    supersedes: Option<&str>,
    reason: Option<&str>,
) -> Result<(String, AuditEntry)> {
    check_evidence_exists(tx, &e.evidence)?;
    insert_proposed_checked(tx, actor, e, supersedes, reason)
}

/// [`insert_proposed`] for a caller that has just checked `e.evidence` in this transaction.
fn insert_proposed_checked(
    tx: &Connection,
    actor: &Actor,
    e: &NewEntry,
    supersedes: Option<&str>,
    reason: Option<&str>,
) -> Result<(String, AuditEntry)> {
    non_empty("a title", &e.title)?;
    check_title(&e.title)?;
    if let Some(n) = &e.narrative {
        check_text("a narrative", n)?;
    }
    check_group(&e.event_time, e.end_time.as_ref(), e.event_count)?;
    let ts = audit::now();
    let ts_text = audit::ts_text(&ts);
    let mut h = Sha256::new();
    for part in [
        e.tenant_key.as_deref().unwrap_or(""),
        &audit::ts_text(&e.event_time),
        &e.title,
        &ts.timestamp_micros().to_string(),
    ] {
        h.update(part.as_bytes());
        h.update([0x1f]);
    }
    let id = hex::encode(h.finalize())[..12].to_string();
    if entry_state(tx, &id)?.is_some() {
        return Err(Error::Decision(format!(
            "timeline entry {id} already exists; propose again"
        )));
    }
    tx.execute(
        "INSERT INTO timeline_entries (entry_id, tenant_key, event_time, end_time, event_count, title, narrative, \
                                       phase, status, supersedes, created_at, updated_at, decided_by, decided_at, \
                                       on_behalf_of) \
         VALUES (?, ?, CAST(? AS TIMESTAMPTZ), CAST(? AS TIMESTAMPTZ), ?, ?, ?, CAST(? AS attack_phase), 'proposed', \
                 ?, CAST(? AS TIMESTAMPTZ), CAST(? AS TIMESTAMPTZ), ?, CAST(? AS TIMESTAMPTZ), ?)",
        params![
            id,
            e.tenant_key,
            audit::ts_text(&e.event_time),
            e.end_time.as_ref().map(audit::ts_text),
            e.event_count.map(|c| c as i64),
            e.title,
            e.narrative,
            e.phase.as_str(),
            supersedes,
            ts_text,
            ts_text,
            actor.as_str(),
            ts_text,
            actor.on_behalf_of()
        ],
    )?;
    set_evidence(tx, &id, &e.evidence)?;
    self_review(tx, "timeline_entries", "entry_id", &id, actor)?;
    let after = existing(tx, &id)?;
    let entry = audit::append_at(
        tx,
        ts,
        actor.as_str(),
        actor.on_behalf_of(),
        "propose_entry",
        "timeline_entry",
        &id,
        None,
        Some(&after),
        reason,
    )?;
    Ok((id, entry))
}

/// Propose a new entry. Evidence is optional here but must exist when given; verifying needs at least one row.
pub fn propose(conn: &Connection, actor: &Actor, entry: NewEntry) -> Result<(String, AuditEntry)> {
    propose_from(conn, actor, entry, None)
}

/// [`propose`] with an audit reason (an accepted share proposal names its source).
pub(crate) fn propose_from(
    conn: &Connection,
    actor: &Actor,
    entry: NewEntry,
    reason: Option<&str>,
) -> Result<(String, AuditEntry)> {
    if let Some(r) = reason {
        check_text("a reason", r)?;
    }
    in_tx(conn, |tx| insert_proposed(tx, actor, &entry, None, reason))
}

/// One decision on an existing entry: before, `apply` (given the before state and the decision ts), the tags, after
/// (plus `extra` keys), the audit row.
fn decide(
    conn: &Connection,
    actor: &Actor,
    id: &str,
    action: &str,
    reason: Option<&str>,
    apply: impl FnOnce(&Connection, &Value, &str) -> Result<Option<(String, Value)>>,
) -> Result<AuditEntry> {
    in_tx(conn, |tx| decide_in(tx, actor, id, action, reason, apply))
}

/// [`decide`] inside a transaction the caller already opened.
fn decide_in(
    tx: &Connection,
    actor: &Actor,
    id: &str,
    action: &str,
    reason: Option<&str>,
    apply: impl FnOnce(&Connection, &Value, &str) -> Result<Option<(String, Value)>>,
) -> Result<AuditEntry> {
    let before = existing(tx, id)?;
    refuse_if_pending(tx, actor, id, &before)?;
    let ts = audit::now();
    let ts_text = audit::ts_text(&ts);
    let extra = apply(tx, &before, &ts_text)?;
    tag(tx, actor, id, &ts_text)?;
    let mut after = existing(tx, id)?;
    if let (Some((k, v)), Some(m)) = (extra, after.as_object_mut()) {
        m.insert(k, v);
    }
    audit::append_at(
        tx,
        ts,
        actor.as_str(),
        actor.on_behalf_of(),
        action,
        "timeline_entry",
        id,
        Some(&before),
        Some(&after),
        reason,
    )
}

/// Verify a proposed entry: it needs at least one evidence row, and every row must exist in `record_sources`. When
/// it supersedes X, X (still verified) becomes `superseded` in the same transaction; the audit `after` names it as
/// `superseded_entry`.
pub fn verify(conn: &Connection, actor: &Actor, entry_id: &str) -> Result<AuditEntry> {
    verify_from(conn, actor, entry_id, None)
}

/// [`verify`] with an audit reason (an accepted share proposal names its source).
pub(crate) fn verify_from(
    conn: &Connection,
    actor: &Actor,
    entry_id: &str,
    reason: Option<&str>,
) -> Result<AuditEntry> {
    if let Some(r) = reason {
        check_text("a reason", r)?;
    }
    decide(
        conn,
        actor,
        entry_id,
        "verify_entry",
        reason,
        verify_step(entry_id, true),
    )
}

/// The change a verification makes (see [`verify`]), for [`decide`] and [`decide_in`]. `check_evidence` is false only
/// for [`create_verified`], which checked the same evidence a moment earlier in the same transaction.
fn verify_step(
    entry_id: &str,
    check_evidence: bool,
) -> impl FnOnce(&Connection, &Value, &str) -> Result<Option<(String, Value)>> + '_ {
    move |tx, before, ts| {
        if status_of(before) != "proposed" {
            return Err(Error::Decision(format!(
                "timeline entry {entry_id} is {}; only a proposed entry can be verified",
                status_of(before)
            )));
        }
        let evidence = evidence_of(tx, entry_id)?;
        if evidence.is_empty() {
            return Err(Error::Decision(format!(
                "timeline entry {entry_id} has no evidence; a verified entry needs at least one evidence row"
            )));
        }
        if check_evidence {
            check_evidence_exists(tx, &evidence)?;
        }
        tx.execute(
            "UPDATE timeline_entries SET status = 'verified' WHERE entry_id = ?",
            params![entry_id],
        )?;
        let Some(old) = before["supersedes"].as_str() else {
            return Ok(None);
        };
        let old_state = existing(tx, old)?;
        if status_of(&old_state) != "verified" {
            return Err(Error::Decision(format!(
                "timeline entry {entry_id} can no longer supersede {old}: {old} is {}, not verified; edit the \
                     current verified entry instead",
                status_of(&old_state)
            )));
        }
        tx.execute(
            "UPDATE timeline_entries SET status = 'superseded', updated_at = CAST(? AS TIMESTAMPTZ) WHERE entry_id = ?",
            params![ts, old],
        )?;
        Ok(Some(("superseded_entry".into(), Value::String(old.into()))))
    }
}

/// Propose and verify an entry in one transaction, as the analyst's own decisions (two audit rows: `propose_entry`
/// then `verify_entry`), through the same code as [`propose`] and [`verify`]. Takes a [`Reviewer`], so an agent cannot
/// call it; an agent's entries stay proposed and go through review. Returns the entry id and both audit rows.
///
/// An [`Actor`] (what an agent is) does not convert to a [`Reviewer`]:
///
/// ```compile_fail,E0308
/// use sparrow_core::case::actor::Actor;
/// use sparrow_core::case::timeline_entries::{create_verified, NewEntry};
/// fn agent_tries(conn: &duckdb::Connection, entry: NewEntry) {
///     let agent = Actor::agent("claude", None).unwrap();
///     let _ = create_verified(conn, &agent, entry);
/// }
/// ```
pub fn create_verified(
    conn: &Connection,
    reviewer: &Reviewer,
    entry: NewEntry,
) -> Result<(String, Vec<AuditEntry>)> {
    in_tx(conn, |tx| create_verified_in(tx, reviewer, entry))
}

/// [`create_verified`] inside the caller's open transaction `tx`: nothing is committed or rolled back here, so a caller
/// can make many entries all-or-nothing by running them in one transaction.
pub fn create_verified_in(
    tx: &Connection,
    reviewer: &Reviewer,
    entry: NewEntry,
) -> Result<(String, Vec<AuditEntry>)> {
    let actor = reviewer.as_actor();
    let (id, proposed) = insert_proposed(tx, &actor, &entry, None, None)?;
    let verified = decide_in(
        tx,
        &actor,
        &id,
        "verify_entry",
        None,
        verify_step(&id, false),
    )?;
    #[cfg(any(test, feature = "test-fixtures"))]
    if test_hooks::countdown_hits() {
        return Err(Error::Decision("injected failure after verify".into()));
    }
    Ok((id, vec![proposed, verified]))
}

/// Reject a proposed or verified entry; the reason is required (it is the audit reason).
pub fn reject(
    conn: &Connection,
    actor: &Actor,
    entry_id: &str,
    reason: &str,
) -> Result<AuditEntry> {
    non_empty("a reason", reason)?;
    check_text("a reason", reason)?;
    decide(
        conn,
        actor,
        entry_id,
        "reject_entry",
        Some(reason.trim()),
        |tx, before, _| {
            if !matches!(status_of(before), "proposed" | "verified") {
                return Err(Error::Decision(format!(
                    "timeline entry {entry_id} is {} and cannot be rejected",
                    status_of(before)
                )));
            }
            tx.execute(
                "UPDATE timeline_entries SET status = 'rejected' WHERE entry_id = ?",
                params![entry_id],
            )?;
            Ok(None)
        },
    )
}

/// Edit an entry. A proposed entry is updated in place (`edit_entry`) and keeps its id. A verified entry is never
/// edited: a successor that supersedes it is proposed (`propose_entry`), carrying the unchanged fields and evidence,
/// and its id is returned. A rejected or superseded entry cannot be edited. An edit that changes nothing is refused.
pub fn edit(
    conn: &Connection,
    actor: &Actor,
    entry_id: &str,
    edit: EntryEdit,
) -> Result<(String, AuditEntry)> {
    edit_from(conn, actor, entry_id, edit, None)
}

/// [`edit`] with an audit reason (an accepted share proposal names its source).
pub(crate) fn edit_from(
    conn: &Connection,
    actor: &Actor,
    entry_id: &str,
    edit: EntryEdit,
    reason: Option<&str>,
) -> Result<(String, AuditEntry)> {
    if let Some(r) = reason {
        check_text("a reason", r)?;
    }
    if let Some(t) = &edit.title {
        non_empty("a title", t)?;
        check_title(t)?;
    }
    if let Some(Some(n)) = &edit.narrative {
        check_text("a narrative", n)?;
    }
    in_tx(conn, |tx| {
        let before = existing(tx, entry_id)?;
        refuse_if_pending(tx, actor, entry_id, &before)?;
        let current = list_where(tx, "entry_id = ?", &[entry_id])?
            .pop()
            .ok_or_else(|| Error::Decision(format!("unknown timeline entry {entry_id}")))?;
        let mut evidence = edit
            .evidence
            .clone()
            .unwrap_or_else(|| current.evidence.clone());
        evidence.sort();
        evidence.dedup();
        let next = NewEntry {
            tenant_key: current.tenant_key.clone(),
            event_time: edit.event_time.unwrap_or(current.event_time),
            end_time: edit.end_time.unwrap_or(current.end_time),
            event_count: edit.event_count.unwrap_or(current.event_count),
            title: edit.title.clone().unwrap_or_else(|| current.title.clone()),
            narrative: edit
                .narrative
                .clone()
                .unwrap_or_else(|| current.narrative.clone()),
            phase: match edit.phase {
                Some(p) => p,
                None => Phase::parse(&current.phase)?,
            },
            evidence,
        };
        let unchanged = next.event_time == current.event_time
            && next.end_time == current.end_time
            && next.event_count == current.event_count
            && next.title == current.title
            && next.narrative == current.narrative
            && next.phase.as_str() == current.phase
            && next.evidence == current.evidence;
        if unchanged {
            return Err(Error::Decision(format!(
                "the edit changes nothing on timeline entry {entry_id}"
            )));
        }
        check_group(&next.event_time, next.end_time.as_ref(), next.event_count)?;
        check_evidence_exists(tx, &next.evidence)?;
        match status_of(&before) {
            "verified" => insert_proposed_checked(tx, actor, &next, Some(entry_id), reason),
            "proposed" => {
                let ts = audit::now();
                let ts_text = audit::ts_text(&ts);
                non_empty("a title", &next.title)?;
                tx.execute(
                    "UPDATE timeline_entries SET event_time = CAST(? AS TIMESTAMPTZ), \
                     end_time = CAST(? AS TIMESTAMPTZ), event_count = ?, title = ?, narrative = ?, \
                     phase = CAST(? AS attack_phase) WHERE entry_id = ?",
                    params![
                        audit::ts_text(&next.event_time),
                        next.end_time.as_ref().map(audit::ts_text),
                        next.event_count.map(|c| c as i64),
                        next.title,
                        next.narrative,
                        next.phase.as_str(),
                        entry_id
                    ],
                )?;
                set_evidence(tx, entry_id, &next.evidence)?;
                tag(tx, actor, entry_id, &ts_text)?;
                let after = existing(tx, entry_id)?;
                let e = audit::append_at(
                    tx,
                    ts,
                    actor.as_str(),
                    actor.on_behalf_of(),
                    "edit_entry",
                    "timeline_entry",
                    entry_id,
                    Some(&before),
                    Some(&after),
                    reason,
                )?;
                Ok((entry_id.to_string(), e))
            }
            other => Err(Error::Decision(format!(
                "timeline entry {entry_id} is {other} and cannot be edited"
            ))),
        }
    })
}

/// Undo the decision `d` on entry `id` for a discard (`case::revert`). A propose is undone by rejecting the entry;
/// any other decision restores the fields and evidence it changed, and a verify that superseded X makes X verified
/// again. Returns what was restored.
pub(crate) fn revert(
    tx: &Connection,
    id: &str,
    d: &AuditEntry,
) -> Result<serde_json::Map<String, Value>> {
    let mut restored = serde_json::Map::new();
    let Some(before) = d.before.as_ref().filter(|b| !b.is_null()) else {
        tx.execute(
            "UPDATE timeline_entries SET status = 'rejected' WHERE entry_id = ?",
            params![id],
        )?;
        restored.insert("status".into(), Value::String("rejected".into()));
        return Ok(restored);
    };
    let after = d.after.as_ref().unwrap_or(&Value::Null);
    for (field, ty) in [
        ("status", "timeline_entry_status"),
        ("title", "VARCHAR"),
        ("narrative", "VARCHAR"),
        ("phase", "attack_phase"),
        ("event_time", "TIMESTAMPTZ"),
        ("end_time", "TIMESTAMPTZ"),
    ] {
        let old = before.get(field).unwrap_or(&Value::Null);
        if after.get(field).unwrap_or(&Value::Null) == old {
            continue;
        }
        tx.execute(
            &format!("UPDATE timeline_entries SET {field} = CAST(? AS {ty}) WHERE entry_id = ?"),
            params![old.as_str(), id],
        )?;
        restored.insert(field.into(), old.clone());
    }
    let old_count = before.get("event_count").unwrap_or(&Value::Null);
    if after.get("event_count").unwrap_or(&Value::Null) != old_count {
        tx.execute(
            "UPDATE timeline_entries SET event_count = ? WHERE entry_id = ?",
            params![old_count.as_i64(), id],
        )?;
        restored.insert("event_count".into(), old_count.clone());
    }
    let old_evidence = before.get("evidence").unwrap_or(&Value::Null);
    if after.get("evidence").unwrap_or(&Value::Null) != old_evidence {
        let refs = old_evidence
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(EvidenceRef::parse)
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        set_evidence(tx, id, &refs)?;
        restored.insert("evidence".into(), old_evidence.clone());
    }
    if let Some(x) = after.get("superseded_entry").and_then(Value::as_str) {
        tx.execute(
            "UPDATE timeline_entries SET status = 'verified' WHERE entry_id = ? AND status = 'superseded'",
            params![x],
        )?;
        restored.insert("superseded_entry_status".into(), json!({ x: "verified" }));
    }
    Ok(restored)
}

fn list_where(conn: &Connection, filter: &str, args: &[&str]) -> Result<Vec<Entry>> {
    let sql = format!(
        "SELECT entry_id, tenant_key, epoch_us(event_time), title, narrative, CAST(phase AS VARCHAR), \
                CAST(status AS VARCHAR), supersedes, epoch_us(created_at), epoch_us(updated_at), decided_by, \
                epoch_us(decided_at), on_behalf_of, CAST(review_state AS VARCHAR), reviewed_by, epoch_us(reviewed_at), \
                review_comment, epoch_us(end_time), event_count \
         FROM timeline_entries WHERE {filter} ORDER BY event_time, entry_id"
    );
    let at = |us: i64| DateTime::from_timestamp_micros(us).unwrap_or_default();
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(duckdb::params_from_iter(args.iter()), |r| {
        Ok(Entry {
            entry_id: r.get(0)?,
            tenant_key: r.get(1)?,
            event_time: at(r.get(2)?),
            title: r.get(3)?,
            narrative: r.get(4)?,
            phase: r.get(5)?,
            status: r.get(6)?,
            supersedes: r.get(7)?,
            created_at: at(r.get(8)?),
            updated_at: at(r.get(9)?),
            decided_by: r.get(10)?,
            decided_at: at(r.get(11)?),
            on_behalf_of: r.get(12)?,
            review_state: r.get(13)?,
            reviewed_by: r.get(14)?,
            reviewed_at: r.get::<_, Option<i64>>(15)?.map(at),
            review_comment: r.get(16)?,
            end_time: r.get::<_, Option<i64>>(17)?.map(at),
            event_count: r.get::<_, Option<i64>>(18)?.map(|c| c as u64),
            evidence: Vec::new(),
        })
    })?;
    let mut out: Vec<Entry> = rows.collect::<std::result::Result<_, _>>()?;
    for e in &mut out {
        e.evidence = evidence_of(conn, &e.entry_id)?;
    }
    Ok(out)
}

/// The entries, optionally only those with `status` and/or `review_state`, ordered by event time then id.
pub fn list(
    conn: &Connection,
    status: Option<&str>,
    review_state: Option<&str>,
) -> Result<Vec<Entry>> {
    if let Some(s) = status.filter(|s| !STATUSES.contains(s)) {
        return Err(Error::Decision(format!(
            "unknown timeline entry status {s:?} ({})",
            STATUSES.join(", ")
        )));
    }
    if let Some(s) = review_state.filter(|s| !REVIEW_STATES.contains(s)) {
        return Err(Error::Decision(format!(
            "unknown review state {s:?} ({})",
            REVIEW_STATES.join(", ")
        )));
    }
    let mut filter = vec!["true"];
    let mut args = Vec::new();
    if let Some(s) = status {
        filter.push("CAST(status AS VARCHAR) = ?");
        args.push(s);
    }
    if let Some(s) = review_state {
        filter.push("CAST(review_state AS VARCHAR) = ?");
        args.push(s);
    }
    list_where(conn, &filter.join(" AND "), &args)
}

/// Test-only failure injection (never compiled into a normal build).
#[cfg(any(test, feature = "test-fixtures"))]
#[doc(hidden)]
pub mod test_hooks {
    thread_local! {
        pub(super) static FAIL_AFTER_EVIDENCE_DELETE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        pub(super) static FAIL_CREATE_COUNTDOWN: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Make the `n`th `create_verified_in` on this thread from now fail right after its entry is verified (0: off).
    pub fn fail_create_verified_on_call(n: usize) {
        FAIL_CREATE_COUNTDOWN.with(|c| c.set(n));
    }

    pub(super) fn countdown_hits() -> bool {
        FAIL_CREATE_COUNTDOWN.with(|c| match c.get() {
            0 => false,
            1 => {
                c.set(0);
                true
            }
            n => {
                c.set(n - 1);
                false
            }
        })
    }

    /// Make every evidence replacement on this thread fail right after its DELETE.
    pub fn fail_after_evidence_delete(on: bool) {
        FAIL_AFTER_EVIDENCE_DELETE.with(|c| c.set(on));
    }
}
