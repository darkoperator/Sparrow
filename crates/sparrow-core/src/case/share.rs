//! Share bundles (Phase 8): one analyst's reviewed work on a case, exported as a JSON file so a second analyst
//! with the same evidence can import it as proposals. A bundle holds A's resulting state (what A concluded), never
//! A's trail: only objects whose current decision is accepted (an analyst decision, or an agent decision a reviewer
//! accepted) and the analyst's own notes. Export reads the case and writes nothing (the caller writes the file).
//!
//! Import stores each item as a proposal in `imported_proposals`; proposals change nothing until the importing
//! analyst accepts one (applied as that analyst's own decision, the source named in the audit reason) or discards it.
//! Every import, accept and discard is audited (`import_share`, `accept_proposal`, `discard_proposal`, object type
//! `share_bundle`). Limit: a bundle says what A concluded, not how; A's trail stays in A's case.

use crate::case::actor::{Actor, Reviewer};
use crate::case::audit::{self, AuditEntry};
use crate::case::indicators::{self, IndicatorType, Verdict};
use crate::case::notes::{self, NoteTarget};
use crate::case::text::{check_text, check_title};
use crate::case::timeline_entries::{self, EntryEdit, EvidenceRef, NewEntry, Phase};
use crate::case::write::{self, FindingStatus, in_tx};
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::{Connection, OptionalExt, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// The bundle format this build writes and reads.
pub const FORMAT: u32 = 1;
/// The largest bundle file import accepts.
pub const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub format: u32,
    /// `audit::ts_text` of the export time.
    pub exported_at: String,
    /// `analyst:<name>` who exported it.
    pub analyst: String,
    pub source_case_id: String,
    pub source_audit_head: Head,
    pub evidence: Evidence,
    pub items: Vec<Item>,
}

/// The exporting case's audit chain head: its entry count and the hash of the last entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub seq: i64,
    pub hash: Option<String>,
}

/// What the case was built from: a bundle is only imported into a case with the same source files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Sorted, distinct sha256 of every source file with status `parsed`.
    pub source_files: Vec<String>,
    /// Sorted `rule_id:rule_sha256` of the latest detection run (`detection_runs`, max run_id per tenant).
    pub rules: Vec<String>,
}

/// One object's resulting state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Item {
    Finding {
        finding_id: String,
        status: String,
        disposition_reason: Option<String>,
    },
    Indicator {
        tenant_key: Option<String>,
        ioc_type: String,
        value: String,
        verdict: String,
        note: Option<String>,
        active: bool,
    },
    TimelineEntry {
        entry_id: String,
        tenant_key: Option<String>,
        event_time: String,
        /// The end of the span a grouped entry covers (`event_time` is the start). Absent from the bundle for an
        /// entry about one moment, and in bundles written before grouped entries existed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        end_time: Option<String>,
        /// How many events a grouped entry covers; absent like `end_time`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event_count: Option<u64>,
        title: String,
        narrative: Option<String>,
        phase: String,
        status: String,
        /// `table:record_key`, sorted.
        evidence: Vec<String>,
        /// The exporting case's ids of the entries this one replaced (an edit of a verified entry proposes a
        /// successor with a new id), nearest first; empty for an entry that was never edited after verification.
        /// An importing case matches the entry it already took from an earlier bundle through them.
        supersedes: Vec<String>,
    },
    Note {
        /// A [`crate::case::notes::NoteTarget`] in its text form.
        target: String,
        text: String,
    },
}

impl Item {
    /// Stable, unambiguous key: `finding:<id>`, `indicator:` + the compact JSON array `[tenant_key or null, type,
    /// value]`, `timeline_entry:<id>`, `note:<first 16 hex of sha256(target \x1f text)>`.
    pub fn key(&self) -> String {
        match self {
            Item::Finding { finding_id, .. } => format!("finding:{finding_id}"),
            Item::Indicator {
                tenant_key,
                ioc_type,
                value,
                ..
            } => format!(
                "indicator:{}",
                serde_json::Value::from(vec![
                    tenant_key
                        .as_deref()
                        .map_or(serde_json::Value::Null, Into::into),
                    ioc_type.as_str().into(),
                    value.as_str().into(),
                ])
            ),
            Item::TimelineEntry { entry_id, .. } => format!("timeline_entry:{entry_id}"),
            Item::Note { target, text } => {
                let mut h = Sha256::new();
                h.update(target.as_bytes());
                h.update([0x1f]);
                h.update(text.as_bytes());
                format!("note:{}", &hex::encode(h.finalize())[..16])
            }
        }
    }
}

/// The case's evidence identity: its parsed source files and the rule set of its latest detection run.
pub fn evidence_of(conn: &Connection) -> Result<Evidence> {
    let strings = |sql: &str| -> Result<Vec<String>> {
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    };
    Ok(Evidence {
        source_files: strings(
            "SELECT DISTINCT sha256 FROM source_files \
             WHERE CAST(status AS VARCHAR) = 'parsed' AND sha256 IS NOT NULL ORDER BY 1",
        )?,
        rules: strings(
            "SELECT DISTINCT rule_id || ':' || rule_sha256 FROM detection_runs \
             WHERE (tenant_key, run_id) IN (SELECT tenant_key, max(run_id) FROM detection_runs GROUP BY tenant_key) \
             ORDER BY 1",
        )?,
    })
}

fn findings(conn: &Connection) -> Result<Vec<Item>> {
    let mut stmt = conn.prepare(
        "SELECT finding_id, CAST(status AS VARCHAR), disposition_reason FROM findings \
         WHERE CAST(review_state AS VARCHAR) = 'accepted' ORDER BY finding_id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Item::Finding {
            finding_id: r.get(0)?,
            status: r.get(1)?,
            disposition_reason: r.get(2)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

fn indicators(conn: &Connection) -> Result<Vec<Item>> {
    let mut stmt = conn.prepare(
        "SELECT tenant_key, CAST(type AS VARCHAR), value, CAST(verdict AS VARCHAR), note, removed_at IS NULL \
         FROM case_indicators WHERE CAST(review_state AS VARCHAR) = 'accepted' \
         ORDER BY tenant_key NULLS FIRST, CAST(type AS VARCHAR), value, indicator_id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Item::Indicator {
            tenant_key: r.get(0)?,
            ioc_type: r.get(1)?,
            value: r.get(2)?,
            verdict: r.get(3)?,
            note: r.get(4)?,
            active: r.get(5)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

fn entries(conn: &Connection) -> Result<Vec<Item>> {
    let mut out = Vec::new();
    for e in timeline_entries::list(conn, None, Some("accepted"))? {
        if !matches!(e.status.as_str(), "verified" | "rejected") {
            continue;
        }
        // Lineage: the predecessors this entry (or one before it) really replaced, i.e. that are `superseded`. A
        // rejected edit proposal never replaced its predecessor, which stays verified and is exported on its own.
        let mut supersedes = Vec::new();
        let mut prev = e.supersedes.clone();
        while let Some(id) = prev.filter(|id| !supersedes.contains(id) && *id != e.entry_id) {
            let Some(s) = timeline_entries::entry_state(conn, &id)? else {
                break;
            };
            if s["status"] != "superseded" {
                break;
            }
            prev = s["supersedes"].as_str().map(String::from);
            supersedes.push(id);
        }
        out.push(Item::TimelineEntry {
            supersedes,
            evidence: e.evidence.iter().map(EvidenceRef::text).collect(),
            event_time: audit::ts_text(&e.event_time),
            end_time: e.end_time.as_ref().map(audit::ts_text),
            event_count: e.event_count,
            entry_id: e.entry_id,
            tenant_key: e.tenant_key,
            title: e.title,
            narrative: e.narrative,
            phase: e.phase,
            status: e.status,
        });
    }
    Ok(out)
}

fn notes(conn: &Connection) -> Result<Vec<Item>> {
    let mut stmt = conn.prepare(
        "SELECT CAST(object_type AS VARCHAR), object_id, source_table, text FROM annotations \
         WHERE starts_with(actor, 'analyst:') ORDER BY created_at, annotation_id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        let (object_type, id, table, text) = row?;
        let target = match (object_type.as_str(), table) {
            ("finding", _) => format!("finding:{id}"),
            ("timeline_entry", _) => format!("entry:{id}"),
            ("indicator", _) => format!("ioc:{id}"),
            ("evidence", Some(t)) => format!("{t}:{id}"),
            (other, _) => {
                return Err(Error::Invalid(format!(
                    "a note on {other} {id} has no target form"
                )));
            }
        };
        let item = Item::Note { target, text };
        // Resulting state: the same text on the same target twice is one note (and one item key).
        if seen.insert(item.key()) {
            out.push(item);
        }
    }
    Ok(out)
}

/// `analyst`'s reviewed work on the case: accepted findings, indicators and verified or rejected timeline entries,
/// and analyst notes (identical target and text once), in that order (each sorted). Refused when the audit chain is broken, since the bundle names
/// its head. Writes nothing.
pub fn export(conn: &Connection, analyst: &Reviewer) -> Result<Bundle> {
    let chain = audit::verify(conn)?;
    if !chain.ok {
        return Err(Error::Invalid(format!(
            "the audit chain is broken ({}); a bundle cannot be exported until it is verified or acknowledged",
            chain.problem.as_deref().unwrap_or("see audit verify")
        )));
    }
    let mut items = findings(conn)?;
    items.extend(indicators(conn)?);
    items.extend(entries(conn)?);
    items.extend(notes(conn)?);
    Ok(Bundle {
        format: FORMAT,
        exported_at: audit::ts_text(&audit::now()),
        analyst: analyst.as_str().to_string(),
        source_case_id: audit::case_id(conn)?,
        source_audit_head: Head {
            seq: chain.entries,
            hash: chain.head_hash,
        },
        evidence: evidence_of(conn)?,
        items,
    })
}

/// Pretty JSON bytes and their hex sha256 (what the analyst sends out of band). Refused above
/// [`MAX_BUNDLE_BYTES`], since import would refuse the file.
pub fn to_bytes(b: &Bundle) -> Result<(Vec<u8>, String)> {
    let bytes = serde_json::to_vec_pretty(b)
        .map_err(|e| Error::Invalid(format!("cannot serialise the bundle: {e}")))?;
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(Error::Invalid(format!(
            "the bundle is {} bytes; a share bundle is limited to {MAX_BUNDLE_BYTES} bytes (16 MiB)",
            bytes.len()
        )));
    }
    let sha = hex::encode(Sha256::digest(&bytes));
    Ok((bytes, sha))
}

// ---------------------------------------------------------------- import

/// What an import found (or, for a bundle imported before, what it found then).
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct ImportSummary {
    pub bundle_sha256: String,
    pub analyst: String,
    pub new: usize,
    pub agrees: usize,
    pub conflicts: usize,
    pub missing: usize,
    /// Items stored (or, for a preview, that would be stored) as `superseded`: a newer open proposal from the same
    /// analyst already covers them.
    pub superseded: usize,
    pub already_imported: bool,
    /// Rule-set difference (warning only): rules in the bundle not in this case, and the reverse.
    pub rules_only_in_bundle: Vec<String>,
    pub rules_only_here: Vec<String>,
}

/// One stored bundle item.
#[derive(Debug, Clone, Serialize)]
pub struct Proposal {
    pub bundle_sha256: String,
    pub item_key: String,
    pub source_analyst: String,
    pub classification: String,
    pub state: String,
    pub item: Item,
    /// This case's state of the object at import, in the item's shape (None when it had none).
    pub current: Option<Value>,
}

/// A refusal of the bundle's content: bad input, not a refused decision.
fn invalid(e: Error) -> Error {
    match e {
        Error::Decision(m) => Error::Invalid(format!("the bundle is invalid: {m}")),
        other => other,
    }
}

fn bad(m: String) -> Error {
    Error::Invalid(format!("the bundle is invalid: {m}"))
}

fn non_empty(what: &str, s: &str) -> Result<()> {
    if s.trim().is_empty() {
        return Err(bad(format!("{what} is empty")));
    }
    Ok(())
}

fn rfc3339(what: &str, s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| bad(format!("{what} {s:?} is not an RFC 3339 time")))
}

fn check_item(item: &Item) -> Result<()> {
    match item {
        Item::Finding {
            finding_id,
            status,
            disposition_reason,
        } => {
            non_empty("a finding id", finding_id)?;
            check_text("a finding id", finding_id).map_err(invalid)?;
            FindingStatus::parse(status).map_err(invalid)?;
            if let Some(r) = disposition_reason {
                check_text("a reason", r).map_err(invalid)?;
            }
        }
        Item::Indicator {
            tenant_key,
            ioc_type,
            value,
            verdict,
            note,
            ..
        } => {
            if let Some(t) = tenant_key {
                check_text("a tenant key", t).map_err(invalid)?;
            }
            IndicatorType::parse(ioc_type).map_err(invalid)?;
            Verdict::parse(verdict).map_err(invalid)?;
            non_empty("an indicator value", value)?;
            check_text("an indicator value", value).map_err(invalid)?;
            if let Some(n) = note {
                check_text("a note", n).map_err(invalid)?;
            }
        }
        Item::TimelineEntry {
            entry_id,
            tenant_key,
            event_time,
            end_time,
            event_count,
            title,
            narrative,
            phase,
            status,
            evidence,
            supersedes,
        } => {
            non_empty("an entry id", entry_id)?;
            for s in supersedes {
                non_empty("a superseded entry id", s)?;
                check_text("a superseded entry id", s).map_err(invalid)?;
            }
            check_text("an entry id", entry_id).map_err(invalid)?;
            if let Some(t) = tenant_key {
                check_text("a tenant key", t).map_err(invalid)?;
            }
            let start = rfc3339("an event time", event_time)?;
            if let Some(end) = end_time {
                if rfc3339("an end time", end)? < start {
                    return Err(bad(format!(
                        "timeline entry {entry_id} ends ({end}) before it starts ({event_time})"
                    )));
                }
            }
            if *event_count == Some(0) || event_count.is_some_and(|c| i64::try_from(c).is_err()) {
                return Err(bad(format!(
                    "timeline entry {entry_id} has an event count outside 1..=i64::MAX"
                )));
            }
            non_empty("a title", title)?;
            check_title(title).map_err(invalid)?;
            if let Some(n) = narrative {
                check_text("a narrative", n).map_err(invalid)?;
            }
            Phase::parse(phase).map_err(invalid)?;
            if !matches!(status.as_str(), "verified" | "rejected") {
                return Err(bad(format!(
                    "timeline entry {entry_id} is {status:?}; a bundle holds verified or rejected entries"
                )));
            }
            if status == "verified" && evidence.is_empty() {
                return Err(bad(format!(
                    "verified timeline entry {entry_id} has no evidence"
                )));
            }
            for r in evidence {
                check_text("an evidence reference", r).map_err(invalid)?;
                EvidenceRef::parse(r).map_err(invalid)?;
            }
        }
        Item::Note { target, text } => {
            check_text("a note target", target).map_err(invalid)?;
            NoteTarget::parse(target).map_err(invalid)?;
            non_empty("a note", text)?;
            check_text("a note", text).map_err(invalid)?;
        }
    }
    Ok(())
}

/// Parse and validate bundle bytes (size, schema, format, every value) without touching the case. Returns the
/// bundle and the hex sha256 of `bytes`.
pub fn parse(bytes: &[u8]) -> Result<(Bundle, String)> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(Error::Invalid(format!(
            "a share bundle is limited to 16 MiB ({MAX_BUNDLE_BYTES} bytes); this file is {} bytes",
            bytes.len()
        )));
    }
    let b: Bundle = serde_json::from_slice(bytes)
        .map_err(|e| Error::Invalid(format!("not a share bundle: {e}")))?;
    if b.format != FORMAT {
        return Err(Error::Invalid(format!(
            "share bundle format {} is not supported (this build reads format {FORMAT})",
            b.format
        )));
    }
    let name = b
        .analyst
        .strip_prefix("analyst:")
        .ok_or_else(|| bad(format!("{:?} is not analyst:<name>", b.analyst)))?;
    if Reviewer::analyst(name).map_err(invalid)?.as_str() != b.analyst {
        return Err(bad(format!("{:?} is not analyst:<name>", b.analyst)));
    }
    rfc3339("exported_at", &b.exported_at)?;
    for (what, v) in [
        ("source_case_id", Some(&b.source_case_id)),
        ("source_audit_head.hash", b.source_audit_head.hash.as_ref()),
    ] {
        if let Some(v) = v {
            check_text(what, v).map_err(invalid)?;
        }
    }
    for v in b.evidence.source_files.iter().chain(&b.evidence.rules) {
        check_text("an evidence identity", v).map_err(invalid)?;
    }
    let mut keys = BTreeSet::new();
    for item in &b.items {
        check_item(item)?;
        if !keys.insert(item.key()) {
            return Err(bad(format!("item {} appears twice", item.key())));
        }
    }
    let sha = hex::encode(Sha256::digest(bytes));
    Ok((b, sha))
}

/// This case's state of an item's object.
enum Current {
    /// The object (finding, note target, entry evidence) does not exist here.
    Missing,
    /// It exists but holds no state of this kind (an undecided finding, no such indicator, entry or note).
    Absent,
    /// Its state, in the item's shape.
    Present(Item),
    /// A timeline entry's state (content in the item's shape, under the item's id and lineage) and the id of the
    /// entry here that holds it.
    Entry { item: Item, here_id: String },
}

impl Current {
    fn json(&self) -> Option<Value> {
        match self {
            Current::Present(i) | Current::Entry { item: i, .. } => serde_json::to_value(i).ok(),
            _ => None,
        }
    }
}

/// `id`, or the entry whose verification superseded it (repeatedly, whatever that entry's status is now): where an
/// entry's content lives now.
fn follow(conn: &Connection, id: String) -> Result<String> {
    let mut id = id;
    for _ in 0..10_000 {
        let superseded =
            timeline_entries::entry_state(conn, &id)?.is_some_and(|s| s["status"] == "superseded");
        if !superseded {
            break;
        }
        let next: Option<String> = conn
            .query_row(
                "SELECT object_id FROM audit_trail WHERE action = 'verify_entry' AND object_type = 'timeline_entry' \
                 AND json_extract_string(after, '$.superseded_entry') = ? ORDER BY seq DESC LIMIT 1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        match next {
            Some(n) => id = n,
            None => break,
        }
    }
    Ok(id)
}

/// The entry here that holds a bundle entry: for its id and then each id it superseded (nearest first), the entry
/// with that id here, or the entry an accepted proposal from the same source case made of it; followed to its
/// current successor. None when there is none.
fn entry_here(
    conn: &Connection,
    source_case_id: &str,
    entry_id: &str,
    supersedes: &[String],
) -> Result<Option<String>> {
    for id in std::iter::once(entry_id).chain(supersedes.iter().map(String::as_str)) {
        if timeline_entries::entry_state(conn, id)?.is_some() {
            return Ok(Some(follow(conn, id.to_string())?));
        }
        if let Some(a) = applied_entry(conn, source_case_id, id)? {
            return Ok(Some(follow(conn, a)?));
        }
    }
    Ok(None)
}

/// The entry an accepted proposal from `source_case_id` made of the source entry `id`: the latest accepted proposal
/// for `timeline_entry:<id>`, or else the latest one whose lineage (`supersedes`) holds `id`.
fn applied_entry(conn: &Connection, source_case_id: &str, id: &str) -> Result<Option<String>> {
    let rows: Vec<(String, String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT item_key, CAST(item AS VARCHAR), applied_entry_id FROM imported_proposals \
             WHERE source_case_id = ? AND state = 'accepted' AND applied_entry_id IS NOT NULL \
               AND starts_with(item_key, 'timeline_entry:') \
             ORDER BY decided_at DESC, bundle_sha256, item_key",
        )?;
        let rows = stmt.query_map(params![source_case_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    let key = format!("timeline_entry:{id}");
    if let Some((_, _, a)) = rows.iter().find(|(k, _, _)| *k == key) {
        return Ok(Some(a.clone()));
    }
    for (_, item, a) in &rows {
        if lineage(item).iter().any(|s| s == id) {
            return Ok(Some(a.clone()));
        }
    }
    Ok(None)
}

/// The `supersedes` list of a stored timeline-entry item (empty for anything else or unreadable JSON).
fn lineage(item_json: &str) -> Vec<String> {
    match serde_json::from_str::<Item>(item_json) {
        Ok(Item::TimelineEntry { supersedes, .. }) => supersedes,
        _ => Vec::new(),
    }
}

/// The source entry ids a set of items proposes: each timeline entry's id and its lineage. A note on one of them
/// depends on that entry's proposal rather than being missing.
fn proposed_entry_ids<'a>(items: impl IntoIterator<Item = &'a Item>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for i in items {
        if let Item::TimelineEntry {
            entry_id,
            supersedes,
            ..
        } = i
        {
            out.insert(entry_id.clone());
            out.extend(supersedes.iter().cloned());
        }
    }
    out
}

/// A note's target in this case: an entry target resolved through [`entry_here`] (entry ids are per case); None when
/// the target does not exist here.
fn note_target_here(
    conn: &Connection,
    source_case_id: &str,
    target: &str,
) -> Result<Option<NoteTarget>> {
    let t = NoteTarget::parse(target)?;
    if let NoteTarget::Entry(id) = &t {
        return Ok(entry_here(conn, source_case_id, id, &[])?.map(NoteTarget::Entry));
    }
    match t.check_exists(conn) {
        Ok(()) => Ok(Some(t)),
        Err(Error::Decision(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

fn exists(conn: &Connection, sql: &str, args: &[&str]) -> Result<bool> {
    // Not cached: DuckDB keeps a cached plan's statistics (see audit::head).
    Ok(conn.query_row(sql, duckdb::params_from_iter(args.iter()), |r| r.get(0))?)
}

/// `pending`: the source entry ids proposed by the same bundle ([`proposed_entry_ids`]).
fn current_of(
    conn: &Connection,
    item: &Item,
    source_case_id: &str,
    pending: &BTreeSet<String>,
) -> Result<Current> {
    Ok(match item {
        Item::Finding { finding_id, .. } => {
            let row = conn
                .query_row(
                    "SELECT CAST(status AS VARCHAR), disposition_reason, decided_by IS NULL FROM findings \
                     WHERE finding_id = ?",
                    params![finding_id],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, Option<String>>(1)?,
                            r.get::<_, bool>(2)?,
                        ))
                    },
                )
                .optional()?;
            match row {
                None => Current::Missing,
                Some((_, _, true)) => Current::Absent,
                Some((status, disposition_reason, false)) => Current::Present(Item::Finding {
                    finding_id: finding_id.clone(),
                    status,
                    disposition_reason,
                }),
            }
        }
        Item::Indicator {
            tenant_key,
            ioc_type,
            value,
            ..
        } => {
            let id = indicators::indicator_id(
                tenant_key.as_deref(),
                IndicatorType::parse(ioc_type)?,
                value,
            );
            conn.query_row(
                "SELECT tenant_key, CAST(type AS VARCHAR), value, CAST(verdict AS VARCHAR), note, \
                        removed_at IS NULL FROM case_indicators WHERE indicator_id = ?",
                params![id],
                |r| {
                    Ok(Item::Indicator {
                        tenant_key: r.get(0)?,
                        ioc_type: r.get(1)?,
                        value: r.get(2)?,
                        verdict: r.get(3)?,
                        note: r.get(4)?,
                        active: r.get(5)?,
                    })
                },
            )
            .optional()?
            .map_or(Current::Absent, Current::Present)
        }
        Item::TimelineEntry {
            entry_id,
            evidence,
            supersedes,
            ..
        } => {
            for r in evidence {
                let r = EvidenceRef::parse(r)?;
                if !exists(
                    conn,
                    "SELECT EXISTS (SELECT 1 FROM record_sources WHERE table_name = ? AND record_key = ?)",
                    &[&r.source_table, &r.record_key],
                )? {
                    return Ok(Current::Missing);
                }
            }
            let here = entry_here(conn, source_case_id, entry_id, supersedes)?;
            match here
                .as_deref()
                .map(|h| timeline_entries::entry_state(conn, h))
                .transpose()?
                .flatten()
            {
                None => Current::Absent,
                Some(s) => {
                    let text = |k: &str| s[k].as_str().unwrap_or_default().to_string();
                    Current::Entry {
                        here_id: here.unwrap_or_default(),
                        item: Item::TimelineEntry {
                            supersedes: supersedes.clone(),
                            entry_id: entry_id.clone(),
                            tenant_key: s["tenant_key"].as_str().map(String::from),
                            event_time: text("event_time"),
                            end_time: s["end_time"].as_str().map(String::from),
                            event_count: s["event_count"].as_u64(),
                            title: text("title"),
                            narrative: s["narrative"].as_str().map(String::from),
                            phase: text("phase"),
                            status: text("status"),
                            evidence: s["evidence"]
                                .as_array()
                                .map(|a| {
                                    a.iter()
                                        .filter_map(Value::as_str)
                                        .map(String::from)
                                        .collect()
                                })
                                .unwrap_or_default(),
                        },
                    }
                }
            }
        }
        Item::Note { target, text } => {
            let Some(t) = note_target_here(conn, source_case_id, target)? else {
                // A note on an entry this bundle proposes waits for that entry: `new`, accepted after the entry.
                return Ok(match NoteTarget::parse(target)? {
                    NoteTarget::Entry(id) if pending.contains(&id) => Current::Absent,
                    _ => Current::Missing,
                });
            };
            let (object_type, object_id, source_table) = match &t {
                NoteTarget::Finding(id) => ("finding", id.as_str(), ""),
                NoteTarget::Entry(id) => ("timeline_entry", id.as_str(), ""),
                NoteTarget::Indicator(id) => ("indicator", id.as_str(), ""),
                NoteTarget::Evidence { table, key } => ("evidence", key.as_str(), table.as_str()),
            };
            if exists(
                conn,
                "SELECT EXISTS (SELECT 1 FROM annotations WHERE CAST(object_type AS VARCHAR) = ? AND object_id = ? \
                 AND coalesce(source_table, '') = ? AND text = ?)",
                &[object_type, object_id, source_table, text],
            )? {
                Current::Present(item.clone())
            } else {
                Current::Absent
            }
        }
    })
}

/// The item as compared: an indicator value case-insensitively, as its id is computed.
fn normalised(item: &Item) -> Item {
    let mut i = item.clone();
    if let Item::Indicator { value, .. } = &mut i {
        *value = value.to_lowercase();
    }
    i
}

fn classify(item: &Item, current: &Current) -> &'static str {
    match current {
        Current::Missing => "missing",
        Current::Absent => "new",
        Current::Present(c) | Current::Entry { item: c, .. } => {
            if normalised(c) == normalised(item) {
                "agrees"
            } else {
                "conflict"
            }
        }
    }
}

/// Sorted lists: (only in `a`, only in `b`).
fn difference(a: &[String], b: &[String]) -> (Vec<String>, Vec<String>) {
    let (sa, sb): (BTreeSet<&String>, BTreeSet<&String>) = (a.iter().collect(), b.iter().collect());
    (
        sa.difference(&sb).map(|s| s.to_string()).collect(),
        sb.difference(&sa).map(|s| s.to_string()).collect(),
    )
}

/// One bundle item as import would store it.
struct PlannedRow {
    key: String,
    /// The proposals this item replaces: its own key and, for an entry, the keys of the entries it superseded.
    keys: Vec<String>,
    item: Item,
    current: Option<String>,
    class: &'static str,
    state: &'static str,
    newer_open: bool,
}

/// What importing a bundle would do, decided without writing anything.
enum Plan {
    /// Imported before: the stored counts.
    Already(ImportSummary),
    Fresh(ImportSummary, Vec<PlannedRow>),
}

/// Validate the bundle against this case and classify every item. Reads only. A row's `state` sees the rows
/// planned before it in the same bundle, as the stored rows would be seen by the next item.
fn plan(conn: &Connection, bundle: &Bundle, sha: &str) -> Result<Plan> {
    let here = evidence_of(conn)?;
    let (rules_only_in_bundle, rules_only_here) = difference(&bundle.evidence.rules, &here.rules);
    let mut summary = ImportSummary {
        bundle_sha256: sha.to_string(),
        analyst: bundle.analyst.clone(),
        rules_only_in_bundle,
        rules_only_here,
        ..ImportSummary::default()
    };
    let tally = |s: &mut ImportSummary, class: &str| match class {
        "new" => s.new += 1,
        "agrees" => s.agrees += 1,
        "conflict" => s.conflicts += 1,
        _ => s.missing += 1,
    };
    let stored: Vec<(String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT classification, state FROM imported_proposals WHERE bundle_sha256 = ? ORDER BY item_key",
        )?;
        let rows = stmt.query_map(params![sha], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    // The audited import is the duplicate marker (a bundle with no items stores no proposal rows).
    let imported = exists(
        conn,
        "SELECT EXISTS (SELECT 1 FROM audit_trail WHERE action = 'import_share' AND object_type = 'share_bundle' \
         AND object_id = ?)",
        &[sha],
    )?;
    if imported || !stored.is_empty() {
        for (c, state) in &stored {
            tally(&mut summary, c);
            summary.superseded += usize::from(state == "superseded");
        }
        summary.already_imported = true;
        return Ok(Plan::Already(summary));
    }
    let (only_bundle, only_here) = difference(&bundle.evidence.source_files, &here.source_files);
    if !only_bundle.is_empty() || !only_here.is_empty() {
        return Err(Error::Invalid(format!(
            "the bundle's evidence differs from this case: {} files only in the bundle, {} only here",
            only_bundle.len(),
            only_here.len()
        )));
    }
    let pending = proposed_entry_ids(&bundle.items);
    let mut rows: Vec<PlannedRow> = Vec::new();
    for item in &bundle.items {
        let key = item.key();
        let current = current_of(conn, item, &bundle.source_case_id, &pending)?;
        let class = classify(item, &current);
        tally(&mut summary, class);
        let mut keys = vec![key.clone()];
        if let Item::TimelineEntry { supersedes, .. } = item {
            keys.extend(supersedes.iter().map(|s| format!("timeline_entry:{s}")));
        }
        // Earlier open rows of this same bundle share its exported_at, so they count as "at or after".
        let mut newer_open = rows
            .iter()
            .any(|r| r.state == "open" && keys.contains(&r.key));
        for k in &keys {
            newer_open |= exists(
                conn,
                "SELECT EXISTS (SELECT 1 FROM imported_proposals WHERE source_analyst = ? AND item_key = ? \
                 AND state = 'open' AND exported_at >= CAST(? AS TIMESTAMPTZ))",
                &[&bundle.analyst, k, &bundle.exported_at],
            )?;
        }
        if let Item::TimelineEntry { entry_id, .. } = item {
            newer_open |=
                rows.iter().any(|r| {
                    r.state == "open"
                        && matches!(&r.item, Item::TimelineEntry { supersedes, .. }
                        if supersedes.iter().any(|s| s == entry_id))
                }) || newer_open_successor(conn, &bundle.analyst, &bundle.exported_at, entry_id)?;
        }
        let state = match class {
            "agrees" => "agrees",
            _ if newer_open => "superseded",
            _ => "open",
        };
        summary.superseded += usize::from(state == "superseded");
        rows.push(PlannedRow {
            key,
            keys,
            item: item.clone(),
            current: current.json().map(|v| v.to_string()),
            class,
            state,
            newer_open,
        });
    }
    Ok(Plan::Fresh(summary, rows))
}

/// What [`import`] would report for these bytes, writing nothing (no proposals, no audit row): the same parsing,
/// evidence check and classification. `already_imported` is reported as import would.
pub fn preview(conn: &Connection, bytes: &[u8]) -> Result<ImportSummary> {
    let (bundle, sha) = parse(bytes)?;
    match plan(conn, &bundle, &sha)? {
        Plan::Already(s) | Plan::Fresh(s, _) => Ok(s),
    }
}

/// Check evidence identity and store every item as a proposal (one transaction, one `import_share` audit row).
/// Refused (storing nothing) when the bundle's source files differ from this case's. A bundle imported before is a
/// no-op: its stored counts come back with `already_imported`. An open proposal from the same analyst for the same
/// item is superseded by the newer of the two bundles (by `exported_at`).
pub fn import(conn: &Connection, reviewer: &Reviewer, bytes: &[u8]) -> Result<ImportSummary> {
    let (bundle, sha) = parse(bytes)?;
    in_tx(conn, |tx| {
        let (summary, rows) = match plan(tx, &bundle, &sha)? {
            Plan::Already(s) => return Ok(s),
            Plan::Fresh(s, rows) => (s, rows),
        };
        let ts = audit::now();
        let ts_text = audit::ts_text(&ts);
        for row in &rows {
            if !row.newer_open {
                for k in &row.keys {
                    tx.execute(
                        "UPDATE imported_proposals SET state = 'superseded' WHERE source_analyst = ? AND item_key = ? \
                         AND state = 'open' AND exported_at < CAST(? AS TIMESTAMPTZ)",
                        params![bundle.analyst, k, bundle.exported_at],
                    )?;
                }
            }
            tx.execute(
                "INSERT INTO imported_proposals (bundle_sha256, item_key, source_analyst, source_case_id, exported_at, \
                     imported_at, item, current, classification, state) \
                 VALUES (?, ?, ?, ?, CAST(? AS TIMESTAMPTZ), CAST(? AS TIMESTAMPTZ), CAST(? AS JSON), \
                         CAST(? AS JSON), ?, ?)",
                params![
                    sha,
                    row.key,
                    bundle.analyst,
                    bundle.source_case_id,
                    bundle.exported_at,
                    ts_text,
                    serde_json::to_string(&row.item).map_err(|e| Error::Invalid(e.to_string()))?,
                    row.current,
                    row.class,
                    row.state
                ],
            )?;
        }
        audit::append_at(
            tx,
            ts,
            reviewer.as_str(),
            None,
            "import_share",
            "share_bundle",
            &sha,
            None,
            Some(&json!({
                "analyst": bundle.analyst,
                "source_case_id": bundle.source_case_id,
                "source_audit_head": bundle.source_audit_head,
                "items": bundle.items.len(),
                "new": summary.new,
                "agrees": summary.agrees,
                "conflicts": summary.conflicts,
                "missing": summary.missing,
            })),
            None,
        )?;
        Ok(summary)
    })
}

/// Whether the same analyst has an open timeline proposal from a bundle exported at or after `exported_at` whose
/// lineage holds `entry_id` (an edited successor of it, imported first).
fn newer_open_successor(
    conn: &Connection,
    analyst: &str,
    exported_at: &str,
    entry_id: &str,
) -> Result<bool> {
    let mut stmt = conn.prepare(
        "SELECT CAST(item AS VARCHAR) FROM imported_proposals WHERE source_analyst = ? AND state = 'open' \
         AND starts_with(item_key, 'timeline_entry:') AND exported_at >= CAST(? AS TIMESTAMPTZ)",
    )?;
    let items: Vec<String> = stmt
        .query_map(params![analyst, exported_at], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(items
        .iter()
        .any(|i| lineage(i).iter().any(|s| s == entry_id)))
}

/// One stored proposal plus its source case id; NotFound when there is none.
fn load(conn: &Connection, sha: &str, key: &str) -> Result<(Proposal, String)> {
    let row = conn
        .query_row(
            "SELECT source_analyst, source_case_id, classification, state, CAST(item AS VARCHAR), \
                    CAST(current AS VARCHAR) \
             FROM imported_proposals WHERE bundle_sha256 = ? AND item_key = ?",
            params![sha, key],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((source_analyst, case_id, classification, state, item, current)) = row else {
        return Err(Error::NotFound(format!("proposal {key} of bundle {sha}")));
    };
    let json_err = |e: serde_json::Error| Error::Invalid(format!("stored proposal {key}: {e}"));
    Ok((
        Proposal {
            bundle_sha256: sha.to_string(),
            item_key: key.to_string(),
            source_analyst,
            classification,
            state,
            item: serde_json::from_str(&item).map_err(json_err)?,
            current: current
                .map(|c| serde_json::from_str(&c))
                .transpose()
                .map_err(json_err)?,
        },
        case_id,
    ))
}

/// Open proposals (state = 'open'), oldest bundle first, then item key.
pub fn proposals(conn: &Connection) -> Result<Vec<Proposal>> {
    let keys: Vec<(String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT bundle_sha256, item_key FROM imported_proposals WHERE state = 'open' \
             ORDER BY exported_at, bundle_sha256, item_key",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    keys.iter()
        .map(|(sha, key)| load(conn, sha, key).map(|(p, _)| p))
        .collect()
}

fn short(sha: &str) -> &str {
    &sha[..sha.len().min(12)]
}

/// Apply `item` as `actor`'s decisions; pushes each audit entry as it commits. Returns the timeline entry id the
/// item ended up as, for an entry.
fn apply(
    conn: &Connection,
    actor: &Actor,
    item: &Item,
    current: &Current,
    source_case_id: &str,
    reason: &str,
    applied: &mut Vec<AuditEntry>,
) -> Result<Option<String>> {
    match item {
        Item::Finding {
            finding_id,
            status,
            disposition_reason,
        } => {
            let status = FindingStatus::parse(status)?;
            let disposition = disposition_reason
                .as_deref()
                .or(status.closes().then_some(reason));
            applied.push(write::set_finding_status_from(
                conn,
                actor,
                finding_id,
                status,
                disposition,
                Some(reason),
            )?);
            Ok(None)
        }
        Item::Indicator {
            tenant_key,
            ioc_type,
            value,
            verdict,
            note,
            active,
        } => {
            let ty = IndicatorType::parse(ioc_type)?;
            let (need_add, active_now) = match current {
                Current::Present(Item::Indicator {
                    verdict: v,
                    note: n,
                    active: a,
                    ..
                }) => {
                    let add = v != verdict || n != note || (*active && !a);
                    (add, add || *a)
                }
                _ => (true, true),
            };
            let id = indicators::indicator_id(tenant_key.as_deref(), ty, value);
            if need_add {
                indicators::add_indicator_from(
                    conn,
                    actor,
                    tenant_key.as_deref(),
                    ty,
                    value,
                    Verdict::parse(verdict)?,
                    note.as_deref(),
                    Some(reason),
                )?;
                applied.extend(audit::log(conn, Some(("indicator", &id)))?.pop());
            }
            if !active && active_now {
                indicators::remove_indicator_from(conn, actor, &id, Some(reason))?;
                applied.extend(audit::log(conn, Some(("indicator", &id)))?.pop());
            }
            Ok(None)
        }
        Item::TimelineEntry {
            entry_id,
            tenant_key,
            event_time,
            end_time,
            event_count,
            title,
            narrative,
            phase,
            status,
            evidence,
            ..
        } => {
            let event_time = rfc3339("an event time", event_time)?;
            let end_time = end_time
                .as_deref()
                .map(|t| rfc3339("an end time", t))
                .transpose()?;
            let event_count = *event_count;
            let phase = Phase::parse(phase)?;
            let evidence = evidence
                .iter()
                .map(|r| EvidenceRef::parse(r))
                .collect::<Result<Vec<_>>>()?;
            let id = match current {
                Current::Entry {
                    item:
                        Item::TimelineEntry {
                            status: here,
                            event_time: t,
                            end_time: et,
                            event_count: ec,
                            title: ti,
                            narrative: n,
                            phase: ph,
                            evidence: ev,
                            ..
                        },
                    here_id,
                } => {
                    if matches!(here.as_str(), "rejected" | "superseded") {
                        return Err(Error::Decision(format!(
                            "timeline entry {here_id} (for {entry_id}) is {here} here and cannot take the proposal"
                        )));
                    }
                    let same_fields = rfc3339("an event time", t)? == event_time
                        && et
                            .as_deref()
                            .map(|t| rfc3339("an end time", t))
                            .transpose()?
                            == end_time
                        && *ec == event_count
                        && ti == title
                        && n == narrative
                        && ph == phase.as_str()
                        && ev == &evidence.iter().map(EvidenceRef::text).collect::<Vec<_>>();
                    if status == "rejected" {
                        // Reconcile the content first, then reject, so the entry here ends as the bundle has it.
                        // A proposed entry is edited in place. A verified one takes a successor that is verified
                        // (superseding it) and then rejected, as the source case did.
                        let edit = EntryEdit {
                            event_time: Some(event_time),
                            end_time: Some(end_time),
                            event_count: Some(event_count),
                            title: Some(title.clone()),
                            narrative: Some(narrative.clone()),
                            phase: Some(phase),
                            evidence: Some(evidence.clone()),
                        };
                        let id = if same_fields {
                            here_id.clone()
                        } else if here == "proposed" {
                            let (id, e) = timeline_entries::edit_from(
                                conn,
                                actor,
                                here_id,
                                edit,
                                Some(reason),
                            )?;
                            applied.push(e);
                            id
                        } else {
                            if evidence.is_empty() {
                                return Err(Error::Decision(format!(
                                    "timeline entry {here_id} (for {entry_id}) is verified here with other content, \
                                     and the rejected version has no evidence to verify it with; discard the \
                                     proposal or reject the entry here"
                                )));
                            }
                            let (id, e) = timeline_entries::edit_from(
                                conn,
                                actor,
                                here_id,
                                edit,
                                Some(reason),
                            )?;
                            applied.push(e);
                            applied.push(timeline_entries::verify_from(
                                conn,
                                actor,
                                &id,
                                Some(reason),
                            )?);
                            id
                        };
                        applied.push(timeline_entries::reject(conn, actor, &id, reason)?);
                        return Ok(Some(id));
                    }
                    let id = if same_fields {
                        here_id.clone()
                    } else {
                        let (id, e) = timeline_entries::edit_from(
                            conn,
                            actor,
                            here_id,
                            EntryEdit {
                                event_time: Some(event_time),
                                end_time: Some(end_time),
                                event_count: Some(event_count),
                                title: Some(title.clone()),
                                narrative: Some(narrative.clone()),
                                phase: Some(phase),
                                evidence: Some(evidence),
                            },
                            Some(reason),
                        )?;
                        applied.push(e);
                        id
                    };
                    if !(same_fields && here == "verified") {
                        applied.push(timeline_entries::verify_from(
                            conn,
                            actor,
                            &id,
                            Some(reason),
                        )?);
                    }
                    id
                }
                _ => {
                    let (id, e) = timeline_entries::propose_from(
                        conn,
                        actor,
                        NewEntry {
                            tenant_key: tenant_key.clone(),
                            event_time,
                            end_time,
                            event_count,
                            title: title.clone(),
                            narrative: narrative.clone(),
                            phase,
                            evidence,
                        },
                        Some(reason),
                    )?;
                    applied.push(e);
                    if status == "rejected" {
                        applied.push(timeline_entries::reject(conn, actor, &id, reason)?);
                    } else {
                        applied.push(timeline_entries::verify_from(
                            conn,
                            actor,
                            &id,
                            Some(reason),
                        )?);
                    }
                    id
                }
            };
            Ok(Some(id))
        }
        Item::Note { target, text } => {
            let Some(t) = note_target_here(conn, source_case_id, target)? else {
                return Err(Error::Decision(format!(
                    "the note's target {target} is not in this case yet; accept the proposal of its timeline entry \
                     first"
                )));
            };
            let (_, e) = notes::add_note_from(conn, actor, t, text, Some(reason))?;
            applied.push(e);
            Ok(None)
        }
    }
}

/// Apply one open proposal as `reviewer`'s analyst decision(s), each with the audit reason
/// `from analyst:<A>, bundle <sha12>`, then mark it accepted (`accept_proposal`). Refused when the proposal is not
/// open, its object is missing here, the object changed since the import ("reload"), or the object has a pending
/// agent decision (review it first). The decisions commit one by one (each in its own transaction): if one fails
/// after another was applied (a timeline edit applied, its verify refused), the proposal stays open and the error
/// names the audit seqs already applied. Returns every audit entry, the `accept_proposal` one last.
pub fn accept(
    conn: &Connection,
    reviewer: &Reviewer,
    bundle_sha256: &str,
    item_key: &str,
) -> Result<Vec<AuditEntry>> {
    let (p, source_case_id) = load(conn, bundle_sha256, item_key)?;
    if p.state != "open" {
        return Err(Error::Decision(format!(
            "proposal {item_key} of bundle {} is {}; only an open proposal can be accepted",
            short(bundle_sha256),
            p.state
        )));
    }
    if p.classification == "missing" {
        return Err(Error::Decision(format!(
            "{item_key} does not exist in this case; the proposal cannot be accepted (discard it)"
        )));
    }
    let pending = {
        let mut stmt = conn.prepare(
            "SELECT item_key FROM imported_proposals WHERE bundle_sha256 = ? ORDER BY item_key",
        )?;
        let keys: Vec<String> = stmt
            .query_map(params![bundle_sha256], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        let mut items = Vec::new();
        for k in keys.iter().filter(|k| k.starts_with("timeline_entry:")) {
            items.push(load(conn, bundle_sha256, k)?.0.item);
        }
        proposed_entry_ids(&items)
    };
    let current = current_of(conn, &p.item, &source_case_id, &pending)?;
    if matches!(current, Current::Missing) || current.json() != p.current {
        return Err(Error::Decision(format!(
            "{item_key} changed since the bundle was imported; reload"
        )));
    }
    let reason = format!("from {}, bundle {}", p.source_analyst, short(bundle_sha256));
    let actor = reviewer.as_actor();
    let mut applied = Vec::new();
    let entry_id = match apply(
        conn,
        &actor,
        &p.item,
        &current,
        &source_case_id,
        &reason,
        &mut applied,
    ) {
        Ok(id) => id,
        Err(e) if applied.is_empty() => return Err(e),
        Err(e) => {
            let seqs: Vec<String> = applied.iter().map(|a| a.seq.to_string()).collect();
            return Err(Error::Decision(format!(
                "{e}; already applied from proposal {item_key}: audit seq {}; the proposal stays open",
                seqs.join(", ")
            )));
        }
    };
    let done = in_tx(conn, |tx| {
        let ts = audit::now();
        let n = tx.execute(
            "UPDATE imported_proposals SET state = 'accepted', decided_by = ?, decided_at = CAST(? AS TIMESTAMPTZ), \
             applied_entry_id = ? WHERE bundle_sha256 = ? AND item_key = ? AND state = 'open'",
            params![reviewer.as_str(), audit::ts_text(&ts), entry_id, bundle_sha256, item_key],
        )?;
        if n != 1 {
            return Err(Error::Decision(format!(
                "proposal {item_key} is no longer open"
            )));
        }
        let mut after = json!({
            "state": "accepted",
            "imported_from": p.source_analyst,
            "bundle_sha256": bundle_sha256,
            "source_case_id": source_case_id,
            "applied": applied.iter().map(|a| a.seq).collect::<Vec<_>>(),
        });
        if let Some(id) = &entry_id {
            after["entry_id"] = Value::String(id.clone());
        }
        audit::append_at(
            tx,
            ts,
            reviewer.as_str(),
            None,
            "accept_proposal",
            "share_bundle",
            &format!("{bundle_sha256}:{item_key}"),
            Some(&json!({ "state": "open", "classification": p.classification })),
            Some(&after),
            None,
        )
    })?;
    applied.push(done);
    Ok(applied)
}

/// Mark one open proposal discarded (one `discard_proposal` audit row; the comment is its reason).
pub fn discard(
    conn: &Connection,
    reviewer: &Reviewer,
    bundle_sha256: &str,
    item_key: &str,
    comment: Option<&str>,
) -> Result<AuditEntry> {
    let comment = comment.map(str::trim).filter(|c| !c.is_empty());
    if let Some(c) = comment {
        check_text("a comment", c)?;
    }
    in_tx(conn, |tx| {
        let (p, _) = load(tx, bundle_sha256, item_key)?;
        if p.state != "open" {
            return Err(Error::Decision(format!(
                "proposal {item_key} of bundle {} is {}; only an open proposal can be discarded",
                short(bundle_sha256),
                p.state
            )));
        }
        let ts = audit::now();
        tx.execute(
            "UPDATE imported_proposals SET state = 'discarded', decided_by = ?, decided_at = CAST(? AS TIMESTAMPTZ) \
             WHERE bundle_sha256 = ? AND item_key = ?",
            params![reviewer.as_str(), audit::ts_text(&ts), bundle_sha256, item_key],
        )?;
        audit::append_at(
            tx,
            ts,
            reviewer.as_str(),
            None,
            "discard_proposal",
            "share_bundle",
            &format!("{bundle_sha256}:{item_key}"),
            Some(&json!({ "state": "open", "classification": p.classification })),
            Some(&json!({ "state": "discarded", "imported_from": p.source_analyst })),
            comment,
        )
    })
}
