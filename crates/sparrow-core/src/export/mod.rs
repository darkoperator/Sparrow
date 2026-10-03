//! Exports (Addendum D.6): the Markdown customer report, the Timeline Explorer CSV and the XLSX workbook. All three
//! read the case through a connection and write nothing to it (no audit row). Every export carries the Sparrow
//! version, the rule-pack hash, the generation time, the audit-chain status, the head hash and the decision counts
//! ([`header`]), and every decided item shows its provenance ([`Provenance`]).

pub mod header;
pub mod report_md;
pub mod text;
pub mod timeline_csv;
pub mod workbook_xlsx;

use crate::Result;
use crate::case::review::DECISION_ACTIONS;
use chrono::{DateTime, Utc};
use duckdb::Connection;
use std::collections::BTreeSet;

/// `yyyy-MM-dd HH:mm:ss` in UTC.
pub(crate) fn when(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub(crate) fn at(us: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(us).unwrap_or_default()
}

/// What an object's decision tags say, for a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionClass {
    /// No decision yet (a rule-created finding nobody has decided).
    None,
    /// An agent decision nobody has reviewed.
    AiPending,
    /// An indicator from before the audit trail, not yet reviewed.
    LegacyPending,
    Accepted,
    Discarded,
}

/// The decision tags of one finding, indicator or timeline entry.
#[derive(Debug, Clone, Default)]
pub struct Provenance {
    pub decided_by: Option<String>,
    pub decided_at: Option<DateTime<Utc>>,
    pub on_behalf_of: Option<String>,
    pub review_state: Option<String>,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub review_comment: Option<String>,
    /// The object's latest decision is a `legacy_decision` audit entry (made before the audit trail existed).
    pub legacy: bool,
}

pub const LABEL_AI_PENDING: &str = "AI decision — not reviewed";
pub const LABEL_LEGACY_PENDING: &str = "decision recorded before the audit trail — not reviewed";

impl Provenance {
    pub fn class(&self) -> DecisionClass {
        match self.review_state.as_deref() {
            Some("pending_review") if self.legacy => DecisionClass::LegacyPending,
            Some("pending_review") => DecisionClass::AiPending,
            Some("accepted") => DecisionClass::Accepted,
            Some("discarded") => DecisionClass::Discarded,
            _ => DecisionClass::None,
        }
    }

    /// The label an export shows next to the item (empty when there is no decision), with reviewer and time for a
    /// reviewed one. Plain text; the caller escapes it for its format.
    pub fn label(&self) -> String {
        let reviewed = |what: &str| {
            let mut s = format!(
                "{what} by {}",
                self.reviewed_by.as_deref().unwrap_or("an unnamed reviewer")
            );
            if let Some(t) = &self.reviewed_at {
                s.push_str(&format!(" at {} UTC", when(t)));
            }
            s
        };
        match self.class() {
            DecisionClass::None => String::new(),
            DecisionClass::AiPending => LABEL_AI_PENDING.to_string(),
            DecisionClass::LegacyPending => LABEL_LEGACY_PENDING.to_string(),
            DecisionClass::Accepted => reviewed("accepted"),
            DecisionClass::Discarded => reviewed("discarded"),
        }
    }

    /// `decided by agent:x on behalf of analyst:y at <time> UTC` (empty without a decision).
    pub fn decided_text(&self) -> String {
        let Some(by) = &self.decided_by else {
            return String::new();
        };
        let mut s = format!("decided by {by}");
        if let Some(o) = &self.on_behalf_of {
            s.push_str(&format!(" on behalf of {o}"));
        }
        if let Some(t) = &self.decided_at {
            s.push_str(&format!(" at {} UTC", when(t)));
        }
        s
    }
}

/// `(object_type, object_id)` of every object whose latest decision is a `legacy_decision` audit entry.
pub(crate) fn legacy_objects(conn: &Connection) -> Result<BTreeSet<(String, String)>> {
    let list = DECISION_ACTIONS
        .iter()
        .map(|a| format!("'{a}'"))
        .collect::<Vec<_>>()
        .join(",");
    // Not cached: an aggregate planned on an empty audit_trail misreads real rows later.
    let mut stmt = conn.prepare(&format!(
        "SELECT a.object_type, a.object_id FROM audit_trail a \
         WHERE a.action = 'legacy_decision' AND a.seq = (SELECT max(b.seq) FROM audit_trail b \
              WHERE b.object_type = a.object_type AND b.object_id = a.object_id AND b.action IN ({list}))"
    ))?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// One indicator with every decision and review tag (the `Indicator` struct has no review columns).
#[derive(Debug, Clone)]
pub struct IndicatorRow {
    pub indicator_id: String,
    pub tenant_key: Option<String>,
    pub ty: String,
    pub value: String,
    pub verdict: String,
    pub note: Option<String>,
    pub added_by: String,
    pub added_at: DateTime<Utc>,
    pub removed_at: Option<DateTime<Utc>>,
    pub removed_by: Option<String>,
    pub prov: Provenance,
}

/// Every indicator (removed ones included, flagged), by type, value, id.
pub fn indicator_rows(conn: &Connection) -> Result<Vec<IndicatorRow>> {
    let legacy = legacy_objects(conn)?;
    let mut stmt = conn.prepare(
        "SELECT indicator_id, tenant_key, CAST(type AS VARCHAR), value, CAST(verdict AS VARCHAR), note, added_by, \
                epoch_us(added_at), epoch_us(removed_at), removed_by, decided_by, epoch_us(decided_at), on_behalf_of, \
                CAST(review_state AS VARCHAR), reviewed_by, epoch_us(reviewed_at), review_comment \
         FROM case_indicators ORDER BY type, value, indicator_id",
    )?;
    let rows = stmt.query_map([], |r| {
        let id: String = r.get(0)?;
        Ok(IndicatorRow {
            tenant_key: r.get(1)?,
            ty: r.get(2)?,
            value: r.get(3)?,
            verdict: r.get(4)?,
            note: r.get(5)?,
            added_by: r.get(6)?,
            added_at: at(r.get(7)?),
            removed_at: r.get::<_, Option<i64>>(8)?.map(at),
            removed_by: r.get(9)?,
            prov: Provenance {
                decided_by: r.get(10)?,
                decided_at: r.get::<_, Option<i64>>(11)?.map(at),
                on_behalf_of: r.get(12)?,
                review_state: r.get(13)?,
                reviewed_by: r.get(14)?,
                reviewed_at: r.get::<_, Option<i64>>(15)?.map(at),
                review_comment: r.get(16)?,
                legacy: legacy.contains(&("indicator".to_string(), id.clone())),
            },
            indicator_id: id,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

pub(crate) fn finding_provenance(
    f: &crate::case::read::FindingRow,
    legacy: &BTreeSet<(String, String)>,
) -> Provenance {
    Provenance {
        decided_by: f.decided_by.clone(),
        decided_at: f.decided_at,
        on_behalf_of: f.on_behalf_of.clone(),
        review_state: f.review_state.clone(),
        reviewed_by: f.reviewed_by.clone(),
        reviewed_at: f.reviewed_at,
        review_comment: f.review_comment.clone(),
        legacy: legacy.contains(&("finding".to_string(), f.finding_id.clone())),
    }
}

pub(crate) fn entry_provenance(
    e: &crate::case::timeline_entries::Entry,
    legacy: &BTreeSet<(String, String)>,
) -> Provenance {
    Provenance {
        decided_by: Some(e.decided_by.clone()),
        decided_at: Some(e.decided_at),
        on_behalf_of: e.on_behalf_of.clone(),
        review_state: Some(e.review_state.clone()),
        reviewed_by: e.reviewed_by.clone(),
        reviewed_at: e.reviewed_at,
        review_comment: e.review_comment.clone(),
        legacy: legacy.contains(&("timeline_entry".to_string(), e.entry_id.clone())),
    }
}

/// One evidence source whose availability is not `collected`, with why.
#[derive(Debug, Clone)]
pub struct Gap {
    pub tenant_key: String,
    pub evidence: String,
    pub title: String,
    pub status: String,
    pub reason: String,
    pub remediation: Option<String>,
    pub rows: i64,
    pub min_time: Option<DateTime<Utc>>,
    pub max_time: Option<DateTime<Utc>>,
    pub users_covered: Option<i64>,
}

/// The evidence sources that are not `collected` (not licensed, not enabled, beyond retention, not collected), by
/// tenant and evidence id.
pub fn evidence_gaps(conn: &Connection) -> Result<Vec<Gap>> {
    let mut stmt = conn.prepare(
        "SELECT tenant_key, evidence, title, CAST(status AS VARCHAR), reason, remediation, rows, \
                epoch_us(min_time), epoch_us(max_time), users_covered \
         FROM evidence_availability WHERE CAST(status AS VARCHAR) <> 'collected' ORDER BY tenant_key, evidence",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Gap {
            tenant_key: r.get(0)?,
            evidence: r.get(1)?,
            title: r.get(2)?,
            status: r.get(3)?,
            reason: r.get(4)?,
            remediation: r.get(5)?,
            rows: r.get(6)?,
            min_time: r.get::<_, Option<i64>>(7)?.map(at),
            max_time: r.get::<_, Option<i64>>(8)?.map(at),
            users_covered: r.get(9)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// `<collection folder>/<file>:<line>` of every sighting of an evidence record (empty for a record provenance
/// could not resolve).
pub fn source_refs(conn: &Connection, table: &str, key: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT to_json(source_refs)::VARCHAR FROM record_source_refs WHERE table_name = ? AND record_key = ?",
    )?;
    let mut rows = stmt.query([table, key])?;
    Ok(match rows.next()? {
        Some(r) => r
            .get::<_, Option<String>>(0)?
            .and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok())
            .unwrap_or_default(),
        None => Vec::new(),
    })
}

pub(crate) fn io_err(e: std::io::Error) -> crate::Error {
    crate::Error::Io {
        path: "export output".into(),
        source: e,
    }
}
