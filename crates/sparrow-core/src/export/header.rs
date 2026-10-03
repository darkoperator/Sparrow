//! The header every export carries (Addendum D.6): Sparrow version, rule-pack hash, generation time, audit-chain
//! status, head hash and the decision counts.

use crate::Result;
use crate::case::audit;
use chrono::{DateTime, Utc};
use duckdb::Connection;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Decisions by review state across findings, indicators and timeline entries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DecisionCounts {
    /// Agent decisions nobody has reviewed ("AI decision — not reviewed").
    pub pending_review: i64,
    /// Decisions recorded before the audit trail existed (indicators from an older case), not yet reviewed.
    pub legacy: i64,
    pub accepted: i64,
    pub discarded: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportHeader {
    pub sparrow_version: String,
    /// SHA-256 over the `rule_id:rule_sha256` lines of the latest detection run; `None` when detection never ran.
    pub rule_pack_sha256: Option<String>,
    pub generated_at: DateTime<Utc>,
    pub chain_ok: bool,
    /// The first open break, when the chain is not ok.
    pub chain_problem: Option<String>,
    pub chain_entries: i64,
    pub head_hash: Option<String>,
    pub decisions: DecisionCounts,
}

fn rule_pack_hash(conn: &Connection) -> Result<Option<String>> {
    // Not cached: an aggregate planned on an empty table misreads real rows later.
    let mut stmt = conn.prepare(
        "SELECT DISTINCT rule_id, rule_sha256 FROM detection_runs \
         WHERE run_id = (SELECT max(run_id) FROM detection_runs) ORDER BY rule_id",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut h = Sha256::new();
    let mut n = 0;
    for row in rows {
        let (id, sha) = row?;
        h.update(format!("{id}:{sha}\n").as_bytes());
        n += 1;
    }
    Ok((n > 0).then(|| hex::encode(h.finalize())))
}

pub fn decision_counts(conn: &Connection) -> Result<DecisionCounts> {
    let legacy = super::legacy_objects(conn)?;
    let mut stmt = conn.prepare(
        "SELECT 'finding', finding_id, CAST(review_state AS VARCHAR) FROM findings WHERE review_state IS NOT NULL \
         UNION ALL SELECT 'indicator', indicator_id, CAST(review_state AS VARCHAR) FROM case_indicators \
                   WHERE review_state IS NOT NULL \
         UNION ALL SELECT 'timeline_entry', entry_id, CAST(review_state AS VARCHAR) FROM timeline_entries",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    let mut c = DecisionCounts::default();
    for row in rows {
        let (ty, id, state) = row?;
        match state.as_str() {
            "pending_review" if legacy.contains(&(ty, id)) => c.legacy += 1,
            "pending_review" => c.pending_review += 1,
            "accepted" => c.accepted += 1,
            "discarded" => c.discarded += 1,
            _ => {}
        }
    }
    Ok(c)
}

/// The header for an export generated at `generated_at` (an input, never the clock: exports are reproducible).
pub fn build(conn: &Connection, generated_at: DateTime<Utc>) -> Result<ExportHeader> {
    let chain = audit::verify(conn)?;
    Ok(ExportHeader {
        sparrow_version: crate::VERSION.to_string(),
        rule_pack_sha256: rule_pack_hash(conn)?,
        generated_at,
        chain_ok: chain.ok,
        chain_problem: chain.problem,
        chain_entries: chain.entries,
        head_hash: chain.head_hash,
        decisions: decision_counts(conn)?,
    })
}

impl ExportHeader {
    pub fn chain_text(&self) -> String {
        if self.chain_ok {
            format!("ok ({} entries)", self.chain_entries)
        } else {
            format!(
                "BROKEN: {}",
                self.chain_problem.as_deref().unwrap_or("unverified")
            )
        }
    }

    pub fn decisions_text(&self) -> String {
        let d = &self.decisions;
        format!(
            "AI-decided, not reviewed {}; recorded before the audit trail {}; accepted {}; discarded {}",
            d.pending_review, d.legacy, d.accepted, d.discarded
        )
    }

    /// The header as `(label, value)` pairs, in the order every export shows them.
    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Sparrow version", self.sparrow_version.clone()),
            (
                "Rule pack SHA-256",
                self.rule_pack_sha256
                    .clone()
                    .unwrap_or_else(|| "no detection run".into()),
            ),
            (
                "Generated at",
                format!("{} UTC", super::when(&self.generated_at)),
            ),
            ("Audit chain", self.chain_text()),
            (
                "Audit head hash",
                self.head_hash.clone().unwrap_or_else(|| "none".into()),
            ),
            ("Decisions", self.decisions_text()),
        ]
    }

    /// The header on one line (the CSV's closing record).
    pub fn one_line(&self) -> String {
        self.pairs()
            .into_iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}
