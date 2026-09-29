//! Writing detection results: the `detection_runs` log and the merge of hits into `findings` /
//! `finding_evidence` by fingerprint.
//!
//! Detection never writes the analyst's columns (`status` after insert, `disposition_reason`,
//! `assigned_to`) and never deletes: a finding is inserted once, later runs only widen its time
//! range, refresh the rule's fields, flag `rule_updated` and append evidence.

use crate::Result;
use crate::detect::rule::Rule;
use crate::detect::rule_conn::Hit;
use chrono::{DateTime, SecondsFormat, Utc};
use duckdb::{Transaction, params};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// sha256 hex of `rule_id 0x1f tenant_key 0x1f value1 0x1f value2 ...`; a NULL value is the
/// single byte 0x00.
pub fn fingerprint(rule_id: &str, tenant_key: &str, group_values: &[Option<String>]) -> String {
    let mut h = Sha256::new();
    h.update(rule_id.as_bytes());
    h.update([0x1f]);
    h.update(tenant_key.as_bytes());
    for v in group_values {
        h.update([0x1f]);
        match v {
            Some(v) => h.update(v.as_bytes()),
            None => h.update([0x00]),
        }
    }
    hex::encode(h.finalize())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Ran,
    NotApplicable,
    Error,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RunStatus::Ran => "ran",
            RunStatus::NotApplicable => "not_applicable",
            RunStatus::Error => "error",
        }
    }
}

/// What happened to one rule for one tenant.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub tenant_key: String,
    pub rule_id: String,
    pub status: RunStatus,
    pub reason: Option<String>,
    pub hits: Vec<Hit>,
    pub duration_ms: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MergeCounts {
    pub findings_new: u64,
    pub findings_updated: u64,
    pub evidence_added: u64,
}

fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn severity_str(rule: &Rule) -> String {
    serde_json::to_value(rule.severity)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "medium".to_string())
}

pub fn next_run_id(tx: &Transaction) -> Result<i64> {
    Ok(tx.query_row(
        "SELECT coalesce(max(run_id), 0) + 1 FROM detection_runs",
        [],
        |r| r.get(0),
    )?)
}

pub fn write_run_row(
    tx: &Transaction,
    run_id: i64,
    started: DateTime<Utc>,
    rule: &Rule,
    o: &Outcome,
) -> Result<()> {
    tx.execute(
        "INSERT INTO detection_runs (run_id, tenant_key, rule_id, rule_version, rule_sha256, status, reason, \
             hits, duration_ms, started_at) \
         VALUES (?, ?, ?, ?, ?, CAST(? AS detection_status), ?, ?, ?, CAST(? AS TIMESTAMPTZ))",
        params![
            run_id,
            o.tenant_key,
            o.rule_id,
            rule.version,
            o.sha256,
            o.status.as_str(),
            o.reason,
            o.hits.len() as i64,
            o.duration_ms as i64,
            ts(started),
        ],
    )?;
    Ok(())
}

/// The value of a `group_by` field for a hit: an output column, else a key of the JSON context.
fn group_value(h: &Hit, field: &str) -> Option<String> {
    match field {
        "record_key" => Some(h.record_key.clone()),
        "source_table" => Some(h.source_table.clone()),
        "event_time" => h.event_time.map(ts),
        "actor_upn" => h.actor_upn.clone(),
        "ip" => h.ip.clone(),
        key => {
            let ctx: serde_json::Value = serde_json::from_str(h.context.as_deref()?).ok()?;
            match ctx.get(key)? {
                serde_json::Value::Null => None,
                serde_json::Value::String(s) => Some(s.clone()),
                other => Some(other.to_string()),
            }
        }
    }
}

struct Stored {
    rule_sha256: Option<String>,
    rule_version: Option<i64>,
    severity: String,
    title: String,
    first_seen: Option<i64>,
    last_seen: Option<i64>,
}

/// Merge the hits of one (tenant, rule) run into `findings` and `finding_evidence`, then flag
/// this rule's other findings for that tenant when the rule text changed under them.
pub fn merge_hits(
    tx: &Transaction,
    run_id: i64,
    now: DateTime<Utc>,
    rule: &Rule,
    o: &Outcome,
) -> Result<MergeCounts> {
    let mut counts = MergeCounts::default();
    let group_by: Vec<String> = if rule.group_by.is_empty() {
        vec!["record_key".to_string()]
    } else {
        rule.group_by.clone()
    };
    let mut groups: BTreeMap<String, Vec<&Hit>> = BTreeMap::new();
    for h in &o.hits {
        let values: Vec<Option<String>> = group_by.iter().map(|g| group_value(h, g)).collect();
        groups
            .entry(fingerprint(&rule.id, &o.tenant_key, &values))
            .or_default()
            .push(h);
    }
    let severity = severity_str(rule);
    let mut touched = BTreeSet::new();
    for (fp, mut hits) in groups {
        hits.sort_by(|a, b| {
            (a.event_time, &a.record_key, &a.source_table).cmp(&(
                b.event_time,
                &b.record_key,
                &b.source_table,
            ))
        });
        let finding_id = fp[..16].to_string();
        touched.insert(finding_id.clone());
        let first = hits.iter().filter_map(|h| h.event_time).min();
        let last = hits.iter().filter_map(|h| h.event_time).max();
        let actor = hits.iter().find_map(|h| h.actor_upn.clone());

        let stored = tx
            .query_row(
                "SELECT rule_sha256, rule_version, severity, title, epoch_us(first_seen), epoch_us(last_seen) \
                 FROM findings WHERE finding_id = ?",
                params![finding_id],
                |r| {
                    Ok(Stored {
                        rule_sha256: r.get(0)?,
                        rule_version: r.get(1)?,
                        severity: r.get(2)?,
                        title: r.get(3)?,
                        first_seen: r.get(4)?,
                        last_seen: r.get(5)?,
                    })
                },
            )
            .ok();
        match stored {
            None => {
                tx.execute(
                    "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, \
                         severity, title, actor_upn, first_seen, last_seen, created_by, created_at, updated_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS TIMESTAMPTZ), CAST(? AS TIMESTAMPTZ), \
                             CAST('rule' AS finding_creator), CAST(? AS TIMESTAMPTZ), CAST(? AS TIMESTAMPTZ))",
                    params![
                        finding_id,
                        fp,
                        o.tenant_key,
                        rule.id,
                        rule.version,
                        o.sha256,
                        severity,
                        rule.title,
                        actor,
                        first.map(ts),
                        last.map(ts),
                        ts(now),
                        ts(now),
                    ],
                )?;
                counts.findings_new += 1;
            }
            Some(s) => {
                let micros = |t: Option<DateTime<Utc>>| t.map(|t| t.timestamp_micros());
                let widen_first = match (s.first_seen, micros(first)) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                let widen_last = match (s.last_seen, micros(last)) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
                let sha_changed = s.rule_sha256.as_deref() != Some(o.sha256.as_str());
                let changed = sha_changed
                    || s.rule_version != Some(i64::from(rule.version))
                    || s.severity != severity
                    || s.title != rule.title
                    || widen_first != s.first_seen
                    || widen_last != s.last_seen;
                if changed {
                    let to_ts =
                        |m: Option<i64>| m.and_then(DateTime::from_timestamp_micros).map(ts);
                    tx.execute(
                        "UPDATE findings SET rule_version = ?, rule_sha256 = ?, severity = ?, title = ?, \
                             first_seen = CAST(? AS TIMESTAMPTZ), last_seen = CAST(? AS TIMESTAMPTZ), \
                             rule_updated = (rule_updated OR ?), updated_at = CAST(? AS TIMESTAMPTZ) \
                         WHERE finding_id = ?",
                        params![
                            rule.version,
                            o.sha256,
                            severity,
                            rule.title,
                            to_ts(widen_first),
                            to_ts(widen_last),
                            sha_changed,
                            ts(now),
                            finding_id,
                        ],
                    )?;
                    counts.findings_updated += 1;
                }
            }
        }

        let mut have: BTreeSet<(String, String)> = BTreeSet::new();
        let mut st = tx.prepare(
            "SELECT source_table, record_key FROM finding_evidence WHERE finding_id = ?",
        )?;
        for row in st.query_map(params![finding_id], |r| Ok((r.get(0)?, r.get(1)?)))? {
            have.insert(row?);
        }
        for h in hits {
            if !have.insert((h.source_table.clone(), h.record_key.clone())) {
                continue;
            }
            tx.execute(
                "INSERT INTO finding_evidence (finding_id, source_table, record_key, event_time, role, context, \
                     added_run_id) \
                 VALUES (?, ?, ?, CAST(? AS TIMESTAMPTZ), CAST('trigger' AS evidence_role), CAST(? AS JSON), ?)",
                params![
                    finding_id,
                    h.source_table,
                    h.record_key,
                    h.event_time.map(ts),
                    h.context,
                    run_id,
                ],
            )?;
            counts.evidence_added += 1;
        }
    }

    // Findings of this rule that were not hit this time: still flag a changed rule (or changed
    // case indicators) so the analyst re-reviews them.
    let ids: Vec<String> = {
        let mut st = tx.prepare(
            "SELECT finding_id FROM findings WHERE tenant_key = ? AND rule_id = ? \
             AND rule_sha256 IS DISTINCT FROM ? ORDER BY finding_id",
        )?;
        st.query_map(params![o.tenant_key, rule.id, o.sha256], |r| r.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?
    };
    for id in ids.into_iter().filter(|id| !touched.contains(id)) {
        tx.execute(
            "UPDATE findings SET rule_updated = true, rule_sha256 = ?, rule_version = ?, \
                 updated_at = CAST(? AS TIMESTAMPTZ) WHERE finding_id = ?",
            params![o.sha256, rule.version, ts(now), id],
        )?;
        counts.findings_updated += 1;
    }
    Ok(counts)
}
