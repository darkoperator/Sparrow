//! Post-detection enrichment (agent accuracy round): computed, checkable FACTS about findings and
//! accounts, stored in `finding_facts` and `account_rollup` so the CLI, the report
//! and the workbook only read them. Facts only: no verdict, label or score.
//!
//! The rebuild runs at the end of every detection run, after the merge transaction, and rewrites
//! both tables from scratch in ONE transaction. It never fails detection: a failed rebuild rolls
//! back (the previous rows stay whole), its message goes to `case_meta.enrichment_error`, and the
//! readers report the facts as unavailable. A successful rebuild clears that key and records its
//! run in `case_meta.enrichment_run_id`.
//!
//! Readers decide whether the stored facts may be shown with [`enrichment_state`] and nothing
//! else: the facts are valid only for [`EnrichState::Ok`], i.e. the enrichment of the LATEST
//! detection run succeeded. The marker alone is not enough: when a rebuild fails and writing its
//! failure marker fails too, the previous run's rows and `enrichment_run_id` remain, and only the
//! run-id comparison shows them stale.

pub mod accounts;
pub mod facts;

use crate::Result;
use crate::detect::load::RuleSet;
use chrono::{DateTime, Utc};
use duckdb::Connection;
use serde::Serialize;

/// Version of the `finding_facts.facts` JSON shape.
pub const FACTS_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize)]
pub struct EnrichReport {
    pub facts_rows: u64,
    pub accounts: u64,
    pub error: Option<String>,
}

/// Whether the stored facts and roll-up describe the case's latest detection run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EnrichState {
    /// The enrichment of the latest detection run (`run_id`) succeeded: the rows are valid.
    Ok { run_id: i64 },
    /// No enrichment ever ran (a case detected before this feature, or never detected).
    Never,
    /// The latest enrichment failed; `reason` is its message (`case_meta.enrichment_error`).
    Failed { reason: String },
    /// The rows come from an earlier run (`enriched_run`) than the latest detection run.
    Stale { enriched_run: i64, latest_run: i64 },
}

/// THE reader check (fail closed): show `finding_facts` / `account_rollup` only when this returns
/// [`EnrichState::Ok`]. Valid means `case_meta.enrichment_run_id` equals the latest
/// `detection_runs.run_id` AND no `case_meta.enrichment_error` exists.
pub fn enrichment_state(conn: &Connection) -> Result<EnrichState> {
    let meta = |key: &str| -> Result<Option<String>> {
        let mut st = conn.prepare("SELECT value FROM case_meta WHERE key = ?")?;
        let mut rows = st.query([key])?;
        Ok(match rows.next()? {
            Some(r) => Some(r.get(0)?),
            None => None,
        })
    };
    if let Some(reason) = meta("enrichment_error")? {
        return Ok(EnrichState::Failed { reason });
    }
    let Some(enriched) = meta("enrichment_run_id")? else {
        return Ok(EnrichState::Never);
    };
    let Ok(enriched_run) = enriched.trim().parse::<i64>() else {
        return Ok(EnrichState::Failed {
            reason: format!("case_meta.enrichment_run_id is not a run id: {enriched:?}"),
        });
    };
    let latest: Option<i64> =
        conn.query_row("SELECT max(run_id) FROM detection_runs", [], |r| r.get(0))?;
    let latest_run = latest.unwrap_or(0);
    Ok(if latest_run == enriched_run {
        EnrichState::Ok {
            run_id: enriched_run,
        }
    } else {
        EnrichState::Stale {
            enriched_run,
            latest_run,
        }
    })
}

/// Rebuild finding_facts and account_rollup in ONE transaction. Never returns Err for a SQL failure of the
/// rebuild itself: it rolls back, writes case_meta.enrichment_error, and returns the report with `error` set.
pub fn rebuild(conn: &mut Connection, set: &RuleSet, run_id: i64) -> Result<EnrichReport> {
    match rebuild_in_tx(conn, set, run_id) {
        Ok(report) => Ok(report),
        Err(e) => {
            // The transaction was dropped, so rolled back: the previous rows are untouched.
            let msg = e.to_string();
            conn.execute(
                "INSERT OR REPLACE INTO case_meta (key, value) VALUES ('enrichment_error', ?)",
                [&msg],
            )?;
            Ok(EnrichReport {
                error: Some(msg),
                ..EnrichReport::default()
            })
        }
    }
}

fn rebuild_in_tx(conn: &mut Connection, set: &RuleSet, run_id: i64) -> Result<EnrichReport> {
    let tx = conn.transaction()?;
    tx.execute_batch("DELETE FROM finding_facts; DELETE FROM account_rollup;")?;
    let facts_rows = facts::rebuild(&tx, set, run_id)?;
    let accounts = accounts::rebuild(&tx, set, run_id)?;
    tx.execute("DELETE FROM case_meta WHERE key = 'enrichment_error'", [])?;
    tx.execute(
        "INSERT OR REPLACE INTO case_meta (key, value) VALUES ('enrichment_run_id', ?)",
        [run_id.to_string()],
    )?;
    tx.commit()?;
    Ok(EnrichReport {
        facts_rows,
        accounts,
        error: None,
    })
}

/// SQL text literal.
pub(crate) fn lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// A time from DuckDB `epoch_us`.
pub(crate) fn at_us(us: Option<i64>) -> Option<DateTime<Utc>> {
    us.and_then(DateTime::from_timestamp_micros)
}

/// Optional times in the case's text form (`2026-03-01T09:00:00.000000Z`, as the audit trail and
/// the read commands write them); read back from any RFC 3339 text.
pub(crate) mod ts_opt {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => s.serialize_str(&crate::case::audit::ts_text(t)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<DateTime<Utc>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .map(|t| t.with_timezone(&Utc))
                    .map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}
