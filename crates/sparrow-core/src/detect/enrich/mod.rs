//! Post-detection enrichment (agent accuracy round): computed, checkable FACTS about findings and
//! accounts, stored in `finding_facts` (and, from Task 2, `account_rollup`) so the CLI, the report
//! and the workbook only read them. Facts only: no verdict, label or score.
//!
//! The rebuild runs at the end of every detection run, after the merge transaction, and rewrites
//! both tables from scratch in ONE transaction. It never fails detection: a failed rebuild rolls
//! back (the previous rows stay whole), its message goes to `case_meta.enrichment_error`, and the
//! readers report the facts as unavailable. A successful rebuild clears that key and records its
//! run in `case_meta.enrichment_run_id`.

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
    tx.execute("DELETE FROM case_meta WHERE key = 'enrichment_error'", [])?;
    tx.execute(
        "INSERT OR REPLACE INTO case_meta (key, value) VALUES ('enrichment_run_id', ?)",
        [run_id.to_string()],
    )?;
    tx.commit()?;
    Ok(EnrichReport {
        facts_rows,
        accounts: 0,
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
