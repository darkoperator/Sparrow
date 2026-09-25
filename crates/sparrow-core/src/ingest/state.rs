//! Staged loading of keyed rows into the state tables (spec 5.2, latest wins), risk
//! detections and collector flags. Same pattern as `bulk.rs`: an appender fills a TEMP
//! staging table (every value as text) and set-based SQL merges it inside the caller's
//! transaction. The tables have no key constraints; this module keeps `record_key` unique.

use crate::db::state_tables::{Col, LoadMode, TableSpec};
use crate::readers::text::SourcePos;
use crate::{Error, Result};
use duckdb::types::Value as DbValue;
use duckdb::{Connection, appender_params_from_iter, params};

/// One row to load. `cells` align with the `columns` passed to `load_rows`.
#[derive(Debug, Clone)]
pub struct StagedRow {
    pub ordinal: u64,
    pub pos: SourcePos,
    pub raw_sha256: String,
    pub record_key: String,
    pub cells: Vec<Option<String>>,
    /// Source record as JSON text (merged into `raw` on update).
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadOutcome {
    /// Rows in the batch.
    pub staged: u64,
    /// New keys.
    pub inserted: u64,
    /// Stored rows whose values this batch changed.
    pub updated: u64,
}

impl LoadOutcome {
    /// Rows that only added a sighting.
    pub fn duplicate(&self) -> u64 {
        self.staged - self.inserted - self.updated
    }
}

/// `expr` (staged text) cast to `sql_type`; lists and structs go through JSON.
fn cast(sql_type: &str, expr: &str) -> String {
    if sql_type.ends_with("[]") || sql_type.starts_with("STRUCT") {
        format!("CAST(CAST({expr} AS JSON) AS {sql_type})")
    } else {
        format!("CAST({expr} AS {sql_type})")
    }
}

/// New value of column `c` (staged as `p.v{i}`) for a stored row of `target`.
fn new_value(c: &Col, i: usize, target: &str) -> String {
    let v = cast(c.sql_type, &format!("p.v{i}"));
    if c.keep_when_null {
        format!("coalesce({v}, {target}.{})", c.name)
    } else {
        v
    }
}

/// Load `rows` into `spec.table`, filling only `columns`. Callers must hold a transaction.
pub fn load_rows(
    conn: &Connection,
    spec: &TableSpec,
    columns: &[&str],
    collection_id: i64,
    file_id: i64,
    rows: &[StagedRow],
) -> Result<LoadOutcome> {
    let t = spec.table;
    let cols: Vec<&Col> = columns
        .iter()
        .map(|n| {
            spec.col(n)
                .ok_or_else(|| Error::Invalid(format!("{t} has no loadable column {n}")))
        })
        .collect::<Result<_>>()?;
    if rows.is_empty() {
        return Ok(LoadOutcome::default());
    }
    let vcols: String = (0..cols.len()).map(|i| format!(", v{i} VARCHAR")).collect();
    conn.execute_batch(&format!(
        "CREATE OR REPLACE TEMP TABLE stage_state (ord BIGINT, record_key VARCHAR, raw VARCHAR,
             line_start BIGINT, line_end BIGINT, byte_offset BIGINT, byte_length BIGINT,
             raw_sha256 VARCHAR{vcols});"
    ))?;
    {
        let mut app = conn.appender("stage_state")?;
        let text = |s: &Option<String>| s.clone().map_or(DbValue::Null, DbValue::Text);
        for r in rows {
            if r.cells.len() != cols.len() {
                return Err(Error::Invalid(format!(
                    "{t}: row {} has {} cells for {} columns",
                    r.record_key,
                    r.cells.len(),
                    cols.len()
                )));
            }
            let mut vals = vec![
                DbValue::BigInt(r.ordinal as i64),
                DbValue::Text(r.record_key.clone()),
                text(&r.raw),
                DbValue::BigInt(r.pos.line_start as i64),
                DbValue::BigInt(r.pos.line_end as i64),
                DbValue::BigInt(r.pos.byte_offset as i64),
                DbValue::BigInt(r.pos.byte_length as i64),
                DbValue::Text(r.raw_sha256.clone()),
            ];
            vals.extend(r.cells.iter().map(text));
            app.append_row(appender_params_from_iter(vals))?;
        }
        app.flush()?;
    }
    conn.execute_batch(&format!(
        "CREATE OR REPLACE TEMP TABLE stage_pick AS SELECT * FROM stage_state
             QUALIFY row_number() OVER (PARTITION BY record_key ORDER BY ord) = 1;
         CREATE OR REPLACE TEMP TABLE stage_new AS SELECT p.* FROM stage_pick p
             WHERE NOT EXISTS (SELECT 1 FROM {t} t WHERE t.record_key = p.record_key);"
    ))?;
    let inserted: i64 = conn.query_row("SELECT count(*) FROM stage_new", [], |r| r.get(0))?;
    let collected_at =
        format!("(SELECT collected_at FROM collections WHERE collection_id = {collection_id})");
    let updated = if spec.mode == LoadMode::LatestWins {
        let unchanged = cols
            .iter()
            .enumerate()
            .map(|(i, c)| format!("t.{} IS NOT DISTINCT FROM {}", c.name, new_value(c, i, "t")))
            .collect::<Vec<_>>()
            .join(" AND ");
        conn.execute_batch(&format!(
            "CREATE OR REPLACE TEMP TABLE stage_upd AS
             SELECT p.* FROM stage_pick p
             JOIN {t} t ON t.record_key = p.record_key
             JOIN collections old ON old.collection_id = t.collection_id
             JOIN collections cur ON cur.collection_id = {collection_id}
             WHERE NOT (CASE WHEN old.collected_at IS NOT NULL AND cur.collected_at IS NOT NULL
                             THEN old.collected_at > cur.collected_at
                             ELSE old.collection_id > cur.collection_id END)
               AND NOT ({unchanged});"
        ))?;
        let n: i64 = conn.query_row("SELECT count(*) FROM stage_upd", [], |r| r.get(0))?;
        let sets = cols
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{} = {}", c.name, new_value(c, i, t)))
            .collect::<Vec<_>>()
            .join(", ");
        conn.execute(
            &format!(
                "UPDATE {t} SET {sets}, collection_id = {collection_id}, collected_at = {collected_at},
                     raw = CASE WHEN p.raw IS NULL THEN {t}.raw
                                ELSE json_merge_patch(coalesce({t}.raw, CAST('{{}}' AS JSON)), CAST(p.raw AS JSON)) END
                 FROM stage_upd p WHERE {t}.record_key = p.record_key"
            ),
            [],
        )?;
        n as u64
    } else {
        0
    };
    let names = cols.iter().map(|c| c.name).collect::<Vec<_>>().join(", ");
    let casts = cols
        .iter()
        .enumerate()
        .map(|(i, c)| cast(c.sql_type, &format!("p.v{i}")))
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute(
        &format!(
            "INSERT INTO {t} (record_key, collection_id, collected_at, {names}, raw)
             SELECT p.record_key, {collection_id}, {collected_at}, {casts}, CAST(p.raw AS JSON)
             FROM stage_new p"
        ),
        [],
    )?;
    conn.execute(
        &format!(
            "INSERT INTO record_sources (table_name, record_key, file_id, record_ordinal, line_start,
                                         line_end, byte_offset, byte_length, raw_sha256)
             SELECT '{t}', record_key, ?, ord, line_start, line_end, byte_offset, byte_length, raw_sha256
             FROM stage_state ON CONFLICT DO NOTHING"
        ),
        params![file_id],
    )?;
    Ok(LoadOutcome {
        staged: rows.len() as u64,
        inserted: inserted as u64,
        updated,
    })
}
