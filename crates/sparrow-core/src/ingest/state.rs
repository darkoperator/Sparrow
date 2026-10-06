//! Staged loading of keyed rows into the state tables (spec 5.2, per-column latest wins), the
//! event tables (fill missing: evidence is never overwritten), risk detections and collector
//! flags. Same pattern as `bulk.rs`: an appender fills a TEMP staging table (every value as
//! text) and set-based SQL merges it inside the caller's transaction. The tables have no key
//! constraints; this module keeps `record_key` unique.

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
    /// Per cell: the value is a time that came without a zone (stored as if UTC). Empty means
    /// false for every cell.
    pub tz_assumed: Vec<bool>,
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

/// `expr` (staged text) cast to `sql_type`; lists, structs and maps go through JSON.
fn cast(sql_type: &str, expr: &str) -> String {
    if sql_type.ends_with("[]") || sql_type.starts_with("STRUCT") || sql_type.starts_with("MAP") {
        format!("CAST(CAST({expr} AS JSON) AS {sql_type})")
    } else {
        format!("CAST({expr} AS {sql_type})")
    }
}

/// `raw` with top-level `null` members removed, so a merge never deletes stored keys
/// (RFC 7396: a null in the patch removes the key). Non-object or invalid JSON is kept as is.
fn strip_top_level_nulls(raw: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::Object(mut map)) => {
            map.retain(|_, v| !v.is_null());
            serde_json::Value::Object(map).to_string()
        }
        _ => raw.to_string(),
    }
}

/// JSON path of column `name` inside `column_collections`.
fn cc_path(name: &str) -> String {
    format!("'$.\"{name}\"'")
}

/// `column_collections` for a new row: every listed column, except NULLs of
/// keep_when_null columns (a NULL there never claims the column).
fn insert_claims(cols: &[&Col], collection_id: i64) -> String {
    let pairs = cols
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let v = if c.keep_when_null {
                format!("CASE WHEN p.v{i} IS NULL THEN NULL ELSE {collection_id} END")
            } else {
                collection_id.to_string()
            };
            format!("'{}', {v}", c.name)
        })
        .collect::<Vec<_>>()
        .join(", ");
    // Merging into {} drops the NULL members.
    format!("json_merge_patch(CAST('{{}}' AS JSON), json_object({pairs}))")
}

/// Loaded columns that hold times.
fn time_columns<'c>(cols: &'c [&'c Col]) -> impl Iterator<Item = (usize, &'c Col)> + 'c {
    cols.iter()
        .copied()
        .enumerate()
        .filter(|(_, c)| c.sql_type == "TIMESTAMPTZ")
}

/// `tz_assumed` of a new row: `{column: true}` for each time column staged without a zone;
/// SQL NULL when no time column is loaded.
fn insert_zones(cols: &[&Col]) -> String {
    let pairs: Vec<String> = time_columns(cols)
        .map(|(i, c)| format!("'{}', CASE WHEN p.z{i} THEN to_json(true) END", c.name))
        .collect();
    if pairs.is_empty() {
        "CAST(NULL AS JSON)".into()
    } else {
        format!(
            "json_merge_patch(CAST('{{}}' AS JSON), json_object({}))",
            pairs.join(", ")
        )
    }
}

/// `SET` clause updating `tz_assumed` for the columns a batch writes (`flag` is the
/// per-column write flag, `w` or `f`); empty when no time column is loaded. A written column
/// sets (`true`) or removes (JSON null in the patch) its entry; others keep theirs.
fn zone_set(t: &str, cols: &[&Col], flag: &str) -> String {
    let pairs: Vec<String> = time_columns(cols)
        .map(|(i, c)| {
            format!(
                "'{n}', CASE WHEN p.{flag}{i} THEN (CASE WHEN p.z{i} THEN to_json(true) END)
                             ELSE json_extract({t}.tz_assumed, {path}) END",
                n = c.name,
                path = cc_path(c.name)
            )
        })
        .collect();
    if pairs.is_empty() {
        String::new()
    } else {
        format!(
            ", tz_assumed = json_merge_patch(coalesce({t}.tz_assumed, CAST('{{}}' AS JSON)), json_object({}))",
            pairs.join(", ")
        )
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
    let _total = super::timing::span(&format!("state load total: {t}"));
    let _all = super::timing::span("state load: total");
    let vcols: String = (0..cols.len())
        .map(|i| format!(", v{i} VARCHAR, z{i} BOOLEAN"))
        .collect();
    conn.execute_batch(&format!(
        "CREATE OR REPLACE TEMP TABLE stage_state (ord BIGINT, seq BIGINT, record_key VARCHAR, raw VARCHAR,
             raw_patch VARCHAR, line_start BIGINT, line_end BIGINT, byte_offset BIGINT, byte_length BIGINT,
             raw_sha256 VARCHAR{vcols});"
    ))?;
    {
        let _a = super::timing::span("state load: appender (stage_state)");
        let mut app = conn.appender("stage_state")?;
        let text = |s: &Option<String>| s.clone().map_or(DbValue::Null, DbValue::Text);
        for (seq, r) in rows.iter().enumerate() {
            if r.cells.len() != cols.len() {
                return Err(Error::Invalid(format!(
                    "{t}: row {} has {} cells for {} columns",
                    r.record_key,
                    r.cells.len(),
                    cols.len()
                )));
            }
            if !r.tz_assumed.is_empty() && r.tz_assumed.len() != cols.len() {
                return Err(Error::Invalid(format!(
                    "{t}: row {} has {} tz_assumed flags for {} columns",
                    r.record_key,
                    r.tz_assumed.len(),
                    cols.len()
                )));
            }
            let mut vals = vec![
                DbValue::BigInt(r.ordinal as i64),
                DbValue::BigInt(seq as i64),
                DbValue::Text(r.record_key.clone()),
                text(&r.raw),
                text(&r.raw.as_deref().map(strip_top_level_nulls)),
                DbValue::BigInt(r.pos.line_start as i64),
                DbValue::BigInt(r.pos.line_end as i64),
                DbValue::BigInt(r.pos.byte_offset as i64),
                DbValue::BigInt(r.pos.byte_length as i64),
                DbValue::Text(r.raw_sha256.clone()),
            ];
            for (i, cell) in r.cells.iter().enumerate() {
                vals.push(text(cell));
                vals.push(DbValue::Boolean(
                    r.tz_assumed.get(i).copied().unwrap_or(false),
                ));
            }
            app.append_row(appender_params_from_iter(vals))?;
        }
        app.flush()?;
    }
    let tp = super::timing::span("state load: pick + new");
    conn.execute_batch(&format!(
        "CREATE OR REPLACE TEMP TABLE stage_pick AS SELECT * FROM stage_state
             QUALIFY row_number() OVER (PARTITION BY record_key ORDER BY ord, seq) = 1;
         CREATE OR REPLACE TEMP TABLE stage_new AS SELECT p.* FROM stage_pick p
             WHERE NOT EXISTS (SELECT 1 FROM {t} t WHERE t.record_key = p.record_key);"
    ))?;
    let inserted: i64 = conn.query_row("SELECT count(*) FROM stage_new", [], |r| r.get(0))?;
    let collected_at =
        format!("(SELECT collected_at FROM collections WHERE collection_id = {collection_id})");
    drop(tp);
    let tu = super::timing::span("state load: update/fill existing");
    let updated = match spec.mode {
        LoadMode::LatestWins => update_existing(conn, t, &cols, collection_id, &collected_at)?,
        LoadMode::FillMissing => fill_missing(conn, t, &cols, collection_id)?,
        LoadMode::InsertOnly => 0,
    };
    drop(tu);
    let ti = super::timing::span("state load: insert new rows");
    let names = cols.iter().map(|c| c.name).collect::<Vec<_>>().join(", ");
    let casts = cols
        .iter()
        .enumerate()
        .map(|(i, c)| cast(c.sql_type, &format!("p.v{i}")))
        .collect::<Vec<_>>()
        .join(", ");
    let claims = insert_claims(&cols, collection_id);
    let zones = insert_zones(&cols);
    conn.execute(
        &format!(
            "INSERT INTO {t} (record_key, collection_id, collected_at, {names}, raw, column_collections, tz_assumed)
             SELECT p.record_key, {collection_id}, {collected_at}, {casts}, CAST(p.raw AS JSON), {claims}, {zones}
             FROM stage_new p"
        ),
        [],
    )?;
    drop(ti);
    let _ts = super::timing::span("state load: insert record_sources");
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

/// Per-column latest wins for the batch rows whose key already exists (spec 5.2).
///
/// Column `c` of a stored row takes the incoming value iff the incoming collection is not
/// older than the collection recorded for `c` in `column_collections` (the row's
/// `collection_id` when the object is NULL; unclaimed when the key is absent). A NULL in a
/// keep_when_null column never writes. So each column ends up with the value of the newest
/// collection that supplied it, whatever the ingest order. Every written column (changed
/// or re-confirmed) is recorded as claimed by this collection; the row's `collection_id`
/// / `collected_at` advance when this collection is not older than the row's. Returns the
/// number of rows whose values changed.
fn update_existing(
    conn: &Connection,
    t: &str,
    cols: &[&Col],
    collection_id: i64,
    collected_at: &str,
) -> Result<u64> {
    // Collections this one is older than ("older": both collected_at known → compare
    // them, else compare collection_id).
    let newer: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT o.collection_id FROM collections o JOIN collections cur ON cur.collection_id = ?
             WHERE CASE WHEN o.collected_at IS NOT NULL AND cur.collected_at IS NOT NULL
                        THEN o.collected_at > cur.collected_at
                        ELSE o.collection_id > cur.collection_id END",
        )?;
        stmt.query_map(params![collection_id], |r| r.get::<_, i64>(0))?
            .map(|r| r.map(|id| id.to_string()))
            .collect::<duckdb::Result<_>>()?
    };
    let blocked = |claim: &str| {
        if newer.is_empty() {
            "false".to_string()
        } else {
            format!("coalesce({claim} IN ({}), false)", newer.join(", "))
        }
    };
    let claim = |c: &Col| {
        format!(
            "CASE WHEN t.column_collections IS NULL THEN t.collection_id
                  ELSE CAST(json_extract_string(t.column_collections, {}) AS BIGINT) END",
            cc_path(c.name)
        )
    };
    let mut select = format!("NOT {} AS row_ok", blocked("t.collection_id"));
    let mut changed = Vec::new();
    let mut any_write = Vec::new();
    let mut sets = Vec::new();
    let mut claims = Vec::new();
    for (i, c) in cols.iter().enumerate() {
        let not_null = if c.keep_when_null {
            format!(" AND p.v{i} IS NOT NULL")
        } else {
            String::new()
        };
        let write = format!("NOT {}{not_null}", blocked(&claim(c)));
        let value = cast(c.sql_type, &format!("p.v{i}"));
        select.push_str(&format!(", {write} AS w{i}"));
        changed.push(format!(
            "(({write}) AND t.{} IS DISTINCT FROM {value})",
            c.name
        ));
        any_write.push(format!("p.w{i}"));
        sets.push(format!(
            "{n} = CASE WHEN p.w{i} THEN {value} ELSE {t}.{n} END",
            n = c.name
        ));
        // Unwritten columns keep their claim (a JSON null for an absent key is dropped by
        // the merge); a NULL object is materialised as the row's collection.
        claims.push(format!(
            "'{n}', CASE WHEN p.w{i} THEN to_json({collection_id})
                         WHEN {t}.column_collections IS NULL THEN to_json({t}.collection_id)
                         ELSE json_extract({t}.column_collections, {path}) END",
            n = c.name,
            path = cc_path(c.name)
        ));
    }
    conn.execute_batch(&format!(
        "CREATE OR REPLACE TEMP TABLE stage_match AS
         SELECT p.*, {select}, {changed} AS changed
         FROM stage_pick p JOIN {t} t ON t.record_key = p.record_key;",
        changed = changed.join(" OR ")
    ))?;
    let n: i64 = conn.query_row("SELECT count(*) FROM stage_match WHERE changed", [], |r| {
        r.get(0)
    })?;
    // raw: merged only when a value changed; keys of the newer side take precedence.
    conn.execute(
        &format!(
            "UPDATE {t} SET {sets},
                 column_collections = json_merge_patch(coalesce({t}.column_collections, CAST('{{}}' AS JSON)),
                                                       json_object({claims})),
                 collection_id = CASE WHEN p.row_ok THEN {collection_id} ELSE {t}.collection_id END,
                 collected_at = CASE WHEN p.row_ok THEN {collected_at} ELSE {t}.collected_at END,
                 raw = CASE WHEN NOT p.changed OR p.raw_patch IS NULL THEN {t}.raw
                            WHEN p.row_ok THEN json_merge_patch(coalesce({t}.raw, CAST('{{}}' AS JSON)), CAST(p.raw_patch AS JSON))
                            ELSE json_merge_patch(CAST(p.raw_patch AS JSON), coalesce({t}.raw, CAST('{{}}' AS JSON))) END{zones}
             FROM stage_match p WHERE {t}.record_key = p.record_key AND ({any})",
            sets = sets.join(", "),
            claims = claims.join(", "),
            any = any_write.join(" OR "),
            zones = zone_set(t, cols, "w")
        ),
        [],
    )?;
    Ok(n as u64)
}

/// Evidence tables (spec 4 "Dedup"): the stored copy of a record is never overwritten; a
/// later copy fills only the columns that are still NULL (e.g. a portal export adding the
/// session id a Graph export lacks). Filled columns are claimed by this collection in
/// `column_collections`; `raw` gains only the keys it lacked. Returns the number of rows
/// that gained a value.
fn fill_missing(conn: &Connection, t: &str, cols: &[&Col], collection_id: i64) -> Result<u64> {
    let fills = cols
        .iter()
        .enumerate()
        .map(|(i, c)| format!("(t.{n} IS NULL AND p.v{i} IS NOT NULL) AS f{i}", n = c.name))
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute_batch(&format!(
        "CREATE OR REPLACE TEMP TABLE stage_fill AS
         SELECT p.*, {fills} FROM stage_pick p JOIN {t} t ON t.record_key = p.record_key;"
    ))?;
    let any = (0..cols.len())
        .map(|i| format!("p.f{i}"))
        .collect::<Vec<_>>()
        .join(" OR ");
    let n: i64 = conn.query_row(
        &format!("SELECT count(*) FROM stage_fill p WHERE {any}"),
        [],
        |r| r.get(0),
    )?;
    let sets = cols
        .iter()
        .enumerate()
        .map(|(i, c)| {
            format!(
                "{n} = CASE WHEN p.f{i} THEN {v} ELSE {t}.{n} END",
                n = c.name,
                v = cast(c.sql_type, &format!("p.v{i}"))
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let claims = cols
        .iter()
        .enumerate()
        .map(|(i, c)| {
            format!(
                "'{n}', CASE WHEN p.f{i} THEN to_json({collection_id})
                             ELSE json_extract({t}.column_collections, {path}) END",
                n = c.name,
                path = cc_path(c.name)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute(
        &format!(
            "UPDATE {t} SET {sets},
                 column_collections = json_merge_patch(coalesce({t}.column_collections, CAST('{{}}' AS JSON)),
                                                       json_object({claims})),
                 raw = CASE WHEN p.raw_patch IS NULL THEN {t}.raw
                            ELSE json_merge_patch(CAST(p.raw_patch AS JSON), coalesce({t}.raw, CAST('{{}}' AS JSON))) END{zones}
             FROM stage_fill p WHERE {t}.record_key = p.record_key AND ({any})",
            zones = zone_set(t, cols, "f")
        ),
        [],
    )?;
    Ok(n as u64)
}
