//! Staged loading of keyed rows into the state tables (spec 5.2, per-column latest wins), the
//! event tables (fill missing: evidence is never overwritten), risk detections and collector
//! flags. Same pattern as `bulk.rs`: an appender fills a TEMP staging table (every value as
//! text) and set-based SQL merges it inside the caller's transaction, once per file and table
//! ([`StateFileStage`]). The tables have no key
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
    let cols = loadable(spec, columns)?;
    if rows.is_empty() {
        return Ok(LoadOutcome::default());
    }
    let mut stage = StateFileStage::create(conn, spec, cols, file_id, Pick::FileOrder)?;
    stage.stage(rows)?;
    stage.finish(collection_id)
}

/// The `Col`s of `columns`, or an error naming one `spec` cannot load.
fn loadable<'s>(spec: &'s TableSpec, columns: &[&str]) -> Result<Vec<&'s Col>> {
    columns
        .iter()
        .map(|n| {
            spec.col(n)
                .ok_or_else(|| Error::Invalid(format!("{} has no loadable column {n}", spec.table)))
        })
        .collect()
}

/// Which staged copy of a key a merge picks.
#[derive(Debug, Clone, Copy)]
enum Pick {
    /// The lowest ordinal, then the first staged ([`load_rows`]: one batch).
    FileOrder,
    /// The first staged ([`StateFileStage`]: the batches of one file, so a later batch never beats an earlier one).
    StagingOrder,
}

/// Merge objects [`StateFileStage::finish`] creates and drops. Every one is narrow (`seq` plus flags): the wide
/// staged columns (`raw`, the cells) are read through the `stage_pick` view, never copied.
const DROP_MERGE: &str = "DROP TABLE IF EXISTS stage_fill; DROP TABLE IF EXISTS stage_match;
    DROP TABLE IF EXISTS stage_new; DROP VIEW IF EXISTS stage_pick; DROP TABLE IF EXISTS stage_pick_keys;";

/// The rows of ONE file for one state table, staged once (an insert-only, constraint-free TEMP table
/// `stage_state_<table>`, appended to per batch with a global `seq`) and merged once by
/// [`StateFileStage::finish`]: one [`load_rows`] of every staged row, a key keeping its first staged copy.
/// A TEMP table's deleted or replaced rows are never reclaimed, so the stage is never emptied or replaced; it is
/// dropped by `finish` and freed when the file's transaction ends.
pub struct StateFileStage<'c> {
    conn: &'c Connection,
    spec: &'c TableSpec,
    cols: Vec<&'c Col>,
    file_id: i64,
    name: String,
    pick: Pick,
    seq: u64,
}

impl<'c> StateFileStage<'c> {
    /// Drops this table's stage left on the connection and creates an empty one. Call inside the file's transaction.
    pub fn begin(
        conn: &'c Connection,
        spec: &'c TableSpec,
        columns: &[&str],
        file_id: i64,
    ) -> Result<Self> {
        let cols = loadable(spec, columns)?;
        Self::create(conn, spec, cols, file_id, Pick::StagingOrder)
    }

    fn create(
        conn: &'c Connection,
        spec: &'c TableSpec,
        cols: Vec<&'c Col>,
        file_id: i64,
        pick: Pick,
    ) -> Result<Self> {
        let name = format!("stage_state_{}", spec.table);
        let vcols: String = (0..cols.len())
            .map(|i| format!(", v{i} VARCHAR, z{i} BOOLEAN"))
            .collect();
        conn.execute_batch(&format!(
            "DROP TABLE IF EXISTS {name};
             CREATE TEMP TABLE {name} (ord BIGINT, seq BIGINT, record_key VARCHAR, raw VARCHAR,
                 raw_patch VARCHAR, line_start BIGINT, line_end BIGINT, byte_offset BIGINT, byte_length BIGINT,
                 raw_sha256 VARCHAR{vcols});"
        ))?;
        Ok(StateFileStage {
            conn,
            spec,
            cols,
            file_id,
            name,
            pick,
            seq: 0,
        })
    }

    /// Appends one batch (an appender only: no DELETE, no merge, no read of the state table).
    pub fn stage(&mut self, rows: &[StagedRow]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let t = self.spec.table;
        let n = self.cols.len();
        let _a = super::timing::span("state load: appender (stage_state)");
        let mut app = self.conn.appender(&self.name)?;
        let text = |s: &Option<String>| s.clone().map_or(DbValue::Null, DbValue::Text);
        for r in rows {
            if r.cells.len() != n {
                return Err(Error::Invalid(format!(
                    "{t}: row {} has {} cells for {n} columns",
                    r.record_key,
                    r.cells.len(),
                )));
            }
            if !r.tz_assumed.is_empty() && r.tz_assumed.len() != n {
                return Err(Error::Invalid(format!(
                    "{t}: row {} has {} tz_assumed flags for {n} columns",
                    r.record_key,
                    r.tz_assumed.len(),
                )));
            }
            let mut vals = vec![
                DbValue::BigInt(r.ordinal as i64),
                DbValue::BigInt(self.seq as i64),
                DbValue::Text(r.record_key.clone()),
                text(&r.raw),
                // Stored only when it differs from `raw` (the `stage_pick` view reads `coalesce(raw_patch, raw)`).
                text(
                    &r.raw
                        .as_deref()
                        .map(strip_top_level_nulls)
                        .filter(|p| Some(p.as_str()) != r.raw.as_deref()),
                ),
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
            self.seq += 1;
        }
        app.flush()?;
        Ok(())
    }

    /// Merges everything staged once (= one [`load_rows`] of every staged row, in staging order), then DROPs the
    /// stage and merge tables.
    pub fn finish(self, collection_id: i64) -> Result<LoadOutcome> {
        let conn = self.conn;
        if self.seq == 0 {
            conn.execute_batch(&format!("DROP TABLE IF EXISTS {}", self.name))?;
            return Ok(LoadOutcome::default());
        }
        let (t, cols, stage) = (self.spec.table, &self.cols[..], &self.name);
        let _total = super::timing::span(&format!("state load total: {t}"));
        let _all = super::timing::span("state load: total");
        let order = match self.pick {
            Pick::FileOrder => "ord, seq",
            Pick::StagingOrder => "seq",
        };
        let tp = super::timing::span("state load: pick + new");
        conn.execute_batch(DROP_MERGE)?;
        conn.execute_batch(&format!(
            "CREATE TEMP TABLE stage_pick_keys AS SELECT seq FROM {stage}
                 QUALIFY row_number() OVER (PARTITION BY record_key ORDER BY {order}) = 1;
             CREATE TEMP VIEW stage_pick AS
                 SELECT s.* EXCLUDE (raw_patch), coalesce(s.raw_patch, s.raw) AS raw_patch
                 FROM {stage} s JOIN stage_pick_keys k ON k.seq = s.seq;
             CREATE TEMP TABLE stage_new AS SELECT p.seq FROM stage_pick p
                 WHERE NOT EXISTS (SELECT 1 FROM {t} t WHERE t.record_key = p.record_key);"
        ))?;
        let inserted: i64 = conn.query_row("SELECT count(*) FROM stage_new", [], |r| r.get(0))?;
        let collected_at =
            format!("(SELECT collected_at FROM collections WHERE collection_id = {collection_id})");
        drop(tp);
        let tu = super::timing::span("state load: update/fill existing");
        let updated = match self.spec.mode {
            LoadMode::LatestWins => update_existing(conn, t, cols, collection_id, &collected_at)?,
            LoadMode::FillMissing => fill_missing(conn, t, cols, collection_id)?,
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
        let claims = insert_claims(cols, collection_id);
        let zones = insert_zones(cols);
        conn.execute(
            &format!(
                "INSERT INTO {t} (record_key, collection_id, collected_at, {names}, raw, column_collections, tz_assumed)
                 SELECT p.record_key, {collection_id}, {collected_at}, {casts}, CAST(p.raw AS JSON), {claims}, {zones}
                 FROM stage_pick p JOIN stage_new n ON n.seq = p.seq"
            ),
            [],
        )?;
        drop(ti);
        let ts = super::timing::span("state load: insert record_sources");
        conn.execute(
            &format!(
                "INSERT INTO record_sources (table_name, record_key, file_id, record_ordinal, line_start,
                                             line_end, byte_offset, byte_length, raw_sha256)
                 SELECT '{t}', record_key, ?, ord, line_start, line_end, byte_offset, byte_length, raw_sha256
                 FROM {stage} ON CONFLICT DO NOTHING"
            ),
            params![self.file_id],
        )?;
        drop(ts);
        conn.execute_batch(&format!("{DROP_MERGE} DROP TABLE {stage};"))?;
        Ok(LoadOutcome {
            staged: self.seq,
            inserted: inserted as u64,
            updated,
        })
    }
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
        "CREATE TEMP TABLE stage_match AS
         SELECT p.seq, {select}, {changed} AS changed
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
             FROM (SELECT p.*, m.* EXCLUDE (seq) FROM stage_pick p JOIN stage_match m ON m.seq = p.seq) p
             WHERE {t}.record_key = p.record_key AND ({any})",
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
        "CREATE TEMP TABLE stage_fill AS
         SELECT p.seq, {fills} FROM stage_pick p JOIN {t} t ON t.record_key = p.record_key;"
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
             FROM (SELECT p.*, f.* EXCLUDE (seq) FROM stage_pick p JOIN stage_fill f ON f.seq = p.seq) p
             WHERE {t}.record_key = p.record_key AND ({any})",
            zones = zone_set(t, cols, "f")
        ),
        [],
    )?;
    Ok(n as u64)
}
