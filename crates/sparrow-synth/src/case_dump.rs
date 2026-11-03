//! A deterministic dump of a case's ingested rows: the oracle the streaming-ingest refactors are
//! checked against. Every base table (less the case-meta tables) becomes a sorted list of
//! one-string rows; columns that hold wall-clock times are left out.

use sparrow_core::{Case, Error, Result};
use std::collections::BTreeMap;

/// Columns whose value is the time of the run (or the temp directory it ran in), not of the
/// evidence: `collections.root_path` is the absolute path of the generated tree.
pub const VOLATILE_COLUMNS: &[&str] = &["ingested_at", "applied_at", "changed_at", "root_path"];

/// Tables that describe the case itself, not what was ingested into it.
pub const CASE_META_TABLES: &[&str] = &[
    "schema_migrations",
    "case_meta",
    "audit_trail",
    "notebooks",
    "notebook_queries",
    "operation_catalog",
];

fn db<T>(r: std::result::Result<T, duckdb::Error>) -> Result<T> {
    r.map_err(Error::from)
}

/// Every table of `case` (less [`CASE_META_TABLES`]) mapped to its rows, each rendered as one
/// string (`NULL` is `\N`, columns joined by the unit separator U+001F), sorted. `record_sources`, `parse_errors` and `source_files` are always
/// present; other tables appear too (empty when nothing was ingested into them).
pub fn dump_case(case: &Case) -> Result<BTreeMap<String, Vec<String>>> {
    let conn = case.conn();
    let mut tables: Vec<String> = Vec::new();
    {
        let mut stmt = db(conn.prepare(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'main' AND table_type = 'BASE TABLE' ORDER BY table_name",
        ))?;
        let rows = db(stmt.query_map([], |r| r.get::<_, String>(0)))?;
        for t in rows {
            let t = db(t)?;
            if !CASE_META_TABLES.contains(&t.as_str()) {
                tables.push(t);
            }
        }
    }
    let mut out = BTreeMap::new();
    for t in tables {
        let mut cols: Vec<String> = Vec::new();
        {
            let mut stmt = db(conn.prepare(
                "SELECT column_name FROM information_schema.columns \
                 WHERE table_schema = 'main' AND table_name = ? ORDER BY ordinal_position",
            ))?;
            let rows = db(stmt.query_map([&t], |r| r.get::<_, String>(0)))?;
            for c in rows {
                let c = db(c)?;
                if !VOLATILE_COLUMNS.contains(&c.as_str()) {
                    cols.push(c);
                }
            }
        }
        let rows = if cols.is_empty() {
            Vec::new()
        } else {
            let exprs: Vec<String> = cols
                .iter()
                .map(|c| format!("coalesce(CAST(\"{c}\" AS VARCHAR), '\\N')"))
                .collect();
            let sql = format!(
                "SELECT concat_ws(chr(31), {}) FROM \"{t}\"",
                exprs.join(", ")
            );
            let mut stmt = db(conn.prepare(&sql))?;
            let mut v = Vec::new();
            for r in db(stmt.query_map([], |r| r.get::<_, String>(0)))? {
                v.push(db(r)?);
            }
            v.sort();
            v
        };
        out.insert(t, rows);
    }
    for must in ["record_sources", "parse_errors", "source_files"] {
        out.entry(must.to_string()).or_default();
    }
    Ok(out)
}
