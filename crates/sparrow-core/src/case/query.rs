//! `sparrow query`: one read-only SELECT over a case, on a locked-down connection. All of the lockdown lives in this
//! file.
//!
//! Layers, each sufficient against writes on its own:
//! 1. **One SELECT only.** DuckDB's own parser checks the text: `json_serialize_sql` serializes SELECT statements
//!    only, so any other statement (INSERT, COPY, ATTACH, SET, PRAGMA, CALL, EXPORT, LOAD, INSTALL, a transaction,
//!    ...) fails, and the parsed result must hold exactly one statement, so a second statement after `;` (also one
//!    hidden behind a comment) is refused. The query that runs is DuckDB's re-rendering of that one parsed SELECT, so
//!    comments and text after it never reach execution. The check runs on its own in-memory instance with no case
//!    attached.
//! 2. **A separate, locked instance.** A fresh in-memory DuckDB with extension auto-install/auto-load and community
//!    extensions off, the case `ATTACH`ed `READ_ONLY`, then `enable_external_access = false` (no file, network or
//!    environment access: read_csv, glob, COPY, ATTACH, getenv) and `lock_configuration = true` (no SET can undo it).
//!    The lockdown is probed before the query runs; if a probe succeeds the query is refused.
//! 3. **Never a writer.** The case file is only ever attached read-only, so no statement can change it.
//!
//!
//! **In the review app** the case's own writer instance is locked down once after opening (`Case::lock_down`);
//! `run_on` runs the one parsed SELECT on it inside a transaction that is always rolled back. Layers 1 and the
//! lockdown hold; layer 3 (a read-only attach) is replaced by the rollback.
//!
//! The query sees every table and view of the case, including `case_meta` (the case id, the audit chain's
//! `audit_head` and `audit_verified` bookkeeping, and `db::POST_MIGRATION_PENDING` and
//! `db::CREDENTIAL_FAILURE_CODES`). That is harmless: they are not secret, and reading them changes
//! nothing; the audit chain's integrity comes from `audit verify`, not from hiding them.

use crate::{Case, Error, Result};
use duckdb::{Connection, params};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    pub columns: Vec<String>,
    /// Each value as JSON (DuckDB's `to_json` of the column).
    pub rows: Vec<Vec<Value>>,
    /// True when the query has more rows than the limit.
    pub truncated: bool,
}

/// The one SELECT in `sql`, re-rendered by DuckDB's parser (no comments, no trailing text); an error for anything
/// else.
fn the_select(sql: &str) -> Result<String> {
    let parser = Connection::open_in_memory()?;
    let parsed: String =
        parser.query_row("SELECT json_serialize_sql(?::VARCHAR)", params![sql], |r| {
            r.get(0)
        })?;
    let v: Value = serde_json::from_str(&parsed)
        .map_err(|e| Error::Invalid(format!("the query parser returned invalid JSON: {e}")))?;
    if v["error"] != Value::Bool(false) {
        return Err(Error::Invalid(format!(
            "query accepts one SELECT statement only: {}",
            v["error_message"].as_str().unwrap_or("not a SELECT")
        )));
    }
    let n = v["statements"].as_array().map_or(0, Vec::len);
    if n != 1 {
        return Err(Error::Invalid(format!(
            "query accepts exactly one SELECT statement, got {n}"
        )));
    }
    let one = serde_json::json!({ "error": false, "statements": [v["statements"][0].clone()] });
    let rendered: String = parser.query_row(
        "SELECT json_deserialize_sql(?::JSON)",
        params![one.to_string()],
        |r| r.get(0),
    )?;
    Ok(rendered)
}

/// The locked query instance with the case attached read-only as `c`.
fn locked(case_path: &Path) -> Result<Connection> {
    if !case_path.is_file() {
        return Err(Error::NotFound(format!(
            "case database {}",
            case_path.display()
        )));
    }
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(
        "SET autoinstall_known_extensions = false; SET autoload_known_extensions = false; \
         SET allow_community_extensions = false;",
    )?;
    let file = case_path.display().to_string().replace('\'', "''");
    conn.execute_batch(&format!("ATTACH '{file}' AS c (READ_ONLY); USE c;"))
        .map_err(|e| crate::db::lock_error(case_path, e))?;
    crate::db::migrations::check_readable(&conn)?;
    conn.execute_batch("SET enable_external_access = false; SET lock_configuration = true;")?;
    probe_lockdown(&conn)?;
    Ok(conn)
}

/// Prove the lockdown holds on `conn`: each attempt to undo it or reach outside the process must fail, else
/// `Error::Invalid`. Shared by [`locked`] and `Case::lock_down`.
pub(crate) fn probe_lockdown(conn: &Connection) -> Result<()> {
    let probe_file =
        std::env::temp_dir().join(format!("sparrow-query-probe-{}.duckdb", std::process::id()));
    let attach_probe = format!(
        "ATTACH '{}' AS sparrow_probe",
        probe_file.display().to_string().replace('\'', "''")
    );
    for probe in [
        "SET enable_external_access = true",
        "SET lock_configuration = false",
        "SELECT * FROM read_csv('/dev/null')",
        "SELECT getenv('HOME')",
        attach_probe.as_str(),
    ] {
        if conn.execute_batch(probe).is_ok() {
            let _ = std::fs::remove_file(&probe_file);
            return Err(Error::Invalid(format!(
                "the query connection is not locked down ({probe} succeeded)"
            )));
        }
    }
    Ok(())
}

/// The tables and views [`run`] can read: every table and view of the case (not DuckDB's own catalog objects), with
/// their table and column comments, read from the same locked connection; only `table` when given.
pub fn schema(case_path: &Path, table: Option<&str>) -> Result<Vec<crate::db::TableInfo>> {
    let conn = locked(case_path)?;
    crate::db::describe::describe_conn(&conn, table)
}

/// Run one SELECT over the case at `case_path`, returning at most `limit` rows.
pub fn run(case_path: &Path, sql: &str, limit: usize) -> Result<QueryResult> {
    let select = the_select(sql)?;
    let conn = locked(case_path)?;
    run_select(&conn, &select, limit)
}

/// `select` (one parsed SELECT from [`the_select`]) on `conn`, at most `limit` rows.
fn run_select(conn: &Connection, select: &str, limit: usize) -> Result<QueryResult> {
    let columns = {
        let mut stmt = conn.prepare(&format!("SELECT * FROM ({select}) LIMIT 0"))?;
        let _ = stmt.query([])?;
        stmt.column_names()
    };
    let limit_plus = i64::try_from(limit).unwrap_or(i64::MAX - 1) + 1;
    let mut stmt = conn.prepare(&format!(
        "SELECT to_json(COLUMNS(*))::VARCHAR FROM ({select}) LIMIT ?"
    ))?;
    let mut rows_iter = stmt.query(params![limit_plus])?;
    let mut rows = Vec::new();
    while let Some(r) = rows_iter.next()? {
        let mut row = Vec::with_capacity(columns.len());
        for i in 0..columns.len() {
            let text: Option<String> = r.get(i)?;
            row.push(match text {
                None => Value::Null,
                Some(t) => serde_json::from_str(&t).unwrap_or(Value::String(t)),
            });
        }
        rows.push(row);
    }
    let truncated = rows.len() > limit;
    rows.truncate(limit);
    Ok(QueryResult {
        columns,
        rows,
        truncated,
    })
}

fn need_locked(case: &Case, what: &str) -> Result<()> {
    if case.is_locked_down()? {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "{what} needs a locked-down case (Case::lock_down)"
        )))
    }
}

/// Like [`schema`], on a case this process holds open and has locked down with `Case::lock_down`.
pub fn schema_on(case: &Case, table: Option<&str>) -> Result<Vec<crate::db::TableInfo>> {
    need_locked(case, "schema_on")?;
    crate::db::describe::describe_conn(case.conn(), table)
}

/// Like [`run`], on the case's own locked-down writer instance: the one parsed SELECT runs inside a transaction that
/// is always rolled back. Refused when the case is not locked down or a transaction is already open (the caller's
/// transaction is left alone).
pub fn run_on(case: &Case, sql: &str, limit: usize) -> Result<QueryResult> {
    case.ensure_usable()?;
    need_locked(case, "run_on")?;
    let select = the_select(sql)?;
    in_rolled_back_tx(case, |conn| run_select(conn, &select, limit))
}

/// `f` inside a transaction that is always rolled back. A failed ROLLBACK is tried once more; if that fails too the
/// case is made unusable (no further `run_on`, `ensure_usable` fails) and the error says so; the error of `f` wins
/// when both fail.
fn in_rolled_back_tx<T>(case: &Case, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
    let conn = case.conn();
    conn.execute_batch("BEGIN TRANSACTION").map_err(|e| {
        Error::Invalid(format!(
            "run_on refuses to run inside an open transaction: {e}"
        ))
    })?;
    let out = f(conn);
    let ended = conn
        .execute_batch("ROLLBACK")
        .or_else(|_| conn.execute_batch("ROLLBACK"));
    if let Err(e) = ended {
        let msg = format!(
            "the case's read-only query transaction could not be rolled back: {e}; this Case is unusable, open the case again"
        );
        case.poison(msg.clone());
        return out.and(Err(Error::Invalid(msg)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked_case() -> Case {
        let c = Case::in_memory().unwrap();
        c.lock_down().unwrap();
        c
    }

    #[test]
    fn a_write_inside_the_transaction_is_rolled_back() {
        let c = locked_case();
        let n = |c: &Case| -> i64 {
            c.conn()
                .query_row("SELECT count(*) FROM case_meta WHERE key = 'zz'", [], |r| {
                    r.get(0)
                })
                .unwrap()
        };
        in_rolled_back_tx(&c, |conn| {
            conn.execute_batch("INSERT INTO case_meta VALUES ('zz', '1')")?;
            let inside: i64 =
                conn.query_row("SELECT count(*) FROM case_meta WHERE key = 'zz'", [], |r| {
                    r.get(0)
                })?;
            assert_eq!(inside, 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(n(&c), 0);
        // A write outside any transaction works afterwards.
        crate::case::write::in_tx(c.conn(), |tx| {
            tx.execute_batch("INSERT INTO case_meta VALUES ('zz', '2')")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(n(&c), 1);
    }

    #[test]
    fn an_error_inside_the_transaction_still_rolls_back() {
        let c = locked_case();
        let e = run_on(&c, "SELECT CAST('x' AS INTEGER)", 10).unwrap_err();
        assert!(!matches!(e, Error::NotFound(_)), "{e}");
        c.conn()
            .execute_batch("BEGIN TRANSACTION; ROLLBACK")
            .unwrap();
        assert_eq!(run_on(&c, "SELECT 1", 10).unwrap().rows.len(), 1);
    }

    #[test]
    fn a_failed_rollback_fails_the_case_closed_and_keeps_the_query_error() {
        // Ending the transaction inside `f` makes the ROLLBACK fail (no transaction is active), both times.
        let c = locked_case();
        let r: Result<()> = in_rolled_back_tx(&c, |conn| {
            conn.execute_batch("COMMIT")?;
            Ok(())
        });
        let e = r.unwrap_err();
        assert!(
            matches!(&e, Error::Invalid(m) if m.contains("rolled back")),
            "{e}"
        );
        assert!(c.ensure_usable().is_err());
        assert!(run_on(&c, "SELECT 1", 10).is_err());

        // When the query failed too, its error is the one reported, and the case is still marked unusable.
        let c = locked_case();
        let r: Result<()> = in_rolled_back_tx(&c, |conn| {
            conn.execute_batch("COMMIT")?;
            Err(Error::Invalid("the query failed".into()))
        });
        assert!(
            matches!(&r, Err(Error::Invalid(m)) if m == "the query failed"),
            "{r:?}"
        );
        assert!(c.ensure_usable().is_err());
    }
}
