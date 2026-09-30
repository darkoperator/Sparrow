//! The only way rule SQL executes (Task 3 ruling B). A [`RuleConn`] is a **separate DuckDB
//! instance**: a fresh in-memory database that `ATTACH`es the case file `READ_ONLY`, then applies
//! the tenant scope and the external-access lockdown of `detect::scope`. The lockdown settings
//! are per instance, so the case's writer connection (which ingest needs unlocked) is never
//! touched. The constructor is private to [`with_rule_conn`], which releases the writer while the
//! rule instance reads the file; there is no public way to run compiled SQL elsewhere.

use crate::detect::compile::{CaseSchema, Compiled};
use crate::detect::scope::{lock_down, scope_to_tenant};
use crate::{Case, Error, Result};
use chrono::{DateTime, Utc};
use duckdb::types::Value;
use duckdb::{Connection, ToSql};
use std::collections::BTreeMap;
use std::path::Path;

/// One row of the output contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub record_key: String,
    pub source_table: String,
    pub event_time: Option<DateTime<Utc>>,
    pub actor_upn: Option<String>,
    pub ip: Option<String>,
    /// The JSON `context`, serialized (`None` when NULL).
    pub context: Option<String>,
}

pub struct RuleConn {
    conn: Connection,
    schema: CaseSchema,
    tenant: Option<String>,
}

/// Run `f` with a locked, read-only rule connection on `case`'s data. The case's writer
/// connection is closed while `f` runs and reopened afterwards (see `Case::with_file_released`),
/// so `f` must not touch `case`; hits are collected into Rust and merged after.
pub fn with_rule_conn<T>(case: &mut Case, f: impl FnOnce(&mut RuleConn) -> Result<T>) -> Result<T> {
    case.with_file_released(|path| {
        let mut rc = RuleConn::open(path)?;
        f(&mut rc)
    })
}

impl RuleConn {
    fn open(path: &Path) -> Result<RuleConn> {
        let t = std::time::Instant::now();
        let conn = Connection::open_in_memory()?;
        let file = path.display().to_string().replace('\'', "''");
        conn.execute_batch(&format!(
            "ATTACH '{file}' AS case_ro (READ_ONLY); USE case_ro;"
        ))?;
        crate::detect::phase::record("rule instance: attach", t);
        let t = std::time::Instant::now();
        let schema = CaseSchema::of(&conn)?;
        crate::detect::phase::record("rule instance: schema", t);
        let t = std::time::Instant::now();
        lock_down(&conn)?;
        let rc = RuleConn {
            conn,
            schema,
            tenant: None,
        };
        rc.assert_locked()?;
        crate::detect::phase::record("rule instance: lock down", t);
        Ok(rc)
    }

    /// The lockdown must hold before any rule runs: fail closed if it does not.
    fn assert_locked(&self) -> Result<()> {
        for stmt in [
            "SET enable_external_access = true",
            "SELECT * FROM read_csv('/dev/null')",
            "ATTACH '/tmp/sparrow-rule-conn-probe.duckdb' AS probe",
        ] {
            if self.conn.execute_batch(stmt).is_ok() {
                return Err(Error::Invalid(format!(
                    "the rule connection is not locked down ({stmt} succeeded)"
                )));
            }
        }
        Ok(())
    }

    /// The case's tables and columns (read before any scope views exist).
    pub fn schema(&self) -> &CaseSchema {
        &self.schema
    }

    /// Scope the connection to one tenant (replaces the previous tenant's views).
    pub fn scope(&mut self, tenant: &str) -> Result<()> {
        let t = std::time::Instant::now();
        scope_to_tenant(&self.conn, &self.schema, tenant)?;
        crate::detect::phase::record("rule instance: scope views", t);
        self.tenant = Some(tenant.to_string());
        Ok(())
    }

    /// Execute a compiled rule for the scoped tenant. `iocs` binds the `ioc_<type>` parameters
    /// (the case indicators of each `case_iocs.<type>` list the rule references).
    pub fn run(
        &self,
        compiled: &Compiled,
        iocs: &BTreeMap<String, Vec<String>>,
    ) -> Result<Vec<Hit>> {
        let Some(tenant) = &self.tenant else {
            return Err(Error::Invalid(
                "scope the rule connection to a tenant first".into(),
            ));
        };
        let mut named: Vec<(String, Value)> = compiled.params.clone();
        if compiled.uses_tenant {
            named.push(("tenant".to_string(), Value::Text(tenant.clone())));
        }
        for l in &compiled.lists {
            if let Some(t) = l.strip_prefix("case_iocs.") {
                let vals = iocs.get(t).cloned().unwrap_or_default();
                named.push((
                    format!("ioc_{t}"),
                    Value::Text(serde_json::to_string(&vals).expect("strings serialize")),
                ));
            }
        }
        let refs: Vec<(&str, &dyn ToSql)> = named
            .iter()
            .map(|(k, v)| (k.as_str(), v as &dyn ToSql))
            .collect();
        let mut st = self.conn.prepare(&format!(
            "SELECT record_key, source_table, epoch_us(event_time), actor_upn, ip, CAST(context AS VARCHAR) FROM ({})",
            compiled.sql
        ))?;
        let rows = st.query_map(refs.as_slice(), |r| {
            let us: Option<i64> = r.get(2)?;
            Ok(Hit {
                record_key: r.get(0)?,
                source_table: r.get(1)?,
                event_time: us.and_then(DateTime::from_timestamp_micros),
                actor_upn: r.get(3)?,
                ip: r.get(4)?,
                context: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rule_instance_is_locked_and_separate_from_the_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("case.duckdb");
        let mut case = Case::create_or_open(&path).unwrap();
        case.conn()
            .execute_batch("INSERT INTO collections (tool, root_path, sparrow_version, tenant_key) VALUES ('hawk', '/x', 't', 't1'), ('hawk', '/y', 't', 't2')")
            .unwrap();
        with_rule_conn(&mut case, |rc| {
            for stmt in [
                "SELECT * FROM read_csv('/etc/hosts')",
                "SELECT * FROM read_json('/etc/hosts')",
                "SELECT * FROM read_parquet('/etc/x.parquet')",
                "SELECT * FROM glob('/etc/*')",
                "ATTACH '/tmp/zz-sparrow.db' AS z",
                "COPY (SELECT 1) TO '/tmp/zz-sparrow.csv'",
                "SET enable_external_access = true",
                "SET lock_configuration = false",
                "INSERT INTO collections (tool, root_path, sparrow_version) VALUES ('hawk', '/z', 't')",
            ] {
                assert!(rc.conn.execute_batch(stmt).is_err(), "{stmt} must fail");
            }
            // The tenant can still be switched: views are not configuration.
            for t in ["t1", "t2"] {
                rc.scope(t).unwrap();
                let n: i64 = rc
                    .conn
                    .query_row("SELECT count(*) FROM collections", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(n, 1, "{t}");
            }
            Ok(())
        })
        .unwrap();
        // The writer is back and not locked: it reads files the way ingest does, and writes.
        let csv = dir.path().join("x.csv");
        std::fs::write(&csv, "a\n1\n2\n").unwrap();
        let rows: i64 = case
            .conn()
            .query_row(
                &format!("SELECT count(*) FROM read_csv('{}')", csv.display()),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2);
        case.conn()
            .execute_batch("INSERT INTO collections (tool, root_path, sparrow_version) VALUES ('hawk', '/w', 't')")
            .unwrap();
        let n: i64 = case
            .conn()
            .query_row("SELECT count(*) FROM collections", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 3);
    }
}
