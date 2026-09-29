//! Structural tenant scope and file isolation for rule SQL (Task 2 review, blockers 1 and 2).
//!
//! A rule runs on a **dedicated connection** (the settings below are per database instance, so
//! never the case's own writer connection). For each tenant the connection gets one TEMP VIEW
//! per tenant-aware table with the same name, filtered to that tenant. DuckDB resolves temp
//! objects before `main`, so a rule that reads `ual_events` sees only its tenant's rows even if
//! its SQL tries otherwise; compile rejects schema/catalog-qualified table references so the
//! base tables cannot be named directly.
//!
//! Only `detect::rule_conn::RuleConn` calls these, so lockdown cannot be forgotten by a caller.
//!
//! Usage: `scope_to_tenant` (per tenant, replaces the previous tenant's views), and `lock_down`
//! once before any rule SQL runs: `enable_external_access = false` (no `read_csv`, `ATTACH`,
//! `COPY`, glob, ...) and `lock_configuration = true` (the rule cannot turn it back on).

use crate::detect::compile::CaseSchema;
use crate::{Error, Result};
use duckdb::Connection;

/// Tables with neither `collection_id` nor `tenant_key` that a rule may still read: shared
/// reference data, identical for every tenant.
pub const GLOBAL_TABLES: &[&str] = &["ip_intel", "capabilities", "operation_catalog"];

/// Whether a rule may read `table`: it is tenant-aware (the scope filters it) or shared data.
pub fn readable(schema: &CaseSchema, table: &str) -> bool {
    GLOBAL_TABLES.contains(&table)
        || schema
            .tables
            .get(table)
            .is_some_and(|c| c.contains_key("tenant_key") || c.contains_key("collection_id"))
}

fn check_tenant(tenant: &str) -> Result<()> {
    if tenant.chars().any(char::is_control) {
        return Err(Error::Invalid(
            "tenant key contains control characters".into(),
        ));
    }
    Ok(())
}

/// Shadow every tenant-aware table with a TEMP VIEW of the same name filtered to `tenant`
/// (tables with a `tenant_key` filter on it; tables with a `collection_id` filter on the
/// tenant's collections). Replaces the views of a previous tenant.
pub(crate) fn scope_to_tenant(conn: &Connection, schema: &CaseSchema, tenant: &str) -> Result<()> {
    check_tenant(tenant)?;
    let db: String = conn.query_row("SELECT current_database()", [], |r| r.get(0))?;
    let lit = tenant.replace('\'', "''");
    let base = |t: &str| format!("\"{}\".main.\"{t}\"", db.replace('"', "\"\""));
    for (table, cols) in &schema.tables {
        let filter = if cols.contains_key("tenant_key") {
            format!("tenant_key = '{lit}'")
        } else if cols.contains_key("collection_id") {
            format!(
                "collection_id IN (SELECT collection_id FROM {} WHERE tenant_key = '{lit}')",
                base("collections")
            )
        } else {
            continue;
        };
        conn.execute_batch(&format!(
            "CREATE OR REPLACE TEMP VIEW \"{table}\" AS SELECT * FROM {} WHERE {filter}",
            base(table)
        ))?;
    }
    Ok(())
}

/// Turn off external access and lock the configuration of the connection's database instance.
/// Irreversible for that instance: call it only on the dedicated rule connection.
pub(crate) fn lock_down(conn: &Connection) -> Result<()> {
    conn.execute_batch("SET enable_external_access = false; SET lock_configuration = true;")?;
    Ok(())
}
