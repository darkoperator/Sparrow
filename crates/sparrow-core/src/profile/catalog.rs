//! Operation catalog (spec §5.3): `data/operation_catalog.yaml`, overlaid by `--data`, stored in
//! `operation_catalog` for the `timeline` view's `category` column.

use crate::Result;
use crate::data::{OperationDef, operation_key};
use duckdb::{Connection, params};

/// Replace the `operation_catalog` table with `defs`. Returns the number of rows.
pub fn store(conn: &Connection, defs: &[OperationDef]) -> Result<usize> {
    conn.execute("DELETE FROM operation_catalog", [])?;
    {
        let mut stmt = conn.prepare(
            "INSERT INTO operation_catalog (operation, operation_key, workload, category,
                 description, mitre, origin)
             VALUES (?, ?, ?, CAST(? AS event_category), ?, CAST(CAST(? AS JSON) AS VARCHAR[]), ?)",
        )?;
        for d in defs {
            let mitre = serde_json::to_string(&d.mitre).expect("strings serialize");
            stmt.execute(params![
                d.operation,
                operation_key(&d.operation),
                d.workload,
                d.category,
                d.description,
                mitre,
                d.origin,
            ])?;
        }
    }
    Ok(defs.len())
}
