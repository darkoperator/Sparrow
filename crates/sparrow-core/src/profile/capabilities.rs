//! Capability definitions (Task 2) and, per tenant, whether each is licensed (Task 5).

use crate::data::CapabilityDef;
use crate::{Case, Result};
use duckdb::params;

/// Replace the `capabilities` table with `defs`. Returns the number of rows.
pub fn store_definitions(case: &mut Case, defs: &[CapabilityDef]) -> Result<usize> {
    let tx = case.conn_mut().transaction()?;
    tx.execute("DELETE FROM capabilities", [])?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO capabilities (capability_id, title, baseline, unlocked_by_service_plans,
                 hawk_license_tiers, retention_days, evidence, notes, sources, as_of, origin)
             VALUES (?, ?, ?, CAST(CAST(? AS JSON) AS VARCHAR[]), CAST(CAST(? AS JSON) AS VARCHAR[]),
                     ?, CAST(CAST(? AS JSON) AS VARCHAR[]), ?, CAST(CAST(? AS JSON) AS VARCHAR[]),
                     CAST(? AS DATE), ?)",
        )?;
        let list = |v: &Vec<String>| serde_json::to_string(v).expect("strings serialize");
        for d in defs {
            stmt.execute(params![
                d.id,
                d.title,
                d.baseline,
                list(&d.unlocked_by_service_plans),
                list(&d.hawk_license_tiers),
                d.retention_days.map(i64::from),
                list(&d.evidence),
                d.notes,
                list(&d.sources),
                d.as_of,
                d.origin
            ])?;
        }
    }
    tx.commit()?;
    Ok(defs.len())
}
