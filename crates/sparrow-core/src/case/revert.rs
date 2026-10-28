//! What a discard restores (Addendum D.4): only the decision-bearing fields the discarded decision changed (its
//! audit `before` vs `after`), so later changes by detection (`rule_updated`) or to other fields survive. Timeline
//! entries have their own revert (evidence rows, a superseded entry): `timeline_entries::revert`.

use crate::case::actor::Reviewer;
use crate::case::audit::AuditEntry;
use crate::case::marks::RowRef;
use crate::{Error, Result};
use duckdb::{Connection, params};
use serde_json::{Map, Value};

/// (field, SQL type it is restored as) per object type. Provenance tags are not in these lists: after a discard,
/// `decided_by`/`on_behalf_of` keep naming the discarded decision and `review_state` says it was undone.
const FINDING: &[(&str, &str)] = &[
    ("status", "finding_status"),
    ("disposition_reason", "VARCHAR"),
    ("assigned_to", "VARCHAR"),
    ("rule_updated", "BOOLEAN"),
];
const INDICATOR: &[(&str, &str)] = &[
    ("verdict", "indicator_verdict"),
    ("note", "VARCHAR"),
    ("removed_at", "TIMESTAMPTZ"),
    ("removed_by", "VARCHAR"),
];
const VALUE_FLAG: &[(&str, &str)] = &[
    ("level", "flag_level"),
    ("removed_at", "TIMESTAMPTZ"),
    ("removed_by", "VARCHAR"),
];

/// The SQL text of a JSON field for a parameter: strings as is, booleans as 'true'/'false', null as NULL.
fn text(v: &Value) -> Result<Option<String>> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        Value::Bool(b) => Ok(Some(b.to_string())),
        other => Err(Error::Invalid(format!(
            "unexpected value {other} in an audit state"
        ))),
    }
}

/// Restore the fields the decision `d` changed on the object; returns them with their restored values.
/// A decision that created an indicator or a value flag (`before` null) is undone by removing it, by `reviewer` at
/// `ts`. The decision of a call that marked event rows (`event_flag`, `event_tag`) is undone row by row from its own
/// audit entry (`case::marks::revert_batch`), only for `only` when given.
pub(crate) fn apply(
    tx: &Connection,
    object_type: &str,
    object_id: &str,
    d: &AuditEntry,
    reviewer: &Reviewer,
    ts: &str,
    only: Option<&[RowRef]>,
) -> Result<Map<String, Value>> {
    let (table, key, fields) = match object_type {
        "finding" => ("findings", "finding_id", FINDING),
        "indicator" => ("case_indicators", "indicator_id", INDICATOR),
        "value_flag" => ("value_flags", "flag_id", VALUE_FLAG),
        "event_flag" | "event_tag" => {
            return crate::case::marks::revert_batch(tx, object_type, object_id, d, only);
        }
        "timeline_entry" => {
            return crate::case::timeline_entries::revert(tx, object_id, d);
        }
        other => return Err(Error::Decision(format!("cannot review a {other}"))),
    };
    let mut restored = Map::new();
    let Some(before) = d.before.as_ref().filter(|b| !b.is_null()) else {
        if object_type != "indicator" && object_type != "value_flag" {
            return Err(Error::Invalid(format!(
                "decision {} on {object_type} {object_id} has no prior state",
                d.seq
            )));
        }
        tx.execute(
            &format!(
                "UPDATE {table} SET removed_at = CAST(? AS TIMESTAMPTZ), removed_by = ? WHERE {key} = ?"
            ),
            params![ts, reviewer.as_str(), object_id],
        )?;
        restored.insert("removed_at".into(), Value::String(ts.into()));
        restored.insert("removed_by".into(), Value::String(reviewer.as_str().into()));
        return Ok(restored);
    };
    let after = d.after.as_ref().unwrap_or(&Value::Null);
    for (field, ty) in fields {
        let old = before.get(*field).unwrap_or(&Value::Null);
        if after.get(*field).unwrap_or(&Value::Null) == old {
            continue;
        }
        tx.execute(
            &format!("UPDATE {table} SET {field} = CAST(? AS {ty}) WHERE {key} = ?"),
            params![text(old)?, object_id],
        )?;
        restored.insert((*field).into(), old.clone());
    }
    Ok(restored)
}
