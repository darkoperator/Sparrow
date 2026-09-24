//! Shapes of unified audit log data (Addendum A.3) and the AuditData object each record carries.

use serde_json::{Map, Value};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UalShape {
    /// Search-UnifiedAuditLog output: `RecordType, CreationDate, UserIds, Operations,
    /// AuditData` (AuditData an embedded JSON string).
    Raw,
    /// Purview audit search export: `RecordId, CreationDate, RecordType, Operation, UserId, AuditData`.
    Purview,
    /// AuditData keys at top level (Hawk 3 `Exchange_UAL_Audit`, Hawk 4 `MailItemsAccessed_*`,
    /// `SendActivity_*`, per-IP event files, Hawk 3 `eDiscoveryLogs`).
    Record,
    /// Hawk `Simple_*`: AuditData flattened to scalar columns (`Param_*`, `_N` suffixes).
    Flattened,
    /// Hawk `Azure_Application_Audit` / `Entra_ID_Application_Audit`: 10 columns with `env_time`.
    AppAudit,
    /// Hawk 3 Search-AdminAuditLog records (`CmdletName, Caller, RunDate, ...`): not UAL.
    AdminAudit,
    /// Hawk 3 five-column summary (`Caller, Cmdlet, FullCommand, RunDate(UTC), ObjectModified`).
    AdminAuditSimple,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness {
    Full,
    Partial,
}

impl Completeness {
    pub fn as_str(self) -> &'static str {
        match self {
            Completeness::Full => "full",
            Completeness::Partial => "partial",
        }
    }
}

/// Shape of a record from its column names or JSON keys (case-insensitive).
/// `flattened_artifact`: the file is a derived Hawk artifact (`Simple_*`, `Converted_*`).
pub fn detect_shape<'k>(
    keys: impl IntoIterator<Item = &'k str>,
    flattened_artifact: bool,
) -> UalShape {
    let set: HashSet<String> = keys.into_iter().map(|k| k.to_ascii_lowercase()).collect();
    let has = |k: &str| set.contains(k);
    if has("cmdletname") && has("caller") && has("rundate") {
        UalShape::AdminAudit
    } else if has("cmdlet") && has("fullcommand") && has("caller") {
        UalShape::AdminAuditSimple
    } else if has("auditdata") && has("recordid") {
        UalShape::Purview
    } else if has("auditdata") {
        UalShape::Raw
    } else if has("env_time") && has("id") && has("operation") {
        UalShape::AppAudit
    } else if has("id") && has("operation") && has("creationtime") {
        if flattened_artifact {
            UalShape::Flattened
        } else {
            UalShape::Record
        }
    } else {
        UalShape::Unknown
    }
}

/// One record reduced to its AuditData object plus what the outer shape adds.
#[derive(Debug, Clone)]
pub struct AuditInput {
    pub audit: Map<String, Value>,
    pub completeness: Completeness,
    /// Outer `RecordType` of raw / Purview records (enum name, or number as text).
    pub outer_record_type: Option<String>,
    /// Outer `CreationDate` of raw / Purview records (used when AuditData has no CreationTime).
    pub outer_time: Option<String>,
    /// `Param_<Name>` columns of flattened records.
    pub flat_params: Vec<(String, String)>,
}

/// Case-insensitive key lookup (exact match first).
pub fn get_ci<'m>(map: &'m Map<String, Value>, key: &str) -> Option<&'m Value> {
    map.get(key).or_else(|| {
        map.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
    })
}

/// A value as text; `None` for null and blank strings. Arrays/objects give their JSON.
pub fn value_text(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) if s.trim().is_empty() => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        other => Some(other.to_string()),
    }
}

/// Reduce `record` to its AuditData. `lossy`: the record came from a CSV (first-record
/// columns, `@{...}` / `System.Object[]` cells) or a derived artifact, so a `Record` is partial.
pub fn to_audit(
    shape: UalShape,
    record: &Map<String, Value>,
    lossy: bool,
) -> Result<AuditInput, String> {
    let plain = |audit: Map<String, Value>, completeness| AuditInput {
        audit,
        completeness,
        outer_record_type: None,
        outer_time: None,
        flat_params: Vec::new(),
    };
    match shape {
        UalShape::Raw | UalShape::Purview => {
            let audit = match get_ci(record, "AuditData") {
                None | Some(Value::Null) => return Err("record has no AuditData".into()),
                Some(Value::Object(m)) => m.clone(),
                Some(Value::String(s)) => match serde_json::from_str::<Value>(s) {
                    Ok(Value::Object(m)) => m,
                    Ok(_) => return Err("AuditData is not a JSON object".into()),
                    Err(e) => return Err(format!("AuditData is not valid JSON: {e}")),
                },
                Some(_) => return Err("AuditData is not a JSON object".into()),
            };
            Ok(AuditInput {
                audit,
                completeness: Completeness::Full,
                outer_record_type: get_ci(record, "RecordType").and_then(value_text),
                outer_time: get_ci(record, "CreationDate").and_then(value_text),
                flat_params: Vec::new(),
            })
        }
        UalShape::Record => Ok(plain(
            record.clone(),
            if lossy {
                Completeness::Partial
            } else {
                Completeness::Full
            },
        )),
        UalShape::Flattened => {
            let flat_params = record
                .iter()
                .filter_map(|(k, v)| {
                    let name = k
                        .get(..6)
                        .filter(|p| p.eq_ignore_ascii_case("param_"))
                        .map(|_| &k[6..])?;
                    Some((name.to_string(), value_text(v)?))
                })
                .collect();
            Ok(AuditInput {
                flat_params,
                ..plain(record.clone(), Completeness::Partial)
            })
        }
        UalShape::AppAudit => {
            let mut audit = record.clone();
            if get_ci(&audit, "CreationTime").is_none() {
                // Hawk writes `env_time: null` in real captures; null or blank is no time.
                if let Some(t) = get_ci(record, "env_time")
                    .filter(|t| value_text(t).is_some())
                    .cloned()
                {
                    audit.insert("CreationTime".into(), t);
                }
            }
            Ok(plain(audit, Completeness::Partial))
        }
        UalShape::AdminAudit | UalShape::AdminAuditSimple => {
            Err("admin audit log record, not a unified audit log record".into())
        }
        UalShape::Unknown => Err("unrecognized unified audit log record shape".into()),
    }
}
