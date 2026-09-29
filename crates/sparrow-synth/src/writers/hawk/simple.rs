//! `Get-SimpleUnifiedAuditLog` (Hawk 4.0 `internal/functions/Get-SimpleUnifiedAuditLog.ps1`;
//! research hawk layouts §4): a raw `Search-UnifiedAuditLog` record flattened to one object of
//! scalar properties.
//!
//! The record's own properties (all but `AuditData`) come first, then the flattened AuditData
//! overwrites same-named ones (so `RecordType` becomes AuditData's number). AuditData is
//! flattened property by property:
//! - `Parameters` (an array, at any depth) becomes `ParameterString` (`N=V | N=V`), one
//!   `Param_<Name>` per parameter (never prefixed) and, when the object has an `Operation`,
//!   `FullCommand` (`<Operation> -N v ...`, each value through Hawk's `switch -Regex` without
//!   `break`: a value with a space and a `;` is quoted twice);
//! - an object becomes `<key>_<sub>` properties; PowerShell's `switch` enumerates arrays, so
//!   each array element is flattened under the same key, collisions taking the smallest free
//!   `_<n>` suffix (`ExtendedProperties_Name`, `ExtendedProperties_Name_1`, ...); an array of
//!   scalars keeps its last element and an empty array leaves no property;
//! - a scalar is kept typed (date, bool, number), `null` becomes `""`.
//!
//! Output order: `CreationTime, Workload, RecordType, Operation, ResultStatus, ClientIP, UserId,
//! Id, OrganizationId, UserType, UserKey, ObjectId, Scope, AppAccessContext` when present, then
//! `ParameterString` and the `Param_*` properties sorted by name, then every other property in
//! PowerShell hashtable order: a permutation seeded by `order_seed`, the same for every record
//! written with that seed (one file).

use crate::ps::{Origin, PsDate, Row, Val};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// The fixed leading properties, in Hawk's order.
const ORDERED: &[&str] = &[
    "CreationTime",
    "Workload",
    "RecordType",
    "Operation",
    "ResultStatus",
    "ClientIP",
    "UserId",
    "Id",
    "OrganizationId",
    "UserType",
    "UserKey",
    "ObjectId",
    "Scope",
    "AppAccessContext",
];

/// A PowerShell hashtable: insertion-ordered here, keys compared case-insensitively.
#[derive(Debug, Default, Clone)]
struct Flat {
    items: Vec<(String, Val)>,
    lower: BTreeSet<String>,
}

impl Flat {
    fn contains(&self, key: &str) -> bool {
        self.lower.contains(&key.to_lowercase())
    }

    fn set(&mut self, key: String, v: Val) {
        let l = key.to_lowercase();
        if self.lower.contains(&l) {
            if let Some(slot) = self.items.iter_mut().find(|(k, _)| k.to_lowercase() == l) {
                slot.1 = v;
            }
        } else {
            self.lower.insert(l);
            self.items.push((key, v));
        }
    }

    /// Merges a nested object's properties, renaming a colliding key to the smallest free
    /// `<key>_<n>`.
    fn merge(&mut self, nested: Flat) {
        for (k, v) in nested.items {
            let key = if self.contains(&k) {
                let mut n = 1;
                while self.contains(&format!("{k}_{n}")) {
                    n += 1;
                }
                format!("{k}_{n}")
            } else {
                k
            };
            self.set(key, v);
        }
    }
}

/// ISO 8601 text (`yyyy-MM-ddTHH:mm:ss[.f][Z]`) as PowerShell 7's `ConvertFrom-Json` turns
/// into a `DateTime`.
fn iso_time(s: &str) -> Option<DateTime<Utc>> {
    let t = s.strip_suffix('Z').unwrap_or(s);
    if t.len() < 19 || t.as_bytes().get(10) != Some(&b'T') {
        return None;
    }
    ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"]
        .iter()
        .find_map(|f| NaiveDateTime::parse_from_str(t, f).ok())
        .map(|n| n.and_utc())
}

/// A JSON scalar as `ConvertFrom-Json` hands it over: ISO text becomes a date (rendered by the
/// edition: a culture date on 7, the text on 5.1), numbers and booleans stay typed.
pub fn json_scalar(v: &Value) -> Val {
    match v {
        Value::Null => Val::Null,
        Value::Bool(b) => Val::Bool(*b),
        Value::Number(n) => match n.as_i64() {
            Some(i) => Val::Int(i),
            None => Val::Float(n.as_f64().unwrap_or_default()),
        },
        Value::String(s) => match iso_time(s) {
            Some(utc) => Val::DateText(PsDate {
                utc,
                origin: Origin::IsoText(s.clone()),
            }),
            None => Val::Str(s.clone()),
        },
        other => Val::Raw(other.clone()),
    }
}

/// `"$value"` of a JSON value (PowerShell string conversion).
pub fn ps_text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(ps_text).collect::<Vec<_>>().join(" "),
        Value::Object(_) => "System.Management.Automation.PSCustomObject".into(),
    }
}

/// One value through `switch -Regex` without `break`: every matching clause emits.
fn command_value(v: &Value) -> String {
    if v.is_null() {
        return String::new();
    }
    let s = ps_text(v);
    let mut out = Vec::new();
    if s.chars().any(char::is_whitespace) {
        out.push(format!("'{s}'"));
    }
    if s.eq_ignore_ascii_case("true") || s.eq_ignore_ascii_case("false") {
        out.push(format!("${}", s.to_lowercase()));
    }
    if s.contains(';') {
        out.push(format!("'{s}'"));
    }
    if out.is_empty() {
        out.push(s);
    }
    out.join(" ")
}

fn param_name_value(p: &Value) -> (String, Value) {
    let name = p.get("Name").map(ps_text).unwrap_or_default();
    let value = p.get("Value").cloned().unwrap_or(Value::Null);
    (name, value)
}

/// `ConvertTo-FlatObject`.
fn flat_object(obj: &Map<String, Value>, prefix: &str) -> Flat {
    let mut flat = Flat::default();
    for (name, value) in obj {
        let key = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}_{name}")
        };
        if name == "Parameters" {
            if let Value::Array(params) = value {
                let pairs: Vec<(String, Value)> = params.iter().map(param_name_value).collect();
                let joined: Vec<String> = pairs
                    .iter()
                    .map(|(n, v)| format!("{n}={}", ps_text(v)))
                    .collect();
                flat.set("ParameterString".into(), Val::Str(joined.join(" | ")));
                for (n, v) in &pairs {
                    // Every parameter value is a string, as `Get-SimpleUnifiedAuditLog` leaves
                    // it: the survey records `Param_StartTime`/`Param_EndTime` in the service's
                    // own 24-hour rendering, not as an ISO string re-typed by `ConvertFrom-Json`
                    // (survey 2026-09-24-hawk-capture-survey.md:123, against :122).
                    let val = match v {
                        Value::Null => Val::Null,
                        other => Val::Str(ps_text(other)),
                    };
                    flat.set(format!("Param_{n}"), val);
                }
                let operation = obj.get("Operation").map(ps_text).unwrap_or_default();
                if !operation.is_empty() {
                    let args: Vec<String> = pairs
                        .iter()
                        .map(|(n, v)| format!("-{n} {}", command_value(v)))
                        .collect();
                    flat.set(
                        "FullCommand".into(),
                        Val::Str(format!("{operation} {}", args.join(" "))),
                    );
                }
                continue;
            }
        }
        match value {
            Value::Array(items) => {
                for item in items {
                    element(&mut flat, &key, item);
                }
            }
            other => element(&mut flat, &key, other),
        }
    }
    flat
}

/// One `switch` iteration: an object is flattened under `key`, a scalar stored as it is.
fn element(flat: &mut Flat, key: &str, v: &Value) {
    match v {
        Value::Object(m) => {
            let nested = flat_object(m, key);
            flat.merge(nested);
        }
        Value::Array(items) => {
            // An array inside an array reaches the IList branch.
            if items.is_empty() {
                flat.set(key.to_string(), Val::Str(String::new()));
            } else if let Some(Value::Object(_)) = items.first() {
                for (i, item) in items.iter().enumerate() {
                    if let Value::Object(m) = item {
                        let nested = flat_object(m, &format!("{key}_{i}"));
                        flat.merge(nested);
                    }
                }
            } else {
                let joined: Vec<String> = items.iter().map(ps_text).collect();
                flat.set(key.to_string(), Val::Str(joined.join("|")));
            }
        }
        Value::Null => flat.set(key.to_string(), Val::Str(String::new())),
        other => flat.set(key.to_string(), json_scalar(other)),
    }
}

/// FNV-1a over the seed and the lower-cased key: the seeded hashtable order.
fn order_hash(seed: u64, key: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ seed;
    for b in key.to_lowercase().bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// Flattens one raw record: `record_base` is the record's properties (its `AuditData`, if
/// present, is ignored), `audit` its parsed AuditData. `order_seed` fixes the order of the
/// properties Hawk leaves in hashtable order.
pub fn flatten(record_base: &Row, audit: &Map<String, Value>, order_seed: u64) -> Row {
    let mut combined = Flat::default();
    for (k, v) in record_base {
        if k != "AuditData" {
            combined.set(k.clone(), v.clone());
        }
    }
    for (k, v) in flat_object(audit, "").items {
        combined.set(k, v);
    }
    let get = |name: &str| {
        let l = name.to_lowercase();
        combined
            .items
            .iter()
            .find(|(k, _)| k.to_lowercase() == l)
            .map(|(_, v)| v.clone())
    };
    let mut out: Row = Vec::new();
    for name in ORDERED {
        if let Some(v) = get(name) {
            out.push((name.to_string(), v));
        }
    }
    let is_param = |k: &str| k.len() > 6 && k[..6].eq_ignore_ascii_case("param_");
    if let Some(v) = get("ParameterString") {
        out.push(("ParameterString".into(), v));
        let mut params: Vec<&(String, Val)> =
            combined.items.iter().filter(|(k, _)| is_param(k)).collect();
        params.sort_by_key(|(k, _)| k.to_lowercase());
        out.extend(params.into_iter().cloned());
    }
    let fixed: BTreeSet<String> = ORDERED.iter().map(|k| k.to_lowercase()).collect();
    let mut rest: Vec<&(String, Val)> = combined
        .items
        .iter()
        .filter(|(k, _)| {
            !fixed.contains(&k.to_lowercase())
                && !k.eq_ignore_ascii_case("ParameterString")
                && !is_param(k)
        })
        .collect();
    rest.sort_by_key(|(k, _)| (order_hash(order_seed, k), k.to_lowercase()));
    out.extend(rest.into_iter().cloned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn keys(r: &Row) -> Vec<&str> {
        r.iter().map(|(k, _)| k.as_str()).collect()
    }

    fn value<'a>(r: &'a Row, k: &str) -> &'a Val {
        &r.iter().find(|(n, _)| n == k).unwrap().1
    }

    #[test]
    fn parameters_become_param_columns_and_a_full_command() {
        let base: Row = vec![
            ("RecordType".into(), Val::Str("ExchangeAdmin".into())),
            ("AuditData".into(), Val::Str("{}".into())),
            ("ResultIndex".into(), Val::Int(1)),
        ];
        let audit = json!({
            "CreationTime": "2026-08-01T10:00:00",
            "Id": "11111111-1111-1111-1111-111111111111",
            "Operation": "New-InboxRule",
            "RecordType": 1,
            "Parameters": [
                {"Name": "Name", "Value": "a; b c"},
                {"Name": "DeleteMessage", "Value": "False"},
                {"Name": "ForwardTo", "Value": null},
            ],
        });
        let r = flatten(&base, audit.as_object().unwrap(), 7);
        assert_eq!(
            &keys(&r)[..4],
            ["CreationTime", "RecordType", "Operation", "Id"]
        );
        assert_eq!(value(&r, "RecordType"), &Val::Int(1));
        assert_eq!(
            value(&r, "ParameterString"),
            &Val::Str("Name=a; b c | DeleteMessage=False | ForwardTo=".into())
        );
        assert_eq!(
            &keys(&r)[4..8],
            [
                "ParameterString",
                "Param_DeleteMessage",
                "Param_ForwardTo",
                "Param_Name"
            ]
        );
        assert_eq!(
            value(&r, "FullCommand"),
            &Val::Str(
                "New-InboxRule -Name 'a; b c' 'a; b c' -DeleteMessage $false -ForwardTo ".into()
            )
        );
        assert!(!keys(&r).contains(&"AuditData"));
    }

    #[test]
    fn arrays_of_objects_take_collision_suffixes_and_scalar_arrays_keep_the_last() {
        let audit = json!({
            "Id": "x", "Operation": "UserLoggedIn", "CreationTime": "2026-08-01T10:00:00",
            "ExtendedProperties": [
                {"Name": "A", "Value": "1"}, {"Name": "B", "Value": "2"}, {"Name": "C", "Value": null}
            ],
            "Tags": ["one", "two"],
            "Empty": [],
            "Nothing": null,
        });
        let r = flatten(&Vec::new(), audit.as_object().unwrap(), 1);
        for k in [
            "ExtendedProperties_Name",
            "ExtendedProperties_Name_1",
            "ExtendedProperties_Name_2",
            "ExtendedProperties_Value_2",
        ] {
            assert!(keys(&r).contains(&k), "{k}");
        }
        assert_eq!(
            value(&r, "ExtendedProperties_Value_2"),
            &Val::Str("".into())
        );
        assert_eq!(value(&r, "Tags"), &Val::Str("two".into()));
        assert!(!keys(&r).contains(&"Empty"));
        assert_eq!(value(&r, "Nothing"), &Val::Str("".into()));
    }

    #[test]
    fn the_hashtable_order_is_fixed_per_seed() {
        let audit = json!({"Id": "x", "Operation": "o", "CreationTime": "2026-08-01T10:00:00",
            "Zeta": 1, "Alpha": 2, "Mid": 3, "Other": 4});
        let a = flatten(&Vec::new(), audit.as_object().unwrap(), 5);
        let b = flatten(&Vec::new(), audit.as_object().unwrap(), 5);
        assert_eq!(keys(&a), keys(&b));
        let orders: BTreeSet<Vec<String>> = (0..16)
            .map(|s| {
                flatten(&Vec::new(), audit.as_object().unwrap(), s)
                    .into_iter()
                    .map(|(k, _)| k)
                    .collect()
            })
            .collect();
        assert!(orders.len() > 1, "the seed permutes the remaining keys");
    }
}
