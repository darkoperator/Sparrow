//! Rule inline tests (`tests:` in a rule file). Each test builds a fresh in-memory case with one
//! collection and the tenant `test`, inserts its records (`{table: <t>, <column>: <value>, ...}`,
//! required columns defaulted), compiles the rule and runs it through the production path
//! (`with_rule_conn`), and compares the hit count with `expect_hits`.
//!
//! The record inserter is shared with the integration tests (`tests/common/detect.rs`).

use crate::Case;
use crate::detect::compile::{CaseSchema, compile_with_meta};
use crate::detect::load::RuleSet;
use crate::detect::rule::RuleTest;
use crate::detect::rule_conn::with_rule_conn;
use crate::{Error, Result};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

/// The tenant every inline test runs in.
pub const TEST_TENANT: &str = "test";

#[derive(Debug, Clone, Serialize)]
pub struct RuleTestResult {
    pub rule_id: String,
    pub name: String,
    pub expected: u32,
    pub got: u64,
    pub ok: bool,
    pub error: Option<String>,
}

/// The `collection_id` of `tenant`'s (single) test collection, created on first use. Also makes
/// sure a `tenant` row exists so the runner sees the tenant.
pub fn ensure_collection(case: &Case, tenant: &str) -> Result<i64> {
    let existing: Option<i64> = case
        .conn()
        .query_row(
            "SELECT collection_id FROM collections WHERE tenant_key = ?",
            [tenant],
            |r| r.get(0),
        )
        .ok();
    if let Some(id) = existing {
        return Ok(id);
    }
    case.conn().execute(
        "INSERT INTO collections (tool, root_path, sparrow_version, tenant_key) VALUES ('hawk', ?, 'test', ?)",
        [format!("/test/{tenant}").as_str(), tenant],
    )?;
    ensure_collection(case, tenant)
}

fn lit(v: &Value, ty: &str) -> String {
    match v {
        Value::Null => "NULL".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("'{}'", s.replace('\'', "''")),
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(|x| lit(x, "")).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(_) if ty == "JSON" => format!("'{}'", v.to_string().replace('\'', "''")),
        Value::Object(o) if ty.starts_with("MAP") => {
            if o.is_empty() {
                "MAP {}".to_string()
            } else {
                format!(
                    "MAP {{{}}}",
                    o.iter()
                        .map(|(k, x)| format!("'{}': {}", k.replace('\'', "''"), lit(x, "")))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        }
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, x)| format!("'{}': {}", k.replace('\'', "''"), lit(x, "")))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// A neutral value for a NOT NULL column the record left out. `seed` makes generated ids
/// deterministic (UUIDv5 of seed, table and column).
fn default_for(seed: &str, table: &str, col: &str, ty: &str) -> Result<String> {
    if col == "record_key" {
        return Ok(format!("'{}'", stable_id(seed, table, col)));
    }
    Ok(match ty {
        "UUID" => format!("'{}'", stable_id(seed, table, col)),
        "VARCHAR" => "''".to_string(),
        "BOOLEAN" => "false".to_string(),
        "BIGINT" | "INTEGER" | "SMALLINT" => "0".to_string(),
        "TIMESTAMP WITH TIME ZONE" => "TIMESTAMPTZ '2026-01-01 00:00:00+00'".to_string(),
        "JSON" => "'{}'::JSON".to_string(),
        t if t.starts_with("ENUM(") => {
            let first = t
                .trim_start_matches("ENUM(")
                .split(',')
                .next()
                .unwrap_or("");
            format!("CAST({} AS {t})", first.trim())
        }
        t => {
            return Err(Error::Invalid(format!(
                "no default for NOT NULL column {table}.{col} ({t}); give it in the record"
            )));
        }
    })
}

fn stable_id(seed: &str, table: &str, col: &str) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        format!("{seed}/{table}/{col}").as_bytes(),
    )
    .to_string()
}

/// Insert one record into `table` for `tenant`. `fields` is an object of column values
/// (`event_time` as an ISO string, `parameters` as an object, ...). NOT NULL columns without a
/// default get a neutral value, `collection_id` is the tenant's test collection, and generated
/// ids derive from `seed` (so repeated runs insert the same ids). A record for the `tenant` table
/// also needs no other columns.
pub fn insert_record(
    case: &Case,
    tenant: &str,
    table: &str,
    fields: &Value,
    seed: &str,
) -> Result<()> {
    let mut st = case.conn().prepare(
        "SELECT column_name, replace(data_type, chr(10), ' '), is_nullable = 'YES', column_default IS NOT NULL \
         FROM information_schema.columns WHERE table_schema = 'main' AND table_name = ? ORDER BY ordinal_position",
    )?;
    let cols: Vec<(String, String, bool, bool)> = st
        .query_map([table], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<std::result::Result<_, _>>()?;
    if cols.is_empty() {
        return Err(Error::Invalid(format!("unknown table {table:?}")));
    }
    let obj = fields
        .as_object()
        .ok_or_else(|| Error::Invalid("a record is an object".into()))?;
    for k in obj.keys() {
        if !cols.iter().any(|c| &c.0 == k) {
            return Err(Error::Invalid(format!("table {table} has no column {k:?}")));
        }
    }
    let mut names = Vec::new();
    let mut values = Vec::new();
    for (name, ty, nullable, has_default) in &cols {
        if name == "collection_id" && !obj.contains_key(name) {
            names.push(name.clone());
            values.push(ensure_collection(case, tenant)?.to_string());
        } else if let Some(v) = obj.get(name) {
            names.push(name.clone());
            values.push(format!("CAST({} AS {ty})", lit(v, ty)));
        } else if !nullable && !has_default {
            names.push(name.clone());
            values.push(default_for(seed, table, name, ty)?);
        }
    }
    let sql = format!(
        "INSERT INTO {table} ({}) VALUES ({})",
        names.join(", "),
        values.join(", ")
    );
    case.conn()
        .execute_batch(&sql)
        .map_err(|e| Error::Invalid(format!("{table} record: {e}")))
}

fn run_one(set: &RuleSet, rule_index: usize, test_index: usize, t: &RuleTest) -> Result<u64> {
    let lr = &set.rules[rule_index];
    let mut case = Case::in_memory()?;
    ensure_collection(&case, TEST_TENANT)?;
    insert_record(
        &case,
        TEST_TENANT,
        "tenant",
        &serde_json::json!({"tenant_key": TEST_TENANT}),
        "tenant",
    )?;
    for (i, rec) in t.records.iter().enumerate() {
        let mut rec = rec.clone();
        let table = match rec.remove("table") {
            Some(Value::String(s)) => s,
            _ => {
                return Err(Error::Invalid(format!("record {i} has no `table:` key")));
            }
        };
        let seed = format!("{}#{}#{i}", lr.rule.id, test_index);
        insert_record(&case, TEST_TENANT, &table, &Value::Object(rec), &seed)?;
    }
    let schema = CaseSchema::of(case.conn())?;
    let compiled = compile_with_meta(&lr.rule, &set.lists, &set.list_meta, &schema)?;
    let hits = with_rule_conn(&mut case, |rc| {
        rc.scope(TEST_TENANT)?;
        rc.run(&compiled, &Default::default())
    })?;
    Ok(hits.len() as u64)
}

/// Run the inline tests of `rule_id` (every rule when `None`). Errors when `rule_id` is unknown.
pub fn run_inline_tests(set: &RuleSet, rule_id: Option<&str>) -> Result<Vec<RuleTestResult>> {
    if let Some(id) = rule_id {
        if !set.rules.iter().any(|r| r.rule.id == id) {
            return Err(Error::Invalid(format!("unknown rule id {id}")));
        }
    }
    let mut out = Vec::new();
    for (ri, lr) in set.rules.iter().enumerate() {
        if rule_id.is_some_and(|id| id != lr.rule.id) {
            continue;
        }
        for (ti, t) in lr.rule.tests.iter().enumerate() {
            let result = run_one(set, ri, ti, t);
            out.push(match result {
                Ok(got) => RuleTestResult {
                    rule_id: lr.rule.id.clone(),
                    name: t.name.clone(),
                    expected: t.expect_hits,
                    got,
                    ok: got == u64::from(t.expect_hits),
                    error: None,
                },
                Err(e) => RuleTestResult {
                    rule_id: lr.rule.id.clone(),
                    name: t.name.clone(),
                    expected: t.expect_hits,
                    got: 0,
                    ok: false,
                    error: Some(e.to_string()),
                },
            });
        }
    }
    Ok(out)
}
