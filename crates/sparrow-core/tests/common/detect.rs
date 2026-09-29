//! Helpers for the detection tests: build a small in-memory case by SQL, and run a compiled
//! rule the way the runner does (named parameters, the tenant bound last).

#![allow(dead_code)]

use serde_json::Value;
use sparrow_core::Case;
use sparrow_core::detect::compile::Compiled;
use sparrow_core::detect::rule_conn::with_rule_conn;
use std::collections::BTreeMap;

/// The `collection_id` of `tenant`'s (single) test collection, created on first use.
pub fn collection_of(case: &Case, tenant: &str) -> i64 {
    let existing: Option<i64> = case
        .conn()
        .query_row(
            "SELECT collection_id FROM collections WHERE tenant_key = ?",
            [tenant],
            |r| r.get(0),
        )
        .ok();
    if let Some(id) = existing {
        return id;
    }
    case.conn()
        .execute(
            "INSERT INTO collections (tool, root_path, sparrow_version, tenant_key) VALUES ('hawk', ?, 'test', ?)",
            [format!("/test/{tenant}").as_str(), tenant],
        )
        .unwrap();
    collection_of(case, tenant)
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
        Value::Object(_) if ty == "JSON" => {
            format!("'{}'", v.to_string().replace('\'', "''"))
        }
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

fn default_for(col: &str, ty: &str) -> String {
    if col == "record_key" {
        return "CAST(gen_random_uuid() AS VARCHAR)".to_string();
    }
    match ty {
        "UUID" => "gen_random_uuid()".to_string(),
        "VARCHAR" => "''".to_string(),
        "BOOLEAN" => "false".to_string(),
        "BIGINT" | "INTEGER" | "SMALLINT" => "0".to_string(),
        "TIMESTAMP WITH TIME ZONE" => "TIMESTAMPTZ '2026-01-01 00:00:00+00'".to_string(),
        "JSON" => "'{}'::JSON".to_string(),
        t if t.starts_with("ENUM(") => {
            let first = t.trim_start_matches("ENUM(").split(',').next().unwrap();
            format!("CAST({} AS {t})", first.trim())
        }
        t => panic!("no test default for {col} {t}"),
    }
}

/// Insert one row into `table` for `tenant`. `fields` gives the columns to set (`event_time`
/// as an ISO string, `parameters` as an object, ...); NOT NULL columns without a default get a
/// neutral value and `collection_id` is the tenant's test collection.
pub fn insert_row(case: &Case, table: &str, tenant: &str, fields: Value) {
    let mut st = case
        .conn()
        .prepare(
            "SELECT column_name, replace(data_type, chr(10), ' '), is_nullable = 'YES', column_default IS NOT NULL \
             FROM information_schema.columns WHERE table_schema = 'main' AND table_name = ? ORDER BY ordinal_position",
        )
        .unwrap();
    let cols: Vec<(String, String, bool, bool)> = st
        .query_map([table], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(!cols.is_empty(), "no table {table}");
    let obj = fields.as_object().expect("fields is an object");
    for k in obj.keys() {
        assert!(cols.iter().any(|c| &c.0 == k), "{table} has no column {k}");
    }
    let mut names = Vec::new();
    let mut values = Vec::new();
    for (name, ty, nullable, has_default) in &cols {
        if name == "collection_id" {
            names.push(name.clone());
            values.push(collection_of(case, tenant).to_string());
        } else if let Some(v) = obj.get(name) {
            names.push(name.clone());
            values.push(format!("CAST({} AS {ty})", lit(v, ty)));
        } else if !nullable && !has_default {
            names.push(name.clone());
            values.push(default_for(name, ty));
        }
    }
    let sql = format!(
        "INSERT INTO {table} ({}) VALUES ({})",
        names.join(", "),
        values.join(", ")
    );
    case.conn()
        .execute_batch(&sql)
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

pub fn insert_ual(case: &Case, tenant: &str, fields: Value) {
    insert_row(case, "ual_events", tenant, fields);
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hit {
    pub record_key: String,
    pub source_table: String,
    pub event_epoch: Option<i64>,
    pub actor_upn: Option<String>,
    pub ip: Option<String>,
}

/// Run a compiled rule for `tenant` through the production path (`with_rule_conn`: a separate,
/// locked, tenant-scoped read-only instance). The case's writer connection is released while it
/// runs and comes back afterwards. `iocs` binds the `ioc_<type>` parameters.
pub fn run(
    case: &mut Case,
    compiled: &Compiled,
    tenant: &str,
    iocs: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<Hit>, sparrow_core::Error> {
    with_rule_conn(case, |rc| {
        rc.scope(tenant)?;
        let hits = rc.run(compiled, iocs)?;
        let mut out: Vec<Hit> = hits
            .into_iter()
            .map(|h| Hit {
                record_key: h.record_key,
                source_table: h.source_table,
                event_epoch: h.event_time.map(|t| t.timestamp()),
                actor_upn: h.actor_upn,
                ip: h.ip,
            })
            .collect();
        out.sort_by(|a, b| {
            (a.event_epoch, &a.record_key, &a.source_table).cmp(&(
                b.event_epoch,
                &b.record_key,
                &b.source_table,
            ))
        });
        Ok(out)
    })
}
