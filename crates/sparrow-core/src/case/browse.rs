//! Table browsing for the review app: one page of a case table or view with typed, server-side filters.
//!
//! Nothing from the caller reaches the SQL text except identifiers that were first matched, exactly, against the
//! case's own catalog (`db::describe`), and those are double-quoted. Filter values are bound parameters, passed as
//! text and compared in the column's own type (integer, floating, decimal, time) or, for every other type, on the
//! column cast to text. The cast types come from a static map of catalog type names, never from input.

use crate::db::describe::{TableInfo, describe_conn};
use crate::{Error, Result};
use duckdb::{Connection, params_from_iter};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Most rows a page returns, whatever the caller asks for.
pub const MAX_PAGE: usize = 500;
/// Matching rows are counted up to this many.
pub const COUNT_CAP: u64 = 1_000_000;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Filter {
    Eq {
        column: String,
        value: Value,
    },
    Ne {
        column: String,
        value: Value,
    },
    /// Case-insensitive substring; `%`, `_` and `\` in the value are plain text.
    Contains {
        column: String,
        value: String,
    },
    /// Inclusive on both ends; times for a time column, numbers for a number column, text order otherwise.
    Between {
        column: String,
        low: Value,
        high: Value,
    },
    In {
        column: String,
        values: Vec<Value>,
    },
    IsNull {
        column: String,
    },
    NotNull {
        column: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Sort {
    pub column: String,
    pub descending: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowsePage {
    pub table: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub offset: usize,
    /// Matching rows, counted up to `COUNT_CAP`; `total_capped` when there are more.
    pub total: u64,
    pub total_capped: bool,
}

/// The browsable tables and views: exactly what `describe_conn(conn, None)` lists.
pub fn tables(conn: &Connection) -> Result<Vec<String>> {
    Ok(describe_conn(conn, None)?
        .into_iter()
        .map(|t| t.table)
        .collect())
}

fn quote(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

/// The column's catalog entry; `Error::Invalid` when the table has no such column.
fn column<'a>(info: &'a TableInfo, name: &str) -> Result<&'a crate::db::describe::ColumnInfo> {
    info.columns
        .iter()
        .find(|c| c.name == name)
        .ok_or_else(|| Error::Invalid(format!("unknown column {name:?} in {}", info.table)))
}

/// How a column's values are compared and returned, from the catalog's type name.
#[derive(Debug, Clone, PartialEq)]
enum Kind {
    /// Compared as HUGEINT (holds every integer type up to UBIGINT).
    Int,
    /// FLOAT or DOUBLE, compared in that type.
    Float(&'static str),
    /// DECIMAL(p,s), compared in that type.
    Decimal(String),
    /// TIMESTAMPTZ, TIMESTAMP or DATE.
    Time(&'static str),
    Text,
}

fn kind_of(data_type: &str) -> Kind {
    let t = data_type.to_ascii_uppercase();
    match t.as_str() {
        "TINYINT" | "SMALLINT" | "INTEGER" | "BIGINT" | "HUGEINT" | "UTINYINT" | "USMALLINT"
        | "UINTEGER" | "UBIGINT" => Kind::Int,
        "FLOAT" => Kind::Float("FLOAT"),
        "DOUBLE" => Kind::Float("DOUBLE"),
        "TIMESTAMP WITH TIME ZONE" | "TIMESTAMPTZ" => Kind::Time("TIMESTAMPTZ"),
        "TIMESTAMP" => Kind::Time("TIMESTAMP"),
        "DATE" => Kind::Time("DATE"),
        _ => {
            let dec = t
                .strip_prefix("DECIMAL(")
                .and_then(|r| r.strip_suffix(')'))
                .and_then(|r| r.split_once(','))
                .filter(|(p, sc)| {
                    !p.is_empty()
                        && p.chars().all(|c| c.is_ascii_digit())
                        && !sc.is_empty()
                        && sc.chars().all(|c| c.is_ascii_digit())
                });
            match dec {
                Some((p, sc)) => Kind::Decimal(format!("DECIMAL({p},{sc})")),
                None => Kind::Text,
            }
        }
    }
}

/// True for the types whose values come back as JSON text: JSON itself and every structured type.
fn is_structured(data_type: &str) -> bool {
    let t = data_type.to_ascii_uppercase();
    t == "JSON"
        || t.starts_with("STRUCT")
        || t.starts_with("MAP")
        || t.starts_with("UNION")
        || t.ends_with(']')
}

/// A filter value as the text a bound parameter carries, validated for the column's kind.
fn text_of(kind: &Kind, v: &Value) -> Result<String> {
    let bad = |what: &str| Error::Invalid(format!("a filter value for a {what} column is {v}"));
    match kind {
        Kind::Text => match v {
            Value::String(s) => Ok(s.clone()),
            Value::Number(_) | Value::Bool(_) => Ok(v.to_string()),
            _ => Err(Error::Invalid(
                "a filter value is a string, number or boolean".into(),
            )),
        },
        Kind::Int => {
            let n = match v {
                Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string(),
                Value::Number(n) => match n.as_f64() {
                    Some(f) if f.fract() == 0.0 && f.abs() < 9.0e15 => format!("{}", f as i64),
                    _ => return Err(bad("integer")),
                },
                Value::String(s) if s.trim().parse::<i128>().is_ok() => s.trim().to_string(),
                _ => return Err(bad("integer")),
            };
            Ok(n)
        }
        Kind::Float(_) | Kind::Decimal(_) => {
            let t = match v {
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.trim().to_string(),
                _ => return Err(bad("numeric")),
            };
            match t.parse::<f64>() {
                Ok(f) if f.is_finite() => Ok(t),
                _ => Err(bad("numeric")),
            }
        }
        Kind::Time(_) => match v {
            Value::String(s) => Ok(s.clone()),
            _ => Err(bad("time")),
        },
    }
}

/// The SQL for `col` and for one bound value of that column: the column cast to text for text columns, the bare
/// column against a cast parameter for typed ones.
fn operands(kind: &Kind, col: &str) -> (String, String) {
    match kind {
        Kind::Text => (format!("CAST({col} AS VARCHAR)"), "?".into()),
        Kind::Int => (col.to_string(), "CAST(? AS HUGEINT)".into()),
        Kind::Float(t) | Kind::Time(t) => (col.to_string(), format!("CAST(? AS {t})")),
        Kind::Decimal(t) => (col.to_string(), format!("CAST(? AS {t})")),
    }
}

fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `WHERE ...` (or empty) and its parameters, in placeholder order.
fn where_clause(info: &TableInfo, filters: &[Filter]) -> Result<(String, Vec<String>)> {
    let mut parts = Vec::new();
    let mut args: Vec<String> = Vec::new();
    for f in filters {
        match f {
            Filter::Eq { column: c, value } | Filter::Ne { column: c, value } => {
                let ci = column(info, c)?;
                let k = kind_of(&ci.data_type);
                let (lhs, rhs) = operands(&k, &quote(&ci.name));
                let op = if matches!(f, Filter::Eq { .. }) {
                    "="
                } else {
                    "<>"
                };
                parts.push(format!("{lhs} {op} {rhs}"));
                args.push(text_of(&k, value)?);
            }
            Filter::Contains { column: c, value } => {
                let col = quote(&column(info, c)?.name);
                parts.push(format!(
                    "CAST({col} AS VARCHAR) ILIKE '%' || ? || '%' ESCAPE '\\'"
                ));
                args.push(escape_like(value));
            }
            Filter::Between {
                column: c,
                low,
                high,
            } => {
                let ci = column(info, c)?;
                let k = kind_of(&ci.data_type);
                let (lhs, rhs) = operands(&k, &quote(&ci.name));
                parts.push(format!("{lhs} BETWEEN {rhs} AND {rhs}"));
                args.push(text_of(&k, low)?);
                args.push(text_of(&k, high)?);
            }
            Filter::In { column: c, values } => {
                let ci = column(info, c)?;
                let k = kind_of(&ci.data_type);
                if values.is_empty() {
                    parts.push("FALSE".to_string());
                } else {
                    let (lhs, rhs) = operands(&k, &quote(&ci.name));
                    parts.push(format!("{lhs} IN ({})", vec![rhs; values.len()].join(", ")));
                    for v in values {
                        args.push(text_of(&k, v)?);
                    }
                }
            }
            Filter::IsNull { column: c } => {
                parts.push(format!("{} IS NULL", quote(&column(info, c)?.name)));
            }
            Filter::NotNull { column: c } => {
                parts.push(format!("{} IS NOT NULL", quote(&column(info, c)?.name)));
            }
        }
    }
    let sql = if parts.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", parts.join(" AND "))
    };
    Ok((sql, args))
}

/// The columns that are unique per row of `info`, when that is proven; `None` otherwise (views, and tables whose
/// uniqueness nothing guarantees).
///
/// - Declared `PRIMARY KEY`s (migrations 0001, 0003, 0009, 0016, 0020): `ual_events(record_id)`, `collections`,
///   `source_files`, `collection_log`, `case_meta`, `audit_trail`, `findings`, `finding_facts`, `timeline_entries`,
///   `annotations`, and the composite keys of `record_sources`, `timeline_entry_evidence` and `account_rollup`.
/// - Every other table with a `record_key` column is loaded by `ingest::state::load_rows`, which inserts a row
///   only `WHERE NOT EXISTS (... t.record_key = p.record_key)` over the whole table (not per collection) and picks
///   one staged row per key, so `record_key` alone is unique. `finding_evidence` has a `record_key` column that is
///   a reference, not a key, and is excluded.
fn unique_key(info: &TableInfo) -> Option<Vec<&'static str>> {
    if info.kind != "table" {
        return None;
    }
    let declared: Option<&[&'static str]> = match info.table.as_str() {
        "ual_events" => Some(&["record_id"]),
        "collections" => Some(&["collection_id"]),
        "source_files" => Some(&["file_id"]),
        "collection_log" => Some(&["log_key"]),
        "case_meta" => Some(&["key"]),
        "audit_trail" => Some(&["seq"]),
        "findings" | "finding_facts" => Some(&["finding_id"]),
        "timeline_entries" => Some(&["entry_id"]),
        "annotations" => Some(&["annotation_id"]),
        "record_sources" => Some(&["table_name", "record_key", "file_id", "record_ordinal"]),
        "timeline_entry_evidence" => Some(&["entry_id", "source_table", "record_key"]),
        "account_rollup" => Some(&["tenant_key", "upn"]),
        "finding_evidence" => None,
        _ if info.columns.iter().any(|c| c.name == "record_key") => Some(&["record_key"]),
        _ => None,
    };
    declared.map(<[_]>::to_vec)
}

/// The order: the sort column (NULLs last) first, then a total order so pages never overlap or skip: the table's
/// proven-unique key, or every column as text where there is none.
fn order_by(info: &TableInfo, sort: Option<&Sort>) -> Result<String> {
    let mut keys = Vec::new();
    if let Some(s) = sort {
        let col = quote(&column(info, &s.column)?.name);
        let dir = if s.descending { "DESC" } else { "ASC" };
        keys.push(format!("{col} {dir} NULLS LAST"));
    }
    match unique_key(info) {
        Some(cols) => keys.extend(cols.into_iter().map(quote)),
        None => keys.extend(
            info.columns
                .iter()
                .map(|c| format!("CAST({} AS VARCHAR)", quote(&c.name))),
        ),
    }
    Ok(format!(" ORDER BY {}", keys.join(", ")))
}

/// `* REPLACE (...)` for the columns whose returned form differs from DuckDB's JSON: times in the core's
/// `audit::ts_text` form (UTC, microseconds, `Z`), and every JSON / structured value as JSON text.
fn replace_list(info: &TableInfo) -> String {
    let mut items = Vec::new();
    for c in &info.columns {
        let col = quote(&c.name);
        let t = c.data_type.to_ascii_uppercase();
        if t == "TIMESTAMP WITH TIME ZONE" || t == "TIMESTAMPTZ" || t == "TIMESTAMP" {
            items.push(format!(
                "strftime(CAST({col} AS TIMESTAMP), '%Y-%m-%dT%H:%M:%S.%fZ') AS {col}"
            ));
        } else if t == "JSON" {
            items.push(format!("CAST({col} AS VARCHAR) AS {col}"));
        } else if is_structured(&t) {
            items.push(format!("CAST(to_json({col}) AS VARCHAR) AS {col}"));
        }
    }
    if items.is_empty() {
        String::new()
    } else {
        format!(" REPLACE ({})", items.join(", "))
    }
}

/// One page of `table`. `limit` is capped at `MAX_PAGE`. Times come back as `YYYY-MM-DDTHH:MM:SS.ffffffZ` (UTC);
/// JSON, struct, list and map values come back as JSON text.
pub fn page(
    conn: &Connection,
    table: &str,
    filters: &[Filter],
    sort: Option<&Sort>,
    offset: usize,
    limit: usize,
) -> Result<BrowsePage> {
    let info = describe_conn(conn, Some(table))?
        .into_iter()
        .find(|t| t.table == table)
        .ok_or_else(|| Error::Invalid(format!("unknown table {table:?}")))?;
    let (wh, args) = where_clause(&info, filters)?;
    let order = order_by(&info, sort)?;
    let replace = replace_list(&info);
    let limit = limit.min(MAX_PAGE);
    let q = quote(&info.table);

    // A value that does not cast (a time that is not a time) fails here, before any row is read.
    let bad_value = |e: duckdb::Error| Error::Invalid(format!("filter on {table}: {e}"));
    let counted: u64 = conn
        .query_row(
            &format!(
                "SELECT count(*) FROM (SELECT 1 FROM {q}{wh} LIMIT {})",
                COUNT_CAP + 1
            ),
            params_from_iter(args.iter()),
            |r| r.get::<_, i64>(0),
        )
        .map_err(bad_value)? as u64;
    let total_capped = counted > COUNT_CAP;
    let total = counted.min(COUNT_CAP);

    let columns: Vec<String> = info.columns.iter().map(|c| c.name.clone()).collect();
    let mut stmt = conn.prepare(&format!(
        "SELECT CAST(to_json(u) AS VARCHAR) FROM (SELECT *{replace} FROM \
         (SELECT * FROM {q}{wh}{order} LIMIT {limit} OFFSET {offset}) s) u"
    ))?;
    let mut rows = Vec::new();
    let mut result = stmt.query(params_from_iter(args.iter()))?;
    while let Some(r) = result.next()? {
        let text: String = r.get(0)?;
        let Value::Object(mut obj) = serde_json::from_str::<Value>(&text)
            .map_err(|e| Error::Invalid(format!("row of {table} is not JSON: {e}")))?
        else {
            return Err(Error::Invalid(format!("row of {table} is not an object")));
        };
        rows.push(
            columns
                .iter()
                .map(|c| obj.remove(c).unwrap_or(Value::Null))
                .collect(),
        );
    }
    Ok(BrowsePage {
        table: info.table,
        columns,
        rows,
        offset,
        total,
        total_capped,
    })
}
