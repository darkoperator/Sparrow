//! The rule compiler (spec §8.2, Addendum C): a [`Rule`] becomes one read-only `SELECT` with named
//! parameters (`$tenant`, `$list_<name>`, `$p<N>`, `$ioc_<type>`), producing the output contract
//! `record_key, source_table, event_time, actor_upn, ip, context`.
//!
//! Choices worth knowing:
//! - **List parameters are JSON text.** `duckdb-rs` cannot bind a `LIST`, so every list (`@list:`
//!   or a literal `in` array) is bound as the JSON text of a string array and expanded in SQL by
//!   `from_json($p, '["VARCHAR"]')`. Values are never part of the SQL text.
//! - **MAP keys** (`parameters.ForwardTo`) are looked up case-insensitively with
//!   `list_filter(map_entries(col), e -> lower(e.key) = 'forwardto')`, everywhere.
//! - **CIDR** is IPv4 range arithmetic in SQL (the `inet` extension is not bundled with the
//!   pinned `duckdb` crate and extensions are not downloaded). IPv6 CIDRs are a compile error.
//! - **Text comparison** (`eq`, `in`, `contains`, ...) is case-insensitive unless the list says
//!   `case_sensitive: true`; scalars in a rule are always case-insensitive.

use crate::detect::load::ListMeta;
use crate::detect::rule::{Cond, Op, Rule, RuleBody, Threshold};
use crate::{Error, Result};
use duckdb::types::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// A compiled rule. `params` are bound by name (`tenant` and the `ioc_<type>` parameters of
/// `lists` entries `case_iocs.<type>` are added by the runner; the latter as JSON text arrays).
#[derive(Debug, Clone)]
pub struct Compiled {
    pub rule_id: String,
    /// One `SELECT` with named parameters and the six output columns.
    pub sql: String,
    pub params: Vec<(String, Value)>,
    pub tables: BTreeSet<String>,
    /// Static list names and `case_iocs.<type>` entries the rule references.
    pub lists: BTreeSet<String>,
    /// The SQL references `$tenant` (only `sql:` rules may). The runner binds it when set; the
    /// tenant scope itself is structural (see `detect::scope`), not this parameter.
    pub uses_tenant: bool,
    /// The `source_table` values the rule emits, when they can be read from the SQL (always for
    /// `match:` and `sources:` rules; the projected string constants for `sql:` rules; `None`
    /// when a `sql:` rule projects none).
    pub emitted_tables: Option<BTreeSet<String>>,
}

/// Column names and types of every table and view in a case.
#[derive(Debug, Clone, Default)]
pub struct CaseSchema {
    /// `table -> column -> duckdb type`.
    pub tables: BTreeMap<String, BTreeMap<String, String>>,
}

impl CaseSchema {
    pub fn of(conn: &duckdb::Connection) -> Result<CaseSchema> {
        let mut st = conn.prepare(
            "SELECT table_name, column_name, replace(data_type, chr(10), ' ') \
             FROM information_schema.columns WHERE table_schema = 'main' \
               AND table_catalog NOT IN ('temp', 'system') \
             ORDER BY table_name, ordinal_position",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut tables: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        for row in rows {
            let (t, c, ty) = row?;
            tables.entry(t).or_default().insert(c, ty);
        }
        Ok(CaseSchema { tables })
    }
}

/// How one evidence or state table maps to the output contract.
#[derive(Debug, Clone, Copy)]
pub struct TableOutput {
    pub table: &'static str,
    /// `record_key`, or `record_id` (UUID; the key is its lower-cased text, as the manifest keys
    /// `ual_events`).
    pub key_col: &'static str,
    /// The table's time column (its `event_time`, else the closest event time, else
    /// `collected_at`); for `via_ual` tables it is a `ual_events` column.
    pub time_col: &'static str,
    /// Used when `time_col` is NULL (the timeline view's fallbacks).
    pub time_fallback: Option<&'static str>,
    pub actor: Option<&'static str>,
    pub ip: Option<&'static str>,
    /// The table has no time or actor of its own: it joins `ual_events` on `record_id`.
    pub via_ual: bool,
    /// A `*_current` view scoped by its own `tenant_key` instead of a collection.
    pub tenant_key: bool,
}

const fn state(
    table: &'static str,
    time_col: &'static str,
    actor: Option<&'static str>,
    ip: Option<&'static str>,
) -> TableOutput {
    TableOutput {
        table,
        key_col: "record_key",
        time_col,
        time_fallback: None,
        actor,
        ip,
        via_ual: false,
        tenant_key: false,
    }
}

const fn current(table: &'static str) -> TableOutput {
    TableOutput {
        tenant_key: true,
        ..state(table, "collected_at", None, None)
    }
}

const fn side(table: &'static str) -> TableOutput {
    TableOutput {
        table,
        key_col: "record_id",
        time_col: "event_time",
        time_fallback: None,
        actor: Some("user_upn"),
        ip: Some("client_ip"),
        via_ual: true,
        tenant_key: false,
    }
}

/// Every table a rule may hit on. `mail_items_accessed` is deliberately absent (no record key of
/// its own: one UAL record fans out into many rows).
pub const OUTPUT_COLUMNS: &[TableOutput] = &[
    state(
        "admin_audit_events",
        "run_time",
        Some("caller"),
        Some("client_ip"),
    ),
    state("app_credentials", "collected_at", None, None),
    state(
        "applications",
        "collected_at",
        Some("associated_user"),
        None,
    ),
    state("audit_config", "collected_at", None, None),
    state("azure_activity", "event_time", Some("caller"), Some("ip")),
    state("ca_policies", "collected_at", None, None),
    state("devices", "collected_at", None, None),
    state(
        "directory_audits",
        "event_time",
        Some("initiated_by_upn"),
        Some("initiated_by_ip"),
    ),
    state(
        "email_artifacts",
        "collected_at",
        None,
        Some("originating_ip"),
    ),
    side("file_events"),
    state("group_members", "collected_at", Some("member_upn"), None),
    state("groups", "collected_at", None, None),
    state("inbox_rules", "collected_at", Some("mailbox_upn"), None),
    state("licenses", "collected_at", None, None),
    state(
        "mailbox_audit_legacy",
        "event_time",
        Some("mailbox_upn"),
        Some("client_ip"),
    ),
    state(
        "mailbox_permissions",
        "collected_at",
        Some("mailbox_upn"),
        None,
    ),
    state("mailboxes", "collected_at", Some("upn"), None),
    state("message_trace", "received", Some("sender"), Some("from_ip")),
    state("mfa_registration", "collected_at", Some("upn"), None),
    state("mobile_devices", "collected_at", Some("mailbox"), None),
    state("oauth_grants", "collected_at", Some("principal_upn"), None),
    state("remote_domains", "collected_at", None, None),
    current("remote_domains_current"),
    TableOutput {
        time_fallback: Some("detected_time"),
        ..state(
            "risk_detections",
            "activity_time",
            Some("user_upn"),
            Some("ip"),
        )
    },
    state("risky_users", "collected_at", Some("upn"), None),
    state(
        "role_assignments",
        "collected_at",
        Some("principal_upn"),
        None,
    ),
    side("search_queries"),
    state("secure_score", "collected_at", None, None),
    TableOutput {
        time_fallback: Some("created_time"),
        ..state("security_alerts", "event_time", None, None)
    },
    side("sharing_events"),
    state("signins", "event_time", Some("user_upn"), Some("ip")),
    state("tenant_settings", "collected_at", None, None),
    state("transport_rules", "collected_at", None, None),
    current("transport_rules_current"),
    TableOutput {
        table: "ual_events",
        key_col: "record_id",
        time_col: "event_time",
        time_fallback: None,
        actor: Some("user_upn"),
        ip: Some("client_ip"),
        via_ual: false,
        tenant_key: false,
    },
    state("user_licenses", "collected_at", Some("upn"), None),
    state("users", "collected_at", Some("upn"), None),
];

/// The output columns of every compiled rule, in order.
pub const OUTPUT_FIELDS: &[&str] = &[
    "record_key",
    "source_table",
    "event_time",
    "actor_upn",
    "ip",
    "context",
];

pub fn compile(
    rule: &Rule,
    lists: &BTreeMap<String, Vec<String>>,
    schema: &CaseSchema,
) -> Result<Compiled> {
    compile_with_meta(rule, lists, &BTreeMap::new(), schema)
}

/// [`compile`] with per-list metadata (`case_sensitive`); lists without an entry compare
/// case-insensitively.
pub fn compile_with_meta(
    rule: &Rule,
    lists: &BTreeMap<String, Vec<String>>,
    meta: &BTreeMap<String, ListMeta>,
    schema: &CaseSchema,
) -> Result<Compiled> {
    build(rule, lists, meta, schema).map_err(|e| match e {
        Error::Invalid(m) => Error::Invalid(format!("{}: {m}", rule.id)),
        other => other,
    })
}

fn build(
    rule: &Rule,
    lists: &BTreeMap<String, Vec<String>>,
    meta: &BTreeMap<String, ListMeta>,
    schema: &CaseSchema,
) -> Result<Compiled> {
    let mut cx = Cx {
        lists,
        meta,
        params: Vec::new(),
        used_lists: BTreeSet::new(),
        counter: 0,
    };
    let mut tables = BTreeSet::new();
    let mut uses_tenant = false;
    let emitted: Option<BTreeSet<String>>;
    let base = match &rule.body {
        RuleBody::Match { source, m } => {
            tables.insert(source.clone());
            emitted = Some(BTreeSet::from([source.clone()]));
            hit_select(&mut cx, schema, source, m)?
        }
        RuleBody::Sources { sources } => {
            if sources.is_empty() {
                return bad("sources must not be empty");
            }
            let mut parts = Vec::new();
            emitted = Some(sources.iter().map(|s| s.source.clone()).collect());
            for s in sources {
                tables.insert(s.source.clone());
                parts.push(hit_select(&mut cx, schema, &s.source, &s.m)?);
            }
            parts.join("\nUNION ALL\n")
        }
        RuleBody::Sql { sql } => {
            let sel = sql_select(&mut cx, schema, sql, &mut tables)?;
            uses_tenant = sel.uses_tenant;
            emitted = sel.emitted;
            sel.sql
        }
    };
    let base = match &rule.threshold {
        Some(th) => threshold_sql(&base, th)?,
        None => base,
    };
    let sql = format!("SELECT * FROM ({base}) ORDER BY event_time, record_key, source_table");
    Ok(Compiled {
        rule_id: rule.id.clone(),
        sql,
        params: cx.params,
        tables,
        lists: cx.used_lists,
        uses_tenant,
        emitted_tables: emitted,
    })
}

fn bad<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Invalid(msg.into()))
}

// ---------------------------------------------------------------------------------------------
// Match rules

struct Cx<'a> {
    lists: &'a BTreeMap<String, Vec<String>>,
    meta: &'a BTreeMap<String, ListMeta>,
    params: Vec<(String, Value)>,
    used_lists: BTreeSet<String>,
    counter: usize,
}

impl Cx<'_> {
    fn param(&mut self, v: Value) -> String {
        let name = format!("p{}", self.counter);
        self.counter += 1;
        self.params.push((name.clone(), v));
        format!("${name}")
    }

    fn text(&mut self, s: &str) -> String {
        self.param(Value::Text(s.to_string()))
    }
}

/// A `VARCHAR[]` operand: a static list, a case indicator list, or a literal array.
struct ListOperand {
    /// SQL expression of type `VARCHAR[]` (values unchanged).
    expr: String,
    /// Compare exactly (a list that sets `case_sensitive: true`).
    case_sensitive: bool,
}

impl ListOperand {
    /// The list as compared: lower-cased unless case-sensitive.
    fn compared(&self) -> String {
        if self.case_sensitive {
            self.expr.clone()
        } else {
            format!("list_transform({}, lv -> lower(lv))", self.expr)
        }
    }
}

const JSON_LIST: &str = r#"'["VARCHAR"]'"#;

fn scalar_string(v: &serde_json::Value, what: &str) -> Result<String> {
    match v {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        _ => bad(format!("{what}: expected a scalar value")),
    }
}

fn list_param_name(name: &str) -> Result<String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return bad(format!("list name {name:?} must be letters, digits and _"));
    }
    Ok(format!("list_{name}"))
}

fn resolve_list_ref(cx: &mut Cx, name: &str) -> Result<ListOperand> {
    if let Some(ty) = name.strip_prefix("case_iocs.") {
        if ty.is_empty() || !ty.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return bad(format!("bad case indicator list @list:{name}"));
        }
        cx.used_lists.insert(name.to_string());
        return Ok(ListOperand {
            expr: format!("from_json($ioc_{ty}, {JSON_LIST})"),
            case_sensitive: false,
        });
    }
    let Some(values) = cx.lists.get(name) else {
        return bad(format!("unknown list @list:{name}"));
    };
    let param = list_param_name(name)?;
    cx.used_lists.insert(name.to_string());
    if !cx.params.iter().any(|(k, _)| *k == param) {
        cx.params.push((
            param.clone(),
            Value::Text(serde_json::to_string(values).expect("strings serialize")),
        ));
    }
    Ok(ListOperand {
        expr: format!("from_json(${param}, {JSON_LIST})"),
        case_sensitive: cx.meta.get(name).is_some_and(|m| m.case_sensitive),
    })
}

fn resolve_list(cx: &mut Cx, v: &serde_json::Value, what: &str) -> Result<ListOperand> {
    match v {
        serde_json::Value::String(s) if s.starts_with("@list:") => {
            resolve_list_ref(cx, &s["@list:".len()..])
        }
        serde_json::Value::Array(items) => {
            let values = items
                .iter()
                .map(|i| scalar_string(i, what))
                .collect::<Result<Vec<_>>>()?;
            let p = cx.param(Value::Text(
                serde_json::to_string(&values).expect("strings serialize"),
            ));
            Ok(ListOperand {
                expr: format!("from_json({p}, {JSON_LIST})"),
                case_sensitive: false,
            })
        }
        _ => bad(format!("{what}: expected a list or @list:<name>")),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Text,
    List,
    Bool,
    Num,
    Ts,
}

struct Field {
    /// SQL expression: a `VARCHAR` for `Text`, the native type otherwise.
    expr: String,
    kind: Kind,
}

impl Field {
    /// The value as `VARCHAR` (a `List` has no scalar form).
    fn as_text(&self) -> String {
        match self.kind {
            Kind::Text => self.expr.clone(),
            _ => format!("CAST({} AS VARCHAR)", self.expr),
        }
    }
}

fn kind_of(ty: &str) -> Option<Kind> {
    match ty {
        "VARCHAR" | "UUID" | "JSON" => Some(Kind::Text),
        t if t.starts_with("ENUM(") => Some(Kind::Text),
        "BOOLEAN" => Some(Kind::Bool),
        "TIMESTAMP WITH TIME ZONE" | "TIMESTAMP" | "DATE" => Some(Kind::Ts),
        "TINYINT" | "SMALLINT" | "INTEGER" | "BIGINT" | "HUGEINT" | "DOUBLE" | "FLOAT" => {
            Some(Kind::Num)
        }
        "VARCHAR[]" => Some(Kind::List),
        _ => None,
    }
}

/// Split `a B, c STRUCT(d E, f G)` at top-level commas.
fn split_top(s: &str) -> Vec<&str> {
    let (mut out, mut depth, mut start) = (Vec::new(), 0i32, 0usize);
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(s[start..].trim());
    out
}

fn safe_path(p: &str) -> bool {
    !p.is_empty()
        && p.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '$' | '[' | ']' | ' ')
        })
}

/// The tables a match arm can read: its own, and `ual_events` for side tables.
struct Resolver<'a> {
    table: &'a str,
    t: &'a BTreeMap<String, String>,
    u: Option<&'a BTreeMap<String, String>>,
}

impl Resolver<'_> {
    fn field(&self, path: &str) -> Result<Field> {
        let (col, rest) = match path.split_once('.') {
            Some((c, r)) => (c, Some(r)),
            None => (path, None),
        };
        let (alias, ty) = if let Some(ty) = self.t.get(col) {
            ("t", ty)
        } else if let Some(ty) = self.u.and_then(|u| u.get(col)) {
            ("u", ty)
        } else {
            return bad(format!(
                "unknown column {col:?} in table {:?} (field {path:?})",
                self.table
            ));
        };
        let colref = format!("{alias}.{col}");
        if let Some(inner) = ty.strip_prefix("MAP(") {
            let _ = inner;
            let Some(key) = rest else {
                return bad(format!(
                    "field {path:?}: a MAP column needs a key ({col}.<Key>)"
                ));
            };
            if !safe_path(key) {
                return bad(format!(
                    "field {path:?}: unsupported characters in the MAP key"
                ));
            }
            let key = key.to_lowercase().replace('\'', "''");
            return Ok(Field {
                expr: format!(
                    "list_extract(list_transform(list_filter(map_entries({colref}), e -> lower(e.key) = '{key}'), e -> e.value), 1)"
                ),
                kind: Kind::Text,
            });
        }
        if let Some(inner) = ty.strip_prefix("STRUCT(").and_then(|s| s.strip_suffix(')')) {
            let Some(name) = rest else {
                return bad(format!(
                    "field {path:?}: a STRUCT column needs a member ({col}.<member>)"
                ));
            };
            let member = split_top(inner).into_iter().find_map(|m| {
                let (n, t) = m.split_once(' ')?;
                (n.trim_matches('"') == name).then(|| t.trim().to_string())
            });
            let Some(mty) = member else {
                return bad(format!("unknown member {name:?} of STRUCT column {col:?}"));
            };
            let Some(kind) = kind_of(&mty) else {
                return bad(format!("field {path:?}: unsupported member type {mty}"));
            };
            return Ok(Field {
                expr: format!("struct_extract({colref}, '{name}')"),
                kind,
            });
        }
        if ty == "JSON" {
            return Ok(match rest {
                None => Field {
                    expr: format!("CAST({colref} AS VARCHAR)"),
                    kind: Kind::Text,
                },
                Some(p) => {
                    if !safe_path(p) {
                        return bad(format!(
                            "field {path:?}: unsupported characters in the JSON path"
                        ));
                    }
                    let p = if p.starts_with('$') {
                        p.to_string()
                    } else {
                        format!("$.{p}")
                    };
                    Field {
                        expr: format!("json_extract_string({colref}, '{p}')"),
                        kind: Kind::Text,
                    }
                }
            });
        }
        if rest.is_some() {
            return bad(format!(
                "field {path:?}: column {col:?} ({ty}) has no members"
            ));
        }
        let Some(kind) = kind_of(ty) else {
            return bad(format!("field {path:?}: unsupported column type {ty}"));
        };
        let expr = match ty.as_str() {
            "VARCHAR" | "VARCHAR[]" => colref,
            t if kind == Kind::Text && t != "VARCHAR" => format!("CAST({colref} AS VARCHAR)"),
            _ => colref,
        };
        Ok(Field { expr, kind })
    }
}

fn hit_select(cx: &mut Cx, schema: &CaseSchema, source: &str, m: &Cond) -> Result<String> {
    let Some(out) = OUTPUT_COLUMNS.iter().find(|o| o.table == source) else {
        return if source == "mail_items_accessed" {
            bad(
                "mail_items_accessed cannot be a hit table (it has no record key; hit ual_events instead)",
            )
        } else if schema.tables.contains_key(source) {
            bad(format!("table {source:?} cannot be a hit table"))
        } else {
            bad(format!("unknown table {source:?}"))
        };
    };
    let Some(t) = schema.tables.get(source) else {
        return bad(format!("unknown table {source:?}"));
    };
    let u = if out.via_ual {
        Some(&schema.tables["ual_events"])
    } else {
        None
    };
    let res = Resolver {
        table: source,
        t,
        u,
    };
    let cond = cond_sql(cx, &res, m)?;

    let key = if out.key_col == "record_id" {
        "lower(CAST(t.record_id AS VARCHAR))".to_string()
    } else {
        format!("t.{}", out.key_col)
    };
    let owner = if out.via_ual { "u" } else { "t" };
    let time = match out.time_fallback {
        Some(fb) => format!("coalesce({owner}.{}, {owner}.{fb})", out.time_col),
        None => format!("{owner}.{}", out.time_col),
    };
    let actor = out.actor.map_or("CAST(NULL AS VARCHAR)".to_string(), |c| {
        format!("{owner}.{c}")
    });
    let ip = out.ip.map_or("CAST(NULL AS VARCHAR)".to_string(), |c| {
        format!("{owner}.{c}")
    });
    // No tenant predicate: the tenant scope is structural (`detect::scope` shadows every
    // tenant-aware table with a view of the tenant's rows on the rule connection).
    let from = if out.via_ual {
        format!("{source} t JOIN ual_events u ON u.record_id = t.record_id")
    } else {
        format!("{source} t")
    };
    Ok(format!(
        "SELECT {key} AS record_key, '{source}' AS source_table, {time} AS event_time, {actor} AS actor_upn, {ip} AS ip, CAST(NULL AS JSON) AS context\nFROM {from}\nWHERE COALESCE(({cond}), false)"
    ))
}

fn cond_sql(cx: &mut Cx, res: &Resolver, c: &Cond) -> Result<String> {
    match c {
        Cond::All { all } => {
            if all.is_empty() {
                return bad("all: must not be empty");
            }
            let parts = all
                .iter()
                .map(|c| cond_sql(cx, res, c))
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("({})", parts.join(" AND ")))
        }
        Cond::Any { any } => {
            if any.is_empty() {
                return bad("any: must not be empty");
            }
            let parts = any
                .iter()
                .map(|c| cond_sql(cx, res, c))
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("({})", parts.join(" OR ")))
        }
        Cond::Not { not } => Ok(format!("(NOT {})", cond_sql(cx, res, not)?)),
        Cond::Leaf(map) => {
            let (field, ops) = map
                .iter()
                .next()
                .ok_or_else(|| Error::Invalid("empty leaf".into()))?;
            let (op, value) = ops
                .iter()
                .next()
                .ok_or_else(|| Error::Invalid("empty leaf".into()))?;
            leaf_sql(cx, res, field, *op, value)
        }
    }
}

fn leaf_sql(
    cx: &mut Cx,
    res: &Resolver,
    path: &str,
    op: Op,
    v: &serde_json::Value,
) -> Result<String> {
    let f = res.field(path)?;
    let inner = match op {
        // Three-valued: a missing value makes the leaf NULL (no match); use `exists: false`.
        Op::Neq => format!("NOT ({})", leaf_positive(cx, &f, path, Op::Eq, v)?),
        Op::Exists => exists_sql(&f, path, v)?,
        Op::EqField | Op::NeqField => {
            let other = scalar_string(v, &format!("{path}.{op:?}"))?;
            let g = res.field(&other)?;
            if f.kind == Kind::List || g.kind == Kind::List {
                return bad(format!("{path}: eq_field/neq_field compare scalar columns"));
            }
            let (a, b) = (
                format!("lower({})", f.as_text()),
                format!("lower({})", g.as_text()),
            );
            if op == Op::EqField {
                format!("{a} = {b}")
            } else {
                format!("{a} <> {b}")
            }
        }
        Op::Gt | Op::Gte | Op::Lt | Op::Lte => compare_sql(cx, &f, path, op, v)?,
        _ => leaf_positive(cx, &f, path, op, v)?,
    };
    Ok(format!("({inner})"))
}

fn exists_sql(f: &Field, path: &str, v: &serde_json::Value) -> Result<String> {
    let want = match v {
        serde_json::Value::Bool(b) => *b,
        _ => return bad(format!("{path}: exists takes true or false")),
    };
    let e = &f.expr;
    // `exists` is the explicit test for absence, so it is two-valued.
    let present = match f.kind {
        Kind::Text => format!("({e} IS NOT NULL AND {e} <> '')"),
        Kind::List => {
            format!("COALESCE(len(list_filter({e}, x -> x IS NOT NULL AND x <> '')) > 0, false)")
        }
        _ => format!("{e} IS NOT NULL"),
    };
    Ok(if want {
        present
    } else {
        format!("NOT ({present})")
    })
}

fn compare_sql(
    cx: &mut Cx,
    f: &Field,
    path: &str,
    op: Op,
    v: &serde_json::Value,
) -> Result<String> {
    let sym = match op {
        Op::Gt => ">",
        Op::Gte => ">=",
        Op::Lt => "<",
        _ => "<=",
    };
    match f.kind {
        Kind::Ts => {
            let s = scalar_string(v, path)?;
            if chrono::DateTime::parse_from_rfc3339(&s).is_err()
                && chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").is_err()
            {
                return bad(format!(
                    "{path}: {s:?} is not an RFC 3339 timestamp or a date"
                ));
            }
            let p = cx.text(&s);
            Ok(format!("{} {sym} CAST({p} AS TIMESTAMPTZ)", f.expr))
        }
        Kind::Num | Kind::Text => {
            let n = match v {
                serde_json::Value::Number(n) => n.as_f64(),
                serde_json::Value::String(s) => s.trim().parse::<f64>().ok(),
                _ => None,
            };
            let Some(n) = n else {
                return bad(format!("{path}: {op:?} needs a number for this column"));
            };
            let p = cx.param(Value::Double(n));
            Ok(if f.kind == Kind::Num {
                format!("{} {sym} {p}", f.expr)
            } else {
                format!("TRY_CAST({} AS DOUBLE) {sym} {p}", f.expr)
            })
        }
        _ => bad(format!("{path}: {op:?} does not apply to this column type")),
    }
}

/// `eq`, `in`, `contains`, `contains_any`, `startswith`, `endswith`, `regex`, `cidr`.
fn leaf_positive(
    cx: &mut Cx,
    f: &Field,
    path: &str,
    op: Op,
    v: &serde_json::Value,
) -> Result<String> {
    // Typed equality for numbers and timestamps.
    if op == Op::Eq && matches!(f.kind, Kind::Num | Kind::Ts) {
        let s = scalar_string(v, path)?;
        let p = cx.text(&s);
        let ty = if f.kind == Kind::Num {
            "DOUBLE"
        } else {
            "TIMESTAMPTZ"
        };
        return Ok(format!("{} = CAST({p} AS {ty})", f.expr));
    }
    if f.kind == Kind::List {
        let pred = text_pred(cx, "e", path, op, v)?;
        return Ok(format!("len(list_filter({}, e -> {pred})) > 0", f.expr));
    }
    text_pred(cx, &f.as_text(), path, op, v)
}

/// A boolean over the `VARCHAR` expression `x`.
fn text_pred(cx: &mut Cx, x: &str, path: &str, op: Op, v: &serde_json::Value) -> Result<String> {
    let scalar = |cx: &mut Cx| -> Result<String> {
        let s = scalar_string(v, path)?;
        if let Some(name) = s.strip_prefix("@list:") {
            return bad(format!(
                "{path}: {op:?} takes one value, not @list:{name} (use `in` or `contains_any`)"
            ));
        }
        if s.is_empty() && matches!(op, Op::Contains | Op::Startswith | Op::Endswith) {
            return bad(format!(
                "{path}: {op:?} with an empty value would match every row"
            ));
        }
        Ok(cx.text(&s))
    };
    Ok(match op {
        Op::Eq => {
            let p = scalar(cx)?;
            format!("lower({x}) = lower({p})")
        }
        Op::Contains => {
            let p = scalar(cx)?;
            format!("strpos(lower({x}), lower({p})) > 0")
        }
        Op::Startswith => {
            let p = scalar(cx)?;
            format!("starts_with(lower({x}), lower({p}))")
        }
        Op::Endswith => {
            let p = scalar(cx)?;
            format!("ends_with(lower({x}), lower({p}))")
        }
        Op::Regex => {
            let s = scalar_string(v, path)?;
            if let Err(e) = regex::Regex::new(&s) {
                return bad(format!("{path}: regex {s:?} does not compile: {e}"));
            }
            let p = cx.text(&s);
            format!("regexp_matches({x}, {p})")
        }
        Op::In => {
            let l = resolve_list(cx, v, path)?;
            let needle = if l.case_sensitive {
                x.to_string()
            } else {
                format!("lower({x})")
            };
            format!("list_contains({}, {needle})", l.compared())
        }
        Op::ContainsAny => {
            let l = resolve_list(cx, v, path)?;
            let hay = if l.case_sensitive {
                x.to_string()
            } else {
                format!("lower({x})")
            };
            format!(
                "len(list_filter({}, cv -> cv <> '' AND strpos({hay}, cv) > 0)) > 0",
                l.compared()
            )
        }
        Op::Cidr => cidr_pred(cx, x, path, v)?,
        _ => return bad(format!("{path}: operator {op:?} is not a text operator")),
    })
}

fn cidr_pred(cx: &mut Cx, x: &str, path: &str, v: &serde_json::Value) -> Result<String> {
    // The ranges are computed here, so no list parameter is bound.
    let raw: Vec<String> = match v {
        serde_json::Value::String(s) if !s.starts_with("@list:") => vec![s.clone()],
        serde_json::Value::String(s) => {
            let name = &s["@list:".len()..];
            let Some(values) = cx.lists.get(name) else {
                return bad(format!(
                    "{path}: cidr needs literal or static list values (@list:{name})"
                ));
            };
            cx.used_lists.insert(name.to_string());
            values.clone()
        }
        serde_json::Value::Array(items) => items
            .iter()
            .map(|i| scalar_string(i, path))
            .collect::<Result<Vec<_>>>()?,
        _ => {
            return bad(format!(
                "{path}: cidr takes a range, a list of ranges or @list:<name>"
            ));
        }
    };
    if raw.is_empty() {
        return bad(format!("{path}: cidr list is empty"));
    }
    let mut ranges = Vec::new();
    for s in &raw {
        let net: ipnet::IpNet = match s.parse() {
            Ok(n) => n,
            Err(_) => match s.parse::<std::net::IpAddr>() {
                Ok(a) => ipnet::IpNet::from(a),
                Err(_) => return bad(format!("{path}: {s:?} is not a CIDR range or IP address")),
            },
        };
        let ipnet::IpNet::V4(n) = net else {
            return bad(format!(
                "{path}: IPv6 CIDR {s:?} is not supported (the inet extension is not bundled)"
            ));
        };
        ranges.push((u32::from(n.network()), u32::from(n.broadcast())));
    }
    // Normalise to a dotted quad: `[v6]:port` brackets, an IPv4-mapped `::ffff:` prefix and an
    // `:port` suffix are stripped; anything that is not four octets 0..=255 yields NULL (no
    // match, never a different address).
    let h = format!("lower(trim({x}))");
    let unbracketed = format!(
        "(CASE WHEN starts_with({h}, '[') THEN split_part(substr({h}, 2), ']', 1) ELSE {h} END)"
    );
    let unmapped = format!(
        "(CASE WHEN starts_with({unbracketed}, '::ffff:') THEN substr({unbracketed}, 8) ELSE {unbracketed} END)"
    );
    let base = format!("split_part({unmapped}, ':', 1)");
    let octet = |i: u8| format!("TRY_CAST(split_part({base}, '.', {i}) AS BIGINT)");
    let valid = format!(
        "regexp_full_match({base}, '[0-9]{{1,3}}(\\.[0-9]{{1,3}}){{3}}') AND {} <= 255 AND {} <= 255 AND {} <= 255 AND {} <= 255",
        octet(1),
        octet(2),
        octet(3),
        octet(4)
    );
    let ip = format!(
        "(CASE WHEN {valid} THEN {} * 16777216 + {} * 65536 + {} * 256 + {} END)",
        octet(1),
        octet(2),
        octet(3),
        octet(4)
    );
    let alts: Vec<String> = ranges
        .iter()
        .map(|(lo, hi)| format!("{ip} BETWEEN {lo} AND {hi}"))
        .collect();
    Ok(format!("({})", alts.join(" OR ")))
}

// ---------------------------------------------------------------------------------------------
// Threshold

fn threshold_sql(base: &str, th: &Threshold) -> Result<String> {
    for g in &th.group_by {
        if !OUTPUT_FIELDS[..5].contains(&g.as_str()) {
            return bad(format!(
                "threshold group_by {g:?} is not an output column ({})",
                OUTPUT_FIELDS[..5].join(", ")
            ));
        }
    }
    let w = th.window.trim();
    let (num, unit) = w.split_at(w.len().saturating_sub(1));
    let n: u32 = num
        .parse()
        .map_err(|_| Error::Invalid(format!("threshold window {w:?}: expected 10m, 1h or 1d")))?;
    let unit = match unit {
        "m" => 60u64,
        "h" => 3600,
        "d" => 86_400,
        _ => return bad(format!("threshold window {w:?}: expected 10m, 1h or 1d")),
    };
    // Epoch milliseconds: TIMESTAMPTZ arithmetic and `epoch()` need the ICU extension, which a
    // locked rule connection cannot autoload. `epoch_ms` is built in.
    let secs = u64::from(n) * unit * 1000;
    let count = th.count.trim();
    let (cmp, rest) = if let Some(r) = count.strip_prefix(">=") {
        (">=", r)
    } else if let Some(r) = count.strip_prefix('>') {
        (">", r)
    } else if let Some(r) = count.strip_prefix('=') {
        ("=", r)
    } else {
        return bad(format!(
            "threshold count {count:?}: expected \">= N\", \"> N\" or \"= N\""
        ));
    };
    let n: u64 = rest
        .trim()
        .parse()
        .map_err(|_| Error::Invalid(format!("threshold count {count:?}: not a number")))?;
    let partition = if th.group_by.is_empty() {
        String::new()
    } else {
        format!("PARTITION BY {} ", th.group_by.join(", "))
    };
    let same = if th.group_by.is_empty() {
        "true".to_string()
    } else {
        th.group_by
            .iter()
            .map(|g| format!("q.{g} IS NOT DISTINCT FROM b.{g}"))
            .collect::<Vec<_>>()
            .join(" AND ")
    };
    Ok(format!(
        "WITH base AS ({base}),\n\
         w AS (SELECT *, count(*) OVER ({partition}ORDER BY epoch_ms(event_time) RANGE BETWEEN {secs} PRECEDING AND CURRENT ROW) AS n FROM base),\n\
         q AS (SELECT * FROM w WHERE n {cmp} {n})\n\
         SELECT b.record_key, b.source_table, b.event_time, b.actor_upn, b.ip, b.context FROM base b\n\
         WHERE EXISTS (SELECT 1 FROM q WHERE {same} AND epoch_ms(b.event_time) <= epoch_ms(q.event_time) AND epoch_ms(b.event_time) >= epoch_ms(q.event_time) - {secs})"
    ))
}

// ---------------------------------------------------------------------------------------------
// sql: rules

fn list_token() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"@list:([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)").unwrap()
    })
}

fn param_token() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]*)").unwrap())
}

/// Table functions a rule may call in `FROM`: none reads files or the catalog by name.
const ALLOWED_TABLE_FUNCTIONS: &[&str] = &[
    "unnest",
    "generate_series",
    "range",
    "json_each",
    "json_tree",
];

/// Reject what would let a `sql:` rule escape the tenant scope or the file sandbox:
/// schema/catalog-qualified tables (the base tables sit behind the tenant views), tables the
/// scope does not cover, and table functions outside the allow-list (`read_csv`, `glob`,
/// `query_table`, `duckdb_tables`, ...). Collects the case tables the rule reads.
fn check_ast(v: &serde_json::Value, schema: &CaseSchema, out: &mut BTreeSet<String>) -> Result<()> {
    match v {
        serde_json::Value::Object(o) => {
            match o.get("type").and_then(|t| t.as_str()) {
                Some("BASE_TABLE") => {
                    let name = o.get("table_name").and_then(|n| n.as_str()).unwrap_or("");
                    for key in ["schema_name", "catalog_name"] {
                        let q = o.get(key).and_then(|n| n.as_str()).unwrap_or("");
                        if !q.is_empty() {
                            return bad(format!(
                                "schema-qualified reference to {q}.{name}: use the plain table name (the tenant scope replaces it)"
                            ));
                        }
                    }
                    if schema.tables.contains_key(name) {
                        if !crate::detect::scope::readable(schema, name) {
                            return bad(format!(
                                "table {name:?} cannot be read by a rule (it has no tenant scope)"
                            ));
                        }
                        out.insert(name.to_string());
                    }
                }
                Some("TABLE_FUNCTION") => {
                    let f = v
                        .pointer("/function/function_name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("?");
                    if !ALLOWED_TABLE_FUNCTIONS.contains(&f.to_lowercase().as_str()) {
                        return bad(format!(
                            "table function {f} is not allowed in a rule (allowed: {})",
                            ALLOWED_TABLE_FUNCTIONS.join(", ")
                        ));
                    }
                }
                _ => {}
            }
            for x in o.values() {
                check_ast(x, schema, out)?;
            }
        }
        serde_json::Value::Array(a) => {
            for x in a {
                check_ast(x, schema, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// The `source_table` strings a `sql:` rule projects: the select-list position aliased
/// `source_table` in any SELECT, read as a string constant in every SELECT of the statement
/// (later `UNION` arms are often unaliased). `None` when no constant is found.
fn emitted_source_tables(ast: &serde_json::Value) -> Option<BTreeSet<String>> {
    fn selects<'a>(v: &'a serde_json::Value, out: &mut Vec<&'a Vec<serde_json::Value>>) {
        match v {
            serde_json::Value::Object(o) => {
                if o.get("type").and_then(|t| t.as_str()) == Some("SELECT_NODE") {
                    if let Some(l) = o.get("select_list").and_then(|l| l.as_array()) {
                        out.push(l);
                    }
                }
                o.values().for_each(|x| selects(x, out));
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| selects(x, out)),
            _ => {}
        }
    }
    let mut lists = Vec::new();
    selects(ast, &mut lists);
    let pos = lists.iter().find_map(|l| {
        l.iter()
            .position(|i| i.get("alias").and_then(|a| a.as_str()) == Some("source_table"))
    })?;
    let out: BTreeSet<String> = lists
        .iter()
        .filter_map(|l| l.get(pos))
        .filter(|i| i.get("class").and_then(|c| c.as_str()) == Some("CONSTANT"))
        .filter_map(|i| i.pointer("/value/value").and_then(|v| v.as_str()))
        .map(String::from)
        .collect();
    (!out.is_empty()).then_some(out)
}

/// An empty in-memory database with the case's tables (views included, as tables) to check a
/// `sql:` rule's shape without touching the case.
fn scratch(schema: &CaseSchema) -> Result<duckdb::Connection> {
    let conn = duckdb::Connection::open_in_memory()?;
    for (table, cols) in &schema.tables {
        let defs: Vec<String> = cols.iter().map(|(c, ty)| format!("\"{c}\" {ty}")).collect();
        conn.execute_batch(&format!("CREATE TABLE \"{table}\" ({})", defs.join(", ")))
            .map_err(|e| Error::Invalid(format!("scratch table {table}: {e}")))?;
    }
    // Validation must not read files either.
    crate::detect::scope::lock_down(&conn)?;
    Ok(conn)
}

fn sql_select(
    cx: &mut Cx,
    schema: &CaseSchema,
    sql: &str,
    tables: &mut BTreeSet<String>,
) -> Result<SqlSel> {
    let uses_tenant = regex::Regex::new(r"\$tenant\b").unwrap().is_match(sql);
    // @list:name -> from_json($list_name, ...) / @list:case_iocs.t -> from_json($ioc_t, ...)
    let mut failure = None;
    let mut expanded = String::new();
    let mut last = 0;
    for m in list_token().captures_iter(sql) {
        let whole = m.get(0).expect("group 0");
        expanded.push_str(&sql[last..whole.start()]);
        match resolve_list_ref(cx, &m[1]) {
            Ok(l) => expanded.push_str(&l.expr),
            Err(e) => failure = Some(e),
        }
        last = whole.end();
    }
    if let Some(e) = failure {
        return Err(e);
    }
    expanded.push_str(&sql[last..]);

    let conn = scratch(schema)?;
    let quoted = expanded.replace('\'', "''");
    let ser: String =
        conn.query_row(&format!("SELECT json_serialize_sql('{quoted}')"), [], |r| {
            r.get(0)
        })?;
    let ast: serde_json::Value =
        serde_json::from_str(&ser).map_err(|e| Error::Invalid(e.to_string()))?;
    if ast["error"].as_bool() == Some(true) {
        return bad(format!(
            "sql rule is not a SELECT statement or does not parse: {}",
            ast["error_message"].as_str().unwrap_or("?")
        ));
    }
    if ast["statements"].as_array().map_or(0, Vec::len) != 1 {
        return bad("sql rule must be a single statement");
    }
    let mut found = BTreeSet::new();
    check_ast(&ast, schema, &mut found)?;
    tables.extend(found.into_iter().filter(|t| schema.tables.contains_key(t)));
    let emitted = emitted_source_tables(&ast);

    // Bind every parameter the text uses so DuckDB can type it.
    let mut bound: Vec<(String, Value)> = Vec::new();
    for m in param_token().captures_iter(&expanded) {
        let name = m[1].to_string();
        if bound.iter().any(|(k, _)| *k == name) {
            continue;
        }
        let v = if name == "tenant" {
            Value::Text("x".into())
        } else if name.starts_with("ioc_") {
            Value::Text("[]".into())
        } else if let Some((_, v)) = cx.params.iter().find(|(k, _)| *k == name) {
            v.clone()
        } else {
            return bad(format!(
                "unknown parameter ${name} (only $tenant and @list:<name> are available)"
            ));
        };
        bound.push((name, v));
    }
    let refs: Vec<(&str, &dyn duckdb::ToSql)> = bound
        .iter()
        .map(|(k, v)| (k.as_str(), v as &dyn duckdb::ToSql))
        .collect();
    let mut st = conn.prepare(&format!("DESCRIBE SELECT * FROM ({expanded}) AS probe"))?;
    let cols: BTreeMap<String, String> = st
        .query_map(refs.as_slice(), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .map_err(|e| Error::Invalid(format!("sql rule does not bind: {e}")))?
        .collect::<std::result::Result<_, _>>()?;
    for (name, ty) in [
        ("record_key", "VARCHAR"),
        ("source_table", "VARCHAR"),
        ("event_time", "TIMESTAMP WITH TIME ZONE"),
    ] {
        match cols.get(name) {
            None => return bad(format!("sql rule must project {name} ({ty})")),
            Some(found) if found != ty => {
                return bad(format!(
                    "sql rule column {name} must be {ty}, found {found}"
                ));
            }
            _ => {}
        }
    }
    let optional = |name: &str, ty: &str| -> Result<String> {
        match cols.get(name) {
            None => Ok(format!("CAST(NULL AS {ty})")),
            Some(found) if found == ty => Ok(name.to_string()),
            Some(found) => bad(format!(
                "sql rule column {name} must be {ty}, found {found}"
            )),
        }
    };
    Ok(SqlSel {
        sql: format!(
            "SELECT record_key, source_table, event_time, {} AS actor_upn, {} AS ip, {} AS context FROM ({expanded}) AS s",
            optional("actor_upn", "VARCHAR")?,
            optional("ip", "VARCHAR")?,
            optional("context", "JSON")?,
        ),
        uses_tenant,
        emitted,
    })
}

struct SqlSel {
    sql: String,
    uses_tenant: bool,
    emitted: Option<BTreeSet<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_columns_name_real_columns() {
        let case = crate::Case::in_memory().unwrap();
        let schema = CaseSchema::of(case.conn()).unwrap();
        let mut seen = BTreeSet::new();
        for o in OUTPUT_COLUMNS {
            assert!(seen.insert(o.table), "duplicate {}", o.table);
            let own = &schema.tables[o.table];
            let other = if o.via_ual {
                &schema.tables["ual_events"]
            } else {
                own
            };
            assert!(own.contains_key(o.key_col), "{} {}", o.table, o.key_col);
            assert!(
                own.contains_key("collection_id") || o.tenant_key,
                "{}",
                o.table
            );
            assert!(other.contains_key(o.time_col), "{} {}", o.table, o.time_col);
            if let Some(fb) = o.time_fallback {
                assert!(other.contains_key(fb), "{} {fb}", o.table);
            }
            for c in o.actor.into_iter().chain(o.ip) {
                assert!(other.contains_key(c), "{} {c}", o.table);
            }
            if o.tenant_key {
                assert!(own.contains_key("tenant_key"), "{}", o.table);
            }
        }
    }
}
