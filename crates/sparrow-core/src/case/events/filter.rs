//! Events filters as SQL: Harrier's field syntax, the entity scope and the time range. Every value is a bound
//! parameter; only column names and operators chosen here are ever formatted into the SQL.

use super::{Entity, EventQuery, Field, FlagFilter};
use crate::normalize::net::normalize_ip;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::types::Value;
use std::net::IpAddr;

/// The one source that is hidden unless the Source field names it (there are many events per message).
pub(super) const HIDDEN_SOURCE: &str = "message_trace_event";

/// WHERE clauses over `events e`, ANDed, with their bound parameters in order.
#[derive(Default)]
pub(crate) struct Where {
    pub clauses: Vec<String>,
    pub params: Vec<Value>,
}

impl Where {
    fn push(&mut self, clause: String, params: Vec<Value>) {
        self.clauses.push(clause);
        self.params.extend(params);
    }

    /// ` WHERE ...`, or empty.
    pub fn sql(&self) -> String {
        if self.clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", self.clauses.join(" AND "))
        }
    }
}

impl Field {
    pub fn name(self) -> &'static str {
        match self {
            Field::Source => "Source",
            Field::Operation => "Operation",
            Field::Account => "Account",
            Field::Ip => "IP",
            Field::Country => "Country",
            Field::Asn => "ASN",
            Field::Device => "Device",
            Field::Session => "Session",
            Field::Tag => "Tag",
        }
    }

    /// The SQL expressions a value is compared with (OR'ed). `None` for Tag, which has no column.
    fn exprs(self) -> Option<&'static [&'static str]> {
        Some(match self {
            Field::Source => &["e.source"],
            Field::Operation => &["e.operation"],
            Field::Account => &["e.actor_upn", "e.owner_upn"],
            Field::Ip => &["e.ip"],
            Field::Country => &["e.ip_country"],
            Field::Asn => &["CAST(e.asn AS VARCHAR)"],
            Field::Device => &["e.device_id", "e.device_object_id", "lower(e.device_name)"],
            Field::Session => &["e.entra_session_id"],
            Field::Tag => return None,
        })
    }

    /// Stored lower-cased, so compared lower-cased (Harrier: everything else is exact and case-sensitive).
    fn case_insensitive(self) -> bool {
        matches!(
            self,
            Field::Account | Field::Device | Field::Session | Field::Tag
        )
    }
}

/// One parsed field: the values to include (OR'ed) and to exclude (AND NOT'ed), without their `!`.
#[derive(Debug, PartialEq)]
pub(super) struct Parsed {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

/// Harrier's list syntax. `Ok(None)` for a blank field (no filter). Refused with a message naming the field: a field
/// of only commas, a lone `!` (also `!,`, `! `): they would otherwise match everything or nothing silently.
pub(super) fn parse_list(field: Field, text: &str) -> Result<Option<Parsed>> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    let mut p = Parsed {
        include: vec![],
        exclude: vec![],
    };
    for part in text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match part.strip_prefix('!') {
            Some(rest) if rest.trim().is_empty() => {
                return Err(Error::Invalid(format!(
                    "{} filter: a '!' needs a value after it (like !value)",
                    field.name()
                )));
            }
            Some(rest) => p.exclude.push(rest.trim().to_string()),
            None => p.include.push(part.to_string()),
        }
    }
    if p.include.is_empty() && p.exclude.is_empty() {
        return Err(Error::Invalid(format!(
            "{} filter: only commas, no value",
            field.name()
        )));
    }
    Ok(Some(p))
}

/// `value` as a LIKE pattern: `*` is a wildcard, `%`, `_` and `\` are literal.
pub(super) fn like_pattern(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for c in value.chars() {
        match c {
            '*' => out.push('%'),
            '%' | '_' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

/// `%term%` for a search term, with the same wildcard rule.
fn contains_pattern(term: &str) -> String {
    format!("%{}%", like_pattern(term))
}

/// The predicate for one value of `field` and its parameters (one per expression).
fn value_predicate(field: Field, exprs: &[&str], value: &str) -> (String, Vec<Value>) {
    let wild = value.contains('*');
    let (op, bound) = if wild {
        (" ILIKE ", like_pattern(value))
    } else if field.case_insensitive() {
        (" = ", value.to_lowercase())
    } else if field == Field::Ip {
        // A spelling of the same address (upper-case IPv6, brackets) finds the same rows.
        (" = ", normalize_ip(value).unwrap_or_else(|| value.into()))
    } else {
        (" = ", value.to_string())
    };
    let esc = if wild { " ESCAPE '\\'" } else { "" };
    let parts: Vec<String> = exprs.iter().map(|x| format!("{x}{op}?{esc}")).collect();
    let params = exprs.iter().map(|_| Value::Text(bound.clone())).collect();
    (format!("({})", parts.join(" OR ")), params)
}

/// The clause of one filter field, or `None` for a blank field.
fn field_clause(field: Field, text: &str) -> Result<Option<(String, Vec<Value>)>> {
    let Some(parsed) = parse_list(field, text)? else {
        return Ok(None);
    };
    let Some(exprs) = field.exprs() else {
        // Tag: no tag exists before marks do (analyst marks are a later migration). An include list matches nothing;
        // a list of only excludes keeps every row, none of them carrying a tag.
        // Task 4: with tags in place, excludes must drop the rows that carry the tag; revisit this branch.
        return Ok(if parsed.include.is_empty() {
            None
        } else {
            Some(("FALSE".into(), vec![]))
        });
    };
    let mut params = Vec::new();
    let mut inc = Vec::new();
    for v in &parsed.include {
        let (sql, p) = value_predicate(field, exprs, v);
        inc.push(sql);
        params.extend(p);
    }
    let mut parts = Vec::new();
    if !inc.is_empty() {
        parts.push(format!("({})", inc.join(" OR ")));
    }
    for v in &parsed.exclude {
        let (sql, p) = value_predicate(field, exprs, v);
        // A NULL column is not a match, so an excluded value never hides rows that simply have none.
        parts.push(format!("NOT coalesce({sql}, false)"));
        params.extend(p);
    }
    Ok(Some((parts.join(" AND "), params)))
}

impl Entity {
    /// The entity in its stored spelling: accounts, devices and sessions lower-cased and trimmed, an IP in
    /// `normalize_ip` form. Refused when empty or, for an IP, not an address.
    pub fn normalized(self) -> Result<Entity> {
        let clean = |kind: &str, v: String| {
            let v = v.trim().to_lowercase();
            if v.is_empty() {
                Err(Error::Invalid(format!("an empty {kind} cannot be opened")))
            } else {
                Ok(v)
            }
        };
        Ok(match self {
            Entity::Account(v) => Entity::Account(clean("account", v)?),
            Entity::Device(v) => Entity::Device(clean("device", v)?),
            Entity::Session(v) => Entity::Session(clean("session", v)?),
            Entity::Ip(v) => {
                let ip = normalize_ip(&v)
                    .filter(|n| n.parse::<IpAddr>().is_ok())
                    .ok_or_else(|| {
                        Error::Invalid(format!("{:?} is not an IP address", v.trim()))
                    })?;
                Entity::Ip(ip)
            }
        })
    }

    fn clause(&self) -> (&'static str, Vec<Value>) {
        let t = |v: &String| Value::Text(v.clone());
        match self {
            Entity::Account(v) => ("(e.actor_upn = ? OR e.owner_upn = ?)", vec![t(v), t(v)]),
            Entity::Ip(v) => ("e.ip = ?", vec![t(v)]),
            // The directory object id as well: directory audit events name the device by it.
            Entity::Device(v) => (
                "(e.device_id = ? OR e.device_object_id = ?)",
                vec![t(v), t(v)],
            ),
            Entity::Session(v) => ("e.entra_session_id = ?", vec![t(v)]),
        }
    }
}

/// Microsecond-precision UTC text, for `CAST(? AS TIMESTAMPTZ)`.
pub(super) fn ts_param(t: &DateTime<Utc>) -> Value {
    Value::Text(t.format("%Y-%m-%dT%H:%M:%S%.6f+00").to_string())
}

/// True when `text` (a source name) matches `pattern`: exact without `*`, a case-insensitive wildcard with it.
fn names_source(pattern: &str, source: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == source;
    }
    let (p, s) = (pattern.to_lowercase(), source.to_lowercase());
    let parts: Vec<&str> = p.split('*').collect();
    let mut rest = s.as_str();
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            match rest.strip_prefix(part) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            match rest.find(part) {
                Some(at) => rest = &rest[at + part.len()..],
                None => return false,
            }
        }
    }
    true
}

/// Whether `q` leaves the `message_trace_event` rows out: they are hidden unless an include value of the Source
/// field names them (a wildcard that matches counts).
pub(super) fn hides_trace_events(q: &EventQuery) -> Result<bool> {
    for (f, text) in &q.fields {
        if *f != Field::Source {
            continue;
        }
        if let Some(p) = parse_list(*f, text)? {
            if p.include.iter().any(|v| names_source(v, HIDDEN_SOURCE)) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Source tables a search reads, each with the SQL expression of its record key.
pub(super) const SEARCH_TABLES: &[(&str, &str)] = &[
    ("ual_events", "CAST(t.record_id AS VARCHAR)"),
    ("mail_items_accessed", "t.item_key"),
    ("signins", "t.record_key"),
    ("directory_audits", "t.record_key"),
    ("message_trace", "t.record_key"),
    ("message_trace_events", "t.record_key"),
    ("mailbox_audit_legacy", "t.record_key"),
    ("admin_audit_events", "t.record_key"),
    ("risk_detections", "t.record_key"),
    ("azure_activity", "t.record_key"),
    ("security_alerts", "t.record_key"),
];

/// The WHERE for `q` over `events e`. `show_hidden` keeps the `message_trace_event` rows even when `q` does not
/// name them (the summary uses it to count what the default view hides).
pub(crate) fn build(q: &EventQuery, show_hidden: bool) -> Result<Where> {
    let mut w = Where::default();
    if let Some(e) = &q.entity {
        let (sql, p) = e.clone().normalized()?.clause();
        w.push(sql.into(), p);
    }
    for (field, text) in &q.fields {
        if let Some((sql, p)) = field_clause(*field, text)? {
            w.push(format!("({sql})"), p);
        }
    }
    if !show_hidden && hides_trace_events(q)? {
        w.push(format!("e.source <> '{HIDDEN_SOURCE}'"), vec![]);
    }
    if let Some(from) = &q.from {
        w.push(
            "e.event_time >= CAST(? AS TIMESTAMPTZ)".into(),
            vec![ts_param(from)],
        );
    }
    if let Some(to) = &q.to {
        w.push(
            "e.event_time <= CAST(? AS TIMESTAMPTZ)".into(),
            vec![ts_param(to)],
        );
    }
    // Marks arrive with the marks tables: until then nothing is flagged and nothing is agent-marked.
    if q.flag != FlagFilter::All || q.ai != super::AiFilter::All {
        w.push("FALSE".into(), vec![]);
    }
    if let Some(search) = &q.search {
        if let Some((sql, p)) = search_clause(search)? {
            w.push(sql, p);
        }
    }
    Ok(w)
}

/// A case-insensitive substring over each source row's raw JSON.
///
/// Slow on a big case (about 5 s for 1.4M events: every source table is scanned in full, whatever the other filters
/// are). Two ways to speed it up if needed: restrict each scan to the keys that pass the other filters (a temp table of
/// candidate keys), or keep a trigram / full-text side table. Comma separates terms (OR), `*` is a wildcard.
fn search_clause(text: &str) -> Result<Option<(String, Vec<Value>)>> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    let terms: Vec<String> = text
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(contains_pattern)
        .collect();
    if terms.is_empty() {
        return Err(Error::Invalid("search: only commas, no term".into()));
    }
    let like = vec!["CAST(to_json(t) AS VARCHAR) ILIKE ? ESCAPE '\\'"; terms.len()].join(" OR ");
    let mut parts = Vec::new();
    let mut params = Vec::new();
    for (table, key) in SEARCH_TABLES {
        parts.push(format!(
            "(e.source_table = '{table}' AND e.record_key IN (SELECT {key} FROM {table} t WHERE {like}))"
        ));
        params.extend(terms.iter().map(|t| Value::Text(t.clone())));
    }
    Ok(Some((format!("({})", parts.join(" OR ")), params)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_syntax() {
        let p = parse_list(Field::Account, "  a , !b,, c ")
            .unwrap()
            .unwrap();
        assert_eq!(p.include, ["a", "c"]);
        assert_eq!(p.exclude, ["b"]);
        assert!(parse_list(Field::Account, "   ").unwrap().is_none());
        for bad in ["!", ",,", "!,", "a, !", " ! "] {
            assert!(parse_list(Field::Ip, bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn source_names() {
        assert!(names_source("message_trace_event", HIDDEN_SOURCE));
        assert!(!names_source("Message_Trace_Event", HIDDEN_SOURCE));
        assert!(names_source("message_trace*", HIDDEN_SOURCE));
        assert!(names_source("MESSAGE*", HIDDEN_SOURCE));
        assert!(names_source("*event", HIDDEN_SOURCE));
        assert!(names_source("*trace*", HIDDEN_SOURCE));
        assert!(names_source("*", HIDDEN_SOURCE));
        assert!(!names_source("message_trace", HIDDEN_SOURCE));
        assert!(!names_source("ual*", HIDDEN_SOURCE));
        assert!(!names_source("*trace", HIDDEN_SOURCE));
    }

    #[test]
    fn like_patterns_escape() {
        assert_eq!(like_pattern("a_b%c\\d*"), "a\\_b\\%c\\\\d%");
    }
}
