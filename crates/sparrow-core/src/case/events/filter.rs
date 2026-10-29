//! Events filters as SQL: Harrier's field syntax, the entity scope and the time range. Every value is a bound
//! parameter; only column names and operators chosen here are ever formatted into the SQL.

use super::{Entity, EventQuery, Field, FlagFilter, marksql};
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

    /// The SQL expressions a value is compared with (OR'ed). Tag compares `t.name` of the tags a row carries, inside
    /// an `EXISTS` over `event_tags` (see [`tag_exists`]).
    fn exprs(self) -> &'static [&'static str] {
        match self {
            Field::Source => &["e.source"],
            Field::Operation => &["e.operation"],
            Field::Account => &["e.actor_upn", "e.owner_upn"],
            Field::Ip => &["e.ip"],
            Field::Country => &["e.ip_country"],
            Field::Asn => &["CAST(e.asn AS VARCHAR)"],
            Field::Device => &["e.device_id", "e.device_object_id", "lower(e.device_name)"],
            Field::Session => &["e.entra_session_id"],
            Field::Tag => &["t.name"],
        }
    }

    /// Stored lower-cased, so compared lower-cased (Harrier: everything else is exact and case-sensitive).
    fn case_insensitive(self) -> bool {
        matches!(
            self,
            Field::Account | Field::Device | Field::Session | Field::Tag
        )
    }
}

/// One value of a field: its text (without the `!` and the quotes) and whether its `*`s are wildcards. A quoted value
/// is always literal.
#[derive(Debug, PartialEq)]
pub(super) struct Term {
    pub text: String,
    pub wild: bool,
}

/// One parsed field: the values to include (OR'ed) and to exclude (AND NOT'ed).
#[derive(Debug, PartialEq)]
pub(super) struct Parsed {
    pub include: Vec<Term>,
    pub exclude: Vec<Term>,
}

/// Harrier's list syntax, plus quoting: a value in double quotes (`"a,b"`, `!"*x"`) is taken literally, commas, `*`, a
/// leading `!` and outer spaces included, and `""` inside it is one quote. A quote anywhere but at the start of a value
/// is an ordinary character. `Ok(None)` for a blank field (no filter). Refused with a message naming the field: a field
/// of only commas, a lone `!` (also `!,`, `! `), a quote that is not closed, and text after a closing quote: they would
/// otherwise match everything, nothing, or something else silently.
pub(super) fn parse_list(field: Field, text: &str) -> Result<Option<Parsed>> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    let refuse = |why: &str| Err(Error::Invalid(format!("{} filter: {why}", field.name())));
    let mut p = Parsed {
        include: vec![],
        exclude: vec![],
    };
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let skip_space = |i: &mut usize| {
        while *i < chars.len() && chars[*i].is_whitespace() {
            *i += 1;
        }
    };
    while i <= chars.len() {
        skip_space(&mut i);
        let bang = i < chars.len() && chars[i] == '!';
        if bang {
            i += 1;
            skip_space(&mut i);
        }
        let term = if i < chars.len() && chars[i] == '"' {
            let mut value = String::new();
            i += 1;
            loop {
                match chars.get(i) {
                    None => return refuse("a quote is not closed (a quoted value ends with \")"),
                    Some('"') if chars.get(i + 1) == Some(&'"') => {
                        value.push('"');
                        i += 2;
                    }
                    Some('"') => {
                        i += 1;
                        break;
                    }
                    Some(c) => {
                        value.push(*c);
                        i += 1;
                    }
                }
            }
            skip_space(&mut i);
            if i < chars.len() && chars[i] != ',' {
                return refuse(
                    "a quoted value must end at its closing quote (put a comma after it)",
                );
            }
            Some(Term {
                text: value,
                wild: false,
            })
        } else {
            let start = i;
            while i < chars.len() && chars[i] != ',' {
                i += 1;
            }
            let value: String = chars[start..i]
                .iter()
                .collect::<String>()
                .trim()
                .to_string();
            if value.is_empty() {
                if bang {
                    return refuse("a '!' needs a value after it (like !value)");
                }
                None
            } else {
                Some(Term {
                    wild: value.contains('*'),
                    text: value,
                })
            }
        };
        if let Some(t) = term {
            if bang {
                p.exclude.push(t);
            } else {
                p.include.push(t);
            }
        }
        // Past the comma that ends this value (or the end of the text).
        i += 1;
    }
    if p.include.is_empty() && p.exclude.is_empty() {
        return refuse("only commas, no value");
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
fn value_predicate(field: Field, exprs: &[&str], term: &Term) -> (String, Vec<Value>) {
    let (value, wild) = (term.text.as_str(), term.wild);
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

/// `EXISTS` a tag of the row `e` that satisfies `pred` (over `t.name`).
fn tag_exists(pred: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM event_tags et JOIN tags t ON t.tag_id = et.tag_id \
         WHERE et.source_table = e.source_table AND et.record_key = e.record_key AND {pred})"
    )
}

/// The clause of one filter field, or `None` for a blank field.
fn field_clause(field: Field, text: &str) -> Result<Option<(String, Vec<Value>)>> {
    let Some(parsed) = parse_list(field, text)? else {
        return Ok(None);
    };
    let exprs = field.exprs();
    let mut params = Vec::new();
    let mut inc = Vec::new();
    for v in &parsed.include {
        let (sql, p) = value_predicate(field, exprs, v);
        inc.push(if field == Field::Tag {
            tag_exists(&sql)
        } else {
            sql
        });
        params.extend(p);
    }
    let mut parts = Vec::new();
    if !inc.is_empty() {
        parts.push(format!("({})", inc.join(" OR ")));
    }
    for v in &parsed.exclude {
        let (sql, p) = value_predicate(field, exprs, v);
        if field == Field::Tag {
            // Rows without the tag, untagged rows included: `!x` alone is "everything except x".
            parts.push(format!("NOT {}", tag_exists(&sql)));
        } else {
            // A NULL column is not a match, so an excluded value never hides rows that simply have none.
            parts.push(format!("NOT coalesce({sql}, false)"));
        }
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

    /// `account`, `ip`, `device` or `session`.
    pub(crate) fn kind_name(&self) -> &'static str {
        match self {
            Entity::Account(_) => "account",
            Entity::Ip(_) => "ip",
            Entity::Device(_) => "device",
            Entity::Session(_) => "session",
        }
    }

    pub(crate) fn value(&self) -> &str {
        match self {
            Entity::Account(v) | Entity::Ip(v) | Entity::Device(v) | Entity::Session(v) => v,
        }
    }

    /// The scope predicate over `events e` and its bound parameters (already normalized).
    pub(crate) fn clause(&self) -> (String, Vec<Value>) {
        let cols = entity_columns(self.kind_name()).len();
        (
            entity_predicate(self.kind_name(), "?"),
            vec![Value::Text(self.value().to_string()); cols],
        )
    }
}

/// The `events` columns an entity kind is compared with: the one rule for entity scopes, for the value a standing flag
/// matches and for the scope of a flag. An account is the actor or the mailbox owner; a device is its device id or its
/// directory object id (directory audit events name the device by it).
pub(crate) fn entity_columns(kind: &str) -> &'static [&'static str] {
    match kind {
        "account" => &["e.actor_upn", "e.owner_upn"],
        "ip" => &["e.ip"],
        "device" => &["e.device_id", "e.device_object_id"],
        "session" => &["e.entra_session_id"],
        other => unreachable!("entity kind {other:?}"),
    }
}

/// SQL over `events e` that holds when an entity of `kind` equals `rhs` (a `?` or a column such as `vf.scope_value`).
pub(crate) fn entity_predicate(kind: &str, rhs: &str) -> String {
    let parts: Vec<String> = entity_columns(kind)
        .iter()
        .map(|c| format!("{c} = {rhs}"))
        .collect();
    if parts.len() == 1 {
        parts[0].clone()
    } else {
        format!("({})", parts.join(" OR "))
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
            let names = |t: &Term| {
                if t.wild {
                    names_source(&t.text, HIDDEN_SOURCE)
                } else {
                    t.text == HIDDEN_SOURCE
                }
            };
            if p.include.iter().any(names) {
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
    build_with(q, show_hidden, true)
}

/// [`build`] with the flag toggle optional: the summary counts the suspicious and malicious rows of everything else
/// the query selects, whatever the toggle says.
pub(crate) fn build_with(q: &EventQuery, show_hidden: bool, apply_flag: bool) -> Result<Where> {
    let mut w = Where::default();
    if let Some(e) = &q.entity {
        let (sql, p) = e.clone().normalized()?.clause();
        w.push(sql, p);
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
    if let Some(search) = &q.search {
        if let Some((sql, p)) = search_clause(search)? {
            w.push(sql, p);
        }
    }
    // The flag toggle and the agent filter are semi-joins on the flagged rows of everything else the query selects,
    // computed once (`marksql::flagged`). The toggle is the effective flag exactly: Suspicious shows the suspicious
    // rows, so the summary's count and the grid's total agree after a click.
    let base_where = w.sql();
    let base_params = w.params.clone();
    let restrict = !w.clauses.is_empty();
    let toggle = match q.flag {
        FlagFilter::All => None,
        FlagFilter::Suspicious => Some("sus AND NOT mal"),
        FlagFilter::Malicious => Some("mal"),
    };
    if let (true, Some(cond)) = (apply_flag, toggle) {
        w.push(
            marksql::flagged_clause(&base_where, restrict, cond),
            base_params.clone(),
        );
    }
    let agent = match q.ai {
        super::AiFilter::All => None,
        super::AiFilter::Marked => Some(("agent_any", false)),
        super::AiFilter::Unreviewed => Some(("agent_pend", true)),
    };
    if let Some((cond, pending)) = agent {
        w.push(
            format!(
                "({} OR {})",
                marksql::flagged_clause(&base_where, restrict, cond),
                marksql::agent_tag_clause(pending)
            ),
            base_params,
        );
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
        let texts = |v: &[Term]| v.iter().map(|t| t.text.clone()).collect::<Vec<_>>();
        assert_eq!(texts(&p.include), ["a", "c"]);
        assert_eq!(texts(&p.exclude), ["b"]);
        assert!(parse_list(Field::Account, "   ").unwrap().is_none());
        for bad in ["!", ",,", "!,", "a, !", " ! "] {
            assert!(parse_list(Field::Ip, bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn quoted_values_are_literal() {
        let lit = |s: &str| Term {
            text: s.into(),
            wild: false,
        };
        let p = parse_list(
            Field::Operation,
            r#""a,b" , !"*x", "say ""hi""", "!bang",  " pad " ,c*,!"","#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            p.include,
            [
                lit("a,b"),
                lit("say \"hi\""),
                lit("!bang"),
                lit(" pad "),
                Term {
                    text: "c*".into(),
                    wild: true
                }
            ]
        );
        assert_eq!(p.exclude, [lit("*x"), lit("")]);
        // A quote inside an unquoted value is a character.
        let p = parse_list(Field::Operation, r#"O"Brien"#).unwrap().unwrap();
        assert_eq!(p.include, [lit("O\"Brien")]);
        for bad in [r#""open"#, r#""a"b"#, r#"!"x"y, z"#] {
            let e = parse_list(Field::Operation, bad).unwrap_err();
            assert!(e.to_string().contains("Operation filter"), "{bad:?}: {e}");
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
