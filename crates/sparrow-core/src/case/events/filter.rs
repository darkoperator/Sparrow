//! Events filters as SQL: Harrier's field syntax, the entity scope and the time range. Every value is a bound
//! parameter; only column names and operators chosen here are ever formatted into the SQL.

use super::{Entity, EventQuery, Field, FlagFilter, marksql};
use crate::normalize::net::normalize_ip;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::types::Value;
use duckdb::{Connection, OptionalExt, params_from_iter};
use std::net::IpAddr;

/// The one source that is hidden unless the Source field names it (there are many events per message).
pub(super) const HIDDEN_SOURCE: &str = "message_trace_event";

/// WHERE clauses over `events e`, ANDed, with their bound parameters in order.
#[derive(Default, Clone)]
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
            Field::Rule => "Rule",
        }
    }

    /// The SQL expressions a value is compared with (OR'ed). Tag compares `t.name` of the tags a row carries, inside
    /// an `EXISTS` over `event_tags` (see [`tag_exists`]); Rule compares the rule id of the row's open findings, inside an
    /// `EXISTS` over `finding_evidence` (see [`rule_exists`]).
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
            Field::Rule => &["lower(f.rule_id)"],
        }
    }

    /// Stored lower-cased, so compared lower-cased (Harrier: everything else is exact and case-sensitive).
    fn case_insensitive(self) -> bool {
        matches!(
            self,
            Field::Account | Field::Device | Field::Session | Field::Tag | Field::Rule
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

/// The findings an event row's rule labels come from: open ones (not closed as false positive or benign).
pub(super) const OPEN_FINDING: &str = "f.status NOT IN ('false_positive', 'benign')";

/// `EXISTS` an open finding with the row `e` as evidence whose rule satisfies `pred` (over `f.rule_id`).
fn rule_exists(pred: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM finding_evidence fe JOIN findings f ON f.finding_id = fe.finding_id \
         WHERE fe.source_table = e.source_table AND fe.record_key = e.record_key AND {OPEN_FINDING} AND {pred})"
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
        inc.push(match field {
            Field::Tag => tag_exists(&sql),
            Field::Rule => rule_exists(&sql),
            _ => sql,
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
        } else if field == Field::Rule {
            parts.push(format!("NOT {}", rule_exists(&sql)));
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
pub(crate) fn build(conn: &Connection, q: &EventQuery, show_hidden: bool) -> Result<Where> {
    build_with(Some(conn), q, show_hidden, true)
}

/// [`build`] for a query without a search (an entity tab's scope), which needs no connection.
pub(crate) fn build_unsearched(q: &EventQuery, show_hidden: bool) -> Result<Where> {
    build_with(None, q, show_hidden, true)
}

/// [`build`] with the flag toggle optional: the summary counts the suspicious and malicious rows of everything else
/// the query selects, whatever the toggle says.
pub(crate) fn build_with(
    conn: Option<&Connection>,
    q: &EventQuery,
    show_hidden: bool,
    apply_flag: bool,
) -> Result<Where> {
    let mut w = Where::default();
    // What narrows the search (see `search_clause`): only clauses over the `events` row itself, which a rebuild alone
    // changes. Tag and Rule read the analyst's tags and the findings, which change between two queries of one view, and
    // the hidden source and the flags are left out so the page, the summary and the histogram share the hits.
    let mut narrowing = Where::default();
    if let Some(e) = &q.entity {
        let (sql, p) = e.clone().normalized()?.clause();
        narrowing.push(sql.clone(), p.clone());
        w.push(sql, p);
    }
    for (field, text) in &q.fields {
        if let Some((sql, p)) = field_clause(*field, text)? {
            if !matches!(field, Field::Tag | Field::Rule) {
                narrowing.push(format!("({sql})"), p.clone());
            }
            w.push(format!("({sql})"), p);
        }
    }
    for (bound, op) in [(&q.from, ">="), (&q.to, "<=")] {
        if let Some(t) = bound {
            let clause = format!("e.event_time {op} CAST(? AS TIMESTAMPTZ)");
            narrowing.push(clause.clone(), vec![ts_param(t)]);
            w.push(clause, vec![ts_param(t)]);
        }
    }
    if !show_hidden && hides_trace_events(q)? {
        w.push(format!("e.source <> '{HIDDEN_SOURCE}'"), vec![]);
    }
    if let Some(search) = q.search.as_deref().filter(|s| !s.trim().is_empty()) {
        let conn =
            conn.ok_or_else(|| Error::Invalid("a search needs the case connection".into()))?;
        if let Some((sql, p)) = search_clause(conn, &narrowing, search)? {
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

/// A narrowed search reads at most this many UAL records by id (the primary-key index); more are scanned.
const INDEX_LOOKUP_MAX: usize = 50_000;
/// Hit rows a connection keeps across its cached searches; the oldest-used searches go first (the current one stays).
const SEARCH_CACHE_ROWS: i64 = 2_000_000;

/// A case-insensitive substring over each source row's raw JSON. Comma separates terms (OR), `*` is a wildcard.
///
/// The hits are computed once into the connection's temp table `events_search_hits`, keyed by the terms, the
/// `narrowing` filters and the events generation (`case_meta.events_generation`, new on every rebuild, with the count
/// for a case built before it existed), and the clause reads them: the page, its count, the summary and the histogram of one view share one scan. Reading the raw JSON is what
/// costs (UAL AuditData: about 12 s for 3.4M records on an external drive), so a search narrowed by other filters reads
/// only their records: none of a table they leave nothing of, UAL ones by id through the primary-key index in chunks of
/// 1000 (a join, or one long IN list, scans the whole column first), the rest through a semi-join on their keys (they
/// have no index).
fn search_clause(
    conn: &Connection,
    narrowing: &Where,
    text: &str,
) -> Result<Option<(String, Vec<Value>)>> {
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
    let events: String = conn.query_row(
        "SELECT coalesce((SELECT value FROM case_meta WHERE key = 'events_generation'), '') || ':' || \
                (SELECT count(*) FROM events)",
        [],
        |r| r.get(0),
    )?;
    let cache_key = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for part in [
            format!("{terms:?}"),
            format!("{:?}", narrowing.clauses),
            format!("{:?}", narrowing.params),
            events,
        ] {
            h.update(part.as_bytes());
            h.update([0x1f]);
        }
        hex::encode(h.finalize())
    };
    // A search is a small id in the hits (a broad term can match millions of rows); `events_search_cache` maps the key
    // to it, with when it was last used and how many hits it holds.
    conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS events_search_hits (search_id BIGINT, source_table VARCHAR, record_key VARCHAR);
         CREATE TEMP TABLE IF NOT EXISTS events_search_cache
             (cache_key VARCHAR, search_id BIGINT, used BIGINT, hits BIGINT);",
    )?;
    let next_use = "(SELECT coalesce(max(used), 0) + 1 FROM events_search_cache)";
    let id: Option<i64> = conn
        .query_row(
            "SELECT search_id FROM events_search_cache WHERE cache_key = ?",
            [&cache_key],
            |r| r.get(0),
        )
        .optional()?;
    let id = match id {
        Some(id) => {
            conn.execute(
                &format!("UPDATE events_search_cache SET used = {next_use} WHERE search_id = ?"),
                [id],
            )?;
            id
        }
        None => {
            let id: i64 = conn.query_row(
                "SELECT coalesce(max(search_id), 0) + 1 FROM \
                 (SELECT search_id FROM events_search_cache UNION ALL SELECT search_id FROM events_search_hits)",
                [],
                |r| r.get(0),
            )?;
            // A fill cut short (an interrupted read) leaves rows under no cache entry: never trusted, and gone here.
            conn.execute_batch(
                "DELETE FROM events_search_hits WHERE search_id NOT IN (SELECT search_id FROM events_search_cache)",
            )?;
            fill_search_hits(conn, narrowing, &terms, &like, id)?;
            conn.execute(
                &format!(
                    "INSERT INTO events_search_cache SELECT ?, ?, {next_use}, \
                     (SELECT count(*) FROM events_search_hits WHERE search_id = ?)"
                ),
                duckdb::params![cache_key, id, id],
            )?;
            // Keep the most recently used searches within SEARCH_CACHE_ROWS hit rows; this one always stays.
            conn.execute_batch(&format!(
                "CREATE OR REPLACE TEMP TABLE events_search_evict AS
                     SELECT search_id FROM (
                         SELECT search_id, sum(hits) OVER (ORDER BY used DESC) AS kept FROM events_search_cache
                     ) WHERE kept > {SEARCH_CACHE_ROWS} AND search_id <> {id};
                 DELETE FROM events_search_hits WHERE search_id IN (SELECT search_id FROM events_search_evict);
                 DELETE FROM events_search_cache WHERE search_id IN (SELECT search_id FROM events_search_evict);
                 DROP TABLE events_search_evict;"
            ))?;
            id
        }
    };
    Ok(Some((
        "EXISTS (SELECT 1 FROM events_search_hits h WHERE h.search_id = ? AND h.source_table = e.source_table \
         AND h.record_key = e.record_key)"
            .into(),
        vec![Value::BigInt(id)],
    )))
}

/// Compute a search's hits into `events_search_hits` under `search_id` (see [`search_clause`]).
fn fill_search_hits(
    conn: &Connection,
    narrowing: &Where,
    terms: &[String],
    like: &str,
    search_id: i64,
) -> Result<()> {
    let term_params = || terms.iter().map(|t| Value::Text(t.clone()));
    let key_param = || std::iter::once(Value::BigInt(search_id));
    let narrowed = !narrowing.clauses.is_empty();
    let base = narrowing.clauses.join(" AND ");
    // How many records of each table the other filters leave: a table with none is not read at all.
    let mut left: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    if narrowed {
        let mut st = conn.prepare(&format!(
            "SELECT e.source_table, count(*) FROM events e WHERE {base} GROUP BY 1"
        ))?;
        let mut rows = st.query(params_from_iter(narrowing.params.iter()))?;
        while let Some(r) = rows.next()? {
            left.insert(r.get(0)?, r.get(1)?);
        }
    }
    for (table, key) in SEARCH_TABLES {
        if narrowed && left.get(*table).copied().unwrap_or(0) == 0 {
            continue;
        }
        let candidates = format!(
            "SELECT e.record_key FROM events e WHERE e.source_table = '{table}' AND {base}"
        );
        if !narrowed {
            conn.execute(
                &format!("INSERT INTO events_search_hits SELECT ?, '{table}', {key} FROM {table} t WHERE {like}"),
                params_from_iter(key_param().chain(term_params())),
            )?;
            continue;
        }
        if *table == "ual_events" {
            let mut ids = std::collections::BTreeSet::new();
            let mut over = false;
            {
                let mut st =
                    conn.prepare(&format!("{candidates} LIMIT {}", INDEX_LOOKUP_MAX + 1))?;
                let mut rows = st.query(params_from_iter(narrowing.params.iter()))?;
                let mut n = 0usize;
                while let Some(r) = rows.next()? {
                    n += 1;
                    if n > INDEX_LOOKUP_MAX {
                        over = true;
                        break;
                    }
                    // A UAL key is its record id; anything else cannot be one (and is never inlined).
                    if let Ok(id) = uuid::Uuid::parse_str(&r.get::<_, String>(0)?) {
                        ids.insert(id);
                    }
                }
            }
            if !over {
                let ids: Vec<String> = ids.into_iter().map(|u| format!("'{u}'")).collect();
                for chunk in ids.chunks(1000) {
                    conn.execute(
                        &format!(
                            "INSERT INTO events_search_hits SELECT ?, 'ual_events', {key} FROM ual_events t \
                             WHERE t.record_id IN ({}) AND ({like})",
                            chunk.join(", ")
                        ),
                        params_from_iter(key_param().chain(term_params())),
                    )?;
                }
                continue;
            }
        }
        conn.execute(
            &format!(
                "INSERT INTO events_search_hits SELECT ?, '{table}', {key} FROM {table} t \
                 WHERE {key} IN ({candidates}) AND ({like})"
            ),
            params_from_iter(
                key_param()
                    .chain(narrowing.params.iter().cloned())
                    .chain(term_params()),
            ),
        )?;
    }
    Ok(())
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
