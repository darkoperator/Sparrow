//! The export check: values from this case written into a notebook's text (SQL and comments), so an analyst sees
//! them before a file meant for sharing leaves the case. It looks for what a query usually carries: exact account,
//! IP, device and session values the Events grid keys on, the tenant's own mail domains, and the ranges (/24, /48) of
//! the case's IPs. Every candidate is checked against the case, so it never warns about a value the case does not
//! hold.

use super::file::title;
use crate::Result;
use duckdb::{Connection, params_from_iter};
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};
use std::net::Ipv6Addr;
use std::sync::LazyLock;

/// The case values found in one query.
#[derive(Debug, Clone, Serialize)]
pub struct CaseValueHit {
    pub query_id: String,
    pub title: String,
    /// Sorted, each once, as the case holds them (lower case; a range as `a.b.c.0/24` or `x:y:z::/48`).
    pub values: Vec<String>,
}

static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[a-z0-9._%+'-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap());
static IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").unwrap());
/// Three octets and a dot, then something that is not a fourth octet: a `LIKE '203.0.113.%'` prefix.
static IPV4_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.(?:[^0-9]|$)").unwrap());
static IPV4_CIDR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}/\d{1,2}\b").unwrap());
static IPV6: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}").unwrap());
static GUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap()
});

/// The `/48` network text (`2001:db8:abcd::/48`) of an IPv6 address or of a prefix of at least three groups.
fn v6_prefix(token: &str) -> Option<String> {
    let groups: Vec<u16> = match token.parse::<Ipv6Addr>() {
        Ok(a) => a.segments()[..3].to_vec(),
        Err(_) => token
            .split(':')
            .take(3)
            .map(|g| u16::from_str_radix(g, 16).ok().filter(|_| !g.is_empty()))
            .collect::<Option<Vec<u16>>>()?,
    };
    (groups.len() == 3).then(|| format!("{:x}:{:x}:{:x}::/48", groups[0], groups[1], groups[2]))
}

/// What one query's text could name: exact values and ranges, both lower case.
struct Candidates {
    exact: BTreeSet<String>,
    ranges: BTreeSet<String>,
}

fn candidates(text: &str) -> Candidates {
    let mut exact = BTreeSet::new();
    let mut ranges = BTreeSet::new();
    // An address may hold an apostrophe (o'brien@...), but one at its start is the SQL string's quote.
    for m in EMAIL.find_iter(text) {
        exact.insert(m.as_str().trim_start_matches('\'').to_string());
    }
    for m in GUID.find_iter(text) {
        exact.insert(m.as_str().to_string());
    }
    // A complete address is an exact value only: the network it is in is not named by the query.
    for m in IPV4.find_iter(text) {
        exact.insert(m.as_str().to_string());
    }
    // A range is named by a prefix (`'203.0.113.%'`) or a CIDR (`'203.0.113.0/24'`).
    for c in IPV4_PREFIX
        .captures_iter(text)
        .chain(IPV4_CIDR.captures_iter(text))
    {
        ranges.insert(format!("{}.0/24", &c[1]));
    }
    for m in IPV6.find_iter(text) {
        let token = m.as_str();
        if token.matches(':').count() < 2 {
            continue;
        }
        let complete = token.parse::<Ipv6Addr>().is_ok();
        if complete {
            exact.insert(token.to_string());
        }
        let cidr = text[m.end()..].starts_with('/');
        if !complete || cidr {
            if let Some(p) = v6_prefix(token) {
                ranges.insert(p);
            }
        }
    }
    Candidates { exact, ranges }
}

/// Of `values`, those `sql` (one `?` per value, as `IN (...)`) finds in the case.
fn present(conn: &Connection, sql: &str, values: &BTreeSet<String>) -> Result<HashSet<String>> {
    let mut out = HashSet::new();
    let values: Vec<&String> = values.iter().collect();
    for chunk in values.chunks(2000) {
        let marks = vec!["?"; chunk.len()].join(", ");
        let mut stmt = conn.prepare(&sql.replace("{in}", &marks))?;
        let rows = stmt.query_map(params_from_iter(chunk.iter()), |r| r.get::<_, String>(0))?;
        for r in rows {
            out.insert(r?);
        }
    }
    Ok(out)
}

/// The case values in each of `queries` (`(query_id, text)`); only queries holding at least one are returned.
pub fn case_values_in(
    conn: &Connection,
    queries: &[(String, String)],
) -> Result<Vec<CaseValueHit>> {
    let lowered: Vec<String> = queries.iter().map(|(_, s)| s.to_lowercase()).collect();
    let per_query: Vec<Candidates> = lowered.iter().map(|s| candidates(s)).collect();
    let all_exact: BTreeSet<String> = per_query
        .iter()
        .flat_map(|c| c.exact.iter().cloned())
        .collect();
    let all_ranges: BTreeSet<String> = per_query
        .iter()
        .flat_map(|c| c.ranges.iter().cloned())
        .collect();
    // One pass over events: every candidate against every column a value or range can be in.
    let wanted: BTreeSet<String> = all_exact.union(&all_ranges).cloned().collect();
    let found = present(
        conn,
        "SELECT DISTINCT v FROM (
             SELECT unnest([lower(actor_upn), lower(owner_upn), lower(ip), lower(device_id), lower(device_object_id),
                            lower(entra_session_id), lower(ip_prefix)]) AS v FROM events
         ) WHERE v IN ({in})",
        &wanted,
    )?;
    let domains: Vec<String> = {
        let mut stmt = conn.prepare("SELECT DISTINCT lower(domain) FROM tenant_domains")?;
        stmt.query_map([], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?
    };
    let mut out = Vec::new();
    for (((id, sql), text), cands) in queries.iter().zip(&lowered).zip(&per_query) {
        let mut values: BTreeSet<String> = cands
            .exact
            .iter()
            .filter(|v| found.contains(*v))
            .cloned()
            .collect();
        values.extend(cands.ranges.iter().filter(|r| found.contains(*r)).cloned());
        values.extend(domains.iter().filter(|d| names_domain(text, d)).cloned());
        if !values.is_empty() {
            out.push(CaseValueHit {
                query_id: id.clone(),
                title: title(sql),
                values: values.into_iter().collect(),
            });
        }
    }
    Ok(out)
}

/// Whether `text` holds `domain` as a whole name: after `@`, a dot or a non-name character, and not followed by a
/// name character (so `contoso.example` is not found in `mycontoso.example` or `contoso.examples`).
fn names_domain(text: &str, domain: &str) -> bool {
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    text.match_indices(domain).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + domain.len()..].chars().next();
        !before.is_some_and(is_name) && !after.is_some_and(is_name)
    })
}
