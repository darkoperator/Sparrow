//! `sparrow investigate`: one account in one window, in one call — its sessions (by Entra session, else Exchange
//! session, else IP) with what each reached, the mail around the window (a lure the day before is in view), its
//! configuration changes, and its findings' times. Composed from the events table, `access` and the findings; facts
//! only, no verdict. Read-only.

use crate::Result;
use crate::case::access::{Category, ScopeSource, items_with};
use crate::case::marks::ValueKind;
use chrono::{DateTime, Duration, Utc};
use duckdb::Connection;
use duckdb::types::Value;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Mail rows per direction at most.
pub const MAIL_LIMIT: usize = 200;

/// One address a session used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpInfo {
    pub ip: String,
    pub asn: Option<i32>,
    pub asn_org: Option<String>,
    pub country: Option<String>,
    pub kind: Option<String>,
    /// The account has events before the window, none of them from this address.
    pub new_for_account: bool,
    /// Likewise for the address's ASN.
    pub asn_new_for_account: bool,
}

/// What a session reached: the access report's items of one category, in the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reach {
    pub category: Category,
    pub items: u64,
}

/// The account's events of one session in the window.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SessionRow {
    /// The Entra session id, else `exchange:<UAL SessionId>`, else `ip:<address>`, else `none`.
    pub key: String,
    pub first: DateTime<Utc>,
    pub last: DateTime<Utc>,
    pub events: u64,
    pub ips: Vec<IpInfo>,
    pub devices: Vec<String>,
    pub user_agents: Vec<String>,
    /// Sign-in result codes and how often each came.
    pub signin_results: BTreeMap<String, u64>,
    /// Value flags on the session, its addresses or its devices: `kind=value level (review state)`.
    pub flags: Vec<String>,
    /// Findings whose evidence includes an event of the session.
    pub findings: Vec<String>,
    pub reach: Vec<Reach>,
}

/// A message-trace row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MailRow {
    pub received: Option<DateTime<Utc>>,
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub subject: Option<String>,
    pub direction: Option<String>,
    pub status: Option<String>,
}

/// An event, by the reference `mark flag --row` takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventRef {
    pub row: String,
    pub time: Option<DateTime<Utc>>,
    pub operation: String,
    pub summary: Option<String>,
}

/// When one of the account's findings fired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingTime {
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// A command worth running next: its arguments after `sparrow` (without `--case`). The CLI renders `command`, each
/// argument quoted for a shell (session ids and addresses are evidence text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NextStep {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub command: String,
    pub args: Vec<String>,
    pub about: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Investigation {
    pub account: String,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub sessions: Vec<SessionRow>,
    /// Mail to the account from a day before the window to its end; mail it sent in the window.
    pub mail_in: Vec<MailRow>,
    pub mail_out: Vec<MailRow>,
    pub mail_truncated: bool,
    pub config_changes: Vec<EventRef>,
    pub finding_times: Vec<FindingTime>,
    pub next: Vec<NextStep>,
}

struct WindowEvent {
    row: (String, String),
    t: DateTime<Utc>,
    ip: Option<String>,
    country: Option<String>,
    asn: Option<i32>,
    asn_org: Option<String>,
    ip_kind: Option<String>,
    device: Option<String>,
    entra: Option<String>,
    ua: Option<String>,
    operation: Option<String>,
    result: Option<String>,
    category: String,
    source: String,
    summary: Option<String>,
}

fn us(t: DateTime<Utc>) -> i64 {
    t.timestamp_micros()
}

fn at(v: Option<i64>) -> Option<DateTime<Utc>> {
    v.and_then(DateTime::from_timestamp_micros)
}

/// The account `upn` (any case) in `[from, to)`.
pub fn investigate(
    conn: &Connection,
    upn: &str,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Investigation> {
    if to <= from {
        return Err(crate::Error::Invalid(
            "the window ends before it starts".into(),
        ));
    }
    let account = upn.trim().to_lowercase();
    let events = window_events(conn, &account, from, to)?;
    let exchange = exchange_sessions(conn, &events)?;

    // An Exchange session seen on a record of an Entra session belongs to it, with that record's IPs (the access
    // report's propagation rule).
    let mut entra_of: BTreeMap<&str, (String, BTreeSet<&str>)> = BTreeMap::new();
    for e in &events {
        if let (Some(s), Some(x)) = (&e.entra, exchange.get(&e.row.1)) {
            let entry = entra_of
                .entry(x.as_str())
                .or_insert_with(|| (s.to_lowercase(), BTreeSet::new()));
            entry.1.extend(e.ip.as_deref());
        }
    }
    // Group: Entra session, else Exchange session, else IP.
    let mut groups: BTreeMap<String, Vec<&WindowEvent>> = BTreeMap::new();
    for e in &events {
        let key = match (&e.entra, exchange.get(&e.row.1), &e.ip) {
            (Some(s), _, _) => s.to_lowercase(),
            (None, Some(x), ip) => match entra_of.get(x.as_str()) {
                Some((s, ips)) if ip.as_deref().is_none_or(|ip| ips.contains(ip)) => s.clone(),
                _ => format!("exchange:{x}"),
            },
            (None, None, Some(ip)) => format!("ip:{ip}"),
            _ => "none".to_string(),
        };
        groups.entry(key).or_default().push(e);
    }

    let (new_ips, new_asns) = new_values(conn, &account)?;
    let flags = value_flags(conn)?;
    let findings = findings_of_rows(conn, &account, from, to)?;

    let mut sessions = Vec::new();
    for (key, evs) in &groups {
        let mut ips: BTreeMap<String, IpInfo> = BTreeMap::new();
        let (mut devices, mut uas) = (BTreeSet::new(), BTreeSet::new());
        let mut results = BTreeMap::new();
        let mut finding_ids = BTreeSet::new();
        for e in evs {
            if let Some(ip) = &e.ip {
                ips.entry(ip.clone()).or_insert_with(|| IpInfo {
                    ip: ip.clone(),
                    asn: e.asn,
                    asn_org: e.asn_org.clone(),
                    country: e.country.clone(),
                    kind: e.ip_kind.clone(),
                    new_for_account: new_ips.contains(ip),
                    asn_new_for_account: e.asn.is_some_and(|a| new_asns.contains(&a)),
                });
            }
            if let Some(d) = &e.device {
                devices.insert(d.clone());
            }
            if let Some(u) = &e.ua {
                uas.insert(u.clone());
            }
            if e.source.starts_with("signin") || e.category == "auth" {
                if let Some(r) = &e.result {
                    *results.entry(r.clone()).or_insert(0u64) += 1;
                }
            }
            if let Some(f) = findings.get(&e.row) {
                finding_ids.extend(f.iter().cloned());
            }
        }
        let mut touching = BTreeSet::new();
        let session_ids: BTreeSet<String> = evs
            .iter()
            .filter_map(|e| e.entra.as_ref().map(|s| s.to_lowercase()))
            .chain(key.strip_prefix("exchange:").map(str::to_string))
            .collect();
        for f in &flags {
            let hit = match f.kind.as_str() {
                "session" => session_ids.contains(&f.value),
                "ip" => ips.contains_key(&f.value),
                "device" => devices.contains(&f.value),
                _ => false,
            };
            // A scoped flag counts only where its scope holds, as in the events grid and the access report.
            let in_scope = match (f.scope_kind.as_deref(), f.scope_value.as_deref()) {
                (None, _) | (_, None) => true,
                (Some("account"), Some(v)) => v.eq_ignore_ascii_case(&account),
                (Some("ip"), Some(v)) => ips.contains_key(v),
                (Some("device"), Some(v)) => devices.contains(v),
                (Some("session"), Some(v)) => session_ids.contains(&v.to_lowercase()),
                _ => false,
            };
            if hit && in_scope {
                touching.insert(f.label.clone());
            }
        }
        sessions.push(SessionRow {
            key: key.clone(),
            first: evs.iter().map(|e| e.t).min().unwrap_or(from),
            last: evs.iter().map(|e| e.t).max().unwrap_or(from),
            events: evs.len() as u64,
            ips: ips.into_values().collect(),
            devices: devices.into_iter().collect(),
            user_agents: uas.into_iter().collect(),
            signin_results: results,
            flags: touching.into_iter().collect(),
            findings: finding_ids.into_iter().collect(),
            reach: reach(conn, &account, from, to, key)?,
        });
    }
    sessions.sort_by(|a, b| a.first.cmp(&b.first).then(a.key.cmp(&b.key)));

    let config_changes = events
        .iter()
        .filter(|e| e.category == "config_change")
        .map(|e| EventRef {
            row: format!("{}:{}", e.row.0, e.row.1),
            time: Some(e.t),
            operation: e.operation.clone().unwrap_or_default(),
            summary: e.summary.clone(),
        })
        .collect();
    let lookback = from
        .checked_sub_signed(Duration::hours(24))
        .ok_or_else(|| crate::Error::Invalid("the window starts too early".into()))?;
    let (mail_in, in_more) = mail(conn, "recipient", &account, lookback, to)?;
    let (mail_out, out_more) = mail(conn, "sender", &account, from, to)?;
    let next = next_steps(&account, &sessions);
    Ok(Investigation {
        account: account.clone(),
        from,
        to,
        sessions,
        mail_in,
        mail_out,
        mail_truncated: in_more || out_more,
        config_changes,
        finding_times: finding_times(conn, &account)?,
        next,
    })
}

fn window_events(
    conn: &Connection,
    account: &str,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<WindowEvent>> {
    let mut st = conn.prepare(
        "SELECT source_table, record_key, epoch_us(event_time), ip, ip_country, asn, asn_org, ip_kind, \
                coalesce(device_id, device_name), entra_session_id, user_agent, operation, result, \
                CAST(category AS VARCHAR), source, summary \
         FROM events WHERE lower(actor_upn) = ? AND epoch_us(event_time) >= ? AND epoch_us(event_time) < ? \
         ORDER BY event_time, source_table, record_key",
    )?;
    let rows = st.query_map(duckdb::params![account, us(from), us(to)], |r| {
        Ok(WindowEvent {
            row: (r.get(0)?, r.get(1)?),
            t: at(r.get(2)?).unwrap_or_default(),
            ip: r.get(3)?,
            country: r.get(4)?,
            asn: r.get(5)?,
            asn_org: r.get(6)?,
            ip_kind: r.get(7)?,
            device: r.get(8)?,
            entra: r.get(9)?,
            ua: r.get(10)?,
            operation: r.get(11)?,
            result: r.get(12)?,
            category: r.get(13)?,
            source: r.get(14)?,
            summary: r.get(15)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// The UAL SessionId (lower-cased) of the window's UAL records, by record key. Looked up by
/// constant record ids (the primary-key index), never by a join that would scan AuditData.
fn exchange_sessions(
    conn: &Connection,
    events: &[WindowEvent],
) -> Result<BTreeMap<String, String>> {
    let ids: BTreeSet<uuid::Uuid> = events
        .iter()
        .filter(|e| e.row.0 == "ual_events")
        .filter_map(|e| uuid::Uuid::parse_str(&e.row.1).ok())
        .collect();
    let ids: Vec<String> = ids.into_iter().map(|u| format!("'{u}'")).collect();
    let mut out = BTreeMap::new();
    for chunk in ids.chunks(1000) {
        let mut st = conn.prepare(&format!(
            "SELECT CAST(record_id AS VARCHAR), lower(session_id) FROM ual_events \
             WHERE record_id IN ({}) AND coalesce(session_id, '') <> ''",
            chunk.join(", ")
        ))?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (k, s) = row?;
            out.insert(k, s);
        }
    }
    Ok(out)
}

/// The account's addresses and ASNs first seen after its first day (the entity pivots' `is_new` rule): over all its
/// events, a value's first day is later than the account's first day.
fn new_values(conn: &Connection, account: &str) -> Result<(BTreeSet<String>, BTreeSet<i32>)> {
    let day = 86_400_000_000i64;
    let mut st = conn.prepare(&format!(
        "WITH a AS (SELECT ip, asn, epoch_us(event_time) // {day} AS d FROM events \
                    WHERE lower(actor_upn) = ? AND event_time IS NOT NULL), \
              f AS (SELECT min(d) AS d FROM a) \
         SELECT 'ip', ip, NULL::INTEGER FROM a GROUP BY ip HAVING ip IS NOT NULL AND min(d) > (SELECT d FROM f) \
         UNION ALL \
         SELECT 'asn', NULL, asn FROM a GROUP BY asn HAVING asn IS NOT NULL AND min(d) > (SELECT d FROM f)"
    ))?;
    let rows = st.query_map([account], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, Option<i32>>(2)?,
        ))
    })?;
    let (mut ips, mut asns) = (BTreeSet::new(), BTreeSet::new());
    for row in rows {
        let (what, ip, asn) = row?;
        if what == "ip" {
            ips.extend(ip);
        } else {
            asns.extend(asn);
        }
    }
    Ok((ips, asns))
}

/// A value flag on a session, an address or a device (not removed), with its scope.
struct ValueFlag {
    kind: String,
    value: String,
    scope_kind: Option<String>,
    scope_value: Option<String>,
    label: String,
}

fn value_flags(conn: &Connection) -> Result<Vec<ValueFlag>> {
    let mut st = conn.prepare(
        "SELECT kind::VARCHAR, value, level::VARCHAR, review_state::VARCHAR, scope_kind, scope_value FROM value_flags \
         WHERE removed_at IS NULL AND kind IN ('session', 'ip', 'device') ORDER BY 1, 2",
    )?;
    let rows = st.query_map([], |r| {
        let (k, v, l, s): (String, String, String, String) =
            (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?);
        let (sk, sv): (Option<String>, Option<String>) = (r.get(4)?, r.get(5)?);
        let scope = match (&sk, &sv) {
            (Some(k), Some(v)) => format!(" scope {k}={v}"),
            _ => String::new(),
        };
        Ok(ValueFlag {
            label: format!("{k}={v} {l} ({s}){scope}"),
            kind: k,
            value: v,
            scope_kind: sk,
            scope_value: sv,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// The findings whose evidence holds each of the account's window events.
fn findings_of_rows(
    conn: &Connection,
    account: &str,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<BTreeMap<(String, String), Vec<String>>> {
    let mut st = conn.prepare(
        "SELECT DISTINCT fe.source_table, fe.record_key, fe.finding_id FROM finding_evidence fe \
         JOIN events e USING (source_table, record_key) \
         WHERE lower(e.actor_upn) = ? AND epoch_us(e.event_time) >= ? AND epoch_us(e.event_time) < ? \
         ORDER BY 3",
    )?;
    let rows = st.query_map(duckdb::params![account, us(from), us(to)], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    let mut out: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for row in rows {
        let (t, k, f) = row?;
        out.entry((t, k)).or_default().push(f);
    }
    Ok(out)
}

/// What each session reached: the access report's items with the session's value as ad-hoc scope (as `sparrow access
/// --session ID` or `--ip IP` would give them), limited to the window, by category. One attribution per session.
fn reach(
    conn: &Connection,
    account: &str,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    key: &str,
) -> Result<Vec<Reach>> {
    let value = if let Some(ip) = key.strip_prefix("ip:") {
        (ValueKind::Ip, ip.to_string())
    } else if let Some(x) = key.strip_prefix("exchange:") {
        (ValueKind::Session, x.to_string())
    } else if key == "none" {
        return Ok(Vec::new());
    } else {
        (ValueKind::Session, key.to_string())
    };
    let src = ScopeSource {
        adhoc: vec![value],
        window: Some((from, to)),
        ..ScopeSource::accepted()
    };
    let mut by: BTreeMap<Category, u64> = BTreeMap::new();
    for i in items_with(conn, Some(account), &src)? {
        *by.entry(i.category).or_insert(0) += 1;
    }
    Ok(Category::ALL
        .iter()
        .filter_map(|c| {
            by.get(c).map(|n| Reach {
                category: *c,
                items: *n,
            })
        })
        .collect())
}

/// Message-trace rows whose `column` (sender or recipient) is the account, received in `[from, to)`.
fn mail(
    conn: &Connection,
    column: &str,
    account: &str,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<(Vec<MailRow>, bool)> {
    let column = if column == "sender" {
        "sender"
    } else {
        "recipient"
    };
    let mut st = conn.prepare(&format!(
        "SELECT epoch_us(received), sender, recipient, subject, direction, status FROM message_trace \
         WHERE lower({column}) = ? AND epoch_us(received) >= ? AND epoch_us(received) < ? \
         ORDER BY received, sender, recipient LIMIT ?"
    ))?;
    let rows = st.query_map(
        duckdb::params![account, us(from), us(to), (MAIL_LIMIT + 1) as i64],
        |r| {
            Ok(MailRow {
                received: at(r.get(0)?),
                sender: r.get(1)?,
                recipient: r.get(2)?,
                subject: r.get(3)?,
                direction: r.get(4)?,
                status: r.get(5)?,
            })
        },
    )?;
    let mut out: Vec<MailRow> = rows.collect::<std::result::Result<_, _>>()?;
    let more = out.len() > MAIL_LIMIT;
    out.truncate(MAIL_LIMIT);
    Ok((out, more))
}

fn finding_times(conn: &Connection, account: &str) -> Result<Vec<FindingTime>> {
    let mut st = conn.prepare(
        "SELECT finding_id, title, severity, epoch_us(first_seen), epoch_us(last_seen) FROM findings \
         WHERE lower(actor_upn) = ? ORDER BY first_seen NULLS LAST, finding_id",
    )?;
    let rows = st.query_map([Value::Text(account.to_string())], |r| {
        Ok(FindingTime {
            finding_id: r.get(0)?,
            title: r.get(1)?,
            severity: r.get(2)?,
            first_seen: at(r.get(3)?),
            last_seen: at(r.get(4)?),
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// Per session: flag it, and see what it reached.
fn next_steps(account: &str, sessions: &[SessionRow]) -> Vec<NextStep> {
    let mut out = Vec::new();
    for s in sessions {
        let (kind, value, what) = if let Some(ip) = s.key.strip_prefix("ip:") {
            ("ip", ip.to_string(), format!("address {ip}"))
        } else if let Some(x) = s.key.strip_prefix("exchange:") {
            ("session", x.to_string(), format!("Exchange session {x}"))
        } else if s.key == "none" {
            continue;
        } else {
            ("session", s.key.clone(), format!("Entra session {}", s.key))
        };
        let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        out.push(NextStep {
            command: String::new(),
            args: words(&[
                "access",
                "--account",
                account,
                &format!("--{kind}"),
                &value,
                "--brief",
                "--json",
            ]),
            about: format!("what the {what} reached (a preview: nothing is flagged)"),
        });
        out.push(NextStep {
            command: String::new(),
            args: words(&[
                "mark",
                "flag",
                "--value",
                &format!("{kind}={value}"),
                "--level",
                "malicious",
            ]),
            about: format!("if the {what} is the attacker's: flag it for the analyst to review"),
        });
    }
    out
}
