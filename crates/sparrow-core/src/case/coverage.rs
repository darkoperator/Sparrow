//! Evidence coverage per account and what to request next (`sparrow coverage`). For every account (the accounts with
//! findings, or the users asked for) and every evidence source it can appear in, how many rows the case holds, over
//! which dates, whether any of them came from a capped (sampled) export, and which dates of the account's reference
//! window the evidence does not cover. The gaps become a pull list: one request per account and source, with the
//! console, Hawk and Microsoft-Extractor-Suite way to collect it (`rules/lists/collection_hints.yaml`).
//!
//! Everything is computed from the case tables on each call; nothing is stored and nothing is written.
//!
//! - **Reference window** (dates, UTC): `start` = the earliest `first_seen` of the account's findings, else the
//!   account's earliest row in any source, else the tenant's earliest event, minus 30 days (nothing is subtracted
//!   from the tenant's earliest event); `end` = the latest event time of the whole tenant, any source. `start` is
//!   never after `end`. A tenant with no events has no window and no gaps.
//! - **Gaps** (inclusive dates): `absent` (no rows: the whole window), `before` (window start up to the day before
//!   the first row), `after` (the day after the last row up to the window end) and `sampled` (rows exist but came
//!   from a capped export: first to last row, since the absence of an event there proves nothing). Quiet days
//!   inside first..last are not gaps.
//! - **Sampled**: any of the rows was sighted in a source file whose warnings name a known export cap, the rule
//!   `profile::availability` uses for `truncated`.

use crate::case::audit;
use crate::data::{CollectionHint, DataDirs, collection_hints};
use crate::detect::enrich::accounts::ACCOUNT_ORDER;
use crate::detect::enrich::{EnrichState, enrichment_state};
use crate::profile::availability::EXPORT_CAP_WARNING_LIKE;
use crate::{Error, Result};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use duckdb::Connection;
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};

const DAY_US: i64 = 86_400_000_000;
/// The window starts this many days before the first suspicious (or first) event of the account.
pub const LEAD_DAYS: i64 = 30;

/// The evidence sources, in report order: id and title.
pub const SOURCES: &[(&str, &str)] = &[
    ("ual", "Unified audit log"),
    ("signins_interactive", "Sign-ins (interactive)"),
    ("signins_noninteractive", "Sign-ins (non-interactive)"),
    ("mail_items_accessed", "MailItemsAccessed"),
    ("message_trace", "Message trace"),
    ("entra_audit", "Entra audit log"),
    ("mailbox_audit", "Mailbox audit log (legacy)"),
];

fn title_of(source: &str) -> &'static str {
    SOURCES
        .iter()
        .find(|(id, _)| *id == source)
        .map(|(_, t)| *t)
        .unwrap_or("")
}

fn date<S: Serializer>(d: &NaiveDate, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&d.format("%Y-%m-%d").to_string())
}

fn ts_opt<S: Serializer>(t: &Option<DateTime<Utc>>, s: S) -> std::result::Result<S::Ok, S::Error> {
    match t {
        Some(t) => s.serialize_str(&audit::ts_text(t)),
        None => s.serialize_none(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct CoverageOptions {
    /// Only this tenant key.
    pub tenant: Option<String>,
    /// Only these users (lower-cased). Empty: every account with findings.
    pub users: Vec<String>,
    /// Where the collection hints come from (built-ins plus `--rules` overlays).
    pub dirs: DataDirs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Window {
    #[serde(serialize_with = "date")]
    pub start: NaiveDate,
    #[serde(serialize_with = "date")]
    pub end: NaiveDate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Gap {
    #[serde(serialize_with = "date")]
    pub from: NaiveDate,
    #[serde(serialize_with = "date")]
    pub to: NaiveDate,
    /// `absent`, `before`, `after` or `sampled`.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SourceCoverage {
    pub source: String,
    pub title: String,
    pub rows: i64,
    #[serde(serialize_with = "ts_opt")]
    pub first: Option<DateTime<Utc>>,
    #[serde(serialize_with = "ts_opt")]
    pub last: Option<DateTime<Utc>>,
    /// Distinct UTC dates with at least one row.
    pub days: i64,
    pub sampled: bool,
    pub gaps: Vec<Gap>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AccountCoverage {
    pub tenant_key: String,
    pub upn: String,
    pub window: Option<Window>,
    pub sources: Vec<SourceCoverage>,
}

/// One thing to ask for: an account's evidence of one source over the merged dates of its gaps.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Request {
    pub tenant_key: String,
    pub user: String,
    pub source: String,
    pub title: String,
    #[serde(serialize_with = "date")]
    pub from: NaiveDate,
    #[serde(serialize_with = "date")]
    pub to: NaiveDate,
    pub reasons: Vec<String>,
    /// The admin portal path; `None` when the hints file gives none.
    pub console: Option<String>,
    pub hawk: Option<String>,
    pub invictus: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Coverage {
    pub accounts: Vec<AccountCoverage>,
    pub requests: Vec<Request>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct Stats {
    rows: i64,
    first_us: i64,
    last_us: i64,
    days: i64,
    sampled: bool,
}

fn at(us: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(us).unwrap_or_default()
}

fn day_of(us: i64) -> NaiveDate {
    at(us).date_naive()
}

/// 1,234,567.
pub fn thousands(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 { format!("-{out}") } else { out }
}

/// Record sightings in a file whose warnings name a known export cap, as `(table, record key)`.
fn capped_cte() -> String {
    format!(
        "capped AS (SELECT DISTINCT rs.table_name AS tn, rs.record_key AS k FROM record_sources rs \
         JOIN source_files sf ON sf.file_id = rs.file_id \
         WHERE CAST(sf.warnings AS VARCHAR) LIKE '{EXPORT_CAP_WARNING_LIKE}')"
    )
}

/// Per source, the rows `(cid, acct, t_us, tn, k)` that belong to an account: collection, the account as stored,
/// event time (epoch microseconds), and the `record_sources` table and key of the row.
fn sql_sources() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "ual",
            "SELECT collection_id AS cid, user_upn AS acct, epoch_us(event_time) AS t_us, \
                    'ual_events' AS tn, CAST(record_id AS VARCHAR) AS k FROM ual_events",
        ),
        (
            "signins_interactive",
            "SELECT collection_id, user_upn, epoch_us(event_time), 'signins', record_key \
             FROM signins WHERE event_type = 'interactive'",
        ),
        (
            "signins_noninteractive",
            "SELECT collection_id, user_upn, epoch_us(event_time), 'signins', record_key \
             FROM signins WHERE event_type = 'noninteractive'",
        ),
        // The MailItemsAccessed events of the UAL, plus the parent-less rows of Microsoft-Extractor-Suite's
        // MessageIDs export (the same definition `evidence_availability` uses).
        (
            "mail_items_accessed",
            "SELECT collection_id, user_upn, epoch_us(event_time), 'ual_events', CAST(record_id AS VARCHAR) \
             FROM ual_events WHERE operation = 'MailItemsAccessed' \
             UNION ALL \
             SELECT collection_id, user_upn, epoch_us(event_time), 'mail_items_accessed', item_key \
             FROM mail_items_accessed WHERE record_id IS NULL",
        ),
        // A message belongs to its sender and to its recipient (once when they are the same address).
        (
            "message_trace",
            "SELECT collection_id, sender, epoch_us(received), 'message_trace', record_key FROM message_trace \
             UNION ALL \
             SELECT collection_id, recipient, epoch_us(received), 'message_trace', record_key FROM message_trace \
             WHERE lower(trim(recipient)) IS DISTINCT FROM lower(trim(sender))",
        ),
        (
            "mailbox_audit",
            "SELECT collection_id, mailbox_upn, epoch_us(event_time), 'mailbox_audit_legacy', record_key \
             FROM mailbox_audit_legacy",
        ),
    ]
}

fn norm(s: &str) -> Option<String> {
    let s = s.trim().to_lowercase();
    (!s.is_empty()).then_some(s)
}

type StatKey = (String, String, String);

fn load_stats(conn: &Connection) -> Result<HashMap<StatKey, Stats>> {
    let mut out: HashMap<StatKey, Stats> = HashMap::new();
    let capped = capped_cte();
    for (source, inner) in sql_sources() {
        let mut st = conn.prepare(&format!(
            "WITH {capped} \
             SELECT c.tenant_key, lower(trim(x.acct)), count(*), min(x.t_us), max(x.t_us), \
                    count(DISTINCT x.t_us // {DAY_US}), coalesce(bool_or(cap.k IS NOT NULL), false) \
             FROM ({inner}) x(cid, acct, t_us, tn, k) \
             JOIN collections c ON c.collection_id = x.cid \
             LEFT JOIN capped cap ON cap.tn = x.tn AND cap.k = x.k \
             WHERE c.tenant_key IS NOT NULL AND x.acct IS NOT NULL AND trim(x.acct) <> '' AND x.t_us IS NOT NULL \
             GROUP BY 1, 2"
        ))?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                Stats {
                    rows: r.get(2)?,
                    first_us: r.get(3)?,
                    last_us: r.get(4)?,
                    days: r.get(5)?,
                    sampled: r.get(6)?,
                },
            ))
        })?;
        for row in rows {
            let (tenant, acct, stats) = row?;
            out.insert((source.to_string(), tenant, acct), stats);
        }
    }
    entra_audit_stats(conn, &mut out)?;
    Ok(out)
}

/// The UPNs in `targets[].userPrincipalName` (the key is matched case-insensitively), lower-cased.
fn target_upns(targets: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<Value>(targets) else {
        return Vec::new();
    };
    let items: Vec<&Value> = match &v {
        Value::Array(a) => a.iter().collect(),
        Value::Object(_) => vec![&v],
        _ => Vec::new(),
    };
    items
        .into_iter()
        .filter_map(|t| {
            let o = t.as_object()?;
            let (_, upn) = o
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("userPrincipalName"))?;
            norm(upn.as_str()?)
        })
        .collect()
}

/// `directory_audits`: a row belongs to the account that initiated it and to every account it targets. The target
/// list is JSON, so this source is accumulated here rather than in SQL.
fn entra_audit_stats(conn: &Connection, out: &mut HashMap<StatKey, Stats>) -> Result<()> {
    struct Acc {
        stats: Stats,
        days: BTreeSet<i64>,
    }
    let mut acc: BTreeMap<(String, String), Acc> = BTreeMap::new();
    let mut st = conn.prepare(&format!(
        "WITH {} \
         SELECT c.tenant_key, epoch_us(x.event_time), x.initiated_by_upn, CAST(x.targets AS VARCHAR), \
                cap.k IS NOT NULL \
         FROM directory_audits x JOIN collections c ON c.collection_id = x.collection_id \
         LEFT JOIN capped cap ON cap.tn = 'directory_audits' AND cap.k = x.record_key \
         WHERE c.tenant_key IS NOT NULL AND x.event_time IS NOT NULL",
        capped_cte()
    ))?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, bool>(4)?,
        ))
    })?;
    for row in rows {
        let (tenant, t, actor, targets, sampled) = row?;
        let mut accounts: BTreeSet<String> = BTreeSet::new();
        accounts.extend(actor.as_deref().and_then(norm));
        accounts.extend(targets.as_deref().map(target_upns).unwrap_or_default());
        for upn in accounts {
            let a = acc.entry((tenant.clone(), upn)).or_insert_with(|| Acc {
                stats: Stats {
                    first_us: t,
                    last_us: t,
                    ..Stats::default()
                },
                days: BTreeSet::new(),
            });
            a.stats.rows += 1;
            a.stats.first_us = a.stats.first_us.min(t);
            a.stats.last_us = a.stats.last_us.max(t);
            a.stats.sampled |= sampled;
            a.days.insert(t.div_euclid(DAY_US));
        }
    }
    for ((tenant, upn), mut a) in acc {
        a.stats.days = a.days.len() as i64;
        out.insert(("entra_audit".to_string(), tenant, upn), a.stats);
    }
    Ok(())
}

/// Earliest and latest event of every tenant, over all the sources (the rows of any user).
fn tenant_span(conn: &Connection) -> Result<HashMap<String, (i64, i64)>> {
    let times = [
        ("ual_events", "event_time"),
        ("signins", "event_time"),
        ("mail_items_accessed", "event_time"),
        ("message_trace", "received"),
        ("directory_audits", "event_time"),
        ("mailbox_audit_legacy", "event_time"),
    ]
    .iter()
    .map(|(t, c)| format!("SELECT collection_id, epoch_us({c}) AS t_us FROM {t}"))
    .collect::<Vec<_>>()
    .join(" UNION ALL ");
    let mut st = conn.prepare(&format!(
        "SELECT c.tenant_key, min(x.t_us), max(x.t_us) FROM ({times}) x \
         JOIN collections c ON c.collection_id = x.collection_id \
         WHERE c.tenant_key IS NOT NULL AND x.t_us IS NOT NULL GROUP BY 1"
    ))?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    let mut out = HashMap::new();
    for row in rows {
        let (t, lo, hi) = row?;
        out.insert(t, (lo, hi));
    }
    Ok(out)
}

/// Earliest `first_seen` of the findings of every `(tenant, lower-cased actor)`.
fn finding_starts(conn: &Connection) -> Result<HashMap<(String, String), i64>> {
    let mut st = conn.prepare(
        "SELECT tenant_key, lower(trim(actor_upn)), min(epoch_us(first_seen)) FROM findings \
         WHERE actor_upn IS NOT NULL AND trim(actor_upn) <> '' AND first_seen IS NOT NULL GROUP BY 1, 2",
    )?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    let mut out = HashMap::new();
    for row in rows {
        let (t, u, us) = row?;
        out.insert((t, u), us);
    }
    Ok(out)
}

fn strings(conn: &Connection, sql: &str) -> Result<Vec<String>> {
    let mut st = conn.prepare(sql)?;
    let rows = st.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// Fills `{upn}`, `{from}`, `{to}` (inclusive last day) and `{to_next}` (the day after `{to}`, the exclusive end
/// Microsoft-Extractor-Suite wants).
pub fn fill(template: &str, upn: &str, from: NaiveDate, to: NaiveDate) -> String {
    template
        .replace("{upn}", upn)
        .replace("{from}", &from.format("%Y-%m-%d").to_string())
        .replace(
            "{to_next}",
            &(to + Duration::days(1)).format("%Y-%m-%d").to_string(),
        )
        .replace("{to}", &to.format("%Y-%m-%d").to_string())
}

/// The gaps of one source against the window; see the module comment.
fn gaps_of(window: Window, stats: Option<&Stats>) -> Vec<Gap> {
    let gap = |from, to, reason: &str| Gap {
        from,
        to,
        reason: reason.to_string(),
    };
    let Some(s) = stats else {
        return vec![gap(window.start, window.end, "absent")];
    };
    let (first, last) = (day_of(s.first_us), day_of(s.last_us));
    let mut gaps = Vec::new();
    if window.start < first {
        gaps.push(gap(window.start, first - Duration::days(1), "before"));
    }
    if s.sampled {
        gaps.push(gap(first, last, "sampled"));
    }
    if last < window.end {
        gaps.push(gap(last + Duration::days(1), window.end, "after"));
    }
    gaps
}

/// Evidence coverage of the accounts selected by `opts`. Only reads.
pub fn coverage(conn: &Connection, opts: &CoverageOptions) -> Result<Coverage> {
    let hints: Vec<CollectionHint> = collection_hints(&opts.dirs)?;
    let stats = load_stats(conn)?;
    let spans = tenant_span(conn)?;
    let starts = finding_starts(conn)?;
    let mut warnings = Vec::new();

    // The accounts: (tenant, upn).
    let mut accounts: Vec<(String, String)> = Vec::new();
    if opts.users.is_empty() {
        match enrichment_state(conn)? {
            EnrichState::Ok { .. } => {}
            _ => warnings.push(
                "the account roll-up is not current; accounts with findings may be missing or out of date: run `sparrow detect`"
                    .to_string(),
            ),
        }
        let mut st = conn.prepare(&format!(
            "SELECT tenant_key, lower(upn) FROM account_rollup ORDER BY {ACCOUNT_ORDER}"
        ))?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (t, u) = row?;
            if opts.tenant.as_deref().is_none_or(|x| x == t) {
                accounts.push((t, u));
            }
        }
    } else {
        let tenants: BTreeSet<String> = strings(
            conn,
            "SELECT tenant_key FROM collections WHERE tenant_key IS NOT NULL \
             UNION SELECT tenant_key FROM account_rollup UNION SELECT tenant_key FROM findings",
        )?
        .into_iter()
        .filter(|t| opts.tenant.as_deref().is_none_or(|x| x == t))
        .collect();
        if let Some(t) = &opts.tenant
            && tenants.is_empty()
        {
            return Err(Error::Invalid(format!("no tenant {t:?} in the case")));
        }
        let mut seen = BTreeSet::new();
        for u in &opts.users {
            let Some(u) = norm(u) else { continue };
            if seen.insert(u.clone()) {
                for t in &tenants {
                    accounts.push((t.clone(), u.clone()));
                }
            }
        }
    }

    let mut out = Vec::new();
    let mut requests = Vec::new();
    for (tenant, upn) in accounts {
        let own: Vec<(&str, Option<&Stats>)> = SOURCES
            .iter()
            .map(|(id, _)| {
                (
                    *id,
                    stats.get(&(id.to_string(), tenant.clone(), upn.clone())),
                )
            })
            .collect();
        let earliest_row = own.iter().filter_map(|(_, s)| s.map(|s| s.first_us)).min();
        let span = spans.get(&tenant).copied();
        // The window: from the finding (else the account's first row) minus the lead; to the tenant's last event.
        let start_us = starts
            .get(&(tenant.clone(), upn.clone()))
            .copied()
            .or(earliest_row)
            .map(|us| day_of(us) - Duration::days(LEAD_DAYS))
            .or(span.map(|(lo, _)| day_of(lo)));
        let window = match (start_us, span) {
            (Some(start), Some((_, hi))) => {
                let end = day_of(hi);
                Some(Window {
                    start: start.min(end),
                    end,
                })
            }
            _ => None,
        };
        let mut sources = Vec::new();
        for (id, s) in &own {
            sources.push(SourceCoverage {
                source: (*id).to_string(),
                title: title_of(id).to_string(),
                rows: s.map_or(0, |s| s.rows),
                first: s.map(|s| at(s.first_us)),
                last: s.map(|s| at(s.last_us)),
                days: s.map_or(0, |s| s.days),
                sampled: s.is_some_and(|s| s.sampled),
                gaps: window.map(|w| gaps_of(w, *s)).unwrap_or_default(),
            });
        }
        for s in &sources {
            let (Some(from), Some(to)) = (
                s.gaps.iter().map(|g| g.from).min(),
                s.gaps.iter().map(|g| g.to).max(),
            ) else {
                continue;
            };
            let mut reasons: Vec<String> = Vec::new();
            for g in &s.gaps {
                if !reasons.contains(&g.reason) {
                    reasons.push(g.reason.clone());
                }
            }
            let hint = hints.iter().find(|h| h.source == s.source);
            let render = |t: Option<&String>| t.map(|t| fill(t, &upn, from, to));
            requests.push(Request {
                tenant_key: tenant.clone(),
                user: upn.clone(),
                source: s.source.clone(),
                title: s.title.clone(),
                from,
                to,
                reasons,
                console: render(hint.and_then(|h| h.console.as_ref())),
                hawk: render(hint.and_then(|h| h.hawk.as_ref())),
                invictus: render(hint.and_then(|h| h.invictus.as_ref())),
            });
        }
        out.push(AccountCoverage {
            tenant_key: tenant,
            upn,
            window,
            sources,
        });
    }
    Ok(Coverage {
        accounts: out,
        requests,
        warnings,
    })
}
