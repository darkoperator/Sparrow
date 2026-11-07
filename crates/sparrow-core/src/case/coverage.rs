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
//! - **Collector manifests** (`case::collector`, loaded once per call): the gaps are computed in instants (R1). `W` = the window,
//!   `[start 00:00Z, tenant's last event + 1us)`; `E` = the rows' whole days `[day(first), day(last) + 1)`, or none;
//!   `V` = vouched; `G` = open collector gaps within `W`; covered `C` = (`E` u `V`) - `G`. Gaps: `collector_gap` over
//!   `G`; `sampled` over `E - V - G` when sampled; of `W - C - G`, `absent` when there is no `E`, else `before` /
//!   `after` for the parts before / after `E`. Each span becomes the dates `day(start)..=day(end - 1us)`; same-reason
//!   gaps that touch merge; ordered by `from`, then `collector_gap, before, sampled, absent, after`. `collected` is
//!   `V` within `W` as dates, and a source without rows but with `collected` is "collected, no events". This applies
//!   to every source of every account of a tenant with any counted manifest unit; a tenant without one keeps the
//!   date computation above, unchanged.

use crate::case::audit;
use crate::case::collector::{self, ManifestIndex, Span, Spans};
use crate::data::{CollectionHint, DataDirs, collection_hints};
use crate::detect::enrich::accounts::ACCOUNT_ORDER;
use crate::detect::enrich::{EnrichState, enrichment_state};
use crate::profile::availability::EXPORT_CAP_WARNING_LIKE;
use crate::{Error, Result};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use duckdb::types::Value as DbValue;
use duckdb::{Connection, params_from_iter};
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
    /// `absent`, `before`, `after`, `sampled` or `collector_gap`.
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
    /// The days inside the window the collector's manifests vouch were fully collected, merged.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub collected: Vec<DayRange>,
    /// No rows, while the collector vouches for some of the window ("collected, no events").
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub collected_no_events: bool,
}

/// Inclusive UTC dates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DayRange {
    #[serde(serialize_with = "date")]
    pub from: NaiveDate,
    #[serde(serialize_with = "date")]
    pub to: NaiveDate,
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

/// What `load_stats_in` is narrowed to. The default is everything, as `coverage` uses it.
#[derive(Default)]
struct Filter<'a> {
    /// Event times in `[from, to)`, epoch microseconds.
    span: Option<(i64, i64)>,
    tenant: Option<&'a str>,
    /// Lower-cased accounts; `None` is every account.
    accounts: Option<&'a [String]>,
    /// Leave out the sources judged tenant-wide ([`TENANT_WIDE`]).
    per_account_only: bool,
}

/// Judged for the whole tenant, whoever the row names, in the range coverage.
const TENANT_WIDE: &[&str] = &["message_trace", "entra_audit"];

/// The extra `AND ...` conditions of `f` over the row's time (`t`) and account (`acct`) expressions and the
/// collection alias `c`, with the values they bind, in order. Nothing from `f` is written into the SQL text.
fn narrow(f: &Filter, t: &str, acct: &str) -> (String, Vec<DbValue>) {
    let mut sql = String::new();
    let mut args: Vec<DbValue> = Vec::new();
    if let Some((lo, hi)) = f.span {
        sql.push_str(&format!(" AND {t} >= ? AND {t} < ?"));
        args.push(DbValue::BigInt(lo));
        args.push(DbValue::BigInt(hi));
    }
    if let Some(tenant) = f.tenant {
        sql.push_str(" AND c.tenant_key = ?");
        args.push(DbValue::Text(tenant.to_string()));
    }
    if let Some(accounts) = f.accounts {
        if accounts.is_empty() {
            sql.push_str(" AND false");
        } else {
            let marks = vec!["?"; accounts.len()].join(", ");
            sql.push_str(&format!(" AND lower(trim({acct})) IN ({marks})"));
            args.extend(accounts.iter().map(|a| DbValue::Text(a.clone())));
        }
    }
    (sql, args)
}

fn load_stats(conn: &Connection) -> Result<HashMap<StatKey, Stats>> {
    load_stats_in(conn, &Filter::default())
}

fn load_stats_in(conn: &Connection, f: &Filter) -> Result<HashMap<StatKey, Stats>> {
    let mut out: HashMap<StatKey, Stats> = HashMap::new();
    let capped = capped_cte();
    for (source, inner) in sql_sources() {
        if f.per_account_only && TENANT_WIDE.contains(&source) {
            continue;
        }
        let (extra, args) = narrow(f, "x.t_us", "x.acct");
        let mut st = conn.prepare(&format!(
            "WITH {capped} \
             SELECT c.tenant_key, lower(trim(x.acct)), count(*), min(x.t_us), max(x.t_us), \
                    count(DISTINCT x.t_us // {DAY_US}), coalesce(bool_or(cap.k IS NOT NULL), false) \
             FROM ({inner}) x(cid, acct, t_us, tn, k) \
             JOIN collections c ON c.collection_id = x.cid \
             LEFT JOIN capped cap ON cap.tn = x.tn AND cap.k = x.k \
             WHERE c.tenant_key IS NOT NULL AND x.acct IS NOT NULL AND trim(x.acct) <> '' AND x.t_us IS NOT NULL{extra} \
             GROUP BY 1, 2"
        ))?;
        let rows = st.query_map(params_from_iter(args.iter()), |r| {
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
    if !f.per_account_only {
        entra_audit_stats(conn, &mut out)?;
    }
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

/// Midnight UTC of `d`, epoch microseconds.
fn day_start_us(d: NaiveDate) -> i64 {
    d.and_hms_opt(0, 0, 0)
        .unwrap_or_default()
        .and_utc()
        .timestamp_micros()
}

/// The inclusive UTC dates `day(start) ..= day(end - 1us)` of a half-open span.
fn days_of(s: &Span) -> (NaiveDate, NaiveDate) {
    (day_of(s.start_us), day_of(s.end_us - 1))
}

/// The order of gap reasons that start on the same date.
const REASON_ORDER: &[&str] = &["collector_gap", "before", "sampled", "absent", "after"];

/// Spans with their reasons as date gaps: same-reason gaps that overlap or touch (by date) merge; ordered by `from`,
/// then by [`REASON_ORDER`].
fn date_gaps(spans: Vec<(Span, &str)>) -> Vec<Gap> {
    let mut out: Vec<Gap> = Vec::new();
    for reason in REASON_ORDER {
        let mut days: Vec<(NaiveDate, NaiveDate)> = spans
            .iter()
            .filter(|(_, r)| r == reason)
            .map(|(s, _)| days_of(s))
            .collect();
        days.sort_unstable();
        let mut merged: Vec<(NaiveDate, NaiveDate)> = Vec::new();
        for (from, to) in days {
            match merged.last_mut() {
                Some(last) if from <= last.1 + Duration::days(1) => last.1 = last.1.max(to),
                _ => merged.push((from, to)),
            }
        }
        out.extend(merged.into_iter().map(|(from, to)| Gap {
            from,
            to,
            reason: (*reason).to_string(),
        }));
    }
    let rank = |r: &str| {
        REASON_ORDER
            .iter()
            .position(|x| *x == r)
            .unwrap_or(usize::MAX)
    };
    out.sort_by_key(|g| (g.from, rank(&g.reason)));
    out
}

/// `spans` as inclusive date ranges, merged where they overlap or touch by date.
fn day_ranges(spans: &Spans) -> Vec<DayRange> {
    let mut out: Vec<DayRange> = Vec::new();
    for s in spans.iter() {
        let (from, to) = days_of(s);
        match out.last_mut() {
            Some(last) if from <= last.to + Duration::days(1) => last.to = last.to.max(to),
            _ => out.push(DayRange { from, to }),
        }
    }
    out
}

/// The gaps of one source against the window `w` (instants, R1) from the event evidence `stats`, the collector's
/// vouching `v` and open collector gaps `g_all` of the account and source; see the module comment.
fn interval_gaps(w: Span, stats: Option<&Stats>, v: &Spans, g_all: &Spans) -> Vec<Gap> {
    let ws: Spans = std::iter::once(w).collect();
    let g = g_all.intersect(&ws);
    // The event evidence: whole days, first to last row.
    let e: Option<Span> = stats.map(|s| Span {
        start_us: day_start_us(day_of(s.first_us)),
        end_us: day_start_us(day_of(s.last_us) + Duration::days(1)),
    });
    let es: Spans = e.into_iter().collect();
    let covered = es.union(v).minus(&g);
    let open = ws.minus(&covered).minus(&g);
    let mut spans: Vec<(Span, &str)> = g.iter().map(|s| (*s, "collector_gap")).collect();
    if stats.is_some_and(|s| s.sampled) {
        spans.extend(es.minus(v).minus(&g).iter().map(|s| (*s, "sampled")));
    }
    for s in open.iter() {
        // `open` holds nothing of `e`: each part lies wholly before or wholly after it.
        let reason = match e {
            None => "absent",
            Some(e) if s.end_us <= e.start_us => "before",
            Some(_) => "after",
        };
        spans.push((*s, reason));
    }
    date_gaps(spans)
}

/// The gaps of one source against the window when the collector says nothing about it; see the module comment.
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
    let index: ManifestIndex = collector::load(conn)?;
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
        // The window as instants (R1): its first day's midnight up to and including the tenant's last event.
        let window_span = window.zip(span).map(|(w, (_, hi))| Span {
            start_us: day_start_us(w.start),
            end_us: hi + 1,
        });
        // A tenant the collector's manifests say anything about takes the interval computation for every source.
        let manifests = index.has_tenant(&tenant);
        let mut sources = Vec::new();
        for (id, s) in &own {
            let v = index.vouched(&tenant, &upn, id);
            let g = index.account_gaps(&tenant, &upn, id);
            let (gaps, collected) = match (window, window_span) {
                (Some(w), _) if !manifests => (gaps_of(w, *s), Vec::new()),
                (Some(_), Some(ws)) => (
                    interval_gaps(ws, *s, &v, &g),
                    day_ranges(&v.intersect(&std::iter::once(ws).collect())),
                ),
                _ => (Vec::new(), Vec::new()),
            };
            let rows = s.map_or(0, |s| s.rows);
            sources.push(SourceCoverage {
                source: (*id).to_string(),
                title: title_of(id).to_string(),
                rows,
                first: s.map(|s| at(s.first_us)),
                last: s.map(|s| at(s.last_us)),
                days: s.map_or(0, |s| s.days),
                sampled: s.is_some_and(|s| s.sampled),
                gaps,
                collected_no_events: rows == 0 && !collected.is_empty(),
                collected,
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

/// One source's state over a date range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RangeState {
    /// Rows exist in the range and none came from a capped export.
    Covered,
    /// Some row in the range came from a capped export.
    Sampled,
    /// No rows in the range.
    Absent,
}

impl RangeState {
    pub fn as_str(self) -> &'static str {
        match self {
            RangeState::Covered => "covered",
            RangeState::Sampled => "sampled",
            RangeState::Absent => "absent",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceState {
    pub source: String,
    pub title: String,
    /// The worst state over the accounts (absent, then sampled, then covered); the tenant's own for a tenant-wide
    /// source.
    pub state: RangeState,
    /// State name -> the accounts in it, sorted. Empty for a tenant-wide source.
    pub accounts_by_state: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RangeCoverage {
    pub sources: Vec<SourceState>,
}

fn state_of(rows: Option<bool>) -> RangeState {
    match rows {
        None => RangeState::Absent,
        Some(true) => RangeState::Sampled,
        Some(false) => RangeState::Covered,
    }
}

/// `(rows, sampled)` of the tenant-wide sources in the range, per source, over the tenants selected.
fn tenant_wide_states(
    conn: &Connection,
    tenant: Option<&str>,
    span: (i64, i64),
) -> Result<HashMap<&'static str, bool>> {
    let mut out = HashMap::new();
    for (source, table, col) in [
        ("message_trace", "message_trace", "received"),
        ("entra_audit", "directory_audits", "event_time"),
    ] {
        let f = Filter {
            span: Some(span),
            tenant,
            ..Filter::default()
        };
        let (extra, args) = narrow(&f, &format!("epoch_us(x.{col})"), "''");
        let sampled: Option<bool> = conn.query_row(
            &format!(
                "WITH {} SELECT count(*) > 0, coalesce(bool_or(cap.k IS NOT NULL), false) \
                 FROM {table} x JOIN collections c ON c.collection_id = x.collection_id \
                 LEFT JOIN capped cap ON cap.tn = '{table}' AND cap.k = x.record_key \
                 WHERE c.tenant_key IS NOT NULL AND x.{col} IS NOT NULL{extra}",
                capped_cte()
            ),
            params_from_iter(args.iter()),
            |r| {
                let any = r.get::<_, bool>(0)?;
                let sampled = r.get::<_, bool>(1)?;
                Ok(any.then_some(sampled))
            },
        )?;
        if let Some(sampled) = sampled {
            out.insert(source, sampled);
        }
    }
    Ok(out)
}

/// The state of every source over the UTC days `from..=to` (both inclusive) for `accounts` of `tenant` (every tenant
/// when `None`), by the same counting and the same sampled rule as [`coverage`]. `message_trace` and `entra_audit`
/// are judged for the whole tenant whatever `accounts` holds; with no accounts only those two are listed.
pub fn coverage_for_range(
    conn: &Connection,
    tenant: Option<&str>,
    accounts: &[String],
    from: NaiveDate,
    to: NaiveDate,
) -> Result<RangeCoverage> {
    if to < from {
        return Err(Error::Invalid(format!(
            "coverage range {from}..{to} ends before it starts"
        )));
    }
    let span = (day_start_us(from), day_start_us(to + Duration::days(1)));
    let accounts: Vec<String> = accounts
        .iter()
        .filter_map(|a| norm(a))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let stats = if accounts.is_empty() {
        HashMap::new()
    } else {
        load_stats_in(
            conn,
            &Filter {
                span: Some(span),
                tenant,
                accounts: Some(&accounts),
                per_account_only: true,
            },
        )?
    };
    let wide = tenant_wide_states(conn, tenant, span)?;
    let mut sources = Vec::new();
    for (id, title) in SOURCES {
        if TENANT_WIDE.contains(id) {
            sources.push(SourceState {
                source: (*id).to_string(),
                title: (*title).to_string(),
                state: state_of(wide.get(id).copied()),
                accounts_by_state: BTreeMap::new(),
            });
            continue;
        }
        if accounts.is_empty() {
            continue;
        }
        // Per account: sampled if any tenant holds it sampled in the range; rows in no tenant: absent.
        let mut by_state: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut worst = RangeState::Covered;
        for acct in &accounts {
            let held: Vec<bool> = stats
                .iter()
                .filter(|((s, _, a), _)| s == id && a == acct)
                .map(|(_, st)| st.sampled)
                .collect();
            let state = state_of((!held.is_empty()).then(|| held.contains(&true)));
            worst = worst.max(state);
            by_state
                .entry(state.as_str().to_string())
                .or_default()
                .push(acct.clone());
        }
        sources.push(SourceState {
            source: (*id).to_string(),
            title: (*title).to_string(),
            state: worst,
            accounts_by_state: by_state,
        });
    }
    Ok(RangeCoverage { sources })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn us(s: &str) -> i64 {
        DateTime::parse_from_rfc3339(s).unwrap().timestamp_micros()
    }

    fn stats(first: &str, last: &str, sampled: bool) -> Stats {
        Stats {
            rows: 2,
            first_us: us(first),
            last_us: us(last),
            days: 2,
            sampled,
        }
    }

    /// With nothing from the collector, the interval computation is `gaps_of` exactly (R1): the golden's guarantee
    /// holds whichever path a source takes.
    #[test]
    fn interval_gaps_without_manifests_equal_gaps_of() {
        let last_event = "2026-07-31T23:30:00Z";
        let windows = [
            ("2026-06-01", "2026-07-31"),
            ("2026-07-01", "2026-07-31"),
            ("2026-07-31", "2026-07-31"),
        ];
        let evidence = [
            None,
            Some(stats("2026-07-01T10:00:00Z", "2026-07-05T09:00:00Z", false)),
            Some(stats("2026-07-01T10:00:00Z", "2026-07-05T09:00:00Z", true)),
            Some(stats("2026-06-01T00:00:00Z", "2026-07-31T23:30:00Z", true)),
            Some(stats("2026-05-20T00:00:00Z", "2026-07-31T00:00:00Z", false)),
            Some(stats("2026-07-31T01:00:00Z", "2026-07-31T02:00:00Z", true)),
        ];
        for (start, end) in windows {
            let w = Window {
                start: d(start),
                end: d(end),
            };
            let ws = Span {
                start_us: day_start_us(w.start),
                end_us: us(last_event) + 1,
            };
            for s in &evidence {
                // Evidence ending before the window starts (a finding long after the rows): `gaps_of` starts the
                // `after` gap the day after the last row, outside the window; intervals keep it inside (below).
                if s.as_ref().is_some_and(|s| day_of(s.last_us) < w.start) {
                    continue;
                }
                assert_eq!(
                    interval_gaps(ws, s.as_ref(), &Spans::default(), &Spans::default()),
                    gaps_of(w, s.as_ref()),
                    "{start}..{end} {s:?}"
                );
            }
        }
    }

    #[test]
    fn interval_after_gap_stays_inside_the_window() {
        let w = Span {
            start_us: us("2026-07-31T00:00:00Z"),
            end_us: us("2026-07-31T23:30:00Z") + 1,
        };
        let s = stats("2026-07-01T10:00:00Z", "2026-07-05T09:00:00Z", false);
        let gaps = interval_gaps(w, Some(&s), &Spans::default(), &Spans::default());
        assert_eq!(
            gaps,
            vec![Gap {
                from: d("2026-07-31"),
                to: d("2026-07-31"),
                reason: "after".to_string()
            }]
        );
    }

    #[test]
    fn same_reason_gaps_on_one_date_merge_and_reasons_order_on_a_shared_date() {
        let sp = |a: &str, b: &str| Span {
            start_us: us(a),
            end_us: us(b),
        };
        let gaps = date_gaps(vec![
            (
                sp("2026-07-02T06:00:00Z", "2026-07-02T07:00:00Z"),
                "collector_gap",
            ),
            (
                sp("2026-07-02T09:00:00Z", "2026-07-03T00:00:00Z"),
                "collector_gap",
            ),
            (sp("2026-07-01T00:00:00Z", "2026-07-02T06:00:00Z"), "before"),
            (
                sp("2026-07-03T00:00:00Z", "2026-07-04T00:00:00Z"),
                "collector_gap",
            ),
        ]);
        let got: Vec<(String, String, &str)> = gaps
            .iter()
            .map(|g| (g.from.to_string(), g.to.to_string(), g.reason.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("2026-07-01".into(), "2026-07-02".into(), "before"),
                ("2026-07-02".into(), "2026-07-03".into(), "collector_gap"),
            ]
        );
    }
}
