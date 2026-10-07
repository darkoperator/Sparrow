//! Read commands (Addendum D.5): finding list/show, the evidence timeline, and pivots on an IP or a user. Nothing
//! here writes. Every list is ordered by something that means something, and every capped list says whether it was
//! truncated.

use crate::case::audit::{self, AuditEntry};
use crate::case::notes::{self, Note, NoteTarget};
use crate::case::write::FindingStatus;
use crate::detect::enrich::accounts::{AccountRow, read_accounts};
use crate::detect::enrich::facts::{FAMILIES, FindingFacts};
use crate::detect::load::RuleSet;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::{Connection, ToSql, params_from_iter};
use serde::{Serialize, Serializer};
use serde_json::Value;

const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];
const REVIEW_STATES: &[&str] = &["pending_review", "accepted", "discarded"];

/// `ORDER BY` rank of `severity` (critical first).
const SEVERITY_RANK: &str = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 \
     WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END";

fn ts<S: Serializer>(t: &DateTime<Utc>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&audit::ts_text(t))
}

fn ts_opt<S: Serializer>(t: &Option<DateTime<Utc>>, s: S) -> std::result::Result<S::Ok, S::Error> {
    match t {
        Some(t) => ts(t, s),
        None => s.serialize_none(),
    }
}

fn at(us: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(us).unwrap_or_default()
}

/// A JSON array text (DuckDB `to_json` of a list) as strings.
fn strings(json: Option<String>) -> Vec<String> {
    json.and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok())
        .unwrap_or_default()
}

fn one_of(what: &str, v: Option<&str>, allowed: &[&str]) -> Result<()> {
    match v {
        Some(v) if !allowed.contains(&v) => Err(Error::Invalid(format!(
            "unknown {what} {v:?} ({})",
            allowed.join(", ")
        ))),
        _ => Ok(()),
    }
}

// ------------------------------------------------------------------ findings

#[derive(Debug, Clone, Default)]
pub struct FindingFilter {
    pub status: Option<String>,
    /// The minimum severity (info < low < medium < high < critical).
    pub severity: Option<String>,
    /// Rule ids, exact; a finding of any of them matches (none: every rule).
    pub rule: Vec<String>,
    /// The finding's actor (case-insensitive).
    pub user: Option<String>,
    pub tenant: Option<String>,
    pub rule_updated: Option<bool>,
    pub review_state: Option<String>,
}

/// A finding with its decision and review tags and its evidence count.
#[derive(Debug, Clone, Serialize)]
pub struct FindingRow {
    pub finding_id: String,
    pub tenant_key: String,
    pub rule_id: Option<String>,
    pub rule_version: Option<i32>,
    pub severity: String,
    pub title: String,
    pub actor_upn: Option<String>,
    #[serde(serialize_with = "ts_opt")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(serialize_with = "ts_opt")]
    pub last_seen: Option<DateTime<Utc>>,
    pub status: String,
    pub disposition_reason: Option<String>,
    pub created_by: String,
    pub assigned_to: Option<String>,
    pub rule_updated: bool,
    #[serde(serialize_with = "ts")]
    pub created_at: DateTime<Utc>,
    #[serde(serialize_with = "ts")]
    pub updated_at: DateTime<Utc>,
    pub decided_by: Option<String>,
    #[serde(serialize_with = "ts_opt")]
    pub decided_at: Option<DateTime<Utc>>,
    pub on_behalf_of: Option<String>,
    pub review_state: Option<String>,
    pub reviewed_by: Option<String>,
    #[serde(serialize_with = "ts_opt")]
    pub reviewed_at: Option<DateTime<Utc>>,
    pub review_comment: Option<String>,
    pub evidence_count: i64,
}

/// The findings matching `filter` in list order, at most `limit` of them (all when `None`).
fn finding_rows(
    conn: &Connection,
    filter: &str,
    args: &[&dyn ToSql],
    limit: Option<usize>,
) -> Result<Vec<FindingRow>> {
    let limit = limit.map(|n| format!(" LIMIT {n}")).unwrap_or_default();
    let sql = format!(
        "SELECT f.finding_id, f.tenant_key, f.rule_id, f.rule_version, f.severity, f.title, f.actor_upn, \
                epoch_us(f.first_seen), epoch_us(f.last_seen), CAST(f.status AS VARCHAR), f.disposition_reason, \
                CAST(f.created_by AS VARCHAR), f.assigned_to, f.rule_updated, epoch_us(f.created_at), \
                epoch_us(f.updated_at), f.decided_by, epoch_us(f.decided_at), f.on_behalf_of, \
                CAST(f.review_state AS VARCHAR), f.reviewed_by, epoch_us(f.reviewed_at), f.review_comment, \
                (SELECT count(*) FROM finding_evidence fe WHERE fe.finding_id = f.finding_id) \
         FROM findings f WHERE {filter} \
         ORDER BY {SEVERITY_RANK}, f.last_seen DESC NULLS LAST, f.finding_id{limit}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(args, |r| {
        Ok(FindingRow {
            finding_id: r.get(0)?,
            tenant_key: r.get(1)?,
            rule_id: r.get(2)?,
            rule_version: r.get(3)?,
            severity: r.get(4)?,
            title: r.get(5)?,
            actor_upn: r.get(6)?,
            first_seen: r.get::<_, Option<i64>>(7)?.map(at),
            last_seen: r.get::<_, Option<i64>>(8)?.map(at),
            status: r.get(9)?,
            disposition_reason: r.get(10)?,
            created_by: r.get(11)?,
            assigned_to: r.get(12)?,
            rule_updated: r.get(13)?,
            created_at: at(r.get(14)?),
            updated_at: at(r.get(15)?),
            decided_by: r.get(16)?,
            decided_at: r.get::<_, Option<i64>>(17)?.map(at),
            on_behalf_of: r.get(18)?,
            review_state: r.get(19)?,
            reviewed_by: r.get(20)?,
            reviewed_at: r.get::<_, Option<i64>>(21)?.map(at),
            review_comment: r.get(22)?,
            evidence_count: r.get(23)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// The findings matching `f`: severity (critical first), then the latest `last_seen`, then id.
pub fn finding_list(conn: &Connection, f: &FindingFilter) -> Result<Vec<FindingRow>> {
    Ok(finding_page(conn, f, None)?.rows)
}

/// [`finding_list`], at most `limit` rows (all when `None`), with the filtered total.
pub fn finding_page(
    conn: &Connection,
    f: &FindingFilter,
    limit: Option<usize>,
) -> Result<Page<FindingRow>> {
    if let Some(s) = &f.status {
        FindingStatus::parse(s)?;
    }
    one_of("severity", f.severity.as_deref(), SEVERITIES)?;
    one_of("review state", f.review_state.as_deref(), REVIEW_STATES)?;
    let mut filter = vec!["true".to_string()];
    let mut args: Vec<Box<dyn ToSql>> = Vec::new();
    let mut add = |cond: &str, v: Box<dyn ToSql>| {
        filter.push(cond.to_string());
        args.push(v);
    };
    if let Some(v) = &f.status {
        add("CAST(f.status AS VARCHAR) = ?", Box::new(v.clone()));
    }
    if let Some(v) = &f.severity {
        // SEVERITIES is critical first, as SEVERITY_RANK ranks them.
        let rank = SEVERITIES.iter().position(|s| s == v).unwrap_or(0) as i64;
        add(&format!("{SEVERITY_RANK} <= ?"), Box::new(rank));
    }
    if let Some(v) = &f.user {
        add("lower(f.actor_upn) = lower(?)", Box::new(v.clone()));
    }
    if let Some(v) = &f.tenant {
        add("f.tenant_key = ?", Box::new(v.clone()));
    }
    if let Some(v) = f.rule_updated {
        add("f.rule_updated = ?", Box::new(v));
    }
    if let Some(v) = &f.review_state {
        add("CAST(f.review_state AS VARCHAR) = ?", Box::new(v.clone()));
    }
    // Any of the rule ids (after `add`'s last use: this pushes several arguments).
    if !f.rule.is_empty() {
        let marks = vec!["?"; f.rule.len()].join(", ");
        filter.push(format!("f.rule_id IN ({marks})"));
        for r in &f.rule {
            args.push(Box::new(r.clone()));
        }
    }
    let refs: Vec<&dyn ToSql> = args.iter().map(|b| b.as_ref()).collect();
    let filter = filter.join(" AND ");
    let total: i64 = conn.query_row(
        &format!("SELECT count(*) FROM findings f WHERE {filter}"),
        refs.as_slice(),
        |r| r.get(0),
    )?;
    let rows = finding_rows(conn, &filter, &refs, limit)?;
    Ok(Page {
        truncated: (rows.len() as i64) < total,
        rows,
        total,
    })
}

/// One evidence row of a finding: its provenance, and its timeline row when the table feeds the timeline.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceRow {
    pub source_table: String,
    pub record_key: String,
    pub role: String,
    #[serde(serialize_with = "ts_opt")]
    pub event_time: Option<DateTime<Utc>>,
    /// `<collection folder>/<rel_path>:<line>[-<line>]` per sighting (record_source_refs).
    pub source_refs: Vec<String>,
    pub timeline: Option<TimelineRow>,
    /// The evidence's stored `finding_evidence.context` (what the rule recorded about this row); null when none.
    pub context: Option<Value>,
}

/// The facts of a finding in the facts families (persistence, consent, MFA change), or why they are not there.
/// Serialised flat into `finding show`: `facts`, or `facts_unavailable` (never an empty list or object).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum FactsField {
    Present { facts: FindingFacts },
    Unavailable { facts_unavailable: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingDetail {
    pub finding: FindingRow,
    pub evidence: Vec<EvidenceRow>,
    /// `Some` only for a finding of a rule whose stage is in the facts families; absent otherwise.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub facts: Option<FactsField>,
    /// The rule's `analyst_guidance`, when the rule is in the loaded rule set.
    pub analyst_guidance: Option<String>,
    pub notes: Vec<Note>,
    /// The finding's audit history (decisions and reviews), oldest first.
    pub audit: Vec<AuditEntry>,
}

/// Everything about one finding.
pub fn finding_show(conn: &Connection, id: &str, rules: &RuleSet) -> Result<FindingDetail> {
    let finding = finding_rows(conn, "f.finding_id = ?", &[&id], None)?
        .pop()
        .ok_or_else(|| Error::NotFound(format!("finding {id}")))?;
    let mut stmt = conn.prepare(&format!(
        "SELECT fe.source_table, fe.record_key, CAST(fe.role AS VARCHAR), epoch_us(fe.event_time), \
                to_json(refs.source_refs)::VARCHAR, t.record_key IS NOT NULL, CAST(fe.context AS VARCHAR), {TIMELINE_COLS} \
         FROM finding_evidence fe \
         LEFT JOIN record_source_refs refs ON refs.table_name = fe.source_table AND refs.record_key = fe.record_key \
         LEFT JOIN timeline t ON t.source_table = fe.source_table AND t.record_key = fe.record_key \
         WHERE fe.finding_id = ? \
         ORDER BY fe.event_time NULLS LAST, fe.source_table, fe.record_key"
    ))?;
    let rows = stmt.query_map([id], |r| {
        Ok(EvidenceRow {
            source_table: r.get(0)?,
            record_key: r.get(1)?,
            role: r.get(2)?,
            event_time: r.get::<_, Option<i64>>(3)?.map(at),
            source_refs: strings(r.get(4)?),
            timeline: if r.get::<_, bool>(5)? {
                Some(timeline_row(r, 7)?)
            } else {
                None
            },
            context: r
                .get::<_, Option<String>>(6)?
                .and_then(|c| serde_json::from_str(&c).ok()),
        })
    })?;
    let evidence = rows.collect::<std::result::Result<_, _>>()?;
    let analyst_guidance = finding.rule_id.as_deref().and_then(|rid| {
        rules
            .rules
            .iter()
            .find(|l| l.rule.id == rid)
            .map(|l| l.rule.analyst_guidance.clone())
    });
    let facts = facts_field(conn, id, finding.rule_id.as_deref(), rules)?;
    Ok(FindingDetail {
        notes: notes::notes_for(conn, &NoteTarget::Finding(id.to_string()))?,
        audit: audit::log(conn, Some(("finding", id)))?,
        finding,
        evidence,
        facts,
        analyst_guidance,
    })
}

// ---------------------------------------------------------------- enrichment

/// A `case_meta` value.
fn meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM case_meta WHERE key = ?", [key], |r| {
            r.get(0)
        })
        .ok())
}

// STUB (agent accuracy T4): the single decision "may a reader show facts?" belongs to
// `detect::enrich::enrichment_state` (Tasks 1-2 review). This local copy has the same name, variants and
// signature; at merge, delete it and import `crate::detect::enrich::{EnrichState, enrichment_state}`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EnrichState {
    /// The tables were rebuilt by the latest detection run.
    Ok { run_id: i64 },
    /// No enrichment has ever run (a case detected before the feature).
    Never,
    /// The last enrichment failed.
    Failed { reason: String },
    /// Enrichment ran for an earlier detection run than the latest one.
    Stale { enriched_run: i64, latest_run: i64 },
}

fn enrichment_state(conn: &Connection) -> Result<EnrichState> {
    if let Some(reason) = meta(conn, "enrichment_error")? {
        return Ok(EnrichState::Failed { reason });
    }
    let Some(run) = meta(conn, "enrichment_run_id")? else {
        return Ok(EnrichState::Never);
    };
    let enriched_run: i64 = run.parse().map_err(|_| {
        Error::Invalid(format!(
            "case_meta enrichment_run_id {run:?} is not a run id"
        ))
    })?;
    let latest: Option<i64> = conn
        .query_row("SELECT max(run_id) FROM detection_runs", [], |r| r.get(0))
        .unwrap_or(None);
    Ok(match latest {
        Some(latest_run) if latest_run > enriched_run => EnrichState::Stale {
            enriched_run,
            latest_run,
        },
        _ => EnrichState::Ok {
            run_id: enriched_run,
        },
    })
}

/// Why the enrichment tables cannot be read as facts, `None` for [`EnrichState::Ok`]. Readers say this instead
/// of offering an empty list or stale rows.
fn enrichment_unavailable(conn: &Connection) -> Result<Option<String>> {
    Ok(match enrichment_state(conn)? {
        EnrichState::Ok { .. } => None,
        EnrichState::Never => {
            Some("detection has not run since this version; run `sparrow detect`".to_string())
        }
        EnrichState::Stale {
            enriched_run,
            latest_run,
        } => Some(format!(
            "the facts are from detection run {enriched_run} but run {latest_run} is newer; run `sparrow detect`"
        )),
        EnrichState::Failed { reason } => Some(format!(
            "the last enrichment failed: {reason}; run `sparrow detect` again"
        )),
    })
}

/// The `facts` of finding `id`: only for a finding of a rule whose stage is in the facts families.
fn facts_field(
    conn: &Connection,
    id: &str,
    rule_id: Option<&str>,
    rules: &RuleSet,
) -> Result<Option<FactsField>> {
    let in_families = rule_id.is_some_and(|rid| {
        rules
            .rules
            .iter()
            .find(|l| l.rule.id == rid)
            .is_some_and(|l| l.rule.stage.iter().any(|s| FAMILIES.contains(s)))
    });
    if !in_families {
        return Ok(None);
    }
    if let Some(why) = enrichment_unavailable(conn)? {
        return Ok(Some(FactsField::Unavailable {
            facts_unavailable: why,
        }));
    }
    let stored: Option<String> = conn
        .query_row(
            "SELECT CAST(facts AS VARCHAR) FROM finding_facts WHERE finding_id = ?",
            [id],
            |r| r.get(0),
        )
        .ok();
    Ok(Some(
        match stored.map(|s| serde_json::from_str::<FindingFacts>(&s)) {
            Some(Ok(facts)) => FactsField::Present { facts },
            Some(Err(e)) => FactsField::Unavailable {
                facts_unavailable: format!(
                    "the stored facts cannot be read ({e}); run `sparrow detect`"
                ),
            },
            None => FactsField::Unavailable {
                facts_unavailable: "no facts were stored for this finding; run `sparrow detect`"
                    .to_string(),
            },
        },
    ))
}

/// The account roll-up in reader order (worst severity, stages, first suspicious, upn).
#[derive(Debug, Clone, Serialize)]
pub struct AccountPage {
    pub accounts: Vec<AccountRow>,
    /// Accounts before the limit (of the tenant, when one was asked for).
    pub total: u64,
    pub truncated: bool,
    /// Why the list may be incomplete: a case detected before the roll-up existed, or a failed enrichment. Empty
    /// when the roll-up is current.
    pub warnings: Vec<String>,
}

/// The roll-up of `tenant` (all tenants when `None`), at most `limit` accounts. When the enrichment tables are
/// not current (see [`enrichment_unavailable`]) the list is empty and a warning names the reason: never silently
/// empty, and never stale rows.
pub fn accounts(
    conn: &Connection,
    tenant: Option<&str>,
    limit: Option<usize>,
) -> Result<AccountPage> {
    if let Some(why) = enrichment_unavailable(conn)? {
        return Ok(AccountPage {
            accounts: Vec::new(),
            total: 0,
            truncated: false,
            warnings: vec![format!("account roll-up unavailable: {why}")],
        });
    }
    let mut all = read_accounts(conn)?;
    if let Some(t) = tenant {
        all.retain(|a| a.tenant_key == t);
    }
    let total = all.len() as u64;
    let truncated = limit.is_some_and(|l| all.len() > l);
    if let Some(l) = limit {
        all.truncate(l);
    }
    Ok(AccountPage {
        accounts: all,
        total,
        truncated,
        warnings: Vec::new(),
    })
}

/// The `addresses` section of `pivot user`: the account's roll-up addresses (every tenant the UPN has a row in),
/// each as the roll-up stores it. Empty when the account has no roll-up row, or the case has no roll-up yet.
fn addresses_section(conn: &Connection, upn: &str, cap: usize) -> Result<PivotSection> {
    let rows: Vec<AccountRow> = if enrichment_unavailable(conn)?.is_some() {
        Vec::new()
    } else {
        read_accounts(conn)?
            .into_iter()
            .filter(|a| a.upn.eq_ignore_ascii_case(upn.trim()))
            .collect()
    };
    let total: i64 = rows.iter().map(|a| i64::from(a.addresses_total)).sum();
    let out: Vec<Value> = rows
        .iter()
        .flat_map(|a| a.addresses.iter())
        .take(cap)
        .map(|x| serde_json::to_value(x).unwrap_or(Value::Null))
        .collect();
    Ok(PivotSection {
        name: "addresses".into(),
        truncated: total > out.len() as i64,
        total,
        rows: out,
    })
}

// ------------------------------------------------------------------ timeline

/// The `timeline` view's columns, in `timeline_row` order (`t` is the view's alias).
const TIMELINE_COLS: &str = "epoch_us(t.event_time), t.time_tz_assumed, t.source_table, t.record_key, \
     CAST(t.category AS VARCHAR), t.operation, t.actor_upn, t.target, t.ip, t.ip_country, t.ip_asn_org, \
     t.user_agent, t.summary, to_json(t.source_refs)::VARCHAR, t.finding_count, to_json(t.finding_ids)::VARCHAR";

/// One row of the `timeline` view.
#[derive(Debug, Clone, Serialize)]
pub struct TimelineRow {
    #[serde(serialize_with = "ts")]
    pub event_time: DateTime<Utc>,
    pub time_tz_assumed: Option<bool>,
    pub source_table: String,
    pub record_key: String,
    pub category: String,
    pub operation: Option<String>,
    pub actor_upn: Option<String>,
    pub target: Option<String>,
    pub ip: Option<String>,
    pub ip_country: Option<String>,
    pub ip_asn_org: Option<String>,
    pub user_agent: Option<String>,
    pub summary: Option<String>,
    pub source_refs: Vec<String>,
    pub finding_count: i64,
    pub finding_ids: Vec<String>,
}

fn timeline_row(r: &duckdb::Row<'_>, o: usize) -> duckdb::Result<TimelineRow> {
    Ok(TimelineRow {
        event_time: at(r.get::<_, Option<i64>>(o)?.unwrap_or_default()),
        time_tz_assumed: r.get(o + 1)?,
        source_table: r.get(o + 2)?,
        record_key: r.get(o + 3)?,
        category: r.get(o + 4)?,
        operation: r.get(o + 5)?,
        actor_upn: r.get(o + 6)?,
        target: r.get(o + 7)?,
        ip: r.get(o + 8)?,
        ip_country: r.get(o + 9)?,
        ip_asn_org: r.get(o + 10)?,
        user_agent: r.get(o + 11)?,
        summary: r.get(o + 12)?,
        source_refs: strings(r.get(o + 13)?),
        finding_count: r.get::<_, Option<i64>>(o + 14)?.unwrap_or(0),
        finding_ids: strings(r.get(o + 15)?),
    })
}

#[derive(Debug, Clone, Default)]
pub struct TimelineFilter {
    /// The actor or the target (case-insensitive).
    pub user: Option<String>,
    /// Case-insensitive (IPv6 text may differ in case).
    pub ip: Option<String>,
    pub category: Option<String>,
    /// Inclusive bounds on the event time.
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// Rows cited as evidence by this finding.
    pub finding: Option<String>,
    pub limit: usize,
}

/// A capped list: `total` is the full count, `truncated` says rows were left out.
#[derive(Debug, Clone, Serialize)]
pub struct Page<T> {
    pub rows: Vec<T>,
    pub truncated: bool,
    pub total: i64,
}

/// The `WHERE` clause (over the `timeline` view aliased `t`) and its text arguments for `f`; the category is
/// checked against the enum first.
pub fn timeline_where(conn: &Connection, f: &TimelineFilter) -> Result<(String, Vec<String>)> {
    if let Some(c) = &f.category {
        let known: bool = conn.query_row(
            "SELECT ? IN (SELECT unnest(enum_range(NULL::event_category))::VARCHAR)",
            [c],
            |r| r.get(0),
        )?;
        if !known {
            return Err(Error::Invalid(format!("unknown timeline category {c:?}")));
        }
    }
    let mut filter = vec!["true".to_string()];
    let mut args: Vec<String> = Vec::new();
    if let Some(u) = &f.user {
        filter.push("(lower(t.actor_upn) = lower(?) OR lower(t.target) = lower(?))".into());
        args.push(u.clone());
        args.push(u.clone());
    }
    if let Some(v) = &f.ip {
        filter.push("lower(t.ip) = lower(?)".into());
        args.push(v.clone());
    }
    if let Some(v) = &f.category {
        filter.push("CAST(t.category AS VARCHAR) = ?".into());
        args.push(v.clone());
    }
    if let Some(v) = &f.from {
        filter.push("t.event_time >= CAST(? AS TIMESTAMPTZ)".into());
        args.push(audit::ts_text(v));
    }
    if let Some(v) = &f.to {
        filter.push("t.event_time <= CAST(? AS TIMESTAMPTZ)".into());
        args.push(audit::ts_text(v));
    }
    if let Some(v) = &f.finding {
        filter.push("list_contains(t.finding_ids, ?)".into());
        args.push(v.clone());
    }
    Ok((filter.join(" AND "), args))
}

/// The timeline rows matching `f`, by event time, then table and key; at most `f.limit`.
pub fn timeline_query(conn: &Connection, f: &TimelineFilter) -> Result<Page<TimelineRow>> {
    let (filter, args) = timeline_where(conn, f)?;
    let total: i64 = conn.query_row(
        &format!("SELECT count(*) FROM timeline t WHERE {filter}"),
        params_from_iter(args.iter()),
        |r| r.get(0),
    )?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {TIMELINE_COLS} FROM timeline t WHERE {filter} \
         ORDER BY t.event_time, t.source_table, t.record_key LIMIT {}",
        f.limit
    ))?;
    let rows = stmt.query_map(params_from_iter(args.iter()), |r| timeline_row(r, 0))?;
    let rows: Vec<TimelineRow> = rows.collect::<std::result::Result<_, _>>()?;
    Ok(Page {
        truncated: total > rows.len() as i64,
        total,
        rows,
    })
}

// ------------------------------------------------------------------ pivots

#[derive(Debug, Clone, Serialize)]
pub struct PivotSection {
    pub name: String,
    /// At most the cap, each row as JSON (DuckDB `to_json`).
    pub rows: Vec<Value>,
    pub total: i64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Pivot {
    pub sections: Vec<PivotSection>,
}

/// One section: the rows of `query` (bound to `args`) ordered by `order`, at most `cap`, with the full count.
fn section(
    conn: &Connection,
    name: &str,
    query: &str,
    order: &str,
    args: &[&str],
    cap: usize,
) -> Result<PivotSection> {
    let total: i64 = conn.query_row(
        &format!("SELECT count(*) FROM ({query}) q"),
        params_from_iter(args.iter()),
        |r| r.get(0),
    )?;
    let mut stmt = conn.prepare(&format!(
        "SELECT to_json(q)::VARCHAR FROM ({query}) q ORDER BY {order} LIMIT {cap}"
    ))?;
    let rows = stmt.query_map(params_from_iter(args.iter()), |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        let text = row?;
        out.push(serde_json::from_str(&text).unwrap_or(Value::String(text)));
    }
    Ok(PivotSection {
        name: name.into(),
        truncated: total > out.len() as i64,
        total,
        rows: out,
    })
}

const TIMELINE_JSON: &str = "SELECT t.event_time, t.source_table, t.record_key, CAST(t.category AS VARCHAR) AS category, \
     t.operation, t.actor_upn, t.target, t.ip, t.ip_country, t.ip_asn_org, t.user_agent, t.summary, t.source_refs, \
     t.finding_ids FROM timeline t";
const TIMELINE_ORDER: &str = "q.event_time, q.source_table, q.record_key";
const FINDING_JSON: &str = "SELECT f.finding_id, f.tenant_key, f.rule_id, f.severity, f.title, f.actor_upn, \
     f.first_seen, f.last_seen, CAST(f.status AS VARCHAR) AS status, f.decided_by, f.on_behalf_of, \
     CAST(f.review_state AS VARCHAR) AS review_state FROM findings f";
const FINDING_ORDER: &str = "CASE q.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 \
     WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, q.last_seen DESC NULLS LAST, q.finding_id";
const INDICATOR_JSON: &str = "SELECT indicator_id, tenant_key, CAST(type AS VARCHAR) AS type, value, \
     CAST(verdict AS VARCHAR) AS verdict, note, decided_by, on_behalf_of, CAST(review_state AS VARCHAR) AS review_state \
     FROM case_indicators WHERE removed_at IS NULL";

/// Everything the case knows about one IP: ip_intel, spray_source, timeline, findings (citing its timeline rows),
/// indicators. Each section holds at most `cap` rows.
pub fn pivot_ip(conn: &Connection, ip: &str, cap: usize) -> Result<Pivot> {
    Ok(Pivot {
        sections: vec![
            section(
                conn,
                "ip_intel",
                "SELECT * FROM ip_intel WHERE lower(ip) = lower(?)",
                "q.ip",
                &[ip],
                cap,
            )?,
            section(
                conn,
                "spray_source",
                "SELECT * FROM spray_sources WHERE lower(ip) = lower(?)",
                "q.tenant_key",
                &[ip],
                cap,
            )?,
            section(
                conn,
                "timeline",
                &format!("{TIMELINE_JSON} WHERE lower(t.ip) = lower(?)"),
                TIMELINE_ORDER,
                &[ip],
                cap,
            )?,
            section(
                conn,
                "findings",
                &format!(
                    "{FINDING_JSON} WHERE f.finding_id IN (SELECT unnest(finding_ids) FROM timeline WHERE lower(ip) = lower(?))"
                ),
                FINDING_ORDER,
                &[ip],
                cap,
            )?,
            section(
                conn,
                "indicators",
                &format!("{INDICATOR_JSON} AND type = 'ip' AND lower(value) = lower(?)"),
                "q.indicator_id",
                &[ip],
                cap,
            )?,
        ],
    })
}

/// Everything the case knows about one user (case-insensitive UPN): identity (Sparrow's resolved identities, by
/// UPN or alias), directory (the users table), roles, mfa, timeline (as actor or target), findings (as actor, or
/// citing timeline rows where the user is the actor or the target), indicators (upn or email). Each section holds at most `cap` rows.
pub fn pivot_user(conn: &Connection, upn: &str, cap: usize) -> Result<Pivot> {
    Ok(Pivot {
        sections: vec![
            section(
                conn,
                "identity",
                "SELECT * FROM identities WHERE lower(upn) = lower(?) OR identity_id IN \
                 (SELECT identity_id FROM identity_aliases WHERE lower(alias) = lower(?))",
                "q.tenant_key, q.identity_id",
                &[upn, upn],
                cap,
            )?,
            section(
                conn,
                "directory",
                "SELECT * EXCLUDE (raw, column_collections, tz_assumed) FROM users WHERE lower(upn) = lower(?)",
                "q.collected_at DESC NULLS LAST, q.record_key",
                &[upn],
                cap,
            )?,
            section(
                conn,
                "roles",
                "SELECT * EXCLUDE (raw, column_collections, tz_assumed) FROM role_assignments \
                 WHERE lower(principal_upn) = lower(?)",
                "q.role_name, q.record_key",
                &[upn],
                cap,
            )?,
            section(
                conn,
                "mfa",
                "SELECT * EXCLUDE (raw, column_collections, tz_assumed) FROM mfa_registration WHERE lower(upn) = lower(?)",
                "q.collected_at DESC NULLS LAST, q.record_key",
                &[upn],
                cap,
            )?,
            section(
                conn,
                "timeline",
                &format!(
                    "{TIMELINE_JSON} WHERE lower(t.actor_upn) = lower(?) OR lower(t.target) = lower(?)"
                ),
                TIMELINE_ORDER,
                &[upn, upn],
                cap,
            )?,
            section(
                conn,
                "findings",
                &format!(
                    "{FINDING_JSON} WHERE lower(f.actor_upn) = lower(?) OR f.finding_id IN \
                     (SELECT unnest(finding_ids) FROM timeline \
                      WHERE lower(actor_upn) = lower(?) OR lower(target) = lower(?))"
                ),
                FINDING_ORDER,
                &[upn, upn, upn],
                cap,
            )?,
            section(
                conn,
                "indicators",
                &format!(
                    "{INDICATOR_JSON} AND type IN ('upn', 'email') AND lower(value) = lower(?)"
                ),
                "q.indicator_id",
                &[upn],
                cap,
            )?,
            addresses_section(conn, upn, cap)?,
        ],
    })
}
