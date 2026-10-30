//! Read commands (Addendum D.5): `finding list|show`, `timeline`, `timeline-entry list`, `pivot ip|user` and `query`.
//! Each opens the case read-only. Plain output passes agent and evidence text through `display_safe_line` (one-line
//! values) or `display_safe` (multi-line blocks); `--json`
//! prints the stored values.

use crate::{open_read, print_json};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
use sparrow_core::case::read::{self, FindingFilter, Page, Pivot, TimelineFilter, TimelineRow};
use sparrow_core::case::text::{display_safe, display_safe_line as safe};
use sparrow_core::case::{audit, query, timeline_entries};
use sparrow_core::detect::enrich::facts::FindingFacts;
use sparrow_core::detect::load::load_rules;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn opt(s: Option<&str>) -> String {
    s.map(safe).unwrap_or_else(|| "-".into())
}

fn ts(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub(crate) fn time(flag: &str, s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .with_context(|| {
            format!("{flag} must be RFC 3339 (for example 2026-08-03T09:00:00Z), got {s:?}")
        })
}

fn truncated_line(shown: usize, total: i64) {
    if total > shown as i64 {
        outln!("… {} more (truncated)", total - shown as i64);
    }
}

// ------------------------------------------------------------------ accounts

#[derive(Args)]
pub struct AccountsArgs {
    /// Case database file
    #[arg(long)]
    pub case: PathBuf,
    /// Only this tenant key
    #[arg(long)]
    pub tenant: Option<String>,
    /// At most this many accounts (default: all); the output says how many more there are
    #[arg(long)]
    pub limit: Option<usize>,
}

/// The addresses a plain-text account block lists before "+N more".
const ACCOUNT_ADDRESSES_SHOWN: usize = 5;

pub fn accounts(a: AccountsArgs, json: bool) -> Result<ExitCode> {
    let c = open_read(&a.case)?;
    let page = read::accounts(c.conn(), a.tenant.as_deref(), a.limit)?;
    if json {
        print_json(&page)?;
        return Ok(ExitCode::SUCCESS);
    }
    for w in &page.warnings {
        errln!("warning: {w}");
    }
    for acc in &page.accounts {
        outln!(
            "{}  {}  {}  ({} findings)",
            safe(&acc.upn),
            safe(&acc.tenant_key),
            acc.worst_severity,
            acc.finding_count
        );
        let stages: Vec<&str> = acc.stages.iter().map(|s| s.as_str()).collect();
        outln!(
            "  stages {}  first suspicious {}  {}",
            if stages.is_empty() {
                "-".to_string()
            } else {
                stages.join(", ")
            },
            acc.first_suspicious
                .as_ref()
                .map(ts)
                .unwrap_or_else(|| "-".into()),
            match (&acc.signins_first, &acc.signins_last) {
                (Some(first), Some(last)) => format!("sign-ins {} to {}", ts(first), ts(last)),
                _ => "no sign-ins collected".to_string(),
            }
        );
        let covered = acc.signins_first.is_some();
        for x in acc.addresses.iter().take(ACCOUNT_ADDRESSES_SHOWN) {
            outln!(
                "  {}  {}{}{}",
                safe(&x.ip),
                x.reasons.join(", "),
                x.asn_org
                    .as_deref()
                    .map(|o| format!("  {}", safe(o)))
                    .unwrap_or_default(),
                if x.in_user_signins || !covered {
                    ""
                } else {
                    "  (never a sign-in of this account)"
                }
            );
        }
        let shown = acc.addresses.len().min(ACCOUNT_ADDRESSES_SHOWN);
        let more = (acc.addresses_total as usize).saturating_sub(shown);
        if more > 0 {
            outln!("  +{more} more addresses");
        }
    }
    outln!("{} of {} accounts", page.accounts.len(), page.total);
    Ok(ExitCode::SUCCESS)
}

/// The facts of a finding as plain text lines. A count that cannot be compared (null) is "unknown", never 0.
fn facts_lines(facts: &FindingFacts) -> Vec<String> {
    let count = |n: Option<u32>| n.map_or_else(|| "unknown".to_string(), |n| n.to_string());
    let mut out = vec![format!(
        "facts (window start {}):",
        facts
            .window_start
            .as_ref()
            .map(audit::ts_text)
            .unwrap_or_else(|| "unknown".to_string())
    )];
    for ip in &facts.actor_ips {
        out.push(format!(
            "  {}  signed in by this user on {} earlier day(s) within the capture",
            safe(&ip.ip),
            count(ip.user_signin_days_before)
        ));
    }
    out.push(format!(
        "  other findings on this account: {}",
        facts.other_signals.total
    ));
    for s in &facts.other_signals.items {
        out.push(format!("    {} {}", safe(&s.rule_id), safe(&s.severity)));
    }
    for t in facts.targets.iter().flatten() {
        out.push(format!(
            "  target {}  {}  prior messages {}",
            safe(&t.address),
            safe(&t.scope),
            count(t.prior_messages)
        ));
    }
    out
}

fn print_facts(facts: &FindingFacts) {
    for line in facts_lines(facts) {
        outln!("{line}");
    }
}

// ------------------------------------------------------------------ finding list / show

#[derive(Args)]
pub struct FindingListArgs {
    /// Case database file
    #[arg(long)]
    pub case: PathBuf,
    /// new, in_review, confirmed, false_positive, benign or needs_more_data
    #[arg(long)]
    pub status: Option<String>,
    /// The minimum severity: info < low < medium < high < critical
    #[arg(long)]
    pub severity: Option<String>,
    /// Rule id, exact (repeatable: a finding of any of them)
    #[arg(long = "rule")]
    pub rule: Vec<String>,
    /// The finding's actor UPN (case-insensitive)
    #[arg(long)]
    pub user: Option<String>,
    /// Tenant key
    /// Tenant key
    #[arg(long)]
    pub tenant: Option<String>,
    /// true or false
    #[arg(long)]
    pub rule_updated: Option<bool>,
    /// pending_review, accepted or discarded
    #[arg(long)]
    pub review_state: Option<String>,
    /// At most this many findings (default: all); the output says how many more the filters matched
    #[arg(long)]
    pub limit: Option<usize>,
}

pub fn finding_list(a: FindingListArgs, json: bool) -> Result<ExitCode> {
    let c = open_read(&a.case)?;
    let page = read::finding_page(
        c.conn(),
        &FindingFilter {
            status: a.status,
            severity: a.severity,
            rule: a.rule,
            user: a.user,
            tenant: a.tenant,
            rule_updated: a.rule_updated,
            review_state: a.review_state,
        },
        a.limit,
    )?;
    if json {
        print_json(&serde_json::json!({
            "findings": page.rows,
            "total": page.total,
            "truncated": page.truncated,
        }))?;
        return Ok(ExitCode::SUCCESS);
    }
    for f in &page.rows {
        let decision = match (&f.decided_by, &f.review_state) {
            (Some(by), Some(rs)) => format!("  [{} {}]", safe(by), rs),
            _ => String::new(),
        };
        outln!(
            "{}  {:<8} {:<15} {:<12} {}  {}  ({} evidence){}{}",
            f.finding_id,
            f.severity,
            f.status,
            opt(f.rule_id.as_deref()),
            safe(&f.title),
            opt(f.actor_upn.as_deref()),
            f.evidence_count,
            if f.rule_updated { "  RULE UPDATED" } else { "" },
            decision
        );
    }
    truncated_line(page.rows.len(), page.total);
    outln!("{} findings", page.total);
    Ok(ExitCode::SUCCESS)
}

/// Evidence rows `finding show` prints without `--all`.
const SHOW_EVIDENCE: usize = 50;

/// Finding ids `finding show` takes in one call.
pub const SHOW_MAX_IDS: usize = 50;

/// The rule line between findings when `finding show` prints several.
fn show_separator() -> String {
    "─".repeat(72)
}

/// `finding show`: one id prints its finding exactly as it always has (an unknown id is an error). Several ids print
/// each finding in argument order (a repeated id once): `--json` `{"findings": [...], "missing": [...]}`, plain the
/// blocks separated by a rule line, then `not found: <ids>`; exit 2 when any id is unknown.
pub fn finding_show(
    case: &Path,
    ids: &[String],
    data: Option<PathBuf>,
    rules: Vec<PathBuf>,
    all: bool,
    json: bool,
) -> Result<ExitCode> {
    if ids.len() > SHOW_MAX_IDS {
        anyhow::bail!(
            "finding show takes at most {SHOW_MAX_IDS} finding ids at once, got {}",
            ids.len()
        );
    }
    let c = open_read(case)?;
    let set = load_rules(&crate::data_dirs(data, rules))?;
    if let [id] = ids {
        let d = read::finding_show(c.conn(), id, &set)?;
        if json {
            print_json(&d)?;
        } else {
            print_finding(&d, all);
        }
        return Ok(ExitCode::SUCCESS);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for id in ids.iter().filter(|id| seen.insert(id.as_str())) {
        match read::finding_show(c.conn(), id, &set) {
            Ok(d) => found.push(d),
            Err(sparrow_core::Error::NotFound(_)) => missing.push(id.clone()),
            Err(e) => return Err(e.into()),
        }
    }
    if json {
        print_json(&serde_json::json!({ "findings": found, "missing": missing }))?;
    } else {
        for d in &found {
            print_finding(d, all);
            outln!("{}", show_separator());
        }
        if !missing.is_empty() {
            outln!(
                "not found: {}",
                missing
                    .iter()
                    .map(|m| safe(m))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    Ok(if missing.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

/// One finding's plain block, as `finding show <id>` prints it.
fn print_finding(d: &read::FindingDetail, all: bool) {
    let f = &d.finding;
    outln!("{}  {}  {}", f.finding_id, f.severity, safe(&f.title));
    outln!(
        "  rule {}  tenant {}  actor {}",
        opt(f.rule_id.as_deref()),
        safe(&f.tenant_key),
        opt(f.actor_upn.as_deref())
    );
    outln!(
        "  seen {} .. {}{}",
        f.first_seen.as_ref().map(ts).unwrap_or_else(|| "-".into()),
        f.last_seen.as_ref().map(ts).unwrap_or_else(|| "-".into()),
        if f.rule_updated { "  RULE UPDATED" } else { "" }
    );
    outln!(
        "  status {}{}  assigned {}",
        f.status,
        f.disposition_reason
            .as_deref()
            .map(|r| format!(" ({})", safe(r)))
            .unwrap_or_default(),
        opt(f.assigned_to.as_deref())
    );
    match &f.decided_by {
        Some(by) => outln!(
            "  decided by {}{}  review {}{}",
            safe(by),
            f.on_behalf_of
                .as_deref()
                .map(|a| format!(" for {}", safe(a)))
                .unwrap_or_default(),
            f.review_state.as_deref().unwrap_or("-"),
            f.reviewed_by
                .as_deref()
                .map(|r| format!(" by {}", safe(r)))
                .unwrap_or_default()
        ),
        None => outln!("  no decision yet"),
    }
    if let Some(g) = &d.analyst_guidance {
        outln!("guidance:");
        for line in g.lines() {
            outln!("  {}", display_safe(line));
        }
    }
    match &d.facts {
        Some(read::FactsField::Present { facts }) => {
            print_facts(facts);
        }
        Some(read::FactsField::Unavailable { facts_unavailable }) => {
            outln!("facts unavailable: {}", safe(facts_unavailable));
        }
        None => {}
    }
    outln!("evidence ({}):", d.evidence.len());
    let shown = if all {
        d.evidence.len()
    } else {
        d.evidence.len().min(SHOW_EVIDENCE)
    };
    for e in &d.evidence[..shown] {
        let what = e
            .timeline
            .as_ref()
            .map(|t| {
                format!(
                    "  {}  {}",
                    opt(t.actor_upn.as_deref()),
                    opt(t.summary.as_deref())
                )
            })
            .unwrap_or_default();
        outln!(
            "  {} {}:{}{}  [{}]",
            e.event_time.as_ref().map(ts).unwrap_or_else(|| "-".into()),
            e.source_table,
            safe(&e.record_key),
            what,
            safe(&e.source_refs.join(", "))
        );
    }
    if shown < d.evidence.len() {
        outln!(
            "  … {} more (use --json or --all)",
            d.evidence.len() - shown
        );
    }
    if !d.notes.is_empty() {
        outln!("notes:");
        for n in &d.notes {
            outln!(
                "  {} {}: {}",
                audit::ts_text(&n.created_at),
                safe(&n.actor),
                safe(&n.text)
            );
        }
    }
    if !d.audit.is_empty() {
        outln!("history:");
        for e in &d.audit {
            outln!(
                "  {} {} {} {}{}",
                e.seq,
                audit::ts_text(&e.ts),
                safe(&e.actor),
                safe(&e.action),
                e.reason
                    .as_deref()
                    .map(|r| format!(" ({})", safe(r)))
                    .unwrap_or_default()
            );
        }
    }
}

// ------------------------------------------------------------------ timeline

#[derive(Args)]
pub struct TimelineArgs {
    /// Case database file
    #[arg(long)]
    pub case: PathBuf,
    /// Actor or target UPN (case-insensitive)
    #[arg(long)]
    pub user: Option<String>,
    /// Source IP address
    #[arg(long)]
    pub ip: Option<String>,
    /// Event category (auth, mail_flow, config_change, ...)
    #[arg(long)]
    pub category: Option<String>,
    /// From this time (inclusive, RFC 3339)
    #[arg(long)]
    pub from: Option<String>,
    /// Up to this time (inclusive, RFC 3339)
    #[arg(long)]
    pub to: Option<String>,
    /// Only the rows this finding cites as evidence
    #[arg(long)]
    pub finding: Option<String>,
    /// At most this many rows
    #[arg(long, default_value_t = 200)]
    pub limit: usize,
}

fn print_timeline_row(r: &TimelineRow) {
    outln!(
        "{}  {:<20} {:<14} {:<28} {:<32} {:<15} {}",
        ts(&r.event_time),
        r.source_table,
        r.category,
        opt(r.operation.as_deref()),
        opt(r.actor_upn.as_deref()),
        opt(r.ip.as_deref()),
        opt(r.summary.as_deref())
    );
}

pub fn timeline(a: TimelineArgs, json: bool) -> Result<ExitCode> {
    let filter = TimelineFilter {
        user: a.user,
        ip: a.ip,
        category: a.category,
        from: a.from.as_deref().map(|s| time("--from", s)).transpose()?,
        to: a.to.as_deref().map(|s| time("--to", s)).transpose()?,
        finding: a.finding,
        limit: a.limit,
    };
    let c = open_read(&a.case)?;
    let page: Page<TimelineRow> = read::timeline_query(c.conn(), &filter)?;
    if json {
        print_json(&page)?;
        return Ok(ExitCode::SUCCESS);
    }
    for r in &page.rows {
        print_timeline_row(r);
    }
    truncated_line(page.rows.len(), page.total);
    Ok(ExitCode::SUCCESS)
}

// ------------------------------------------------------------------ timeline-entry list

pub fn timeline_entry_list(
    case: &Path,
    status: Option<&str>,
    review_state: Option<&str>,
    json: bool,
) -> Result<ExitCode> {
    let c = open_read(case)?;
    let entries = timeline_entries::list(c.conn(), status, review_state)?;
    if json {
        print_json(&serde_json::json!({ "entries": entries }))?;
        return Ok(ExitCode::SUCCESS);
    }
    for e in &entries {
        outln!(
            "{}  {}  {:<10} {:<15} {:<16} {}  ({} evidence; {} {}){}",
            e.entry_id,
            ts(&e.event_time),
            e.status,
            e.phase,
            e.review_state,
            safe(&e.title),
            e.evidence.len(),
            safe(&e.decided_by),
            e.on_behalf_of
                .as_deref()
                .map(|a| format!("for {}", safe(a)))
                .unwrap_or_default(),
            e.supersedes
                .as_deref()
                .map(|s| format!("  supersedes {s}"))
                .unwrap_or_default()
        );
    }
    outln!("{} entries", entries.len());
    Ok(ExitCode::SUCCESS)
}

// ------------------------------------------------------------------ pivot

#[derive(Subcommand)]
pub enum PivotCommand {
    /// Everything about an IP: ip_intel, spray source, timeline, findings, indicators
    Ip {
        /// The IP address (IPv4 or IPv6)
        ip: String,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Rows per section
        #[arg(long, default_value_t = 50)]
        cap: usize,
    },
    /// Everything about a user: identity, directory, roles, MFA, timeline, findings, indicators
    User {
        /// The user principal name
        upn: String,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Rows per section
        #[arg(long, default_value_t = 50)]
        cap: usize,
    },
}

pub fn pivot(cmd: PivotCommand, json: bool) -> Result<ExitCode> {
    let p: Pivot = match cmd {
        PivotCommand::Ip { ip, case, cap } => read::pivot_ip(open_read(&case)?.conn(), &ip, cap)?,
        PivotCommand::User { upn, case, cap } => {
            read::pivot_user(open_read(&case)?.conn(), &upn, cap)?
        }
    };
    if json {
        print_json(&p)?;
        return Ok(ExitCode::SUCCESS);
    }
    for s in &p.sections {
        if let Some(why) = &s.unavailable {
            outln!("== {}", s.name);
            outln!("  {} unavailable: {}", s.name, safe(why));
            continue;
        }
        outln!("== {} ({})", s.name, s.total);
        for r in &s.rows {
            outln!("  {}", safe(&r.to_string()));
        }
        truncated_line(s.rows.len(), s.total);
    }
    Ok(ExitCode::SUCCESS)
}

// ------------------------------------------------------------------ query

pub fn query(case: &Path, sql: &str, limit: usize, json: bool) -> Result<ExitCode> {
    // The query attaches the file itself; the case is opened (and closed) first for its warnings. A shared view (the
    // app's agent bridge) is queried on its own locked connection instead: the process already holds the file.
    let c = open_read(case)?;
    let r = if c.is_shared_view() {
        query::run_on(&c, sql, limit, 0)?
    } else {
        drop(c);
        query::run(case, sql, limit)?
    };
    if json {
        print_json(&r)?;
        return Ok(ExitCode::SUCCESS);
    }
    outln!(
        "{}",
        r.columns
            .iter()
            .map(|c| safe(c))
            .collect::<Vec<_>>()
            .join("\t")
    );
    for row in &r.rows {
        let cells: Vec<String> = row
            .iter()
            .map(|v| match v {
                serde_json::Value::String(s) => safe(s),
                serde_json::Value::Null => "NULL".into(),
                other => safe(&other.to_string()),
            })
            .collect();
        outln!("{}", cells.join("\t"));
    }
    if r.truncated {
        outln!("… more rows (truncated at {limit}; raise --limit)");
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sparrow_core::detect::enrich::facts::{ActorIp, OtherSignals, Target};

    fn facts(days: Option<u32>, prior: Option<u32>, window: bool) -> FindingFacts {
        FindingFacts {
            facts_version: 1,
            window_start: window.then(|| DateTime::from_timestamp(1_786_000_000, 0).unwrap()),
            actor_ips: vec![ActorIp {
                ip: "203.0.113.7".into(),
                asn: None,
                asn_org: None,
                is_hosting: None,
                spray_source: false,
                user_signin_days_before: days,
                user_first_signin: None,
            }],
            other_signals: OtherSignals {
                total: 0,
                items: vec![],
            },
            targets: Some(vec![Target {
                address: "bob@partner.example".into(),
                domain: "partner.example".into(),
                scope: "external".into(),
                prior_messages: prior,
            }]),
        }
    }

    #[test]
    fn a_null_count_is_unknown_never_zero() {
        let text = facts_lines(&facts(None, None, false)).join("\n");
        assert!(text.contains("window start unknown"), "{text}");
        assert!(text.contains("on unknown earlier day(s)"), "{text}");
        assert!(text.contains("prior messages unknown"), "{text}");
        // A known zero is printed as 0, and is not the same text as unknown.
        let zero = facts_lines(&facts(Some(0), Some(0), true)).join("\n");
        assert!(
            zero.contains("on 0 earlier day(s)") && zero.contains("prior messages 0"),
            "{zero}"
        );
        assert!(!zero.contains("unknown"), "{zero}");
        let three = facts_lines(&facts(Some(3), Some(14), true)).join("\n");
        assert!(
            three.contains("on 3 earlier day(s)") && three.contains("prior messages 14"),
            "{three}"
        );
    }
}
