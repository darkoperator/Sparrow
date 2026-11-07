//! `sparrow coverage`: which evidence covers each account, over which dates, and what to request next. Opens the case
//! read-only; nothing is written and no audit entry is added.

use crate::{open_read, print_json};
use anyhow::Result;
use clap::Args;
use sparrow_core::case::collector::incomplete_collection;
use sparrow_core::case::coverage::{
    AccountCoverage, CollectorRequest, CoverageOptions, Request, SourceCoverage, coverage,
    thousands,
};
use sparrow_core::case::text::display_safe_line as safe;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Args)]
pub struct CoverageArgs {
    /// Case database file
    #[arg(long)]
    pub case: PathBuf,
    /// Only this tenant key
    #[arg(long)]
    pub tenant: Option<String>,
    /// Only this user (repeatable); default: every account with findings
    #[arg(long = "user")]
    pub user: Vec<String>,
    /// Rule directory (repeatable) whose lists/collection_hints.yaml replaces built-in hints by source; default
    /// $SPARROW_RULES
    #[arg(long)]
    pub rules: Vec<PathBuf>,
}

/// `ual  rows 1,234  2026-06-01..2026-10-25  48 days  SAMPLED`, `ual  absent`, or (no rows, but the collector's
/// manifests vouch for some of the window) `ual  collected, no events  2026-06-01..2026-08-27, 2026-08-31..2026-10-25`,
/// each collected range on its own so the days between them never read as collected.
pub fn source_line(s: &SourceCoverage) -> String {
    if s.collected_no_events && !s.collected.is_empty() {
        let ranges: Vec<String> = s
            .collected
            .iter()
            .map(|r| format!("{}..{}", r.from, r.to))
            .collect();
        return format!("{}  collected, no events  {}", s.source, ranges.join(", "));
    }
    let (Some(first), Some(last)) = (&s.first, &s.last) else {
        return format!("{}  absent", s.source);
    };
    format!(
        "{}  rows {}  {}..{}  {} {}{}",
        s.source,
        thousands(s.rows),
        first.format("%Y-%m-%d"),
        last.format("%Y-%m-%d"),
        s.days,
        if s.days == 1 { "day" } else { "days" },
        if s.sampled { "  SAMPLED" } else { "" }
    )
}

fn print_account(a: &AccountCoverage, requests: &[&Request]) {
    outln!(
        "{}  {}  {}",
        safe(&a.upn),
        safe(&a.tenant_key),
        match &a.window {
            Some(w) => format!("window {}..{}", w.start, w.end),
            None => "window none (the tenant has no events)".to_string(),
        }
    );
    for s in &a.sources {
        outln!("  {}", source_line(s));
    }
    for r in requests {
        outln!(
            "  Request: {}  {}..{}  ({})",
            r.source,
            r.from,
            r.to,
            r.reasons.join(", ")
        );
        let line = |name: &str, how: &Option<String>| {
            outln!(
                "    {name}: {}",
                how.as_deref()
                    .map(safe)
                    .unwrap_or_else(|| "- (no matching command)".to_string())
            );
        };
        line("console", &r.console);
        line("hawk", &r.hawk);
        line("invictus", &r.invictus);
    }
}

/// `{from}..{to}` of the request's open spans, or `undated`.
fn request_range(r: &CollectorRequest) -> String {
    match (r.spans.iter().next(), r.spans.iter().last()) {
        (Some(a), Some(b)) if !r.undated => format!("{}..{}", ts(a.start_us), ts(b.end_us)),
        _ => "undated".to_string(),
    }
}

fn ts(us: i64) -> String {
    chrono::DateTime::from_timestamp_micros(us)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn print_collector_requests(rs: &[CollectorRequest]) {
    if rs.is_empty() {
        return;
    }
    outln!("Collector gaps (re-run these first):");
    for r in rs {
        // A run that stopped before its first unit: no sources known, no unit.
        let sources = if r.sources.is_empty() {
            "unknown sources".to_string()
        } else {
            safe(&r.sources.join(","))
        };
        let unit = if r.unit_id.is_empty() {
            String::new()
        } else {
            format!(" unit {}", safe(&r.unit_id))
        };
        outln!(
            "  {}  {}  {}  run {}{}",
            sources,
            request_range(r),
            safe(&r.reason),
            safe(&r.run_id),
            unit
        );
        if let Some(d) = &r.detail {
            outln!("    detail: {}", safe(d));
        }
        for c in &r.rerun {
            outln!("    rerun: {}", safe(c));
        }
        if let Some(c) = &r.resume {
            outln!("    resume: {}", safe(c));
        }
    }
}

pub fn run(a: CoverageArgs, json: bool) -> Result<ExitCode> {
    let c = open_read(&a.case)?;
    let report = coverage(
        c.conn(),
        &CoverageOptions {
            tenant: a.tenant,
            users: a.user,
            dirs: crate::data_dirs(None, a.rules),
        },
    )?;
    if json {
        print_json(&report)?;
        return Ok(ExitCode::SUCCESS);
    }
    for w in &report.warnings {
        errln!("warning: {w}");
    }
    if let Some(b) = incomplete_collection(c.conn())? {
        errln!("warning: {}", safe(&b.text));
    }
    print_collector_requests(&report.collector_requests);
    for acc in &report.accounts {
        let own: Vec<&Request> = report
            .requests
            .iter()
            .filter(|r| r.tenant_key == acc.tenant_key && r.user == acc.upn)
            .collect();
        print_account(acc, &own);
    }
    if report.accounts.is_empty() {
        outln!("no accounts with findings; name one with --user");
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use sparrow_core::case::coverage::DayRange;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn empty(source: &str) -> SourceCoverage {
        SourceCoverage {
            source: source.to_string(),
            title: String::new(),
            rows: 0,
            first: None,
            last: None,
            days: 0,
            sampled: false,
            gaps: Vec::new(),
            collected: Vec::new(),
            collected_no_events: false,
        }
    }

    #[test]
    fn collected_with_no_events_names_each_collected_range() {
        let mut s = empty("signins_interactive");
        assert_eq!(source_line(&s), "signins_interactive  absent");
        s.collected = vec![
            DayRange {
                from: d("2026-08-02"),
                to: d("2026-08-10"),
            },
            DayRange {
                from: d("2026-08-20"),
                to: d("2026-09-09"),
            },
        ];
        s.collected_no_events = true;
        // The days between the two collected ranges (an open collector gap) must not read as collected.
        assert_eq!(
            source_line(&s),
            "signins_interactive  collected, no events  2026-08-02..2026-08-10, 2026-08-20..2026-09-09"
        );
    }
}
