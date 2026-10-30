//! `sparrow coverage`: which evidence covers each account, over which dates, and what to request next. Opens the case
//! read-only; nothing is written and no audit entry is added.

use crate::{open_read, print_json};
use anyhow::Result;
use clap::Args;
use sparrow_core::case::coverage::{
    AccountCoverage, CoverageOptions, Request, SourceCoverage, coverage, thousands,
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

/// `ual  rows 1,234  2026-06-01..2026-10-25  48 days  SAMPLED`, or `ual  absent`.
pub fn source_line(s: &SourceCoverage) -> String {
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
