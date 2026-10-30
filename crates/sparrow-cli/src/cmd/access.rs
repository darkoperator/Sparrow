//! `sparrow access`: what the attacker reached through each compromised account (mail read and sent, attachments,
//! SharePoint/OneDrive, Teams, Copilot, other apps), from the accepted malicious flags. Opens the case read-only;
//! nothing is written and no audit entry is added.

use super::export::{atomic, check_out};
use crate::{open_read, print_json};
use anyhow::{Context, Result};
use clap::Args;
use sparrow_core::case::access::{AccountAccess, Tile, report};
use sparrow_core::case::text::display_safe_line as safe;
use sparrow_core::export::access::{write_csv, write_summary};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Args)]
pub struct AccessArgs {
    /// Case database file
    #[arg(long)]
    pub case: PathBuf,
    /// Only this account (any case); default: every account with malicious activity
    #[arg(long)]
    pub account: Option<String>,
    /// Write every item to this CSV file (one row per item, for legal)
    #[arg(long, conflicts_with = "markdown")]
    pub csv: Option<PathBuf>,
    /// Print the Markdown summary table (one row per account) and the coverage gaps
    #[arg(long)]
    pub markdown: bool,
}

fn iso(t: &chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// `mail_read  48 direct  3 by time  3 folders · 4.1 MB`, or `none seen`, or the coverage status.
fn tile_line(t: &Tile) -> String {
    let tail = match (&t.qualifier, t.none_seen) {
        (Some(q), _) => safe(q),
        (None, true) => "none seen".to_string(),
        (None, false) if t.direct + t.by_time == 0 => {
            format!("{} ({})", t.coverage.status, safe(&t.coverage.reason))
        }
        (None, false) => String::new(),
    };
    format!(
        "{}  {} direct  {} by time  {tail}",
        t.category.as_str(),
        t.direct,
        t.by_time
    )
    .trim_end()
    .to_string()
}

fn print_account(a: &AccountAccess) {
    outln!(
        "{}  tenant {}",
        safe(&a.account),
        a.tenant_key
            .as_deref()
            .map(safe)
            .unwrap_or_else(|| "unknown".into())
    );
    for s in &a.scope {
        let w: Vec<String> = s
            .windows
            .iter()
            .map(|w| format!("{}..{}", iso(&w.start), iso(&w.end)))
            .collect();
        outln!("  scope  {} {}  {}", s.kind, safe(&s.value), w.join(", "));
    }
    for t in &a.tiles {
        outln!("  {}", tile_line(t));
    }
    for g in &a.gaps {
        outln!("  gap  {}", safe(g));
    }
}

pub fn run(a: AccessArgs, json: bool) -> Result<ExitCode> {
    if json && (a.csv.is_some() || a.markdown) {
        anyhow::bail!("--json prints the report itself; leave it out with --csv or --markdown");
    }
    if let Some(path) = &a.csv {
        check_out(path, &a.case)?;
    }
    let c = open_read(&a.case)?;
    let r = report(c.conn(), a.account.as_deref())?;
    if json {
        print_json(&r)?;
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(path) = &a.csv {
        atomic(path, |tmp| {
            let f =
                std::fs::File::create(tmp).with_context(|| format!("create {}", tmp.display()))?;
            let mut w = BufWriter::new(f);
            write_csv(&r, &mut w)?;
            w.flush()?;
            Ok(())
        })?;
        let n: usize = r.accounts.iter().map(|a| a.items.len()).sum();
        outln!(
            "wrote {n} items for {} accounts to {}",
            r.accounts.len(),
            safe(&path.display().to_string())
        );
        return Ok(ExitCode::SUCCESS);
    }
    if a.markdown {
        crate::cx::with_out(|out| write_summary(&r, out))?;
        return Ok(ExitCode::SUCCESS);
    }
    for acc in &r.accounts {
        print_account(acc);
    }
    if r.accounts.is_empty() {
        outln!(
            "no accounts with accepted malicious flags; flag the attacker's sessions or IPs first"
        );
    }
    if r.pending_flags > 0 {
        outln!(
            "{} malicious flags are waiting for review (they count once accepted)",
            r.pending_flags
        );
    }
    Ok(ExitCode::SUCCESS)
}
