//! `sparrow access`: what the attacker reached through each compromised account (mail read and sent, attachments,
//! SharePoint/OneDrive, Teams, Copilot, other apps), from the accepted malicious flags; `--include-pending` and the
//! ad-hoc `--ip/--prefix/--session/--device` make it a preview, labelled on every line. Opens the case read-only;
//! nothing is written and no audit entry is added.

use super::export::{atomic, check_out};
use crate::{open_read, print_json};
use anyhow::{Context, Result};
use clap::Args;
use sparrow_core::case::access::{AccountAccess, Basis, ScopeSource, Tile, report_with};
use sparrow_core::case::marks::ValueKind;
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
    /// Count pending (agent) malicious flags too: a preview, never the reviewed report
    #[arg(long)]
    pub include_pending: bool,
    /// An ad-hoc scope value, as if flagged malicious and accepted, case-wide (repeatable): a preview
    #[arg(long = "ip", value_name = "IP")]
    pub ips: Vec<String>,
    /// An ad-hoc IP prefix (a.b.c.0/24, or an address of it) (repeatable)
    #[arg(long = "prefix", value_name = "CIDR")]
    pub prefixes: Vec<String>,
    /// An ad-hoc Entra or Exchange session id (repeatable)
    #[arg(long = "session", value_name = "ID")]
    pub sessions: Vec<String>,
    /// An ad-hoc device id (repeatable)
    #[arg(long = "device", value_name = "ID")]
    pub devices: Vec<String>,
}

/// The first line of every preview.
pub const PREVIEW_BANNER: &str =
    "PREVIEW: includes pending or ad-hoc scope; not the reviewed report";

impl AccessArgs {
    /// The flags the report counts; an ad-hoc value that is not one of its kind is refused.
    pub fn scope_source(&self) -> Result<ScopeSource> {
        let mut adhoc = Vec::new();
        for (kind, values) in [
            (ValueKind::Ip, &self.ips),
            (ValueKind::IpPrefix, &self.prefixes),
            (ValueKind::Session, &self.sessions),
            (ValueKind::Device, &self.devices),
        ] {
            for v in values {
                kind.normalize(v)
                    .with_context(|| format!("--{}", flag_of(kind)))?;
                adhoc.push((kind, v.clone()));
            }
        }
        Ok(ScopeSource {
            include_pending: self.include_pending,
            adhoc,
        })
    }
}

fn flag_of(k: ValueKind) -> &'static str {
    match k {
        ValueKind::IpPrefix => "prefix",
        other => other.as_str(),
    }
}

/// `PENDING ` / `AD-HOC ` before what a preview added.
fn basis_chip(b: Basis) -> &'static str {
    match b {
        Basis::Accepted => "",
        Basis::Pending => "PENDING ",
        Basis::Adhoc => "AD-HOC ",
    }
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
    let preview = match (t.pending, t.adhoc) {
        (0, 0) => String::new(),
        (p, 0) => format!("  PENDING {p}"),
        (0, a) => format!("  AD-HOC {a}"),
        (p, a) => format!("  PENDING {p}  AD-HOC {a}"),
    };
    format!(
        "{}  {} direct  {} by time{preview}  {tail}",
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
        outln!(
            "  scope  {}{} {}  {}",
            basis_chip(s.basis),
            s.kind,
            safe(&s.value),
            w.join(", ")
        );
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
    let src = a.scope_source()?;
    let c = open_read(&a.case)?;
    let r = report_with(c.conn(), a.account.as_deref(), &src)?;
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
        if r.preview {
            outln!("{PREVIEW_BANNER} (see the CSV's basis column)");
        }
        outln!(
            "wrote {n} items for {} accounts to {}",
            r.accounts.len(),
            safe(&path.display().to_string())
        );
        return Ok(ExitCode::SUCCESS);
    }
    if r.preview {
        outln!("{PREVIEW_BANNER}");
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
        let how = if src.include_pending {
            "counted here as PENDING; the reviewed report counts them once accepted"
        } else {
            "they count once accepted; --include-pending previews them"
        };
        outln!(
            "{} malicious flags are waiting for review ({how})",
            r.pending_flags
        );
    }
    Ok(ExitCode::SUCCESS)
}
