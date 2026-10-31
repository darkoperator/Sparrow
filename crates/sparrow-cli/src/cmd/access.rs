//! `sparrow access`: what the attacker reached through each compromised account (mail read and sent, attachments,
//! SharePoint/OneDrive, Teams, Copilot, other apps), from the accepted malicious flags; `--include-pending` and the
//! ad-hoc `--ip/--prefix/--session/--device` make it a preview, labelled on every line. Opens the case read-only;
//! nothing is written and no audit entry is added.

use super::export::{atomic, check_out};
use crate::{open_read, print_json};
use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;
use sparrow_core::case::access::{
    AccessReport, AccountAccess, Basis, Category, Item, ScopeSource, Tile, report_timed,
};
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
    /// Per account only the tiles and the scope values (their window count, first and last time); no items
    #[arg(long, conflicts_with_all = ["csv", "markdown", "category"])]
    pub brief: bool,
    /// Only the items of one category (mail_read, mail_sent, attachment, file, teams, copilot, other), paged
    #[arg(long, value_name = "CAT", conflicts_with_all = ["csv", "markdown"])]
    pub category: Option<String>,
    /// With --category: at most this many items per account
    #[arg(long, default_value_t = 100, requires = "category")]
    pub limit: usize,
    /// With --category: skip this many items of each account first
    #[arg(long, default_value_t = 0, requires = "category")]
    pub offset: usize,
}

/// `--brief`: an account's windows as a count and a span.
#[derive(Serialize)]
struct BriefWindows {
    count: usize,
    first: Option<chrono::DateTime<chrono::Utc>>,
    last: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize)]
struct BriefScope<'a> {
    kind: &'a str,
    value: &'a str,
    basis: Basis,
    windows: BriefWindows,
}

#[derive(Serialize)]
struct BriefAccount<'a> {
    account: &'a str,
    tenant_key: Option<&'a str>,
    scope: Vec<BriefScope<'a>>,
    tiles: &'a [Tile],
    gaps: &'a [String],
}

/// `--category`: one page of one category's items of an account, and how many there are.
#[derive(Serialize)]
struct CategoryPage<'a> {
    account: &'a str,
    category: Category,
    total: usize,
    items: Vec<&'a Item>,
}

/// `--brief` and `--category` output: the report's own top-level fields around the accounts.
#[derive(Serialize)]
struct Compact<T: Serialize> {
    accounts: Vec<T>,
    pending_flags: u64,
    preview: bool,
    never_logged: Vec<String>,
}

fn compact<T: Serialize>(r: &AccessReport, accounts: Vec<T>) -> Compact<T> {
    Compact {
        accounts,
        pending_flags: r.pending_flags,
        preview: r.preview,
        never_logged: r.never_logged.clone(),
    }
}

fn brief(a: &AccountAccess) -> BriefAccount<'_> {
    BriefAccount {
        account: &a.account,
        tenant_key: a.tenant_key.as_deref(),
        scope: a
            .scope
            .iter()
            .map(|s| BriefScope {
                kind: &s.kind,
                value: &s.value,
                basis: s.basis,
                windows: BriefWindows {
                    count: s.windows.len(),
                    first: s.windows.first().map(|w| w.start),
                    last: s.windows.last().map(|w| w.end),
                },
            })
            .collect(),
        tiles: &a.tiles,
        gaps: &a.gaps,
    }
}

fn page(a: &AccountAccess, c: Category, offset: usize, limit: usize) -> CategoryPage<'_> {
    let of: Vec<&Item> = a.items.iter().filter(|i| i.category == c).collect();
    CategoryPage {
        account: &a.account,
        category: c,
        total: of.len(),
        items: of.into_iter().skip(offset).take(limit).collect(),
    }
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

fn print_account(a: &AccountAccess, brief: bool) {
    outln!(
        "{}  tenant {}",
        safe(&a.account),
        a.tenant_key
            .as_deref()
            .map(safe)
            .unwrap_or_else(|| "unknown".into())
    );
    for s in &a.scope {
        let w: Vec<String> = if brief {
            let n = s.windows.len();
            match (s.windows.first(), s.windows.last()) {
                (Some(f), Some(l)) => vec![format!(
                    "{n} window{}  {}..{}",
                    if n == 1 { "" } else { "s" },
                    iso(&f.start),
                    iso(&l.end)
                )],
                _ => vec!["0 windows".to_string()],
            }
        } else {
            s.windows
                .iter()
                .map(|w| format!("{}..{}", iso(&w.start), iso(&w.end)))
                .collect()
        };
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
    let category = match &a.category {
        Some(c) => Some(Category::parse(c).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown category {c:?}: mail_read, mail_sent, attachment, file, teams, copilot or other"
            )
        })?),
        None => None,
    };
    let c = crate::timed("open", || open_read(&a.case))?;
    let r = crate::with_timings(|t| report_timed(c.conn(), a.account.as_deref(), &src, t))?;
    if let Some(cat) = category {
        let pages: Vec<CategoryPage> = r
            .accounts
            .iter()
            .map(|acc| page(acc, cat, a.offset, a.limit))
            .collect();
        if json {
            print_json(&compact(&r, pages))?;
            return Ok(ExitCode::SUCCESS);
        }
        if r.preview {
            outln!("{PREVIEW_BANNER}");
        }
        for (p, acc) in pages.iter().zip(&r.accounts) {
            // The page header counts the whole category: it says how much of it a preview added.
            let of = |b: Basis| {
                acc.items
                    .iter()
                    .filter(|i| i.category == p.category && i.basis == b)
                    .count()
            };
            let marks = [
                ("PENDING", of(Basis::Pending)),
                ("AD-HOC", of(Basis::Adhoc)),
            ]
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(l, n)| format!("  {l} {n}"))
            .collect::<String>();
            outln!(
                "{}  {}  {} of {} (from {}){marks}",
                safe(p.account),
                p.category.as_str(),
                p.items.len(),
                p.total,
                a.offset
            );
            for i in &p.items {
                outln!(
                    "  {}  {}{}  {}  {}",
                    iso(&i.accessed),
                    basis_chip(i.basis),
                    safe(&i.action),
                    i.item.as_deref().map(safe).unwrap_or_default(),
                    safe(&i.row)
                );
            }
        }
        print_context(&r, &src);
        return Ok(ExitCode::SUCCESS);
    }
    if a.brief && json {
        let accounts: Vec<BriefAccount> = r.accounts.iter().map(brief).collect();
        print_json(&compact(&r, accounts))?;
        return Ok(ExitCode::SUCCESS);
    }
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
        print_account(acc, a.brief);
    }
    if r.accounts.is_empty() {
        outln!(
            "no accounts with accepted malicious flags; flag the attacker's sessions or IPs first"
        );
    }
    print_context(&r, &src);
    Ok(ExitCode::SUCCESS)
}

/// What every text report ends with: the gaps Microsoft never logs (also for an empty report) and the flags still
/// waiting for review.
fn print_context(r: &AccessReport, src: &ScopeSource) {
    for g in &r.never_logged {
        outln!("never logged  {}", safe(g));
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
}
