//! `sparrow investigate`: one account in one window — sessions with what each reached, the mail around it, its
//! configuration changes and its findings' times, with the next commands to run. Read-only; the window comes from the
//! analyst (the customer's dates), never from the command.

use crate::cmd::read::time;
use crate::{open_read, print_json};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use clap::Args;
use sparrow_core::case::investigate::{Investigation, MailRow, investigate};
use sparrow_core::case::text::display_safe_line as safe;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Args)]
#[command(group = clap::ArgGroup::new("window").required(true).multiple(true).args(["from", "on"]))]
pub struct InvestigateArgs {
    /// Case database file
    #[arg(long)]
    pub case: PathBuf,
    /// The account (UPN, any case)
    #[arg(long)]
    pub user: String,
    /// Start of the window (RFC 3339)
    #[arg(long, requires = "to", conflicts_with = "on")]
    pub from: Option<String>,
    /// End of the window (RFC 3339, exclusive)
    #[arg(long, requires = "from")]
    pub to: Option<String>,
    /// The UTC day YYYY-MM-DD (the customer's date), widened by --pad
    #[arg(long, value_name = "DATE")]
    pub on: Option<String>,
    /// With --on: widen the day on both sides, e.g. 12h or 1d
    #[arg(long, value_name = "DURATION", requires = "on")]
    pub pad: Option<String>,
}

/// `1d`, `12h`, `30m`.
fn duration(s: &str) -> Result<Duration> {
    let bad = || anyhow::anyhow!("--pad is a number with d, h or m (1d, 12h, 30m), got {s:?}");
    let s = s.trim();
    // Split before the last character (any width), never inside one.
    let Some((at, _)) = s.char_indices().last() else {
        return Err(bad());
    };
    let (n, unit) = s.split_at(at);
    let n: i64 = n.parse().map_err(|_| bad())?;
    // At most a year: a window is days, and chrono's arithmetic must never overflow.
    if !(0..=366 * 24 * 60).contains(&n) {
        return Err(bad());
    }
    match unit {
        "d" if n <= 366 => Ok(Duration::days(n)),
        "h" if n <= 366 * 24 => Ok(Duration::hours(n)),
        "m" => Ok(Duration::minutes(n)),
        _ => Err(bad()),
    }
}

fn window(a: &InvestigateArgs) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
    if let Some(day) = &a.on {
        let d = NaiveDate::parse_from_str(day, "%Y-%m-%d")
            .with_context(|| format!("--on is a date YYYY-MM-DD, got {day:?}"))?;
        let start = d.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
        let pad = a
            .pad
            .as_deref()
            .map(duration)
            .transpose()?
            .unwrap_or_default();
        let from = start.checked_sub_signed(pad);
        let to = start
            .checked_add_signed(Duration::days(1))
            .and_then(|t| t.checked_add_signed(pad));
        return match (from, to) {
            (Some(f), Some(t)) => Ok((f, t)),
            _ => anyhow::bail!("the window around {day} is out of range"),
        };
    }
    match (&a.from, &a.to) {
        (Some(f), Some(t)) => Ok((time("--from", f)?, time("--to", t)?)),
        _ => anyhow::bail!("give the window: --from T --to T, or --on DATE [--pad D]"),
    }
}

fn iso(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn opt(s: &Option<String>) -> String {
    s.as_deref().map(safe).unwrap_or_else(|| "-".into())
}

fn mail_line(m: &MailRow) -> String {
    format!(
        "  {}  {} -> {}  {}  {}",
        m.received.as_ref().map(iso).unwrap_or_default(),
        opt(&m.sender),
        opt(&m.recipient),
        opt(&m.subject),
        opt(&m.direction)
    )
}

fn print(inv: &Investigation) {
    outln!(
        "{}  {}..{}",
        safe(&inv.account),
        iso(&inv.from),
        iso(&inv.to)
    );
    if inv.sessions.is_empty() {
        outln!(
            "no events of {} in {}..{}; widen the window (its findings' times are below)",
            safe(&inv.account),
            iso(&inv.from),
            iso(&inv.to)
        );
    }
    outln!("Sessions ({})", inv.sessions.len());
    for s in &inv.sessions {
        outln!(
            "  {}  {}..{}  {} events",
            safe(&s.key),
            iso(&s.first),
            iso(&s.last),
            s.events
        );
        for ip in &s.ips {
            let new = match (ip.new_for_account, ip.asn_new_for_account) {
                (true, true) => "  NEW ip, NEW asn",
                (true, false) => "  NEW ip",
                (false, true) => "  NEW asn",
                (false, false) => "",
            };
            outln!(
                "    ip {}  AS{} {}  {}  {}{new}",
                safe(&ip.ip),
                ip.asn.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
                opt(&ip.asn_org),
                opt(&ip.country),
                opt(&ip.kind)
            );
        }
        for d in &s.devices {
            outln!("    device {}", safe(d));
        }
        for u in &s.user_agents {
            outln!("    agent {}", safe(u));
        }
        if !s.signin_results.is_empty() {
            let r: Vec<String> = s
                .signin_results
                .iter()
                .map(|(k, n)| format!("{}×{n}", safe(k)))
                .collect();
            outln!("    sign-in results {}", r.join(" "));
        }
        for f in &s.flags {
            outln!("    flag {}", safe(f));
        }
        if !s.findings.is_empty() {
            outln!("    findings {}", s.findings.join(" "));
        }
        if !s.reach.is_empty() {
            let r: Vec<String> = s
                .reach
                .iter()
                .map(|x| format!("{} {}", x.category.as_str(), x.items))
                .collect();
            outln!("    would reach if flagged {}", r.join("  "));
        }
    }
    outln!(
        "Mail to the account (from a day before) ({})",
        inv.mail_in.len()
    );
    for m in &inv.mail_in {
        outln!("{}", mail_line(m));
    }
    outln!("Mail sent ({})", inv.mail_out.len());
    for m in &inv.mail_out {
        outln!("{}", mail_line(m));
    }
    if inv.mail_truncated {
        outln!(
            "  … more mail (first {} per direction)",
            sparrow_core::case::investigate::MAIL_LIMIT
        );
    }
    outln!("Config changes ({})", inv.config_changes.len());
    for c in &inv.config_changes {
        outln!(
            "  {}  {}  {}  {}",
            c.time.as_ref().map(iso).unwrap_or_default(),
            safe(&c.operation),
            opt(&c.summary),
            safe(&c.row)
        );
    }
    outln!("Findings of the account ({})", inv.finding_times.len());
    for f in &inv.finding_times {
        outln!(
            "  {}  {}  {}  {}..{}",
            f.finding_id,
            f.severity,
            safe(&f.title),
            f.first_seen.as_ref().map(iso).unwrap_or_default(),
            f.last_seen.as_ref().map(iso).unwrap_or_default()
        );
    }
    outln!("Next");
    for n in &inv.next {
        outln!("  {}  # {}", n.command, safe(&n.about));
    }
}

/// Ready to run: `sparrow`, every argument and this case, each quoted for a POSIX shell (as `summary` does): session ids
/// and addresses are evidence text.
fn command_line(args: &[String], case: &str) -> String {
    let word = |s: &str| {
        let plain = !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "@%+=:,./_-".contains(c));
        if plain {
            s.to_string()
        } else {
            crate::shell_quote(s)
        }
    };
    let mut words = vec!["sparrow".to_string()];
    words.extend(args.iter().map(|a| word(a)));
    words.push("--case".into());
    words.push(word(case));
    words.join(" ")
}

pub fn run(a: InvestigateArgs, json: bool) -> Result<ExitCode> {
    let (from, to) = window(&a)?;
    let c = crate::timed("open", || open_read(&a.case))?;
    let mut inv = crate::timed("investigate", || investigate(c.conn(), &a.user, from, to))?;
    for n in &mut inv.next {
        n.command = command_line(&n.args, &a.case.display().to_string());
    }
    if json {
        print_json(&inv)?;
    } else {
        print(&inv);
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_commands_quote_evidence_text() {
        let args = vec![
            "mark".to_string(),
            "flag".into(),
            "--value".into(),
            "session=a'b; rm -rf ~".into(),
        ];
        let c = command_line(&args, "/cases/my case.duckdb");
        assert_eq!(
            c,
            "sparrow mark flag --value 'session=a'\\''b; rm -rf ~' --case '/cases/my case.duckdb'"
        );
    }

    #[test]
    fn pad_is_bounded() {
        assert!(duration("366d").is_ok());
        assert!(duration("367d").is_err());
        assert!(duration("99999999999999h").is_err());
        assert!(duration("-1h").is_err());
        assert!(
            duration("1é").is_err(),
            "a multi-byte last character is an error, not a panic"
        );
        assert!(duration("é").is_err());
        assert!(duration("").is_err());
    }
}
