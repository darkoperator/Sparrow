//! `sparrow entity`: the tiles, every pivot table and the findings of one account, IP, device or Entra session.
//! Opens the case read-only; nothing is written.

use crate::cmd::events::entity_of;
use crate::cmd::read::time;
use crate::{open_read, print_json};
use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::Args;
use serde::Serialize;
use sparrow_core::Error;
use sparrow_core::case::entity::{
    self, EntitySummary, FindingRef, PIVOT_DEFAULT_LIMIT, PivotOf, PivotPage, PivotRow,
};
use sparrow_core::case::events::Entity;
use sparrow_core::case::text::display_safe_line as safe;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Args)]
#[command(group = clap::ArgGroup::new("entity").required(true).multiple(false))]
pub struct EntityArgs {
    /// Case database file
    #[arg(long)]
    pub case: PathBuf,
    /// The account (actor or mailbox owner) to open
    #[arg(long, group = "entity")]
    pub user: Option<String>,
    /// The IP address to open
    #[arg(long, group = "entity")]
    pub ip: Option<String>,
    /// The device (device id or directory object id) to open
    #[arg(long, group = "entity")]
    pub device: Option<String>,
    /// The Entra session id to open
    #[arg(long, group = "entity")]
    pub session: Option<String>,
    /// From this time (inclusive, RFC 3339)
    #[arg(long)]
    pub from: Option<String>,
    /// Up to this time (inclusive, RFC 3339)
    #[arg(long)]
    pub to: Option<String>,
}

/// Everything an entity tab shows. `pivots` is keyed `accounts`, `ips`, `devices`, `sessions`, `device_changes`;
/// only the ones that kind of entity has are present.
#[derive(Serialize)]
pub struct EntityReport {
    pub summary: EntitySummary,
    pub pivots: BTreeMap<&'static str, PivotPage>,
    pub findings: Vec<FindingRef>,
}

const PIVOTS: [(PivotOf, &str); 5] = [
    (PivotOf::Accounts, "accounts"),
    (PivotOf::Ips, "ips"),
    (PivotOf::Devices, "devices"),
    (PivotOf::Sessions, "sessions"),
    (PivotOf::DeviceChanges, "device_changes"),
];

fn pivot_name(of: PivotOf) -> &'static str {
    PIVOTS.iter().find(|(o, _)| *o == of).map_or("", |(_, n)| n)
}

fn iso(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn iso_opt(t: &Option<DateTime<Utc>>) -> String {
    t.as_ref().map_or_else(|| "-".into(), iso)
}

fn kind(e: &Entity) -> (&'static str, &str) {
    match e {
        Entity::Account(v) => ("account", v),
        Entity::Ip(v) => ("ip", v),
        Entity::Device(v) => ("device", v),
        Entity::Session(v) => ("session", v),
    }
}

fn pivot_line(of: PivotOf, r: &PivotRow) -> String {
    let mut s = format!(
        "  {}  {}  {}..{}",
        safe(&r.value),
        r.count,
        iso(&r.first_seen),
        iso(&r.last_seen)
    );
    if r.is_new {
        s.push_str("  new");
    }
    if let Some(l) = &r.label {
        s.push_str(&format!("  {}", safe(l)));
    }
    if of != PivotOf::DeviceChanges {
        // `device_name` is the label already shown.
        for (k, v) in r.extra.iter().filter(|(k, _)| *k != "device_name") {
            let v = v.as_str().map_or_else(|| v.to_string(), str::to_string);
            s.push_str(&format!("  {k}={}", safe(&v)));
        }
    }
    s
}

fn print_text(rep: &EntityReport) {
    let s = &rep.summary;
    let (k, v) = kind(&s.entity);
    outln!("{k} {}", safe(v));
    outln!(
        "events {}  first {}  last {}",
        s.events,
        iso_opt(&s.first_seen),
        iso_opt(&s.last_seen)
    );
    outln!(
        "distinct  {}",
        s.distinct
            .iter()
            .map(|(k, n)| format!("{k} {n}"))
            .collect::<Vec<_>>()
            .join("  ")
    );
    outln!(
        "open findings  {}",
        if s.open_findings.is_empty() {
            "none".to_string()
        } else {
            s.open_findings
                .iter()
                .map(|(sev, n)| format!("{} {n}", safe(sev)))
                .collect::<Vec<_>>()
                .join("  ")
        }
    );
    if !s.roles_matched.is_empty() {
        outln!("roles  {}", safe(&s.roles_matched.join(", ")));
    }
    if let Some(i) = &s.ip_intel {
        outln!("ip_intel  {}", safe(&i.to_string()));
    }
    if let Some(d) = &s.device {
        outln!("device  {}", safe(&d.to_string()));
    }
    for (of, name) in PIVOTS {
        let Some(p) = rep.pivots.get(name) else {
            continue;
        };
        if (p.rows.len() as u64) < p.total {
            outln!("\n{name} (showing {} of {})", p.rows.len(), p.total);
        } else {
            outln!("\n{name} ({})", p.total);
        }
        for r in &p.rows {
            outln!("{}", pivot_line(of, r));
        }
    }
    outln!("\nfindings ({})", rep.findings.len());
    for f in &rep.findings {
        outln!(
            "  {}  {}  {}  {}  {}",
            safe(&f.finding_id),
            safe(&f.severity),
            safe(&f.status),
            iso_opt(&f.first_seen),
            safe(&f.title)
        );
    }
}

pub fn run(a: EntityArgs, json: bool) -> Result<ExitCode> {
    let e = entity_of(a.user, a.ip, a.device, a.session)
        .ok_or_else(|| Error::Invalid("name one of --user, --ip, --device or --session".into()))?;
    let from = a.from.as_deref().map(|s| time("--from", s)).transpose()?;
    let to = a.to.as_deref().map(|s| time("--to", s)).transpose()?;
    let c = crate::timed("open", || open_read(&a.case))?;
    let summary = crate::timed("summary", || entity::summary(c.conn(), &e, from, to))?;
    let pivots = crate::timed("pivots", || -> Result<BTreeMap<_, _>> {
        let mut pivots = BTreeMap::new();
        for of in entity::pivots_of(&summary.entity) {
            pivots.insert(
                pivot_name(of),
                entity::pivot(
                    c.conn(),
                    &summary.entity,
                    of,
                    from,
                    to,
                    Some(PIVOT_DEFAULT_LIMIT),
                )?,
            );
        }
        Ok(pivots)
    })?;
    let findings = crate::timed("findings", || {
        entity::findings(c.conn(), &summary.entity, from, to)
    })?;
    let rep = EntityReport {
        summary,
        pivots,
        findings,
    };
    if json {
        print_json(&rep)?;
    } else {
        print_text(&rep);
    }
    Ok(ExitCode::SUCCESS)
}
