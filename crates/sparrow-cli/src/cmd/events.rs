//! `sparrow events`: the Events grid on the command line. Opens the case read-only; nothing is written.

use crate::cmd::read::time;
use crate::{open_read, print_json};
use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::Args;
use sparrow_core::Error;
use sparrow_core::case::events::{
    self, Entity, EventQuery, EventRow, EventsPage, Field, FlagFilter,
};
use sparrow_core::case::marks::FlagLevel;
use sparrow_core::case::text::display_safe_line as safe;
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_LIMIT: usize = 200;

#[derive(Args)]
pub struct EventsArgs {
    /// Case database file
    #[arg(long)]
    pub case: PathBuf,
    /// Only the events of this account (actor or mailbox owner)
    #[arg(long, group = "entity")]
    pub user: Option<String>,
    /// Only the events from this IP address
    #[arg(long, group = "entity")]
    pub ip: Option<String>,
    /// Only the events of this device id or directory object id (a device name: --where device=NAME)
    #[arg(long, group = "entity")]
    pub device: Option<String>,
    /// Only the events of this Entra session id
    #[arg(long, group = "entity")]
    pub session: Option<String>,
    /// FIELD=TEXT filter (repeatable). FIELD: source, operation, account, ip, country, asn, device, session or tag.
    /// TEXT: comma separates values, !value excludes, * is a wildcard; a value in double quotes is literal
    /// (commas, *, a leading ! and spaces included; "" inside is one quote), like operation="a,b"
    #[arg(long = "where", value_name = "FIELD=TEXT")]
    pub filters: Vec<String>,
    /// Case-insensitive text in the raw record (comma: any of, * wildcard)
    #[arg(long)]
    pub search: Option<String>,
    /// From this time (inclusive, RFC 3339)
    #[arg(long)]
    pub from: Option<String>,
    /// Up to this time (inclusive, RFC 3339)
    #[arg(long)]
    pub to: Option<String>,
    /// Only rows whose effective flag is this: suspicious or malicious
    #[arg(long)]
    pub flag: Option<String>,
    /// Skip this many rows
    #[arg(long)]
    pub offset: Option<usize>,
    /// At most this many rows (default 200)
    #[arg(long)]
    pub limit: Option<usize>,
    /// Write every matching row (not a page) to this CSV file and print the row count
    #[arg(long, value_name = "PATH")]
    pub csv: Option<PathBuf>,
}

fn field(name: &str) -> Result<Field> {
    Ok(match name.trim() {
        "source" => Field::Source,
        "operation" => Field::Operation,
        "account" => Field::Account,
        "ip" => Field::Ip,
        "country" => Field::Country,
        "asn" => Field::Asn,
        "device" => Field::Device,
        "session" => Field::Session,
        "tag" => Field::Tag,
        other => {
            return Err(Error::Invalid(format!(
                "unknown --where field {other:?} (source, operation, account, ip, country, asn, device, session or tag)"
            ))
            .into());
        }
    })
}

/// The entity of whichever of `--user|--ip|--device|--session` was given.
pub(crate) fn entity_of(
    user: Option<String>,
    ip: Option<String>,
    device: Option<String>,
    session: Option<String>,
) -> Option<Entity> {
    user.map(Entity::Account)
        .or(ip.map(Entity::Ip))
        .or(device.map(Entity::Device))
        .or(session.map(Entity::Session))
}

fn query_of(a: &EventsArgs) -> Result<EventQuery> {
    let mut fields = Vec::new();
    for f in &a.filters {
        let (name, text) = f
            .split_once('=')
            .ok_or_else(|| Error::Invalid(format!("--where is FIELD=TEXT, got {f:?}")))?;
        fields.push((field(name)?, text.to_string()));
    }
    let flag = match a.flag.as_deref() {
        None => FlagFilter::All,
        Some(s) => match FlagLevel::parse(s)? {
            FlagLevel::Suspicious => FlagFilter::Suspicious,
            FlagLevel::Malicious => FlagFilter::Malicious,
        },
    };
    Ok(EventQuery {
        entity: entity_of(
            a.user.clone(),
            a.ip.clone(),
            a.device.clone(),
            a.session.clone(),
        ),
        fields,
        search: a.search.clone(),
        from: a.from.as_deref().map(|s| time("--from", s)).transpose()?,
        to: a.to.as_deref().map(|s| time("--to", s)).transpose()?,
        flag,
        ai: Default::default(),
    })
}

/// `YYYY-MM-DDTHH:MM:SSZ`, or `-` for a row without a time.
fn iso(t: &Option<DateTime<Utc>>) -> String {
    t.map_or_else(
        || "-".into(),
        |t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

/// `4f1c…9a2e`: the first and last four characters of a long id.
pub(crate) fn short_id(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    if chars.len() <= 12 {
        return id.to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

fn dash(s: Option<&str>) -> String {
    s.filter(|s| !s.is_empty()).map_or_else(|| "-".into(), safe)
}

/// One line: time, source, operation, account, ip, device, session, flag, tags (two spaces apart, `-` for none).
pub fn row_line(r: &EventRow) -> String {
    let account = r.actor_upn.as_deref().or(r.owner_upn.as_deref());
    let device = r.device_name.as_deref().or(r.device_id.as_deref());
    let flag = match r.flag {
        Some(l) if r.flag_ai => format!("{} (ai)", l.as_str()),
        Some(l) => l.as_str().to_string(),
        None => "-".into(),
    };
    let tags = if r.tags.is_empty() {
        "-".to_string()
    } else {
        r.tags
            .iter()
            .map(|t| {
                if t.ai {
                    format!("{} (ai)", safe(&t.name))
                } else {
                    safe(&t.name)
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    [
        iso(&r.event_time),
        safe(&r.source),
        dash(r.operation.as_deref()),
        dash(account),
        dash(r.ip.as_deref()),
        dash(device),
        r.entra_session_id
            .as_deref()
            .map_or_else(|| "-".into(), |s| safe(&short_id(s))),
        flag,
        tags,
    ]
    .join("  ")
}

/// `total 3  showing 3 from offset 0`; `total 100000 (capped)` when the count stopped at its cap.
pub fn header_line(p: &EventsPage) -> String {
    format!(
        "total {}{}  showing {} from offset {}",
        p.total,
        if p.total_capped { " (capped)" } else { "" },
        p.rows.len(),
        p.offset
    )
}

pub fn run(a: EventsArgs, json: bool) -> Result<ExitCode> {
    if a.csv.is_some() && (a.offset.is_some() || a.limit.is_some()) {
        return Err(Error::Invalid(
            "--csv writes every matching row; it cannot be combined with --offset or --limit"
                .into(),
        )
        .into());
    }
    let q = query_of(&a)?;
    let c = open_read(&a.case)?;
    if let Some(out) = &a.csv {
        let rows = events::export_csv(c.conn(), &q, out)?;
        if json {
            print_json(&serde_json::json!({ "csv": out.display().to_string(), "rows": rows }))?;
        } else {
            println!("wrote {rows} rows to {}", safe(&out.display().to_string()));
        }
        return Ok(ExitCode::SUCCESS);
    }
    let page = events::page(
        c.conn(),
        &q,
        None,
        a.offset.unwrap_or(0),
        a.limit.unwrap_or(DEFAULT_LIMIT),
    )?;
    if json {
        print_json(&page)?;
        return Ok(ExitCode::SUCCESS);
    }
    println!("{}", header_line(&page));
    for r in &page.rows {
        println!("{}", row_line(r));
    }
    Ok(ExitCode::SUCCESS)
}
