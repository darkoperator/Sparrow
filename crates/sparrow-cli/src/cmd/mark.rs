//! `sparrow mark flag|tag`: flags and tags on event rows, as agent decisions. They are pending until an analyst confirms
//! them in the app; the CLI has no confirm or discard. Notes keep their own command (`sparrow note add`).

use crate::ActorArgs;
use crate::cmd::finding::print_decision;
use anyhow::Result;
use clap::Subcommand;
use sparrow_core::Error;
use sparrow_core::case::events::Entity;
use sparrow_core::case::marks::{self, FlagLevel, RowRef, ValueKind};
use sparrow_core::case::timeline_entries::EvidenceRef;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Subcommand)]
pub enum MarkCommand {
    /// Flag event rows (or every event with a value) suspicious or malicious, or clear a flag
    #[command(group = clap::ArgGroup::new("target").required(true).multiple(false))]
    Flag {
        /// Event row as <table>:<record_key> (repeatable; at most 1,000 for an agent)
        #[arg(long = "row", group = "target")]
        rows: Vec<String>,
        /// Standing flag on every event with this value, also ones ingested later: KIND=VALUE, KIND one of ip,
        /// ip_prefix, account, asn, device, session
        #[arg(long, group = "target", value_name = "KIND=VALUE")]
        value: Option<String>,
        /// Only that entity's events carry the value flag: KIND=VALUE, KIND one of account, ip, device, session
        #[arg(long, value_name = "KIND=VALUE")]
        scope: Option<String>,
        /// suspicious, malicious or clear
        #[arg(long)]
        level: String,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Add a tag to event rows, or remove it (an agent's new tag names start with ai:)
    Tag {
        /// Event row as <table>:<record_key> (repeatable)
        #[arg(long = "row", required = true)]
        rows: Vec<String>,
        /// The tag name (trimmed and lower-cased)
        #[arg(long)]
        tag: String,
        /// Remove the tag instead of adding it
        #[arg(long)]
        remove: bool,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
}

fn rows(refs: &[String]) -> Result<Vec<RowRef>> {
    refs.iter()
        .map(|r| {
            let e = EvidenceRef::parse(r)?;
            Ok(RowRef::new(&e.source_table, &e.record_key))
        })
        .collect()
}

fn kind_value<'a>(flag: &str, s: &'a str) -> Result<(&'a str, &'a str)> {
    s.split_once('=')
        .filter(|(k, v)| !k.is_empty() && !v.trim().is_empty())
        .ok_or_else(|| Error::Invalid(format!("{flag} is KIND=VALUE, got {s:?}")).into())
}

fn scope_entity(s: &str) -> Result<Entity> {
    let (k, v) = kind_value("--scope", s)?;
    let v = v.to_string();
    Ok(match k {
        "account" => Entity::Account(v),
        "ip" => Entity::Ip(v),
        "device" => Entity::Device(v),
        "session" => Entity::Session(v),
        other => {
            return Err(Error::Invalid(format!(
                "unknown scope kind {other:?} (account, ip, device or session)"
            ))
            .into());
        }
    })
}

fn level(s: &str) -> Result<Option<FlagLevel>> {
    if s == "clear" {
        return Ok(None);
    }
    FlagLevel::parse(s).map(Some).map_err(|_| {
        Error::Invalid(format!(
            "unknown flag level {s:?} (suspicious, malicious or clear)"
        ))
        .into()
    })
}

pub fn run(command: MarkCommand, json: bool) -> Result<ExitCode> {
    match command {
        MarkCommand::Flag {
            rows: refs,
            value,
            scope,
            level: lvl,
            case,
            actor,
        } => {
            let actor = actor.resolve()?;
            let lvl = level(&lvl)?;
            if scope.is_some() && value.is_none() {
                return Err(Error::Invalid("--scope goes with --value, not --row".into()).into());
            }
            let what = lvl.map_or("clear", FlagLevel::as_str);
            let (entry, label) = match value {
                Some(v) => {
                    let (k, val) = kind_value("--value", &v)?;
                    let kind = ValueKind::parse(k)?;
                    let scope = scope.as_deref().map(scope_entity).transpose()?;
                    let c = crate::open_case_for_write(&case)?;
                    let e = marks::flag_value(c.conn(), &actor, kind, val, scope.as_ref(), lvl)?;
                    (e, format!("value flag {what} on {k}={val}"))
                }
                None => {
                    let rows = rows(&refs)?;
                    let c = crate::open_case_for_write(&case)?;
                    let e = marks::flag_rows(c.conn(), &actor, &rows, lvl)?;
                    (e, format!("flag {what} on {} row(s)", rows.len()))
                }
            };
            print_decision(&entry, &label, json)?;
        }
        MarkCommand::Tag {
            rows: refs,
            tag,
            remove,
            case,
            actor,
        } => {
            let actor = actor.resolve()?;
            let rows = rows(&refs)?;
            let c = crate::open_case_for_write(&case)?;
            let entry = marks::tag_rows(c.conn(), &actor, &rows, &tag, !remove)?;
            let verb = if remove { "removed from" } else { "added to" };
            print_decision(
                &entry,
                &format!(
                    "tag {} {verb} {} row(s)",
                    tag.trim().to_lowercase(),
                    rows.len()
                ),
                json,
            )?;
        }
    }
    Ok(ExitCode::SUCCESS)
}
