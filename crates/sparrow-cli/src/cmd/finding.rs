//! `sparrow finding set-status|assign|ack-rule-update`: agent decisions on findings (Addendum D.5). `list` and
//! `show` are read commands (`cmd::read`).

use crate::ActorArgs;
use anyhow::Result;
use clap::Subcommand;
use sparrow_core::case::audit::AuditEntry;
use sparrow_core::case::text::display_safe_line;
use sparrow_core::case::write::{self, FindingStatus};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Subcommand)]
pub enum FindingCommand {
    /// List findings: severity first, then the most recent
    List(super::read::FindingListArgs),
    /// Findings by id: evidence with source references, analyst guidance, notes, decision and review, history.
    /// Several ids (at most 50) print each in turn; exit 2 when one is not found
    Show {
        /// Finding id(s) (see `finding list`)
        #[arg(required = true, num_args = 1..)]
        ids: Vec<String>,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Directory overriding the embedded data files; default $SPARROW_DATA
        #[arg(long)]
        data: Option<PathBuf>,
        /// Rule directory (repeatable), for the guidance of custom rules; default $SPARROW_RULES
        #[arg(long)]
        rules: Vec<PathBuf>,
        /// Print every evidence row (plain output shows the first 50; --json always has all)
        #[arg(long)]
        all: bool,
    },
    /// Set a finding's status (new, in_review, confirmed, false_positive, benign, needs_more_data)
    SetStatus {
        /// Finding id (see `finding list`)
        id: String,
        /// new, in_review, confirmed, false_positive, benign or needs_more_data
        status: String,
        /// Why; required for confirmed, false_positive and benign (becomes the disposition reason)
        #[arg(long)]
        reason: Option<String>,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Assign a finding to an analyst
    Assign {
        /// Finding id (see `finding list`)
        id: String,
        /// The analyst the finding is assigned to
        analyst_name: String,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Acknowledge that a finding's rule (or the indicators it reads) changed since it was raised
    AckRuleUpdate {
        /// Finding id (see `finding list`)
        id: String,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
}

/// "(decided by agent:x for analyst:y, pending review)".
pub fn provenance(decided_by: &str, on_behalf_of: Option<&str>) -> String {
    let on_behalf = on_behalf_of
        .map(|a| format!(" for {}", display_safe_line(a)))
        .unwrap_or_default();
    format!(
        "(decided by {}{on_behalf}, pending review)",
        display_safe_line(decided_by)
    )
}

/// The audit entry with `--json`; otherwise `<object id> <what> (decided by ..., pending review)`.
pub fn print_decision(e: &AuditEntry, what: &str, json: bool) -> Result<()> {
    print_decision_with(e, &[], what, json)
}

/// [`print_decision`] for a command that creates an object: `--json` adds `extra` (the new id, ...) to the audit
/// entry's fields.
pub fn print_decision_with(
    e: &AuditEntry,
    extra: &[(&str, serde_json::Value)],
    what: &str,
    json: bool,
) -> Result<()> {
    if json {
        let mut v = serde_json::to_value(e)?;
        if let Some(m) = v.as_object_mut() {
            for (k, x) in extra {
                m.insert((*k).to_string(), x.clone());
            }
        }
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!(
            "{} {} {}",
            display_safe_line(&e.object_id),
            display_safe_line(what),
            provenance(&e.actor, e.on_behalf_of.as_deref())
        );
    }
    Ok(())
}

pub fn run(command: FindingCommand, json: bool) -> Result<ExitCode> {
    match command {
        FindingCommand::List(a) => return super::read::finding_list(a, json),
        FindingCommand::Show {
            ids,
            case,
            data,
            rules,
            all,
        } => return super::read::finding_show(&case, &ids, data, rules, all, json),
        FindingCommand::SetStatus {
            id,
            status,
            reason,
            case,
            actor,
        } => {
            let actor = actor.resolve()?;
            let status = FindingStatus::parse(&status)?;
            let c = crate::open_case_for_write(&case)?;
            let e = write::set_finding_status(c.conn(), &actor, &id, status, reason.as_deref())?;
            print_decision(&e, status.as_str(), json)?;
        }
        FindingCommand::Assign {
            id,
            analyst_name,
            case,
            actor,
        } => {
            let actor = actor.resolve()?;
            let c = crate::open_case_for_write(&case)?;
            let e = write::assign_finding(c.conn(), &actor, &id, &analyst_name)?;
            print_decision(&e, &format!("assigned to {}", analyst_name.trim()), json)?;
        }
        FindingCommand::AckRuleUpdate { id, case, actor } => {
            let actor = actor.resolve()?;
            let c = crate::open_case_for_write(&case)?;
            let e = write::ack_rule_update(c.conn(), &actor, &id)?;
            print_decision(&e, "rule update acknowledged", json)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}
