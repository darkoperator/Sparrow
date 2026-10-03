//! `sparrow finding set-status|assign|ack-rule-update`: agent decisions on findings (Addendum D.5).

use crate::ActorArgs;
use anyhow::Result;
use clap::Subcommand;
use sparrow_core::case::audit::AuditEntry;
use sparrow_core::case::write::{self, FindingStatus};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Subcommand)]
pub enum FindingCommand {
    /// Set a finding's status (new, in_review, confirmed, false_positive, benign, needs_more_data)
    SetStatus {
        id: String,
        status: String,
        /// Why; required for confirmed, false_positive and benign (becomes the disposition reason)
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Assign a finding to an analyst
    Assign {
        id: String,
        analyst_name: String,
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Acknowledge that a finding's rule (or the indicators it reads) changed since it was raised
    AckRuleUpdate {
        id: String,
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
}

/// "(decided by agent:x for analyst:y, pending review)".
pub fn provenance(decided_by: &str, on_behalf_of: Option<&str>) -> String {
    let on_behalf = on_behalf_of
        .map(|a| format!(" for {a}"))
        .unwrap_or_default();
    format!("(decided by {decided_by}{on_behalf}, pending review)")
}

/// The audit entry with `--json`; otherwise `<object id> <what> (decided by ..., pending review)`.
pub fn print_decision(e: &AuditEntry, what: &str, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(e)?);
    } else {
        println!(
            "{} {what} {}",
            e.object_id,
            provenance(&e.actor, e.on_behalf_of.as_deref())
        );
    }
    Ok(())
}

pub fn run(command: FindingCommand, json: bool) -> Result<ExitCode> {
    match command {
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
