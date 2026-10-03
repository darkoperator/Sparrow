//! `sparrow timeline-entry propose|verify|reject|edit`: curated timeline entries as agent decisions (Addendum D.5).
//! `timeline-entry list` is a read command (Task 4).

use crate::ActorArgs;
use crate::cmd::finding::print_decision;
use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::Subcommand;
use sparrow_core::Error;
use sparrow_core::case::timeline_entries::{self as te, EntryEdit, EvidenceRef, NewEntry, Phase};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Subcommand)]
pub enum TimelineEntryCommand {
    /// Propose an entry (verify it once its evidence is attached)
    Propose {
        /// When the event happened, RFC 3339 (for example 2026-08-03T09:00:00Z)
        #[arg(long)]
        time: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        narrative: Option<String>,
        /// initial_access, persistence, defense_evasion, recon, collection, exfiltration, impact or remediation
        #[arg(long)]
        phase: String,
        /// Evidence row as <table>:<record_key> (repeatable)
        #[arg(long)]
        evidence: Vec<String>,
        /// Tenant the entry belongs to; default case-wide
        #[arg(long)]
        tenant: Option<String>,
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Verify a proposed entry (needs evidence that exists in the case)
    Verify {
        id: String,
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Reject a proposed or verified entry
    Reject {
        id: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Edit an entry: in place when proposed; a verified entry gets a successor that supersedes it once verified
    Edit {
        id: String,
        #[arg(long)]
        time: Option<String>,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        narrative: Option<String>,
        #[arg(long)]
        phase: Option<String>,
        /// Replaces the evidence (repeatable)
        #[arg(long)]
        evidence: Vec<String>,
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
}

fn time(s: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| Error::Decision(format!("--time must be RFC 3339 ({e}): {s:?}")))?)
}

fn evidence(refs: &[String]) -> Result<Vec<EvidenceRef>> {
    Ok(refs
        .iter()
        .map(|r| EvidenceRef::parse(r))
        .collect::<sparrow_core::Result<_>>()?)
}

pub fn run(command: TimelineEntryCommand, json: bool) -> Result<ExitCode> {
    match command {
        TimelineEntryCommand::Propose {
            time: t,
            title,
            narrative,
            phase,
            evidence: refs,
            tenant,
            case,
            actor,
        } => {
            let actor = actor.resolve()?;
            let entry = NewEntry {
                tenant_key: tenant,
                event_time: time(&t)?,
                title,
                narrative,
                phase: Phase::parse(&phase)?,
                evidence: evidence(&refs)?,
            };
            let c = crate::open_case_for_write(&case)?;
            let (_, e) = te::propose(c.conn(), &actor, entry)?;
            print_decision(&e, "proposed", json)?;
        }
        TimelineEntryCommand::Verify { id, case, actor } => {
            let actor = actor.resolve()?;
            let c = crate::open_case_for_write(&case)?;
            let e = te::verify(c.conn(), &actor, &id)?;
            print_decision(&e, "verified", json)?;
        }
        TimelineEntryCommand::Reject {
            id,
            reason,
            case,
            actor,
        } => {
            let actor = actor.resolve()?;
            let c = crate::open_case_for_write(&case)?;
            let e = te::reject(c.conn(), &actor, &id, &reason)?;
            print_decision(&e, "rejected", json)?;
        }
        TimelineEntryCommand::Edit {
            id,
            time: t,
            title,
            narrative,
            phase,
            evidence: refs,
            case,
            actor,
        } => {
            let actor = actor.resolve()?;
            let edit = EntryEdit {
                event_time: t.as_deref().map(time).transpose()?,
                title,
                narrative,
                phase: phase.as_deref().map(Phase::parse).transpose()?,
                evidence: if refs.is_empty() {
                    None
                } else {
                    Some(evidence(&refs)?)
                },
            };
            let c = crate::open_case_for_write(&case)?;
            let (new_id, e) = te::edit(c.conn(), &actor, &id, edit)?;
            let what = if new_id == id {
                "edited".to_string()
            } else {
                format!("proposed to supersede {id}")
            };
            print_decision(&e, &what, json)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}
