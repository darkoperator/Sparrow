//! `sparrow timeline-entry propose|verify|reject|edit`: curated timeline entries as agent decisions (Addendum D.5).
//! `timeline-entry list` is a read command (`cmd::read`).

use crate::ActorArgs;
use crate::cmd::finding::{print_decision, print_decision_with};
use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::Subcommand;
use sparrow_core::Error;
use sparrow_core::case::timeline_entries::{self as te, EntryEdit, EvidenceRef, NewEntry, Phase};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Subcommand)]
pub enum TimelineEntryCommand {
    /// List the entries, by event time
    List {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// proposed, verified, rejected or superseded
        #[arg(long)]
        status: Option<String>,
        /// pending_review, accepted or discarded
        #[arg(long)]
        review_state: Option<String>,
    },
    /// Propose an entry (verify it once its evidence is attached)
    Propose {
        /// When the event happened, RFC 3339 (for example 2026-08-03T09:00:00Z)
        #[arg(long)]
        time: String,
        /// One line saying what happened (up to 500 characters)
        #[arg(long)]
        title: String,
        /// What happened and why it matters (optional)
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
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Verify a proposed entry (needs evidence that exists in the case)
    Verify {
        /// Entry id (see `timeline-entry list`)
        id: String,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Reject a proposed or verified entry
    Reject {
        /// Entry id (see `timeline-entry list`)
        id: String,
        /// Why the entry is wrong
        #[arg(long)]
        reason: String,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Edit an entry: in place when proposed; a verified entry gets a successor that supersedes it once verified
    Edit {
        /// Entry id (see `timeline-entry list`)
        id: String,
        /// New event time, RFC 3339
        #[arg(long)]
        time: Option<String>,
        /// New title
        #[arg(long)]
        title: Option<String>,
        /// New narrative
        #[arg(long, conflicts_with = "clear_narrative")]
        narrative: Option<String>,
        /// Remove the narrative
        #[arg(long)]
        clear_narrative: bool,
        /// New phase (as for propose)
        #[arg(long)]
        phase: Option<String>,
        /// Replaces the evidence (repeatable)
        #[arg(long)]
        evidence: Vec<String>,
        /// Case database file
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
        TimelineEntryCommand::List {
            case,
            status,
            review_state,
        } => {
            return super::read::timeline_entry_list(
                &case,
                status.as_deref(),
                review_state.as_deref(),
                json,
            );
        }
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
            let (new_id, e) = te::propose(c.conn(), &actor, entry)?;
            print_decision_with(&e, &[("entry_id", new_id.into())], "proposed", json)?;
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
            clear_narrative,
            phase,
            evidence: refs,
            case,
            actor,
        } => {
            let actor = actor.resolve()?;
            let edit = EntryEdit {
                event_time: t.as_deref().map(time).transpose()?,
                title,
                narrative: if clear_narrative {
                    Some(None)
                } else {
                    narrative.map(Some)
                },
                phase: phase.as_deref().map(Phase::parse).transpose()?,
                evidence: if refs.is_empty() {
                    None
                } else {
                    Some(evidence(&refs)?)
                },
            };
            let c = crate::open_case_for_write(&case)?;
            let (new_id, e) = te::edit(c.conn(), &actor, &id, edit)?;
            // In place (same id), or a successor that supersedes the verified entry once verified.
            let (what, supersedes) = if new_id == id {
                ("edited".to_string(), serde_json::Value::Null)
            } else {
                (format!("proposed to supersede {id}"), id.clone().into())
            };
            print_decision_with(
                &e,
                &[("entry_id", new_id.into()), ("supersedes", supersedes)],
                &what,
                json,
            )?;
        }
    }
    Ok(ExitCode::SUCCESS)
}
