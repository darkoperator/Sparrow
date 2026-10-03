//! `sparrow note add <target> --text`: notes on findings, timeline entries, indicators and evidence rows.

use crate::ActorArgs;
use anyhow::Result;
use clap::Subcommand;
use sparrow_core::case::notes::{NoteTarget, add_note};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Subcommand)]
pub enum NoteCommand {
    /// Add a note to finding:ID, entry:ID, ioc:ID or an evidence row <table>:<record_key>
    Add {
        target: String,
        #[arg(long)]
        text: String,
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
}

pub fn run(command: NoteCommand, json: bool) -> Result<ExitCode> {
    match command {
        NoteCommand::Add {
            target,
            text,
            case,
            actor,
        } => {
            let actor = actor.resolve()?;
            let t = NoteTarget::parse(&target)?;
            let c = crate::open_case_for_write(&case)?;
            let (id, e) = add_note(c.conn(), &actor, t, &text)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&e)?);
            } else {
                println!("note {id} on {target} by {}", e.actor);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
