//! `sparrow note add <target> --text`: notes on findings, timeline entries, indicators and evidence rows.

use crate::ActorArgs;
use anyhow::Result;
use clap::Subcommand;
use sparrow_core::case::notes::{NoteTarget, add_note};
use sparrow_core::case::text::display_safe_line;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Subcommand)]
pub enum NoteCommand {
    /// Add a note to finding:ID, entry:ID, ioc:ID or an evidence row <table>:<record_key>
    Add {
        /// What the note is about: finding:ID, entry:ID, ioc:ID or <table>:<record_key>
        target: String,
        /// The note (plain text, up to 16 KiB)
        #[arg(long)]
        text: String,
        /// Case database file
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
                let mut v = serde_json::to_value(&e)?;
                v["annotation_id"] = id.clone().into();
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                println!(
                    "note {id} on {} by {}",
                    display_safe_line(&target),
                    display_safe_line(&e.actor)
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
