//! `sparrow audit verify|log`: check and read the hash-chained audit trail.

use anyhow::{Context, Result};
use sparrow_core::Case;
use sparrow_core::case::audit::{self, ChainReport};
use sparrow_core::case::text::display_safe_line;
use std::path::Path;
use std::process::ExitCode;

/// The exit code of `audit verify` on a broken chain.
pub const BROKEN_CHAIN: u8 = 3;

fn print_report(r: &ChainReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(r)?);
        return Ok(());
    }
    if r.ok {
        println!(
            "audit chain ok: {} entries, head {}",
            r.entries,
            r.head_hash.as_deref().unwrap_or("(none)")
        );
    } else {
        println!(
            "audit chain BROKEN at seq {}: {} ({} entries)",
            r.first_bad_seq.unwrap_or(0),
            display_safe_line(r.problem.as_deref().unwrap_or("")),
            r.entries
        );
    }
    if !r.acknowledged_breaks.is_empty() {
        let seqs: Vec<String> = r.acknowledged_breaks.iter().map(i64::to_string).collect();
        println!("acknowledged breaks at seq {}", seqs.join(", "));
    }
    Ok(())
}

/// Verify the chain (read-only), or with `acknowledge` first record every open break as an entry by `actor`.
/// Exit code 0 when the chain is ok, [`BROKEN_CHAIN`] otherwise.
pub fn verify(
    case_path: &Path,
    acknowledge: bool,
    agent: Option<String>,
    analyst: Option<String>,
    json: bool,
) -> Result<ExitCode> {
    let report = if acknowledge {
        let actor = super::actor::resolve(agent, analyst)?;
        let case = crate::open_case_for_write(case_path)?;
        // One entry per open break; each closes only the break it names.
        let mut r = audit::verify(case.conn())?;
        for _ in 0..=r.entries {
            if r.ok {
                break;
            }
            audit::acknowledge_break(case.conn(), &actor)?;
            r = audit::verify(case.conn())?;
        }
        r
    } else {
        let case = Case::open_read_only(case_path)?;
        audit::verify(case.conn())?
    };
    print_report(&report, json)?;
    Ok(if report.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(BROKEN_CHAIN)
    })
}

/// The entries in seq order, only those of `object` (`TYPE:ID`) when given.
pub fn log(case_path: &Path, object: Option<&str>, json: bool) -> Result<ExitCode> {
    let object = object
        .map(|o| {
            o.split_once(':')
                .filter(|(t, i)| !t.is_empty() && !i.is_empty())
                .with_context(|| format!("--object must be TYPE:ID, got {o:?}"))
        })
        .transpose()?;
    let case = Case::open_read_only(case_path)?;
    let entries = audit::log(case.conn(), object)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "entries": entries }))?
        );
    } else {
        for e in &entries {
            let on_behalf = e
                .on_behalf_of
                .as_deref()
                .map(|a| format!(" for {}", display_safe_line(a)))
                .unwrap_or_default();
            println!(
                "{} {} {}{on_behalf} {} {}:{}",
                e.seq,
                audit::ts_text(&e.ts),
                display_safe_line(&e.actor),
                display_safe_line(&e.action),
                display_safe_line(&e.object_type),
                display_safe_line(&e.object_id)
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}
