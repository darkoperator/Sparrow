//! The Markdown customer report (Addendum D.6). Sections in a fixed order: Scope, Executive summary (a placeholder
//! for the analyst, never a conclusion), Timeline by phase (verified entries), Findings (confirmed), Indicators
//! (malicious and suspicious), Devices to contain, Evidence gaps, Evidence coverage and what to request, Method and integrity. Pending AI decisions are included and labelled
//! "AI decision — not reviewed" unless `reviewed_only` keeps accepted decisions only. Every line that states
//! evidence cites it as a footnote: `table:record_key` and the source file and line.

use super::facts_text::{self, ADDRESSES_SHOWN, FactRules};
use super::header;
use super::text::{block, indented, md_cell, single_line as one};
use super::{
    LABEL_ANALYST_NOTE, Provenance, entry_provenance, evidence_gaps, finding_provenance,
    indicator_rows, source_refs, when,
};
use crate::Result;
use crate::case::coverage;
use crate::case::notes::{Note, NoteTarget, notes_for};
use crate::case::read::{self, EvidenceRow, FactsField, FindingFilter};
use crate::case::timeline_entries::{self, Phase};
use crate::data::DataDirs;
use crate::summary::summarize_conn;
use chrono::{DateTime, Utc};
use duckdb::Connection;
use std::collections::BTreeMap;
use std::io::Write;

#[derive(Debug, Clone)]
pub struct ReportOpts {
    /// Keep accepted decisions only (the default includes pending AI decisions, labelled).
    pub reviewed_only: bool,
    pub generated_at: DateTime<Utc>,
    /// Where the rules come from when the facts need them (see [`FactRules`]): the same directories as the other
    /// commands. `DataDirs::default()` is the built-in rules only.
    pub dirs: DataDirs,
}

/// Source files and lines named per footnote (a record seen in several collector files lists the first few).
const SIGHTINGS_PER_FOOTNOTE: usize = 3;

/// The evidence rows listed per finding; the rest are counted.
const EVIDENCE_PER_FINDING: usize = 20;

/// Footnotes in order of first use.
#[derive(Default)]
struct Footnotes {
    order: Vec<(String, String)>,
    index: BTreeMap<(String, String), usize>,
}

impl Footnotes {
    fn mark(&mut self, table: &str, key: &str) -> String {
        let k = (table.to_string(), key.to_string());
        let n = match self.index.get(&k) {
            Some(n) => *n,
            None => {
                self.order.push(k.clone());
                self.index.insert(k, self.order.len());
                self.order.len()
            }
        };
        format!("[^{n}]")
    }
}

fn keep(prov: &Provenance, reviewed_only: bool) -> bool {
    !reviewed_only || prov.review_state.as_deref() == Some("accepted")
}

/// The label of an agent note: notes carry no review state, so an agent's is never reviewed.
pub const LABEL_AGENT_NOTE: &str = "agent note — not reviewed";

/// The notes as list items, an analyst's labelled [`LABEL_ANALYST_NOTE`] and an agent's [`LABEL_AGENT_NOTE`]. Under
/// `--reviewed-only` only analyst notes (an analyst's own words need no reviewer; no reviewer accepted an agent's).
fn note_lines(out: &mut Vec<String>, notes: &[Note], reviewed_only: bool) {
    for n in notes {
        let analyst = n.actor.starts_with("analyst:");
        if reviewed_only && !analyst {
            continue;
        }
        let label = if analyst {
            LABEL_ANALYST_NOTE
        } else {
            LABEL_AGENT_NOTE
        };
        let by = match &n.on_behalf_of {
            Some(o) => format!("{} on behalf of {o}", n.actor),
            None => n.actor.clone(),
        };
        out.push(format!(
            "  - {label} ({} at {} UTC): {}",
            one(&by),
            when(&n.created_at),
            block(&n.text).replace('\n', "\n    ")
        ));
    }
}

fn provenance_lines(out: &mut Vec<String>, p: &Provenance, indent: &str) {
    let label = p.label();
    if label.is_empty() {
        return;
    }
    out.push(format!(
        "{indent}- Decision: _{}_ ({})",
        one(&label),
        one(&p.decided_text())
    ));
    if let Some(c) = p.review_comment.as_deref().filter(|c| !c.is_empty()) {
        out.push(format!("{indent}- Reviewer comment: {}", one(c)));
    }
}

fn evidence_line(fn_: &mut Footnotes, e: &EvidenceRow) -> String {
    let mark = fn_.mark(&e.source_table, &e.record_key);
    match &e.timeline {
        Some(t) => {
            let mut parts = vec![format!("{} UTC", when(&t.event_time)), one(&t.category)];
            for v in [&t.operation, &t.actor_upn, &t.ip, &t.summary] {
                if let Some(v) = v.as_deref().filter(|v| !v.is_empty()) {
                    parts.push(one(v));
                }
            }
            format!("{}{mark}", parts.join(" · "))
        }
        None => format!("{}:{}{mark}", one(&e.source_table), one(&e.record_key)),
    }
}

/// Write the report to `out`.
pub fn write(conn: &Connection, out: &mut dyn Write, opts: &ReportOpts) -> Result<()> {
    let head = header::build(conn, opts.generated_at)?;
    let legacy = super::legacy_objects(conn)?;
    let summary = summarize_conn(conn)?;
    let mut notes_fn = Footnotes::default();
    // Rules are needed only to tell which findings should have facts when the enrichment is not current.
    let rules = FactRules::for_case(conn, &opts.dirs)?;
    let mut doc: Vec<String> = Vec::new();

    doc.push("# Sparrow case report".into());
    doc.push(String::new());
    for (k, v) in head.pairs() {
        doc.push(format!("- **{k}:** {v}"));
    }
    if opts.reviewed_only {
        doc.push("- **Decisions shown:** accepted decisions only (`--reviewed-only`)".into());
    } else {
        doc.push(
            "- **Decisions shown:** all, each labelled with its review state (an agent decision nobody has reviewed says so)".into(),
        );
    }

    // ---- Scope
    doc.push(String::new());
    doc.push("## Scope".into());
    for t in &summary.tenants {
        doc.push(String::new());
        let name = t.tenant_name.as_deref().unwrap_or(&t.tenant_key);
        doc.push(format!("### Tenant {}", one(name)));
        doc.push(String::new());
        doc.push(format!("- Tenant key: {}", one(&t.tenant_key)));
        if let Some(id) = &t.tenant_id {
            doc.push(format!("- Tenant id: {}", one(id)));
        }
        if !t.domains.is_empty() {
            doc.push(format!("- Domains: {}", one(&t.domains.join(", "))));
        }
        let start = t
            .collections
            .iter()
            .filter_map(|c| c.window_start.as_deref())
            .min();
        let end = t
            .collections
            .iter()
            .filter_map(|c| c.window_end.as_deref())
            .max();
        if let (Some(s), Some(e)) = (start, end) {
            doc.push(format!("- Coverage window: {} to {}", one(s), one(e)));
        }
        for c in &t.collections {
            doc.push(format!(
                "- Collection {}: {}{}",
                c.collection_id,
                one(&c.tool),
                c.collected_at
                    .as_deref()
                    .map(|a| format!(", collected {}", one(a)))
                    .unwrap_or_default()
            ));
        }
        if !t.coverage.is_empty() {
            doc.push(String::new());
            doc.push("| Evidence table | Rows | First | Last |".into());
            doc.push("| --- | ---: | --- | --- |".into());
            for c in &t.coverage {
                doc.push(format!(
                    "| {} | {} | {} | {} |",
                    md_cell(&c.source_table),
                    c.rows,
                    md_cell(c.first.as_deref().unwrap_or("")),
                    md_cell(c.last.as_deref().unwrap_or(""))
                ));
            }
        }
    }

    // ---- Executive summary
    doc.push(String::new());
    doc.push("## Executive summary".into());
    doc.push(String::new());
    doc.push("_Analyst to write._".into());

    // ---- Accounts (the roll-up detection builds; facts, not decisions)
    doc.push(String::new());
    doc.push("## Accounts".into());
    doc.push(String::new());
    accounts_section(conn, &mut doc, opts.reviewed_only)?;

    // ---- Timeline by phase
    doc.push(String::new());
    doc.push("## Timeline by phase".into());
    let entries = timeline_entries::list(conn, Some("verified"), None)?;
    let mut shown_entries = 0;
    for phase in Phase::ALL {
        let mut lines: Vec<String> = Vec::new();
        for e in entries.iter().filter(|e| e.phase == phase.as_str()) {
            let prov = entry_provenance(e, &legacy);
            if !keep(&prov, opts.reviewed_only) {
                continue;
            }
            shown_entries += 1;
            let marks: String = e
                .evidence
                .iter()
                .map(|r| notes_fn.mark(&r.source_table, &r.record_key))
                .collect();
            lines.push(format!(
                "- **{} UTC** — {}{marks}",
                when(&e.event_time),
                one(&e.title)
            ));
            if let Some(n) = e.narrative.as_deref().filter(|n| !n.is_empty()) {
                lines.push(format!("  {}", indented(n)));
            }
            provenance_lines(&mut lines, &prov, "  ");
            note_lines(
                &mut lines,
                &notes_for(conn, &NoteTarget::Entry(e.entry_id.clone()))?,
                opts.reviewed_only,
            );
        }
        if !lines.is_empty() {
            doc.push(String::new());
            doc.push(format!("### {}", phase.as_str().replace('_', " ")));
            doc.push(String::new());
            doc.extend(lines);
        }
    }
    if shown_entries == 0 {
        doc.push(String::new());
        doc.push("_No verified timeline entries._".into());
    }

    // ---- Findings
    doc.push(String::new());
    doc.push("## Findings".into());
    let findings = read::finding_list(
        conn,
        &FindingFilter {
            status: Some("confirmed".into()),
            ..FindingFilter::default()
        },
    )?;
    let mut shown_findings = 0;
    for f in &findings {
        let prov = finding_provenance(f, &legacy);
        if !keep(&prov, opts.reviewed_only) {
            continue;
        }
        shown_findings += 1;
        let detail = read::finding_show(conn, &f.finding_id, &rules.set)?;
        doc.push(String::new());
        doc.push(format!("### {} — {}", one(&f.severity), one(&f.title)));
        doc.push(String::new());
        doc.push(format!(
            "- Finding `{}`{} · status **{}**{}",
            one(&f.finding_id),
            f.rule_id
                .as_deref()
                .map(|r| format!(" · rule `{}`", one(r)))
                .unwrap_or_default(),
            one(&f.status),
            f.actor_upn
                .as_deref()
                .map(|a| format!(" · user {}", one(a)))
                .unwrap_or_default()
        ));
        if let (Some(a), Some(b)) = (&f.first_seen, &f.last_seen) {
            doc.push(format!("- Seen {} to {} UTC", when(a), when(b)));
        }
        if let Some(r) = f.disposition_reason.as_deref().filter(|r| !r.is_empty()) {
            doc.push(format!("- Reason: {}", one(r)));
        }
        provenance_lines(&mut doc, &prov, "");
        let mut note_buf = Vec::new();
        note_lines(&mut note_buf, &detail.notes, opts.reviewed_only);
        if !note_buf.is_empty() {
            doc.push("- Notes:".into());
            doc.extend(note_buf);
        }
        match &detail.facts {
            Some(FactsField::Present { facts }) => {
                doc.push("- Facts:".into());
                for line in facts_text::fact_lines(facts) {
                    doc.push(format!("  - {line}"));
                }
            }
            Some(FactsField::Unavailable { facts_unavailable }) => {
                doc.push(format!(
                    "- {}",
                    facts_text::unavailable_line(&rules.note(facts_unavailable))
                ));
            }
            None => {}
        }
        if !detail.evidence.is_empty() {
            doc.push(format!("- Evidence ({} rows):", detail.evidence.len()));
            for e in detail.evidence.iter().take(EVIDENCE_PER_FINDING) {
                doc.push(format!("  - {}", evidence_line(&mut notes_fn, e)));
            }
            if detail.evidence.len() > EVIDENCE_PER_FINDING {
                doc.push(format!(
                    "  - … {} more evidence rows (`sparrow finding show {}`)",
                    detail.evidence.len() - EVIDENCE_PER_FINDING,
                    one(&f.finding_id)
                ));
            }
        }
    }
    if shown_findings == 0 {
        doc.push(String::new());
        doc.push("_No confirmed findings._".into());
    }

    // ---- Indicators
    doc.push(String::new());
    doc.push("## Indicators".into());
    let indicators: Vec<_> = indicator_rows(conn)?
        .into_iter()
        .filter(|i| i.removed_at.is_none())
        .filter(|i| i.verdict == "malicious" || i.verdict == "suspicious")
        .filter(|i| keep(&i.prov, opts.reviewed_only))
        .collect();
    doc.push(String::new());
    if indicators.is_empty() {
        doc.push("_No malicious or suspicious indicators._".into());
    } else {
        doc.push("| Type | Value | Verdict | Note | Decision |".into());
        doc.push("| --- | --- | --- | --- | --- |".into());
        for i in &indicators {
            doc.push(format!(
                "| {} | {} | {} | {} | {} |",
                md_cell(&i.ty),
                md_cell(&i.value),
                md_cell(&i.verdict),
                md_cell(i.note.as_deref().unwrap_or("")),
                md_cell(&format!("{} ({})", i.prov.label(), i.prov.decided_text()))
            ));
        }
    }

    // ---- Devices to contain (the high-confidence suspect devices that are not removed; low-confidence ones are counted)
    doc.push(String::new());
    doc.push("## Devices to contain".into());
    doc.push(String::new());
    let suspects = crate::case::devices::suspect_devices(conn, None)?;
    let any_suspect = !suspects.is_empty();
    let (removed, devices): (Vec<_>, Vec<_>) = suspects
        .into_iter()
        .partition(|d| d.lifecycle.status == crate::case::devices::DeviceStatus::Removed);
    // Devices reached only through impossible-travel legs are weak evidence: counted here, listed in devices.csv, the
    // workbook and the app.
    let (devices, low): (Vec<_>, Vec<_>) = devices
        .into_iter()
        .partition(|d| d.confidence == crate::case::devices::Confidence::High);
    let sources =
        super::devices_csv::first_sources(conn, &super::devices_csv::mark_keys(&devices))?;
    if !any_suspect {
        doc.push("No device was seen on a malicious IP.".into());
    } else {
        if devices.is_empty() {
            // Decided from the unfiltered list: say why nothing is listed.
            if removed.is_empty() {
                doc.push("No high-confidence device was seen on a malicious IP.".into());
            } else {
                let n = removed.len();
                let listed = if n == 1 {
                    "1 removed device is listed in devices.csv".to_string()
                } else {
                    format!("{n} removed devices are listed in devices.csv")
                };
                doc.push(if low.is_empty() {
                    // Everything seen was removed.
                    format!("Every device seen on a malicious IP has been removed ({listed}).")
                } else {
                    // Low-confidence devices that are not removed remain, so not every device was removed.
                    format!("No high-confidence device is left to contain; {listed}.")
                });
            }
        } else {
            doc.push(
                "| Status | Device | Name | Last active | Users | Malicious IPs | Other IPs |"
                    .into(),
            );
            doc.push("| --- | --- | --- | --- | --- | --- | --- |".into());
        }
        for d in &devices {
            let mut status = d.lifecycle.status.as_str().to_string();
            let note = super::devices_csv::note(d.lifecycle.status);
            if !note.is_empty() {
                status.push_str(&format!(" — {note}"));
            }
            let device = d.device_id.clone();
            doc.push(format!(
                "| {} | {} | {} | {} | {} | {} | {} |",
                md_cell(&status),
                md_cell(&device),
                md_cell(d.display_name.as_deref().unwrap_or("")),
                md_cell(&{
                    let src = super::devices_csv::mark_source(&sources, &d.lifecycle.last_active);
                    match (&d.lifecycle.last_active, src.is_empty()) {
                        (None, _) => String::new(),
                        (Some(m), true) => format!("{} UTC", when(&m.at)),
                        (Some(m), false) => format!("{} UTC ({src})", when(&m.at)),
                    }
                }),
                md_cell(&d.users.join("; ")),
                md_cell(&d.malicious_ips.join("; ")),
                md_cell(
                    &d.other_ips
                        .iter()
                        .map(super::devices_csv::other_ip_text)
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            ));
        }
        if !low.is_empty() {
            if !devices.is_empty() {
                doc.push(String::new());
            }
            doc.push(if low.len() == 1 {
                "1 more low-confidence device (reached only through impossible-travel legs) is listed in devices.csv and the app.".to_string()
            } else {
                format!(
                    "{} more low-confidence devices (reached only through impossible-travel legs) are listed in devices.csv and the app.",
                    low.len()
                )
            });
        }
    }

    // ---- Evidence gaps
    doc.push(String::new());
    doc.push("## Evidence gaps".into());
    doc.push(String::new());
    let gaps = evidence_gaps(conn)?;
    if gaps.is_empty() {
        doc.push("_Every evidence source Sparrow expects was collected._".into());
    } else {
        doc.push("| Tenant | Evidence | Status | Why | Remediation |".into());
        doc.push("| --- | --- | --- | --- | --- |".into());
        for g in &gaps {
            doc.push(format!(
                "| {} | {} | {} | {} | {} |",
                md_cell(&g.tenant_key),
                md_cell(&g.title),
                md_cell(&g.status),
                md_cell(&g.reason),
                md_cell(g.remediation.as_deref().unwrap_or(""))
            ));
        }
    }

    // ---- Evidence coverage and what to request
    doc.push(String::new());
    doc.push("## Evidence coverage and what to request".into());
    doc.push(String::new());
    if opts.reviewed_only {
        doc.push(format!("_{}_", one(COVERAGE_OMITTED)));
    } else {
        coverage_section(conn, &mut doc, &opts.dirs)?;
    }

    // ---- Method and integrity
    doc.push(String::new());
    doc.push("## Method and integrity".into());
    doc.push(String::new());
    doc.push(
        "Sparrow ingested the collector output into a case database, enriched it and ran its detection rules. \
         Findings, indicators and timeline entries were triaged by decisions, each recorded in a hash-chained audit \
         trail with who made it and when. A decision is either an agent decision, made by an AI agent through the \
         command line, which stays an AI decision that no analyst has reviewed until a reviewer accepts or discards \
         it, or an analyst decision, made by an analyst in the review app and reviewed when made. An item shows \
         `accepted` or `discarded` only when a reviewer's decision was recorded, and a review covers the latest \
         decision on each object (an earlier decision that a later one replaced was not itself reviewed). Notes \
         carry no review state: agent notes are never reviewed and are left out of a reviewed-only report; analyst \
         notes are an analyst's own words and are kept."
            .into(),
    );
    doc.push(String::new());
    for (k, v) in head.pairs() {
        doc.push(format!("- {k}: {v}"));
    }
    write_footnotes(conn, &mut doc, &notes_fn)?;

    for line in &doc {
        writeln!(out, "{line}").map_err(super::io_err)?;
    }
    Ok(())
}

/// The line that replaces the Accounts table in a `--reviewed-only` report: the roll-up is computed from every
/// finding, so listing it would present accounts supported only by unreviewed or rejected findings.
pub const ACCOUNTS_OMITTED: &str =
    "Account roll-up omitted: it is computed from all findings, including ones not yet reviewed.";

/// Accounts (in the roll-up's order) the report's coverage section lists; the CLI and JSON list all.
pub const COVERAGE_ACCOUNTS_SHOWN: usize = 10;

/// The line that replaces the coverage tables in a `--reviewed-only` report: they list the accounts of the roll-up and
/// start each window at the account's first finding, reviewed or not.
pub const COVERAGE_OMITTED: &str = "Evidence coverage omitted: it covers the accounts of the roll-up and starts at their first finding, including ones not yet reviewed.";

/// Per (tenant, lower-case account): how many of its findings have an accepted review.
pub(crate) fn reviewed_counts(conn: &Connection) -> Result<BTreeMap<(String, String), u32>> {
    let accepted = read::finding_list(
        conn,
        &FindingFilter {
            review_state: Some("accepted".into()),
            ..FindingFilter::default()
        },
    )?;
    let mut counts = BTreeMap::new();
    for f in accepted {
        if let Some(a) = f
            .actor_upn
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            *counts
                .entry((f.tenant_key.clone(), a.to_lowercase()))
                .or_insert(0) += 1;
        }
    }
    Ok(counts)
}

/// The Accounts table: one row per tenant and account with findings, worst first, with how many of the account's
/// findings have an accepted review. When the roll-up is not current the section says why it is empty (the same
/// reason the read commands give) instead of listing nothing. A `--reviewed-only` report has no table, only
/// [`ACCOUNTS_OMITTED`].
fn accounts_section(conn: &Connection, doc: &mut Vec<String>, reviewed_only: bool) -> Result<()> {
    if reviewed_only {
        doc.push(format!("_{}_", one(ACCOUNTS_OMITTED)));
        return Ok(());
    }
    let page = read::accounts(conn, None, None)?;
    if let Some(w) = page.warnings.first() {
        doc.push(format!("_{}._", one(w.trim_end_matches('.'))));
        return Ok(());
    }
    doc.push(
        "_Computed by Sparrow from every finding of the case, whatever its decision: facts, not decisions. \"Reviewed\" counts the account's findings with an accepted review._".into(),
    );
    doc.push(String::new());
    if page.accounts.is_empty() {
        doc.push("_No accounts with findings._".into());
        return Ok(());
    }
    let reviewed = reviewed_counts(conn)?;
    doc.push(
        "| Tenant | Account | Worst severity | Stages | First suspicious (UTC) | Sign-in coverage (UTC) | Reviewed | Addresses |"
            .into(),
    );
    doc.push("| --- | --- | --- | --- | --- | --- | ---: | --- |".into());
    for a in &page.accounts {
        let stages: Vec<&str> = a.stages.iter().map(|s| s.as_str()).collect();
        let (items, more) = facts_text::address_items(a, ADDRESSES_SHOWN);
        let mut cell: Vec<String> = items.iter().map(|i| md_cell(i)).collect();
        if more > 0 {
            cell.push(format!("+{more} more"));
        }
        doc.push(format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |",
            md_cell(&a.tenant_key),
            md_cell(&a.upn),
            md_cell(&a.worst_severity),
            md_cell(&stages.join(", ")),
            a.first_suspicious.as_ref().map(when).unwrap_or_default(),
            facts_text::signin_coverage(a),
            reviewed
                .get(&(a.tenant_key.clone(), a.upn.to_lowercase()))
                .copied()
                .unwrap_or(0),
            cell.join("<br>")
        ));
    }
    Ok(())
}

/// Per account with findings, what each evidence source holds and over which dates, and what to request for the
/// dates it does not cover (`case::coverage`). Facts about the case, never a conclusion: "no event" in a source that
/// does not cover a date proves nothing about that date.
fn coverage_section(conn: &Connection, doc: &mut Vec<String>, dirs: &DataDirs) -> Result<()> {
    let cov = coverage::coverage(
        conn,
        &coverage::CoverageOptions {
            tenant: None,
            users: Vec::new(),
            dirs: dirs.clone(),
        },
    )?;
    for w in &cov.warnings {
        doc.push(format!("_{}._", one(w.trim_end_matches('.'))));
        doc.push(String::new());
    }
    if cov.accounts.is_empty() {
        doc.push(
            if cov.warnings.is_empty() {
                "_No accounts with findings._"
            } else {
                "_The account list is unavailable._"
            }
            .into(),
        );
        return Ok(());
    }
    doc.push(
        "_Per account: the rows each source holds and the dates they span (UTC). The reference window runs from 30 days before the account's first finding (else its first row) to the tenant's last event. A source that is absent, starts after the window starts, ends before it ends, or came from a capped export (sampled) does not show that nothing happened on the dates in its gaps._".into(),
    );
    for a in cov.accounts.iter().take(COVERAGE_ACCOUNTS_SHOWN) {
        doc.push(String::new());
        doc.push(format!(
            "**{}** (tenant {}): window {}",
            md_cell(&a.upn),
            md_cell(&a.tenant_key),
            match &a.window {
                Some(w) => format!("{} to {}", w.start, w.end),
                None => "none, the tenant has no events".to_string(),
            }
        ));
        doc.push(String::new());
        doc.push("| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |".into());
        doc.push("| --- | ---: | --- | --- | ---: | --- | --- |".into());
        for s in &a.sources {
            let gaps: Vec<String> = s
                .gaps
                .iter()
                .map(|g| format!("{} {} to {}", g.reason, g.from, g.to))
                .collect();
            doc.push(format!(
                "| {} | {} | {} | {} | {} | {} | {} |",
                md_cell(&s.title),
                coverage::thousands(s.rows),
                s.first.as_ref().map(when).unwrap_or_default(),
                s.last.as_ref().map(when).unwrap_or_default(),
                s.days,
                if s.sampled { "yes" } else { "no" },
                md_cell(&gaps.join("; "))
            ));
        }
        let own: Vec<_> = cov
            .requests
            .iter()
            .filter(|r| r.tenant_key == a.tenant_key && r.user == a.upn)
            .collect();
        if own.is_empty() {
            doc.push(String::new());
            doc.push("_Every source covers the window._".into());
            continue;
        }
        doc.push(String::new());
        doc.push("What to request:".into());
        doc.push(String::new());
        for r in own {
            let how = |h: &Option<String>| md_cell(h.as_deref().unwrap_or("none"));
            doc.push(format!(
                "- {}, {} to {} ({})",
                md_cell(&r.title),
                r.from,
                r.to,
                md_cell(&r.reasons.join(", "))
            ));
            doc.push(format!("  - Admin portal: {}", how(&r.console)));
            doc.push(format!("  - Hawk: {}", how(&r.hawk)));
            doc.push(format!(
                "  - Microsoft-Extractor-Suite: {}",
                how(&r.invictus)
            ));
        }
    }
    if cov.accounts.len() > COVERAGE_ACCOUNTS_SHOWN {
        doc.push(String::new());
        doc.push(format!(
            "+{} more accounts: run `sparrow coverage --case <file>` for all of them",
            cov.accounts.len() - COVERAGE_ACCOUNTS_SHOWN
        ));
    }
    Ok(())
}

fn write_footnotes(conn: &Connection, doc: &mut Vec<String>, f: &Footnotes) -> Result<()> {
    if f.order.is_empty() {
        return Ok(());
    }
    doc.push(String::new());
    doc.push("## Evidence references".into());
    doc.push(String::new());
    for (i, (table, key)) in f.order.iter().enumerate() {
        let refs = source_refs(conn, table, key)?;
        let refs = if refs.is_empty() {
            "no source file reference".to_string()
        } else {
            let more = refs.len().saturating_sub(SIGHTINGS_PER_FOOTNOTE);
            let mut text = one(&refs
                .iter()
                .take(SIGHTINGS_PER_FOOTNOTE)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "));
            if more > 0 {
                text.push_str(&format!(" (+{more} more sightings)"));
            }
            text
        };
        doc.push(format!(
            "[^{}]: {}:{} — {}",
            i + 1,
            one(table),
            one(key),
            refs
        ));
    }
    Ok(())
}
