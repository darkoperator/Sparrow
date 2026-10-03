//! The Markdown customer report (Addendum D.6). Sections in a fixed order: Scope, Executive summary (a placeholder
//! for the analyst, never a conclusion), Timeline by phase (verified entries), Findings (confirmed), Indicators
//! (malicious and suspicious), Evidence gaps, Method and integrity. Pending AI decisions are included and labelled
//! "AI decision — not reviewed" unless `reviewed_only` keeps accepted decisions only. Every line that states
//! evidence cites it as a footnote: `table:record_key` and the source file and line.

use super::header;
use super::text::{block, indented, md_cell, single_line as one};
use super::{
    Provenance, entry_provenance, evidence_gaps, finding_provenance, indicator_rows, source_refs,
    when,
};
use crate::Result;
use crate::case::notes::{Note, NoteTarget, notes_for};
use crate::case::read::{self, EvidenceRow, FindingFilter};
use crate::case::timeline_entries::{self, Phase};
use crate::detect::load::RuleSet;
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

/// The label of an agent note: notes carry no review state, so none of them is ever reviewed.
pub const LABEL_AGENT_NOTE: &str = "agent note — not reviewed";

/// The notes as list items, each labelled [`LABEL_AGENT_NOTE`]; none at all under `--reviewed-only` (no reviewer
/// accepted them).
fn note_lines(out: &mut Vec<String>, notes: &[Note], reviewed_only: bool) {
    if reviewed_only {
        return;
    }
    for n in notes {
        let by = match &n.on_behalf_of {
            Some(o) => format!("{} on behalf of {o}", n.actor),
            None => n.actor.clone(),
        };
        out.push(format!(
            "  - {LABEL_AGENT_NOTE} ({} at {} UTC): {}",
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
    let empty_rules = RuleSet {
        rules: Vec::new(),
        lists: BTreeMap::new(),
        list_meta: BTreeMap::new(),
        warnings: Vec::new(),
    };
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
        let detail = read::finding_show(conn, &f.finding_id, &empty_rules)?;
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

    // ---- Method and integrity
    doc.push(String::new());
    doc.push("## Method and integrity".into());
    doc.push(String::new());
    doc.push(
        "Sparrow ingested the collector output into a case database, enriched it and ran its detection rules. \
         Findings, indicators and timeline entries were triaged by an AI agent through the command line: every such \
         decision is recorded in a hash-chained audit trail with who made it and when, and starts as an AI decision \
         that no analyst has reviewed. Review happens outside Sparrow; an item shows `accepted` or `discarded` only \
         when a reviewer's decision was recorded, and a review covers the latest decision on each object (an \
         earlier decision that a later one replaced was not itself reviewed). Notes carry no review state and are \
         labelled as agent notes."
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
