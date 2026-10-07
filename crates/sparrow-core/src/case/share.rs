//! Share bundles (Phase 8): one analyst's reviewed work on a case, exported as a JSON file so a second analyst
//! with the same evidence can import it as proposals. A bundle holds A's resulting state (what A concluded), never
//! A's trail: only objects whose current decision is accepted (an analyst decision, or an agent decision a reviewer
//! accepted) and the analyst's own notes. Export reads the case and writes nothing (the caller writes the file).

use crate::case::actor::Reviewer;
use crate::case::audit;
use crate::case::timeline_entries::{self, EvidenceRef};
use crate::{Error, Result};
use duckdb::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// The bundle format this build writes and reads.
pub const FORMAT: u32 = 1;
/// The largest bundle file import accepts.
pub const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub format: u32,
    /// `audit::ts_text` of the export time.
    pub exported_at: String,
    /// `analyst:<name>` who exported it.
    pub analyst: String,
    pub source_case_id: String,
    pub source_audit_head: Head,
    pub evidence: Evidence,
    pub items: Vec<Item>,
}

/// The exporting case's audit chain head: its entry count and the hash of the last entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub seq: i64,
    pub hash: Option<String>,
}

/// What the case was built from: a bundle is only imported into a case with the same source files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Sorted, distinct sha256 of every source file with status `parsed`.
    pub source_files: Vec<String>,
    /// Sorted `rule_id:rule_sha256` of the latest detection run (`detection_runs`, max run_id per tenant).
    pub rules: Vec<String>,
}

/// One object's resulting state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Item {
    Finding {
        finding_id: String,
        status: String,
        disposition_reason: Option<String>,
    },
    Indicator {
        tenant_key: Option<String>,
        ioc_type: String,
        value: String,
        verdict: String,
        note: Option<String>,
        active: bool,
    },
    TimelineEntry {
        entry_id: String,
        tenant_key: Option<String>,
        event_time: String,
        title: String,
        narrative: Option<String>,
        phase: String,
        status: String,
        /// `table:record_key`, sorted.
        evidence: Vec<String>,
    },
    Note {
        /// A [`crate::case::notes::NoteTarget`] in its text form.
        target: String,
        text: String,
    },
}

impl Item {
    /// Stable, unambiguous key: `finding:<id>`, `indicator:` + the compact JSON array `[tenant_key or null, type,
    /// value]`, `timeline_entry:<id>`, `note:<first 16 hex of sha256(target \x1f text)>`.
    pub fn key(&self) -> String {
        match self {
            Item::Finding { finding_id, .. } => format!("finding:{finding_id}"),
            Item::Indicator {
                tenant_key,
                ioc_type,
                value,
                ..
            } => format!(
                "indicator:{}",
                serde_json::Value::from(vec![
                    tenant_key
                        .as_deref()
                        .map_or(serde_json::Value::Null, Into::into),
                    ioc_type.as_str().into(),
                    value.as_str().into(),
                ])
            ),
            Item::TimelineEntry { entry_id, .. } => format!("timeline_entry:{entry_id}"),
            Item::Note { target, text } => {
                let mut h = Sha256::new();
                h.update(target.as_bytes());
                h.update([0x1f]);
                h.update(text.as_bytes());
                format!("note:{}", &hex::encode(h.finalize())[..16])
            }
        }
    }
}

/// The case's evidence identity: its parsed source files and the rule set of its latest detection run.
pub fn evidence_of(conn: &Connection) -> Result<Evidence> {
    let strings = |sql: &str| -> Result<Vec<String>> {
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    };
    Ok(Evidence {
        source_files: strings(
            "SELECT DISTINCT sha256 FROM source_files \
             WHERE CAST(status AS VARCHAR) = 'parsed' AND sha256 IS NOT NULL ORDER BY 1",
        )?,
        rules: strings(
            "SELECT DISTINCT rule_id || ':' || rule_sha256 FROM detection_runs \
             WHERE (tenant_key, run_id) IN (SELECT tenant_key, max(run_id) FROM detection_runs GROUP BY tenant_key) \
             ORDER BY 1",
        )?,
    })
}

fn findings(conn: &Connection) -> Result<Vec<Item>> {
    let mut stmt = conn.prepare(
        "SELECT finding_id, CAST(status AS VARCHAR), disposition_reason FROM findings \
         WHERE CAST(review_state AS VARCHAR) = 'accepted' ORDER BY finding_id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Item::Finding {
            finding_id: r.get(0)?,
            status: r.get(1)?,
            disposition_reason: r.get(2)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

fn indicators(conn: &Connection) -> Result<Vec<Item>> {
    let mut stmt = conn.prepare(
        "SELECT tenant_key, CAST(type AS VARCHAR), value, CAST(verdict AS VARCHAR), note, removed_at IS NULL \
         FROM case_indicators WHERE CAST(review_state AS VARCHAR) = 'accepted' \
         ORDER BY tenant_key NULLS FIRST, CAST(type AS VARCHAR), value, indicator_id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Item::Indicator {
            tenant_key: r.get(0)?,
            ioc_type: r.get(1)?,
            value: r.get(2)?,
            verdict: r.get(3)?,
            note: r.get(4)?,
            active: r.get(5)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

fn entries(conn: &Connection) -> Result<Vec<Item>> {
    let mut out = Vec::new();
    for e in timeline_entries::list(conn, None, Some("accepted"))? {
        if !matches!(e.status.as_str(), "verified" | "rejected") {
            continue;
        }
        out.push(Item::TimelineEntry {
            evidence: e.evidence.iter().map(EvidenceRef::text).collect(),
            event_time: audit::ts_text(&e.event_time),
            entry_id: e.entry_id,
            tenant_key: e.tenant_key,
            title: e.title,
            narrative: e.narrative,
            phase: e.phase,
            status: e.status,
        });
    }
    Ok(out)
}

fn notes(conn: &Connection) -> Result<Vec<Item>> {
    let mut stmt = conn.prepare(
        "SELECT CAST(object_type AS VARCHAR), object_id, source_table, text FROM annotations \
         WHERE starts_with(actor, 'analyst:') ORDER BY created_at, annotation_id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        let (object_type, id, table, text) = row?;
        let target = match (object_type.as_str(), table) {
            ("finding", _) => format!("finding:{id}"),
            ("timeline_entry", _) => format!("entry:{id}"),
            ("indicator", _) => format!("ioc:{id}"),
            ("evidence", Some(t)) => format!("{t}:{id}"),
            (other, _) => {
                return Err(Error::Invalid(format!(
                    "a note on {other} {id} has no target form"
                )));
            }
        };
        let item = Item::Note { target, text };
        // Resulting state: the same text on the same target twice is one note (and one item key).
        if seen.insert(item.key()) {
            out.push(item);
        }
    }
    Ok(out)
}

/// `analyst`'s reviewed work on the case: accepted findings, indicators and verified or rejected timeline entries,
/// and analyst notes (identical target and text once), in that order (each sorted). Refused when the audit chain is broken, since the bundle names
/// its head. Writes nothing.
pub fn export(conn: &Connection, analyst: &Reviewer) -> Result<Bundle> {
    let chain = audit::verify(conn)?;
    if !chain.ok {
        return Err(Error::Invalid(format!(
            "the audit chain is broken ({}); a bundle cannot be exported until it is verified or acknowledged",
            chain.problem.as_deref().unwrap_or("see audit verify")
        )));
    }
    let mut items = findings(conn)?;
    items.extend(indicators(conn)?);
    items.extend(entries(conn)?);
    items.extend(notes(conn)?);
    Ok(Bundle {
        format: FORMAT,
        exported_at: audit::ts_text(&audit::now()),
        analyst: analyst.as_str().to_string(),
        source_case_id: audit::case_id(conn)?,
        source_audit_head: Head {
            seq: chain.entries,
            hash: chain.head_hash,
        },
        evidence: evidence_of(conn)?,
        items,
    })
}

/// Pretty JSON bytes and their hex sha256 (what the analyst sends out of band). Refused above
/// [`MAX_BUNDLE_BYTES`], since import would refuse the file.
pub fn to_bytes(b: &Bundle) -> Result<(Vec<u8>, String)> {
    let bytes = serde_json::to_vec_pretty(b)
        .map_err(|e| Error::Invalid(format!("cannot serialise the bundle: {e}")))?;
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(Error::Invalid(format!(
            "the bundle is {} bytes; a share bundle is limited to {MAX_BUNDLE_BYTES} bytes (16 MiB)",
            bytes.len()
        )));
    }
    let sha = hex::encode(Sha256::digest(&bytes));
    Ok((bytes, sha))
}
