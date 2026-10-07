//! Notes (`annotations`, Addendum D.3): append-only free text on evidence rows, findings, timeline entries and
//! indicators. Each note is audited (`add_note`, object_type `annotation`) but is not a decision: it has no review
//! state.

use crate::case::actor::Actor;
use crate::case::audit::{self, AuditEntry};
use crate::case::timeline_entries::{EvidenceRef, check_evidence_exists};
use crate::case::write::in_tx;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::{Connection, params};
use serde::{Serialize, Serializer};
use serde_json::json;
use sha2::{Digest, Sha256};

/// What a note is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteTarget {
    Finding(String),
    Entry(String),
    Indicator(String),
    Evidence { table: String, key: String },
}

impl NoteTarget {
    /// `finding:ID`, `entry:ID`, `ioc:ID`, or `<table>:<record_key>` for an evidence row (the table is everything
    /// before the first ':').
    pub fn parse(s: &str) -> Result<NoteTarget> {
        let bad = || {
            Error::Decision(format!(
                "a note target is finding:ID, entry:ID, ioc:ID or <table>:<record_key>, got {s:?}"
            ))
        };
        let (kind, rest) = s.split_once(':').ok_or_else(bad)?;
        if rest.is_empty() {
            return Err(bad());
        }
        Ok(match kind {
            "finding" => NoteTarget::Finding(rest.into()),
            "entry" => NoteTarget::Entry(rest.into()),
            "ioc" => NoteTarget::Indicator(rest.into()),
            _ => {
                let r = EvidenceRef::parse(s)?;
                NoteTarget::Evidence {
                    table: r.source_table,
                    key: r.record_key,
                }
            }
        })
    }

    /// The text form [`NoteTarget::parse`] reads: `finding:ID`, `entry:ID`, `ioc:ID` or `<table>:<record_key>`.
    pub fn text(&self) -> String {
        match self {
            NoteTarget::Finding(id) => format!("finding:{id}"),
            NoteTarget::Entry(id) => format!("entry:{id}"),
            NoteTarget::Indicator(id) => format!("ioc:{id}"),
            NoteTarget::Evidence { table, key } => format!("{table}:{key}"),
        }
    }

    /// (`annotations.object_type`, `object_id`, `source_table`).
    fn columns(&self) -> (&'static str, &str, Option<&str>) {
        match self {
            NoteTarget::Finding(id) => ("finding", id, None),
            NoteTarget::Entry(id) => ("timeline_entry", id, None),
            NoteTarget::Indicator(id) => ("indicator", id, None),
            NoteTarget::Evidence { table, key } => ("evidence", key, Some(table)),
        }
    }

    fn check_exists(&self, conn: &Connection) -> Result<()> {
        let (sql, id) = match self {
            NoteTarget::Finding(id) => ("SELECT count(*) FROM findings WHERE finding_id = ?", id),
            NoteTarget::Entry(id) => (
                "SELECT count(*) FROM timeline_entries WHERE entry_id = ?",
                id,
            ),
            NoteTarget::Indicator(id) => (
                "SELECT count(*) FROM case_indicators WHERE indicator_id = ?",
                id,
            ),
            NoteTarget::Evidence { table, key } => {
                return check_evidence_exists(
                    conn,
                    &[EvidenceRef {
                        source_table: table.clone(),
                        record_key: key.clone(),
                    }],
                );
            }
        };
        let n: i64 = conn.query_row(sql, params![id], |r| r.get(0))?;
        if n == 0 {
            let (kind, id, _) = self.columns();
            return Err(Error::Decision(format!("unknown {kind} {id}")));
        }
        Ok(())
    }
}

fn ts<S: Serializer>(t: &DateTime<Utc>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&audit::ts_text(t))
}

#[derive(Debug, Clone, Serialize)]
pub struct Note {
    pub annotation_id: String,
    pub object_type: String,
    pub object_id: String,
    pub source_table: Option<String>,
    pub text: String,
    pub actor: String,
    pub on_behalf_of: Option<String>,
    #[serde(serialize_with = "ts")]
    pub created_at: DateTime<Utc>,
}

/// Add a note to an existing target. The text is stored as given; text that is only whitespace is refused.
pub fn add_note(
    conn: &Connection,
    actor: &Actor,
    target: NoteTarget,
    text: &str,
) -> Result<(String, AuditEntry)> {
    if text.trim().is_empty() {
        return Err(Error::Decision("a note must not be empty".into()));
    }
    crate::case::text::check_text("a note", text)?;
    in_tx(conn, |tx| {
        target.check_exists(tx)?;
        let (object_type, object_id, source_table) = target.columns();
        let ts = audit::now();
        let mut h = Sha256::new();
        for part in [
            object_type,
            source_table.unwrap_or(""),
            object_id,
            text,
            actor.as_str(),
            &ts.timestamp_micros().to_string(),
        ] {
            h.update(part.as_bytes());
            h.update([0x1f]);
        }
        let id = hex::encode(h.finalize())[..16].to_string();
        tx.execute(
            "INSERT INTO annotations (annotation_id, object_type, object_id, source_table, text, actor, on_behalf_of, \
                                      created_at) \
             VALUES (?, CAST(? AS annotation_object), ?, ?, ?, ?, ?, CAST(? AS TIMESTAMPTZ))",
            params![
                id,
                object_type,
                object_id,
                source_table,
                text,
                actor.as_str(),
                actor.on_behalf_of(),
                audit::ts_text(&ts)
            ],
        )?;
        let after = json!({
            "object_type": object_type,
            "object_id": object_id,
            "source_table": source_table,
            "text": text,
        });
        let e = audit::append_at(
            tx,
            ts,
            actor.as_str(),
            actor.on_behalf_of(),
            "add_note",
            "annotation",
            &id,
            None,
            Some(&after),
            None,
        )?;
        Ok((id, e))
    })
}

/// The notes on `target`, oldest first.
pub fn notes_for(conn: &Connection, target: &NoteTarget) -> Result<Vec<Note>> {
    let (object_type, object_id, source_table) = target.columns();
    let mut stmt = conn.prepare(
        "SELECT annotation_id, CAST(object_type AS VARCHAR), object_id, source_table, text, actor, on_behalf_of, \
                epoch_us(created_at) \
         FROM annotations \
         WHERE CAST(object_type AS VARCHAR) = ? AND object_id = ? AND source_table IS NOT DISTINCT FROM ? \
         ORDER BY created_at, annotation_id",
    )?;
    let rows = stmt.query_map(params![object_type, object_id, source_table], |r| {
        Ok(Note {
            annotation_id: r.get(0)?,
            object_type: r.get(1)?,
            object_id: r.get(2)?,
            source_table: r.get(3)?,
            text: r.get(4)?,
            actor: r.get(5)?,
            on_behalf_of: r.get(6)?,
            created_at: DateTime::from_timestamp_micros(r.get(7)?).unwrap_or_default(),
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}
