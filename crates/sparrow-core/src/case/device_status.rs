//! The analyst's status of a device: Removed, Disabled, Confirmed attacker or Benign, with an optional note. It is
//! recorded next to the status `case::devices` computes from the evidence and never replaces it: the Devices list, the
//! device tab and the containment exports show both.
//!
//! - **Who.** An analyst's own decision only; an agent is refused and nothing is written.
//! - **Storage.** `device_analyst_status`, one row per decision: a new status closes the live row and adds one, a clear
//!   closes it (soft delete), so at most one live row per device id and the history stays in the table.
//! - **Audit.** One `audit_trail` row per change, object type `device_status`, object id the device id, actions
//!   `set_device_status` and `clear_device_status`; `before` / `after` are the live decision (null when none).
//! - **Warning.** A Removed or Disabled device seen after the decision was made ([`DeviceDecision::active_after`]):
//!   the responders' removal did not hold, as `active_after_removal` says of a removal Sparrow found in the logs.

use crate::case::actor::Actor;
use crate::case::audit::{self, AuditEntry};
use crate::case::text::check_text;
use crate::case::write::in_tx;
use crate::detect::enrich::at_us;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::{Connection, OptionalExt, params};
use serde::{Serialize, Serializer};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// The audit `object_type` of a device status change.
pub const OBJECT_TYPE: &str = "device_status";

/// What the analyst says of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalystStatus {
    Removed,
    Disabled,
    ConfirmedAttacker,
    Benign,
}

impl AnalystStatus {
    pub const ALL: [AnalystStatus; 4] = [
        Self::Removed,
        Self::Disabled,
        Self::ConfirmedAttacker,
        Self::Benign,
    ];

    /// The serde (and stored) name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::Disabled => "disabled",
            Self::ConfirmedAttacker => "confirmed_attacker",
            Self::Benign => "benign",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == s)
            .ok_or_else(|| {
                Error::Invalid(format!(
                    "unknown device status {s:?} (removed, disabled, confirmed_attacker or benign)"
                ))
            })
    }

    /// The device was taken out of the tenant's hands (removed or disabled), so a later sighting means it was not.
    pub fn takes_device_out(self) -> bool {
        matches!(self, Self::Removed | Self::Disabled)
    }
}

fn ts<S: Serializer>(t: &DateTime<Utc>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&audit::ts_text(t))
}

/// The live analyst status of one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceDecision {
    /// Lower case, trimmed.
    pub device_id: String,
    pub status: AnalystStatus,
    pub note: Option<String>,
    /// `analyst:<name>`.
    pub decided_by: String,
    #[serde(serialize_with = "ts")]
    pub decided_at: DateTime<Utc>,
}

impl DeviceDecision {
    /// A Removed or Disabled device whose `last_seen` is later than the decision: active after the analyst's removal.
    pub fn active_after(&self, last_seen: Option<DateTime<Utc>>) -> bool {
        self.status.takes_device_out() && last_seen.is_some_and(|t| t > self.decided_at)
    }

    fn json(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "note": self.note,
            "decided_by": self.decided_by,
            "decided_at": audit::ts_text(&self.decided_at),
        })
    }
}

/// The stored spelling of a device id: trimmed, lower case; an empty id or one with a control character is refused.
pub fn normalize_id(device_id: &str) -> Result<String> {
    let id = device_id.trim().to_lowercase();
    if id.is_empty() || id.chars().any(char::is_control) {
        return Err(Error::Invalid(
            "a device id must be non-empty text without control characters".into(),
        ));
    }
    Ok(id)
}

const SELECT: &str = "SELECT device_id, CAST(status AS VARCHAR), note, decided_by, epoch_us(decided_at) \
     FROM device_analyst_status WHERE removed_at IS NULL";

fn decision_of(r: &duckdb::Row) -> duckdb::Result<(String, String, Option<String>, String, i64)> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
}

fn build(row: (String, String, Option<String>, String, i64)) -> Result<DeviceDecision> {
    let (device_id, status, note, decided_by, at) = row;
    Ok(DeviceDecision {
        device_id,
        status: AnalystStatus::parse(&status)?,
        note,
        decided_by,
        decided_at: at_us(Some(at)).unwrap_or_default(),
    })
}

/// The live analyst status of `device_id` (any spelling), or `None`.
pub fn current(conn: &Connection, device_id: &str) -> Result<Option<DeviceDecision>> {
    let id = normalize_id(device_id)?;
    conn.query_row(
        &format!("{SELECT} AND device_id = ?"),
        params![id],
        decision_of,
    )
    .optional()?
    .map(build)
    .transpose()
}

/// Every live analyst status, keyed by device id.
pub fn all_current(conn: &Connection) -> Result<BTreeMap<String, DeviceDecision>> {
    let mut stmt = conn.prepare(&format!("{SELECT} ORDER BY device_id"))?;
    let rows = stmt.query_map([], decision_of)?;
    let mut out = BTreeMap::new();
    for row in rows {
        let d = build(row?)?;
        out.insert(d.device_id.clone(), d);
    }
    Ok(out)
}

/// Set (`Some`) or clear (`None`) the analyst status of a device, with an optional note, in one transaction with one
/// audit row. Only an analyst may; clearing a device without a status, or setting the status and note it already has,
/// is refused (`Error::Decision`) and writes nothing.
pub fn set_status(
    conn: &Connection,
    actor: &Actor,
    device_id: &str,
    status: Option<AnalystStatus>,
    note: Option<&str>,
) -> Result<AuditEntry> {
    if !actor.is_analyst() {
        return Err(Error::Decision(
            "only an analyst sets a device's analyst status".into(),
        ));
    }
    let id = normalize_id(device_id)?;
    let note = note.map(str::trim).filter(|n| !n.is_empty());
    if let Some(n) = note {
        check_text("a note", n)?;
    }
    if status.is_none() && note.is_some() {
        return Err(Error::Invalid(
            "clearing a device status takes no note".into(),
        ));
    }
    in_tx(conn, |tx| {
        let before = current(tx, &id)?;
        let ts = audit::now();
        let ts_text = audit::ts_text(&ts);
        match status {
            None if before.is_none() => {
                return Err(Error::Decision(format!(
                    "device {id} has no analyst status to clear"
                )));
            }
            Some(s)
                if before
                    .as_ref()
                    .is_some_and(|b| b.status == s && b.note.as_deref() == note) =>
            {
                return Err(Error::Decision(format!(
                    "device {id} is already {}{}",
                    s.as_str(),
                    if note.is_some() {
                        " with that note"
                    } else {
                        ""
                    }
                )));
            }
            _ => {}
        }
        tx.execute(
            "UPDATE device_analyst_status SET removed_at = CAST(? AS TIMESTAMPTZ), removed_by = ? \
             WHERE device_id = ? AND removed_at IS NULL",
            params![ts_text, actor.as_str(), id],
        )?;
        if let Some(s) = status {
            tx.execute(
                "INSERT INTO device_analyst_status (decision_id, device_id, status, note, decided_by, decided_at) \
                 SELECT coalesce(max(decision_id), 0) + 1, ?, CAST(? AS device_verdict), ?, ?, CAST(? AS TIMESTAMPTZ) \
                 FROM device_analyst_status",
                params![id, s.as_str(), note, actor.as_str(), ts_text],
            )?;
        }
        let after = current(tx, &id)?;
        audit::append_at(
            tx,
            ts,
            actor.as_str(),
            actor.on_behalf_of(),
            if status.is_some() {
                "set_device_status"
            } else {
                "clear_device_status"
            },
            OBJECT_TYPE,
            &id,
            before.as_ref().map(DeviceDecision::json).as_ref(),
            after.as_ref().map(DeviceDecision::json).as_ref(),
            None,
        )
    })
}
