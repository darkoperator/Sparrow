//! The `events` table: one row per event record of every event evidence table, with normalized actor, owner, IP,
//! device and Entra session columns (migration 0025). Derived data, rewritten by [`rebuild`] in every profile run
//! right after `ip_intel`; nothing else writes it and evidence tables are never touched.

mod build;

use crate::Result;
use duckdb::Connection;

/// The `events.source` values, in grid order.
pub const SOURCES: &[&str] = &[
    "ual",
    "signin_interactive",
    "signin_noninteractive",
    "signin_service",
    "mail_items_accessed",
    "message_trace",
    "message_trace_event",
    "entra_audit",
    "mailbox_audit",
    "admin_audit",
    "risk_detection",
    "azure_activity",
    "security_alert",
];

/// Rewrites `events` from the evidence tables and returns the rows written.
///
/// Call it where `ip_intel` was just rebuilt: the IP country, ASN and kind columns come from that table. It runs
/// inside the caller's transaction, so a failed rebuild leaves the previous rows.
pub fn rebuild(conn: &Connection) -> Result<u64> {
    build::rebuild(conn)
}
