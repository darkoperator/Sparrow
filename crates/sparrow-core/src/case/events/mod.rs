//! The `events` table: one row per event record of every event evidence table, with normalized actor, owner, IP,
//! device and Entra session columns (migration 0025). Derived data, rewritten by [`rebuild`] in every profile run
//! right after `ip_intel`; nothing else writes it and evidence tables are never touched.

mod build;
mod filter;
pub(crate) mod marksql;
mod query;

pub use crate::case::marks::{FlagLevel, TagRef};
pub(crate) use build::prefix_of;
pub(crate) use filter::{Where, build_unsearched as scope_where, entity_columns, entity_predicate};
pub(crate) use marksql::{value_columns, value_flag_matches};
pub use query::{
    CSV_COLUMNS, HISTOGRAM_TOP_OPERATIONS, MAX_HISTOGRAM_BUCKETS, MAX_VALUES, detail, export_csv,
    histogram, histogram_by, matching_rows, page, suggest, summary, values,
};

use crate::Result;
use crate::case::notes::Note;
use chrono::{DateTime, Utc};
use duckdb::Connection;
use serde::{Deserialize, Serialize};

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

/// The thing an entity tab is about. Build the query's scope from it; [`Entity::normalized`] gives the stored spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Entity {
    /// Events the account performed or whose mailbox it owns (`actor_upn` or `owner_upn`).
    Account(String),
    Ip(String),
    /// A device id (`device_id`) or directory object id (`device_object_id`).
    /// Known gap: a directory audit row that names the device only by its object id (no `devices` row links the two) has
    /// `device_id` NULL, so opening the device by its device id does not list that row; opening it by object id does.
    Device(String),
    /// An Entra session id.
    Session(String),
}

/// A filter box of the grid. Its text is Harrier's list syntax (see [`EventQuery::fields`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Source,
    Operation,
    /// Matches the actor or the owner.
    Account,
    Ip,
    Country,
    Asn,
    /// Matches the device id, the directory object id or the display name.
    Device,
    Session,
    Tag,
    /// The rule id of an open finding (not closed as `false_positive` or `benign`) that has the row as evidence.
    Rule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagFilter {
    #[default]
    All,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiFilter {
    #[default]
    All,
    Marked,
    Unreviewed,
}

/// What the grid asks for. All fields combine with AND.
#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub entity: Option<Entity>,
    /// Filter boxes: comma separates values (OR); `!value` excludes; `*` is a case-insensitive wildcard; without `*` a
    /// value matches exactly (case-sensitively, except Account, Device, Session, Tag and Rule, which are compared
    /// lower-cased); a list of only excludes means everything except those. A value in double quotes is literal
    /// (commas, `*`, a leading `!` and outer spaces included; `""` is one quote). A blank text is no filter; a lone
    /// `!`, a text of only commas, an unclosed quote or text after a closing quote is refused with an `Error::Invalid`
    /// naming the field. The `message_trace_event` source is
    /// left out unless the Source field names it (a wildcard that matches counts).
    pub fields: Vec<(Field, String)>,
    /// Case-insensitive substring of the raw record (comma: OR, `*`: wildcard).
    pub search: Option<String>,
    /// Inclusive.
    pub from: Option<DateTime<Utc>>,
    /// Inclusive.
    pub to: Option<DateTime<Utc>>,
    pub flag: FlagFilter,
    pub ai: AiFilter,
}

/// Times serialize as `YYYY-MM-DDTHH:MM:SS.ffffffZ` like the rest of the core.
fn ts_opt<S: serde::Serializer>(
    t: &Option<DateTime<Utc>>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    match t {
        Some(t) => s.serialize_str(&crate::case::audit::ts_text(t)),
        None => s.serialize_none(),
    }
}

/// One `events` row, with the marks and counts the grid shows.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EventRow {
    pub source_table: String,
    pub record_key: String,
    pub source: String,
    #[serde(serialize_with = "ts_opt")]
    pub event_time: Option<DateTime<Utc>>,
    pub time_tz_assumed: Option<bool>,
    pub tenant_key: Option<String>,
    pub workload: Option<String>,
    pub category: String,
    pub operation: Option<String>,
    pub result: Option<String>,
    pub actor_upn: Option<String>,
    pub owner_upn: Option<String>,
    pub target: Option<String>,
    pub ip: Option<String>,
    pub ip_prefix: Option<String>,
    pub ip_country: Option<String>,
    pub asn: Option<i32>,
    pub asn_org: Option<String>,
    pub ip_kind: Option<String>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub device_object_id: Option<String>,
    pub entra_session_id: Option<String>,
    pub user_agent: Option<String>,
    pub app_id: Option<String>,
    pub summary: Option<String>,
    /// Distinct findings with this row as evidence (any status), counted from `finding_evidence` when queried.
    pub finding_count: u32,
    /// The tags the row carries, by name; `ai` for an agent's tag no analyst has confirmed.
    pub tags: Vec<TagRef>,
    /// The rule ids of the open findings (not closed as `false_positive` or `benign`) with this row as evidence, sorted:
    /// derived from `finding_evidence` when queried, so they follow every detection run and finding decision.
    pub rules: Vec<String>,
    /// The effective flag: the strongest of the row's own flag and every standing value flag that matches it.
    pub flag: Option<FlagLevel>,
    /// The effective flag comes only from an agent's flag that no analyst has confirmed.
    pub flag_ai: bool,
    /// An agent's mark that no analyst has confirmed covers the row: its own flag, a standing flag on a value it carries,
    /// or a tag. Unlike `flag_ai` this holds even when a stronger confirmed flag hides the pending one, so it says
    /// whether Confirm / Remove has anything to review here.
    pub ai_pending: bool,
    pub latest_note: Option<String>,
    pub note_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventsPage {
    pub rows: Vec<EventRow>,
    pub offset: usize,
    /// Matching rows, counted up to `browse::COUNT_CAP`.
    pub total: u64,
    pub total_capped: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventsSummary {
    /// Rows the query matches (the hidden `message_trace_event` rows are not in it unless the query names them).
    pub total: u64,
    pub suspicious: u64,
    pub malicious: u64,
    /// Rows per source, in `SOURCES` order, sources with none left out.
    pub per_source: Vec<(String, u64)>,
    /// `message_trace_event` rows the query matches but leaves out of everything else; 0 when it names them.
    pub hidden_trace_events: u64,
}

/// One value of a field and the events that carry it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValueCount {
    pub value: String,
    pub count: u64,
}

/// The values of one field under the other filters (see [`values`]): the first ones, and how many there are in all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldValues {
    pub values: Vec<ValueCount>,
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FindingMark {
    pub finding_id: String,
    pub severity: String,
    /// The finding's `first_seen`, else the first matching event of its evidence.
    #[serde(serialize_with = "ts_utc")]
    pub first_seen: DateTime<Utc>,
    #[serde(serialize_with = "ts_utc")]
    pub last_seen: DateTime<Utc>,
}

/// What the histogram stacks its bars by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistogramGroup {
    #[default]
    Source,
    Operation,
}

/// Event counts per time bucket, stacked by source or by operation. Bucket `i` covers `[start + i * bucket_seconds,
/// start + (i + 1) * bucket_seconds)`; an event exactly at the range end opens the last bucket.
#[derive(Debug, Clone, Serialize)]
pub struct Histogram {
    #[serde(serialize_with = "ts_utc")]
    pub start: DateTime<Utc>,
    pub bucket_seconds: i64,
    pub group: HistogramGroup,
    /// `(name, counts per bucket)`, empty for no rows. By source: in `SOURCES` order, sources with no event in range
    /// left out. By operation: the [`HISTOGRAM_TOP_OPERATIONS`] most frequent operations in range, most frequent first
    /// (ties by name).
    pub series: Vec<(String, Vec<u64>)>,
    /// By operation only: the counts of every other event in range (the rest of the operations, and events with no
    /// operation), `None` when there are none. Kept apart from `series` so an operation named "Other" stays distinct.
    pub other: Option<Vec<u64>>,
    /// Open findings (not closed as `false_positive` or `benign`) with evidence among the matching events.
    pub findings: Vec<FindingMark>,
}

fn ts_utc<S: serde::Serializer>(t: &DateTime<Utc>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&crate::case::audit::ts_text(t))
}

#[derive(Debug, Clone, Serialize)]
pub struct EventDetail {
    pub row: EventRow,
    /// The evidence record as stored (its table row as JSON).
    pub raw: serde_json::Value,
    /// `<collection folder>/<rel_path>:<line>[-<line>]` per sighting.
    pub source_refs: Vec<String>,
    pub tags: Vec<TagRef>,
    pub notes: Vec<Note>,
    pub flag: Option<FlagLevel>,
    /// Why the row is flagged: its own flag and each standing value flag that matches it, so the menu can say what a
    /// clear would undo.
    pub flag_sources: Vec<crate::case::marks::FlagSource>,
}
