//! The Exchange admin center message trace DETAIL ("extended") report, `MTDetail_*.csv`
//! (`portal.message_trace_detail`): one row per delivery event of a message. Every event is
//! loaded into `message_trace_events` (keyed by a hash of the row: the report has no event id), and
//! the events of each message are collapsed into `message_trace`, one row per message and
//! recipient, under the same key the summary report and Hawk use, so those copies merge.

use crate::db::state_tables::{MESSAGE_TRACE, MESSAGE_TRACE_EVENTS};
use crate::ingest::IngestOptions;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::{normalize_ip, normalize_upn};
use crate::parsers::message_trace::{COLS as TRACE_COLS, message_trace_key, received_cells};
use crate::parsers::records::{
    RecordEvent, RecordFormat, SourceRecord, for_each_record, holds_placeholder,
    placeholder_message,
};
use crate::parsers::stage::{
    CellRow, LOAD_STREAMED_STEPS, RowDraft, RowOut, TableRows, TailSink, csv_row_key,
    load_streamed, lower, non_empty_cells, read_state_records, unsupported,
};
use crate::readers::stream::Sight;
use crate::readers::text::SourcePos;
use crate::readers::time::parse_timestamp;
use crate::{Error, Result};
use duckdb::types::Value as DbValue;
use duckdb::{Connection, appender_params_from_iter, params};
use serde_json::{Map, Value};
use std::net::IpAddr;

pub fn register(r: &mut ParserRegistry) {
    r.register(
        "portal.message_trace_detail",
        Box::new(MessageTraceDetailParser),
    );
}

const COLS: &[&str] = &[
    "event_time",
    "time_tz_assumed",
    "network_message_id",
    "internal_message_id",
    "internet_message_id",
    "event_id",
    "source",
    "source_context",
    "sender",
    "recipients",
    "related_recipient",
    "recipient_status",
    "client_ip",
    "client_hostname",
    "server_ip",
    "server_hostname",
    "original_client_ip",
    "original_server_ip",
    "connector_id",
    "total_bytes",
    "recipient_count",
    "reference",
    "subject",
    "return_path",
    "message_info",
    "directionality",
    "tenant_id",
    "custom_data",
];

/// Events that say what became of a message for a recipient (compared upper-case).
const STATUS_EVENTS: &[&str] = &[
    "DELIVER",
    "SENDEXTERNAL",
    "FAIL",
    "DROP",
    "REDIRECT",
    "DUPLICATEREDIRECT",
    "DEFER",
    "EXPAND",
    "DUPLICATEDELIVER",
];

/// A plain IPv4/IPv6 address, normalized; anything else (a link-local address with a `%zone`,
/// a host name, text) is `None`. The original text stays in `raw`.
fn strict_ip(v: Option<String>) -> Option<String> {
    v.and_then(|s| normalize_ip(&s))
        .filter(|s| s.parse::<IpAddr>().is_ok())
}

fn upn(v: Option<String>) -> Option<String> {
    v.and_then(|s| normalize_upn(&s))
}

/// The addresses of a `recipient_address` cell (`;`-separated), normalized, empty entries dropped.
fn addresses(v: Option<String>) -> Vec<String> {
    v.as_deref()
        .unwrap_or("")
        .split(';')
        .filter_map(normalize_upn)
        .collect()
}

/// What the collapse needs of one event.
struct Event {
    /// Index of the record in the file's records.
    record: usize,
    time: Option<chrono::DateTime<chrono::Utc>>,
    time_text: Option<String>,
    event_id: Option<String>,
    sender: Option<String>,
    subject: Option<String>,
    internet_message_id: Option<String>,
    direction: Option<String>,
    connector_id: Option<String>,
    original_client_ip_text: Option<String>,
    from_ip: Option<String>,
    total_bytes_text: Option<String>,
    total_bytes: Option<i64>,
    recipients: Vec<String>,
}

/// Where a record sits in the file and its snippet: what a collapsed row takes from its message's earliest event.
type Span = (u64, Sight, String);

fn event_cells(rec: &Rec, recipients: &[String]) -> Vec<Cell> {
    let time = rec.text("date_time_utc");
    let mut c = CellRow::new(COLS);
    c.set(
        "time_tz_assumed",
        Cell::bool(time.as_deref().map(crate::readers::time::zone_assumed)),
    )
    .set("event_time", Cell::time(time))
    .set(
        "network_message_id",
        Cell::text(lower(rec.text("network_message_id"))),
    )
    .set(
        "internal_message_id",
        Cell::text(rec.text("internal_message_id")),
    )
    .set("internet_message_id", Cell::text(rec.text("message_id")))
    .set("event_id", Cell::text(rec.text("event_id")))
    .set("source", Cell::text(rec.text("source")))
    .set("source_context", Cell::text(rec.text("source_context")))
    .set("sender", Cell::text(upn(rec.text("sender_address"))))
    .set(
        "recipients",
        Cell::json((!recipients.is_empty()).then(|| Value::from(recipients.to_vec()))),
    )
    .set(
        "related_recipient",
        Cell::text(upn(rec.text("related_recipient_address"))),
    )
    .set("recipient_status", Cell::text(rec.text("recipient_status")))
    .set("client_ip", Cell::text(strict_ip(rec.text("client_ip"))))
    .set("client_hostname", Cell::text(rec.text("client_hostname")))
    .set("server_ip", Cell::text(strict_ip(rec.text("server_ip"))))
    .set("server_hostname", Cell::text(rec.text("server_hostname")))
    .set(
        "original_client_ip",
        Cell::text(strict_ip(rec.text("original_client_ip"))),
    )
    .set(
        "original_server_ip",
        Cell::text(strict_ip(rec.text("original_server_ip"))),
    )
    .set("connector_id", Cell::text(rec.text("connector_id")))
    .set("total_bytes", Cell::int(rec.int("total_bytes")))
    .set("recipient_count", Cell::int(rec.int("recipient_count")))
    .set("reference", Cell::text(rec.text("reference")))
    .set("subject", Cell::text(rec.text("message_subject")))
    .set("return_path", Cell::text(rec.text("return_path")))
    .set("message_info", Cell::text(rec.text("message_info")))
    .set("directionality", Cell::text(rec.text("directionality")))
    .set("tenant_id", Cell::text(rec.text("tenant_id")))
    .set("custom_data", Cell::text(rec.text("custom_data")));
    c.into_cells()
}

/// The UTC time of an event's `date_time_utc` text, if it can be read.
fn event_time(text: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    text.and_then(|t| parse_timestamp(t, None).ok())
        .map(|t| t.utc)
}

fn event_of(record: usize, rec: &Rec, recipients: Vec<String>) -> Event {
    let time_text = rec.text("date_time_utc");
    Event {
        record,
        time: event_time(time_text.as_deref()),
        time_text,
        event_id: rec.text("event_id"),
        sender: upn(rec.text("sender_address")),
        subject: rec.text("message_subject"),
        internet_message_id: rec.text("message_id"),
        direction: rec.text("directionality"),
        connector_id: rec.text("connector_id"),
        original_client_ip_text: rec.text("original_client_ip"),
        from_ip: strict_ip(rec.text("original_client_ip")),
        total_bytes_text: rec.text("total_bytes"),
        total_bytes: rec.int("total_bytes"),
        recipients,
    }
}

/// The first value `f` gives among `events` (already in time order).
fn first<'e, T>(events: &[&'e Event], f: impl Fn(&'e Event) -> Option<T>) -> Option<T> {
    events.iter().find_map(|e| f(e))
}

/// The `message_trace` rows of one message: `events` are all its events in the file, in file order; `span` is
/// the record index and span of its earliest timed event (the first in file order of the earliest time), `None` when
/// no event has a usable time.
fn collapse(
    network_message_id: &str,
    events: &[Event],
    span: Option<&(usize, Span)>,
    rows: &mut TableRows,
) {
    // Events without a usable time cannot be ordered; they stay in `message_trace_events` only.
    let mut timed: Vec<&Event> = events.iter().filter(|e| e.time.is_some()).collect();
    timed.sort_by_key(|e| e.time); // stable: ties keep the file order
    let Some(earliest) = timed.first() else {
        return;
    };
    let mut recipients: Vec<&str> = Vec::new();
    for r in timed.iter().flat_map(|e| &e.recipients) {
        if !recipients.contains(&r.as_str()) {
            recipients.push(r);
        }
    }
    let sender = first(&timed, |e| e.sender.clone());
    let subject = first(&timed, |e| e.subject.clone());
    let internet_message_id = first(&timed, |e| e.internet_message_id.clone());
    let direction = first(&timed, |e| e.direction.clone());
    let connector_id = first(&timed, |e| e.connector_id.clone());
    let from = timed.iter().find(|e| e.from_ip.is_some());
    let size = timed.iter().filter_map(|e| e.total_bytes).max();
    let size_text = timed
        .iter()
        .filter(|e| e.total_bytes == size && size.is_some())
        .find_map(|e| e.total_bytes_text.clone());
    let Some((record, (ordinal, sight, snippet))) = span else {
        unreachable!("{network_message_id}: a timed event but no earliest span");
    };
    debug_assert_eq!(
        *record, earliest.record,
        "{network_message_id}: earliest span"
    );
    for recipient in recipients {
        let decided = timed.iter().rev().find(|e| {
            e.event_id
                .as_deref()
                .is_some_and(|id| STATUS_EVENTS.iter().any(|s| s.eq_ignore_ascii_case(id)))
                && e.recipients.iter().any(|r| r == recipient)
        });
        let status = decided.and_then(|e| e.event_id.clone());
        let mut c = CellRow::new(TRACE_COLS);
        c.set(
            "message_trace_id",
            Cell::text(Some(network_message_id.to_string())),
        )
        .set("sender", Cell::text(sender.clone()))
        .set("recipient", Cell::text(Some(recipient.to_string())))
        .set("subject", Cell::text(subject.clone()))
        .set("status", Cell::text(status.clone()))
        .set("from_ip", Cell::text(from.and_then(|e| e.from_ip.clone())))
        .set("size_bytes", Cell::int(size))
        .set(
            "internet_message_id",
            Cell::text(internet_message_id.clone()),
        )
        .set("direction", Cell::text(direction.clone()))
        .set("connector_id", Cell::text(connector_id.clone()));
        received_cells(&mut c, earliest.time_text.clone());

        let mut raw = Map::new();
        let mut put = |k: &str, v: Option<String>| {
            if let Some(v) = v {
                raw.insert(k.into(), Value::String(v));
            }
        };
        put("date_time_utc", earliest.time_text.clone());
        put("event_id", status);
        put("sender_address", sender.clone());
        put("message_subject", subject.clone());
        put("message_id", internet_message_id.clone());
        put("directionality", direction.clone());
        put("connector_id", connector_id.clone());
        put(
            "original_client_ip",
            from.and_then(|e| e.original_client_ip_text.clone()),
        );
        put("total_bytes", size_text.clone());
        let mut head = Map::new();
        head.insert("network_message_id".into(), network_message_id.into());
        head.insert("recipient".into(), recipient.into());
        head.insert("events".into(), events.len().into());
        head.extend(raw);

        rows.push_draft(RowDraft {
            ordinal: *ordinal,
            sight: sight.clone(),
            snippet: snippet.clone(),
            record_key: message_trace_key(network_message_id, Some(recipient)),
            cells: c.into_cells(),
            raw: Some(Value::Object(head)),
        });
    }
}

pub struct MessageTraceDetailParser;

/// The keyed events of the file being parsed, appended in file order during the first scan (the fields an [`Event`]
/// holds, its record's span, and `msg`, its lower-case network message id).
const EVENTS: &str = "stage_mtd_events";
/// [`EVENTS`] numbered by `pos` in collapse order: messages in order of first appearance, each message's events in
/// file order. Stored in `pos` order, so a range of `pos` reads few row groups.
const SORTED: &str = "stage_mtd_sorted";
const DROP_TEMP: &str =
    "DROP TABLE IF EXISTS stage_mtd_events; DROP TABLE IF EXISTS stage_mtd_sorted;";
/// The event columns of [`EVENTS`] and [`SORTED`], in the order [`append_event`] writes and [`read_event`] reads.
const EVENT_COLUMNS: &str =
    "msg, idx, time_text, event_id, sender, subject, internet_message_id, direction, connector_id,
    original_client_ip_text, from_ip, total_bytes_text, total_bytes, recipients,
    ord, line_start, line_end, byte_offset, byte_length, raw_sha256, snippet";

thread_local! {
    static PEAK_MESSAGE_EVENTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The most events of ONE message the collapse has held at once on this thread since the last
/// [`reset_peak_message_events`]: the collapse holds one message's events at a time, never the file's. Per thread, so
/// tests running in parallel do not see each other's parses (an ingest parses on its caller's thread).
#[doc(hidden)]
pub fn peak_message_events() -> usize {
    PEAK_MESSAGE_EVENTS.with(std::cell::Cell::get)
}

/// Resets [`peak_message_events`] on this thread.
#[doc(hidden)]
pub fn reset_peak_message_events() {
    PEAK_MESSAGE_EVENTS.with(|c| c.set(0));
}

fn text(v: &Option<String>) -> DbValue {
    v.clone().map_or(DbValue::Null, DbValue::Text)
}

/// Append one keyed event (record `idx` of the file) to [`EVENTS`].
fn append_event(
    app: &mut duckdb::Appender<'_>,
    msg: String,
    e: &Event,
    r: &SourceRecord,
) -> Result<()> {
    let pos = &r.sight.pos;
    // `addresses` never yields a `;`: the list round-trips through one `;`-joined text (NULL when empty).
    let recipients = (!e.recipients.is_empty()).then(|| e.recipients.join(";"));
    let vals = [
        DbValue::Text(msg),
        DbValue::BigInt(e.record as i64),
        text(&e.time_text),
        text(&e.event_id),
        text(&e.sender),
        text(&e.subject),
        text(&e.internet_message_id),
        text(&e.direction),
        text(&e.connector_id),
        text(&e.original_client_ip_text),
        text(&e.from_ip),
        text(&e.total_bytes_text),
        e.total_bytes.map_or(DbValue::Null, DbValue::BigInt),
        text(&recipients),
        DbValue::BigInt(r.ordinal as i64),
        DbValue::BigInt(pos.line_start as i64),
        DbValue::BigInt(pos.line_end as i64),
        DbValue::BigInt(pos.byte_offset as i64),
        DbValue::BigInt(pos.byte_length as i64),
        DbValue::Text(r.sight.raw_sha256.clone()),
        DbValue::Text(r.snippet.clone()),
    ];
    app.append_row(appender_params_from_iter(vals))?;
    Ok(())
}

/// The [`Event`] of a row selected with [`EVENT_COLUMNS`] (column 0, the message, is read by the caller).
fn read_event(row: &duckdb::Row<'_>) -> duckdb::Result<Event> {
    let time_text: Option<String> = row.get(2)?;
    let recipients: Option<String> = row.get(13)?;
    Ok(Event {
        record: row.get::<_, i64>(1)? as usize,
        time: event_time(time_text.as_deref()),
        time_text,
        event_id: row.get(3)?,
        sender: row.get(4)?,
        subject: row.get(5)?,
        internet_message_id: row.get(6)?,
        direction: row.get(7)?,
        connector_id: row.get(8)?,
        original_client_ip_text: row.get(9)?,
        from_ip: row.get(10)?,
        total_bytes_text: row.get(11)?,
        total_bytes: row.get(12)?,
        recipients: recipients
            .map_or_else(Vec::new, |r| r.split(';').map(str::to_string).collect()),
    })
}

/// The span of a row selected with [`EVENT_COLUMNS`].
fn read_span(row: &duckdb::Row<'_>) -> duckdb::Result<Span> {
    Ok((
        row.get::<_, i64>(14)? as u64,
        Sight {
            pos: SourcePos {
                line_start: row.get::<_, i64>(15)? as u32,
                line_end: row.get::<_, i64>(16)? as u32,
                byte_offset: row.get::<_, i64>(17)? as u64,
                byte_length: row.get::<_, i64>(18)? as u64,
            },
            raw_sha256: row.get(19)?,
        },
        row.get(20)?,
    ))
}

/// The message being collapsed: its events so far and the span of the earliest timed one.
struct Message {
    id: String,
    events: Vec<Event>,
    /// (time, record, span) of the earliest timed event so far; a later event replaces it only when strictly earlier,
    /// so a tie keeps the file order, as the collapse's stable sort does.
    earliest: Option<(chrono::DateTime<chrono::Utc>, usize, Span)>,
}

impl Message {
    fn push(&mut self, row: &duckdb::Row<'_>) -> Result<()> {
        let e = read_event(row)?;
        if let Some(t) = e.time
            && self.earliest.as_ref().is_none_or(|(best, ..)| t < *best)
        {
            self.earliest = Some((t, e.record, read_span(row)?));
        }
        self.events.push(e);
        let held = self.events.len();
        PEAK_MESSAGE_EVENTS.with(|c| c.set(c.get().max(held)));
        Ok(())
    }

    fn collapse(self, rows: &mut TableRows) {
        let earliest = self.earliest.map(|(_, record, span)| (record, span));
        collapse(&self.id, &self.events, earliest.as_ref(), rows);
    }
}

/// Collapse the events in [`SORTED`] (`count` of them) message by message, reading `batch` events per query, and hand
/// each `message_trace` row to `sink`. Holds one message's events and one batch's rows. Stops with
/// `Error::Interrupted` when `options` asks to cancel (checked once per range).
fn collapse_sorted(
    conn: &Connection,
    options: &IngestOptions,
    count: i64,
    batch: usize,
    sink: &mut TailSink<'_>,
) -> Result<()> {
    let batch = i64::try_from(batch.max(1)).unwrap_or(i64::MAX);
    let sql =
        format!("SELECT {EVENT_COLUMNS} FROM {SORTED} WHERE pos >= ? AND pos < ? ORDER BY pos");
    let mut current: Option<Message> = None;
    let mut from = 0i64;
    while from < count {
        if options.cancelled() {
            return Err(Error::Interrupted);
        }
        let mut out = TableRows::new(&MESSAGE_TRACE, TRACE_COLS);
        {
            let mut stmt = conn.prepare(&sql)?;
            let mut rows = stmt.query(params![from, from.saturating_add(batch)])?;
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                if current.as_ref().is_some_and(|m| m.id != id) {
                    current
                        .take()
                        .into_iter()
                        .for_each(|m| m.collapse(&mut out));
                }
                current
                    .get_or_insert_with(|| Message {
                        id,
                        events: Vec::new(),
                        earliest: None,
                    })
                    .push(row)?;
            }
        }
        // The query is done before staging writes to the connection.
        for d in out.rows {
            sink(1, d)?;
        }
        from = from.saturating_add(batch);
    }
    if let Some(m) = current {
        let mut out = TableRows::new(&MESSAGE_TRACE, TRACE_COLS);
        m.collapse(&mut out);
        for d in out.rows {
            sink(1, d)?;
        }
    }
    Ok(())
}

impl ArtifactParser for MessageTraceDetailParser {
    fn steps(&self) -> &'static [&'static str] {
        LOAD_STREAMED_STEPS
    }

    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        // Its TEMP tables live in the file's transaction: dropped here when the parse succeeds, gone with the
        // rollback when it fails (dropped here too, when the connection still can).
        let conn = ctx.conn;
        conn.execute_batch(DROP_TEMP)?;
        let out = parse_detail(ctx);
        match out {
            Ok(()) => {
                conn.execute_batch(DROP_TEMP)?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute_batch(DROP_TEMP);
                Err(e)
            }
        }
    }
}

fn parse_detail(ctx: &mut ParseContext<'_>) -> Result<()> {
    // Streamed (see `load_streamed`): a large export collected as records peaked at 17.7 GB for 186 MB. A first scan
    // appends what the collapse needs of each event to a TEMP table; the event rows are then streamed and loaded in
    // batches, and the message rows after them, collapsed message by message from the TEMP table.
    let format = RecordFormat::of(ctx.rel_path);
    let conn = ctx.conn;
    let options = ctx.options;
    let batch = options.batch_rows.max(1);
    conn.execute_batch(&format!(
        "CREATE TEMP TABLE {EVENTS} (msg VARCHAR, idx BIGINT, time_text VARCHAR, event_id VARCHAR, sender VARCHAR,
             subject VARCHAR, internet_message_id VARCHAR, direction VARCHAR, connector_id VARCHAR,
             original_client_ip_text VARCHAR, from_ip VARCHAR, total_bytes_text VARCHAR, total_bytes BIGINT,
             recipients VARCHAR, ord BIGINT, line_start BIGINT, line_end BIGINT, byte_offset BIGINT,
             byte_length BIGINT, raw_sha256 VARCHAR, snippet VARCHAR);"
    ))?;
    ctx.set_step(0);
    let mut first: Option<SourceRecord> = None;
    let (mut keyed, mut placeholders) = (false, 0usize);
    let count_placeholders = format == RecordFormat::Csv && !ctx.portal_export;
    let (mut records, mut appended) = (0usize, 0usize);
    {
        let mut app = conn.appender(EVENTS)?;
        for_each_record(&ctx.input(), format, |event| {
            let RecordEvent::Record(r) = event else {
                return Ok(true);
            };
            let i = records;
            records += 1;
            keyed |= Rec::new(&r.map, false).has("network_message_id");
            if count_placeholders && holds_placeholder(&r) {
                placeholders += 1;
            }
            // A portal download holds no PowerShell placeholders: nothing is filtered.
            let rec = Rec::new(&r.map, false);
            if let Some(id) = lower(rec.text("network_message_id")) {
                let recipients = addresses(rec.text("recipient_address"));
                append_event(&mut app, id, &event_of(i, &rec, recipients), &r)?;
                appended += 1;
                if appended % batch == 0 {
                    app.flush()?;
                }
            }
            if first.is_none() {
                first = Some(r);
            }
            Ok(true)
        })?;
        app.flush()?;
    }
    let Some(first) = first else {
        // No readable record: recording the unreadable ones is all there is to do.
        read_state_records(ctx, format)?;
        return Ok(());
    };
    if !ctx.portal_export
        && let Some(w) = placeholder_message(placeholders)
    {
        ctx.warn(w);
    }
    if !keyed {
        return Err(unsupported(
            &first,
            "message trace detail (network_message_id)",
        ));
    }
    drop(first);
    ctx.check_cancelled()?;
    conn.execute_batch(&format!(
        "CREATE TEMP TABLE {SORTED} AS
             SELECT row_number() OVER (ORDER BY first_idx, idx) - 1 AS pos, * EXCLUDE (first_idx)
             FROM (SELECT *, min(idx) OVER (PARTITION BY msg) AS first_idx FROM {EVENTS})
             ORDER BY pos;
         DROP TABLE {EVENTS};"
    ))?;
    load_streamed(
        ctx,
        format,
        &[(&MESSAGE_TRACE_EVENTS, COLS), (&MESSAGE_TRACE, TRACE_COLS)],
        |sink| collapse_sorted(conn, options, appended as i64, batch, sink),
        |r| {
            let rec = Rec::new(&r.map, false);
            let recipients = addresses(rec.text("recipient_address"));
            vec![RowOut::Row {
                table: 0,
                draft: RowDraft {
                    ordinal: r.ordinal,
                    sight: r.sight.clone(),
                    snippet: r.snippet.clone(),
                    record_key: csv_row_key(&non_empty_cells(&r.map)),
                    cells: event_cells(&rec, &recipients),
                    raw: Some(Value::Object(r.map.clone())),
                },
            }]
        },
    )
}
