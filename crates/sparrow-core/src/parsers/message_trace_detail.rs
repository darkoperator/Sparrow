//! The Exchange admin center message trace DETAIL ("extended") report, `MTDetail_*.csv`
//! (`portal.message_trace_detail`): one row per delivery event of a message. Every event is
//! loaded into `message_trace_events` (keyed by a hash of the row: the report has no event id), and
//! the events of each message are collapsed into `message_trace`, one row per message and
//! recipient, under the same key the summary report and Hawk use, so those copies merge.

use crate::Result;
use crate::db::state_tables::{MESSAGE_TRACE, MESSAGE_TRACE_EVENTS};
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
    CellRow, LOAD_STREAMED_STEPS, RowDraft, RowOut, TableRows, csv_row_key, load_streamed, lower,
    non_empty_cells, read_state_records, unsupported,
};
use crate::readers::stream::Sight;
use crate::readers::time::parse_timestamp;
use serde_json::{Map, Value};
use std::collections::HashMap;
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

fn event_of(record: usize, rec: &Rec, recipients: Vec<String>) -> Event {
    let time_text = rec.text("date_time_utc");
    Event {
        record,
        time: time_text
            .as_deref()
            .and_then(|t| parse_timestamp(t, None).ok())
            .map(|t| t.utc),
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

/// The `message_trace` rows of one message: `events` are all its events in the file.
fn collapse(
    network_message_id: &str,
    events: &[Event],
    spans: &[(u64, Sight, String)],
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
    let (ordinal, sight, snippet) = &spans[earliest.record];
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

impl ArtifactParser for MessageTraceDetailParser {
    fn steps(&self) -> &'static [&'static str] {
        LOAD_STREAMED_STEPS
    }

    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        // Streamed (see `load_streamed`): a large export collected as records peaked at 17.7 GB for 186 MB. A first
        // scan keeps only what the collapse needs of each event; the event rows are then streamed and loaded in
        // batches, and the collapsed message rows after them.
        let format = RecordFormat::of(ctx.rel_path);
        ctx.set_step(0);
        let mut first: Option<SourceRecord> = None;
        let (mut keyed, mut placeholders) = (false, 0usize);
        let count_placeholders = format == RecordFormat::Csv && !ctx.portal_export;
        // Messages in order of first appearance, each with its events.
        let mut order: Vec<String> = Vec::new();
        let mut by_message: HashMap<String, Vec<Event>> = HashMap::new();
        // Where each record sits in the file (and its snippet), for the collapsed rows.
        let mut spans: Vec<(u64, Sight, String)> = Vec::new();
        for_each_record(&ctx.input(), format, |event| {
            let RecordEvent::Record(r) = event else {
                return Ok(true);
            };
            let i = spans.len();
            spans.push((r.ordinal, r.sight.clone(), r.snippet.clone()));
            keyed |= Rec::new(&r.map, false).has("network_message_id");
            if count_placeholders && holds_placeholder(&r) {
                placeholders += 1;
            }
            // A portal download holds no PowerShell placeholders: nothing is filtered.
            let rec = Rec::new(&r.map, false);
            let recipients = addresses(rec.text("recipient_address"));
            if let Some(id) = lower(rec.text("network_message_id")) {
                let event = event_of(i, &rec, recipients);
                by_message
                    .entry(id.clone())
                    .or_insert_with(|| {
                        order.push(id);
                        Vec::new()
                    })
                    .push(event);
            }
            if first.is_none() {
                first = Some(r);
            }
            Ok(true)
        })?;
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
        let mut trace_rows = TableRows::new(&MESSAGE_TRACE, TRACE_COLS);
        for id in &order {
            collapse(id, &by_message[id], &spans, &mut trace_rows);
        }
        drop(by_message);
        let tail = trace_rows.rows.into_iter().map(|d| (1, d)).collect();
        load_streamed(
            ctx,
            format,
            &[(&MESSAGE_TRACE_EVENTS, COLS), (&MESSAGE_TRACE, TRACE_COLS)],
            tail,
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
}
