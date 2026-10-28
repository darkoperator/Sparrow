//! Exchange Online message trace (spec 5.1 `message_trace`): Hawk 3 `Message_Trace_<user>`
//! (Get-MessageTrace) and the Exchange admin center summary report download (`MTSummary_*`,
//! snake_case columns, one line per message with `recipient##status` entries), plus the
//! Microsoft-Extractor-Suite `Get-MessageTraceLog` CSVs (`MessageTrace/<ts>/<ts>-MessageTrace.csv`
//! and `MessageTrace/<ts>/<user>-MTL.csv`), which share the Get-MessageTrace columns. All shapes
//! key a row by message trace id (= network message id) and recipient.

use crate::db::state_tables::MESSAGE_TRACE;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::{normalize_ip, normalize_upn};
use crate::parsers::records::{RecordFormat, SourceRecord};
use crate::parsers::stage::{CellRow, TableRows, load_tables, lower, read_state_records, reject};
use crate::readers::time::zone_assumed;
use crate::{Error, Result};

pub fn register(r: &mut ParserRegistry) {
    r.register("hawk.user.message_trace", Box::new(MessageTraceParser));
    r.register("portal.message_trace", Box::new(MessageTraceParser));
    r.register("inv.message_trace", Box::new(MessageTraceParser));
}

/// message_trace.record_key: `<message trace id>|<recipient>`, lower-case.
pub fn message_trace_key(id: &str, recipient: Option<&str>) -> String {
    format!(
        "{}|{}",
        id.to_lowercase(),
        recipient.unwrap_or("").to_lowercase()
    )
}

pub(crate) const COLS: &[&str] = &[
    "message_trace_id",
    "received",
    "time_tz_assumed",
    "sender",
    "recipient",
    "subject",
    "status",
    "from_ip",
    "to_ip",
    "size_bytes",
    "internet_message_id",
    "organization",
    "direction",
    "connector_id",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    MessageTrace,
    Summary,
}

fn shape_of(records: &[SourceRecord]) -> Option<Shape> {
    let any = |a: &str, b: &str| {
        records.iter().any(|r| {
            let rec = Rec::new(&r.map, false);
            rec.has(a) && rec.has(b)
        })
    };
    if any("MessageTraceId", "RecipientAddress") {
        Some(Shape::MessageTrace)
    } else if any("network_message_id", "recipient_status") {
        Some(Shape::Summary)
    } else {
        None
    }
}

fn upn(v: Option<String>) -> Option<String> {
    v.and_then(|s| normalize_upn(&s))
}

fn ip(v: Option<String>) -> Option<String> {
    v.and_then(|s| normalize_ip(&s))
}

/// `recipient_status` of the summary report: `<recipient>##<status>` entries separated by `;`.
/// An entry without `##` is a recipient when it holds an `@`, else a status.
fn recipient_statuses(v: Option<String>) -> Vec<(Option<String>, Option<String>)> {
    let entries: Vec<(Option<String>, Option<String>)> = v
        .as_deref()
        .unwrap_or("")
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once("##") {
            Some((r, s)) => (
                normalize_upn(r),
                Some(s.trim().to_string()).filter(|s| !s.is_empty()),
            ),
            None if p.contains('@') => (normalize_upn(p), None),
            None => (None, Some(p.to_string())),
        })
        .collect();
    if entries.is_empty() {
        vec![(None, None)]
    } else {
        entries
    }
}

pub(crate) fn received_cells(c: &mut CellRow, time: Option<String>) {
    c.set(
        "time_tz_assumed",
        Cell::bool(time.as_deref().map(zone_assumed)),
    )
    .set("received", Cell::time(time));
}

pub struct MessageTraceParser;

impl ArtifactParser for MessageTraceParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        let Some(first) = records.first() else {
            return Ok(());
        };
        let Some(shape) = shape_of(&records) else {
            let cols: Vec<&str> = first.map.keys().take(12).map(String::as_str).collect();
            return Err(Error::UnsupportedShape(format!(
                "no message trace fields (MessageTraceId + RecipientAddress, or network_message_id + recipient_status) in [{}]",
                cols.join(", ")
            )));
        };
        let mut rows = TableRows::new(&MESSAGE_TRACE, COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let id_key = match shape {
                Shape::MessageTrace => "MessageTraceId",
                Shape::Summary => "network_message_id",
            };
            let Some(id) = rec.text(id_key) else {
                reject(ctx, r, &format!("message trace record has no {id_key}"))?;
                continue;
            };
            match shape {
                Shape::MessageTrace => {
                    let recipient = upn(rec.text("RecipientAddress"));
                    let mut c = CellRow::new(COLS);
                    c.set("message_trace_id", Cell::text(lower(Some(id.clone()))))
                        .set("sender", Cell::text(upn(rec.text("SenderAddress"))))
                        .set("recipient", Cell::text(recipient.clone()))
                        .set("subject", Cell::text(rec.text("Subject")))
                        .set("status", Cell::text(rec.text("Status")))
                        .set("from_ip", Cell::text(ip(rec.text("FromIP"))))
                        .set("to_ip", Cell::text(ip(rec.text("ToIP"))))
                        .set("size_bytes", Cell::int(rec.int("Size")))
                        .set("internet_message_id", Cell::text(rec.text("MessageId")))
                        .set("organization", Cell::text(rec.text("Organization")));
                    received_cells(&mut c, rec.text("Received"));
                    rows.push(
                        r,
                        message_trace_key(&id, recipient.as_deref()),
                        c.into_cells(),
                    );
                }
                Shape::Summary => {
                    for (recipient, status) in recipient_statuses(rec.text("recipient_status")) {
                        let mut c = CellRow::new(COLS);
                        c.set("message_trace_id", Cell::text(lower(Some(id.clone()))))
                            .set("sender", Cell::text(upn(rec.text("sender_address"))))
                            .set("recipient", Cell::text(recipient.clone()))
                            .set("subject", Cell::text(rec.text("message_subject")))
                            .set("status", Cell::text(status))
                            .set("from_ip", Cell::text(ip(rec.text("original_client_ip"))))
                            .set("size_bytes", Cell::int(rec.int("total_bytes")))
                            .set("internet_message_id", Cell::text(rec.text("message_id")))
                            .set("direction", Cell::text(rec.text("directionality")))
                            .set("connector_id", Cell::text(rec.text("connector_id")));
                        received_cells(&mut c, rec.text("origin_timestamp_utc"));
                        rows.push(
                            r,
                            message_trace_key(&id, recipient.as_deref()),
                            c.into_cells(),
                        );
                    }
                }
            }
        }
        load_tables(ctx, vec![rows])
    }
}
