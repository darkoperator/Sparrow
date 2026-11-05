//! Exchange Online message trace (spec 5.1 `message_trace`): Hawk 3 `Message_Trace_<user>`
//! (Get-MessageTrace) and the Exchange admin center summary report download (`MTSummary_*`,
//! snake_case columns, one line per message with `recipient##status` entries), plus the
//! Microsoft-Extractor-Suite `Get-MessageTraceLog` CSVs (`MessageTrace/<ts>/<ts>-MessageTrace.csv`
//! and `MessageTrace/<ts>/<user>-MTL.csv`), which share the Get-MessageTrace columns. All shapes
//! key a row by message trace id (= network message id) and recipient.

use crate::db::state_tables::MESSAGE_TRACE;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::ingest::progress::SAVING_RECORDS;
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::{normalize_ip, normalize_upn};
use crate::parsers::records::{
    RecordEvent, RecordFormat, SourceRecord, for_each_record, holds_placeholder,
    placeholder_message,
};
use crate::parsers::stage::{
    CellRow, RowDraft, RowOut, load_streamed, lower, no_tail, read_state_records,
};
use crate::readers::time::zone_assumed;
use crate::{Error, Result};
use serde_json::Value;

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

/// [`MessageTraceParser`]'s steps (a CSV/JSON file is streamed: the shape pass, then [`load_streamed`]'s).
const MESSAGE_TRACE_STEPS: &[&str] = &[
    "Checking columns",
    "Checking dates",
    "Loading records",
    SAVING_RECORDS,
];

const UNSUPPORTED: &str = "no message trace fields (MessageTraceId + RecipientAddress, or network_message_id + recipient_status)";

/// The rows of one record of `shape`: one for a Get-MessageTrace record, one per recipient of a summary line;
/// a record without its id is rejected. Pure: [`load_streamed`] calls it twice per record.
fn rows_of(r: &SourceRecord, shape: Shape, lossy: bool) -> Vec<RowOut> {
    let rec = Rec::new(&r.map, lossy);
    let id_key = match shape {
        Shape::MessageTrace => "MessageTraceId",
        Shape::Summary => "network_message_id",
    };
    let Some(id) = rec.text(id_key) else {
        return vec![RowOut::Reject(format!(
            "message trace record has no {id_key}"
        ))];
    };
    let row = |key: String, cells: Vec<Cell>| RowOut::Row {
        table: 0,
        draft: RowDraft {
            ordinal: r.ordinal,
            sight: r.sight.clone(),
            snippet: r.snippet.clone(),
            record_key: key,
            cells,
            raw: Some(Value::Object(r.map.clone())),
        },
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
            vec![row(
                message_trace_key(&id, recipient.as_deref()),
                c.into_cells(),
            )]
        }
        Shape::Summary => recipient_statuses(rec.text("recipient_status"))
            .into_iter()
            .map(|(recipient, status)| {
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
                row(message_trace_key(&id, recipient.as_deref()), c.into_cells())
            })
            .collect(),
    }
}

/// A CSV/JSON message trace, streamed (see [`load_streamed`]): an admin center summary download can hold millions
/// of messages.
fn parse_streamed(ctx: &mut ParseContext<'_>, format: RecordFormat) -> Result<()> {
    ctx.set_step(0);
    // What the collected records decided: the shape (Get-MessageTrace if any record is one, else summary if any
    // record is one), the first record's columns for the error, and the placeholder count.
    let (mut first, mut trace, mut summary, mut placeholders) = (None, false, false, 0usize);
    // Once a Get-MessageTrace record is seen the shape is settled; only the placeholder count can still change, and
    // it is not reported for a portal download or a JSON file, so the scan stops there.
    let count_placeholders = format == RecordFormat::Csv && !ctx.portal_export;
    // A shape pass: the records' sightings are not needed.
    for_each_record(&ctx.input().with_sights(false), format, |event| {
        if let RecordEvent::Record(r) = event {
            let rec = Rec::new(&r.map, false);
            trace |= rec.has("MessageTraceId") && rec.has("RecipientAddress");
            summary |= rec.has("network_message_id") && rec.has("recipient_status");
            if count_placeholders && holds_placeholder(&r) {
                placeholders += 1;
            }
            if first.is_none() {
                first = Some(r.map.keys().take(12).cloned().collect::<Vec<_>>());
            }
            return Ok(!(trace && !count_placeholders));
        }
        Ok(true)
    })?;
    let Some(first) = first else {
        // No readable record: recording the unreadable ones is all there is to do (the load step's pass).
        ctx.set_step(2);
        read_state_records(ctx, format)?;
        return Ok(());
    };
    if !ctx.portal_export
        && let Some(w) = placeholder_message(placeholders)
    {
        ctx.warn(w);
    }
    let shape = if trace {
        Shape::MessageTrace
    } else if summary {
        Shape::Summary
    } else {
        return Err(Error::UnsupportedShape(format!(
            "{UNSUPPORTED} in [{}]",
            first.join(", ")
        )));
    };
    let lossy = format.lossy();
    load_streamed(ctx, 1, format, &[(&MESSAGE_TRACE, COLS)], no_tail, |r| {
        rows_of(r, shape, lossy)
    })
}

impl ArtifactParser for MessageTraceParser {
    /// The shape pass (which stops at the first Get-MessageTrace record when it need not count placeholders), then
    /// [`load_streamed`]'s two passes and its merge.
    fn steps(&self) -> &'static [&'static str] {
        MESSAGE_TRACE_STEPS
    }

    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        // Every registered path of this parser is `.csv` or `.json` (the portal sniffs read CSV and JSON).
        parse_streamed(ctx, RecordFormat::of(ctx.rel_path))
    }
}
