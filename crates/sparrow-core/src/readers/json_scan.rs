//! Scanner for PowerShell-produced JSON: bare objects, arrays, and several documents
//! concatenated in one file (Hawk `-append`, Extractor Suite same-second pages, JSONL).
//! Each record keeps the exact span of its source text.

use crate::readers::stream::{OnRead, Scan, Step, TextStream, scan_stream, scan_whole, size_text};
use crate::readers::text::Span;
use serde_json::Value;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonShape {
    Empty,
    SingleObject,
    Array,
    Concatenated,
}

#[derive(Debug, Clone)]
pub struct JsonRecord {
    pub ordinal: u64,
    pub span: Span,
    pub value: Value,
}

#[derive(Debug, Clone)]
pub struct JsonRecordError {
    pub ordinal: u64,
    pub span: Span,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct JsonScan {
    pub shape: JsonShape,
    pub records: Vec<JsonRecord>,
    pub errors: Vec<JsonRecordError>,
}

/// One record or record error of [`scan_json_each`], in file order.
#[derive(Debug, Clone)]
pub enum JsonEvent {
    Record(JsonRecord),
    Error(JsonRecordError),
}

/// Where [`Scanner`] is: between documents, in an array before a value (or its `]`), in an array after a value, or
/// at a bad array separator (absolute offset) whose failure is reported once the text has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum At {
    Top,
    Item,
    AfterItem,
    BadSeparator(usize),
    /// A value from this absolute offset is past the record cap (ended or not): drained, then failed.
    OverCap(usize),
    Done,
}

/// Decoded bytes a streamed JSON value may hold (a value of more is failed, ended or not). Only a truncated or
/// unbalanced value (a `{`, `[` or `"` that never closes) makes a record this long, and the scan holds a record whole until it
/// ends, so without a cap one such value in a multi-GB export would hold the rest of the file in memory. A whole-text
/// scan has no cap (the text is already in memory), so the two differ only for a value over the cap.
pub(crate) const JSON_RECORD_MAX_BYTES: usize = 64 * 1024 * 1024;

const TRUNCATED_ARRAY: &str = "unexpected end of input inside array (truncated file?)";

/// The failure of a value past the cap (ended or not).
fn over_cap_message(cap: usize) -> String {
    format!(
        "record exceeds the JSON record size limit ({}); the rest of the file is not read as records",
        size_text(cap)
    )
}

/// The scan behind [`scan_json_each`] and [`scan_json_stream`]. A step over a window that may go on stops short of
/// any value that reaches the window's end (and of a truncation failure, which more text may turn into a value),
/// asking for more text from where it stands; the state it keeps between steps is only what it had at that point,
/// so the rescan over the longer window continues exactly as a scan of the whole text. A bad array separator is a
/// failure whatever follows, spanning to the end of the text: it asks the driver to drain the text from there
/// ([`Step::DrainFrom`]) and reports it on the next step. A value that reaches `cap` decoded bytes while more text
/// follows is failed the same way, from its start to the end of the text.
struct Scanner {
    at: At,
    /// Absolute offset the next step starts at.
    pos: usize,
    docs: usize,
    first_is_array: bool,
    ordinal: u64,
    /// Decoded bytes a value may hold ([`JSON_RECORD_MAX_BYTES`] when streamed; no cap over a whole text, which is
    /// already in memory).
    cap: usize,
}

impl Scanner {
    fn new() -> Self {
        Scanner {
            at: At::Top,
            pos: 0,
            docs: 0,
            first_is_array: false,
            ordinal: 0,
            cap: usize::MAX,
        }
    }

    /// `More(self.pos)` for a value starting at `self.pos` that may go on, unless the window from it is past the cap
    /// (the value, once it ends, will be at least that long): then drain from it (the failure comes on the next step).
    fn more_or_drain(&mut self, text: &str, base: usize) -> Step<JsonEvent> {
        if base + text.len() - self.pos > self.cap {
            return self.drain_over_cap();
        }
        Step::More(self.pos)
    }

    /// The failure of a value of `len` bytes that never ends (the text ended inside it): past the cap, the over-cap
    /// failure a longer window would have drained it with, so the message does not depend on the window either.
    fn unended_message(&self, len: usize, msg: String) -> String {
        if len > self.cap {
            over_cap_message(self.cap)
        } else {
            msg
        }
    }

    /// Fail the value at `self.pos` as past the cap: drain from it; the failure comes on the next step.
    fn drain_over_cap(&mut self) -> Step<JsonEvent> {
        self.at = At::OverCap(self.pos);
        Step::DrainFrom(self.pos)
    }

    fn shape(&self) -> JsonShape {
        match self.docs {
            0 => JsonShape::Empty,
            1 if self.first_is_array => JsonShape::Array,
            1 => JsonShape::SingleObject,
            _ => JsonShape::Concatenated,
        }
    }

    /// The record at `start..end` of the window.
    fn push(&mut self, text: &str, base: usize, start: usize, end: usize) -> JsonEvent {
        let span = Span {
            start: base + start,
            end: base + end,
        };
        let event = match serde_json::from_str::<Value>(&text[start..end]) {
            Ok(value) => JsonEvent::Record(JsonRecord {
                ordinal: self.ordinal,
                span,
                value,
            }),
            Err(e) => JsonEvent::Error(JsonRecordError {
                ordinal: self.ordinal,
                span,
                message: e.to_string(),
            }),
        };
        self.ordinal += 1;
        event
    }

    /// A failure from absolute offset `start` to the end of the text, which ends the scan.
    fn fail(&mut self, text: &str, base: usize, start: usize, message: String) -> JsonEvent {
        let event = JsonEvent::Error(JsonRecordError {
            ordinal: self.ordinal,
            span: Span {
                start,
                end: base + text.len(),
            },
            message,
        });
        self.ordinal += 1;
        self.at = At::Done;
        event
    }
}

/// [`value_end`], or `None` when the value may go on past the window.
fn window_value_end(b: &[u8], start: usize, last: bool) -> Option<Result<usize, String>> {
    match value_end(b, start) {
        Ok(end) if end < b.len() || last => Some(Ok(end)),
        Err(msg) if last => Some(Err(msg)),
        _ => None,
    }
}

impl Scan for Scanner {
    type Event = JsonEvent;

    fn next(&mut self, text: &str, base: usize, last: bool) -> Step<JsonEvent> {
        let b = text.as_bytes();
        loop {
            match self.at {
                At::Done => return Step::End,
                At::BadSeparator(start) if last => {
                    let msg = "expected ',' or ']' in array".into();
                    return Step::Event(self.fail(text, base, start, msg));
                }
                At::BadSeparator(start) => return Step::DrainFrom(start),
                At::OverCap(start) => {
                    // Drained: the text has ended.
                    let msg = over_cap_message(self.cap);
                    return Step::Event(self.fail(text, base, start, msg));
                }
                _ => {}
            }
            let commas = self.at == At::Top;
            let p = skip(b, self.pos - base, commas);
            self.pos = base + p;
            match self.at {
                At::Done | At::BadSeparator(_) | At::OverCap(_) => unreachable!("handled above"),
                At::Top => {
                    if p >= b.len() {
                        if last {
                            self.at = At::Done;
                            return Step::End;
                        }
                        return Step::More(self.pos);
                    }
                    if b[p] == b'[' {
                        self.docs += 1;
                        if self.docs == 1 {
                            self.first_is_array = true;
                        }
                        self.pos += 1;
                        self.at = At::Item;
                        continue;
                    }
                    let Some(end) = window_value_end(b, p, last) else {
                        if base + b.len() - self.pos > self.cap {
                            // A document of its own, failed as a truncated one is.
                            self.docs += 1;
                        }
                        return self.more_or_drain(text, base);
                    };
                    self.docs += 1;
                    return match end {
                        // An ended value past the cap is failed as one that has not ended yet is (above), so the
                        // outcome does not depend on where the windows were cut. A value of exactly the cap is read.
                        Ok(end) if end - p > self.cap => self.drain_over_cap(),
                        Ok(end) => {
                            self.pos = base + end;
                            Step::Event(self.push(text, base, p, end))
                        }
                        Err(msg) => {
                            let msg = self.unended_message(b.len() - p, msg);
                            Step::Event(self.fail(text, base, base + p, msg))
                        }
                    };
                }
                At::Item => {
                    if p >= b.len() {
                        if !last {
                            return Step::More(self.pos);
                        }
                        let msg = TRUNCATED_ARRAY.into();
                        return Step::Event(self.fail(text, base, base + p, msg));
                    }
                    if b[p] == b']' {
                        self.pos += 1;
                        self.at = At::Top;
                        continue;
                    }
                    let Some(end) = window_value_end(b, p, last) else {
                        return self.more_or_drain(text, base);
                    };
                    return match end {
                        // As at the top level: an ended item past the cap is failed from its start to the end.
                        Ok(end) if end - p > self.cap => self.drain_over_cap(),
                        Ok(end) => {
                            self.pos = base + end;
                            self.at = At::AfterItem;
                            Step::Event(self.push(text, base, p, end))
                        }
                        Err(msg) => {
                            let msg = self.unended_message(b.len() - p, msg);
                            Step::Event(self.fail(text, base, base + p, msg))
                        }
                    };
                }
                At::AfterItem => match b.get(p) {
                    Some(b',') => {
                        self.pos += 1;
                        self.at = At::Item;
                    }
                    Some(b']') => {
                        self.pos += 1;
                        self.at = At::Top;
                    }
                    Some(_) => self.at = At::BadSeparator(self.pos),
                    None if !last => return Step::More(self.pos),
                    None => {
                        let msg = TRUNCATED_ARRAY.into();
                        return Step::Event(self.fail(text, base, base + p, msg));
                    }
                },
            }
        }
    }
}

pub fn scan_json(text: &str) -> JsonScan {
    let mut records = Vec::new();
    let mut errors = Vec::new();
    let shape = scan_json_each(text, |event| {
        match event {
            JsonEvent::Record(r) => records.push(r),
            JsonEvent::Error(e) => errors.push(e),
        }
        true
    });
    JsonScan {
        shape,
        records,
        errors,
    }
}

/// [`scan_json`] without collecting: each record (parsed) or record error goes to `sink` in file order, so a caller
/// can hold one record at a time. `sink` returns false to stop the scan; the shape is then that of the part read.
pub fn scan_json_each(text: &str, mut sink: impl FnMut(JsonEvent) -> bool) -> JsonShape {
    let mut scan = Scanner::new();
    scan_whole(&mut scan, text, |_, event| sink(event));
    scan.shape()
}

/// [`scan_json_each`] over a [`TextStream`]: the same events (spans absolute) and shape, each event handed to `sink`
/// while its record is still in the window, so the sink can [`sight`](TextStream::sight) it. A read error, or
/// `on_read` asking to stop, ends the scan with that error. A failure spans the rest of the file: a bad array separator
/// is sighted while the rest of the file is drained, in bounded memory, and so is a value longer than
/// [`JSON_RECORD_MAX_BYTES`], ended or not (an unclosed `{`, `[` or `"` is failed once the window from it passes the
/// cap); a shorter truncated value is failed at the end of the text.
pub fn scan_json_stream(
    stream: &mut TextStream,
    on_read: OnRead,
    sink: impl FnMut(JsonEvent, &mut TextStream) -> bool,
) -> io::Result<JsonShape> {
    scan_json_stream_capped(stream, on_read, JSON_RECORD_MAX_BYTES, sink)
}

/// [`scan_json_stream`] with a record cap of `cap` decoded bytes instead of [`JSON_RECORD_MAX_BYTES`].
pub(crate) fn scan_json_stream_capped(
    stream: &mut TextStream,
    on_read: OnRead,
    cap: usize,
    mut sink: impl FnMut(JsonEvent, &mut TextStream) -> bool,
) -> io::Result<JsonShape> {
    let mut scan = Scanner::new();
    scan.cap = cap;
    scan_stream(&mut scan, stream, on_read, |_, event, stream| {
        sink(event, stream)
    })?;
    Ok(scan.shape())
}

fn skip(b: &[u8], mut pos: usize, commas: bool) -> usize {
    while pos < b.len() && (b[pos].is_ascii_whitespace() || (commas && b[pos] == b',')) {
        pos += 1;
    }
    pos
}

/// End (exclusive) of the JSON value starting at `start`, found structurally.
fn value_end(b: &[u8], start: usize) -> Result<usize, String> {
    match b[start] {
        b'{' | b'[' => {
            let mut depth = 0i32;
            let mut i = start;
            while i < b.len() {
                match b[i] {
                    b'"' => {
                        i = string_end(b, i)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(i + 1);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            Err("unexpected end of input (truncated JSON value)".into())
        }
        b'"' => string_end(b, start),
        _ => {
            let mut i = start;
            while i < b.len() && !matches!(b[i], b',' | b']' | b'}' | b' ' | b'\t' | b'\r' | b'\n')
            {
                i += 1;
            }
            if i == start {
                i = start + 1; // lone ']' / '}': consume it so it is reported, never loop
            }
            Ok(i)
        }
    }
}

/// Index just after the closing quote of the string starting at `start`.
fn string_end(b: &[u8], start: usize) -> Result<usize, String> {
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Ok(i + 1),
            _ => i += 1,
        }
    }
    Err("unexpected end of input inside string (truncated file?)".into())
}
