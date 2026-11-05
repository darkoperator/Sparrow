//! CSV reader for PowerShell `Export-Csv` output that keeps each row's source span.

use crate::readers::stream::{OnRead, Scan, Step, TextStream, scan_stream, scan_whole, size_text};
use crate::readers::text::Span;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::io;

#[derive(Debug, Clone)]
pub struct CsvRow {
    pub ordinal: u64,
    pub span: Span,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CsvRowError {
    pub ordinal: u64,
    pub span: Span,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct CsvTable {
    pub headers: Vec<String>,
    pub rows: Vec<CsvRow>,
    pub errors: Vec<CsvRowError>,
}

/// Header cleanup for collector and portal CSVs: strip a BOM, trim, collapse internal
/// whitespace runs to one space, and number repeated names (`x`, `x_2`, `x_3`).
pub fn normalize_headers<'a>(fields: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    fields
        .into_iter()
        .map(|h| {
            let base = h
                .trim_start_matches('\u{feff}')
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let n = seen.entry(base.clone()).or_insert(0);
            *n += 1;
            if *n == 1 { base } else { format!("{base}_{n}") }
        })
        .collect()
}

pub fn read_csv(text: &str) -> CsvTable {
    let mut table = CsvTable::default();
    table.headers = read_csv_each(text, |_, event| {
        match event {
            CsvEvent::Row(row) => table.rows.push(row),
            CsvEvent::Error(e) => table.errors.push(e),
        }
        true
    });
    table
}

/// One row or row error of [`read_csv_each`], in file order.
#[derive(Debug, Clone)]
pub enum CsvEvent {
    Row(CsvRow),
    Error(CsvRowError),
}

/// [`read_csv`] without collecting: each row or row error goes to `sink` with the normalized headers, in file order,
/// so a caller can hold one row at a time. `sink` returns false to stop. Returns the headers.
pub fn read_csv_each(text: &str, mut sink: impl FnMut(&[String], CsvEvent) -> bool) -> Vec<String> {
    let mut scan = CsvScan::new();
    scan_whole(&mut scan, text, |scan, event| sink(&scan.headers, event));
    scan.headers
}

/// [`read_csv_each`] over a [`TextStream`]: the same events (spans absolute), each handed to `sink` while its row is
/// still in the window, so the sink can [`sight`](TextStream::sight) it. A read error, or `on_read` asking to stop,
/// ends the scan with that error. Returns the headers.
pub fn read_csv_stream(
    stream: &mut TextStream,
    on_read: OnRead,
    sink: impl FnMut(&[String], CsvEvent, &mut TextStream) -> bool,
) -> io::Result<Vec<String>> {
    read_csv_stream_capped(stream, on_read, CSV_RECORD_MAX_BYTES, sink)
}

/// [`read_csv_stream`] with a record cap of `cap` decoded bytes instead of [`CSV_RECORD_MAX_BYTES`].
pub(crate) fn read_csv_stream_capped(
    stream: &mut TextStream,
    on_read: OnRead,
    cap: usize,
    mut sink: impl FnMut(&[String], CsvEvent, &mut TextStream) -> bool,
) -> io::Result<Vec<String>> {
    let mut scan = CsvScan::new();
    scan.cap = cap;
    scan_stream(&mut scan, stream, on_read, |scan, event, stream| {
        sink(&scan.headers, event, stream)
    })?;
    Ok(scan.headers)
}

/// Decoded bytes a streamed record's span may hold (a span of more is failed, ended or not). Only an unclosed quote
/// makes a record this long (a spreadsheet cell holds at most 32,767 characters; audit records are kilobytes), and the scan
/// holds a record whole (its text, its raw bytes and its field bytes, up to about twice this each), so without a cap
/// one stray quote in a multi-GB export would hold the rest of the file in memory. A whole-text scan has no cap (the
/// text is already in memory and under the whole-file guard), so the two differ only for a record over the cap: one
/// error to the end of the file when streamed, one large row over a whole text.
pub(crate) const CSV_RECORD_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Field buffer sizes a scan starts with and returns to after an outsized record.
const FIELDS_KEEP: usize = 64 * 1024;
const ENDS_KEEP: usize = 1024;

/// The scan behind [`read_csv_each`] and [`read_csv_stream`]: the reader core of the `csv` crate (what
/// `csv::Reader` runs, with the defaults `read_csv` has always used: comma, double quotes, CR/LF/CRLF terminators,
/// flexible field counts), fed the text as it arrives. Its records do not depend on how the input is cut, so a
/// window gives the same records as the whole text, and a record is only complete once its terminator (or the end
/// of the text) is seen.
struct CsvScan {
    core: csv_core::Reader,
    /// The current record's field bytes and field ends, filled `out` and `ends` deep.
    fields: Vec<u8>,
    field_ends: Vec<usize>,
    out: usize,
    ends: usize,
    /// Absolute offset of the next byte to feed.
    pos: usize,
    /// Absolute offset where the record being read starts: just after the previous record's terminator.
    before: usize,
    fed: bool,
    done: bool,
    headers: Vec<String>,
    have_header: bool,
    ordinal: u64,
    /// Decoded bytes a record's span may hold ([`CSV_RECORD_MAX_BYTES`] when streamed; no cap over a whole text,
    /// which is already in memory).
    cap: usize,
    /// The record past `cap`: its absolute start, drained to the end of the text and failed on the next step.
    over_cap: Option<usize>,
}

/// The failure of a record past the cap (ended or not).
fn over_cap_message(cap: usize) -> String {
    format!(
        "record exceeds the CSV record size limit ({}); the rest of the file is not read as records",
        size_text(cap)
    )
}

impl CsvScan {
    fn new() -> Self {
        CsvScan {
            core: csv_core::Reader::new(),
            fields: vec![0; FIELDS_KEEP],
            field_ends: vec![0; ENDS_KEEP],
            out: 0,
            ends: 0,
            pos: 0,
            before: 0,
            fed: false,
            done: false,
            headers: Vec::new(),
            have_header: false,
            ordinal: 0,
            cap: usize::MAX,
            over_cap: None,
        }
    }

    /// The `#TYPE` line, the header row, or a row or row error (`None` for the first two).
    fn record(&mut self, text: &str, base: usize) -> Option<CsvEvent> {
        let out = std::mem::take(&mut self.out);
        let ends = std::mem::take(&mut self.ends);
        let before = std::mem::replace(&mut self.before, self.pos);
        let mut record = Vec::with_capacity(ends);
        let mut invalid = None;
        let mut from = 0;
        for (i, &to) in self.field_ends[..ends].iter().enumerate() {
            match std::str::from_utf8(&self.fields[from..to]) {
                Ok(field) => record.push(field.to_string()),
                Err(e) => {
                    invalid = Some(format!("invalid UTF-8 in field {i}: {e}"));
                    break;
                }
            }
            from = to;
        }
        // After a record far larger than usual, give the buffers back.
        if self.fields.len() > 4 * out.max(FIELDS_KEEP) {
            self.fields = vec![0; FIELDS_KEEP];
        }
        if self.field_ends.len() > 4 * ends.max(ENDS_KEEP) {
            self.field_ends = vec![0; ENDS_KEEP];
        }
        // Unreachable: the input is a `str` and the core cuts and unquotes it only at ASCII bytes, so every field is
        // UTF-8. Kept as the old reader's error recovery (span, ordinal, stop without progress); nothing may rely on
        // the message's wording.
        if let Some(message) = invalid {
            return Some(self.error(text, base, before, message));
        }
        let end = base + trim_line_end(text, self.pos - base);
        let start = base + skip_newlines(text, before - base, end - base);
        if !self.have_header {
            let is_type_line = record.len() == 1
                && record[0]
                    .trim_start_matches('\u{feff}')
                    .starts_with("#TYPE");
            if !is_type_line {
                self.headers = normalize_headers(record.iter().map(String::as_str));
                self.have_header = true;
            }
            return None;
        }
        let row = CsvRow {
            ordinal: self.ordinal,
            span: Span { start, end },
            fields: record,
        };
        self.ordinal += 1;
        Some(CsvEvent::Row(row))
    }

    fn error(&mut self, text: &str, base: usize, before: usize, message: String) -> CsvEvent {
        let end = (base + trim_line_end(text, self.pos - base)).max(before);
        let error = CsvRowError {
            ordinal: self.ordinal,
            span: Span { start: before, end },
            message,
        };
        self.ordinal += 1;
        if self.pos <= before {
            self.done = true;
        }
        CsvEvent::Error(error)
    }
}

impl Scan for CsvScan {
    type Event = CsvEvent;

    fn next(&mut self, text: &str, base: usize, last: bool) -> Step<CsvEvent> {
        use csv_core::ReadRecordResult as R;
        loop {
            if self.done {
                return Step::End;
            }
            if let Some(start) = self.over_cap {
                // Drained: the text has ended. The record spans from its start to the end, as a JSON failure does.
                self.done = true;
                let error = CsvRowError {
                    ordinal: self.ordinal,
                    span: Span {
                        start,
                        end: base + text.len(),
                    },
                    message: over_cap_message(self.cap),
                };
                self.ordinal += 1;
                return Step::Event(CsvEvent::Error(error));
            }
            let input = &text.as_bytes()[self.pos - base..];
            // An empty input tells the core the text has ended. Its first input must also be what the whole text
            // would give it: it strips a UTF-8 BOM only when all three bytes are in its first input, and a first
            // input of the BOM alone is then empty, the end.
            if !last && (input.is_empty() || (!self.fed && input.len() <= 3)) {
                // The record so far is the window from its first char (as a row's span starts, after the previous
                // terminator's `\n`) to its last one that is not a line end (as a row's span ends): its span will be
                // at least that long, so past the cap it is failed as an ended one would be (`R::Record` below), and
                // the scan stops holding it and drains the rest.
                let start = base + skip_newlines(text, self.before - base, text.len());
                let end = base + trim_line_end(text, text.len());
                if end.saturating_sub(start) > self.cap {
                    self.over_cap = Some(start);
                    return Step::DrainFrom(start);
                }
                return Step::More(self.before);
            }
            self.fed = true;
            let (res, nin, nout, nend) = self.core.read_record(
                input,
                &mut self.fields[self.out..],
                &mut self.field_ends[self.ends..],
            );
            self.pos += nin;
            self.out += nout;
            self.ends += nend;
            match res {
                R::InputEmpty => {}
                R::OutputFull => {
                    let n = (self.fields.len() * 2).max(4);
                    self.fields.resize(n, 0);
                }
                R::OutputEndsFull => {
                    let n = (self.field_ends.len() * 2).max(4);
                    self.field_ends.resize(n, 0);
                }
                R::Record => {
                    // A record whose span (from its first char to its last that is not a line end, as `record`
                    // computes it) is past the cap is failed from its start to the end of the text, as one that has
                    // not ended yet is: the outcome does not depend on where the windows were cut. A span of exactly
                    // the cap is read.
                    let end = base + trim_line_end(text, self.pos - base);
                    let start = base + skip_newlines(text, self.before - base, end - base);
                    if end - start > self.cap {
                        self.over_cap = Some(start);
                        return Step::DrainFrom(start);
                    }
                    if let Some(event) = self.record(text, base) {
                        return Step::Event(event);
                    }
                }
                R::End => {
                    self.done = true;
                    return Step::End;
                }
            }
        }
    }
}

fn trim_line_end(text: &str, end: usize) -> usize {
    let b = text.as_bytes();
    let mut end = end.min(b.len());
    while end > 0 && matches!(b[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    end
}

fn skip_newlines(text: &str, start: usize, end: usize) -> usize {
    let b = text.as_bytes();
    let mut start = start;
    while start < end && matches!(b[start], b'\n' | b'\r') {
        start += 1;
    }
    start
}

impl CsvTable {
    /// Header → value map for a row; extra fields are keyed `_extra_<n>`.
    pub fn row_map(&self, row: &CsvRow) -> Map<String, Value> {
        fields_map(&self.headers, row.fields.clone())
    }
}

/// [`CsvTable::row_map`] of an owned row's fields: the strings move into the map instead of being copied, so a
/// caller that consumes `CsvTable::rows` holds each value once.
pub fn fields_map(headers: &[String], fields: Vec<String>) -> Map<String, Value> {
    let mut map = Map::new();
    for (i, field) in fields.into_iter().enumerate() {
        let key = match headers.get(i) {
            Some(h) => h.clone(),
            None => format!("_extra_{}", i - headers.len()),
        };
        map.insert(key, Value::String(field));
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_buffers_return_after_an_outsized_record() {
        let mut text = format!("Id,AuditData\n0,\"{}\"\n", "x".repeat(1024 * 1024));
        for i in 1..100 {
            text.push_str(&format!("{i},small\n"));
        }
        let mut scan = CsvScan::new();
        let mut rows = 0;
        scan_whole(&mut scan, &text, |scan, event| {
            let CsvEvent::Row(row) = event else {
                panic!("{event:?}")
            };
            if row.ordinal == 0 {
                // The core needed a buffer of over 1 MiB for this record...
                assert_eq!(row.fields[1].len(), 1024 * 1024);
                assert!(scan.fields.len() > 1024 * 1024, "{}", scan.fields.len());
                rows += 1;
                return true;
            }
            // ...and gives it back at the next one.
            assert!(scan.fields.len() <= FIELDS_KEEP, "{}", scan.fields.len());
            assert!(
                scan.field_ends.len() <= ENDS_KEEP,
                "{}",
                scan.field_ends.len()
            );
            rows += 1;
            true
        });
        assert_eq!(rows, 100);
    }
}
