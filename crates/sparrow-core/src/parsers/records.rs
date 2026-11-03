//! A collector file's records as key → value maps with their source spans: CSV rows, JSON
//! objects (array, bare object or concatenated documents) and Format-List blocks.

use crate::Result;
use crate::discovery::{FileFormat, format_from_path};
use crate::ingest::context::{ParseContext, RecordInput};
use crate::normalize::fields::is_placeholder;
use crate::readers::csv_scan::{CsvEvent, fields_map, read_csv_stream};
use crate::readers::format_list::{FlBlock, parse_format_list, parse_format_list_object};
use crate::readers::json_scan::{JsonEvent, scan_json_stream};
use crate::readers::stream::{Sight, TextStream};
use crate::readers::text::{SourcePos, Span};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordFormat {
    Csv,
    Json,
    /// Format-List text with one object per block.
    FormatList,
    /// Format-List text of a single object (blank lines do not split it).
    FormatListObject,
}

impl RecordFormat {
    /// `.csv` → Csv, `.txt` → FormatList, anything else → Json.
    pub fn of(rel_path: &str) -> RecordFormat {
        match format_from_path(rel_path) {
            FileFormat::Csv => RecordFormat::Csv,
            FileFormat::Txt => RecordFormat::FormatList,
            _ => RecordFormat::Json,
        }
    }

    /// Values are text renderings that may hold PowerShell placeholders.
    pub fn lossy(self) -> bool {
        self != RecordFormat::Json
    }

    /// A `.csv` file whose content is actually JSON: Microsoft-Extractor-Suite
    /// `Get-Devices -Output JSON` writes `ConvertTo-Json` output into the `.csv` path. Detect
    /// it by content (the first non-blank character is `[` or `{`), not by extension.
    pub fn json_content(text: &str) -> bool {
        matches!(
            text.trim_start_matches('\u{feff}')
                .trim_start()
                .chars()
                .next(),
            Some('[' | '{')
        )
    }
}

#[derive(Debug, Clone)]
pub struct SourceRecord {
    pub ordinal: u64,
    /// Where the record lives in the file and the hash of its raw bytes.
    pub sight: Sight,
    pub map: Map<String, Value>,
    /// Sighting of each field (Format-List only).
    pub field_sights: Vec<(String, Sight)>,
    /// At most 500 chars of the record's text: the `parse_errors.raw_snippet` of a record that is read but cannot
    /// be loaded.
    pub snippet: String,
}

fn block_record(ctx: &mut ParseContext<'_>, ordinal: u64, b: FlBlock) -> SourceRecord {
    let map = b.to_map();
    let field_sights = b
        .fields
        .iter()
        .map(|(k, _)| k.clone())
        .zip(b.field_spans.iter().map(|s| ctx.sighting(*s)))
        .collect();
    SourceRecord {
        ordinal,
        sight: ctx.sighting(b.span),
        map,
        field_sights,
        snippet: ctx.snippet(b.span),
    }
}

/// Every readable record of the file. Unreadable records are counted in `ctx.stats.read`
/// and written to `parse_errors`; readable ones are left for the caller to count. CSV and JSON are read in one
/// record pass; Format-List needs the whole text ([`ParseContext::whole`]).
pub fn read_records(ctx: &mut ParseContext<'_>, format: RecordFormat) -> Result<Vec<SourceRecord>> {
    let mut out = Vec::new();
    match format {
        RecordFormat::Csv | RecordFormat::Json => {
            // The scan's errors are written as they come; records that are not objects after them, as the
            // collected scan wrote them.
            let mut not_objects = Vec::new();
            let input = ctx.input();
            scan_records(&input, format, |event| {
                match event {
                    Scanned::Record(r) => out.push(r),
                    Scanned::Error(e) => {
                        ctx.stats.read += 1;
                        ctx.parse_error_at(e.ordinal, &e.pos, &e.snippet, &e.message)?;
                    }
                    Scanned::NotObject(e) => not_objects.push(e),
                }
                Ok(true)
            })?;
            for e in not_objects {
                ctx.stats.read += 1;
                ctx.parse_error_at(e.ordinal, &e.pos, &e.snippet, &e.message)?;
            }
        }
        RecordFormat::FormatList | RecordFormat::FormatListObject => {
            let Some(whole) = ctx.whole().copied() else {
                return Err(crate::Error::Invalid(
                    "Format-List records need the whole text".into(),
                ));
            };
            if format == RecordFormat::FormatList {
                for (i, b) in parse_format_list(&whole.text.text).into_iter().enumerate() {
                    out.push(block_record(ctx, i as u64, b));
                }
            } else if let Some(b) = parse_format_list_object(&whole.text.text) {
                out.push(block_record(ctx, 0, b));
            }
        }
    }
    Ok(out)
}

/// One readable record, or an unreadable one, of [`for_each_record`].
pub enum RecordEvent {
    Record(SourceRecord),
    Error {
        ordinal: u64,
        pos: SourcePos,
        /// At most 500 chars of the record's text.
        snippet: String,
        message: String,
    },
}

/// An unreadable record: where it is, its snippet and why.
struct Unreadable {
    ordinal: u64,
    pos: SourcePos,
    snippet: String,
    message: String,
}

/// What [`scan_records`] gives: a record, a record the scan could not read, or a JSON value that is not an object.
enum Scanned {
    Record(SourceRecord),
    Error(Unreadable),
    NotObject(Unreadable),
}

/// The records of the file one at a time, in file order, without collecting them: what [`read_records`] reads, as
/// events, each with its sighting (taken while the record is read). Each call is a new pass over the file, so a
/// parser can make several passes holding one record at a time. `f` returns `Ok(false)` to stop; its error ends
/// the pass and is returned. CSV and JSON only.
pub fn for_each_record(
    input: &RecordInput<'_>,
    format: RecordFormat,
    mut f: impl FnMut(RecordEvent) -> Result<bool>,
) -> Result<()> {
    scan_records(input, format, |event| {
        f(match event {
            Scanned::Record(r) => RecordEvent::Record(r),
            Scanned::Error(e) | Scanned::NotObject(e) => RecordEvent::Error {
                ordinal: e.ordinal,
                pos: e.pos,
                snippet: e.snippet,
                message: e.message,
            },
        })
    })
}

/// One pass of [`for_each_record`]. Sightings and snippets are taken in the scanner's sink, while the record is in
/// the stream's window (a drained failure is only in the stream's memory of it, never in the window).
fn scan_records(
    input: &RecordInput<'_>,
    format: RecordFormat,
    mut f: impl FnMut(Scanned) -> Result<bool>,
) -> Result<()> {
    let io_err = |source: std::io::Error| crate::Error::Io {
        path: input.admitted().path.display().to_string(),
        source,
    };
    let mut failed = None;
    let mut step = |event: Scanned| match f(event) {
        Ok(go) => go,
        Err(e) => {
            failed = Some(e);
            false
        }
    };
    let unreadable = |s: &mut TextStream, ordinal: u64, span: Span, message: String| Unreadable {
        ordinal,
        pos: s.sight(span).pos,
        snippet: s.snippet(span),
        message,
    };
    let mut stream = input.open().map_err(io_err)?;
    let mut on_read = input.on_read();
    let scanned = match format {
        RecordFormat::Csv => {
            read_csv_stream(&mut stream, &mut on_read, |headers, event, s| match event {
                CsvEvent::Row(row) => step(Scanned::Record(SourceRecord {
                    ordinal: row.ordinal,
                    sight: s.sight(row.span),
                    snippet: s.snippet(row.span),
                    map: fields_map(headers, row.fields),
                    field_sights: Vec::new(),
                })),
                CsvEvent::Error(e) => {
                    step(Scanned::Error(unreadable(s, e.ordinal, e.span, e.message)))
                }
            })
            .map(|_| ())
        }
        RecordFormat::Json => scan_json_stream(&mut stream, &mut on_read, |event, s| match event {
            JsonEvent::Record(r) => match r.value {
                Value::Object(map) => step(Scanned::Record(SourceRecord {
                    ordinal: r.ordinal,
                    sight: s.sight(r.span),
                    snippet: s.snippet(r.span),
                    map,
                    field_sights: Vec::new(),
                })),
                _ => step(Scanned::NotObject(unreadable(
                    s,
                    r.ordinal,
                    r.span,
                    "record is not a JSON object".into(),
                ))),
            },
            JsonEvent::Error(e) => {
                step(Scanned::Error(unreadable(s, e.ordinal, e.span, e.message)))
            }
        })
        .map(|_| ()),
        RecordFormat::FormatList | RecordFormat::FormatListObject => {
            return Err(crate::Error::Invalid(
                "for_each_record reads CSV and JSON only".into(),
            ));
        }
    };
    if let Some(e) = failed {
        return Err(e);
    }
    scanned.map_err(io_err)
}

/// Warning for CSV records that hold PowerShell placeholders: nested and multi-valued
/// values are missing because no usable JSON twin was available.
pub fn placeholder_warning(records: &[SourceRecord], format: RecordFormat) -> Option<String> {
    if format != RecordFormat::Csv {
        return None;
    }
    placeholder_message(records.iter().filter(|r| holds_placeholder(r)).count())
}

/// True when a value of `r` is a PowerShell placeholder (counted by [`placeholder_warning`] for CSV files).
pub fn holds_placeholder(r: &SourceRecord) -> bool {
    r.map
        .values()
        .any(|v| v.as_str().is_some_and(is_placeholder))
}

/// [`placeholder_warning`]'s text for `n` CSV records holding placeholders (`None` for none).
pub fn placeholder_message(n: usize) -> Option<String> {
    (n > 0).then(|| {
        format!(
            "{n} CSV records hold PowerShell placeholders (System.Object[], @{{...}}, .NET type names); nested and multi-valued values are missing (no usable JSON twin)"
        )
    })
}
