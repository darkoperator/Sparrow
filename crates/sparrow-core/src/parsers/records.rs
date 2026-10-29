//! A collector file's records as key → value maps with their source spans: CSV rows, JSON
//! objects (array, bare object or concatenated documents) and Format-List blocks.

use crate::Result;
use crate::discovery::{FileFormat, format_from_path};
use crate::ingest::context::ParseContext;
use crate::normalize::fields::is_placeholder;
use crate::readers::csv_scan::{CsvEvent, fields_map, read_csv, read_csv_each};
use crate::readers::format_list::{FlBlock, parse_format_list, parse_format_list_object};
use crate::readers::json_scan::{JsonEvent, scan_json, scan_json_each};
use crate::readers::text::Span;
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
    pub span: Span,
    pub map: Map<String, Value>,
    /// Span of each field (Format-List only).
    pub field_spans: Vec<(String, Span)>,
}

fn block_record(ordinal: u64, b: FlBlock) -> SourceRecord {
    let map = b.to_map();
    let field_spans = b
        .fields
        .iter()
        .map(|(k, _)| k.clone())
        .zip(b.field_spans.iter().copied())
        .collect();
    SourceRecord {
        ordinal,
        span: b.span,
        map,
        field_spans,
    }
}

/// Every readable record of the file. Unreadable records are counted in `ctx.stats.read`
/// and written to `parse_errors`; readable ones are left for the caller to count.
pub fn read_records(ctx: &mut ParseContext<'_>, format: RecordFormat) -> Result<Vec<SourceRecord>> {
    let text = ctx.text;
    let mut out = Vec::new();
    match format {
        RecordFormat::Csv => {
            let table = read_csv(&text.text);
            for e in &table.errors {
                ctx.stats.read += 1;
                ctx.parse_error(e.ordinal, e.span, &e.message)?;
            }
            out.reserve(table.rows.len());
            // Consumed: each field moves into its record's map, so the file's values are not held twice.
            for row in table.rows {
                out.push(SourceRecord {
                    ordinal: row.ordinal,
                    span: row.span,
                    map: fields_map(&table.headers, row.fields),
                    field_spans: Vec::new(),
                });
            }
        }
        RecordFormat::Json => {
            let scan = scan_json(&text.text);
            for e in &scan.errors {
                ctx.stats.read += 1;
                ctx.parse_error(e.ordinal, e.span, &e.message)?;
            }
            for r in scan.records {
                match r.value {
                    Value::Object(map) => out.push(SourceRecord {
                        ordinal: r.ordinal,
                        span: r.span,
                        map,
                        field_spans: Vec::new(),
                    }),
                    _ => {
                        ctx.stats.read += 1;
                        ctx.parse_error(r.ordinal, r.span, "record is not a JSON object")?;
                    }
                }
            }
        }
        RecordFormat::FormatList => {
            for (i, b) in parse_format_list(&text.text).into_iter().enumerate() {
                out.push(block_record(i as u64, b));
            }
        }
        RecordFormat::FormatListObject => {
            if let Some(b) = parse_format_list_object(&text.text) {
                out.push(block_record(0, b));
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
        span: Span,
        message: String,
    },
}

/// The records of `text` one at a time, in file order, without collecting them: what [`read_records`] reads, as
/// events. Each call scans the text again, so a parser can make several passes holding one record at a time.
/// `f` returns `Ok(false)` to stop; its error ends the scan and is returned. CSV and JSON only.
pub fn for_each_record(
    text: &str,
    format: RecordFormat,
    mut f: impl FnMut(RecordEvent) -> Result<bool>,
) -> Result<()> {
    let mut failed = None;
    let mut step = |event: RecordEvent| match f(event) {
        Ok(go) => go,
        Err(e) => {
            failed = Some(e);
            false
        }
    };
    match format {
        RecordFormat::Csv => {
            read_csv_each(text, |headers, event| match event {
                CsvEvent::Row(row) => step(RecordEvent::Record(SourceRecord {
                    ordinal: row.ordinal,
                    span: row.span,
                    map: fields_map(headers, row.fields),
                    field_spans: Vec::new(),
                })),
                CsvEvent::Error(e) => step(RecordEvent::Error {
                    ordinal: e.ordinal,
                    span: e.span,
                    message: e.message,
                }),
            });
        }
        RecordFormat::Json => {
            scan_json_each(text, |event| match event {
                JsonEvent::Record(r) => match r.value {
                    Value::Object(map) => step(RecordEvent::Record(SourceRecord {
                        ordinal: r.ordinal,
                        span: r.span,
                        map,
                        field_spans: Vec::new(),
                    })),
                    _ => step(RecordEvent::Error {
                        ordinal: r.ordinal,
                        span: r.span,
                        message: "record is not a JSON object".into(),
                    }),
                },
                JsonEvent::Error(e) => step(RecordEvent::Error {
                    ordinal: e.ordinal,
                    span: e.span,
                    message: e.message,
                }),
            });
        }
        RecordFormat::FormatList | RecordFormat::FormatListObject => {
            return Err(crate::Error::Invalid(
                "for_each_record reads CSV and JSON only".into(),
            ));
        }
    }
    failed.map_or(Ok(()), Err)
}

/// Warning for CSV records that hold PowerShell placeholders: nested and multi-valued
/// values are missing because no usable JSON twin was available.
pub fn placeholder_warning(records: &[SourceRecord], format: RecordFormat) -> Option<String> {
    if format != RecordFormat::Csv {
        return None;
    }
    let n = records
        .iter()
        .filter(|r| {
            r.map
                .values()
                .any(|v| v.as_str().is_some_and(is_placeholder))
        })
        .count();
    (n > 0).then(|| {
        format!(
            "{n} CSV records hold PowerShell placeholders (System.Object[], @{{...}}, .NET type names); nested and multi-valued values are missing (no usable JSON twin)"
        )
    })
}
