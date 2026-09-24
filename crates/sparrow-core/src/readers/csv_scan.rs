//! CSV reader for PowerShell `Export-Csv` output that keeps each row's source span.

use crate::readers::text::Span;
use serde_json::{Map, Value};

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

pub fn read_csv(text: &str) -> CsvTable {
    let mut rdr = ::csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut table = CsvTable::default();
    let mut record = ::csv::StringRecord::new();
    let mut ordinal = 0u64;
    let mut have_header = false;
    loop {
        let before = rdr.position().byte() as usize;
        match rdr.read_record(&mut record) {
            Ok(false) => break,
            Ok(true) => {
                let end = trim_line_end(text, rdr.position().byte() as usize);
                let start = skip_newlines(text, before, end);
                if !have_header {
                    table.headers = record
                        .iter()
                        .map(|h| h.trim_start_matches('\u{feff}').trim().to_string())
                        .collect();
                    have_header = true;
                    continue;
                }
                table.rows.push(CsvRow {
                    ordinal,
                    span: Span { start, end },
                    fields: record.iter().map(str::to_string).collect(),
                });
                ordinal += 1;
            }
            Err(e) => {
                let end = trim_line_end(text, rdr.position().byte() as usize).max(before);
                table.errors.push(CsvRowError {
                    ordinal,
                    span: Span { start: before, end },
                    message: e.to_string(),
                });
                ordinal += 1;
                if rdr.position().byte() as usize <= before {
                    break;
                }
            }
        }
    }
    table
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
        let mut map = Map::new();
        for (i, field) in row.fields.iter().enumerate() {
            let key = match self.headers.get(i) {
                Some(h) => h.clone(),
                None => format!("_extra_{}", i - self.headers.len()),
            };
            map.insert(key, Value::String(field.clone()));
        }
        map
    }
}
