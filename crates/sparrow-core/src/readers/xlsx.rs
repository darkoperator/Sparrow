//! First-sheet reader for XLSX workbooks (Entra admin center sign-in exports saved as Excel).
//! Cells come back as the text an analyst sees; Excel date cells as ISO `yyyy-MM-ddTHH:mm:ss`.

use calamine::{Data, DataRef, ExcelDateTime, Reader, Xlsx};
use std::io::Cursor;

/// One non-blank sheet row: its 1-based row number and its cell texts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XlsxRow {
    pub row: u32,
    pub fields: Vec<String>,
}

impl XlsxRow {
    /// The row as provenance hashes it: cell texts joined by tabs.
    pub fn text(&self) -> String {
        self.fields.join("\t")
    }
}

/// The first sheet: its first non-blank row as headers, then every later non-blank row.
#[derive(Debug, Clone, Default)]
pub struct XlsxTable {
    pub headers: Vec<String>,
    pub rows: Vec<XlsxRow>,
}

type Workbook<'b> = Xlsx<Cursor<&'b [u8]>>;

fn open(bytes: &[u8]) -> Result<(Workbook<'_>, String), String> {
    let wb: Workbook<'_> =
        Xlsx::new(Cursor::new(bytes)).map_err(|e| format!("not a readable xlsx workbook: {e}"))?;
    let name = wb
        .sheet_names()
        .first()
        .cloned()
        .ok_or_else(|| "workbook has no sheet".to_string())?;
    Ok((wb, name))
}

fn float_text(f: f64) -> String {
    if f.fract() == 0.0 && f.abs() < 1e15 {
        format!("{}", f as i64)
    } else {
        f.to_string()
    }
}

fn bool_text(b: bool) -> String {
    if b { "True" } else { "False" }.to_string()
}

fn datetime_text(dt: &ExcelDateTime) -> String {
    dt.as_datetime()
        .map(|n| n.format("%Y-%m-%dT%H:%M:%S").to_string())
        .unwrap_or_default()
}

fn data_text(d: &Data) -> String {
    match d {
        Data::Empty | Data::Error(_) => String::new(),
        Data::String(s) | Data::DateTimeIso(s) | Data::DurationIso(s) => s.clone(),
        Data::Int(i) => i.to_string(),
        Data::Float(f) => float_text(*f),
        Data::Bool(b) => bool_text(*b),
        Data::DateTime(dt) => datetime_text(dt),
    }
}

fn ref_text(d: &DataRef<'_>) -> String {
    match d {
        DataRef::Empty | DataRef::Error(_) => String::new(),
        DataRef::SharedString(s) => (*s).to_string(),
        DataRef::String(s) | DataRef::DateTimeIso(s) | DataRef::DurationIso(s) => s.clone(),
        DataRef::Int(i) => i.to_string(),
        DataRef::Float(f) => float_text(*f),
        DataRef::Bool(b) => bool_text(*b),
        DataRef::DateTime(dt) => datetime_text(dt),
    }
}

/// Header row of the first sheet (its first non-blank row), read without loading the sheet.
pub fn xlsx_headers(bytes: &[u8]) -> Option<Vec<String>> {
    let (mut wb, name) = open(bytes).ok()?;
    let mut cells = wb.worksheet_cells_reader(&name).ok()?;
    let mut header_row: Option<u32> = None;
    let mut out: Vec<String> = Vec::new();
    while let Some(cell) = cells.next_cell().ok()? {
        let (row, col) = cell.get_position();
        let text = ref_text(cell.get_value());
        if text.trim().is_empty() {
            continue;
        }
        match header_row {
            None => header_row = Some(row),
            Some(h) if row != h => break,
            Some(_) => {}
        }
        let col = col as usize;
        if out.len() <= col {
            out.resize(col + 1, String::new());
        }
        out[col] = text;
    }
    (!out.is_empty()).then_some(out)
}

/// The first sheet as headers plus non-blank rows (1-based sheet row numbers).
pub fn read_xlsx(bytes: &[u8]) -> Result<XlsxTable, String> {
    let (mut wb, name) = open(bytes)?;
    let range = wb
        .worksheet_range(&name)
        .map_err(|e| format!("cannot read sheet {name}: {e}"))?;
    let first_row = range.start().map_or(0, |(r, _)| r);
    let mut table = XlsxTable::default();
    let mut have_header = false;
    for (i, cells) in range.rows().enumerate() {
        let fields: Vec<String> = cells.iter().map(data_text).collect();
        if fields.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        if !have_header {
            table.headers = fields;
            have_header = true;
            continue;
        }
        table.rows.push(XlsxRow {
            row: first_row + i as u32 + 1,
            fields,
        });
    }
    Ok(table)
}
