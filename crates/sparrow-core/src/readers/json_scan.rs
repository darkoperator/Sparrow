//! Scanner for PowerShell-produced JSON: bare objects, arrays, and several documents
//! concatenated in one file (Hawk `-append`, Extractor Suite same-second pages, JSONL).
//! Each record keeps the exact span of its source text.

use crate::readers::text::Span;
use serde_json::Value;

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

struct Scanner<'t, F> {
    text: &'t str,
    ordinal: u64,
    sink: F,
    /// The sink asked to stop.
    stopped: bool,
}

impl<F: FnMut(JsonEvent) -> bool> Scanner<'_, F> {
    fn emit(&mut self, event: JsonEvent) {
        if !(self.sink)(event) {
            self.stopped = true;
        }
    }

    fn push(&mut self, start: usize, end: usize) {
        let span = Span { start, end };
        let event = match serde_json::from_str::<Value>(&self.text[start..end]) {
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
        self.emit(event);
    }

    fn fail(&mut self, start: usize, message: String) {
        let span = Span {
            start,
            end: self.text.len(),
        };
        let event = JsonEvent::Error(JsonRecordError {
            ordinal: self.ordinal,
            span,
            message,
        });
        self.ordinal += 1;
        self.emit(event);
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
pub fn scan_json_each(text: &str, sink: impl FnMut(JsonEvent) -> bool) -> JsonShape {
    let b = text.as_bytes();
    let mut sc = Scanner {
        text,
        ordinal: 0,
        sink,
        stopped: false,
    };
    let mut pos = 0usize;
    let mut docs = 0usize;
    let mut first_is_array = false;

    'docs: loop {
        pos = skip(b, pos, true);
        if pos >= b.len() || sc.stopped {
            break;
        }
        docs += 1;
        if b[pos] == b'[' {
            if docs == 1 {
                first_is_array = true;
            }
            pos += 1;
            loop {
                if sc.stopped {
                    break 'docs;
                }
                pos = skip(b, pos, false);
                if pos >= b.len() {
                    sc.fail(
                        pos,
                        "unexpected end of input inside array (truncated file?)".into(),
                    );
                    break 'docs;
                }
                if b[pos] == b']' {
                    pos += 1;
                    break;
                }
                match value_end(b, pos) {
                    Ok(end) => {
                        sc.push(pos, end);
                        pos = end;
                    }
                    Err(msg) => {
                        sc.fail(pos, msg);
                        break 'docs;
                    }
                }
                if sc.stopped {
                    break 'docs;
                }
                pos = skip(b, pos, false);
                match b.get(pos) {
                    Some(b',') => pos += 1,
                    Some(b']') => {
                        pos += 1;
                        break;
                    }
                    Some(_) => {
                        sc.fail(pos, "expected ',' or ']' in array".into());
                        break 'docs;
                    }
                    None => {
                        sc.fail(
                            pos,
                            "unexpected end of input inside array (truncated file?)".into(),
                        );
                        break 'docs;
                    }
                }
            }
        } else {
            match value_end(b, pos) {
                Ok(end) => {
                    sc.push(pos, end);
                    pos = end;
                }
                Err(msg) => {
                    sc.fail(pos, msg);
                    break;
                }
            }
        }
    }

    match docs {
        0 => JsonShape::Empty,
        1 if first_is_array => JsonShape::Array,
        1 => JsonShape::SingleObject,
        _ => JsonShape::Concatenated,
    }
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
