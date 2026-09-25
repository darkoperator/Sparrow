//! Decoding of collector files (UTF-8 ± BOM, UTF-16, Windows-1252) with exact mapping
//! from decoded text positions back to physical lines and raw byte offsets.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TextEncoding {
    #[serde(rename = "utf-8")]
    Utf8,
    #[serde(rename = "utf-8-bom")]
    Utf8Bom,
    #[serde(rename = "utf-16le")]
    Utf16Le,
    #[serde(rename = "utf-16be")]
    Utf16Be,
    #[serde(rename = "windows-1252")]
    Windows1252,
}

impl TextEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            TextEncoding::Utf8 => "utf-8",
            TextEncoding::Utf8Bom => "utf-8-bom",
            TextEncoding::Utf16Le => "utf-16le",
            TextEncoding::Utf16Be => "utf-16be",
            TextEncoding::Windows1252 => "windows-1252",
        }
    }

    /// Number of raw bytes `c` occupies in this encoding.
    fn encoded_len(self, c: char) -> u64 {
        match self {
            TextEncoding::Utf8 | TextEncoding::Utf8Bom => c.len_utf8() as u64,
            TextEncoding::Utf16Le | TextEncoding::Utf16Be => (c.len_utf16() * 2) as u64,
            TextEncoding::Windows1252 => 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecodedText {
    pub text: String,
    pub encoding: TextEncoding,
    /// Bytes of byte-order mark preceding the text in the raw file.
    pub bom_len: u64,
    /// True when decoding replaced invalid input (e.g. a truncated UTF-16 code unit) or
    /// invalid UTF-8 forced the Windows-1252 fallback.
    pub lossy: bool,
}

impl DecodedText {
    /// Empty text for binary files (XLSX) that parsers read from the raw bytes.
    pub fn binary() -> DecodedText {
        DecodedText {
            text: String::new(),
            encoding: TextEncoding::Utf8,
            bom_len: 0,
            lossy: false,
        }
    }

    /// Warning to record on the file when decoding was lossy.
    pub fn lossy_warning(&self) -> Option<String> {
        if !self.lossy {
            return None;
        }
        let why = match self.encoding {
            TextEncoding::Windows1252 => "windows-1252 fallback",
            TextEncoding::Utf16Le | TextEncoding::Utf16Be => "invalid utf-16",
            TextEncoding::Utf8 | TextEncoding::Utf8Bom => "invalid utf-8",
        };
        Some(format!("text decoding was lossy ({why})"))
    }
}

pub fn decode(bytes: &[u8]) -> DecodedText {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return match std::str::from_utf8(rest) {
            Ok(s) => DecodedText {
                text: s.to_string(),
                encoding: TextEncoding::Utf8Bom,
                bom_len: 3,
                lossy: false,
            },
            Err(_) => windows_1252(rest, 3),
        };
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(rest, TextEncoding::Utf16Le, 2);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return utf16(rest, TextEncoding::Utf16Be, 2);
    }
    if looks_like_bomless_utf16le(bytes) {
        return utf16(bytes, TextEncoding::Utf16Le, 0);
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => DecodedText {
            text: s.to_string(),
            encoding: TextEncoding::Utf8,
            bom_len: 0,
            lossy: false,
        },
        Err(_) => windows_1252(bytes, 0),
    }
}

fn utf16(bytes: &[u8], encoding: TextEncoding, bom_len: u64) -> DecodedText {
    let codec = if encoding == TextEncoding::Utf16Le {
        encoding_rs::UTF_16LE
    } else {
        encoding_rs::UTF_16BE
    };
    let (text, had_errors) = codec.decode_without_bom_handling(bytes);
    DecodedText {
        text: text.into_owned(),
        encoding,
        bom_len,
        lossy: had_errors,
    }
}

/// Fallback used only when the bytes are not valid UTF-8, so the result is always lossy:
/// the bytes are guessed to be Windows-1252.
fn windows_1252(bytes: &[u8], bom_len: u64) -> DecodedText {
    let (text, _had_errors) = encoding_rs::WINDOWS_1252.decode_without_bom_handling(bytes);
    DecodedText {
        text: text.into_owned(),
        encoding: TextEncoding::Windows1252,
        bom_len,
        lossy: true,
    }
}

fn looks_like_bomless_utf16le(b: &[u8]) -> bool {
    if b.len() < 4 || b.len() % 2 != 0 {
        return false;
    }
    let n = b.len().min(256) / 2;
    let zeros_odd = (0..n).filter(|i| b[2 * i + 1] == 0).count();
    let zeros_even = (0..n).filter(|i| b[2 * i] == 0).count();
    zeros_odd * 10 >= n * 9 && zeros_even * 10 <= n
}

/// Decoded-text byte range, end exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// Where a record lives in the original file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourcePos {
    pub line_start: u32,
    pub line_end: u32,
    pub byte_offset: u64,
    pub byte_length: u64,
}

/// Start offsets of every physical line (lines end at `\n`).
#[derive(Debug, Clone)]
pub struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    pub fn new(text: &str) -> Self {
        let mut starts = vec![0];
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' && i + 1 < text.len() {
                starts.push(i + 1);
            }
        }
        LineIndex { starts }
    }

    /// 1-based line containing decoded byte `offset`.
    pub fn line_of(&self, offset: usize) -> u32 {
        let i = match self.starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        (i + 1) as u32
    }

    pub fn line_count(&self) -> usize {
        self.starts.len()
    }

    /// Text of lines `start_line..=end_line` (1-based) without the final line terminator.
    pub fn line_text<'t>(&self, text: &'t str, start_line: u32, end_line: u32) -> &'t str {
        let first = (start_line.max(1) as usize - 1).min(self.starts.len() - 1);
        let s = self.starts[first];
        let e = self
            .starts
            .get(end_line as usize)
            .copied()
            .unwrap_or(text.len());
        text[s..e.max(s)].trim_end_matches(['\r', '\n'])
    }
}

/// Maps decoded offsets to raw file offsets. Queries should move forward; moving
/// backwards restarts the scan from the beginning. Offsets never exceed the raw length:
/// a replacement character for a truncated trailing code unit stands for fewer raw bytes
/// than a full code unit.
#[derive(Debug, Clone)]
pub struct OffsetMapper {
    encoding: TextEncoding,
    bom_len: u64,
    raw_len: u64,
    cur_dec: usize,
    cur_raw: u64,
}

impl OffsetMapper {
    /// `raw_len` is the length of the raw file `decoded` was decoded from.
    pub fn new(decoded: &DecodedText, raw_len: u64) -> Self {
        OffsetMapper {
            encoding: decoded.encoding,
            bom_len: decoded.bom_len,
            raw_len,
            cur_dec: 0,
            cur_raw: decoded.bom_len,
        }
    }

    /// Raw byte offset of decoded byte offset `decoded` (must be a char boundary of `text`).
    pub fn raw_offset(&mut self, text: &str, decoded: usize) -> u64 {
        self.unclamped_raw_offset(text, decoded).min(self.raw_len)
    }

    fn unclamped_raw_offset(&mut self, text: &str, decoded: usize) -> u64 {
        if matches!(self.encoding, TextEncoding::Utf8 | TextEncoding::Utf8Bom) {
            return self.bom_len + decoded as u64;
        }
        if decoded < self.cur_dec {
            self.cur_dec = 0;
            self.cur_raw = self.bom_len;
        }
        let enc = self.encoding;
        self.cur_raw += text[self.cur_dec..decoded]
            .chars()
            .map(|c| enc.encoded_len(c))
            .sum::<u64>();
        self.cur_dec = decoded;
        self.cur_raw
    }
}

pub fn locate(text: &str, index: &LineIndex, mapper: &mut OffsetMapper, span: Span) -> SourcePos {
    let line_start = index.line_of(span.start);
    let last = if span.end > span.start {
        span.end - 1
    } else {
        span.start
    };
    let line_end = index.line_of(last);
    let raw_start = mapper.raw_offset(text, span.start);
    let raw_end = mapper.raw_offset(text, span.end);
    SourcePos {
        line_start,
        line_end,
        byte_offset: raw_start,
        byte_length: raw_end - raw_start,
    }
}

/// True when `raw` holds nothing but an optional byte-order mark plus whitespace: what
/// Export-Csv and Out-File write when given zero objects (0 bytes on PowerShell 7, a bare
/// BOM on Windows PowerShell 5.1). NUL bytes count as blank only after a UTF-16 BOM (the
/// high byte of UTF-16 whitespace); an all-NUL file without one is corrupt, not empty.
pub fn is_blank_content(raw: &[u8]) -> bool {
    let (body, utf16) = match raw {
        [0xFF, 0xFE, rest @ ..] | [0xFE, 0xFF, rest @ ..] => (rest, true),
        [0xEF, 0xBB, 0xBF, rest @ ..] => (rest, false),
        _ => (raw, false),
    };
    body.iter()
        .all(|&b| matches!(b, b' ' | b'\t' | b'\r' | b'\n') || (utf16 && b == 0))
}

/// Every physical line as a span excluding its `\r\n` / `\n` terminator.
pub fn line_spans(text: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let trimmed = line.trim_end_matches(['\r', '\n']);
        spans.push(Span {
            start,
            end: start + trimmed.len(),
        });
    }
    spans
}
