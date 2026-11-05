//! Streamed reading of collector text files, for files too large to hold whole.
//!
//! [`admit`] reads a file once: its SHA-256, its head, whether it is blank, and the encoding decision
//! [`decode`](super::text::decode) would make on the whole file (including the Windows-1252 fallback when the whole
//! file is not valid UTF-8, and whether decoding is lossy). [`Admitted::open`] then starts a pass that decodes the
//! file a chunk at a time into a [`TextStream`] window. Offsets in spans are absolute decoded offsets, the same
//! numbers the whole-text path produces, and [`TextStream::sight`] gives the same [`SourcePos`] as
//! [`locate`](super::text::locate) plus the hash of the record's raw bytes.

use super::text::{SourcePos, Span, TextEncoding, is_blank_content, looks_like_bomless_utf16le};
use crate::discovery::SNIFF_BYTES;
use crate::hash::{Sha256Stream, sha256_hex};
use encoding_rs::{CoderResult, Decoder};
use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Raw bytes read per [`TextStream::fill`] (and per read of [`admit`]) in production.
pub const CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// Called with raw bytes read since the last call; return false to stop (the read fails with ErrorKind::Interrupted).
pub type OnRead<'a> = &'a mut dyn FnMut(u64) -> bool;

/// Decoded bytes between two sighting checkpoints, as in `OffsetMapper`.
const CHECKPOINT_EVERY: usize = 64 * 1024;

/// Raw bytes the encoding decision looks at: a BOM in the first three, the bomless UTF-16LE test in the first 256.
const DECIDE_BYTES: usize = 256;

/// Longest `parse_errors.raw_snippet`, in chars.
const SNIPPET_CHARS: usize = 500;

/// A file read once by [`admit`]: what ingest records about it and how its text is decoded.
#[derive(Debug, Clone)]
pub struct Admitted {
    pub path: PathBuf,
    pub raw_len: u64,
    pub modified: Option<SystemTime>,
    pub sha256: String,
    pub blank: bool,
    /// First [`SNIFF_BYTES`] raw bytes.
    pub head: Vec<u8>,
    pub encoding: TextEncoding,
    pub bom_len: u64,
    pub lossy: bool,
}

/// Where a record lives in the original file and the SHA-256 of its raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sight {
    pub pos: SourcePos,
    pub raw_sha256: String,
}

fn interrupted() -> io::Error {
    io::Error::new(ErrorKind::Interrupted, "read stopped")
}

fn changed() -> io::Error {
    io::Error::new(
        ErrorKind::InvalidData,
        "file is no longer valid UTF-8: it changed since it was admitted",
    )
}

/// Read until `buf` is full or the reader is exhausted, reporting each read to `on_read`. Fewer bytes than
/// `buf.len()` means the end of the input was reached.
fn read_chunk(r: &mut dyn Read, buf: &mut [u8], on_read: OnRead) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => {
                n += k;
                if !on_read(k as u64) {
                    return Err(interrupted());
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Length of the UTF-8 sequence a lead byte starts (1 for anything that is not a multi-byte lead).
fn utf8_width(b: u8) -> usize {
    match b {
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

/// Incremental UTF-8 validation: an incomplete sequence at the end of one piece is completed by the next, so the
/// pieces are valid exactly when their concatenation is.
#[derive(Default)]
struct Utf8Carry {
    buf: [u8; 4],
    len: usize,
}

impl Utf8Carry {
    /// Validate `bytes`, passing each valid run to `push`. `Err` when the input is not UTF-8.
    fn feed(&mut self, mut bytes: &[u8], mut push: impl FnMut(&str)) -> Result<(), ()> {
        if self.len > 0 {
            let need = utf8_width(self.buf[0]);
            let take = (need - self.len).min(bytes.len());
            self.buf[self.len..self.len + take].copy_from_slice(&bytes[..take]);
            self.len += take;
            bytes = &bytes[take..];
            if self.len < need {
                return Ok(());
            }
            push(std::str::from_utf8(&self.buf[..need]).map_err(|_| ())?);
            self.len = 0;
        }
        // Hold back a multi-byte sequence the piece cuts off.
        let mut cut = bytes.len();
        for back in 1..=3.min(bytes.len()) {
            let i = bytes.len() - back;
            if bytes[i] & 0xC0 != 0x80 {
                if i + utf8_width(bytes[i]) > bytes.len() {
                    cut = i;
                }
                break;
            }
        }
        push(std::str::from_utf8(&bytes[..cut]).map_err(|_| ())?);
        let tail = &bytes[cut..];
        self.buf[..tail.len()].copy_from_slice(tail);
        self.len = tail.len();
        Ok(())
    }

    /// True when no sequence is left incomplete.
    fn complete(&self) -> bool {
        self.len == 0
    }
}

/// Whether an `encoding_rs` decode of all the bytes fed would report errors, without keeping its output.
struct ErrorCheck {
    decoder: Decoder,
    scratch: Vec<u8>,
    errors: bool,
}

impl ErrorCheck {
    fn new(decoder: Decoder) -> Self {
        ErrorCheck {
            decoder,
            scratch: vec![0; 64 * 1024],
            errors: false,
        }
    }

    fn feed(&mut self, mut src: &[u8], last: bool) {
        loop {
            let (res, read, _written, had_errors) =
                self.decoder.decode_to_utf8(src, &mut self.scratch, last);
            self.errors |= had_errors;
            src = &src[read..];
            if res == CoderResult::InputEmpty {
                break;
            }
        }
    }
}

/// [`is_blank_content`] over a file fed in pieces: decided once its first three bytes are known.
#[derive(Default)]
struct BlankCheck {
    prefix: Vec<u8>,
    utf16: Option<bool>,
    blank: bool,
}

impl BlankCheck {
    fn blank_byte(b: u8, utf16: bool) -> bool {
        matches!(b, b' ' | b'\t' | b'\r' | b'\n') || (utf16 && b == 0)
    }

    fn feed(&mut self, mut bytes: &[u8]) {
        if self.utf16.is_none() {
            let take = (3 - self.prefix.len()).min(bytes.len());
            self.prefix.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.prefix.len() < 3 {
                return;
            }
            let (body, is16): (&[u8], bool) = match self.prefix.as_slice() {
                [0xFF, 0xFE, r @ ..] | [0xFE, 0xFF, r @ ..] => (r, true),
                [0xEF, 0xBB, 0xBF] => (&[], false),
                p => (p, false),
            };
            self.utf16 = Some(is16);
            self.blank = body.iter().all(|&b| Self::blank_byte(b, is16));
        }
        if self.blank {
            let is16 = self.utf16.unwrap_or(false);
            self.blank = bytes.iter().all(|&b| Self::blank_byte(b, is16));
        }
    }

    fn finish(&self) -> bool {
        match self.utf16 {
            Some(_) => self.blank,
            // Fewer than three bytes in all.
            None => is_blank_content(&self.prefix),
        }
    }
}

/// The encoding decision of `decode`, made over a file fed in pieces. Created from the first [`DECIDE_BYTES`]
/// bytes (or the whole file, when shorter) and fed every byte from the start.
enum Analyzer {
    /// `EF BB BF`: UTF-8 with BOM if the rest is valid UTF-8, else Windows-1252 after the BOM.
    Utf8Signed(Utf8Carry, bool),
    /// `FF FE` / `FE FF`: UTF-16 after the BOM; `skip` counts BOM bytes not yet passed.
    Utf16Signed {
        encoding: TextEncoding,
        check: ErrorCheck,
        skip: usize,
    },
    /// No BOM: bomless UTF-16LE if `candidate` (the zero-byte pattern held) and the length suits, else UTF-8 or
    /// Windows-1252.
    Unsigned {
        utf8: Utf8Carry,
        utf8_ok: bool,
        candidate: Option<ErrorCheck>,
        whole: bool,
    },
}

impl Analyzer {
    /// `first` is `min(DECIDE_BYTES, len)` bytes of the file; `whole` says it is the whole file.
    fn new(first: &[u8], whole: bool) -> Self {
        if first.starts_with(&[0xEF, 0xBB, 0xBF]) {
            return Analyzer::Utf8Signed(Utf8Carry::default(), true);
        }
        let utf16 = |encoding: TextEncoding| {
            let codec = if encoding == TextEncoding::Utf16Le {
                encoding_rs::UTF_16LE
            } else {
                encoding_rs::UTF_16BE
            };
            Analyzer::Utf16Signed {
                encoding,
                check: ErrorCheck::new(codec.new_decoder_without_bom_handling()),
                skip: 2,
            }
        };
        if first.starts_with(&[0xFF, 0xFE]) {
            return utf16(TextEncoding::Utf16Le);
        }
        if first.starts_with(&[0xFE, 0xFF]) {
            return utf16(TextEncoding::Utf16Be);
        }
        // With the whole file this is `decode`'s test; with its first 256 bytes, the zero-byte pattern only (the
        // length test is applied at the end).
        let candidate = looks_like_bomless_utf16le(first)
            .then(|| ErrorCheck::new(encoding_rs::UTF_16LE.new_decoder_without_bom_handling()));
        Analyzer::Unsigned {
            utf8: Utf8Carry::default(),
            utf8_ok: true,
            candidate,
            whole,
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        match self {
            Analyzer::Utf8Signed(carry, ok) => {
                // The BOM is itself a complete UTF-8 character: the rest is valid exactly when all of it is.
                if *ok {
                    *ok = carry.feed(bytes, |_| ()).is_ok();
                }
            }
            Analyzer::Utf16Signed { check, skip, .. } => {
                let k = (*skip).min(bytes.len());
                *skip -= k;
                check.feed(&bytes[k..], false);
            }
            Analyzer::Unsigned {
                utf8,
                utf8_ok,
                candidate,
                ..
            } => {
                if *utf8_ok {
                    *utf8_ok = utf8.feed(bytes, |_| ()).is_ok();
                }
                if let Some(c) = candidate {
                    c.feed(bytes, false);
                }
            }
        }
    }

    /// (encoding, bom_len, lossy) for a file of `raw_len` bytes.
    fn finish(self, raw_len: u64) -> (TextEncoding, u64, bool) {
        match self {
            Analyzer::Utf8Signed(carry, ok) => {
                if ok && carry.complete() {
                    (TextEncoding::Utf8Bom, 3, false)
                } else {
                    (TextEncoding::Windows1252, 3, true)
                }
            }
            Analyzer::Utf16Signed {
                encoding,
                mut check,
                ..
            } => {
                check.feed(&[], true);
                (encoding, 2, check.errors)
            }
            Analyzer::Unsigned {
                utf8,
                utf8_ok,
                candidate,
                whole,
            } => {
                if let Some(mut c) = candidate
                    && (whole || raw_len % 2 == 0)
                {
                    c.feed(&[], true);
                    return (TextEncoding::Utf16Le, 0, c.errors);
                }
                if utf8_ok && utf8.complete() {
                    (TextEncoding::Utf8, 0, false)
                } else {
                    (TextEncoding::Windows1252, 0, true)
                }
            }
        }
    }
}

/// Read `path` once in reads of up to `chunk` bytes: hash, head, blank flag and the encoding decision `decode`
/// would make on the whole file. Memory stays at a chunk plus the head whatever the file size.
pub fn admit(path: &Path, chunk: usize, on_read: OnRead) -> io::Result<Admitted> {
    let mut file = File::open(path)?;
    let modified = file.metadata()?.modified().ok();
    admit_from(&mut file, path, modified, chunk, on_read)
}

/// [`admit`] reading the content from `reader`; `modified` is the file's modification time when it was opened.
pub fn admit_from(
    reader: &mut dyn Read,
    path: &Path,
    modified: Option<SystemTime>,
    chunk: usize,
    on_read: OnRead,
) -> io::Result<Admitted> {
    admit_from_with_head(reader, path, modified, chunk, on_read, &mut |_| {})
}

/// [`admit_from`], calling `on_head` once with the head (the first [`SNIFF_BYTES`], or the whole of a shorter file)
/// as soon as it has been read, before the rest of the file is: the file can be classified while it is still being
/// hashed. A read error or a cancel before the head is complete never calls it.
pub fn admit_from_with_head(
    reader: &mut dyn Read,
    path: &Path,
    modified: Option<SystemTime>,
    chunk: usize,
    on_read: OnRead,
    on_head: &mut dyn FnMut(&[u8]),
) -> io::Result<Admitted> {
    let mut head_told = false;
    let mut buf = vec![0u8; chunk.max(1)];
    let mut hash = Sha256Stream::new();
    let mut blank = BlankCheck::default();
    let mut head: Vec<u8> = Vec::new();
    let mut analyzer: Option<Analyzer> = None;
    let mut raw_len = 0u64;
    loop {
        let n = read_chunk(reader, &mut buf, &mut *on_read)?;
        let bytes = &buf[..n];
        hash.update(bytes);
        blank.feed(bytes);
        raw_len += n as u64;
        let take = (SNIFF_BYTES - head.len().min(SNIFF_BYTES)).min(n);
        head.extend_from_slice(&bytes[..take]);
        if !head_told && (head.len() >= SNIFF_BYTES || n < buf.len()) {
            head_told = true;
            on_head(&head);
        }
        match &mut analyzer {
            Some(a) => a.feed(bytes),
            None if head.len() >= DECIDE_BYTES => {
                let mut a = Analyzer::new(&head[..DECIDE_BYTES], false);
                // Every byte so far: those in the head, then any of this read past it.
                a.feed(&head);
                a.feed(&bytes[take..]);
                analyzer = Some(a);
            }
            None => {}
        }
        if n < buf.len() {
            break;
        }
    }
    let analyzer = analyzer.unwrap_or_else(|| {
        // The whole file is shorter than DECIDE_BYTES and sits in the head.
        let mut a = Analyzer::new(&head, true);
        a.feed(&head);
        a
    });
    let (encoding, bom_len, lossy) = analyzer.finish(raw_len);
    Ok(Admitted {
        path: path.to_path_buf(),
        raw_len,
        modified,
        sha256: hash.finish_hex(),
        blank: blank.finish(),
        head,
        encoding,
        bom_len,
        lossy,
    })
}

fn decoder_for(encoding: TextEncoding) -> Option<Decoder> {
    let codec = match encoding {
        TextEncoding::Utf8 | TextEncoding::Utf8Bom => return None,
        TextEncoding::Utf16Le => encoding_rs::UTF_16LE,
        TextEncoding::Utf16Be => encoding_rs::UTF_16BE,
        TextEncoding::Windows1252 => encoding_rs::WINDOWS_1252,
    };
    Some(codec.new_decoder_without_bom_handling())
}

/// Most decoded bytes one fill of `raw` bytes can add: a UTF-8 char held back from the last fill, or the decoder's
/// bound.
fn text_growth(decoder: Option<&Decoder>, raw: usize) -> usize {
    match decoder {
        None => raw + 3,
        Some(d) => d.max_utf8_buffer_length(raw).unwrap_or(raw * 3 + 16),
    }
}

/// The `reserve_exact` that gives room for `grow` more bytes: geometric growth as `Vec` does, but stopping at
/// `steady` while the need fits under it, so the steady state is one allocation of that size rather than up to
/// twice it. `None` when there is room, or when the need is past `steady` (an outsized record: plain growth).
fn reserve_for(cap: usize, len: usize, grow: usize, steady: usize) -> Option<usize> {
    let need = len + grow;
    if need <= cap || need > steady {
        return None;
    }
    Some((2 * cap).max(need).min(steady) - len)
}

/// Decode `src` into `out` with `decoder`, `last` flushing what it holds back.
fn decode_into(decoder: &mut Decoder, mut src: &[u8], out: &mut String, last: bool) {
    loop {
        let need = decoder
            .max_utf8_buffer_length(src.len())
            .unwrap_or(src.len() * 3 + 16);
        out.reserve(need);
        let (res, read, _had_errors) = decoder.decode_to_string(src, out, last);
        src = &src[read..];
        if res == CoderResult::InputEmpty {
            break;
        }
    }
}

impl Admitted {
    /// What [`admit`] gives for the file at `path` whose content is `raw`, already read into memory: everything is
    /// computed from `raw`, only the modification time comes from `path` (`None` when it cannot be read).
    pub fn from_bytes(path: &Path, raw: &[u8]) -> Admitted {
        let modified = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
        Admitted::from_bytes_at(path, raw, modified)
    }

    /// [`from_bytes`](Self::from_bytes) with the modification time `modified` the file had before `raw` was read
    /// (so a file rewritten during the read is not [`unchanged`](Self::unchanged)).
    pub fn from_bytes_at(path: &Path, raw: &[u8], modified: Option<SystemTime>) -> Admitted {
        // One read takes it all: the result does not depend on the read size.
        let chunk = CHUNK_BYTES.min(raw.len() + 1);
        admit_from(
            &mut io::Cursor::new(raw),
            path,
            modified,
            chunk,
            &mut |_| true,
        )
        .expect("reading from memory cannot fail")
    }

    /// A new pass over the file from byte 0, reading `chunk` bytes per fill.
    pub fn open(&self, chunk: usize) -> io::Result<TextStream> {
        let file = File::open(&self.path)?;
        Ok(TextStream::new(Box::new(file), self, chunk))
    }

    /// The head decoded with the admitted encoding, for sniffs. When the head is not the whole file, a character it
    /// cuts off is dropped.
    pub fn head_text(&self) -> String {
        let whole = self.head.len() as u64 >= self.raw_len;
        let body = &self.head[(self.bom_len as usize).min(self.head.len())..];
        match decoder_for(self.encoding) {
            None => match std::str::from_utf8(body) {
                Ok(s) => s.to_string(),
                Err(e) if !whole && e.error_len().is_none() => {
                    String::from_utf8_lossy(&body[..e.valid_up_to()]).into_owned()
                }
                Err(_) => String::from_utf8_lossy(body).into_owned(),
            },
            Some(mut decoder) => {
                let mut out = String::new();
                decode_into(&mut decoder, body, &mut out, whole);
                out
            }
        }
    }

    /// True when the file's size and modification time are still those seen at admission.
    pub fn unchanged(&self) -> io::Result<bool> {
        let m = std::fs::metadata(&self.path)?;
        Ok(m.len() == self.raw_len && m.modified().ok() == self.modified)
    }
}

/// A scan position: decoded offset, raw offset (unclamped), and `\n` count in the text before it.
#[derive(Debug, Clone, Copy)]
struct Mark {
    dec: usize,
    raw: u64,
    nl: u64,
}

/// A pass over an admitted file: a window of decoded text that [`TextStream::fill`] extends at the end and
/// [`TextStream::consume`] shrinks at the start. Spans are absolute decoded offsets.
pub struct TextStream {
    reader: Box<dyn Read>,
    buf: Vec<u8>,
    encoding: TextEncoding,
    bom_len: u64,
    raw_len: u64,
    /// BOM bytes not yet passed.
    skip: usize,
    utf8: Utf8Carry,
    decoder: Option<Decoder>,
    eof: bool,
    /// Decoded text from absolute offset `text_base`; the window is its part from `base`. Text before `base` is
    /// kept only back to the first checkpoint, so sightings can rescan from it.
    text: String,
    text_base: usize,
    base: usize,
    /// Raw bytes read, from raw offset `raw_base` (the first checkpoint's).
    raw: Vec<u8>,
    raw_base: u64,
    /// The last decoded char is `\n` (decides the line of the end-of-text offset, as `LineIndex` does).
    ends_nl: bool,
    cur: Mark,
    /// Ascending; the first is at or before `base`.
    checkpoints: Vec<Mark>,
    /// Capacities of `text` and `raw` that hold the steady state: what compaction keeps (up to a checkpoint
    /// interval, plus a char of slack) and one fill.
    steady: (usize, usize),
    /// The span [`TextStream::sight_to_end`] drained, its sighting and snippet.
    drained: Option<(Span, Sight, String)>,
    /// Largest capacities of `text` and `raw` seen after a fill.
    #[cfg(test)]
    peak: (usize, usize),
}

impl TextStream {
    fn new(reader: Box<dyn Read>, admitted: &Admitted, chunk: usize) -> TextStream {
        let chunk = chunk.max(1);
        let decoder = decoder_for(admitted.encoding);
        let kept = CHECKPOINT_EVERY + 8;
        let raw_per_byte = match admitted.encoding {
            TextEncoding::Utf16Le | TextEncoding::Utf16Be => 2,
            _ => 1,
        };
        let steady = (
            kept + text_growth(decoder.as_ref(), chunk),
            chunk + raw_per_byte * kept,
        );
        let start = Mark {
            dec: 0,
            raw: admitted.bom_len,
            nl: 0,
        };
        TextStream {
            reader,
            buf: vec![0; chunk],
            encoding: admitted.encoding,
            bom_len: admitted.bom_len,
            raw_len: admitted.raw_len,
            skip: admitted.bom_len as usize,
            utf8: Utf8Carry::default(),
            decoder,
            eof: false,
            text: String::new(),
            text_base: 0,
            base: 0,
            raw: Vec::new(),
            raw_base: 0,
            ends_nl: false,
            cur: start,
            checkpoints: vec![start],
            steady,
            drained: None,
            #[cfg(test)]
            peak: (0, 0),
        }
    }

    /// A pass over the admitted file's content read from `reader` (from its first byte); behaves exactly like
    /// [`Admitted::open`].
    pub fn from_reader(reader: Box<dyn Read>, admitted: &Admitted, chunk: usize) -> TextStream {
        TextStream::new(reader, admitted, chunk)
    }

    /// A pass over `bytes` (the admitted file's content) held in memory; behaves exactly like [`Admitted::open`].
    pub fn from_bytes(bytes: Vec<u8>, admitted: &Admitted, chunk: usize) -> TextStream {
        TextStream::new(Box::new(io::Cursor::new(bytes)), admitted, chunk)
    }

    /// Decoded text starting at [`TextStream::base`].
    pub fn window(&self) -> &str {
        &self.text[self.base - self.text_base..]
    }

    /// Absolute decoded offset of `window()[0]`.
    pub fn base(&self) -> usize {
        self.base
    }

    /// True once the whole file has been read and decoded into the window.
    pub fn at_eof(&self) -> bool {
        self.eof
    }

    fn end(&self) -> usize {
        self.text_base + self.text.len()
    }

    /// Append the next chunk (or everything left) to the window. `Ok(false)` only when nothing was left.
    pub fn fill(&mut self, on_read: OnRead) -> io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        self.compact();
        let n = read_chunk(&mut *self.reader, &mut self.buf, on_read)?;
        let last = n < self.buf.len();
        let before = self.text.len();
        if let Some(extra) = reserve_for(self.raw.capacity(), self.raw.len(), n, self.steady.1) {
            self.raw.reserve_exact(extra);
        }
        self.raw.extend_from_slice(&self.buf[..n]);
        let mut bytes = &self.buf[..n];
        let k = self.skip.min(bytes.len());
        self.skip -= k;
        bytes = &bytes[k..];
        let grow = text_growth(self.decoder.as_ref(), bytes.len());
        if let Some(extra) = reserve_for(self.text.capacity(), self.text.len(), grow, self.steady.0)
        {
            self.text.reserve_exact(extra);
        }
        let text = &mut self.text;
        match &mut self.decoder {
            None => {
                self.utf8
                    .feed(bytes, |s| text.push_str(s))
                    .map_err(|_| changed())?;
                if last && !self.utf8.complete() {
                    return Err(changed());
                }
            }
            Some(decoder) => decode_into(decoder, bytes, text, last),
        }
        if self.text.len() > before {
            self.ends_nl = self.text.ends_with('\n');
        }
        self.eof = last;
        #[cfg(test)]
        {
            self.peak.0 = self.peak.0.max(self.text.capacity());
            self.peak.1 = self.peak.1.max(self.raw.capacity());
        }
        Ok(n > 0 || self.text.len() > before)
    }

    /// Drop the window's text before absolute decoded offset `upto` (clamped to the window; a char boundary).
    pub fn consume(&mut self, upto: usize) {
        self.base = upto.clamp(self.base, self.end());
    }

    /// Drop text and raw bytes no sighting can need any more: everything before the last checkpoint at or before
    /// `base`, after moving the scan up to `base` so that checkpoint is close.
    fn compact(&mut self) {
        if self.cur.dec < self.base {
            self.scan_to(self.base);
        }
        let i = self.checkpoints.partition_point(|c| c.dec <= self.base) - 1;
        self.checkpoints.drain(..i);
        let first = self.checkpoints[0];
        if first.dec > self.text_base {
            self.text.drain(..first.dec - self.text_base);
            self.text_base = first.dec;
        }
        let raw_cut = first.raw.min(self.raw_base + self.raw.len() as u64);
        if raw_cut > self.raw_base {
            self.raw.drain(..(raw_cut - self.raw_base) as usize);
            self.raw_base = raw_cut;
        }
        // After a record far larger than a chunk, give back what the steady state (a chunk plus a checkpoint
        // interval) does not need.
        let (text, raw) = self.steady;
        if self.text.capacity() > 2 * text && self.text.len() <= text {
            self.text.shrink_to(text);
        }
        if self.raw.capacity() > 2 * raw && self.raw.len() <= raw {
            self.raw.shrink_to(raw);
        }
    }

    /// Move the scan to decoded offset `target` (a char boundary in the kept text), from the cursor or, going back,
    /// from the nearest checkpoint before it.
    fn scan_to(&mut self, target: usize) -> Mark {
        if target < self.cur.dec {
            let i = self.checkpoints.partition_point(|c| c.dec <= target) - 1;
            self.cur = self.checkpoints[i];
        }
        let tb = self.text_base;
        match self.encoding {
            TextEncoding::Utf8 | TextEncoding::Utf8Bom => {
                let bytes = self.text.as_bytes();
                while self.cur.dec < target {
                    let next = self.checkpoints.last().map_or(0, |c| c.dec) + CHECKPOINT_EVERY;
                    let stop = if next > self.cur.dec && next < target {
                        // A checkpoint is a char boundary (the kept text is cut there); `target` is one.
                        let mut b = next;
                        while !self.text.is_char_boundary(b - tb) {
                            b += 1;
                        }
                        b
                    } else {
                        target
                    };
                    let nl = bytes[self.cur.dec - tb..stop - tb]
                        .iter()
                        .filter(|&&b| b == b'\n')
                        .count();
                    self.cur.nl += nl as u64;
                    self.cur.dec = stop;
                    self.cur.raw = self.bom_len + stop as u64;
                    if stop >= next && stop > self.checkpoints.last().map_or(0, |c| c.dec) {
                        self.checkpoints.push(self.cur);
                    }
                }
            }
            enc => {
                let mut last = self.checkpoints.last().map_or(0, |c| c.dec);
                for c in self.text[self.cur.dec - tb..target - tb].chars() {
                    self.cur.raw += enc.encoded_len(c);
                    self.cur.dec += c.len_utf8();
                    self.cur.nl += (c == '\n') as u64;
                    if self.cur.dec >= last + CHECKPOINT_EVERY {
                        self.checkpoints.push(self.cur);
                        last = self.cur.dec;
                    }
                }
            }
        }
        self.cur
    }

    /// 1-based line of decoded offset `m.dec`, as `LineIndex::line_of` on the whole text.
    fn line_of(&self, m: Mark) -> u32 {
        // LineIndex starts no line at the very end of the text when it ends with `\n`.
        let at_text_end = self.eof && m.dec == self.end();
        let nl = if at_text_end && self.ends_nl {
            m.nl - 1
        } else {
            m.nl
        };
        (nl + 1) as u32
    }

    /// Where `span` (absolute, inside the window) lives in the file: as `locate` on the whole text, and the
    /// SHA-256 of those raw bytes.
    pub fn sight(&mut self, span: Span) -> Sight {
        if let Some((drained, sight, _)) = &self.drained
            && *drained == span
        {
            return sight.clone();
        }
        assert!(
            self.base <= span.start && span.start <= span.end && span.end <= self.end(),
            "span {span:?} outside the window {}..{}",
            self.base,
            self.end()
        );
        let ms = self.scan_to(span.start);
        let line_start = self.line_of(ms);
        let me = self.scan_to(span.end);
        let line_end = if span.end > span.start {
            // Line of the span's last byte, `end - 1`, which is before the end of the text.
            let last_is_nl = self.text.as_bytes()[span.end - 1 - self.text_base] == b'\n';
            (me.nl - last_is_nl as u64 + 1) as u32
        } else {
            line_start
        };
        let raw_start = ms.raw.min(self.raw_len);
        let raw_end = me.raw.min(self.raw_len);
        // An empty span may sit before any raw byte is read (just after a BOM).
        let from = (raw_start - self.raw_base) as usize;
        let to = (raw_end - self.raw_base) as usize;
        let raw: &[u8] = if to > from { &self.raw[from..to] } else { &[] };
        Sight {
            pos: SourcePos {
                line_start,
                line_end,
                byte_offset: raw_start,
                byte_length: raw_end - raw_start,
            },
            raw_sha256: sha256_hex(raw),
        }
    }

    /// At most [`SNIPPET_CHARS`] chars of `span`'s text (clamped to the window, as `parse_error` clamps to the
    /// text).
    pub fn snippet(&self, span: Span) -> String {
        if let Some((drained, _, snippet)) = &self.drained
            && *drained == span
        {
            return snippet.clone();
        }
        let end = floor_boundary(
            &self.text,
            span.end.clamp(self.base, self.end()) - self.text_base,
        );
        let start = floor_boundary(
            &self.text,
            span.start.clamp(self.base, self.text_base + end) - self.text_base,
        );
        self.text[start..end].chars().take(SNIPPET_CHARS).collect()
    }
}

impl TextStream {
    /// Sight the span from absolute offset `start` (in the window) to the end of the text, reading the file to its
    /// end: the window is consumed as the span's raw bytes are hashed and its lines counted, so memory stays at a
    /// chunk or so however long the rest of the file is. Returns the sighting, the snippet and the span's end (the
    /// text's length); afterwards [`sight`](Self::sight) and [`snippet`](Self::snippet) of that span return them.
    pub fn sight_to_end(
        &mut self,
        start: usize,
        on_read: OnRead,
    ) -> io::Result<(Sight, String, usize)> {
        assert!(
            self.base <= start && start <= self.end(),
            "start {start} outside the window {}..{}",
            self.base,
            self.end()
        );
        self.consume(start);
        while !self.eof && self.window().chars().take(SNIPPET_CHARS).count() < SNIPPET_CHARS {
            self.fill(&mut *on_read)?;
        }
        let snippet: String = self.window().chars().take(SNIPPET_CHARS).collect();
        let ms = self.scan_to(start);
        let line_start = self.line_of(ms);
        let raw_start = ms.raw.min(self.raw_len);
        let mut hash = Sha256Stream::new();
        let mut hashed = raw_start;
        loop {
            // Hash up to the scan before the next fill compacts the raw bytes away.
            let end = self.end();
            let upto = self.scan_to(end).raw.min(self.raw_len);
            if upto > hashed {
                let from = (hashed - self.raw_base) as usize;
                hash.update(&self.raw[from..(upto - self.raw_base) as usize]);
                hashed = upto;
            }
            if self.eof {
                break;
            }
            self.consume(end);
            self.fill(&mut *on_read)?;
        }
        let end = self.end();
        let line_end = if end > start {
            // Line of the span's last byte, `end - 1`, as `sight` counts it.
            (self.cur.nl - self.ends_nl as u64 + 1) as u32
        } else {
            line_start
        };
        let sight = Sight {
            pos: SourcePos {
                line_start,
                line_end,
                byte_offset: raw_start,
                byte_length: hashed - raw_start,
            },
            raw_sha256: hash.finish_hex(),
        };
        self.consume(end);
        self.drained = Some((Span { start, end }, sight.clone(), snippet.clone()));
        Ok((sight, snippet, end))
    }
}

/// A record size limit as text for its failure message: `64 MiB`, `256 KiB` or `1000 bytes`.
pub(crate) fn size_text(bytes: usize) -> String {
    const KIB: usize = 1024;
    const MIB: usize = 1024 * KIB;
    if bytes >= MIB && bytes % MIB == 0 {
        format!("{} MiB", bytes / MIB)
    } else if bytes >= KIB && bytes % KIB == 0 {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{bytes} bytes")
    }
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// One step of a [`Scan`]: an event, a request for more text (keeping the text from an absolute decoded offset),
/// or the end of the scan.
pub(crate) enum Step<E> {
    Event(E),
    More(usize),
    /// The next event spans from this absolute offset to the end of the text: sight it while reading to the end
    /// ([`TextStream::sight_to_end`]), then step again with the text ended.
    DrainFrom(usize),
    End,
}

/// A record scanner that runs the same way over a whole text and over a [`TextStream`]'s window.
pub(crate) trait Scan {
    type Event;

    /// The next step over `text`, the decoded text from absolute offset `base`; `last` says no text follows it.
    /// With `last` false it returns no event whose span reaches the end of `text` (the record may go on, and an
    /// empty span there cannot be sighted yet), and `More(keep)` has `base <= keep <= base + text.len()`, a char
    /// boundary.
    fn next(&mut self, text: &str, base: usize, last: bool) -> Step<Self::Event>;
}

/// Run `scan` over the whole `text`, handing each event to `sink` until it returns false.
pub(crate) fn scan_whole<S: Scan>(
    scan: &mut S,
    text: &str,
    mut sink: impl FnMut(&S, S::Event) -> bool,
) {
    // Over the whole text a scanner neither asks for more nor drains: the text has ended.
    while let Step::Event(e) = scan.next(text, 0, true) {
        if !sink(scan, e) {
            break;
        }
    }
}

/// Run `scan` over `stream`, handing each event to `sink` while its record is still in the window (so the sink can
/// [`sight`](TextStream::sight) it), until the sink returns false or the text ends. A read error, or `on_read`
/// asking to stop (`ErrorKind::Interrupted`), ends the scan with that error.
pub(crate) fn scan_stream<S: Scan>(
    scan: &mut S,
    stream: &mut TextStream,
    on_read: OnRead,
    mut sink: impl FnMut(&S, S::Event, &mut TextStream) -> bool,
) -> io::Result<()> {
    loop {
        match scan.next(stream.window(), stream.base(), stream.at_eof()) {
            Step::Event(e) => {
                if !sink(scan, e, stream) {
                    return Ok(());
                }
            }
            Step::End => return Ok(()),
            Step::DrainFrom(start) => {
                stream.sight_to_end(start, &mut *on_read)?;
            }
            Step::More(_) if stream.at_eof() => {
                // A scanner never asks for more at the end of the text; fail rather than loop.
                return Err(io::Error::other("scanner asked for text past the end"));
            }
            Step::More(keep) => {
                stream.consume(keep);
                // Grow the window to at least twice the text kept, so a record larger than a chunk is rescanned a
                // logarithmic number of times rather than once per chunk.
                let kept = stream.window().len();
                loop {
                    stream.fill(&mut *on_read)?;
                    if stream.at_eof() || stream.window().len() >= 2 * kept {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admitted(raw: &[u8], encoding: TextEncoding, bom_len: u64) -> Admitted {
        Admitted {
            path: PathBuf::new(),
            raw_len: raw.len() as u64,
            modified: None,
            sha256: sha256_hex(raw),
            blank: false,
            head: raw[..raw.len().min(SNIFF_BYTES)].to_vec(),
            encoding,
            bom_len,
            lossy: false,
        }
    }

    const CHUNK: usize = 4096;
    const MARGIN: usize = 1024;

    /// Stream `raw` with full consumes after every fill: the kept decoded text and raw bytes, and their
    /// capacities, stay within a chunk (`growth` decoded bytes from one chunk) plus a checkpoint interval
    /// (`raw_per_char` raw bytes per ASCII char) however long the input.
    fn assert_bounded(
        raw: Vec<u8>,
        encoding: TextEncoding,
        bom_len: u64,
        raw_per_char: usize,
        growth: usize,
    ) {
        let chunk = CHUNK;
        let margin = MARGIN;
        let a = admitted(&raw, encoding, bom_len);
        let mut s = TextStream::from_bytes(raw.clone(), &a, chunk);
        let (mut max_text, mut max_raw) = (0, 0);
        while s.fill(&mut |_| true).unwrap() {
            max_text = max_text.max(s.text.len());
            max_raw = max_raw.max(s.raw.len());
            let end = s.base() + s.window().len();
            s.consume(end);
        }
        assert!(s.at_eof());
        let streamed = s.base() + s.window().len();
        assert_eq!(
            streamed as u64 * raw_per_char as u64,
            raw.len() as u64 - bom_len,
            "the whole input was streamed"
        );
        assert!(
            max_text <= chunk + CHECKPOINT_EVERY + margin,
            "decoded text kept: {max_text}"
        );
        assert!(
            max_raw <= chunk + CHECKPOINT_EVERY * raw_per_char + margin,
            "raw bytes kept: {max_raw}"
        );
        let (text_cap, raw_cap) = s.peak;
        assert!(
            text_cap <= growth + CHECKPOINT_EVERY + margin,
            "decoded text capacity: {text_cap}"
        );
        assert!(
            raw_cap <= chunk + CHECKPOINT_EVERY * raw_per_char + margin,
            "raw capacity: {raw_cap}"
        );
        assert!(
            s.checkpoints.len() <= 3,
            "{} checkpoints",
            s.checkpoints.len()
        );
    }

    fn ascii_rows(len: usize) -> String {
        let mut s = String::new();
        let mut i = 0;
        while s.len() < len {
            s.push_str(&format!("{i},user{i}@contoso.com,MailItemsAccessed\r\n"));
            i += 1;
        }
        s
    }

    #[test]
    fn full_consumes_keep_the_window_bounded() {
        let text = ascii_rows(2 * 1024 * 1024);
        assert_bounded(text.clone().into_bytes(), TextEncoding::Utf8, 0, 1, CHUNK);
        let mut utf16 = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            utf16.extend_from_slice(&u.to_le_bytes());
        }
        assert_bounded(utf16, TextEncoding::Utf16Le, 2, 2, CHUNK * 3 / 2);
    }

    /// The window's length and capacity, and their largest values.
    #[derive(Default, Debug)]
    struct Sizes {
        now: (usize, usize, usize, usize),
        max: (usize, usize, usize, usize),
    }

    impl Sizes {
        fn see(&mut self, s: &TextStream) {
            self.now = (
                s.text.len(),
                s.text.capacity(),
                s.raw.len(),
                s.raw.capacity(),
            );
            self.max.0 = self.max.0.max(self.now.0);
            self.max.1 = self.max.1.max(self.now.1);
            self.max.2 = self.max.2.max(self.now.2);
            self.max.3 = self.max.3.max(self.now.3);
        }
    }

    #[test]
    fn capacity_returns_after_an_outsized_record() {
        let mut csv = format!("Id,AuditData\n0,\"{}\"\n", "x".repeat(1024 * 1024));
        csv.push_str(&ascii_rows(4 * 1024 * 1024));
        let raw = csv.into_bytes();
        let a = admitted(&raw, TextEncoding::Utf8, 0);
        let mut s = TextStream::from_bytes(raw, &a, CHUNK);
        let mut after = Sizes::default();
        let mut rows = 0;
        crate::readers::csv_scan::read_csv_stream(&mut s, &mut |_| true, |_, _, st| {
            rows += 1;
            // Past the outsized record and the read-ahead that came with it (the window grew to twice the record
            // while it was incomplete): several fills, and so compactions, later.
            if st.base() > 3 * 1024 * 1024 {
                after.see(st);
            }
            true
        })
        .unwrap();
        assert!(rows > 10_000, "{rows} rows");
        assert!(after.now.0 > 0, "sizes were sampled");
        assert!(
            s.peak.0 > 1024 * 1024,
            "the record grew the window: {:?}",
            s.peak
        );
        let bound = CHUNK + CHECKPOINT_EVERY + MARGIN;
        let (text, text_cap, raw, raw_cap) = after.max;
        assert!(
            text <= bound && text_cap <= bound,
            "text {text} capacity {text_cap}"
        );
        assert!(
            raw <= bound && raw_cap <= bound,
            "raw {raw} capacity {raw_cap}"
        );
    }

    /// A CSV record that never ends (an unclosed quote, then a long quote-free rest): past the record cap the scan
    /// stops holding it and fails it from its start to the end of the file, as JSON fails a bad separator.
    #[test]
    fn an_unclosed_csv_quote_is_failed_at_the_record_cap_in_bounded_memory() {
        use crate::readers::csv_scan::{CsvEvent, read_csv_stream_capped};
        const CAP: usize = 256 * 1024;
        let mut csv = String::from("Id,AuditData\r\n0,a\r\n1,b\r\n");
        let start = csv.len();
        csv.push_str("2,\"unclosed\r\n");
        csv.push_str(&ascii_rows(4 * 1024 * 1024));
        let lines = csv.matches('\n').count() as u32;
        let raw = csv.clone().into_bytes();
        let a = admitted(&raw, TextEncoding::Utf8, 0);
        let mut s = TextStream::from_bytes(raw.clone(), &a, CHUNK);
        let mut got = Vec::new();
        read_csv_stream_capped(&mut s, &mut |_| true, CAP, |_, e, st| {
            let span = match &e {
                CsvEvent::Row(r) => r.span,
                CsvEvent::Error(e) => e.span,
            };
            got.push((e, st.sight(span), st.snippet(span)));
            true
        })
        .unwrap();
        assert_eq!(got.len(), 3, "two rows, then the failure");
        assert!(matches!(&got[0].0, CsvEvent::Row(r) if r.fields == ["0", "a"]));
        assert!(matches!(&got[1].0, CsvEvent::Row(r) if r.fields == ["1", "b"]));
        let (CsvEvent::Error(e), sight, snippet) = &got[2] else {
            let CsvEvent::Row(r) = &got[2].0 else {
                unreachable!()
            };
            let held: usize = r.fields.iter().map(String::len).sum();
            panic!(
                "a row of {held} bytes instead of the failure; peak capacities {:?}",
                s.peak
            )
        };
        assert_eq!(e.ordinal, 2);
        assert_eq!((e.span.start, e.span.end), (start, raw.len()));
        assert!(
            e.message.contains("record size limit (256 KiB)"),
            "{}",
            e.message
        );
        assert_eq!(sight.pos.byte_offset, start as u64);
        assert_eq!(sight.pos.byte_length, (raw.len() - start) as u64);
        assert_eq!((sight.pos.line_start, sight.pos.line_end), (4, lines));
        assert_eq!(sight.raw_sha256, sha256_hex(&raw[start..]));
        assert_eq!(*snippet, csv[start..].chars().take(500).collect::<String>());
        let bound = 2 * CAP + CHUNK + CHECKPOINT_EVERY + MARGIN;
        assert!(
            s.peak.0 <= bound && s.peak.1 <= bound,
            "peak capacities {:?} over {bound}",
            s.peak
        );
    }

    /// Each event of a capped CSV scan of `raw` read in chunks of `chunk` bytes: a row's ordinal and fields, or an
    /// error's ordinal, span and message.
    fn capped_csv_events(raw: &[u8], cap: usize, chunk: usize) -> Vec<String> {
        capped_csv_events_bom(raw, false, cap, chunk)
    }

    /// [`capped_csv_events`] of a UTF-8 file that starts with a BOM when `bom` is set.
    fn capped_csv_events_bom(raw: &[u8], bom: bool, cap: usize, chunk: usize) -> Vec<String> {
        use crate::readers::csv_scan::{CsvEvent, read_csv_stream_capped};
        let a = if bom {
            admitted(raw, TextEncoding::Utf8Bom, 3)
        } else {
            admitted(raw, TextEncoding::Utf8, 0)
        };
        let mut s = TextStream::from_bytes(raw.to_vec(), &a, chunk);
        let mut got = Vec::new();
        read_csv_stream_capped(&mut s, &mut |_| true, cap, |_, e, st| {
            got.push(match e {
                CsvEvent::Row(r) => format!("row {} {:?}", r.ordinal, r.fields),
                CsvEvent::Error(e) => {
                    let sight = st.sight(e.span);
                    format!(
                        "error {} {}..{} {} {} {}",
                        e.ordinal,
                        e.span.start,
                        e.span.end,
                        sight.pos.byte_offset,
                        sight.pos.byte_length,
                        e.message
                    )
                }
            });
            true
        })
        .unwrap();
        got
    }

    /// The record cap is exact: a record whose span is over the cap is failed from its start to the end of the file
    /// even when it ends (here between the cap and twice it, which a grown window would hold whole), the same for
    /// every chunk size; a span of exactly the cap is read (the cap is `>`, not `>=`).
    #[test]
    fn a_csv_record_over_the_cap_is_failed_even_when_it_ends() {
        const CAP: usize = 4096;
        let head = "Id,AuditData\r\n0,a\r\n1,b\r\n";
        let tail = "3,c\r\n4,d\r\n";
        let msg = "record exceeds the CSV record size limit (4 KiB); the rest of the file is not read as records";
        // (record, over the cap): quoted and unquoted, a span of the cap plus one, of the cap, and of 1.5 caps.
        let quoted = |n: usize| format!("2,\"{}\"", "x".repeat(n - 4));
        let bare = |n: usize| format!("2,{}", "x".repeat(n - 2));
        for (record, over) in [
            (quoted(CAP + CAP / 2), true),
            (bare(CAP + CAP / 2), true),
            (quoted(CAP + 1), true),
            (bare(CAP + 1), true),
            (quoted(CAP), false),
            (bare(CAP), false),
            // A quoted field holding line ends, past the cap.
            (
                format!("2,\"{}\r\n{}\"", "x".repeat(CAP), "y".repeat(10)),
                true,
            ),
        ] {
            let csv = format!("{head}{record}\r\n{tail}");
            let start = head.len();
            for chunk in [7, CAP / 2, 4 * CAP] {
                let got = capped_csv_events(csv.as_bytes(), CAP, chunk);
                let what = format!("{} bytes, chunk {chunk}", record.len());
                assert_eq!(
                    got[..2],
                    ["row 0 [\"0\", \"a\"]", "row 1 [\"1\", \"b\"]"],
                    "{what}"
                );
                if over {
                    assert_eq!(
                        got[2..],
                        [format!(
                            "error 2 {start}..{} {start} {} {msg}",
                            csv.len(),
                            csv.len() - start
                        )],
                        "{what}"
                    );
                } else {
                    assert_eq!(got.len(), 5, "{what}: {got:?}");
                    assert!(got[2].starts_with("row 2 "), "{what}: {}", got[2]);
                    assert_eq!(
                        got[3..],
                        ["row 3 [\"3\", \"c\"]", "row 4 [\"4\", \"d\"]"],
                        "{what}"
                    );
                }
            }
        }
    }

    /// Each event of a capped JSON scan of `raw` in chunks of `chunk` bytes: a record's ordinal and span, or an
    /// error's ordinal, span and message.
    fn capped_json_events(raw: &[u8], cap: usize, chunk: usize) -> Vec<String> {
        capped_json_events_bom(raw, false, cap, chunk)
    }

    /// [`capped_json_events`] of a UTF-8 file that starts with a BOM when `bom` is set.
    fn capped_json_events_bom(raw: &[u8], bom: bool, cap: usize, chunk: usize) -> Vec<String> {
        use crate::readers::json_scan::{JsonEvent, scan_json_stream_capped};
        let a = if bom {
            admitted(raw, TextEncoding::Utf8Bom, 3)
        } else {
            admitted(raw, TextEncoding::Utf8, 0)
        };
        let mut s = TextStream::from_bytes(raw.to_vec(), &a, chunk);
        let mut got = Vec::new();
        scan_json_stream_capped(&mut s, &mut |_| true, cap, |e, st| {
            got.push(match e {
                JsonEvent::Record(r) => {
                    format!("record {} {}..{}", r.ordinal, r.span.start, r.span.end)
                }
                JsonEvent::Error(e) => {
                    let sight = st.sight(e.span);
                    format!(
                        "error {} {}..{} {} {} {}",
                        e.ordinal,
                        e.span.start,
                        e.span.end,
                        sight.pos.byte_offset,
                        sight.pos.byte_length,
                        e.message
                    )
                }
            });
            true
        })
        .unwrap();
        got
    }

    /// The JSON record cap is exact, for an array item and for a top-level value (JSONL / concatenated documents):
    /// a value over the cap is failed from its start to the end of the file whether it ends or not, the same for every
    /// chunk size; a value of exactly the cap is read.
    #[test]
    fn a_json_value_over_the_cap_is_failed_even_when_it_ends() {
        const CAP: usize = 4096;
        let msg = "record exceeds the JSON record size limit (4 KiB); the rest of the file is not read as records";
        // A value of `n` bytes: `{"a":"xx..x"}`.
        let value = |n: usize| format!("{{\"a\":\"{}\"}}", "x".repeat(n - 8));
        // An unclosed value whose rest (quote-free) runs to the end of the file.
        let unclosed = format!(
            "{{\"a\":\"unclosed{}",
            " 1 user@contoso.com\r\n".repeat(CAP / 4)
        );
        for (layout, head, sep, tail) in [
            (
                "array",
                "[\r\n{\"a\":0},\r\n{\"a\":1},\r\n",
                ",\r\n",
                "{\"a\":3}\r\n]\r\n",
            ),
            ("top", "{\"a\":0}\r\n{\"a\":1}\r\n", "\r\n", "{\"a\":3}\r\n"),
        ] {
            for (record, ends, over) in [
                (value(CAP + CAP / 2), true, true),
                (value(CAP + 1), true, true),
                (value(CAP), true, false),
                (unclosed.clone(), false, true),
            ] {
                let json = if ends {
                    format!("{head}{record}{sep}{tail}")
                } else {
                    format!("{head}{record}")
                };
                let start = head.len();
                for chunk in [7, CAP / 2, 4 * CAP] {
                    let got = capped_json_events(json.as_bytes(), CAP, chunk);
                    let what = format!("{layout}: {} bytes, chunk {chunk}", record.len());
                    assert!(got[0].starts_with("record 0 "), "{what}: {got:?}");
                    assert!(got[1].starts_with("record 1 "), "{what}: {got:?}");
                    if over {
                        assert_eq!(
                            got[2..],
                            [format!(
                                "error 2 {start}..{} {start} {} {msg}",
                                json.len(),
                                json.len() - start
                            )],
                            "{what}"
                        );
                    } else {
                        assert_eq!(
                            got[2],
                            format!("record 2 {start}..{}", start + CAP),
                            "{what}"
                        );
                        assert_eq!(got.len(), 4, "{what}: {got:?}");
                        assert!(got[3].starts_with("record 3 "), "{what}: {got:?}");
                    }
                }
            }
        }
    }

    /// `n` bytes of multi-byte UTF-8 (2-, 3- and 4-byte chars), padded with ASCII to exactly `n`.
    fn multibyte(n: usize) -> String {
        let mut s = String::new();
        while s.len() + "é€😀".len() <= n {
            s.push_str("é€😀");
        }
        while s.len() < n {
            s.push('x');
        }
        s
    }

    /// The cap with a UTF-8 BOM and multi-byte characters cut across chunk ends (chunks of 7, 13 and an odd half
    /// cap split the 2-, 3- and 4-byte chars): the cap counts decoded bytes from the record's first one (the BOM is
    /// not text), an ended record over it is one failure from its start to the end of the file, and a record of
    /// exactly the cap is read, the same for every chunk size.
    #[test]
    fn the_record_cap_counts_decoded_bytes_with_a_bom_and_multibyte_chars() {
        const CAP: usize = 4096;
        let chunks = [7, 13, CAP / 2 + 1, 4 * CAP];
        let bom = [0xEF, 0xBB, 0xBF];
        let with_bom = |text: &str| [&bom[..], text.as_bytes()].concat();

        // CSV: a header and two rows holding multi-byte text, then the record, then two more rows.
        let head = "Id,Value\r\n0,é€\r\n1,😀\r\n";
        let tail = "3,ü\r\n4,€\r\n";
        let csv_msg = "record exceeds the CSV record size limit (4 KiB); the rest of the file is not read as records";
        for (record, over) in [
            (format!("2,\"{}\"", multibyte(CAP + CAP / 2 - 4)), true),
            (format!("2,{}", multibyte(CAP + 1 - 2)), true),
            (format!("2,\"{}\"", multibyte(CAP - 4)), false),
            (format!("2,{}", multibyte(CAP - 2)), false),
        ] {
            assert_eq!(record.len() > CAP, over, "{} bytes", record.len());
            assert!(over || record.len() == CAP, "{} bytes", record.len());
            let text = format!("{head}{record}\r\n{tail}");
            let raw = with_bom(&text);
            let start = head.len();
            let first = capped_csv_events_bom(&raw, true, CAP, chunks[0]);
            for chunk in chunks {
                let got = capped_csv_events_bom(&raw, true, CAP, chunk);
                let what = format!("CSV {} bytes, chunk {chunk}", record.len());
                assert_eq!(got, first, "{what}: differs from chunk {}", chunks[0]);
                assert_eq!(
                    got[..2],
                    ["row 0 [\"0\", \"é€\"]", "row 1 [\"1\", \"😀\"]"],
                    "{what}"
                );
                if over {
                    // The decoded span starts at the record; its bytes start after the BOM.
                    assert_eq!(
                        got[2..],
                        [format!(
                            "error 2 {start}..{} {} {} {csv_msg}",
                            text.len(),
                            start + 3,
                            text.len() - start
                        )],
                        "{what}"
                    );
                } else {
                    assert_eq!(got.len(), 5, "{what}: {got:?}");
                    let field = record.trim_start_matches("2,").trim_matches('"');
                    assert_eq!(got[2], format!("row 2 {:?}", ["2", field]), "{what}");
                    assert_eq!(
                        got[3..],
                        ["row 3 [\"3\", \"ü\"]", "row 4 [\"4\", \"€\"]"],
                        "{what}"
                    );
                }
            }
        }

        // JSON: an array item and a top-level value, `{"a":"<multi-byte>"}`.
        let json_msg = "record exceeds the JSON record size limit (4 KiB); the rest of the file is not read as records";
        let value = |n: usize| format!("{{\"a\":\"{}\"}}", multibyte(n - 8));
        for (layout, head, sep, tail) in [
            (
                "array",
                "[\r\n{\"a\":\"é\"},\r\n{\"a\":\"😀\"},\r\n",
                ",\r\n",
                "{\"a\":\"€\"}\r\n]\r\n",
            ),
            (
                "top",
                "{\"a\":\"é\"}\r\n{\"a\":\"😀\"}\r\n",
                "\r\n",
                "{\"a\":\"€\"}\r\n",
            ),
        ] {
            for (record, over) in [
                (value(CAP + CAP / 2), true),
                (value(CAP + 1), true),
                (value(CAP), false),
            ] {
                let text = format!("{head}{record}{sep}{tail}");
                let raw = with_bom(&text);
                let start = head.len();
                let first = capped_json_events_bom(&raw, true, CAP, chunks[0]);
                for chunk in chunks {
                    let got = capped_json_events_bom(&raw, true, CAP, chunk);
                    let what = format!("JSON {layout}: {} bytes, chunk {chunk}", record.len());
                    assert_eq!(got, first, "{what}: differs from chunk {}", chunks[0]);
                    assert!(got[0].starts_with("record 0 "), "{what}: {got:?}");
                    assert!(got[1].starts_with("record 1 "), "{what}: {got:?}");
                    if over {
                        assert_eq!(
                            got[2..],
                            [format!(
                                "error 2 {start}..{} {} {} {json_msg}",
                                text.len(),
                                start + 3,
                                text.len() - start
                            )],
                            "{what}"
                        );
                    } else {
                        assert_eq!(
                            got[2],
                            format!("record 2 {start}..{}", start + CAP),
                            "{what}"
                        );
                        assert_eq!(got.len(), 4, "{what}: {got:?}");
                    }
                }
            }
        }
    }

    /// A record just under the cap is read as before.
    #[test]
    fn a_csv_record_under_the_cap_is_read_whole() {
        use crate::readers::csv_scan::{CsvEvent, read_csv_stream_capped};
        const CAP: usize = 256 * 1024;
        let big = "x".repeat(CAP - 1024);
        let mut csv = format!("Id,AuditData\r\n0,\"{big}\"\r\n");
        csv.push_str(&ascii_rows(1024 * 1024));
        let raw = csv.into_bytes();
        let a = admitted(&raw, TextEncoding::Utf8, 0);
        let mut s = TextStream::from_bytes(raw, &a, CHUNK);
        let (mut rows, mut errors) = (0, 0);
        read_csv_stream_capped(&mut s, &mut |_| true, CAP, |_, e, _| {
            match e {
                CsvEvent::Row(r) if r.ordinal == 0 => {
                    assert_eq!(r.fields[1], big);
                    rows += 1
                }
                CsvEvent::Row(_) => rows += 1,
                CsvEvent::Error(_) => errors += 1,
            }
            true
        })
        .unwrap();
        assert_eq!(errors, 0);
        assert!(rows > 10_000, "{rows} rows");
    }

    /// A JSON value that never ends (an unclosed string, object or array, then a long rest of the file): past the
    /// record cap the scan stops holding it and fails it from its start to the end of the file, in bounded memory.
    #[test]
    fn an_unclosed_json_value_is_failed_at_the_record_cap_in_bounded_memory() {
        use crate::readers::json_scan::{JsonEvent, scan_json_stream_capped};
        const CAP: usize = 256 * 1024;
        let quoted = |len: usize| {
            let mut s = String::new();
            let mut i = 0;
            while s.len() < len {
                s.push_str(&format!(",\r\n{{\"a\":{i},\"u\":\"user{i}@contoso.com\"}}"));
                i += 1;
            }
            s
        };
        // An unclosed string must not meet another quote: its rest is quote-free.
        let unquoted = |len: usize| {
            let mut s = String::new();
            let mut i = 0;
            while s.len() < len {
                s.push_str(&format!(" {i} user{i}@contoso.com\r\n"));
                i += 1;
            }
            s
        };
        let size = 4 * 1024 * 1024;
        for (what, opener, rest) in [
            ("string", "{\"a\":\"unclosed", unquoted(size)),
            ("object", "{\"a\":", quoted(size)),
            ("array", "[{\"a\":-1}", quoted(size)),
        ] {
            let mut json = String::from("[\r\n{\"a\":0},\r\n{\"a\":1},\r\n");
            let start = json.len();
            json.push_str(opener);
            json.push_str(&rest);
            let raw = json.clone().into_bytes();
            let a = admitted(&raw, TextEncoding::Utf8, 0);
            let mut s = TextStream::from_bytes(raw.clone(), &a, CHUNK);
            let mut got = Vec::new();
            scan_json_stream_capped(&mut s, &mut |_| true, CAP, |e, st| {
                let span = match &e {
                    JsonEvent::Record(r) => r.span,
                    JsonEvent::Error(e) => e.span,
                };
                got.push((e, st.sight(span), st.snippet(span)));
                true
            })
            .unwrap();
            assert_eq!(got.len(), 3, "{what}: two records, then the failure");
            assert!(
                matches!(&got[0].0, JsonEvent::Record(r) if r.value["a"] == 0),
                "{what}"
            );
            assert!(
                matches!(&got[1].0, JsonEvent::Record(r) if r.value["a"] == 1),
                "{what}"
            );
            let (JsonEvent::Error(e), sight, snippet) = &got[2] else {
                let JsonEvent::Record(r) = &got[2].0 else {
                    unreachable!()
                };
                panic!(
                    "{what}: a record of {} bytes instead of the failure; peak capacities {:?}",
                    r.span.end - r.span.start,
                    s.peak
                )
            };
            assert_eq!(e.ordinal, 2, "{what}");
            assert_eq!((e.span.start, e.span.end), (start, raw.len()), "{what}");
            assert!(
                e.message.contains("record size limit"),
                "{what}: {}; peak capacities {:?}",
                e.message,
                s.peak
            );
            assert_eq!(sight.pos.byte_offset, start as u64, "{what}");
            assert_eq!(sight.pos.byte_length, (raw.len() - start) as u64, "{what}");
            assert_eq!(sight.raw_sha256, sha256_hex(&raw[start..]), "{what}");
            assert_eq!(
                *snippet,
                json[start..].chars().take(500).collect::<String>(),
                "{what}"
            );
            let bound = 2 * CAP + CHUNK + CHECKPOINT_EVERY + MARGIN;
            assert!(
                s.peak.0 <= bound && s.peak.1 <= bound,
                "{what}: peak capacities {:?} over {bound}",
                s.peak
            );
        }
    }

    /// A JSON record just under the cap is read as before.
    #[test]
    fn a_json_record_under_the_cap_is_read_whole() {
        use crate::readers::json_scan::{JsonEvent, scan_json_stream_capped};
        const CAP: usize = 256 * 1024;
        let big = "x".repeat(CAP - 1024);
        let mut json = format!("[\r\n{{\"a\":\"{big}\"}}");
        let mut i = 1;
        while json.len() < 1024 * 1024 {
            json.push_str(&format!(",\r\n{{\"a\":{i}}}"));
            i += 1;
        }
        json.push_str("\r\n]\r\n");
        let raw = json.into_bytes();
        let a = admitted(&raw, TextEncoding::Utf8, 0);
        let mut s = TextStream::from_bytes(raw, &a, CHUNK);
        let (mut records, mut errors) = (0, 0);
        scan_json_stream_capped(&mut s, &mut |_| true, CAP, |e, _| {
            match e {
                JsonEvent::Record(r) if r.ordinal == 0 => {
                    assert_eq!(r.value["a"], big.as_str());
                    records += 1
                }
                JsonEvent::Record(_) => records += 1,
                JsonEvent::Error(_) => errors += 1,
            }
            true
        })
        .unwrap();
        assert_eq!(errors, 0);
        assert_eq!(records, i);
    }

    #[test]
    fn bad_separator_is_sighted_in_bounded_memory() {
        use crate::readers::json_scan::{JsonEvent, scan_json_each, scan_json_stream};
        use crate::readers::text::{LineIndex, OffsetMapper, decode, locate};
        let mut json = String::from("[\r\n{\"a\":0} {\"a\":1}");
        let mut i = 2;
        while json.len() < 2 * 1024 * 1024 {
            json.push_str(&format!(",\r\n{{\"a\":{i},\"u\":\"user{i}@contoso.com\"}}"));
            i += 1;
        }
        json.push_str("\r\n]\r\n");
        let raw = json.into_bytes();
        let span_of = |e: &JsonEvent| match e {
            JsonEvent::Record(r) => r.span,
            JsonEvent::Error(e) => e.span,
        };

        let d = decode(&raw);
        let index = LineIndex::new(&d.text);
        let mut mapper = OffsetMapper::new(&d, raw.len() as u64);
        let mut want = Vec::new();
        scan_json_each(&d.text, |e| {
            let pos = locate(&d.text, &index, &mut mapper, span_of(&e));
            let bytes =
                &raw[pos.byte_offset as usize..(pos.byte_offset + pos.byte_length) as usize];
            let snippet: String = d.text[span_of(&e).start..span_of(&e).end]
                .chars()
                .take(500)
                .collect();
            want.push(format!("{e:?} {pos:?} {} {snippet:?}", sha256_hex(bytes)));
            true
        });
        assert_eq!(want.len(), 2, "one record, then the failure");

        let a = admitted(&raw, TextEncoding::Utf8, 0);
        let mut s = TextStream::from_bytes(raw.clone(), &a, CHUNK);
        let mut got = Vec::new();
        scan_json_stream(&mut s, &mut |_| true, |e, st| {
            let span = span_of(&e);
            let sight = st.sight(span);
            let snippet = st.snippet(span);
            got.push(format!(
                "{e:?} {:?} {} {snippet:?}",
                sight.pos, sight.raw_sha256
            ));
            true
        })
        .unwrap();
        assert_eq!(got, want);
        assert!(want[1].contains("expected ',' or ']'"), "{}", want[1]);
        let bound = CHUNK + CHECKPOINT_EVERY + MARGIN;
        assert!(
            s.peak.0 <= bound && s.peak.1 <= bound,
            "peak capacities {:?}",
            s.peak
        );
    }
}
