//! Everything a parser needs while handling one file inside its transaction.

use crate::Error;
use crate::Result;
use crate::ingest::IngestOptions;
use crate::readers::text::{DecodedText, LineIndex, OffsetMapper, SourcePos, Span, locate};
use crate::readers::time::{DateOrder, DateOrderDetector};
use duckdb::{Connection, params};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileStats {
    pub read: u64,
    pub loaded: u64,
    pub duplicate: u64,
    pub error: u64,
}

pub struct ParseContext<'a> {
    pub conn: &'a Connection,
    pub collection_id: i64,
    pub file_id: i64,
    pub rel_path: &'a str,
    pub subject: Option<&'a str>,
    pub raw: &'a [u8],
    pub text: &'a DecodedText,
    pub index: &'a LineIndex,
    pub options: &'a IngestOptions,
    pub stats: FileStats,
    /// Day/month order the other files of this collection proved (retry pass only).
    pub date_hint: Option<DateOrder>,
    /// First pass: a file whose culture dates are all ambiguous is deferred
    /// (`Error::DateOrderDeferred`) until the rest of its collection has been read.
    pub defer_ambiguous_dates: bool,
    /// Other files of this collection proved both orders (retry pass only): an all-ambiguous
    /// file then fails saying so.
    pub collection_orders_conflict: bool,
    orders_seen: Vec<DateOrder>,
    warnings: Vec<String>,
    mapper: OffsetMapper,
}

impl<'a> ParseContext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        conn: &'a Connection,
        collection_id: i64,
        file_id: i64,
        rel_path: &'a str,
        subject: Option<&'a str>,
        raw: &'a [u8],
        text: &'a DecodedText,
        index: &'a LineIndex,
        options: &'a IngestOptions,
    ) -> Self {
        ParseContext {
            conn,
            collection_id,
            file_id,
            rel_path,
            subject,
            raw,
            text,
            index,
            options,
            stats: FileStats::default(),
            date_hint: None,
            defer_ambiguous_dates: false,
            collection_orders_conflict: false,
            orders_seen: Vec::new(),
            warnings: Vec::new(),
            mapper: OffsetMapper::new(text, raw.len() as u64),
        }
    }

    pub fn locate(&mut self, span: Span) -> SourcePos {
        locate(&self.text.text, self.index, &mut self.mapper, span)
    }

    fn raw_sha256(&self, pos: &SourcePos) -> String {
        let start = pos.byte_offset as usize;
        let end = (pos.byte_offset + pos.byte_length) as usize;
        debug_assert!(end <= self.raw.len(), "record range beyond end of file");
        hex::encode(Sha256::digest(
            &self.raw[start.min(self.raw.len())..end.min(self.raw.len())],
        ))
    }

    /// Position and raw-bytes SHA-256 of a record, for bulk loaders that write
    /// `record_sources` themselves.
    pub fn sighting(&mut self, span: Span) -> (SourcePos, String) {
        let pos = self.locate(span);
        let hash = self.raw_sha256(&pos);
        (pos, hash)
    }

    /// Record that `record_key` in `table` was seen at `span` of this file.
    pub fn record_source(
        &mut self,
        table: &str,
        record_key: &str,
        ordinal: u64,
        span: Span,
    ) -> Result<SourcePos> {
        let (pos, hash) = self.sighting(span);
        self.conn
            .prepare_cached(
                "INSERT INTO record_sources (table_name, record_key, file_id, record_ordinal, line_start, line_end,
                                             byte_offset, byte_length, raw_sha256)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
            )?
            .execute(params![
                table,
                record_key,
                self.file_id,
                ordinal as i64,
                pos.line_start as i64,
                pos.line_end as i64,
                pos.byte_offset as i64,
                pos.byte_length as i64,
                hash
            ])?;
        Ok(pos)
    }

    /// Record a record-level parse failure. Increments `stats.error`.
    pub fn parse_error(&mut self, ordinal: u64, span: Span, message: &str) -> Result<()> {
        let text = &self.text.text;
        let end = floor_char_boundary(text, span.end.min(text.len()));
        let start = floor_char_boundary(text, span.start.min(end));
        let span = Span { start, end };
        let pos = self.locate(span);
        let snippet: String = self.text.text[span.start..span.end]
            .chars()
            .take(500)
            .collect();
        self.conn
            .prepare_cached(
                "INSERT INTO parse_errors (file_id, record_ordinal, line_start, line_end, byte_offset, byte_length,
                                           error, raw_snippet)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )?
            .execute(params![
                self.file_id,
                ordinal as i64,
                pos.line_start as i64,
                pos.line_end as i64,
                pos.byte_offset as i64,
                pos.byte_length as i64,
                message,
                snippet
            ])?;
        self.stats.error += 1;
        Ok(())
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        if !self.warnings.contains(&msg) {
            self.warnings.push(msg);
        }
    }

    /// Day/month order for this file's culture-formatted dates. `--culture` wins (checked
    /// against the file). Otherwise the file's own values decide. When they are all ambiguous,
    /// the order the collection's other files proved is used (with a warning). On the first
    /// pass such a file is deferred instead, and without any order it fails naming `--culture`.
    pub fn resolve_date_order(
        &mut self,
        detector: &DateOrderDetector,
    ) -> Result<Option<DateOrder>> {
        if self.options.date_order.is_some() || !detector.only_ambiguous() {
            let order = detector
                .resolve(self.options.date_order)
                .map_err(Error::Invalid)?;
            if let Some(o) = detector.evidence() {
                if !self.orders_seen.contains(&o) {
                    self.orders_seen.push(o);
                }
            }
            return Ok(order);
        }
        if let Some(hint) = self.date_hint {
            self.warn(format!(
                "every day/month value in this file is ambiguous; read as {}, the order the other files of this collection show",
                hint.describe()
            ));
            return Ok(Some(hint));
        }
        if self.defer_ambiguous_dates {
            return Err(Error::DateOrderDeferred);
        }
        if self.collection_orders_conflict {
            return Err(Error::Invalid(
                "ambiguous day/month order; other files of this collection show both orders; pass --culture"
                    .into(),
            ));
        }
        detector.resolve(None).map_err(Error::Invalid)
    }

    /// Orders this file's own dates proved (they resolve other files of the collection).
    pub fn orders_seen(&self) -> &[DateOrder] {
        &self.orders_seen
    }

    pub fn finish(self) -> (FileStats, Vec<String>) {
        let s = self.stats;
        let mut warnings = self.warnings;
        if s.read != s.loaded + s.duplicate + s.error {
            warnings.push(format!(
                "reconciliation mismatch: read {} != loaded {} + duplicate {} + error {}",
                s.read, s.loaded, s.duplicate, s.error
            ));
        }
        (s, warnings)
    }
}

/// Largest char boundary of `s` at or below `i`.
fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}
