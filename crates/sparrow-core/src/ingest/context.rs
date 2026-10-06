//! Everything a parser needs while handling one file inside its transaction.

use crate::Error;
use crate::Result;
use crate::hash::sha256_hex;
use crate::ingest::IngestOptions;
use crate::readers::text::{DecodedText, LineIndex, OffsetMapper, SourcePos, Span, locate};
use crate::readers::time::{DateOrder, DateOrderDetector};
use duckdb::{Connection, params};

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
    /// Sightings queued by [`ParseContext::queue_source`], written by [`ParseContext::flush_sources`].
    pending_sources: Vec<PendingSource>,
}

/// One queued `record_sources` row.
struct PendingSource {
    table: String,
    key: String,
    ordinal: i64,
    pos: SourcePos,
    sha256: String,
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
            pending_sources: Vec::new(),
        }
    }

    pub fn locate(&mut self, span: Span) -> SourcePos {
        locate(&self.text.text, self.index, &mut self.mapper, span)
    }

    fn raw_sha256(&self, pos: &SourcePos) -> String {
        let start = pos.byte_offset as usize;
        let end = (pos.byte_offset + pos.byte_length) as usize;
        debug_assert!(end <= self.raw.len(), "record range beyond end of file");
        sha256_hex(&self.raw[start.min(self.raw.len())..end.min(self.raw.len())])
    }

    /// Position and raw-bytes SHA-256 of a record, for bulk loaders that write
    /// `record_sources` themselves.
    pub fn sighting(&mut self, span: Span) -> (SourcePos, String) {
        let pos = self.locate(span);
        let hash = self.raw_sha256(&pos);
        (pos, hash)
    }

    /// Provenance of spreadsheet row `row` (1-based sheet row): `line_start = line_end = row`,
    /// the whole file as the byte range, and the SHA-256 of `row_text` (the row's cell texts
    /// joined by tabs), which `verify` recomputes from the workbook.
    pub fn row_sighting(&self, row: u32, row_text: &str) -> (SourcePos, String) {
        (
            SourcePos {
                line_start: row,
                line_end: row,
                byte_offset: 0,
                byte_length: self.raw.len() as u64,
            },
            sha256_hex(row_text.as_bytes()),
        )
    }

    /// Record-level failure of spreadsheet row `row`. Increments `stats.error`.
    pub fn row_parse_error(
        &mut self,
        ordinal: u64,
        row: u32,
        row_text: &str,
        message: &str,
    ) -> Result<()> {
        let (pos, _) = self.row_sighting(row, row_text);
        let snippet: String = row_text.chars().take(500).collect();
        self.insert_parse_error(ordinal, &pos, message, &snippet)
    }

    /// Queue the sighting [`ParseContext::record_source`] would write, for [`ParseContext::flush_sources`]. A parser
    /// that matches thousands of rows against stored records queues them and flushes once: one single-row
    /// `INSERT ... ON CONFLICT` into the `record_sources` primary key costs about a millisecond.
    pub fn queue_source(&mut self, table: &str, record_key: &str, ordinal: u64, span: Span) {
        let (pos, sha256) = self.sighting(span);
        self.pending_sources.push(PendingSource {
            table: table.to_string(),
            key: record_key.to_string(),
            ordinal: ordinal as i64,
            pos,
            sha256,
        });
    }

    /// Write the queued sightings with one `INSERT ... SELECT`, in queue order. The order is not load-bearing: readers
    /// of `record_sources` order explicitly (`record_source_refs` by file and ordinal) and the primary key makes that order
    /// total, so nothing may come to depend on insertion order; the tests compare `rowid` only because that is stricter
    /// than needed. Rows already stored are filtered out with `NOT EXISTS` rather than `ON CONFLICT` (which scrambled the
    /// order, and so the row-for-row comparison with the per-row path). Within the batch and against stored rows
    /// the first sighting of a primary key (table, key, file, ordinal) wins, exactly as the same calls to
    /// `record_source` would leave it. The ingest also flushes after every successful parse, so a parser that
    /// queues and forgets to flush loses nothing.
    pub fn flush_sources(&mut self) -> Result<()> {
        let _t = super::timing::span("flush_sources (queued sightings)");
        if self.pending_sources.is_empty() {
            return Ok(());
        }
        self.conn.execute_batch(
            "CREATE OR REPLACE TEMP TABLE record_sources_stage (
                 seq BIGINT, table_name VARCHAR, record_key VARCHAR, record_ordinal BIGINT,
                 line_start INTEGER, line_end INTEGER, byte_offset BIGINT, byte_length BIGINT, raw_sha256 VARCHAR);",
        )?;
        {
            // The first sighting of a key wins, so later duplicates are dropped here, in order.
            let mut seen = std::collections::HashSet::new();
            let mut app = self.conn.appender("record_sources_stage")?;
            for (seq, p) in self.pending_sources.iter().enumerate() {
                if !seen.insert((p.table.as_str(), p.key.as_str(), p.ordinal)) {
                    continue;
                }
                app.append_row(params![
                    seq as i64,
                    p.table,
                    p.key,
                    p.ordinal,
                    p.pos.line_start as i64,
                    p.pos.line_end as i64,
                    p.pos.byte_offset as i64,
                    p.pos.byte_length as i64,
                    p.sha256
                ])?;
            }
            app.flush()?;
        }
        self.conn.execute(
            "INSERT INTO record_sources (table_name, record_key, file_id, record_ordinal, line_start, line_end,
                                         byte_offset, byte_length, raw_sha256)
             SELECT table_name, record_key, ?, record_ordinal, line_start, line_end, byte_offset, byte_length, raw_sha256
             FROM record_sources_stage s
             WHERE NOT EXISTS (SELECT 1 FROM record_sources r
                               WHERE r.table_name = s.table_name AND r.record_key = s.record_key
                                 AND r.file_id = ? AND r.record_ordinal = s.record_ordinal)
             ORDER BY s.seq",
            params![self.file_id, self.file_id],
        )?;
        self.conn
            .execute_batch("DROP TABLE record_sources_stage;")?;
        self.pending_sources.clear();
        Ok(())
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
        self.insert_parse_error(ordinal, &pos, message, &snippet)
    }

    /// Write one `parse_errors` row and count it in `stats.error`.
    fn insert_parse_error(
        &mut self,
        ordinal: u64,
        pos: &SourcePos,
        message: &str,
        snippet: &str,
    ) -> Result<()> {
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
