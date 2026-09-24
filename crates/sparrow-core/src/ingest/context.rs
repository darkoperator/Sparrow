//! Everything a parser needs while handling one file inside its transaction.

use crate::Result;
use crate::ingest::IngestOptions;
use crate::readers::text::{DecodedText, LineIndex, OffsetMapper, SourcePos, Span, locate};
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

    /// Record that `record_key` in `table` was seen at `span` of this file.
    pub fn record_source(
        &mut self,
        table: &str,
        record_key: &str,
        ordinal: u64,
        span: Span,
    ) -> Result<SourcePos> {
        let pos = self.locate(span);
        let hash = self.raw_sha256(&pos);
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
