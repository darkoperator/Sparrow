//! Everything a parser needs while handling one file inside its transaction.

use crate::Error;
use crate::Result;
use crate::hash::sha256_hex;
use crate::ingest::progress::FileProgress;
use crate::ingest::{HookedRead, IngestOptions, ReadPhase};
use crate::readers::stream::{Admitted, CHUNK_BYTES, Sight, TextStream};
use crate::readers::text::{DecodedText, LineIndex, OffsetMapper, SourcePos, Span, locate};
use crate::readers::time::{DateOrder, DateOrderDetector};
use duckdb::{Connection, params};
use std::cell::Cell;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileStats {
    pub read: u64,
    pub loaded: u64,
    pub duplicate: u64,
    pub error: u64,
    /// Of `error`, records the collector lost: it wrote a failure placeholder instead of data
    /// ([`crate::ingest::COLLECTOR_LOSS`]).
    pub collector_lost: u64,
}

/// A file's whole content in memory: its raw bytes, decoded text and line index. Parsers that read the whole text
/// (`InputMode::Whole`), XLSX workbooks and Format-List files get it.
#[derive(Clone, Copy)]
pub struct WholeText<'a> {
    pub raw: &'a [u8],
    pub text: &'a DecodedText<'a>,
    pub index: &'a LineIndex,
}

/// A file being ingested from disk: what its record passes need besides the admitted file (the ingest's options, for
/// the read size, the cancel check and the test read hook), how many passes it has had and where its progress is
/// reported.
pub struct FileSource<'a> {
    rel_path: &'a str,
    options: &'a IngestOptions,
    passes: Cell<usize>,
    progress: &'a FileProgress<'a>,
}

impl<'a> FileSource<'a> {
    pub(crate) fn new(
        rel_path: &'a str,
        options: &'a IngestOptions,
        progress: &'a FileProgress<'a>,
    ) -> Self {
        FileSource {
            rel_path,
            options,
            passes: Cell::new(0),
            progress,
        }
    }
}

/// Where a pass over a file's records reads its bytes.
#[derive(Clone, Copy)]
pub enum RecordSource<'a> {
    /// The file's content, already in memory (tests that build a context by hand). Each pass copies it.
    Memory(&'a [u8]),
    /// The admitted file on disk, opened again for each pass.
    File(&'a FileSource<'a>),
}

/// What a pass over a file's records needs ([`crate::parsers::records::for_each_record`]): the admitted file, where
/// its bytes come from, the parser step the pass belongs to and whether readable records are sighted. Taken from
/// [`ParseContext::input`]; it does not borrow the context, so a pass can write through the context as it reads.
#[derive(Clone, Copy)]
pub struct RecordInput<'a> {
    admitted: &'a Admitted,
    source: RecordSource<'a>,
    step: usize,
    sights: bool,
    progress: bool,
}

impl<'a> RecordInput<'a> {
    pub fn admitted(&self) -> &'a Admitted {
        self.admitted
    }

    /// Index into the parser's `steps()` of the step this pass belongs to.
    pub fn step(&self) -> usize {
        self.step
    }

    /// This input with readable records sighted (`true`, the default) or not. A pass that discards its records'
    /// sightings and snippets (a shape or date pass) turns them off: the record's [`Sight`] is then empty and its
    /// snippet blank. Unreadable records are sighted either way (they are written to `parse_errors`).
    pub fn with_sights(mut self, on: bool) -> Self {
        self.sights = on;
        self
    }

    /// Whether readable records are sighted ([`Self::with_sights`]).
    pub fn sights(&self) -> bool {
        self.sights
    }

    /// This input with its pass reporting no progress: for a peek that reads only up to the first record, before
    /// the pass of the same step that reads the whole file (a step's bytes would otherwise run to 100 % twice).
    pub fn quiet(mut self) -> Self {
        self.progress = false;
        self
    }

    /// Where this pass reports its progress, if it does.
    fn progress(&self) -> Option<&'a FileProgress<'a>> {
        match self.source {
            RecordSource::File(f) if self.progress => Some(f.progress),
            _ => None,
        }
    }

    /// The pass ended without an error (read to the end, or stopped by the parser): its step is at 100 %.
    pub(crate) fn pass_done(&self) {
        if let Some(p) = self.progress() {
            p.close();
        }
    }

    /// A new pass over the file's text from its first byte.
    pub(crate) fn open(&self) -> std::io::Result<TextStream> {
        let chunk = match self.source {
            RecordSource::Memory(_) => CHUNK_BYTES,
            RecordSource::File(f) => f.options.chunk(),
        };
        // Sightings do not depend on the read size; a small file needs no full-size buffer.
        let chunk = chunk.min(
            usize::try_from(self.admitted.raw_len)
                .unwrap_or(usize::MAX)
                .saturating_add(1),
        );
        match self.source {
            RecordSource::Memory(raw) => {
                Ok(TextStream::from_bytes(raw.to_vec(), self.admitted, chunk))
            }
            RecordSource::File(f) => {
                if let Some(p) = self.progress() {
                    p.begin_pass(self.step + 1);
                }
                let pass = f.passes.get() + 1;
                f.passes.set(pass);
                let file = std::fs::File::open(&self.admitted.path)?;
                let reader = HookedRead::open(
                    file,
                    f.options.read_hook.clone(),
                    f.rel_path,
                    ReadPhase::Pass(pass),
                )?;
                Ok(TextStream::from_reader(
                    Box::new(reader),
                    self.admitted,
                    chunk,
                ))
            }
        }
    }

    /// What a pass reports for the raw bytes it reads (its progress); false stops it (the ingest was cancelled).
    pub(crate) fn on_read(&self) -> impl FnMut(u64) -> bool + use<'a> {
        let cancel = match self.source {
            RecordSource::Memory(_) => None,
            RecordSource::File(f) => f.options.cancel.clone(),
        };
        let progress = self.progress();
        move |n| {
            if cancel.as_ref().is_some_and(|c| c()) {
                return false;
            }
            if let Some(p) = progress {
                p.read(n);
            }
            true
        }
    }
}

pub struct ParseContext<'a> {
    pub conn: &'a Connection,
    pub collection_id: i64,
    pub file_id: i64,
    pub rel_path: &'a str,
    pub subject: Option<&'a str>,
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
    /// The file is an analyst portal download (`portal.*` artifact), not a PowerShell export: its
    /// values are never PowerShell placeholders.
    pub portal_export: bool,
    orders_seen: Vec<DateOrder>,
    warnings: Vec<String>,
    admitted: &'a Admitted,
    source: RecordSource<'a>,
    whole: Option<WholeText<'a>>,
    /// Raw offsets of the whole text (with `whole`).
    mapper: Option<OffsetMapper>,
    step: usize,
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
    /// `whole` is the file's whole content when the parser reads it whole (see [`WholeText`]); record passes read
    /// `source` either way.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        conn: &'a Connection,
        collection_id: i64,
        file_id: i64,
        rel_path: &'a str,
        subject: Option<&'a str>,
        admitted: &'a Admitted,
        source: RecordSource<'a>,
        whole: Option<WholeText<'a>>,
        options: &'a IngestOptions,
    ) -> Self {
        ParseContext {
            conn,
            collection_id,
            file_id,
            rel_path,
            subject,
            options,
            stats: FileStats::default(),
            date_hint: None,
            defer_ambiguous_dates: false,
            collection_orders_conflict: false,
            portal_export: false,
            orders_seen: Vec::new(),
            warnings: Vec::new(),
            admitted,
            source,
            whole,
            mapper: whole.map(|w| OffsetMapper::new(w.text, w.raw.len() as u64)),
            step: 0,
            pending_sources: Vec::new(),
        }
    }

    /// What a pass over the file's records reads, for the current step.
    pub fn input(&self) -> RecordInput<'a> {
        RecordInput {
            admitted: self.admitted,
            source: self.source,
            step: self.step,
            sights: true,
            progress: true,
        }
    }

    /// Where the file's progress is reported (a file read from disk).
    fn progress(&self) -> Option<&'a FileProgress<'a>> {
        match self.source {
            RecordSource::File(f) => Some(f.progress),
            RecordSource::Memory(_) => None,
        }
    }

    /// Hand the counts so far to the file's progress: records loaded (or staged, [`Self::note_staged`]) and errors.
    fn sync_progress(&self) {
        if let Some(p) = self.progress() {
            p.set_counts(self.stats.loaded, self.stats.error);
        }
    }

    /// `n` more records were staged for loading (a parser that stages the file's records and merges them once, so
    /// they count as loaded only at the end): the progress counts them as they are staged.
    pub fn note_staged(&self, n: u64) {
        if let Some(p) = self.progress() {
            p.add_staged(n);
        }
    }

    /// The parse ended: the current step is at 100 % with the final counts.
    pub(crate) fn finish_progress(&self) {
        if let Some(p) = self.progress() {
            p.set_counts(self.stats.loaded, self.stats.error);
            p.close();
        }
    }

    /// `Err(Error::Interrupted)` when the ingest was cancelled: the streaming parsers check it before loading each
    /// batch, so a cancel stops a file between reads too.
    pub fn check_cancelled(&self) -> Result<()> {
        self.sync_progress();
        if self.options.cancelled() {
            return Err(Error::Interrupted);
        }
        Ok(())
    }

    pub fn admitted(&self) -> &'a Admitted {
        self.admitted
    }

    /// The whole content, for whole-mode parsers, XLSX workbooks and Format-List files; `None` otherwise.
    pub fn whole(&self) -> Option<&WholeText<'a>> {
        self.whole.as_ref()
    }

    /// The file's first bytes decoded, for sniffs of its content.
    pub fn head_text(&self) -> String {
        self.admitted.head_text()
    }

    /// The parser step (index into its `steps()`) the next record passes belong to.
    pub fn set_step(&mut self, step: usize) {
        self.step = step;
        self.sync_progress();
        if let Some(p) = self.progress() {
            p.begin_step(step + 1);
        }
    }

    fn whole_text(&self) -> WholeText<'a> {
        self.whole
            .expect("whole-text helper used on a file the parser reads streamed")
    }

    fn locate(&mut self, span: Span) -> SourcePos {
        let w = self.whole_text();
        let mapper = self
            .mapper
            .as_mut()
            .expect("mapper is set with the whole text");
        locate(&w.text.text, w.index, mapper, span)
    }

    /// Position and raw-bytes SHA-256 of `span` of the whole text. Whole text only: panics without [`Self::whole`].
    pub fn sighting(&mut self, span: Span) -> Sight {
        let pos = self.locate(span);
        let raw = self.whole_text().raw;
        let start = pos.byte_offset as usize;
        let end = (pos.byte_offset + pos.byte_length) as usize;
        debug_assert!(end <= raw.len(), "record range beyond end of file");
        Sight {
            pos,
            raw_sha256: sha256_hex(&raw[start.min(raw.len())..end.min(raw.len())]),
        }
    }

    /// The `parse_errors.raw_snippet` of `span` of the whole text: at most 500 chars, the span clamped to the text.
    /// Whole text only: panics without [`Self::whole`].
    pub fn snippet(&self, span: Span) -> String {
        let text = &self.whole_text().text.text;
        let span = clamp_span(text, span);
        text[span.start..span.end].chars().take(500).collect()
    }

    /// Provenance of spreadsheet row `row` (1-based sheet row): `line_start = line_end = row`,
    /// the whole file as the byte range, and the SHA-256 of `row_text` (the row's cell texts
    /// joined by tabs), which `verify` recomputes from the workbook.
    pub fn row_sighting(&self, row: u32, row_text: &str) -> Sight {
        Sight {
            pos: SourcePos {
                line_start: row,
                line_end: row,
                byte_offset: 0,
                byte_length: self.admitted.raw_len,
            },
            raw_sha256: sha256_hex(row_text.as_bytes()),
        }
    }

    /// Queue the sighting [`ParseContext::record_source`] would write, for [`ParseContext::flush_sources`]. A parser
    /// that matches thousands of rows against stored records queues them and flushes once: one single-row
    /// `INSERT ... ON CONFLICT` into the `record_sources` primary key costs about a millisecond.
    pub fn queue_source(&mut self, table: &str, record_key: &str, ordinal: u64, sight: &Sight) {
        self.pending_sources.push(PendingSource {
            table: table.to_string(),
            key: record_key.to_string(),
            ordinal: ordinal as i64,
            pos: sight.pos,
            sha256: sight.raw_sha256.clone(),
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

    /// Record that `record_key` in `table` was seen at `sight` of this file.
    pub fn record_source(
        &mut self,
        table: &str,
        record_key: &str,
        ordinal: u64,
        sight: &Sight,
    ) -> Result<SourcePos> {
        let (pos, hash) = (sight.pos, &sight.raw_sha256);
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

    /// Record a record-level parse failure at `span` of the whole text. Increments `stats.error`. Whole text only:
    /// panics without [`Self::whole`].
    pub fn parse_error(&mut self, ordinal: u64, span: Span, message: &str) -> Result<()> {
        let span = clamp_span(&self.whole_text().text.text, span);
        let pos = self.locate(span);
        let snippet = self.snippet(span);
        self.insert_parse_error(ordinal, &pos, message, &snippet)
    }

    /// Record a record-level parse failure at `pos`, with its `snippet` (at most 500 chars of the record's text).
    /// Increments `stats.error`.
    pub fn parse_error_at(
        &mut self,
        ordinal: u64,
        pos: &SourcePos,
        snippet: &str,
        message: &str,
    ) -> Result<()> {
        self.insert_parse_error(ordinal, pos, message, snippet)
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
        self.sync_progress();
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

/// `span` clamped to `text` and to its char boundaries.
fn clamp_span(text: &str, span: Span) -> Span {
    let end = floor_char_boundary(text, span.end.min(text.len()));
    let start = floor_char_boundary(text, span.start.min(end));
    Span { start, end }
}

/// Largest char boundary of `s` at or below `i`.
fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}
