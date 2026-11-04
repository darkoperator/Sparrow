-- Migration 30: record_sources without its PRIMARY KEY (table_name, record_key, file_id, record_ordinal). DuckDB holds
-- a key index in memory and never spills it (about 135 B a key for message trace keys), so a case failed with "failed
-- to pin block" once it held about 12M sightings, however the ingest committed. The ingest keeps the four columns
-- unique itself (each file's sightings are deduplicated before they are written, first sighting wins). DuckDB cannot
-- drop a constraint in place, so the table is rebuilt: same columns, same rows (in the same order: DuckDB preserves
-- insertion order), same comments. The views that read it (record_source_refs, state_absent_in_newer) bind by name
-- and need no change. The migration runner applies this in one transaction: a failure leaves the case as it was.
CREATE TABLE record_sources_v30 (
    table_name VARCHAR NOT NULL,
    record_key VARCHAR NOT NULL,
    file_id BIGINT NOT NULL,
    record_ordinal BIGINT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    byte_offset BIGINT NOT NULL,
    byte_length BIGINT NOT NULL,
    raw_sha256 VARCHAR NOT NULL
);
INSERT INTO record_sources_v30
SELECT table_name, record_key, file_id, record_ordinal, line_start, line_end, byte_offset, byte_length, raw_sha256
FROM record_sources;
DROP TABLE record_sources;
ALTER TABLE record_sources_v30 RENAME TO record_sources;

COMMENT ON TABLE record_sources IS 'Provenance: every sighting of an evidence record, with file, 1-based line range, raw byte range and SHA-256 of the raw record bytes. One row per (table_name, record_key, file_id, record_ordinal): the ingest keeps that unique (there is no key index).';
COMMENT ON COLUMN record_sources.table_name IS 'Evidence table holding the record.';
COMMENT ON COLUMN record_sources.record_key IS 'Key of the record in table_name.';
COMMENT ON COLUMN record_sources.file_id IS 'Source file (source_files.file_id).';
COMMENT ON COLUMN record_sources.record_ordinal IS '0-based position of the record in the file (array index or CSV data row); for XLSX the 1-based sheet row.';
COMMENT ON COLUMN record_sources.line_start IS 'First physical line (1-based) of the record in the decoded file; for XLSX the sheet row number.';
COMMENT ON COLUMN record_sources.line_end IS 'Last physical line (1-based) of the record in the decoded file; for XLSX the sheet row number.';
COMMENT ON COLUMN record_sources.byte_offset IS 'Offset of the record in the raw file bytes; 0 for XLSX (the byte range is the whole workbook).';
COMMENT ON COLUMN record_sources.byte_length IS 'Length of the record in raw file bytes; the file size for XLSX.';
COMMENT ON COLUMN record_sources.raw_sha256 IS 'SHA-256 (hex) of the raw record bytes; for XLSX rows the SHA-256 of the row''s cell texts joined by tabs. sparrow verify re-computes it.';
