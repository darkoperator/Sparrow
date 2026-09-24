-- 0001: provenance. Evidence tables are added by later migrations.
CREATE TYPE collector_tool AS ENUM ('hawk', 'invictus');
CREATE TYPE file_status AS ENUM ('parsed', 'duplicate_file', 'unrecognized', 'not_supported', 'skipped_superseded', 'error');

CREATE SEQUENCE seq_collection_id START 1;
CREATE SEQUENCE seq_file_id START 1;

CREATE TABLE collections (
    collection_id BIGINT PRIMARY KEY DEFAULT nextval('seq_collection_id'),
    tool collector_tool NOT NULL,
    tool_version VARCHAR,
    root_path VARCHAR NOT NULL,
    tenant_name_reported VARCHAR,
    window_start TIMESTAMPTZ,
    window_end TIMESTAMPTZ,
    collected_at TIMESTAMPTZ,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp,
    sparrow_version VARCHAR NOT NULL
);

CREATE TABLE source_files (
    file_id BIGINT PRIMARY KEY DEFAULT nextval('seq_file_id'),
    collection_id BIGINT NOT NULL,
    rel_path VARCHAR NOT NULL,
    artifact_type VARCHAR,
    format VARCHAR,
    encoding VARCHAR,
    size_bytes BIGINT NOT NULL,
    sha256 VARCHAR NOT NULL,
    records_read BIGINT NOT NULL DEFAULT 0,
    records_loaded BIGINT NOT NULL DEFAULT 0,
    records_duplicate BIGINT NOT NULL DEFAULT 0,
    records_error BIGINT NOT NULL DEFAULT 0,
    status file_status NOT NULL,
    warnings JSON,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp
);

CREATE TABLE record_sources (
    table_name VARCHAR NOT NULL,
    record_key VARCHAR NOT NULL,
    file_id BIGINT NOT NULL,
    record_ordinal BIGINT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    byte_offset BIGINT NOT NULL,
    byte_length BIGINT NOT NULL,
    raw_sha256 VARCHAR NOT NULL,
    PRIMARY KEY (table_name, record_key, file_id, record_ordinal)
);

CREATE TABLE parse_errors (
    file_id BIGINT NOT NULL,
    record_ordinal BIGINT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    byte_offset BIGINT NOT NULL,
    byte_length BIGINT NOT NULL,
    error VARCHAR NOT NULL,
    raw_snippet VARCHAR
);

CREATE TABLE collection_log (
    log_key VARCHAR PRIMARY KEY,
    collection_id BIGINT NOT NULL,
    file_id BIGINT NOT NULL,
    record_ordinal BIGINT NOT NULL,
    ts TIMESTAMPTZ,
    ts_raw VARCHAR,
    tz_assumed BOOLEAN NOT NULL,
    level VARCHAR,
    message VARCHAR NOT NULL
);

COMMENT ON TABLE collections IS 'One row per collector output folder ingested: a Hawk_<tenant>_<timestamp> folder or a Microsoft-Extractor-Suite Output folder.';
COMMENT ON COLUMN collections.collection_id IS 'Surrogate key.';
COMMENT ON COLUMN collections.tool IS 'Collector that produced the folder: hawk or invictus (Microsoft-Extractor-Suite).';
COMMENT ON COLUMN collections.tool_version IS 'Collector version when recorded in its log (Hawk only).';
COMMENT ON COLUMN collections.root_path IS 'Absolute path of the collection root at ingest time; relative paths in source_files are relative to it.';
COMMENT ON COLUMN collections.tenant_name_reported IS 'Tenant name as reported by the collector (Hawk folder name / log). Not authoritative; see tenant table in later phases.';
COMMENT ON COLUMN collections.window_start IS 'Start of the collection time window reported by the collector (UTC), if known.';
COMMENT ON COLUMN collections.window_end IS 'End of the collection time window reported by the collector (UTC), if known.';
COMMENT ON COLUMN collections.collected_at IS 'When the collector run started (UTC), from the folder timestamp when available.';
COMMENT ON COLUMN collections.ingested_at IS 'When sparrow first ingested this collection.';
COMMENT ON COLUMN collections.sparrow_version IS 'Sparrow version that created this row.';

COMMENT ON TABLE source_files IS 'Every file seen in a collection, with its SHA-256, detected artifact type, parse status and record reconciliation counts.';
COMMENT ON COLUMN source_files.file_id IS 'Surrogate key referenced by record_sources and parse_errors.';
COMMENT ON COLUMN source_files.collection_id IS 'Owning collection (collections.collection_id).';
COMMENT ON COLUMN source_files.rel_path IS 'Path relative to the collection root, forward slashes.';
COMMENT ON COLUMN source_files.artifact_type IS 'Artifact id from the discovery registry (e.g. hawk.log, inv.ual.window); NULL when unrecognized.';
COMMENT ON COLUMN source_files.format IS 'File format from the extension: json, jsonl, csv, txt, log, eml, xml or unknown.';
COMMENT ON COLUMN source_files.encoding IS 'Detected text encoding (utf-8, utf-8-bom, utf-16le, utf-16be, windows-1252); NULL when not decoded.';
COMMENT ON COLUMN source_files.size_bytes IS 'File size in bytes.';
COMMENT ON COLUMN source_files.sha256 IS 'SHA-256 of the whole file (hex). Used for duplicate detection and verify.';
COMMENT ON COLUMN source_files.records_read IS 'Records found in the file.';
COMMENT ON COLUMN source_files.records_loaded IS 'Records written as new evidence rows.';
COMMENT ON COLUMN source_files.records_duplicate IS 'Records already present from another file (provenance link added instead).';
COMMENT ON COLUMN source_files.records_error IS 'Records that failed to parse (see parse_errors).';
COMMENT ON COLUMN source_files.status IS 'parsed, duplicate_file, unrecognized, not_supported (recognized but no parser yet), skipped_superseded, or error.';
COMMENT ON COLUMN source_files.warnings IS 'JSON array of warning strings raised while handling the file.';
COMMENT ON COLUMN source_files.ingested_at IS 'When the file was handled.';

COMMENT ON TABLE record_sources IS 'Provenance: every sighting of an evidence record, with file, 1-based line range, raw byte range and SHA-256 of the raw record bytes.';
COMMENT ON COLUMN record_sources.table_name IS 'Evidence table holding the record.';
COMMENT ON COLUMN record_sources.record_key IS 'Key of the record in table_name.';
COMMENT ON COLUMN record_sources.file_id IS 'Source file (source_files.file_id).';
COMMENT ON COLUMN record_sources.record_ordinal IS '0-based position of the record in the file (array index or CSV data row).';
COMMENT ON COLUMN record_sources.line_start IS 'First physical line (1-based) of the record in the decoded file.';
COMMENT ON COLUMN record_sources.line_end IS 'Last physical line (1-based) of the record in the decoded file.';
COMMENT ON COLUMN record_sources.byte_offset IS 'Offset of the record in the raw file bytes.';
COMMENT ON COLUMN record_sources.byte_length IS 'Length of the record in raw file bytes.';
COMMENT ON COLUMN record_sources.raw_sha256 IS 'SHA-256 (hex) of the raw record bytes; sparrow verify re-computes it.';

COMMENT ON TABLE parse_errors IS 'Records that could not be parsed, with location and a raw snippet. Nothing is dropped silently.';
COMMENT ON COLUMN parse_errors.file_id IS 'Source file (source_files.file_id).';
COMMENT ON COLUMN parse_errors.record_ordinal IS '0-based position of the failed record in the file.';
COMMENT ON COLUMN parse_errors.line_start IS 'First physical line (1-based) of the failed record.';
COMMENT ON COLUMN parse_errors.line_end IS 'Last physical line (1-based) of the failed record.';
COMMENT ON COLUMN parse_errors.byte_offset IS 'Offset of the failed record in raw file bytes.';
COMMENT ON COLUMN parse_errors.byte_length IS 'Length of the failed record in raw file bytes.';
COMMENT ON COLUMN parse_errors.error IS 'Parser error message.';
COMMENT ON COLUMN parse_errors.raw_snippet IS 'First 500 characters of the failed record text.';

COMMENT ON TABLE collection_log IS 'Collector run log lines (Hawk.log, Extractor Suite LogFile.txt).';
COMMENT ON COLUMN collection_log.log_key IS 'Record key: <file_id>:<ordinal>.';
COMMENT ON COLUMN collection_log.collection_id IS 'Owning collection.';
COMMENT ON COLUMN collection_log.file_id IS 'Source log file.';
COMMENT ON COLUMN collection_log.record_ordinal IS '0-based entry number within the log file.';
COMMENT ON COLUMN collection_log.ts IS 'Entry time. UTC for Hawk; for Extractor Suite the local time of the collecting machine stored as if UTC (see tz_assumed).';
COMMENT ON COLUMN collection_log.ts_raw IS 'Timestamp text exactly as written in the log.';
COMMENT ON COLUMN collection_log.tz_assumed IS 'True when the log has no timezone and ts assumes UTC.';
COMMENT ON COLUMN collection_log.level IS 'Log level tag when present (INFO, ACTION, WARNING, ERROR, INVESTIGATE, PROMPT, ...).';
COMMENT ON COLUMN collection_log.message IS 'Log message; continuation lines are joined with newlines.';
