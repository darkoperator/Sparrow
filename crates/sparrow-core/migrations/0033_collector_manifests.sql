-- Migration 33: manifest_runs, manifest_units, manifest_gaps. The CollectionManifest-<GUID>.mesmanifest files that the
-- Microsoft-Extractor-Suite fork writes beside its output: one run per cmdlet execution, the work units it requested
-- (sources x scope x time range) with their outcome, and the gaps it could not collect. Nothing existing is rewritten.
-- (collector_runs, migration 6, is the run FOLDERS table and is unchanged.)
CREATE TABLE manifest_runs (
    run_id VARCHAR PRIMARY KEY, collection_id BIGINT NOT NULL, file_id BIGINT NOT NULL, schema VARCHAR,
    supported BOOLEAN NOT NULL, tool VARCHAR, tool_version VARCHAR, fork VARCHAR, cmdlet VARCHAR, parameters JSON,
    started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ, status VARCHAR, throttle_wait_count BIGINT,
    throttle_wait_seconds DOUBLE, raw JSON
);
CREATE TABLE manifest_units (
    unit_key VARCHAR PRIMARY KEY, run_id VARCHAR NOT NULL, unit_id VARCHAR NOT NULL, sources JSON NOT NULL,
    scope JSON, user_ids JSON, narrowed BOOLEAN NOT NULL, mia_only BOOLEAN NOT NULL, direction VARCHAR,
    start_at TIMESTAMPTZ, end_at TIMESTAMPTZ, state VARCHAR, records_written BIGINT, output_written BOOLEAN NOT NULL,
    files JSON
);
CREATE TABLE manifest_gaps (
    gap_key VARCHAR PRIMARY KEY, unit_key VARCHAR NOT NULL, ordinal INTEGER NOT NULL, start_at TIMESTAMPTZ,
    end_at TIMESTAMPTZ, reason VARCHAR, detail VARCHAR, attempts BIGINT, records_in_window BIGINT, search_id VARCHAR,
    widened BOOLEAN NOT NULL
);

COMMENT ON TABLE manifest_runs IS 'One run of a Microsoft-Extractor-Suite cmdlet, from its CollectionManifest-<GUID>.mesmanifest file (JSON written by the collector itself, so its text is not trusted). The collector records what it was asked to collect and what it could not; a run with status partial or failed means the export is incomplete over some ranges. The same manifest seen twice (re-import, copied folder) is one row with two sightings in record_sources; a second file with the same run_id but different content is only a sighting plus a warning.';
COMMENT ON COLUMN manifest_runs.run_id IS 'run_id as written (a GUID): the run''s key.';
COMMENT ON COLUMN manifest_runs.collection_id IS 'Collection in which the manifest was first loaded.';
COMMENT ON COLUMN manifest_runs.file_id IS 'source_files row of the manifest file that was loaded first.';
COMMENT ON COLUMN manifest_runs.schema IS 'schema as written (mes-collection-manifest/1).';
COMMENT ON COLUMN manifest_runs.supported IS 'True when the schema major version is 1. An unsupported manifest keeps its run row and raw but has no units or gaps and never vouches for anything.';
COMMENT ON COLUMN manifest_runs.tool IS 'tool as written (Microsoft-Extractor-Suite).';
COMMENT ON COLUMN manifest_runs.tool_version IS 'tool_version as written.';
COMMENT ON COLUMN manifest_runs.fork IS 'fork as written: the collector build that wrote the manifest.';
COMMENT ON COLUMN manifest_runs.cmdlet IS 'The cmdlet that ran (Get-UALGraph, Get-MailboxAuditLog, ...). Collector text, not trusted.';
COMMENT ON COLUMN manifest_runs.parameters IS 'The cmdlet parameters as recorded (secrets are left out by the collector), as a JSON object. Collector text, not trusted.';
COMMENT ON COLUMN manifest_runs.started_at IS 'started_utc: when the run started (NULL when missing or unparseable; the file warning says so).';
COMMENT ON COLUMN manifest_runs.finished_at IS 'finished_utc: when the run ended (NULL when the run never saved its end).';
COMMENT ON COLUMN manifest_runs.status IS 'Run outcome as written: complete, partial, failed or search_only. Other values are kept as written and treated as failed.';
COMMENT ON COLUMN manifest_runs.throttle_wait_count IS 'throttle_waits.count: how many times the run waited for service throttling.';
COMMENT ON COLUMN manifest_runs.throttle_wait_seconds IS 'throttle_waits.total_seconds: the total time spent waiting.';
COMMENT ON COLUMN manifest_runs.raw IS 'The whole manifest document as first loaded.';
COMMENT ON TABLE manifest_units IS 'One work unit of a run: a set of sources x a scope x a half-open time range [start_at, end_at), with its outcome. Only units with output_written vouch for their range, and only when complete or partial (a partial unit vouches for its range minus its gaps).';
COMMENT ON COLUMN manifest_units.unit_key IS 'run_id || ''/'' || unit_id.';
COMMENT ON COLUMN manifest_units.run_id IS 'manifest_runs.run_id.';
COMMENT ON COLUMN manifest_units.unit_id IS 'unit_id as written (u-0001, ...).';
COMMENT ON COLUMN manifest_units.sources IS 'JSON array of the evidence sources the unit collected (ual, signins, mail_items_accessed, message_trace, ...), as written. signins_service_principal and signins_managed_identity are kept but are not coverage sources.';
COMMENT ON COLUMN manifest_units.scope IS 'The unit''s scope object as written (user_ids, operations, record_types, ip_addresses, session_ids, event_type, direction, other_filters).';
COMMENT ON COLUMN manifest_units.user_ids IS 'scope.user_ids as a JSON array, each trimmed and lower-cased. NULL means every account (tenant-wide).';
COMMENT ON COLUMN manifest_units.narrowed IS 'True when the scope filters the records (operations, record_types, ip_addresses, session_ids or other_filters set). A narrowed unit does not vouch for an account''s coverage. event_type and direction do not narrow. False for a MailItemsAccessed-only unit (see mia_only).';
COMMENT ON COLUMN manifest_units.mia_only IS 'True when operations is exactly [MailItemsAccessed] (any case) and nothing else narrows the unit: it vouches mail_items_accessed only, never ual.';
COMMENT ON COLUMN manifest_units.direction IS 'scope.direction as written (sender or recipient for message trace), NULL when absent.';
COMMENT ON COLUMN manifest_units.start_at IS 'start_utc of the range (inclusive). NULL when the range is not RFC 3339 or end <= start; such a unit vouches nothing. A time without a zone is read as UTC (the file warning says so).';
COMMENT ON COLUMN manifest_units.end_at IS 'end_utc of the range (exclusive); NULL under the same conditions as start_at.';
COMMENT ON COLUMN manifest_units.state IS 'Unit outcome as written: complete, partial, failed, not_started or search_only. Other values are kept as written and treated as failed.';
COMMENT ON COLUMN manifest_units.records_written IS 'How many records the unit wrote to its files.';
COMMENT ON COLUMN manifest_units.output_written IS 'False when the unit wrote no output file (for example a search-only unit); such a unit never vouches and never raises a gap.';
COMMENT ON COLUMN manifest_units.files IS 'JSON array of the output files the unit wrote, relative to the manifest folder (or absolute). Collector text, not trusted.';
COMMENT ON TABLE manifest_gaps IS 'A range a unit could not collect, half-open [start_at, end_at). The collector lists them so that absence of events in them is not read as absence of activity.';
COMMENT ON COLUMN manifest_gaps.gap_key IS 'unit_key || ''/'' || ordinal.';
COMMENT ON COLUMN manifest_gaps.unit_key IS 'manifest_units.unit_key.';
COMMENT ON COLUMN manifest_gaps.ordinal IS 'Position of the gap in its unit (from 0).';
COMMENT ON COLUMN manifest_gaps.start_at IS 'start_utc of the gap. When the gap''s own range is bad it is the unit''s start (widened = true); NULL when the unit''s range is bad too.';
COMMENT ON COLUMN manifest_gaps.end_at IS 'end_utc of the gap, widened under the same rule.';
COMMENT ON COLUMN manifest_gaps.reason IS 'retries_exhausted, cap_exceeded, search_failed, search_timeout, download_incomplete, write_failed or aborted. Other values are kept as written and treated like failed.';
COMMENT ON COLUMN manifest_gaps.detail IS 'Collector''s free-text explanation. Collector text, not trusted.';
COMMENT ON COLUMN manifest_gaps.attempts IS 'How many attempts the collector made.';
COMMENT ON COLUMN manifest_gaps.records_in_window IS 'Records the service reported for the window, when known.';
COMMENT ON COLUMN manifest_gaps.search_id IS 'Service search id that can resume the download (Get-UALGraph), when recorded.';
COMMENT ON COLUMN manifest_gaps.widened IS 'True when the gap''s own range was missing, unparseable or reversed and the unit''s range was used instead (the conservative reading).';
