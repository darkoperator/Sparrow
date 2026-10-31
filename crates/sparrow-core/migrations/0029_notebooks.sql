-- Migration 29: SQL notebooks. A case notebook is a named, ordered list of saved queries (plain SQL with a comment
-- block and [placeholders]). The built-in notebook ships with Sparrow and is not stored here. Written only through
-- sparrow_core::case::notebooks, each change with one audit_trail row. Agents may only add queries and import
-- notebooks; renaming, reordering and deleting are the analyst's. A saved query asserts nothing about the case, so it
-- has no review state.
CREATE TABLE notebooks (
    notebook_id VARCHAR PRIMARY KEY,
    name VARCHAR NOT NULL,
    decided_by VARCHAR NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL,
    on_behalf_of VARCHAR
);

CREATE TABLE notebook_queries (
    query_id VARCHAR PRIMARY KEY,
    notebook_id VARCHAR NOT NULL,
    position INTEGER NOT NULL,
    sql VARCHAR NOT NULL,
    decided_by VARCHAR NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL,
    on_behalf_of VARCHAR
);

COMMENT ON TABLE notebooks IS 'Case notebooks: named lists of saved SQL queries (the built-in notebook is not stored). Names are unique case-insensitively and never "Built-in". Written only through sparrow_core::case::notebooks, with one audit_trail row per change (object_type notebook).';
COMMENT ON COLUMN notebooks.notebook_id IS '16 hex characters of a SHA-256 over the name, the creator and the time.';
COMMENT ON COLUMN notebooks.name IS 'The notebook''s name as the analyst or agent wrote it (one line, at most 500 characters).';
COMMENT ON COLUMN notebooks.decided_by IS 'agent:<id> or analyst:<name> who created the notebook (an import creates one).';
COMMENT ON COLUMN notebooks.decided_at IS 'When decided_by created it (the audit_trail entry time).';
COMMENT ON COLUMN notebooks.on_behalf_of IS 'analyst:<name> an agent worked for; NULL for an analyst''s own.';

COMMENT ON TABLE notebook_queries IS 'The saved queries of the case notebooks, in order. The text is stored as written: a -- comment block (its first line is the title), then the SQL, with [placeholders] the analyst fills in before running. Never run on write; runs go through the read-only query path. One audit_trail row per change (object_type notebook_query).';
COMMENT ON COLUMN notebook_queries.query_id IS '16 hex characters of a SHA-256 over the notebook, the text, the author and the time.';
COMMENT ON COLUMN notebook_queries.notebook_id IS 'notebooks.notebook_id of the notebook holding it.';
COMMENT ON COLUMN notebook_queries.position IS 'Place in the notebook, 1..n without gaps.';
COMMENT ON COLUMN notebook_queries.sql IS 'The query text: comment block and SQL, at most 64 KiB, never holding the line "-- ==== query ====" (the export file''s separator).';
COMMENT ON COLUMN notebook_queries.decided_by IS 'agent:<id> or analyst:<name> who saved the query.';
COMMENT ON COLUMN notebook_queries.decided_at IS 'When decided_by saved it (the audit_trail entry time).';
COMMENT ON COLUMN notebook_queries.on_behalf_of IS 'analyst:<name> an agent worked for; NULL for an analyst''s own.';

COMMENT ON COLUMN audit_trail.object_type IS 'Kind of object changed: finding, indicator, timeline_entry, annotation, case, audit_trail, share_bundle, device_status (object_id is the device id), notebook and notebook_query (object_id is the notebook or query id), or a mark: event_flag and event_tag (object_id is the id of one call that marked many rows) and value_flag (object_id is the flag_id).';
COMMENT ON COLUMN audit_trail.action IS 'What was done: schema_upgrade, acknowledge_break, or an agent or analyst decision or review action (set_status, add_ioc, flag_rows, flag_value, tag_rows, set_device_status, clear_device_status, review_accept, create_notebook, add_notebook_query, import_notebook, ...).';
