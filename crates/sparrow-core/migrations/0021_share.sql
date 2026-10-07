-- Migration 21: share bundles (Phase 8). An imported bundle's items are proposals: they change nothing until the
-- analyst accepts one (applied as that analyst's decision) or discards it.
CREATE TABLE imported_proposals (
    bundle_sha256 VARCHAR NOT NULL,
    item_key VARCHAR NOT NULL,
    source_analyst VARCHAR NOT NULL,
    source_case_id VARCHAR NOT NULL,
    exported_at TIMESTAMPTZ NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL,
    item JSON NOT NULL,
    current JSON,
    classification VARCHAR NOT NULL,
    state VARCHAR NOT NULL,
    decided_by VARCHAR,
    decided_at TIMESTAMPTZ,
    applied_entry_id VARCHAR,
    PRIMARY KEY (bundle_sha256, item_key)
);
COMMENT ON TABLE imported_proposals IS 'Items of share bundles imported from another analyst (same evidence), one row per bundle and item. Written only by sparrow_core::case::share; every import, accept and discard is audited.';
COMMENT ON COLUMN imported_proposals.bundle_sha256 IS 'hex SHA-256 of the bundle file as imported.';
COMMENT ON COLUMN imported_proposals.item_key IS 'The item''s stable key: finding:<id>, indicator: followed by the compact JSON array [tenant_key or null, type, value], timeline_entry:<id> or note:<hash>.';
COMMENT ON COLUMN imported_proposals.source_analyst IS 'analyst:<name> who exported the bundle (a claim, as every actor name).';
COMMENT ON COLUMN imported_proposals.source_case_id IS 'case_id of the exporting case.';
COMMENT ON COLUMN imported_proposals.exported_at IS 'When the bundle was exported (UTC).';
COMMENT ON COLUMN imported_proposals.imported_at IS 'When this case imported it (UTC).';
COMMENT ON COLUMN imported_proposals.item IS 'The proposed state (the bundle item as JSON).';
COMMENT ON COLUMN imported_proposals.current IS 'This case''s state of the same object at import time (NULL when it had none).';
COMMENT ON COLUMN imported_proposals.classification IS 'new (this case has nothing), agrees (same value), conflict (different value) or missing (the object does not exist here).';
COMMENT ON COLUMN imported_proposals.state IS 'open, accepted, discarded, superseded (a newer bundle from the same analyst proposes the same item) or agrees (nothing to do).';
COMMENT ON COLUMN imported_proposals.decided_by IS 'analyst:<name> who accepted or discarded it.';
COMMENT ON COLUMN imported_proposals.decided_at IS 'When it was accepted or discarded (UTC).';
COMMENT ON COLUMN imported_proposals.applied_entry_id IS 'For an accepted timeline entry: the entry_id it became in this case (entry ids are per case), so a later bundle from the same source case matches it; NULL otherwise.';
COMMENT ON COLUMN findings.decided_by IS 'agent:<id> or analyst:<name> that last set an analyst field (status, disposition, assignment, rule_updated ack); NULL while only detection has touched the finding.';
COMMENT ON COLUMN case_indicators.decided_by IS 'agent:<id> or analyst:<name> of the last decision on the indicator; rows from earlier cases keep their added_by.';
COMMENT ON COLUMN timeline_entries.decided_by IS 'agent:<id> or analyst:<name> of the last decision on the entry.';
COMMENT ON COLUMN annotations.actor IS 'agent:<id> or analyst:<name> that wrote the note.';
COMMENT ON COLUMN audit_trail.actor IS 'agent:<id> for every CLI write, analyst:<name> for a review or an analyst decision in the review app, system:upgrade for the schema upgrade.';
