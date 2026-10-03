-- Migration 16: Phase 7 agent workflow (Addendum D.3). Decision provenance, review state, audit trail, curated
-- timeline, notes. (The plan calls this "migration 15"; 15 was taken by the Phase 6 spray tuning.)
CREATE TYPE review_state AS ENUM ('pending_review', 'accepted', 'discarded');
CREATE TYPE timeline_entry_status AS ENUM ('proposed', 'verified', 'rejected', 'superseded');
CREATE TYPE attack_phase AS ENUM ('initial_access', 'persistence', 'defense_evasion', 'recon', 'collection', 'exfiltration', 'impact', 'remediation');
CREATE TYPE annotation_object AS ENUM ('evidence', 'finding', 'timeline_entry', 'indicator');

CREATE TABLE case_meta (key VARCHAR PRIMARY KEY, value VARCHAR NOT NULL);
INSERT INTO case_meta VALUES ('case_id', CAST(gen_random_uuid() AS VARCHAR));

CREATE TABLE audit_trail (
    seq BIGINT PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    actor VARCHAR NOT NULL,
    on_behalf_of VARCHAR,
    action VARCHAR NOT NULL,
    object_type VARCHAR NOT NULL,
    object_id VARCHAR NOT NULL,
    before JSON,
    after JSON,
    reason VARCHAR,
    prev_hash VARCHAR NOT NULL,
    hash VARCHAR NOT NULL
);

ALTER TABLE findings ADD COLUMN decided_by VARCHAR;
ALTER TABLE findings ADD COLUMN decided_at TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN on_behalf_of VARCHAR;
ALTER TABLE findings ADD COLUMN review_state review_state;
ALTER TABLE findings ADD COLUMN reviewed_by VARCHAR;
ALTER TABLE findings ADD COLUMN reviewed_at TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN review_comment VARCHAR;

ALTER TABLE case_indicators ADD COLUMN decided_by VARCHAR;
ALTER TABLE case_indicators ADD COLUMN decided_at TIMESTAMPTZ;
ALTER TABLE case_indicators ADD COLUMN on_behalf_of VARCHAR;
ALTER TABLE case_indicators ADD COLUMN review_state review_state;
ALTER TABLE case_indicators ADD COLUMN reviewed_by VARCHAR;
ALTER TABLE case_indicators ADD COLUMN reviewed_at TIMESTAMPTZ;
ALTER TABLE case_indicators ADD COLUMN review_comment VARCHAR;
ALTER TABLE case_indicators ADD COLUMN removed_at TIMESTAMPTZ;
ALTER TABLE case_indicators ADD COLUMN removed_by VARCHAR;
UPDATE case_indicators SET decided_by = added_by, decided_at = added_at, review_state = 'pending_review';

CREATE TABLE timeline_entries (
    entry_id VARCHAR PRIMARY KEY,
    tenant_key VARCHAR,
    event_time TIMESTAMPTZ NOT NULL,
    title VARCHAR NOT NULL,
    narrative VARCHAR,
    phase attack_phase NOT NULL,
    status timeline_entry_status NOT NULL DEFAULT 'proposed',
    supersedes VARCHAR,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    decided_by VARCHAR NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL,
    on_behalf_of VARCHAR,
    review_state review_state NOT NULL DEFAULT 'pending_review',
    reviewed_by VARCHAR,
    reviewed_at TIMESTAMPTZ,
    review_comment VARCHAR
);

CREATE TABLE timeline_entry_evidence (
    entry_id VARCHAR NOT NULL,
    source_table VARCHAR NOT NULL,
    record_key VARCHAR NOT NULL,
    PRIMARY KEY (entry_id, source_table, record_key)
);

CREATE TABLE annotations (
    annotation_id VARCHAR PRIMARY KEY,
    object_type annotation_object NOT NULL,
    object_id VARCHAR NOT NULL,
    source_table VARCHAR,
    text VARCHAR NOT NULL,
    actor VARCHAR NOT NULL,
    on_behalf_of VARCHAR,
    created_at TIMESTAMPTZ NOT NULL
);

COMMENT ON TABLE audit_trail IS 'Append-only, SHA-256 hash-chained record of every agent decision and review (Addendum D.3). Written only by sparrow_core::case::audit inside the same transaction as the change. Detection is not audited here (see detection_runs).';
COMMENT ON COLUMN audit_trail.seq IS 'Dense sequence from 1; a gap is a deleted entry.';
COMMENT ON COLUMN audit_trail.actor IS 'agent:<id> for every CLI write, analyst:<name> for a core review, system:upgrade for the schema upgrade.';
COMMENT ON COLUMN audit_trail.on_behalf_of IS 'analyst:<name> responsible for reviewing an agent decision (not an identity claim); NULL when none was given.';
COMMENT ON COLUMN audit_trail.before IS 'The object''s state before the change (canonical JSON); NULL for a creation.';
COMMENT ON COLUMN audit_trail.after IS 'The object''s state after the change (canonical JSON); NULL for a deletion.';
COMMENT ON COLUMN audit_trail.hash IS 'hex SHA-256 of prev_hash followed by the canonical JSON (sorted keys, no whitespace, UTC RFC 3339 microseconds) of seq, ts, actor, on_behalf_of, action, object_type, object_id, before, after, reason.';
COMMENT ON COLUMN audit_trail.prev_hash IS 'hash of seq-1; for seq 1, hex SHA-256 of "sparrow-audit-genesis" followed by case_meta.case_id.';
COMMENT ON TABLE case_meta IS 'Case-level constants. case_id: random UUID set by migration 16; the audit chain genesis.';
COMMENT ON COLUMN findings.decided_by IS 'agent:<id> that last set an analyst field (status, disposition, assignment, rule_updated ack); NULL while only detection has touched the finding.';
COMMENT ON COLUMN findings.decided_at IS 'When decided_by made that decision.';
COMMENT ON COLUMN findings.on_behalf_of IS 'analyst:<name> named by the agent as the reviewer of its decision; not an identity claim.';
COMMENT ON COLUMN findings.review_state IS 'pending_review after an agent decision; accepted or discarded by a reviewer (core review functions, no CLI); NULL while no decision exists.';
COMMENT ON COLUMN findings.reviewed_by IS 'analyst:<name> who accepted or discarded the decision.';
COMMENT ON COLUMN case_indicators.added_by IS 'Who first added it or last changed its verdict: agent:<id> (Phase 7) or analyst:<name> (earlier cases). See decided_by.';
COMMENT ON COLUMN case_indicators.decided_by IS 'agent:<id> of the last decision on the indicator; rows from earlier cases keep their added_by.';
COMMENT ON COLUMN case_indicators.review_state IS 'pending_review after an agent decision; accepted or discarded by a reviewer.';
COMMENT ON COLUMN case_indicators.removed_at IS 'Soft delete: set when the indicator was removed; rules read only rows where it is NULL.';
COMMENT ON TABLE timeline_entries IS 'Curated timeline entries. Every entry is an agent decision with review state. A verified entry is never edited in place: an edit creates a superseding entry.';
COMMENT ON TABLE timeline_entry_evidence IS 'Evidence rows behind a timeline entry; each (source_table, record_key) matches record_sources. A verified entry has at least one.';
COMMENT ON TABLE annotations IS 'Append-only notes on evidence rows, findings, timeline entries and indicators. No review state.';
COMMENT ON COLUMN audit_trail.ts IS 'When the entry was appended (UTC, microseconds).';
COMMENT ON COLUMN audit_trail.action IS 'What was done: schema_upgrade, acknowledge_break, or an agent decision or review action (set_status, add_ioc, review_accept, ...).';
COMMENT ON COLUMN audit_trail.object_type IS 'Kind of object changed: finding, indicator, timeline_entry, annotation, case or audit_trail.';
COMMENT ON COLUMN audit_trail.object_id IS 'Id of the object changed (finding_id, indicator_id, entry_id, ...; the case_id for schema_upgrade; the first bad seq for acknowledge_break).';
COMMENT ON COLUMN audit_trail.reason IS 'Free-text reason given with the decision or review comment; NULL when none.';
COMMENT ON COLUMN case_meta.key IS 'Constant name (case_id).';
COMMENT ON COLUMN case_meta.value IS 'Constant value.';
COMMENT ON COLUMN findings.reviewed_at IS 'When reviewed_by accepted or discarded the decision.';
COMMENT ON COLUMN findings.review_comment IS 'The reviewer''s comment.';
COMMENT ON COLUMN case_indicators.decided_at IS 'When decided_by made that decision.';
COMMENT ON COLUMN case_indicators.on_behalf_of IS 'analyst:<name> named by the agent as the reviewer of its decision; not an identity claim.';
COMMENT ON COLUMN case_indicators.reviewed_by IS 'analyst:<name> who accepted or discarded the decision.';
COMMENT ON COLUMN case_indicators.reviewed_at IS 'When reviewed_by accepted or discarded the decision.';
COMMENT ON COLUMN case_indicators.review_comment IS 'The reviewer''s comment.';
COMMENT ON COLUMN case_indicators.removed_by IS 'agent:<id> that removed the indicator (soft delete); NULL while active.';
COMMENT ON COLUMN timeline_entries.entry_id IS 'Entry id (hex), stable for the life of the entry.';
COMMENT ON COLUMN timeline_entries.tenant_key IS 'Tenant the entry belongs to; NULL for case-wide entries.';
COMMENT ON COLUMN timeline_entries.event_time IS 'When the described event happened (UTC).';
COMMENT ON COLUMN timeline_entries.title IS 'One-line title of the event.';
COMMENT ON COLUMN timeline_entries.narrative IS 'Free-text description of the event.';
COMMENT ON COLUMN timeline_entries.phase IS 'Attack phase: initial_access, persistence, defense_evasion, recon, collection, exfiltration, impact or remediation.';
COMMENT ON COLUMN timeline_entries.status IS 'proposed, verified (backed by evidence rows), rejected, or superseded (a newer verified entry replaces it).';
COMMENT ON COLUMN timeline_entries.supersedes IS 'entry_id of the verified entry this one replaces once verified; NULL otherwise.';
COMMENT ON COLUMN timeline_entries.created_at IS 'When the entry was proposed.';
COMMENT ON COLUMN timeline_entries.updated_at IS 'When the entry last changed.';
COMMENT ON COLUMN timeline_entries.decided_by IS 'agent:<id> of the last decision on the entry.';
COMMENT ON COLUMN timeline_entries.decided_at IS 'When decided_by made that decision.';
COMMENT ON COLUMN timeline_entries.on_behalf_of IS 'analyst:<name> named by the agent as the reviewer of its decision; not an identity claim.';
COMMENT ON COLUMN timeline_entries.review_state IS 'pending_review after an agent decision; accepted or discarded by a reviewer.';
COMMENT ON COLUMN timeline_entries.reviewed_by IS 'analyst:<name> who accepted or discarded the decision.';
COMMENT ON COLUMN timeline_entries.reviewed_at IS 'When reviewed_by accepted or discarded the decision.';
COMMENT ON COLUMN timeline_entries.review_comment IS 'The reviewer''s comment.';
COMMENT ON COLUMN timeline_entry_evidence.entry_id IS 'The timeline entry (timeline_entries.entry_id).';
COMMENT ON COLUMN timeline_entry_evidence.source_table IS 'Evidence table of the record (record_sources.table_name).';
COMMENT ON COLUMN timeline_entry_evidence.record_key IS 'Record key in that table (record_sources.record_key).';
COMMENT ON COLUMN annotations.annotation_id IS 'Note id (hex).';
COMMENT ON COLUMN annotations.object_type IS 'What the note is on: evidence, finding, timeline_entry or indicator.';
COMMENT ON COLUMN annotations.object_id IS 'Id of that object (the record_key for evidence).';
COMMENT ON COLUMN annotations.source_table IS 'Evidence table of the record (evidence notes only); NULL otherwise.';
COMMENT ON COLUMN annotations.text IS 'The note text, as written.';
COMMENT ON COLUMN annotations.actor IS 'agent:<id> that wrote the note.';
COMMENT ON COLUMN annotations.on_behalf_of IS 'analyst:<name> the agent wrote it on behalf of; not an identity claim.';
COMMENT ON COLUMN annotations.created_at IS 'When the note was written.';
