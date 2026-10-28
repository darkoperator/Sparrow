-- Migration 26: analyst marks on events. Flags (Suspicious / Malicious) on single event rows and standing flags on a
-- value (an IP, its /24 or /48, an account, an ASN, a device or an Entra session), and free-text tags. Marks key on
-- (source_table, record_key) or on a value, never on the derived events table, so they survive an events rebuild and a
-- re-ingest. Every write is an analyst or agent decision with the Phase 7 provenance fields and one audit_trail row per
-- action (never per event); an agent's mark is pending_review until confirmed in the events grid (case::marks). Evidence
-- tables are never written.
CREATE TYPE flag_level AS ENUM ('suspicious', 'malicious');
CREATE TYPE flag_value_kind AS ENUM ('ip', 'ip_prefix', 'account', 'asn', 'device', 'session');

CREATE TABLE event_flags (
    source_table VARCHAR NOT NULL, record_key VARCHAR NOT NULL, level flag_level NOT NULL,
    decided_by VARCHAR NOT NULL, decided_at TIMESTAMPTZ NOT NULL, on_behalf_of VARCHAR,
    review_state review_state NOT NULL, reviewed_by VARCHAR, reviewed_at TIMESTAMPTZ, review_comment VARCHAR,
    batch_id VARCHAR NOT NULL,
    PRIMARY KEY (source_table, record_key)
);

CREATE TABLE value_flags (
    flag_id VARCHAR PRIMARY KEY, kind flag_value_kind NOT NULL, value VARCHAR NOT NULL, level flag_level NOT NULL,
    scope_kind VARCHAR, scope_value VARCHAR,
    decided_by VARCHAR NOT NULL, decided_at TIMESTAMPTZ NOT NULL, on_behalf_of VARCHAR,
    review_state review_state NOT NULL, reviewed_by VARCHAR, reviewed_at TIMESTAMPTZ, review_comment VARCHAR,
    removed_at TIMESTAMPTZ, removed_by VARCHAR
);

CREATE TABLE tags (
    tag_id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL UNIQUE, created_by VARCHAR NOT NULL, created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE event_tags (
    tag_id VARCHAR NOT NULL, source_table VARCHAR NOT NULL, record_key VARCHAR NOT NULL,
    decided_by VARCHAR NOT NULL, decided_at TIMESTAMPTZ NOT NULL, on_behalf_of VARCHAR,
    review_state review_state NOT NULL, reviewed_by VARCHAR, reviewed_at TIMESTAMPTZ, review_comment VARCHAR,
    batch_id VARCHAR NOT NULL,
    PRIMARY KEY (tag_id, source_table, record_key)
);

COMMENT ON TYPE flag_level IS 'How suspicious an event or value was judged: suspicious (amber) or malicious (red). Malicious is the stronger.';
COMMENT ON TYPE flag_value_kind IS 'What a standing value flag matches: an ip, its ip_prefix (a.b.c.0/24 or the /48 network text), an account (actor or mailbox owner), an asn, a device (device id or directory object id) or an Entra session.';

COMMENT ON TABLE event_flags IS 'Flags on single event rows, keyed by (source_table, record_key) like the events table but independent of it, so a flag survives an events rebuild and a re-ingest. One flag per row. Written only through sparrow_core::case::marks; a clear deletes the row and the audit_trail keeps what was removed. An agent''s flag is pending_review until confirmed (accepted) or removed (the row is deleted, or restored to what it was before the agent changed it) with case::review; it is not a Review-queue item.';
COMMENT ON COLUMN event_flags.source_table IS 'Evidence table of the flagged event (events.source_table).';
COMMENT ON COLUMN event_flags.record_key IS 'Key of the flagged event in that table (events.record_key).';
COMMENT ON COLUMN event_flags.level IS 'suspicious or malicious. A row''s effective flag is the strongest of this and every standing value flag that matches it.';
COMMENT ON COLUMN event_flags.decided_by IS 'analyst:<name> or agent:<id> that set the flag.';
COMMENT ON COLUMN event_flags.decided_at IS 'When decided_by set it (the audit_trail entry time).';
COMMENT ON COLUMN event_flags.on_behalf_of IS 'analyst:<name> named by the agent as the reviewer of its decision; not an identity claim.';
COMMENT ON COLUMN event_flags.review_state IS 'accepted for an analyst''s own flag; pending_review for an agent''s until an analyst accepts it (a removal deletes the row, so discarded is not kept here).';
COMMENT ON COLUMN event_flags.reviewed_by IS 'analyst:<name> who accepted the flag.';
COMMENT ON COLUMN event_flags.reviewed_at IS 'When reviewed_by accepted it.';
COMMENT ON COLUMN event_flags.review_comment IS 'The reviewer''s comment.';
COMMENT ON COLUMN event_flags.batch_id IS 'The audit_trail object_id (object_type event_flag) of the one decision that set this row; a review names that decision.';

COMMENT ON TABLE value_flags IS 'Standing flags on a value: every event whose column matches the value is flagged, including events ingested later. A scope (scope_kind, scope_value: account, ip, device or session) limits the flag to that entity''s events; both NULL is case-wide. Clearing sets removed_at and leaves direct event_flags alone. Written only through sparrow_core::case::marks; a malicious flag on an ip or account also adds a case_indicators row (asn, ip_prefix, device and session make none: indicator_type has no such kinds).';
COMMENT ON COLUMN value_flags.flag_id IS 'Hex id from the kind, value and scope, so the same flag made again updates the same row.';
COMMENT ON COLUMN value_flags.kind IS 'What the value is: ip, ip_prefix, account, asn, device or session.';
COMMENT ON COLUMN value_flags.value IS 'The value in its stored spelling: IP as normalize_ip, prefix as in events.ip_prefix, account/device/session lower case, ASN as digits.';
COMMENT ON COLUMN value_flags.level IS 'suspicious or malicious.';
COMMENT ON COLUMN value_flags.scope_kind IS 'account, ip, device or session when the flag was made inside that entity''s tab and covers only its events; NULL for a case-wide flag.';
COMMENT ON COLUMN value_flags.scope_value IS 'The scope entity''s value, in the spelling of case::events::Entity::normalized; NULL when case-wide.';
COMMENT ON COLUMN value_flags.decided_by IS 'analyst:<name> or agent:<id> of the last decision on the flag.';
COMMENT ON COLUMN value_flags.decided_at IS 'When decided_by made that decision.';
COMMENT ON COLUMN value_flags.on_behalf_of IS 'analyst:<name> named by the agent as the reviewer of its decision; not an identity claim.';
COMMENT ON COLUMN value_flags.review_state IS 'accepted for an analyst''s decision; pending_review after an agent''s until accepted or discarded with case::review. After a discard decided_by keeps naming the discarded decision.';
COMMENT ON COLUMN value_flags.reviewed_by IS 'analyst:<name> who accepted or discarded the decision.';
COMMENT ON COLUMN value_flags.reviewed_at IS 'When reviewed_by accepted or discarded it.';
COMMENT ON COLUMN value_flags.review_comment IS 'The reviewer''s comment.';
COMMENT ON COLUMN value_flags.removed_at IS 'Soft delete: set when the flag was cleared; only rows where it is NULL flag events.';
COMMENT ON COLUMN value_flags.removed_by IS 'Who cleared it.';

COMMENT ON TABLE tags IS 'Case-wide free-text tag names for events. A name exists while some event carries it (the last removal deletes it). Written only through sparrow_core::case::marks.';
COMMENT ON COLUMN tags.tag_id IS 'Hex id from the name.';
COMMENT ON COLUMN tags.name IS 'Lower case, trimmed, 1 to 64 characters, no control characters. An agent may create only names starting ai:.';
COMMENT ON COLUMN tags.created_by IS 'analyst:<name> or agent:<id> that first used the name.';
COMMENT ON COLUMN tags.created_at IS 'When the name was first used.';

COMMENT ON TABLE event_tags IS 'Tags on single event rows, keyed by (source_table, record_key) like event_flags. Written only through sparrow_core::case::marks. An agent''s tag is pending_review until confirmed (accepted) or removed (the row is deleted) with case::review; it is not a Review-queue item.';
COMMENT ON COLUMN event_tags.tag_id IS 'The tag (tags.tag_id).';
COMMENT ON COLUMN event_tags.source_table IS 'Evidence table of the tagged event (events.source_table).';
COMMENT ON COLUMN event_tags.record_key IS 'Key of the tagged event in that table (events.record_key).';
COMMENT ON COLUMN event_tags.decided_by IS 'analyst:<name> or agent:<id> that applied the tag.';
COMMENT ON COLUMN event_tags.decided_at IS 'When decided_by applied it (the audit_trail entry time).';
COMMENT ON COLUMN event_tags.on_behalf_of IS 'analyst:<name> named by the agent as the reviewer of its decision; not an identity claim.';
COMMENT ON COLUMN event_tags.review_state IS 'accepted for an analyst''s own tag; pending_review for an agent''s until an analyst accepts it.';
COMMENT ON COLUMN event_tags.reviewed_by IS 'analyst:<name> who accepted the tag.';
COMMENT ON COLUMN event_tags.reviewed_at IS 'When reviewed_by accepted it.';
COMMENT ON COLUMN event_tags.review_comment IS 'The reviewer''s comment.';
COMMENT ON COLUMN event_tags.batch_id IS 'The audit_trail object_id (object_type event_tag) of the one decision that applied this row; a review names that decision.';

COMMENT ON COLUMN audit_trail.object_type IS 'Kind of object changed: finding, indicator, timeline_entry, annotation, case, audit_trail, or a mark: event_flag and event_tag (object_id is the id of one call that marked many rows) and value_flag (object_id is the flag_id).';
COMMENT ON COLUMN audit_trail.action IS 'What was done: schema_upgrade, acknowledge_break, or an agent or analyst decision or review action (set_status, add_ioc, flag_rows, flag_value, tag_rows, review_accept, ...).';
