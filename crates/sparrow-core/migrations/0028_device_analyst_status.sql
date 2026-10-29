-- Migration 28: the analyst's status of a device (Removed, Disabled, Confirmed attacker, Benign), recorded next to the
-- status Sparrow computes from the evidence (case::devices) and never replacing it. One row per decision: setting a new
-- status closes the live row and adds one, clearing closes it, so at most one row per device id has removed_at NULL.
-- Analyst decisions only (no agent writes it), each with one audit_trail row (object_type device_status).
CREATE TYPE device_verdict AS ENUM ('removed', 'disabled', 'confirmed_attacker', 'benign');

CREATE TABLE device_analyst_status (
    decision_id BIGINT PRIMARY KEY,
    device_id VARCHAR NOT NULL,
    status device_verdict NOT NULL,
    note VARCHAR,
    decided_by VARCHAR NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL,
    removed_at TIMESTAMPTZ,
    removed_by VARCHAR
);

COMMENT ON TYPE device_verdict IS 'What the analyst says of a device: removed or disabled (in the tenant, by the responders), confirmed_attacker (the attacker''s device, not yet acted on) or benign.';

COMMENT ON TABLE device_analyst_status IS 'The analyst''s status of a device, shown next to the computed lifecycle status of case::devices and never replacing it. One row per decision; the live one (removed_at NULL) is the current status, at most one per device_id. Written only through sparrow_core::case::device_status, by an analyst, with one audit_trail row per change (object_type device_status, object_id the device id).';
COMMENT ON COLUMN device_analyst_status.decision_id IS 'Sequential id of the decision within the case (1, 2, ...).';
COMMENT ON COLUMN device_analyst_status.device_id IS 'The device as an entity tab names it: the device id, else the directory object id, lower case and trimmed.';
COMMENT ON COLUMN device_analyst_status.status IS 'removed, disabled, confirmed_attacker or benign. A sighting later than decided_at on a removed or disabled device is shown as active after the analyst''s removal.';
COMMENT ON COLUMN device_analyst_status.note IS 'The analyst''s optional note (at most 16 KiB); NULL when none.';
COMMENT ON COLUMN device_analyst_status.decided_by IS 'analyst:<name> who set the status.';
COMMENT ON COLUMN device_analyst_status.decided_at IS 'When decided_by set it (the audit_trail entry time).';
COMMENT ON COLUMN device_analyst_status.removed_at IS 'Soft delete: when the status was replaced by a newer one or cleared; NULL for the live row.';
COMMENT ON COLUMN device_analyst_status.removed_by IS 'analyst:<name> whose change replaced or cleared it.';

COMMENT ON COLUMN audit_trail.object_type IS 'Kind of object changed: finding, indicator, timeline_entry, annotation, case, audit_trail, share_bundle, device_status (object_id is the device id), or a mark: event_flag and event_tag (object_id is the id of one call that marked many rows) and value_flag (object_id is the flag_id).';
COMMENT ON COLUMN audit_trail.action IS 'What was done: schema_upgrade, acknowledge_break, or an agent or analyst decision or review action (set_status, add_ioc, flag_rows, flag_value, tag_rows, set_device_status, clear_device_status, review_accept, ...).';
