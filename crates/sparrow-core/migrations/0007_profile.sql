-- 0007: Phase 4 (tenant profile and enrichment). Same conventions as 0004-0006: no key
-- constraints; loaders and the profile step keep keys unique. Later Phase 4 tasks append
-- their DDL below, each under a "-- Task N:" line.

-- Task 1: which time columns were stored as if UTC. Added before the org-key rekeying below:
-- DuckDB will not let one transaction both UPDATE a table's rows and ALTER TABLE it.
ALTER TABLE users ADD COLUMN tz_assumed JSON;
ALTER TABLE role_assignments ADD COLUMN tz_assumed JSON;
ALTER TABLE oauth_grants ADD COLUMN tz_assumed JSON;
ALTER TABLE app_credentials ADD COLUMN tz_assumed JSON;
ALTER TABLE inbox_rules ADD COLUMN tz_assumed JSON;
ALTER TABLE mailboxes ADD COLUMN tz_assumed JSON;
ALTER TABLE audit_config ADD COLUMN tz_assumed JSON;
ALTER TABLE tenant_settings ADD COLUMN tz_assumed JSON;
ALTER TABLE transport_rules ADD COLUMN tz_assumed JSON;
ALTER TABLE remote_domains ADD COLUMN tz_assumed JSON;
ALTER TABLE mobile_devices ADD COLUMN tz_assumed JSON;
ALTER TABLE risky_users ADD COLUMN tz_assumed JSON;
ALTER TABLE risk_detections ADD COLUMN tz_assumed JSON;
ALTER TABLE collector_flags ADD COLUMN tz_assumed JSON;
ALTER TABLE signins ADD COLUMN tz_assumed JSON;
ALTER TABLE directory_audits ADD COLUMN tz_assumed JSON;
ALTER TABLE message_trace ADD COLUMN tz_assumed JSON;
ALTER TABLE mailbox_audit_legacy ADD COLUMN tz_assumed JSON;
ALTER TABLE admin_audit_events ADD COLUMN tz_assumed JSON;
ALTER TABLE mailbox_permissions ADD COLUMN tz_assumed JSON;

COMMENT ON COLUMN users.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN role_assignments.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN oauth_grants.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN app_credentials.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN inbox_rules.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN mailboxes.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN audit_config.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN tenant_settings.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN transport_rules.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN remote_domains.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN mobile_devices.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN risky_users.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN risk_detections.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN collector_flags.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN signins.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN directory_audits.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN message_trace.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN mailbox_audit_legacy.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN admin_audit_events.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON COLUMN mailbox_permissions.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';

-- Task 1: org-level state per collection (a case may hold captures of several tenants; the
-- tenant_* views of Task 3 merge them per tenant). Sightings follow their rows.
UPDATE record_sources SET record_key = 'organization|' || a.collection_id
FROM audit_config a
WHERE record_sources.table_name = 'audit_config' AND record_sources.record_key = 'organization'
  AND a.record_key = 'organization';
UPDATE audit_config SET record_key = 'organization|' || collection_id WHERE record_key = 'organization';
UPDATE record_sources SET record_key = s.collection_id || '|' || s.record_key
FROM tenant_settings s
WHERE record_sources.table_name = 'tenant_settings' AND record_sources.record_key = s.record_key;
UPDATE tenant_settings SET record_key = collection_id || '|' || record_key;

COMMENT ON TABLE audit_config IS 'Organization audit configuration reported by one collection (AdminAuditLogConfig, OrganizationConfig, Microsoft-Extractor-Suite security defaults and mailbox audit status). One row per collection; view tenant_audit_config merges them per tenant, newest collection first.';
COMMENT ON COLUMN audit_config.record_key IS 'organization|<collection_id>. Cases ingested before schema 7 keep one row that merged every collection, keyed by the collection that last wrote it.';
COMMENT ON TABLE tenant_settings IS 'Name/value tenant settings reported by one collection: every AdminAuditLogConfig, OrganizationConfig and TransportConfig property, Microsoft-Extractor-Suite security defaults, and Exchange management role entries. View tenant_settings_current keeps the newest value per tenant.';
COMMENT ON COLUMN tenant_settings.record_key IS '<collection_id>|<source>|<lower name>.';

-- Task 2: capability definitions (data/capabilities.yaml plus --data overrides).
CREATE TABLE capabilities (
    capability_id VARCHAR NOT NULL, title VARCHAR NOT NULL, baseline BOOLEAN NOT NULL,
    unlocked_by_service_plans VARCHAR[], hawk_license_tiers VARCHAR[], retention_days INTEGER,
    evidence VARCHAR[], notes VARCHAR, sources VARCHAR[], as_of DATE, origin VARCHAR NOT NULL
);
COMMENT ON TABLE capabilities IS 'Licensing and retention facts (data/capabilities.yaml, embedded; --data DIR overrides entries by id). Rewritten by every profile run (sparrow ingest / sparrow profile).';
COMMENT ON COLUMN capabilities.capability_id IS 'Capability id (ual_standard, audit_premium, entra_id_p1, identity_protection, ...).';
COMMENT ON COLUMN capabilities.title IS 'Human-readable name.';
COMMENT ON COLUMN capabilities.baseline IS 'Assumed present in every Microsoft 365 tenant with Exchange Online unless a high-confidence licence list proves otherwise.';
COMMENT ON COLUMN capabilities.unlocked_by_service_plans IS 'Graph subscribedSkus service plan names that unlock it.';
COMMENT ON COLUMN capabilities.hawk_license_tiers IS 'Hawk.log licence tiers (E5, G5, E3, G3) that suggest it (low confidence).';
COMMENT ON COLUMN capabilities.retention_days IS 'Days the evidence stays retrievable from Microsoft 365; NULL for current-state data.';
COMMENT ON COLUMN capabilities.evidence IS 'evidence_availability ids this capability provides.';
COMMENT ON COLUMN capabilities.notes IS 'Caveats (SKU lists, contradictions in Microsoft documentation).';
COMMENT ON COLUMN capabilities.sources IS 'Microsoft Learn (or Microsoft blog) URLs the facts were verified against.';
COMMENT ON COLUMN capabilities.as_of IS 'Date the facts were last verified.';
COMMENT ON COLUMN capabilities.origin IS 'builtin, or the path of the external file that supplied the entry.';
