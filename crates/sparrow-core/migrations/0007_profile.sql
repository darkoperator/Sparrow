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

-- Task 3: tenants.
ALTER TABLE collections ADD COLUMN tenant_key VARCHAR;
COMMENT ON COLUMN collections.tenant_key IS 'Tenant the collection belongs to (tenant.tenant_key), set by the profile step: the tenant id its evidence carries, else name:<reported name>, else collection:<id>.';

CREATE TYPE domain_source AS ENUM ('derived_upn', 'message_trace_org', 'analyst');
CREATE TYPE domain_action AS ENUM ('add', 'remove');

CREATE TABLE tenant (
    tenant_key VARCHAR NOT NULL, tenant_id VARCHAR, tenant_id_source VARCHAR, tenant_name VARCHAR,
    tenant_name_source VARCHAR, collections INTEGER NOT NULL, first_collected_at TIMESTAMPTZ,
    last_collected_at TIMESTAMPTZ
);
CREATE TABLE tenant_domains (
    tenant_key VARCHAR NOT NULL, domain VARCHAR NOT NULL, source domain_source NOT NULL, rows_seen BIGINT
);
CREATE TABLE tenant_domain_overrides (
    tenant_key VARCHAR NOT NULL, domain VARCHAR NOT NULL, action domain_action NOT NULL,
    actor VARCHAR NOT NULL, changed_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp
);

COMMENT ON TABLE tenant IS 'One row per tenant seen in the case, rewritten by every profile run. tenant_key groups the case''s collections: the Entra tenant id when evidence carried one, else name:<reported name>, else collection:<id> for a collection that reported neither.';
COMMENT ON COLUMN tenant.tenant_key IS 'Grouping key: the lower-case Entra tenant id when found in evidence, else name:<lower trimmed tenant name>, else collection:<collection_id>.';
COMMENT ON COLUMN tenant.tenant_id IS 'Entra tenant id (lower-case GUID) found in this tenant''s evidence (ual_events.organization_id or signins.resource_tenant_id); NULL when no collection of this tenant reported one.';
COMMENT ON COLUMN tenant.tenant_id_source IS 'Which evidence column supplied tenant_id: ual_organization_id or signin_resource_tenant.';
COMMENT ON COLUMN tenant.tenant_name IS 'Tenant name the newest collection reported (Hawk folder name / log; Microsoft-Extractor-Suite reports none), lower-cased.';
COMMENT ON COLUMN tenant.tenant_name_source IS 'collector_reported when tenant_name is set; NULL otherwise.';
COMMENT ON COLUMN tenant.collections IS 'Number of collections grouped under this tenant_key.';
COMMENT ON COLUMN tenant.first_collected_at IS 'Earliest collections.collected_at over this tenant''s collections.';
COMMENT ON COLUMN tenant.last_collected_at IS 'Latest collections.collected_at over this tenant''s collections.';

COMMENT ON TABLE tenant_domains IS 'Domains that belong to the tenant, used to tell internal from external addresses. Rebuilt by every profile run from the evidence, then the tenant''s tenant_domain_overrides are applied (a removed domain is dropped even when derived; an added domain is kept with source analyst).';
COMMENT ON COLUMN tenant_domains.tenant_key IS 'tenant.tenant_key this domain belongs to.';
COMMENT ON COLUMN tenant_domains.domain IS 'Lower-case domain (the part of a UPN/address after @).';
COMMENT ON COLUMN tenant_domains.source IS 'derived_upn: from users.upn / mailboxes.upn / signins.user_upn. message_trace_org: from message_trace.organization. analyst: added by sparrow tenant domains add.';
COMMENT ON COLUMN tenant_domains.rows_seen IS 'Rows whose UPN or organization had this domain, summed over the deriving sources; NULL for analyst-added rows the evidence did not show.';

COMMENT ON TABLE tenant_domain_overrides IS 'Analyst decisions from sparrow tenant domains add|remove, kept across profile runs (rebuild_domains re-applies them after re-deriving tenant_domains from evidence). The latest decision per (tenant_key, domain) wins.';
COMMENT ON COLUMN tenant_domain_overrides.tenant_key IS 'tenant.tenant_key the decision applies to.';
COMMENT ON COLUMN tenant_domain_overrides.domain IS 'Lower-case domain the decision names.';
COMMENT ON COLUMN tenant_domain_overrides.action IS 'add: treat the domain as internal even if evidence does not show it. remove: treat the domain as external even if evidence does show it.';
COMMENT ON COLUMN tenant_domain_overrides.actor IS 'Who made the decision, e.g. analyst:<name> (from --analyst or $SPARROW_ANALYST, else analyst:unknown).';
COMMENT ON COLUMN tenant_domain_overrides.changed_at IS 'When the decision was recorded.';

CREATE VIEW tenant_audit_config AS
WITH rows AS (
    SELECT coalesce(c.tenant_key, 'collection:' || c.collection_id) AS tenant_key, a.*,
           row_number() OVER (PARTITION BY coalesce(c.tenant_key, 'collection:' || c.collection_id)
                              ORDER BY c.collected_at DESC NULLS LAST, c.collection_id DESC) AS rn
    FROM audit_config a JOIN collections c ON c.collection_id = a.collection_id
)
SELECT tenant_key,
    first(admin_audit_log_enabled ORDER BY rn) FILTER (WHERE json_exists(column_collections, '$.admin_audit_log_enabled')) AS admin_audit_log_enabled,
    first(unified_audit_log_ingestion_enabled ORDER BY rn) FILTER (WHERE json_exists(column_collections, '$.unified_audit_log_ingestion_enabled')) AS unified_audit_log_ingestion_enabled,
    first(admin_audit_log_age_limit ORDER BY rn) FILTER (WHERE json_exists(column_collections, '$.admin_audit_log_age_limit')) AS admin_audit_log_age_limit,
    first(log_level ORDER BY rn) FILTER (WHERE json_exists(column_collections, '$.log_level')) AS log_level,
    first(audit_disabled ORDER BY rn) FILTER (WHERE json_exists(column_collections, '$.audit_disabled')) AS audit_disabled,
    first(security_defaults_enabled ORDER BY rn) FILTER (WHERE json_exists(column_collections, '$.security_defaults_enabled')) AS security_defaults_enabled,
    list(collection_id ORDER BY rn) AS collection_ids
FROM rows GROUP BY tenant_key;

COMMENT ON VIEW tenant_audit_config IS 'Per-tenant organization audit configuration, merging every collection''s audit_config row: each column comes from the newest collection (by collected_at, then collection_id) whose load actually provided that column (its key is set in column_collections), so a newer capture that only reports AdminAuditLogConfig does not blank a column only OrganizationConfig reports (for example audit_disabled). Rows with a NULL column_collections (no loader currently produces this) are treated as providing nothing.';
COMMENT ON COLUMN tenant_audit_config.tenant_key IS 'tenant.tenant_key (or collection:<id> for a collection with no tenant_key, which should not occur after a profile run).';
COMMENT ON COLUMN tenant_audit_config.admin_audit_log_enabled IS 'Newest value a collection''s load provided for audit_config.admin_audit_log_enabled.';
COMMENT ON COLUMN tenant_audit_config.unified_audit_log_ingestion_enabled IS 'Newest value a collection''s load provided for audit_config.unified_audit_log_ingestion_enabled.';
COMMENT ON COLUMN tenant_audit_config.admin_audit_log_age_limit IS 'Newest value a collection''s load provided for audit_config.admin_audit_log_age_limit.';
COMMENT ON COLUMN tenant_audit_config.log_level IS 'Newest value a collection''s load provided for audit_config.log_level.';
COMMENT ON COLUMN tenant_audit_config.audit_disabled IS 'Newest value a collection''s load provided for audit_config.audit_disabled.';
COMMENT ON COLUMN tenant_audit_config.security_defaults_enabled IS 'Newest value a collection''s load provided for audit_config.security_defaults_enabled.';
COMMENT ON COLUMN tenant_audit_config.collection_ids IS 'This tenant''s collections, newest first, that contributed audit_config rows.';

CREATE VIEW tenant_settings_current AS
SELECT coalesce(c.tenant_key, 'collection:' || c.collection_id) AS tenant_key, s.source, s.name, s.value,
       s.collection_id, c.collected_at
FROM tenant_settings s JOIN collections c ON c.collection_id = s.collection_id
QUALIFY row_number() OVER (PARTITION BY coalesce(c.tenant_key, 'collection:' || c.collection_id), s.source, lower(s.name)
                           ORDER BY c.collected_at DESC NULLS LAST, c.collection_id DESC) = 1;

COMMENT ON VIEW tenant_settings_current IS 'Newest tenant_settings row per (tenant, source, lower(name)), merging every collection''s reported settings so the newest capture''s value wins per named setting.';
COMMENT ON COLUMN tenant_settings_current.tenant_key IS 'tenant.tenant_key (or collection:<id> for a collection with no tenant_key, which should not occur after a profile run).';
COMMENT ON COLUMN tenant_settings_current.source IS 'tenant_settings.source (organization_config, admin_audit_log_config, transport_config, security_defaults, rbac_role_entry, ...).';
COMMENT ON COLUMN tenant_settings_current.name IS 'tenant_settings.name, in the case of the collection that reported the newest value.';
COMMENT ON COLUMN tenant_settings_current.value IS 'tenant_settings.value from the newest collection to report this (tenant, source, lower(name)).';
COMMENT ON COLUMN tenant_settings_current.collection_id IS 'Collection whose row won.';
COMMENT ON COLUMN tenant_settings_current.collected_at IS 'collections.collected_at of the winning collection.';

-- Task 4: licences.
CREATE TYPE license_confidence AS ENUM ('high', 'low');
CREATE TABLE licenses (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    source VARCHAR, sku_part_number VARCHAR, sku_id VARCHAR, license_tier VARCHAR,
    capability_status VARCHAR, consumed_units INTEGER, enabled_units INTEGER,
    service_plans VARCHAR[], confidence license_confidence, raw JSON, column_collections JSON,
    tz_assumed JSON
);
CREATE TABLE user_licenses (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    source VARCHAR, upn VARCHAR, user_id VARCHAR, sku_part_number VARCHAR, sku_id VARCHAR,
    service_plans VARCHAR[], raw JSON, column_collections JSON, tz_assumed JSON
);

COMMENT ON TABLE licenses IS 'Tenant licences reported by one collection. High confidence: Microsoft-Extractor-Suite TenantLicenses.csv (Graph subscribedSkus with service plans; parser planned for Phase 5). Low confidence: the Hawk.log line "M365 License type detected: <tier>", which Hawk derives from SKU-name substrings (E5 is also logged for Office 365 E5, which lacks Entra ID P1/P2; Microsoft 365 E3 is logged Unknown). tenant_capabilities interprets them.';
COMMENT ON COLUMN licenses.record_key IS '<collection_id>|<source>|<lower sku_part_number or tier>.';
COMMENT ON COLUMN licenses.collection_id IS 'Newest collection that wrote or re-confirmed any of this row''s columns (per-column writers: column_collections).';
COMMENT ON COLUMN licenses.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN licenses.source IS 'hawk_log or invictus_tenant_licenses.';
COMMENT ON COLUMN licenses.sku_part_number IS 'Graph SkuPartNumber; NULL for the Hawk tier.';
COMMENT ON COLUMN licenses.sku_id IS 'Graph SkuId; NULL for the Hawk tier.';
COMMENT ON COLUMN licenses.license_tier IS 'The Hawk tier (E5, G5, E3, G3, Unknown); NULL for SKU rows.';
COMMENT ON COLUMN licenses.capability_status IS 'Graph capabilityStatus (Enabled, Warning, Suspended, Deleted, LockedOut).';
COMMENT ON COLUMN licenses.consumed_units IS 'Assigned units when reported.';
COMMENT ON COLUMN licenses.enabled_units IS 'Purchased units when reported.';
COMMENT ON COLUMN licenses.service_plans IS 'Service plan names in the SKU (only plans whose provisioningStatus is Success when the source says).';
COMMENT ON COLUMN licenses.confidence IS 'high for SKU lists with service plans, low for the Hawk tier.';
COMMENT ON COLUMN licenses.raw IS 'Source record as loaded.';
COMMENT ON COLUMN licenses.column_collections IS 'Object {column: collection_id} naming the collection that last wrote each column. Per-column latest wins: a load writes a column only when its collection is not older than the one recorded for it, so column values do not depend on ingest order. Columns no load has written (or loaded only as NULL where NULL keeps the stored value) are absent.';
COMMENT ON COLUMN licenses.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';

COMMENT ON TABLE user_licenses IS 'Licences assigned to users, per collection (Microsoft-Extractor-Suite UserLicenses.csv; parser planned for Phase 5). Empty until then.';
COMMENT ON COLUMN user_licenses.record_key IS '<collection_id>|<lower upn>|<lower sku>.';
COMMENT ON COLUMN user_licenses.collection_id IS 'Newest collection that wrote or re-confirmed any of this row''s columns (per-column writers: column_collections).';
COMMENT ON COLUMN user_licenses.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN user_licenses.source IS 'invictus_user_licenses (Microsoft-Extractor-Suite UserLicenses.csv; parser planned for Phase 5).';
COMMENT ON COLUMN user_licenses.upn IS 'User principal name the licence is assigned to.';
COMMENT ON COLUMN user_licenses.user_id IS 'Entra user id the licence is assigned to.';
COMMENT ON COLUMN user_licenses.sku_part_number IS 'Graph SkuPartNumber.';
COMMENT ON COLUMN user_licenses.sku_id IS 'Graph SkuId.';
COMMENT ON COLUMN user_licenses.service_plans IS 'Service plan names assigned to the user from this SKU.';
COMMENT ON COLUMN user_licenses.raw IS 'Source record as loaded.';
COMMENT ON COLUMN user_licenses.column_collections IS 'Object {column: collection_id} naming the collection that last wrote each column. Per-column latest wins: a load writes a column only when its collection is not older than the one recorded for it, so column values do not depend on ingest order. Columns no load has written (or loaded only as NULL where NULL keeps the stored value) are absent.';
COMMENT ON COLUMN user_licenses.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';

-- Task 5: capability status per tenant.
CREATE TYPE capability_status AS ENUM ('licensed', 'not_licensed', 'unknown');
CREATE TABLE tenant_capabilities (
    tenant_key VARCHAR NOT NULL, capability_id VARCHAR NOT NULL, status capability_status NOT NULL,
    confidence license_confidence, basis VARCHAR NOT NULL, retention_days INTEGER
);

COMMENT ON TABLE tenant_capabilities IS 'Whether each capability (capabilities) is available to each tenant, derived by every profile run from, strongest first: a high-confidence licence list (service plans), evidence signals (visible sign-in risk levels, Graph sign-in downloads, Microsoft-Extractor-Suite HasPremiumLicense, UAL records older than Audit (Standard) retention), the Hawk.log licence tier, and baseline assumptions.';
COMMENT ON COLUMN tenant_capabilities.tenant_key IS 'tenant.tenant_key.';
COMMENT ON COLUMN tenant_capabilities.capability_id IS 'capabilities.capability_id.';
COMMENT ON COLUMN tenant_capabilities.status IS 'licensed, not_licensed or unknown.';
COMMENT ON COLUMN tenant_capabilities.confidence IS 'high (licence list or direct evidence) or low (Hawk tier or baseline assumption); NULL when unknown.';
COMMENT ON COLUMN tenant_capabilities.basis IS 'Why, in words, naming the evidence (and any disagreeing evidence).';
COMMENT ON COLUMN tenant_capabilities.retention_days IS 'Retention the capability gives (capabilities.retention_days).';

-- Task 6: evidence availability snapshot.
CREATE TYPE availability_status AS ENUM ('collected', 'available_not_collected', 'not_licensed',
    'not_enabled', 'beyond_retention', 'partial', 'unknown');
CREATE TABLE evidence_availability (
    tenant_key VARCHAR NOT NULL, evidence VARCHAR NOT NULL, title VARCHAR NOT NULL,
    status availability_status NOT NULL, reason VARCHAR NOT NULL, remediation VARCHAR,
    rows BIGINT NOT NULL, min_time TIMESTAMPTZ, max_time TIMESTAMPTZ, users_covered BIGINT,
    retention_days INTEGER, evaluated_at TIMESTAMPTZ NOT NULL
);

COMMENT ON TABLE evidence_availability IS 'Per tenant and evidence source: whether the evidence is in the case and, if not, why (not licensed, not enabled, beyond retention, not collected). Snapshot written by every profile run; sparrow capabilities recomputes it for the current time.';
COMMENT ON COLUMN evidence_availability.tenant_key IS 'tenant.tenant_key.';
COMMENT ON COLUMN evidence_availability.evidence IS 'Evidence source id (ual, mail_items_accessed, signins, ...), as listed in capabilities.evidence.';
COMMENT ON COLUMN evidence_availability.title IS 'Human-readable name of the evidence source.';
COMMENT ON COLUMN evidence_availability.status IS 'collected: in the case (rows may be 0 when the collector ran and found nothing). partial: in the case but incomplete (truncated export, files this Sparrow version does not parse, Hawk''s selected operations or selected users, mailboxes not auditing the action, window reaching past retention). not_licensed: the tenant lacks the licence that produces it. not_enabled: licensed but switched off (UAL ingestion, organization mailbox auditing, or no mailbox audits the action). beyond_retention: not collected and the tenant window ended before Microsoft''s retention reaches back. available_not_collected: could still be collected. unknown: licence unknown and not part of every plan.';
COMMENT ON COLUMN evidence_availability.reason IS 'Why, in words: the counted rows, the partial reasons, the licence basis or the setting that decided the status.';
COMMENT ON COLUMN evidence_availability.remediation IS 'Collector command (or portal path) that would fill the gap.';
COMMENT ON COLUMN evidence_availability.rows IS 'Rows in the case for this tenant.';
COMMENT ON COLUMN evidence_availability.min_time IS 'Earliest event time in those rows (NULL for state evidence or no rows).';
COMMENT ON COLUMN evidence_availability.max_time IS 'Latest event time in those rows (NULL for state evidence or no rows).';
COMMENT ON COLUMN evidence_availability.users_covered IS 'Distinct users in those rows.';
COMMENT ON COLUMN evidence_availability.retention_days IS 'Longest retention among the tenant''s licensed capabilities that provide this evidence (NULL for state evidence or when unknown).';
COMMENT ON COLUMN evidence_availability.evaluated_at IS 'The time the snapshot was evaluated for (retention decisions depend on it).';
