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

-- Task 7: IP enrichment.
CREATE TABLE ip_intel (
    ip VARCHAR NOT NULL, country_iso VARCHAR, country VARCHAR, city VARCHAR, latitude DOUBLE,
    longitude DOUBLE, asn INTEGER, asn_org VARCHAR, is_hosting BOOLEAN, hosting_provider VARCHAR,
    is_microsoft BOOLEAN NOT NULL, microsoft_service_area VARCHAR, is_private BOOLEAN NOT NULL,
    source_db_version VARCHAR
);

COMMENT ON TABLE ip_intel IS 'One row per distinct IP address in the event tables, rewritten by every profile run; join on ip = <table>.<ip column>.';
COMMENT ON COLUMN ip_intel.ip IS 'Text exactly as the event tables store it (client_ip / ip / initiated_by_ip / from_ip / to_ip), so joins work; lookups use the parsed address (normalize_ip).';
COMMENT ON COLUMN ip_intel.country_iso IS 'MaxMind GeoLite2/GeoIP2 City database: ISO 3166-1 alpha-2 country code. NULL without --geoip-dir or a City database, or when the address is not in it.';
COMMENT ON COLUMN ip_intel.country IS 'MaxMind City database: English country name.';
COMMENT ON COLUMN ip_intel.city IS 'MaxMind City database: English city name.';
COMMENT ON COLUMN ip_intel.latitude IS 'City-level estimate from MaxMind, not a precise location.';
COMMENT ON COLUMN ip_intel.longitude IS 'City-level estimate from MaxMind, not a precise location.';
COMMENT ON COLUMN ip_intel.asn IS 'MaxMind GeoLite2/GeoIP2 ASN database: autonomous system number. NULL without --geoip-dir or an ASN database, or when the address is not in it.';
COMMENT ON COLUMN ip_intel.asn_org IS 'MaxMind ASN database: the organization registered against the ASN.';
COMMENT ON COLUMN ip_intel.is_hosting IS 'Whether asn is a known hosting/cloud/VPS provider (rules/lists/hosting_asns.yaml). NULL when the ASN is unknown.';
COMMENT ON COLUMN ip_intel.hosting_provider IS 'Name of the hosting provider from rules/lists/hosting_asns.yaml, when is_hosting is true.';
COMMENT ON COLUMN ip_intel.is_microsoft IS 'In the bundled Microsoft 365 endpoints snapshot (service front ends: Microsoft infrastructure, not a trusted client).';
COMMENT ON COLUMN ip_intel.microsoft_service_area IS 'Microsoft 365 service area (Exchange, SharePoint, Skype, Common) of the matching range, when is_microsoft is true.';
COMMENT ON COLUMN ip_intel.is_private IS 'RFC 1918, loopback, link-local, CGNAT 100.64.0.0/10, unspecified, IPv6 unique-local/link-local, or an IPv4-mapped IPv6 form of one of those (spec §5.3). Documentation ranges (203.0.113.0/24, 198.51.100.0/24, 2001:db8::/32) are not private.';
COMMENT ON COLUMN ip_intel.source_db_version IS 'The MaxMind City/ASN database versions (build date) and the ms365-endpoints snapshot version used to derive this row, e.g. "GeoLite2-City 2026-09-20; GeoLite2-ASN 2026-09-22; ms365-endpoints 2026081400".';

-- Task 8: identities.
CREATE TYPE identity_kind AS ENUM ('user', 'service_principal', 'app', 'system', 'external');
CREATE TABLE identities (
    identity_id VARCHAR NOT NULL, tenant_key VARCHAR, kind identity_kind NOT NULL, upn VARCHAR,
    object_id VARCHAR, puid VARCHAR, app_id VARCHAR, display_names VARCHAR[], sources VARCHAR[],
    aliases INTEGER NOT NULL
);
CREATE TABLE identity_aliases (
    alias_type VARCHAR NOT NULL, alias VARCHAR NOT NULL, identity_id VARCHAR NOT NULL,
    sources VARCHAR[]
);

COMMENT ON TABLE identities IS 'One row per actor, however the evidence names it (UPN, Entra object id, UAL UserKey PUID, application id). Rebuilt by every profile run from users, mailboxes, sign-ins, UAL, directory audits, risk, role assignments, consent grants, mailbox permissions and admin audit rows.';
COMMENT ON COLUMN identities.identity_id IS 'Preferred alias as <type>:<value> (object_id, then app_id, upn, puid, name). Stable while that alias exists.';
COMMENT ON COLUMN identities.tenant_key IS 'Tenant of most observations.';
COMMENT ON COLUMN identities.kind IS 'external when a UPN contains #ext# or any source said Guest, or when the tenant has domains in tenant_domains and none of the identity''s UPN domains is one of them; else system, service_principal, app or user by the first hint in that order of precedence (system > service_principal > app > user).';
COMMENT ON COLUMN identities.upn IS 'The identity''s UPN (smallest when several).';
COMMENT ON COLUMN identities.object_id IS 'The identity''s Entra object id (smallest when several).';
COMMENT ON COLUMN identities.puid IS 'The identity''s UAL UserKey PUID (smallest when several).';
COMMENT ON COLUMN identities.app_id IS 'The identity''s application id (smallest when several).';
COMMENT ON COLUMN identities.display_names IS 'Display names observed, sorted distinct.';
COMMENT ON COLUMN identities.sources IS 'Tables the identity was observed in, sorted distinct.';
COMMENT ON COLUMN identities.aliases IS 'Number of identity_aliases rows resolving to this identity.';

COMMENT ON TABLE identity_aliases IS 'Every identifier observed, with the identity it resolves to; join events on (alias_type, lower(value)).';
COMMENT ON COLUMN identity_aliases.alias_type IS 'upn, object_id, puid, app_id or name.';
COMMENT ON COLUMN identity_aliases.alias IS 'Lower-cased identifier.';
COMMENT ON COLUMN identity_aliases.identity_id IS 'identities.identity_id.';
COMMENT ON COLUMN identity_aliases.sources IS 'Tables it was observed in.';

-- Task 9: operation catalog, timeline, auth_events.
CREATE TYPE event_category AS ENUM ('auth', 'mail_read', 'mail_send', 'mail_rule', 'forwarding',
    'permission', 'app_consent', 'app_credential', 'role_change', 'mfa_change', 'file_access',
    'file_download', 'file_share', 'lure_staging', 'search', 'ediscovery', 'audit_tamper',
    'config_change', 'device', 'mail_flow', 'other');
CREATE TABLE operation_catalog (
    operation VARCHAR NOT NULL, operation_key VARCHAR NOT NULL, workload VARCHAR,
    category event_category NOT NULL, description VARCHAR, mitre VARCHAR[], origin VARCHAR NOT NULL
);

COMMENT ON TABLE operation_catalog IS 'Operations Sparrow knows, with a category for the timeline and ATT&CK techniques (data/operation_catalog.yaml, embedded; --data DIR overrides entries by (operation, workload) and may add new ones). Rewritten by every profile run.';
COMMENT ON COLUMN operation_catalog.operation IS 'Operation name as UAL / Graph / Exchange write it.';
COMMENT ON COLUMN operation_catalog.operation_key IS 'Join key: operation_key(operation) - lower-case, trimmed, trailing "." removed - so UAL "Consent to application." and Graph "Consent to application" meet. The timeline view recomputes this in SQL (lower(trim(rtrim(trim(operation), ''.'')))); DuckDB''s trim() strips plain ASCII whitespace only, unlike Rust''s Unicode-aware trim, which is not expected to matter for these operation names.';
COMMENT ON COLUMN operation_catalog.workload IS 'Workload the entry applies to (Exchange, AzureActiveDirectory, SharePoint, OneDrive); NULL matches any workload. Matched case-insensitively against the event''s workload (an override may spell it in any case).';
COMMENT ON COLUMN operation_catalog.category IS 'Category the timeline view uses for this operation.';
COMMENT ON COLUMN operation_catalog.description IS 'Human-readable description of the operation.';
COMMENT ON COLUMN operation_catalog.mitre IS 'ATT&CK technique ids the operation maps to; empty when no technique clearly applies.';
COMMENT ON COLUMN operation_catalog.origin IS 'builtin, or the path of the external file that supplied the entry.';

CREATE VIEW record_source_refs AS
SELECT rs.table_name, rs.record_key,
       list(regexp_extract(c.root_path, '[^/\\]+$') || '/' || sf.rel_path || ':' || rs.line_start ||
            CASE WHEN rs.line_end <> rs.line_start THEN '-' || rs.line_end ELSE '' END
            ORDER BY sf.file_id, rs.record_ordinal) AS source_refs
FROM record_sources rs
JOIN source_files sf ON sf.file_id = rs.file_id
JOIN collections c ON c.collection_id = sf.collection_id
GROUP BY rs.table_name, rs.record_key;

COMMENT ON VIEW record_source_refs IS 'Every record''s sightings as source_ref text (<collection root folder name>/<rel_path>:<line_start>[-<line_end>]), in file and ordinal order; the same text verify::source_ref builds. Join on (table_name, record_key).';
COMMENT ON COLUMN record_source_refs.table_name IS 'Evidence table holding the record (record_sources.table_name).';
COMMENT ON COLUMN record_source_refs.record_key IS 'Key of the record in table_name (record_sources.record_key).';
COMMENT ON COLUMN record_source_refs.source_refs IS 'One source_ref per sighting, ordered by (file_id, record_ordinal): "<collection root folder name>/<rel_path>:<line_start>[-<line_end>]".';

CREATE VIEW timeline AS
WITH ev AS (
    SELECT u.event_time, u.time_tz_assumed, 'ual_events' AS source_table, CAST(u.record_id AS VARCHAR) AS record_key,
           u.workload, u.operation, u.user_upn AS actor_upn, coalesce(u.mailbox_upn, u.object_id) AS target,
           u.client_ip AS ip, u.user_agent,
           concat_ws(' ', u.workload, u.operation, CASE WHEN u.object_id IS NOT NULL THEN 'on ' || u.object_id END) AS summary
    FROM ual_events u
    UNION ALL
    SELECT m.event_time, m.time_tz_assumed, 'mail_items_accessed', m.item_key, 'Exchange', 'MailItemsAccessed',
           m.user_upn, coalesce(m.internet_message_id, m.folder_path), m.client_ip, NULL,
           concat_ws(' ', 'MailItemsAccessed', CAST(m.access_type AS VARCHAR), m.folder_path)
    FROM mail_items_accessed m WHERE m.record_id IS NULL
    UNION ALL
    SELECT s.event_time, s.time_tz_assumed, 'signins', s.record_key, 'AzureActiveDirectory',
           CASE WHEN coalesce(s.error_code, 0) = 0 THEN 'SignInSucceeded' ELSE 'SignInFailed' END,
           coalesce(s.user_upn, s.app_name), coalesce(s.resource_name, s.app_name), s.ip, s.user_agent,
           concat_ws(' ', CAST(s.event_type AS VARCHAR), 'sign-in to', s.app_name,
                     CASE WHEN coalesce(s.error_code, 0) <> 0 THEN 'failed ' || s.error_code END)
    FROM signins s
    UNION ALL
    SELECT d.event_time, d.time_tz_assumed, 'directory_audits', d.record_key, 'AzureActiveDirectory', d.activity,
           coalesce(d.initiated_by_upn, d.initiated_by_app_name),
           coalesce(d.targets->>'$[0].UserPrincipalName', d.targets->>'$[0].userPrincipalName',
                    d.targets->>'$[0].DisplayName', d.targets->>'$[0].displayName'),
           d.initiated_by_ip, NULL, concat_ws(' ', d.category, d.activity, d.result)
    FROM directory_audits d
    UNION ALL
    SELECT t.received, t.time_tz_assumed, 'message_trace', t.record_key, 'Exchange', 'MessageTrace', t.sender,
           t.recipient, t.from_ip, NULL, concat_ws(' ', t.status, t.subject)
    FROM message_trace t
    UNION ALL
    SELECT l.event_time, l.time_tz_assumed, 'mailbox_audit_legacy', l.record_key, 'Exchange', l.operation,
           l.logon_user, l.mailbox_upn, l.client_ip, l.client_info, concat_ws(' ', l.logon_type, l.operation, l.folder_path)
    FROM mailbox_audit_legacy l
    UNION ALL
    SELECT a.run_time, a.time_tz_assumed, 'admin_audit_events', a.record_key, 'Exchange', a.cmdlet, a.caller,
           a.object_modified, a.client_ip, NULL, concat_ws(' ', a.cmdlet, a.object_modified)
    FROM admin_audit_events a
    UNION ALL
    SELECT coalesce(r.activity_time, r.detected_time), false, 'risk_detections', r.record_key, 'AzureActiveDirectory',
           r.risk_event_type, r.user_upn, NULL, r.ip, NULL, concat_ws(' ', 'risk', r.risk_level, r.risk_event_type)
    FROM risk_detections r
)
SELECT ev.event_time, ev.time_tz_assumed, ev.source_table, ev.record_key,
       coalesce(
           (SELECT o.category FROM operation_catalog o
            WHERE o.operation_key = lower(trim(rtrim(trim(ev.operation), '.')))
              AND (o.workload IS NULL OR lower(o.workload) = lower(ev.workload))
            ORDER BY o.workload NULLS LAST LIMIT 1),
           CASE ev.source_table WHEN 'signins' THEN 'auth' WHEN 'risk_detections' THEN 'auth'
                                WHEN 'message_trace' THEN 'mail_flow' ELSE 'other' END::event_category
       ) AS category,
       ev.operation, ev.actor_upn, ev.target, ev.ip, i.country_iso AS ip_country, i.asn_org AS ip_asn_org,
       ev.user_agent, ev.summary, refs.source_refs
FROM ev
LEFT JOIN ip_intel i ON i.ip = ev.ip
LEFT JOIN record_source_refs refs ON refs.table_name = ev.source_table AND refs.record_key = ev.record_key;

COMMENT ON VIEW timeline IS 'One row per event record: the union of ual_events, parent-less mail_items_accessed rows, signins, directory_audits, message_trace, mailbox_audit_legacy, admin_audit_events and risk_detections, with category from operation_catalog, IP country/ASN from ip_intel, and source_refs. Deviation from spec 5.3: no finding_count column (findings arrive in Phase 6, which recreates this view); a time_tz_assumed column is added; category gains the value mail_flow for message trace rows (the spec category list has nothing for mail delivery).';
COMMENT ON COLUMN timeline.event_time IS 'Event time (UTC): ual_events.event_time, mail_items_accessed.event_time, signins.event_time, directory_audits.event_time, message_trace.received, mailbox_audit_legacy.event_time, admin_audit_events.run_time, or coalesce(risk_detections.activity_time, risk_detections.detected_time).';
COMMENT ON COLUMN timeline.time_tz_assumed IS 'True when the source time had no timezone and UTC was assumed. Always false for risk_detections: it has no time_tz_assumed column because its times are Graph UTC.';
COMMENT ON COLUMN timeline.source_table IS 'Evidence table the row came from: ual_events, mail_items_accessed, signins, directory_audits, message_trace, mailbox_audit_legacy, admin_audit_events or risk_detections.';
COMMENT ON COLUMN timeline.record_key IS 'Key of the record in source_table (record_sources.record_key), joined against record_source_refs and, via that, verify.';
COMMENT ON COLUMN timeline.category IS 'From operation_catalog (matched on operation_key = operation_key(operation) and workload, case-insensitively, most specific workload match wins); else auth for signins/risk_detections, mail_flow for message_trace, other otherwise.';
COMMENT ON COLUMN timeline.operation IS 'Operation name: ual_events.operation, MailItemsAccessed for a parent-less mail_items_accessed row, SignInSucceeded/SignInFailed (Sparrow timeline name) for signins, directory_audits.activity, MessageTrace (Sparrow timeline name) for message_trace, mailbox_audit_legacy.operation, admin_audit_events.cmdlet, or risk_detections.risk_event_type.';
COMMENT ON COLUMN timeline.actor_upn IS 'Who performed the action, from the source row (falls back to an app/service name where the source has no user).';
COMMENT ON COLUMN timeline.target IS 'What the action touched, from the source row. For directory_audits: TargetResources[0]''s UPN, else display name, matching either casing (Hawk''s Get-MgAuditLogDirectoryAudit is PascalCase; Microsoft-Extractor-Suite''s Graph REST JSON is camelCase).';
COMMENT ON COLUMN timeline.ip IS 'Client IP text as the source table stores it; join key into ip_intel.';
COMMENT ON COLUMN timeline.ip_country IS 'ip_intel.country_iso for ip.';
COMMENT ON COLUMN timeline.ip_asn_org IS 'ip_intel.asn_org for ip.';
COMMENT ON COLUMN timeline.user_agent IS 'User agent, when the source table records one.';
COMMENT ON COLUMN timeline.summary IS 'Short human-readable summary built from the source row''s own fields.';
COMMENT ON COLUMN timeline.source_refs IS 'record_source_refs.source_refs for (source_table, record_key); empty for a row provenance could not resolve (should not occur for ingested evidence).';

CREATE VIEW auth_events AS
SELECT s.event_time, s.time_tz_assumed, 'signins' AS source_table, s.record_key,
       CAST(s.event_type AS VARCHAR) AS event_type, s.user_upn, s.user_id,
       coalesce(s.error_code, 0) = 0 AS succeeded, s.error_code, s.failure_reason, s.ip, s.user_agent,
       s.app_id, s.app_name, s.session_id, s.correlation_id
FROM signins s
UNION ALL
SELECT u.event_time, u.time_tz_assumed, 'ual_events', CAST(u.record_id AS VARCHAR), 'ual_logon', u.user_upn,
       NULL, u.operation <> 'UserLoginFailed',
       TRY_CAST(u.audit_data->>'$.ErrorNumber' AS INTEGER), u.audit_data->>'$.LogonError', u.client_ip,
       u.user_agent, coalesce(u.app_id, u.audit_data->>'$.ApplicationId'), NULL, u.session_id, NULL
FROM ual_events u
WHERE u.operation IN ('UserLoggedIn', 'UserLoginFailed') OR u.record_type_name = 'AzureActiveDirectoryStsLogon';

COMMENT ON VIEW auth_events IS 'Sign-in / logon events in one shape (spec 5.1, deferred from Phase 2c): signins and UAL logon records (UserLoggedIn, UserLoginFailed, and records of record_type_name AzureActiveDirectoryStsLogon).';
COMMENT ON COLUMN auth_events.event_time IS 'Event time (UTC): signins.event_time or ual_events.event_time.';
COMMENT ON COLUMN auth_events.time_tz_assumed IS 'True when the source time had no timezone and UTC was assumed.';
COMMENT ON COLUMN auth_events.source_table IS 'signins or ual_events.';
COMMENT ON COLUMN auth_events.record_key IS 'Key of the record in source_table.';
COMMENT ON COLUMN auth_events.event_type IS 'signins.event_type (interactive, noninteractive, service_principal, managed_identity), or ual_logon for a UAL row.';
COMMENT ON COLUMN auth_events.user_upn IS 'signins.user_upn or ual_events.user_upn.';
COMMENT ON COLUMN auth_events.user_id IS 'signins.user_id; NULL for a UAL row (UAL carries no Entra object id).';
COMMENT ON COLUMN auth_events.succeeded IS 'signins: error_code is 0 (or absent). UAL: operation is not UserLoginFailed.';
COMMENT ON COLUMN auth_events.error_code IS 'signins.error_code, or the UAL AuditData ErrorNumber when present and numeric.';
COMMENT ON COLUMN auth_events.failure_reason IS 'signins.failure_reason, or the UAL AuditData LogonError.';
COMMENT ON COLUMN auth_events.ip IS 'signins.ip or ual_events.client_ip.';
COMMENT ON COLUMN auth_events.user_agent IS 'signins.user_agent or ual_events.user_agent.';
COMMENT ON COLUMN auth_events.app_id IS 'signins.app_id, or ual_events.app_id (else AuditData ApplicationId).';
COMMENT ON COLUMN auth_events.app_name IS 'signins.app_name; NULL for a UAL row (UAL carries no application display name).';
COMMENT ON COLUMN auth_events.session_id IS 'signins.session_id or ual_events.session_id.';
COMMENT ON COLUMN auth_events.correlation_id IS 'signins.correlation_id; NULL for a UAL row (UAL carries no correlation id).';

-- Task 10: state rows missing from a newer capture.
CREATE VIEW state_absent_in_newer AS
WITH files AS (
    SELECT sf.file_id, sf.collection_id, sf.artifact_type, sf.subject, sf.status, sf.sha256,
           c.tenant_key, c.collected_at
    FROM source_files sf JOIN collections c ON c.collection_id = sf.collection_id
    WHERE sf.status IN ('parsed', 'duplicate_file') AND sf.artifact_type IS NOT NULL
),
holds AS (
    SELECT rs.file_id, rs.table_name, rs.record_key FROM record_sources rs
    UNION
    SELECT d.file_id, rs.table_name, rs.record_key
    FROM files d
    JOIN source_files p ON p.sha256 = d.sha256 AND p.status = 'parsed' AND p.file_id <> d.file_id
    JOIN record_sources rs ON rs.file_id = p.file_id
    WHERE d.status = 'duplicate_file'
),
seen AS (
    SELECT h.table_name, h.record_key, f.artifact_type, f.subject, f.tenant_key,
           max(f.collected_at) AS last_seen_at,
           arg_max(f.collection_id, f.collected_at) AS last_seen_collection_id
    FROM holds h JOIN files f ON f.file_id = h.file_id
    WHERE h.table_name IN ('users', 'role_assignments', 'oauth_grants', 'app_credentials', 'inbox_rules',
                           'mailboxes', 'transport_rules', 'remote_domains', 'mobile_devices',
                           'risky_users', 'mailbox_permissions')
    GROUP BY ALL
),
last_any AS (
    SELECT table_name, record_key, max(last_seen_at) AS seen_at FROM seen GROUP BY ALL
)
SELECT s.table_name, s.record_key, s.artifact_type, s.subject, s.last_seen_collection_id, s.last_seen_at,
       n.collection_id AS absent_from_collection_id, n.collected_at AS absent_from_at
FROM seen s
JOIN last_any la ON la.table_name = s.table_name AND la.record_key = s.record_key
JOIN files n ON n.artifact_type = s.artifact_type
            AND n.subject IS NOT DISTINCT FROM s.subject
            AND n.tenant_key IS NOT DISTINCT FROM s.tenant_key
            AND n.collected_at > la.seen_at
WHERE NOT EXISTS (
    SELECT 1 FROM holds h2
    WHERE h2.file_id = n.file_id AND h2.table_name = s.table_name AND h2.record_key = s.record_key)
QUALIFY row_number() OVER (PARTITION BY s.table_name, s.record_key, s.artifact_type
                           ORDER BY n.collected_at DESC, n.collection_id DESC) = 1;

COMMENT ON VIEW state_absent_in_newer IS 'State rows a newer capture of the same artifact, for the same subject and tenant, no longer holds. Latest-wins (Phase 2b) never deletes, so a row removed between two captures (e.g. an inbox rule) otherwise still reads as current; this view lists it instead. Rule: same artifact_type, same subject, same tenant_key, a strictly later collection exists for that (artifact_type, subject, tenant_key), and that later collection''s files do not hold the record. A byte-identical newer file (duplicate_file) counts as holding whatever its parsed twin holds. A subject not collected at all in the newer capture (no file for it) yields no later file to compare against, so its rows are not listed - coverage gaps are not the same as removal.';
COMMENT ON COLUMN state_absent_in_newer.table_name IS 'Evidence table holding the record (record_sources.table_name); one of the Phase 2b state tables.';
COMMENT ON COLUMN state_absent_in_newer.record_key IS 'Key of the record in table_name.';
COMMENT ON COLUMN state_absent_in_newer.artifact_type IS 'source_files.artifact_type the record was last seen in.';
COMMENT ON COLUMN state_absent_in_newer.subject IS 'source_files.subject (e.g. the mailbox UPN) the record was last seen under; NULL for a tenant-wide artifact.';
COMMENT ON COLUMN state_absent_in_newer.last_seen_collection_id IS 'collections.collection_id of the latest capture that still held the record.';
COMMENT ON COLUMN state_absent_in_newer.last_seen_at IS 'collections.collected_at of last_seen_collection_id.';
COMMENT ON COLUMN state_absent_in_newer.absent_from_collection_id IS 'collections.collection_id of the newer capture of the same artifact_type/subject/tenant that no longer holds the record (the latest such capture, when several exist).';
COMMENT ON COLUMN state_absent_in_newer.absent_from_at IS 'collections.collected_at of absent_from_collection_id.';
