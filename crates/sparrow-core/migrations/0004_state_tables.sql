-- 0004: tenant state tables (spec 5.2), risk detections (5.1) and collector flags (5.3).
-- No PRIMARY KEY / UNIQUE constraints: the loader (ingest/state.rs) keeps record_key unique,
-- and DuckDB rejects delete + re-insert of a constrained key inside one transaction.

COMMENT ON COLUMN ual_events.client_ip IS 'First of ClientIP, ClientIPAddress, ActorIpAddress; port and brackets removed, IPv6 lower-cased and compressed, IPv4-mapped IPv6 (::ffff:a.b.c.d) written as plain IPv4.';

CREATE TYPE role_source AS ENUM ('entra_directory', 'entra_pim', 'exchange_rbac', 'exchange_ediscovery');
CREATE TYPE permission_type AS ENUM ('delegated', 'application');
CREATE TYPE credential_type AS ENUM ('password', 'certificate');
CREATE TYPE credential_owner AS ENUM ('application', 'service_principal');
CREATE TYPE rule_kind AS ENUM ('inbox', 'sweep');

CREATE TABLE users (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    user_id VARCHAR, upn VARCHAR, display_name VARCHAR, mail VARCHAR, account_enabled BOOLEAN,
    created TIMESTAMPTZ, deleted TIMESTAMPTZ, last_password_change TIMESTAMPTZ, user_type VARCHAR,
    on_prem_sync BOOLEAN, state_changed TIMESTAMPTZ, last_signin TIMESTAMPTZ, department VARCHAR,
    job_title VARCHAR, raw JSON
);

CREATE TABLE role_assignments (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    source role_source, role_name VARCHAR, principal_upn VARCHAR, principal_id VARCHAR,
    principal_name VARCHAR, principal_type VARCHAR, assignment_type VARCHAR, assignment_name VARCHAR,
    enabled BOOLEAN, start_time TIMESTAMPTZ, end_time TIMESTAMPTZ, raw JSON
);

CREATE TABLE oauth_grants (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    permission_type permission_type, client_id VARCHAR, client_name VARCHAR, resource_id VARCHAR,
    resource_name VARCHAR, permission VARCHAR, consent_type VARCHAR, principal_id VARCHAR,
    principal_name VARCHAR, principal_upn VARCHAR, risk_category VARCHAR, publisher VARCHAR,
    verified_publisher VARCHAR, created TIMESTAMPTZ, sign_in_audience VARCHAR, raw JSON
);

CREATE TABLE app_credentials (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    app_object_id VARCHAR, app_name VARCHAR, key_id VARCHAR, cred_type credential_type,
    key_type VARCHAR, start_time TIMESTAMPTZ, end_time TIMESTAMPTZ, owner credential_owner, raw JSON
);

CREATE TABLE inbox_rules (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    kind rule_kind, mailbox VARCHAR, mailbox_upn VARCHAR, rule_identity VARCHAR, name VARCHAR,
    enabled BOOLEAN, in_error BOOLEAN, priority INTEGER, forward_to VARCHAR[],
    forward_as_attachment_to VARCHAR[], redirect_to VARCHAR[], delete_message BOOLEAN,
    soft_delete BOOLEAN, move_to_folder VARCHAR, copy_to_folder VARCHAR, mark_as_read BOOLEAN,
    stop_processing BOOLEAN, from_addresses VARCHAR[], subject_contains VARCHAR[],
    body_contains VARCHAR[], subject_or_body_contains VARCHAR[], has_attachment BOOLEAN,
    source_folder VARCHAR, description VARCHAR, raw JSON
);

CREATE TABLE mailboxes (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    upn VARCHAR, display_name VARCHAR, primary_smtp_address VARCHAR, object_id VARCHAR,
    mailbox_guid VARCHAR, recipient_type VARCHAR, forwarding_smtp_address VARCHAR,
    forwarding_address VARCHAR, deliver_and_forward BOOLEAN, audit_enabled BOOLEAN,
    audit_owner VARCHAR[], audit_delegate VARCHAR[], audit_admin VARCHAR[], pop_enabled BOOLEAN,
    imap_enabled BOOLEAN, ews_enabled BOOLEAN, owa_enabled BOOLEAN, activesync_enabled BOOLEAN,
    mapi_enabled BOOLEAN, auto_reply_state VARCHAR, auto_reply_start TIMESTAMPTZ,
    auto_reply_end TIMESTAMPTZ, auto_reply_external_audience VARCHAR, auto_reply_message VARCHAR,
    auto_reply_external_message VARCHAR, when_changed TIMESTAMPTZ, raw JSON
);

CREATE TABLE audit_config (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    admin_audit_log_enabled BOOLEAN, unified_audit_log_ingestion_enabled BOOLEAN,
    admin_audit_log_age_limit VARCHAR, log_level VARCHAR, audit_disabled BOOLEAN,
    security_defaults_enabled BOOLEAN, raw JSON
);

CREATE TABLE tenant_settings (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    source VARCHAR, name VARCHAR, value JSON, raw JSON
);

CREATE TABLE transport_rules (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    name VARCHAR, guid VARCHAR, state VARCHAR, mode VARCHAR, priority INTEGER, created_by VARCHAR,
    last_modified_by VARCHAR, when_changed TIMESTAMPTZ, description VARCHAR, conditions JSON,
    exceptions JSON, actions JSON, redirect_to VARCHAR[], blind_copy_to VARCHAR[], copy_to VARCHAR[],
    add_to_recipients VARCHAR[], raw JSON
);

CREATE TABLE remote_domains (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    domain_name VARCHAR, name VARCHAR, auto_forward_enabled BOOLEAN, allowed_ooo_type VARCHAR,
    when_changed TIMESTAMPTZ, raw JSON
);

CREATE TABLE mobile_devices (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    mailbox VARCHAR, device_id VARCHAR, friendly_name VARCHAR, device_type VARCHAR, model VARCHAR,
    os VARCHAR, user_agent VARCHAR, client_type VARCHAR, first_sync TIMESTAMPTZ, last_sync TIMESTAMPTZ,
    access_state VARCHAR, access_state_reason VARCHAR, is_managed BOOLEAN, is_compliant BOOLEAN,
    is_disabled BOOLEAN, when_created TIMESTAMPTZ, raw JSON
);

CREATE TABLE risky_users (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    user_id VARCHAR, upn VARCHAR, display_name VARCHAR, risk_level VARCHAR, risk_state VARCHAR,
    risk_detail VARCHAR, risk_last_updated TIMESTAMPTZ, is_deleted BOOLEAN, is_processing BOOLEAN,
    raw JSON
);

CREATE TABLE risk_detections (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    detection_id VARCHAR, detected_time TIMESTAMPTZ, activity_time TIMESTAMPTZ,
    last_updated_time TIMESTAMPTZ, activity VARCHAR, risk_event_type VARCHAR, risk_level VARCHAR,
    risk_state VARCHAR, risk_detail VARCHAR, detection_timing VARCHAR, source VARCHAR,
    token_issuer_type VARCHAR, ip VARCHAR, user_upn VARCHAR, user_id VARCHAR,
    user_display_name VARCHAR, correlation_id VARCHAR, request_id VARCHAR,
    location STRUCT(city VARCHAR, state VARCHAR, country VARCHAR, latitude DOUBLE, longitude DOUBLE),
    additional_info JSON, raw JSON
);

CREATE TABLE collector_flags (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    file_id BIGINT, flag_type VARCHAR, category VARCHAR, flag_time TIMESTAMPTZ, subject VARCHAR,
    description VARCHAR, linked_table VARCHAR, linked_key VARCHAR, raw JSON
);

-- Common columns.
COMMENT ON TABLE users IS 'Directory users at collection time (Hawk 4 EntraIDUsers, Hawk 3 AzureADUsers). One row per record_key; a newer collection replaces the columns it provides (latest wins).';
COMMENT ON COLUMN users.record_key IS 'Entra object id (lower-case), else the lower-cased UPN.';
COMMENT ON COLUMN users.collection_id IS 'Collection that last wrote this row''s values.';
COMMENT ON COLUMN users.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN users.raw IS 'Source record(s) as loaded; objects from several sources are merged (json_merge_patch).';
COMMENT ON COLUMN users.user_id IS 'Entra object id (Graph Id / MSOnline ObjectID), lower-case.';
COMMENT ON COLUMN users.upn IS 'UserPrincipalName, lower-case.';
COMMENT ON COLUMN users.display_name IS 'DisplayName.';
COMMENT ON COLUMN users.mail IS 'Mail (primary e-mail address), lower-case.';
COMMENT ON COLUMN users.account_enabled IS 'AccountEnabled (false = sign-in blocked).';
COMMENT ON COLUMN users.created IS 'CreatedDateTime / DateCreated.';
COMMENT ON COLUMN users.deleted IS 'DeletedDateTime (soft-deleted users).';
COMMENT ON COLUMN users.last_password_change IS 'LastPasswordChangeDateTime - a password reset during the incident window is a remediation or takeover signal.';
COMMENT ON COLUMN users.user_type IS 'Member or Guest (Hawk 3 UserType).';
COMMENT ON COLUMN users.on_prem_sync IS 'Synchronized from on-premises AD (Hawk 3 DirSyncEnabled).';
COMMENT ON COLUMN users.state_changed IS 'Hawk 3 UserStateChangedOn.';
COMMENT ON COLUMN users.last_signin IS 'Last sign-in time when the source provides it (not collected by Hawk).';
COMMENT ON COLUMN users.department IS 'Department when the source provides it (not collected by Hawk).';
COMMENT ON COLUMN users.job_title IS 'Job title when the source provides it (not collected by Hawk).';

COMMENT ON TABLE role_assignments IS 'Admin role memberships and Exchange role assignments (Entra directory roles, Exchange role groups, eDiscovery and ApplicationImpersonation assignments). Latest wins per record_key.';
COMMENT ON COLUMN role_assignments.record_key IS '<source>|<lower role name>|<principal>: principal is the lower UPN, else the object id, else the lower display name; empty for a role without members.';
COMMENT ON COLUMN role_assignments.collection_id IS 'Collection that last wrote this row''s values.';
COMMENT ON COLUMN role_assignments.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN role_assignments.raw IS 'Source record as loaded.';
COMMENT ON COLUMN role_assignments.source IS 'entra_directory (EntraIDAdministrators / AzureADAdministrators), exchange_rbac (ExchangeOnlineAdministrators, Impersonation_Rights), exchange_ediscovery (EDiscoveryRoleAssignments, CustomEDiscoveryRoles), entra_pim (Extractor Suite, later).';
COMMENT ON COLUMN role_assignments.role_name IS 'Directory role, role group or management role name.';
COMMENT ON COLUMN role_assignments.principal_upn IS 'Member UPN / e-mail (lower-case) when the source gives one.';
COMMENT ON COLUMN role_assignments.principal_id IS 'Member object id when the source gives one.';
COMMENT ON COLUMN role_assignments.principal_name IS 'Member display name (or role assignee name for Exchange assignments).';
COMMENT ON COLUMN role_assignments.principal_type IS 'User, servicePrincipal, group, RoleGroup, UserMailbox, ... as reported; none for a role without members.';
COMMENT ON COLUMN role_assignments.assignment_type IS 'active, eligible or permanent (PIM); delegating for Exchange delegating assignments.';
COMMENT ON COLUMN role_assignments.assignment_name IS 'Exchange role assignment Name.';
COMMENT ON COLUMN role_assignments.enabled IS 'Exchange role assignment Enabled.';
COMMENT ON COLUMN role_assignments.start_time IS 'Assignment start or creation (Exchange WhenCreatedUTC).';
COMMENT ON COLUMN role_assignments.end_time IS 'Assignment end (PIM), when known.';

COMMENT ON TABLE oauth_grants IS 'OAuth consent grants: one row per client, resource, permission and principal (Hawk Consent_Grants). Latest wins per record_key.';
COMMENT ON COLUMN oauth_grants.record_key IS '<client_id>|<resource_id>|<lower permission>|<principal_id or empty>.';
COMMENT ON COLUMN oauth_grants.collection_id IS 'Collection that last wrote this row''s values.';
COMMENT ON COLUMN oauth_grants.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN oauth_grants.raw IS 'Source record as loaded.';
COMMENT ON COLUMN oauth_grants.permission_type IS 'delegated (oauth2PermissionGrant scope) or application (app role assignment).';
COMMENT ON COLUMN oauth_grants.client_id IS 'Client service principal object id (Hawk ClientObjectId), lower-case.';
COMMENT ON COLUMN oauth_grants.client_name IS 'Client application display name.';
COMMENT ON COLUMN oauth_grants.resource_id IS 'Resource service principal object id, lower-case.';
COMMENT ON COLUMN oauth_grants.resource_name IS 'Resource display name (e.g. Microsoft Graph).';
COMMENT ON COLUMN oauth_grants.permission IS 'Scope or app role value (e.g. Mail.Read, offline_access).';
COMMENT ON COLUMN oauth_grants.consent_type IS 'AllPrincipals (admin consent) or Principal (user consent); NULL for application permissions.';
COMMENT ON COLUMN oauth_grants.principal_id IS 'Consenting user object id for Principal grants, lower-case.';
COMMENT ON COLUMN oauth_grants.principal_name IS 'Consenting user display name.';
COMMENT ON COLUMN oauth_grants.principal_upn IS 'Consenting user UPN when the source provides it (not collected by Hawk).';
COMMENT ON COLUMN oauth_grants.risk_category IS 'Hawk ConsentGrantRiskCategory (Broad-Scope Grant, Extremely Dangerous, High Risk) - Hawk''s heuristic, not a Microsoft rating.';
COMMENT ON COLUMN oauth_grants.publisher IS 'Publisher when the source provides it.';
COMMENT ON COLUMN oauth_grants.verified_publisher IS 'Verified publisher when the source provides it.';
COMMENT ON COLUMN oauth_grants.created IS 'Grant creation time when the source provides it.';
COMMENT ON COLUMN oauth_grants.sign_in_audience IS 'Client sign-in audience when the source provides it.';

COMMENT ON TABLE app_credentials IS 'Secrets and certificates on app registrations and service principals (Hawk ApplicationCertsAndSecrets, SPNCertsAndSecrets). Latest wins per record_key.';
COMMENT ON COLUMN app_credentials.record_key IS '<lower app_object_id>|<lower key_id>.';
COMMENT ON COLUMN app_credentials.collection_id IS 'Collection that last wrote this row''s values.';
COMMENT ON COLUMN app_credentials.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN app_credentials.raw IS 'Source record as loaded.';
COMMENT ON COLUMN app_credentials.app_object_id IS 'Object id of the application or service principal, lower-case.';
COMMENT ON COLUMN app_credentials.app_name IS 'Application / service principal display name.';
COMMENT ON COLUMN app_credentials.key_id IS 'Credential KeyId.';
COMMENT ON COLUMN app_credentials.cred_type IS 'password (client secret) or certificate.';
COMMENT ON COLUMN app_credentials.key_type IS 'KeyType as reported (AsymmetricX509Cert, Symmetric, ...).';
COMMENT ON COLUMN app_credentials.start_time IS 'StartDateTime - a credential added during the incident window is a persistence signal.';
COMMENT ON COLUMN app_credentials.end_time IS 'EndDateTime.';
COMMENT ON COLUMN app_credentials.owner IS 'application (app registration) or service_principal.';

COMMENT ON TABLE inbox_rules IS 'Inbox rules (Get-InboxRule) and sweep rules (Get-SweepRule) at collection time. Latest wins per record_key.';
COMMENT ON COLUMN inbox_rules.record_key IS '<kind>|<lower mailbox>|<rule_identity>.';
COMMENT ON COLUMN inbox_rules.collection_id IS 'Collection that last wrote this row''s values.';
COMMENT ON COLUMN inbox_rules.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN inbox_rules.raw IS 'Source record as loaded.';
COMMENT ON COLUMN inbox_rules.kind IS 'inbox or sweep.';
COMMENT ON COLUMN inbox_rules.mailbox IS 'MailboxOwnerId (lower-case), else the user folder UPN.';
COMMENT ON COLUMN inbox_rules.mailbox_upn IS 'UPN of the Hawk user folder the rule came from (kept when a tenant-wide copy lacks it).';
COMMENT ON COLUMN inbox_rules.rule_identity IS 'RuleIdentity (inbox) or RuleId (sweep), else Identity, else Name.';
COMMENT ON COLUMN inbox_rules.name IS 'Rule name - single characters, dots or hiding-folder names are BEC red flags.';
COMMENT ON COLUMN inbox_rules.enabled IS 'Enabled.';
COMMENT ON COLUMN inbox_rules.in_error IS 'InError.';
COMMENT ON COLUMN inbox_rules.priority IS 'Priority.';
COMMENT ON COLUMN inbox_rules.forward_to IS 'ForwardTo recipients (CSV sources give one joined item).';
COMMENT ON COLUMN inbox_rules.forward_as_attachment_to IS 'ForwardAsAttachmentTo recipients.';
COMMENT ON COLUMN inbox_rules.redirect_to IS 'RedirectTo recipients.';
COMMENT ON COLUMN inbox_rules.delete_message IS 'DeleteMessage.';
COMMENT ON COLUMN inbox_rules.soft_delete IS 'SoftDeleteMessage.';
COMMENT ON COLUMN inbox_rules.move_to_folder IS 'MoveToFolder (sweep: DestinationFolder).';
COMMENT ON COLUMN inbox_rules.copy_to_folder IS 'CopyToFolder.';
COMMENT ON COLUMN inbox_rules.mark_as_read IS 'MarkAsRead.';
COMMENT ON COLUMN inbox_rules.stop_processing IS 'StopProcessingRules.';
COMMENT ON COLUMN inbox_rules.from_addresses IS 'From condition (sweep: Sender).';
COMMENT ON COLUMN inbox_rules.subject_contains IS 'SubjectContainsWords.';
COMMENT ON COLUMN inbox_rules.body_contains IS 'BodyContainsWords.';
COMMENT ON COLUMN inbox_rules.subject_or_body_contains IS 'SubjectOrBodyContainsWords.';
COMMENT ON COLUMN inbox_rules.has_attachment IS 'HasAttachment condition.';
COMMENT ON COLUMN inbox_rules.source_folder IS 'Sweep rule SourceFolder.';
COMMENT ON COLUMN inbox_rules.description IS 'Exchange''s human-readable rule description.';

COMMENT ON TABLE mailboxes IS 'Mailbox settings merged from several Hawk files (ForwardingReport, Mailbox_Info.txt, CAS_Mailbox_Info.txt, AutoReply.txt); each file fills its own columns. Latest wins per column.';
COMMENT ON COLUMN mailboxes.record_key IS 'Lower-case UPN (Hawk user folder name, else the record UserPrincipalName).';
COMMENT ON COLUMN mailboxes.collection_id IS 'Collection that last wrote this row''s values.';
COMMENT ON COLUMN mailboxes.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN mailboxes.raw IS 'Source records merged (json_merge_patch) in load order.';
COMMENT ON COLUMN mailboxes.upn IS 'Mailbox UPN, lower-case.';
COMMENT ON COLUMN mailboxes.display_name IS 'DisplayName.';
COMMENT ON COLUMN mailboxes.primary_smtp_address IS 'PrimarySmtpAddress, lower-case.';
COMMENT ON COLUMN mailboxes.object_id IS 'ExternalDirectoryObjectId (Entra object id), lower-case.';
COMMENT ON COLUMN mailboxes.mailbox_guid IS 'Exchange mailbox Guid.';
COMMENT ON COLUMN mailboxes.recipient_type IS 'RecipientTypeDetails, else RecipientType (UserMailbox, SharedMailbox, ...).';
COMMENT ON COLUMN mailboxes.forwarding_smtp_address IS 'ForwardingSmtpAddress as recorded (e.g. smtp:x@example.com) - external forwarding set by the user or an attacker.';
COMMENT ON COLUMN mailboxes.forwarding_address IS 'ForwardingAddress (admin-set forwarding to a recipient object).';
COMMENT ON COLUMN mailboxes.deliver_and_forward IS 'DeliverToMailboxAndForward.';
COMMENT ON COLUMN mailboxes.audit_enabled IS 'Mailbox AuditEnabled (not collected by Hawk).';
COMMENT ON COLUMN mailboxes.audit_owner IS 'AuditOwner actions (not collected by Hawk).';
COMMENT ON COLUMN mailboxes.audit_delegate IS 'AuditDelegate actions (not collected by Hawk).';
COMMENT ON COLUMN mailboxes.audit_admin IS 'AuditAdmin actions (not collected by Hawk).';
COMMENT ON COLUMN mailboxes.pop_enabled IS 'CAS PopEnabled (legacy protocol).';
COMMENT ON COLUMN mailboxes.imap_enabled IS 'CAS ImapEnabled (legacy protocol).';
COMMENT ON COLUMN mailboxes.ews_enabled IS 'CAS EwsEnabled.';
COMMENT ON COLUMN mailboxes.owa_enabled IS 'CAS OWAEnabled.';
COMMENT ON COLUMN mailboxes.activesync_enabled IS 'CAS ActiveSyncEnabled.';
COMMENT ON COLUMN mailboxes.mapi_enabled IS 'CAS MAPIEnabled.';
COMMENT ON COLUMN mailboxes.auto_reply_state IS 'AutoReplyState (Disabled, Enabled, Scheduled).';
COMMENT ON COLUMN mailboxes.auto_reply_start IS 'Auto-reply StartTime.';
COMMENT ON COLUMN mailboxes.auto_reply_end IS 'Auto-reply EndTime.';
COMMENT ON COLUMN mailboxes.auto_reply_external_audience IS 'ExternalAudience (None, Known, All).';
COMMENT ON COLUMN mailboxes.auto_reply_message IS 'InternalMessage (wrapped lines joined with spaces).';
COMMENT ON COLUMN mailboxes.auto_reply_external_message IS 'ExternalMessage (wrapped lines joined with spaces).';
COMMENT ON COLUMN mailboxes.when_changed IS 'Mailbox WhenChangedUTC from the forwarding report.';

COMMENT ON TABLE audit_config IS 'Organization audit configuration (AdminAuditLogConfig, OrganizationConfig). One row, record_key organization; each source fills its own columns.';
COMMENT ON COLUMN audit_config.record_key IS 'Always organization.';
COMMENT ON COLUMN audit_config.collection_id IS 'Collection that last wrote this row''s values.';
COMMENT ON COLUMN audit_config.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN audit_config.raw IS 'Source objects merged (json_merge_patch).';
COMMENT ON COLUMN audit_config.admin_audit_log_enabled IS 'AdminAuditLogConfig AdminAuditLogEnabled.';
COMMENT ON COLUMN audit_config.unified_audit_log_ingestion_enabled IS 'AdminAuditLogConfig UnifiedAuditLogIngestionEnabled (false = no unified audit log).';
COMMENT ON COLUMN audit_config.admin_audit_log_age_limit IS 'AdminAuditLogAgeLimit as reported (e.g. 90.00:00:00).';
COMMENT ON COLUMN audit_config.log_level IS 'AdminAuditLogConfig LogLevel.';
COMMENT ON COLUMN audit_config.audit_disabled IS 'OrganizationConfig AuditDisabled (true = mailbox auditing off for the organization).';
COMMENT ON COLUMN audit_config.security_defaults_enabled IS 'Entra security defaults when the source provides it (not collected by Hawk).';

COMMENT ON TABLE tenant_settings IS 'Name/value tenant settings: every AdminAuditLogConfig, OrganizationConfig and TransportConfig property, and Exchange management role entries. Latest wins per record_key.';
COMMENT ON COLUMN tenant_settings.record_key IS '<source>|<lower name>.';
COMMENT ON COLUMN tenant_settings.collection_id IS 'Collection that last wrote this row''s values.';
COMMENT ON COLUMN tenant_settings.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN tenant_settings.raw IS 'Unused (NULL): value holds the setting.';
COMMENT ON COLUMN tenant_settings.source IS 'admin_audit_log_config, organization_config, transport_config or exchange_role_entry.';
COMMENT ON COLUMN tenant_settings.name IS 'Property name (role entries: Identity, i.e. <role>\<cmdlet>).';
COMMENT ON COLUMN tenant_settings.value IS 'Value as JSON: text for Format-List sources, typed JSON for JSON sources, an object for role entries.';

COMMENT ON TABLE transport_rules IS 'Exchange transport (mail flow) rules at collection time. Latest wins per record_key.';
COMMENT ON COLUMN transport_rules.record_key IS 'Lower-case rule name.';
COMMENT ON COLUMN transport_rules.collection_id IS 'Collection that last wrote this row''s values.';
COMMENT ON COLUMN transport_rules.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN transport_rules.raw IS 'Source record as loaded (JSON sources carry every rule property).';
COMMENT ON COLUMN transport_rules.name IS 'Rule name.';
COMMENT ON COLUMN transport_rules.guid IS 'Rule Guid.';
COMMENT ON COLUMN transport_rules.state IS 'Enabled or Disabled.';
COMMENT ON COLUMN transport_rules.mode IS 'Enforce, Audit, AuditAndNotify.';
COMMENT ON COLUMN transport_rules.priority IS 'Priority.';
COMMENT ON COLUMN transport_rules.created_by IS 'CreatedBy.';
COMMENT ON COLUMN transport_rules.last_modified_by IS 'LastModifiedBy.';
COMMENT ON COLUMN transport_rules.when_changed IS 'WhenChangedUTC, else WhenChanged.';
COMMENT ON COLUMN transport_rules.description IS 'Exchange''s human-readable rule description (conditions and actions in words).';
COMMENT ON COLUMN transport_rules.conditions IS 'Conditions predicate type names (JSON sources only).';
COMMENT ON COLUMN transport_rules.exceptions IS 'Exceptions predicate type names (JSON sources only).';
COMMENT ON COLUMN transport_rules.actions IS 'Actions type names (JSON sources only).';
COMMENT ON COLUMN transport_rules.redirect_to IS 'RedirectMessageTo recipients - external redirection is an exfiltration signal.';
COMMENT ON COLUMN transport_rules.blind_copy_to IS 'BlindCopyTo recipients.';
COMMENT ON COLUMN transport_rules.copy_to IS 'CopyTo recipients.';
COMMENT ON COLUMN transport_rules.add_to_recipients IS 'AddToRecipients.';

COMMENT ON TABLE remote_domains IS 'Exchange remote domains (Get-RemoteDomain): automatic forwarding and out-of-office policy per domain. Latest wins per record_key.';
COMMENT ON COLUMN remote_domains.record_key IS 'Lower-case DomainName.';
COMMENT ON COLUMN remote_domains.collection_id IS 'Collection that last wrote this row''s values.';
COMMENT ON COLUMN remote_domains.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN remote_domains.raw IS 'Source record as loaded.';
COMMENT ON COLUMN remote_domains.domain_name IS 'DomainName (* for the Default remote domain).';
COMMENT ON COLUMN remote_domains.name IS 'Remote domain name.';
COMMENT ON COLUMN remote_domains.auto_forward_enabled IS 'AutoForwardEnabled - true on * allows external auto-forwarding.';
COMMENT ON COLUMN remote_domains.allowed_ooo_type IS 'AllowedOOFType.';
COMMENT ON COLUMN remote_domains.when_changed IS 'WhenChangedUTC, else WhenChanged.';

COMMENT ON TABLE mobile_devices IS 'Exchange ActiveSync / mobile devices per mailbox (Get-MobileDevice). Latest wins per record_key.';
COMMENT ON COLUMN mobile_devices.record_key IS '<lower mailbox>|<lower device_id>.';
COMMENT ON COLUMN mobile_devices.collection_id IS 'Collection that last wrote this row''s values.';
COMMENT ON COLUMN mobile_devices.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN mobile_devices.raw IS 'Source record as loaded.';
COMMENT ON COLUMN mobile_devices.mailbox IS 'Mailbox UPN (Hawk user folder), lower-case.';
COMMENT ON COLUMN mobile_devices.device_id IS 'DeviceId.';
COMMENT ON COLUMN mobile_devices.friendly_name IS 'FriendlyName.';
COMMENT ON COLUMN mobile_devices.device_type IS 'DeviceType.';
COMMENT ON COLUMN mobile_devices.model IS 'DeviceModel.';
COMMENT ON COLUMN mobile_devices.os IS 'DeviceOS.';
COMMENT ON COLUMN mobile_devices.user_agent IS 'DeviceUserAgent.';
COMMENT ON COLUMN mobile_devices.client_type IS 'ClientType (EAS, Outlook, ...).';
COMMENT ON COLUMN mobile_devices.first_sync IS 'FirstSyncTime - a first sync inside the incident window is a persistence signal.';
COMMENT ON COLUMN mobile_devices.last_sync IS 'Last successful sync when the source provides it (not in Get-MobileDevice).';
COMMENT ON COLUMN mobile_devices.access_state IS 'DeviceAccessState.';
COMMENT ON COLUMN mobile_devices.access_state_reason IS 'DeviceAccessStateReason.';
COMMENT ON COLUMN mobile_devices.is_managed IS 'IsManaged.';
COMMENT ON COLUMN mobile_devices.is_compliant IS 'IsCompliant.';
COMMENT ON COLUMN mobile_devices.is_disabled IS 'IsDisabled.';
COMMENT ON COLUMN mobile_devices.when_created IS 'WhenCreatedUTC, else WhenCreated.';

COMMENT ON TABLE risky_users IS 'Entra ID Protection risky users (Get-MgRiskyUser). Latest wins per record_key.';
COMMENT ON COLUMN risky_users.record_key IS 'Lower-case user object id, else lower-case UPN.';
COMMENT ON COLUMN risky_users.collection_id IS 'Collection that last wrote this row''s values.';
COMMENT ON COLUMN risky_users.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN risky_users.raw IS 'Source record as loaded.';
COMMENT ON COLUMN risky_users.user_id IS 'User object id, lower-case.';
COMMENT ON COLUMN risky_users.upn IS 'UserPrincipalName, lower-case.';
COMMENT ON COLUMN risky_users.display_name IS 'UserDisplayName.';
COMMENT ON COLUMN risky_users.risk_level IS 'low, medium, high, hidden, none.';
COMMENT ON COLUMN risky_users.risk_state IS 'atRisk, confirmedCompromised, remediated, dismissed, ...';
COMMENT ON COLUMN risky_users.risk_detail IS 'RiskDetail.';
COMMENT ON COLUMN risky_users.risk_last_updated IS 'RiskLastUpdatedDateTime.';
COMMENT ON COLUMN risky_users.is_deleted IS 'IsDeleted.';
COMMENT ON COLUMN risky_users.is_processing IS 'IsProcessing.';

COMMENT ON TABLE risk_detections IS 'Entra ID Protection risk detections (Get-MgRiskDetection; Hawk Risk_Detections, JSON preferred over the flattened CSV). Keyed by detection id; a newer collection''s copy updates risk_state and other columns (latest wins).';
COMMENT ON COLUMN risk_detections.record_key IS 'Lower-case detection id.';
COMMENT ON COLUMN risk_detections.collection_id IS 'Collection that last wrote this row''s values.';
COMMENT ON COLUMN risk_detections.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN risk_detections.raw IS 'Source record as loaded.';
COMMENT ON COLUMN risk_detections.detection_id IS 'Detection Id.';
COMMENT ON COLUMN risk_detections.detected_time IS 'DetectedDateTime.';
COMMENT ON COLUMN risk_detections.activity_time IS 'ActivityDateTime (when the risky activity happened).';
COMMENT ON COLUMN risk_detections.last_updated_time IS 'LastUpdatedDateTime.';
COMMENT ON COLUMN risk_detections.activity IS 'signin or user.';
COMMENT ON COLUMN risk_detections.risk_event_type IS 'RiskEventType (unfamiliarFeatures, anonymizedIPAddress, impossibleTravel, ...).';
COMMENT ON COLUMN risk_detections.risk_level IS 'low, medium, high, hidden, none.';
COMMENT ON COLUMN risk_detections.risk_state IS 'atRisk, confirmedCompromised, remediated, dismissed, ...';
COMMENT ON COLUMN risk_detections.risk_detail IS 'RiskDetail.';
COMMENT ON COLUMN risk_detections.detection_timing IS 'DetectionTimingType (realtime, offline, ...).';
COMMENT ON COLUMN risk_detections.source IS 'Detection source (IdentityProtection, MicrosoftCloudAppSecurity, ...).';
COMMENT ON COLUMN risk_detections.token_issuer_type IS 'TokenIssuerType.';
COMMENT ON COLUMN risk_detections.ip IS 'IPAddress, normalized like ual_events.client_ip.';
COMMENT ON COLUMN risk_detections.user_upn IS 'UserPrincipalName, lower-case.';
COMMENT ON COLUMN risk_detections.user_id IS 'User object id, lower-case.';
COMMENT ON COLUMN risk_detections.user_display_name IS 'UserDisplayName.';
COMMENT ON COLUMN risk_detections.correlation_id IS 'CorrelationId (joins to sign-ins).';
COMMENT ON COLUMN risk_detections.request_id IS 'RequestId (joins to sign-ins).';
COMMENT ON COLUMN risk_detections.location IS 'Location: city, state, country (CountryOrRegion), latitude, longitude.';
COMMENT ON COLUMN risk_detections.additional_info IS 'AdditionalInfo parsed from its embedded JSON (CSV sources: the AdditionalInfo_* columns as an object).';

COMMENT ON TABLE collector_flags IS 'Items Hawk itself flagged: records of _Investigate_* files and lines of _Investigate.txt. Kept apart from Sparrow findings. linked_table/linked_key point at the flagged row when it can be keyed.';
COMMENT ON COLUMN collector_flags.record_key IS 'SHA-256 hex of flag_type, linked table and key (or the canonical record / log line), so byte-identical copies deduplicate.';
COMMENT ON COLUMN collector_flags.collection_id IS 'Collection in which the flag was first loaded.';
COMMENT ON COLUMN collector_flags.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN collector_flags.raw IS 'Flagged record, or {line} for _Investigate.txt entries.';
COMMENT ON COLUMN collector_flags.file_id IS 'source_files.file_id of the first file the flag was read from.';
COMMENT ON COLUMN collector_flags.flag_type IS 'inbox_rule, risky_consent_grant, impersonation_rights, risky_user, compromised_user, risk_detection, confirmed_compromised_risk_detection, new_mobile_device, admin_inbox_rule_change, mailbox_permission_change, risky_signin, investigate_note, investigate_file_reference or other.';
COMMENT ON COLUMN collector_flags.category IS 'Hawk 3 _Investigate.txt section tag (## Tag ##).';
COMMENT ON COLUMN collector_flags.flag_time IS 'Timestamp of the _Investigate.txt line; NULL for file records and for ambiguous culture dates.';
COMMENT ON COLUMN collector_flags.subject IS 'User UPN of the Hawk user folder, when the file sits in one.';
COMMENT ON COLUMN collector_flags.description IS 'Why Hawk flagged it (fixed text per flag_type, or the log message).';
COMMENT ON COLUMN collector_flags.linked_table IS 'Table holding the flagged record (ual_events, inbox_rules, oauth_grants, role_assignments, risky_users, risk_detections, mobile_devices, signins, admin_audit_events, source_files).';
COMMENT ON COLUMN collector_flags.linked_key IS 'record_key of the flagged row in linked_table (rel_path for source_files; NULL when not computable, e.g. admin_audit_events before that table exists).';
