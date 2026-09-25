-- 0006: Phase 3 (Microsoft-Extractor-Suite). Same conventions as 0004/0005: no key
-- constraints; the loaders keep record_key unique.

CREATE TABLE collector_runs (
    collection_id BIGINT NOT NULL,
    rel_dir VARCHAR NOT NULL,
    component VARCHAR,
    run_stamp TIMESTAMPTZ,
    run_stamp_tz_assumed BOOLEAN,
    run_label VARCHAR,
    files INTEGER NOT NULL,
    empty_files INTEGER NOT NULL,
    bytes BIGINT NOT NULL
);
COMMENT ON TABLE collector_runs IS 'Microsoft-Extractor-Suite run folders: every directory at or below a <Component>/<yyyyMMdd-HHmmss>[-Label] folder of an Output root, with what it holds. A folder with files = 0, or files that are all empty, means the cmdlet ran and returned nothing (not the same as "not collected"). Rewritten from the file system on every ingest of the collection.';
COMMENT ON COLUMN collector_runs.collection_id IS 'Collection (Output root) holding the folder.';
COMMENT ON COLUMN collector_runs.rel_dir IS 'Folder path relative to the collection root, components joined with /.';
COMMENT ON COLUMN collector_runs.component IS 'Component folder the run belongs to (UnifiedAuditLog, EntraID, Mailbox Audit Log, ...): the path component before the first run-stamp folder.';
COMMENT ON COLUMN collector_runs.run_stamp IS 'Stamp of the nearest run folder at or above rel_dir (yyyyMMdd-HHmmss, the collecting host''s local time stored as if UTC; see run_stamp_tz_assumed).';
COMMENT ON COLUMN collector_runs.run_stamp_tz_assumed IS 'Always true: run folder stamps carry no time zone.';
COMMENT ON COLUMN collector_runs.run_label IS 'Suffix of that run folder after the stamp (SignInLogs, AuditLogs, OAuthPermissions, Legacy, ...); NULL when none.';
COMMENT ON COLUMN collector_runs.files IS 'Regular files directly in the folder (OS junk such as .DS_Store excluded).';
COMMENT ON COLUMN collector_runs.empty_files IS 'Of those, files with no content (0 bytes, or only a byte-order mark and whitespace): the cmdlet exported zero objects.';
COMMENT ON COLUMN collector_runs.bytes IS 'Total size of those files in bytes.';
COMMENT ON COLUMN collections.collected_at IS 'When the collection started: the Hawk folder timestamp, or the earliest Microsoft-Extractor-Suite run folder stamp. The stamp is the collecting machine''s local time stored as if UTC (see collected_at_tz_assumed).';

CREATE TYPE mailbox_right AS ENUM ('full_access', 'send_as', 'send_on_behalf', 'folder');

CREATE TABLE mailbox_permissions (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    mailbox_upn VARCHAR, mailbox_display_name VARCHAR, recipient_type VARCHAR, grantee VARCHAR,
    grantee_upn VARCHAR, permission mailbox_right, folder VARCHAR, access_rights VARCHAR[],
    deny BOOLEAN, inheritance VARCHAR, raw JSON, column_collections JSON
);
COMMENT ON TABLE mailbox_permissions IS 'Mailbox delegation at collection time, one row per grant (spec 5.2), from Microsoft-Extractor-Suite Get-MailboxPermissions. Latest wins per column; a grant removed later is not deleted (see collection_id).';
COMMENT ON COLUMN mailbox_permissions.record_key IS '<mailbox upn>|<permission>|<folder or empty>|<lower-case grantee>.';
COMMENT ON COLUMN mailbox_permissions.collection_id IS 'Newest collection that wrote or re-confirmed any of this row''s columns (per-column writers: column_collections).';
COMMENT ON COLUMN mailbox_permissions.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN mailbox_permissions.mailbox_upn IS 'Mailbox UserPrincipalName, lower-case.';
COMMENT ON COLUMN mailbox_permissions.mailbox_display_name IS 'Mailbox DisplayName.';
COMMENT ON COLUMN mailbox_permissions.recipient_type IS 'Mailbox RecipientTypeDetails (UserMailbox, SharedMailbox, ...).';
COMMENT ON COLUMN mailbox_permissions.grantee IS 'Grantee as exported: "<DisplayName> (<PrimarySmtpAddress>)", or the raw identity when the collector could not resolve it (e.g. a role group such as Discovery Management).';
COMMENT ON COLUMN mailbox_permissions.grantee_upn IS 'SMTP address from the grantee text, lower-case; NULL when the grantee has none.';
COMMENT ON COLUMN mailbox_permissions.permission IS 'full_access (Add-MailboxPermission), send_as (Add-RecipientPermission), send_on_behalf (GrantSendOnBehalfTo) or folder (Calendar / Inbox folder permission).';
COMMENT ON COLUMN mailbox_permissions.folder IS 'calendar or inbox for folder permissions; NULL otherwise.';
COMMENT ON COLUMN mailbox_permissions.access_rights IS 'Access rights of the grant (FullAccess; SendAs; folder roles such as Editor, Reviewer); NULL when not exported (SendOnBehalf).';
COMMENT ON COLUMN mailbox_permissions.deny IS 'True for a Deny entry (FullAccess Deny, SendAs Type Deny); NULL when not exported.';
COMMENT ON COLUMN mailbox_permissions.inheritance IS 'InheritanceType of the entry (All, None, ...); NULL when not exported.';
COMMENT ON COLUMN mailbox_permissions.raw IS 'The mailbox row the grant was parsed from (json_merge_patch across copies, top-level nulls ignored).';
COMMENT ON COLUMN mailbox_permissions.column_collections IS 'Object {column: collection_id} naming the collection that last wrote each column. Per-column latest wins.';

ALTER TABLE mailboxes ADD COLUMN audit_bypass_enabled BOOLEAN;
ALTER TABLE mailboxes ADD COLUMN default_audit_set VARCHAR[];
ALTER TABLE mailboxes ADD COLUMN effective_audit_state VARCHAR;
COMMENT ON TABLE mailboxes IS 'Mailbox settings merged from several files, each filling its own columns: Hawk ForwardingReport, Mailbox_Info.txt, CAS_Mailbox_Info.txt, AutoReply.txt; Microsoft-Extractor-Suite MailboxAuditStatus and MailboxPermissions. Latest wins per column.';
COMMENT ON COLUMN mailboxes.audit_enabled IS 'Mailbox AuditEnabled (Microsoft-Extractor-Suite MailboxAuditStatus; not collected by Hawk). With organization-default auditing Get-Mailbox shows True for supported mailboxes; False on e.g. a discovery mailbox, which is not a supported mailbox type.';
COMMENT ON COLUMN mailboxes.audit_owner IS 'AuditOwner actions (MailboxAuditStatus OwnerAuditActions; not collected by Hawk).';
COMMENT ON COLUMN mailboxes.audit_delegate IS 'AuditDelegate actions (MailboxAuditStatus DelegateAuditActions; not collected by Hawk).';
COMMENT ON COLUMN mailboxes.audit_admin IS 'AuditAdmin actions (MailboxAuditStatus AdminAuditActions; not collected by Hawk).';
COMMENT ON COLUMN mailboxes.audit_bypass_enabled IS 'Mailbox audit bypass (Get-MailboxAuditBypassAssociation AuditBypassEnabled): when true, no mailbox action by this account is logged, as owner, delegate or admin.';
COMMENT ON COLUMN mailboxes.default_audit_set IS 'DefaultAuditSet: logon types (Admin, Delegate, Owner) still on Microsoft''s default action list. A type missing here was customized and does not get new default actions (e.g. MailItemsAccessed, Send).';
COMMENT ON COLUMN mailboxes.effective_audit_state IS 'Microsoft-Extractor-Suite EffectiveAuditState: "Enabled (Organization Policy)" (organization auditing on, not bypassed), "Bypassed" or "Disabled" (organization auditing off). Computed by the collector from AuditDisabled and the bypass list, not from AuditEnabled.';
COMMENT ON COLUMN audit_config.audit_disabled IS 'Get-OrganizationConfig AuditDisabled (Hawk OrgConfig.txt). For Microsoft-Extractor-Suite it is derived from MailboxAuditStatus EffectiveAuditState: any "Enabled (Organization Policy)" mailbox means false, any "Disabled" mailbox means true.';

ALTER TABLE mail_items_accessed ADD COLUMN item_key VARCHAR;
ALTER TABLE mail_items_accessed ADD COLUMN event_time TIMESTAMPTZ;
ALTER TABLE mail_items_accessed ADD COLUMN time_tz_assumed BOOLEAN;
ALTER TABLE mail_items_accessed ADD COLUMN user_upn VARCHAR;
ALTER TABLE mail_items_accessed ADD COLUMN client_ip VARCHAR;
ALTER TABLE mail_items_accessed ADD COLUMN session_id VARCHAR;
COMMENT ON TABLE mail_items_accessed IS 'MailItemsAccessed details: one row per accessed item (or one row per folder/record when items are not listed). Child of ual_events; rows with record_id NULL come from Microsoft-Extractor-Suite MessageIDs CSVs whose raw UAL record was not collected.';
COMMENT ON COLUMN mail_items_accessed.record_id IS 'Parent ual_events.record_id; NULL for a Microsoft-Extractor-Suite MessageIDs row with no matching raw MailItemsAccessed record (then item_key, event_time, user_upn, client_ip and session_id describe the access).';
COMMENT ON COLUMN mail_items_accessed.item_key IS 'Key of a parent-less MessageIDs row (UUIDv5 of its normalized values; record_sources.record_key with table_name mail_items_accessed); NULL for child rows.';
COMMENT ON COLUMN mail_items_accessed.event_time IS 'Access time (UTC) of a parent-less row; NULL for child rows (see the parent ual_events.event_time).';
COMMENT ON COLUMN mail_items_accessed.time_tz_assumed IS 'True when event_time came without a zone (UAL CreationTime is UTC by definition); NULL for child rows.';
COMMENT ON COLUMN mail_items_accessed.user_upn IS 'Mailbox user of a parent-less row, lower-case; NULL for child rows.';
COMMENT ON COLUMN mail_items_accessed.client_ip IS 'Client IP of a parent-less row, normalized; NULL for child rows.';
COMMENT ON COLUMN mail_items_accessed.session_id IS 'Session id of a parent-less row; NULL for child rows and when the collector left it empty.';

-- Sign-ins: Microsoft-Extractor-Suite reads Graph beta sign-ins.
COMMENT ON COLUMN signins.event_type IS 'interactive, noninteractive, service_principal or managed_identity: from Graph beta signInEventTypes (Microsoft-Extractor-Suite), else isInteractive (Hawk Graph v1.0 objects; interactive or noninteractive only), else the portal export file name.';
COMMENT ON COLUMN signins.mfa_detail IS 'Portal Multifactor authentication auth detail, or Graph beta mfaDetail.authDetail.';
COMMENT ON COLUMN signins.auth_methods IS 'Authentication methods used (portal Multifactor authentication auth method; Graph beta authenticationDetails, with mfaDetail.authMethod appended when not already listed).';
