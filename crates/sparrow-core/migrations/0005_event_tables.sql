-- 0005: Phase 2c event tables (spec 5.1 signins, directory_audits, message_trace,
-- mailbox_audit_legacy; Addendum A.3 admin_audit_events). Same conventions as 0004: no key
-- constraints; the loader (ingest/state.rs, LoadMode::FillMissing) keeps record_key unique.

CREATE TYPE signin_event_type AS ENUM ('interactive', 'noninteractive', 'service_principal', 'managed_identity');

CREATE TABLE signins (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    signin_id VARCHAR, event_time TIMESTAMPTZ, time_tz_assumed BOOLEAN, event_type signin_event_type,
    user_upn VARCHAR, user_id VARCHAR, user_display_name VARCHAR, app_id VARCHAR, app_name VARCHAR,
    resource_id VARCHAR, resource_name VARCHAR, ip VARCHAR, user_agent VARCHAR, client_app VARCHAR,
    is_interactive BOOLEAN, status VARCHAR, error_code INTEGER, failure_reason VARCHAR,
    ca_status VARCHAR, ca_policies JSON, risk_level_during VARCHAR, risk_level_aggregated VARCHAR,
    risk_state VARCHAR, risk_detail VARCHAR, risk_event_types VARCHAR[], auth_requirement VARCHAR,
    mfa_result VARCHAR, mfa_detail VARCHAR, auth_methods VARCHAR[],
    device STRUCT(device_id VARCHAR, display_name VARCHAR, os VARCHAR, browser VARCHAR, is_compliant BOOLEAN, is_managed BOOLEAN, trust_type VARCHAR),
    location STRUCT(city VARCHAR, state VARCHAR, country VARCHAR, latitude DOUBLE, longitude DOUBLE),
    asn INTEGER, session_id VARCHAR, correlation_id VARCHAR, unique_token_id VARCHAR,
    token_issuer_type VARCHAR, incoming_token_type VARCHAR, cross_tenant_access_type VARCHAR,
    home_tenant_id VARCHAR, resource_tenant_id VARCHAR, raw JSON, column_collections JSON
);

CREATE TABLE directory_audits (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    audit_id VARCHAR, event_time TIMESTAMPTZ, time_tz_assumed BOOLEAN, activity VARCHAR,
    category VARCHAR, operation_type VARCHAR, result VARCHAR, result_reason VARCHAR,
    logged_by_service VARCHAR, initiated_by_upn VARCHAR, initiated_by_user_id VARCHAR,
    initiated_by_app_id VARCHAR, initiated_by_app_name VARCHAR, initiated_by_ip VARCHAR,
    targets JSON, modified_properties JSON, additional_details JSON, correlation_id VARCHAR,
    raw JSON, column_collections JSON
);

CREATE TABLE message_trace (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    message_trace_id VARCHAR, received TIMESTAMPTZ, time_tz_assumed BOOLEAN, sender VARCHAR,
    recipient VARCHAR, subject VARCHAR, status VARCHAR, from_ip VARCHAR, to_ip VARCHAR,
    size_bytes BIGINT, internet_message_id VARCHAR, organization VARCHAR, direction VARCHAR,
    connector_id VARCHAR, raw JSON, column_collections JSON
);

CREATE TABLE mailbox_audit_legacy (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    event_time TIMESTAMPTZ, time_tz_assumed BOOLEAN, mailbox_upn VARCHAR, mailbox_guid VARCHAR,
    operation VARCHAR, operation_result VARCHAR, logon_type VARCHAR, logon_user VARCHAR,
    logon_user_sid VARCHAR, client_ip VARCHAR, client_info VARCHAR, client_machine VARCHAR,
    client_process VARCHAR, external_access BOOLEAN, folder_path VARCHAR, dest_folder_path VARCHAR,
    dest_mailbox_upn VARCHAR, cross_mailbox BOOLEAN, subjects VARCHAR[], internet_message_ids VARCHAR[],
    session_id VARCHAR, app_id VARCHAR, client_app_id VARCHAR, raw JSON, column_collections JSON
);

CREATE TABLE admin_audit_events (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    run_time TIMESTAMPTZ, time_tz_assumed BOOLEAN, caller VARCHAR, cmdlet VARCHAR,
    object_modified VARCHAR, parameters MAP(VARCHAR, VARCHAR), modified_properties JSON,
    succeeded BOOLEAN, error VARCHAR, external_access BOOLEAN, client_ip VARCHAR,
    session_id VARCHAR, app_id VARCHAR, client_app_id VARCHAR, originating_server VARCHAR,
    full_command VARCHAR, data_completeness data_completeness, raw JSON, column_collections JSON
);

-- Provenance comments touched by this phase.
COMMENT ON COLUMN source_files.format IS 'File format from the extension: json, jsonl, csv, txt, log, eml, xml, xlsx or unknown.';
COMMENT ON COLUMN source_files.encoding IS 'Detected text encoding (utf-8, utf-8-bom, utf-16le, utf-16be, windows-1252); NULL when not decoded (not parsed, or a binary format such as xlsx).';
COMMENT ON COLUMN source_files.records_read IS 'Records found in the file. Files that expand into several rows per record (Format-List settings, message trace summaries with several recipients) count rows.';
COMMENT ON COLUMN record_sources.record_ordinal IS '0-based position of the record in the file (array index or CSV data row); for XLSX the 1-based sheet row.';
COMMENT ON COLUMN record_sources.line_start IS 'First physical line (1-based) of the record in the decoded file; for XLSX the sheet row number.';
COMMENT ON COLUMN record_sources.line_end IS 'Last physical line (1-based) of the record in the decoded file; for XLSX the sheet row number.';
COMMENT ON COLUMN record_sources.byte_offset IS 'Offset of the record in the raw file bytes; 0 for XLSX (the byte range is the whole workbook).';
COMMENT ON COLUMN record_sources.byte_length IS 'Length of the record in raw file bytes; the file size for XLSX.';
COMMENT ON COLUMN record_sources.raw_sha256 IS 'SHA-256 (hex) of the raw record bytes; for XLSX rows the SHA-256 of the row''s cell texts joined by tabs. sparrow verify re-computes it.';
COMMENT ON COLUMN parse_errors.line_start IS 'First physical line (1-based) of the failed record; for XLSX the sheet row.';
COMMENT ON COLUMN parse_errors.line_end IS 'Last physical line (1-based) of the failed record; for XLSX the sheet row.';
COMMENT ON TABLE collection_log IS 'Collector run log lines: Hawk.log (3.x and 4.x), Hawk 3 PSFramework <date>_logs.csv, Extractor Suite LogFile.txt.';
COMMENT ON COLUMN collection_log.ts IS 'Entry time. Hawk 4: UTC. Hawk 3, PSFramework and Extractor Suite: local time of the collecting machine stored as if UTC (see tz_assumed). Hawk 3 culture dates use the day/month order of the log, else of its collection.';
COMMENT ON COLUMN collection_log.level IS 'Log level tag when present (INFO, ACTION, WARNING, ERROR, INVESTIGATE, PROMPT, ...; PSFramework Level upper-cased).';
COMMENT ON COLUMN collector_flags.linked_table IS 'Table holding the flagged record (ual_events, inbox_rules, oauth_grants, role_assignments, risky_users, risk_detections, mobile_devices, signins, admin_audit_events, source_files).';
COMMENT ON COLUMN collector_flags.linked_key IS 'record_key of the flagged row in linked_table. For source_files: the rel_path guessed from the absolute path Hawk logged; join through collector_flags.file_id -> source_files.collection_id to stay in the same collection. NULL when not computable (no id, or an admin audit flag whose dates stay ambiguous).';

-- Shared text of the event tables.
COMMENT ON TABLE signins IS 'Entra ID sign-ins: Hawk Entra_Sign_In_Log (Get-MgAuditLogSignIn; JSON preferred over the flattened CSV) and Entra admin center sign-in exports (CSV or XLSX). One row per sign-in id; a copy from another file or collection only fills columns that are still NULL.';
COMMENT ON COLUMN signins.record_key IS 'Sign-in id (Graph id, portal Request ID), lower-case.';
COMMENT ON COLUMN signins.collection_id IS 'Collection in which the sign-in was first loaded.';
COMMENT ON COLUMN signins.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN signins.raw IS 'Source record as first loaded; later copies add only the keys it lacks (json_merge_patch).';
COMMENT ON COLUMN signins.column_collections IS 'Object {column: collection_id} naming the collection that supplied each column. Evidence is never overwritten: a later copy of the record only fills columns that are still NULL.';
COMMENT ON COLUMN signins.signin_id IS 'Sign-in id (Graph id / portal Request ID), lower-case.';
COMMENT ON COLUMN signins.event_time IS 'Sign-in time (Graph createdDateTime, portal Date (UTC)).';
COMMENT ON COLUMN signins.time_tz_assumed IS 'True when the source time had no zone and UTC was assumed (Hawk CSV culture dates).';
COMMENT ON COLUMN signins.event_type IS 'interactive or noninteractive (Graph isInteractive, or the portal export file name), service_principal or managed_identity (portal export file name).';
COMMENT ON COLUMN signins.user_upn IS 'UserPrincipalName (portal Username), lower-case.';
COMMENT ON COLUMN signins.user_id IS 'User object id, lower-case.';
COMMENT ON COLUMN signins.user_display_name IS 'User display name (portal User).';
COMMENT ON COLUMN signins.app_id IS 'Client application id, lower-case.';
COMMENT ON COLUMN signins.app_name IS 'Client application display name.';
COMMENT ON COLUMN signins.resource_id IS 'Resource (API) id, lower-case.';
COMMENT ON COLUMN signins.resource_name IS 'Resource display name.';
COMMENT ON COLUMN signins.ip IS 'Client IP address, normalized like ual_events.client_ip.';
COMMENT ON COLUMN signins.user_agent IS 'User agent (portal exports and Graph beta only).';
COMMENT ON COLUMN signins.client_app IS 'Client app used (Browser, Mobile Apps and Desktop clients, Exchange ActiveSync, IMAP4, other legacy clients, ...).';
COMMENT ON COLUMN signins.is_interactive IS 'Interactive sign-in.';
COMMENT ON COLUMN signins.status IS 'Success, Failure or Interrupted (portal Status); for Graph sources Success when error_code is 0, else Failure.';
COMMENT ON COLUMN signins.error_code IS 'Sign-in error code (0 success; e.g. 50126 invalid password, 50074 strong authentication required).';
COMMENT ON COLUMN signins.failure_reason IS 'Failure reason text.';
COMMENT ON COLUMN signins.ca_status IS 'Conditional Access result (success, failure, notApplied).';
COMMENT ON COLUMN signins.ca_policies IS 'Applied Conditional Access policies (Graph appliedConditionalAccessPolicies).';
COMMENT ON COLUMN signins.risk_level_during IS 'Risk level during sign-in (none, low, medium, high, hidden).';
COMMENT ON COLUMN signins.risk_level_aggregated IS 'Aggregated user risk level at sign-in.';
COMMENT ON COLUMN signins.risk_state IS 'Risk state (none, atRisk, confirmedCompromised, remediated, dismissed, ...).';
COMMENT ON COLUMN signins.risk_detail IS 'Risk detail.';
COMMENT ON COLUMN signins.risk_event_types IS 'Risk event types (riskEventTypes_v2, else riskEventTypes).';
COMMENT ON COLUMN signins.auth_requirement IS 'singleFactorAuthentication or multiFactorAuthentication (portal Authentication requirement).';
COMMENT ON COLUMN signins.mfa_result IS 'Portal Multifactor authentication result.';
COMMENT ON COLUMN signins.mfa_detail IS 'Portal Multifactor authentication auth detail.';
COMMENT ON COLUMN signins.auth_methods IS 'Authentication methods used (portal Multifactor authentication auth method; Graph beta authenticationDetails).';
COMMENT ON COLUMN signins.device IS 'Device: device_id, display_name, os, browser, is_compliant, is_managed, trust_type (portal Join Type).';
COMMENT ON COLUMN signins.location IS 'Location: city, state, country, latitude, longitude (portal: the Location text split on commas, no coordinates).';
COMMENT ON COLUMN signins.asn IS 'Autonomous system number of the client IP (portal exports).';
COMMENT ON COLUMN signins.session_id IS 'Session id (portal Session ID): groups the sign-ins of one session, an AiTM pivot.';
COMMENT ON COLUMN signins.correlation_id IS 'Correlation id, lower-case.';
COMMENT ON COLUMN signins.unique_token_id IS 'Unique token identifier (portal).';
COMMENT ON COLUMN signins.token_issuer_type IS 'Token issuer type (AzureAD, ADFederationServices, ...).';
COMMENT ON COLUMN signins.incoming_token_type IS 'Incoming token type (portal: primaryRefreshToken, ...).';
COMMENT ON COLUMN signins.cross_tenant_access_type IS 'Cross tenant access type (portal).';
COMMENT ON COLUMN signins.home_tenant_id IS 'Home tenant id of the user, lower-case.';
COMMENT ON COLUMN signins.resource_tenant_id IS 'Tenant id of the resource, lower-case.';

COMMENT ON TABLE directory_audits IS 'Entra ID directory audit events (Hawk EntraIDAuditLogs from Get-MgAuditLogDirectoryAudit; JSON preferred over the CSV, whose nested columns are .NET type names). One row per audit id; later copies only fill NULL columns.';
COMMENT ON COLUMN directory_audits.record_key IS 'Audit id, lower-case.';
COMMENT ON COLUMN directory_audits.collection_id IS 'Collection in which the event was first loaded.';
COMMENT ON COLUMN directory_audits.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN directory_audits.raw IS 'Source record as first loaded; later copies add only the keys it lacks (json_merge_patch).';
COMMENT ON COLUMN directory_audits.column_collections IS 'Object {column: collection_id} naming the collection that supplied each column. Evidence is never overwritten: a later copy of the record only fills columns that are still NULL.';
COMMENT ON COLUMN directory_audits.audit_id IS 'Audit event Id, lower-case.';
COMMENT ON COLUMN directory_audits.event_time IS 'ActivityDateTime.';
COMMENT ON COLUMN directory_audits.time_tz_assumed IS 'True when the source time had no zone and UTC was assumed (CSV culture dates).';
COMMENT ON COLUMN directory_audits.activity IS 'ActivityDisplayName (e.g. Add member to role, Consent to application, Update user).';
COMMENT ON COLUMN directory_audits.category IS 'Category (UserManagement, ApplicationManagement, RoleManagement, ...).';
COMMENT ON COLUMN directory_audits.operation_type IS 'OperationType (Add, Update, Delete, Assign, ...).';
COMMENT ON COLUMN directory_audits.result IS 'Result (success, failure, ...).';
COMMENT ON COLUMN directory_audits.result_reason IS 'ResultReason.';
COMMENT ON COLUMN directory_audits.logged_by_service IS 'LoggedByService (Core Directory, Self-service Password Management, ...).';
COMMENT ON COLUMN directory_audits.initiated_by_upn IS 'InitiatedBy.User.UserPrincipalName, lower-case.';
COMMENT ON COLUMN directory_audits.initiated_by_user_id IS 'InitiatedBy.User.Id, lower-case.';
COMMENT ON COLUMN directory_audits.initiated_by_app_id IS 'InitiatedBy.App.AppId, lower-case.';
COMMENT ON COLUMN directory_audits.initiated_by_app_name IS 'InitiatedBy.App.DisplayName.';
COMMENT ON COLUMN directory_audits.initiated_by_ip IS 'InitiatedBy.User.IPAddress, normalized like ual_events.client_ip.';
COMMENT ON COLUMN directory_audits.targets IS 'TargetResources as collected.';
COMMENT ON COLUMN directory_audits.modified_properties IS 'TargetResources[].ModifiedProperties flattened to [{target, property, old, new}]; old/new are the JSON text Graph returns.';
COMMENT ON COLUMN directory_audits.additional_details IS 'AdditionalDetails key/value list.';
COMMENT ON COLUMN directory_audits.correlation_id IS 'CorrelationId, lower-case.';

COMMENT ON TABLE message_trace IS 'Exchange Online message trace: Hawk 3 Message_Trace (Get-MessageTrace) and Exchange admin center message trace summary reports. One row per message and recipient; a copy from another source only fills NULL columns.';
COMMENT ON COLUMN message_trace.record_key IS '<message_trace_id>|<recipient>, lower-case (Get-MessageTrace MessageTraceId is the summary report network_message_id).';
COMMENT ON COLUMN message_trace.collection_id IS 'Collection in which the row was first loaded.';
COMMENT ON COLUMN message_trace.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN message_trace.raw IS 'Source record as first loaded; later copies add only the keys it lacks (json_merge_patch).';
COMMENT ON COLUMN message_trace.column_collections IS 'Object {column: collection_id} naming the collection that supplied each column. Evidence is never overwritten: a later copy of the record only fills columns that are still NULL.';
COMMENT ON COLUMN message_trace.message_trace_id IS 'MessageTraceId / network_message_id, lower-case.';
COMMENT ON COLUMN message_trace.received IS 'Received / origin_timestamp_utc (UTC).';
COMMENT ON COLUMN message_trace.time_tz_assumed IS 'True when the source time had no zone and UTC was assumed (Get-MessageTrace times are UTC).';
COMMENT ON COLUMN message_trace.sender IS 'SenderAddress / sender_address, lower-case.';
COMMENT ON COLUMN message_trace.recipient IS 'RecipientAddress, or the recipient part of a recipient_status entry, lower-case.';
COMMENT ON COLUMN message_trace.subject IS 'Subject / message_subject.';
COMMENT ON COLUMN message_trace.status IS 'Delivery status (Delivered, Failed, FilteredAsSpam, ...; the status part of a recipient_status entry).';
COMMENT ON COLUMN message_trace.from_ip IS 'FromIP / original_client_ip: address the message was submitted from, normalized.';
COMMENT ON COLUMN message_trace.to_ip IS 'ToIP: address of the receiving server, normalized.';
COMMENT ON COLUMN message_trace.size_bytes IS 'Size / total_bytes.';
COMMENT ON COLUMN message_trace.internet_message_id IS 'MessageId / message_id (Internet message id).';
COMMENT ON COLUMN message_trace.organization IS 'Organization (Hawk).';
COMMENT ON COLUMN message_trace.direction IS 'directionality (portal: Originating, Incoming, ...).';
COMMENT ON COLUMN message_trace.connector_id IS 'connector_id (portal).';

COMMENT ON TABLE mailbox_audit_legacy IS 'Mailbox audit log records from Search-MailboxAuditLog (Hawk 3 Exchange_Mailbox_Audit; JSON preferred over the CSV). No natural id: record_key hashes the fields that identify an action. Later copies only fill NULL columns.';
COMMENT ON COLUMN mailbox_audit_legacy.record_key IS 'SHA-256 hex of event time (UTC, seconds), operation, mailbox, logon user SID, client IP, item ids, folder id, session id and operation result.';
COMMENT ON COLUMN mailbox_audit_legacy.collection_id IS 'Collection in which the record was first loaded.';
COMMENT ON COLUMN mailbox_audit_legacy.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN mailbox_audit_legacy.raw IS 'Source record as first loaded; later copies add only the keys it lacks (json_merge_patch).';
COMMENT ON COLUMN mailbox_audit_legacy.column_collections IS 'Object {column: collection_id} naming the collection that supplied each column. Evidence is never overwritten: a later copy of the record only fills columns that are still NULL.';
COMMENT ON COLUMN mailbox_audit_legacy.event_time IS 'LastAccessed: when the action happened.';
COMMENT ON COLUMN mailbox_audit_legacy.time_tz_assumed IS 'True when LastAccessed had no zone (CSV culture dates: local time of the collecting machine stored as if UTC).';
COMMENT ON COLUMN mailbox_audit_legacy.mailbox_upn IS 'MailboxOwnerUPN, else the Hawk user folder, lower-case.';
COMMENT ON COLUMN mailbox_audit_legacy.mailbox_guid IS 'MailboxGuid, lower-case.';
COMMENT ON COLUMN mailbox_audit_legacy.operation IS 'Operation (HardDelete, SoftDelete, MoveToDeletedItems, SendAs, FolderBind, Update, ...).';
COMMENT ON COLUMN mailbox_audit_legacy.operation_result IS 'OperationResult (Succeeded, Failed, PartiallySucceeded).';
COMMENT ON COLUMN mailbox_audit_legacy.logon_type IS 'LogonType (Owner, Delegate, Admin).';
COMMENT ON COLUMN mailbox_audit_legacy.logon_user IS 'LogonUserDisplayName.';
COMMENT ON COLUMN mailbox_audit_legacy.logon_user_sid IS 'LogonUserSid.';
COMMENT ON COLUMN mailbox_audit_legacy.client_ip IS 'ClientIPAddress, else ClientIP, normalized.';
COMMENT ON COLUMN mailbox_audit_legacy.client_info IS 'ClientInfoString (client application).';
COMMENT ON COLUMN mailbox_audit_legacy.client_machine IS 'ClientMachineName.';
COMMENT ON COLUMN mailbox_audit_legacy.client_process IS 'ClientProcessName.';
COMMENT ON COLUMN mailbox_audit_legacy.external_access IS 'ExternalAccess (true = Microsoft datacenter administrator or service access).';
COMMENT ON COLUMN mailbox_audit_legacy.folder_path IS 'FolderPathName.';
COMMENT ON COLUMN mailbox_audit_legacy.dest_folder_path IS 'DestFolderPathName (move/copy target).';
COMMENT ON COLUMN mailbox_audit_legacy.dest_mailbox_upn IS 'DestMailboxOwnerUPN, lower-case.';
COMMENT ON COLUMN mailbox_audit_legacy.cross_mailbox IS 'CrossMailboxOperation.';
COMMENT ON COLUMN mailbox_audit_legacy.subjects IS 'ItemSubject and SourceItems[].Subject (else SourceItemSubjectsList).';
COMMENT ON COLUMN mailbox_audit_legacy.internet_message_ids IS 'ItemInternetMessageId and SourceItems[].InternetMessageId (else SourceItemInternetMessageIdsList).';
COMMENT ON COLUMN mailbox_audit_legacy.session_id IS 'SessionId.';
COMMENT ON COLUMN mailbox_audit_legacy.app_id IS 'AppId, lower-case.';
COMMENT ON COLUMN mailbox_audit_legacy.client_app_id IS 'ClientAppId, lower-case.';

COMMENT ON TABLE admin_audit_events IS 'Exchange admin audit log (Hawk 3 Search-AdminAuditLog files: New_/Set_/Remove_InboxRules, RBAC_Changes, User_Changes, and the five-column Simple_* summaries when the full file is absent). The same command from JSON, CSV, Format-List text, _Investigate_ copies or a Simple_* summary gets one record_key.';
COMMENT ON COLUMN admin_audit_events.record_key IS 'SHA-256 hex of run time (UTC, seconds), cmdlet, ObjectModified after its last / and \, and the caller as Hawk''s Simple_* summary writes it, all lower-case. Parameters are not part of the key: Simple_* summaries have none.';
COMMENT ON COLUMN admin_audit_events.collection_id IS 'Collection in which the command was first loaded.';
COMMENT ON COLUMN admin_audit_events.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN admin_audit_events.raw IS 'Source record as first loaded; later copies add only the keys it lacks (json_merge_patch).';
COMMENT ON COLUMN admin_audit_events.column_collections IS 'Object {column: collection_id} naming the collection that supplied each column. Evidence is never overwritten: a later copy of the record only fills columns that are still NULL.';
COMMENT ON COLUMN admin_audit_events.run_time IS 'RunDate (RunDate(UTC) of Simple_* summaries).';
COMMENT ON COLUMN admin_audit_events.time_tz_assumed IS 'True when RunDate had no zone (full-form CSV and Format-List text: local time of the collecting machine stored as if UTC). Simple_* RunDate(UTC) is UTC.';
COMMENT ON COLUMN admin_audit_events.caller IS 'Caller, lower-case.';
COMMENT ON COLUMN admin_audit_events.cmdlet IS 'CmdletName (Cmdlet in summaries), e.g. New-InboxRule, Add-MailboxPermission, New-ManagementRoleAssignment.';
COMMENT ON COLUMN admin_audit_events.object_modified IS 'ObjectModified as written (summaries keep only its last path segment).';
COMMENT ON COLUMN admin_audit_events.parameters IS 'CmdletParameters as name -> value (JSON sources only), e.g. parameters[''ForwardTo''].';
COMMENT ON COLUMN admin_audit_events.modified_properties IS 'ModifiedProperties (JSON sources only).';
COMMENT ON COLUMN admin_audit_events.succeeded IS 'Succeeded.';
COMMENT ON COLUMN admin_audit_events.error IS 'Error text.';
COMMENT ON COLUMN admin_audit_events.external_access IS 'ExternalAccess (true = Microsoft datacenter administrator).';
COMMENT ON COLUMN admin_audit_events.client_ip IS 'ClientIP, normalized.';
COMMENT ON COLUMN admin_audit_events.session_id IS 'SessionId.';
COMMENT ON COLUMN admin_audit_events.app_id IS 'AppId, lower-case.';
COMMENT ON COLUMN admin_audit_events.client_app_id IS 'ClientAppId, lower-case.';
COMMENT ON COLUMN admin_audit_events.originating_server IS 'OriginatingServer.';
COMMENT ON COLUMN admin_audit_events.full_command IS 'FullCommand of Simple_* summaries (the command line Hawk rebuilt from the parameters).';
COMMENT ON COLUMN admin_audit_events.data_completeness IS 'full for a JSON Search-AdminAuditLog record; partial for CSV (parameters lost) and Simple_* summaries.';
