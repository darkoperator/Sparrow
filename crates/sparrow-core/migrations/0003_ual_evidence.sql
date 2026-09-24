-- 0003: portal_export collections and unified audit log evidence tables.

-- DuckDB cannot add a value to an ENUM in place: round-trip the column through VARCHAR.
ALTER TABLE collections ALTER tool TYPE VARCHAR;
DROP TYPE collector_tool;
CREATE TYPE collector_tool AS ENUM ('hawk', 'invictus', 'portal_export');
ALTER TABLE collections ALTER tool TYPE collector_tool;
COMMENT ON COLUMN collections.tool IS 'Collector that produced the folder: hawk, invictus (Microsoft-Extractor-Suite) or portal_export (files an analyst exported from the Purview, Entra or Exchange admin portals).';

ALTER TABLE collections ADD COLUMN collected_at_tz_assumed BOOLEAN;
COMMENT ON COLUMN collections.collected_at IS 'When the collector run started, from the Hawk folder timestamp when available. The stamp is the collecting machine''s local time stored as if UTC (see collected_at_tz_assumed).';
COMMENT ON COLUMN collections.collected_at_tz_assumed IS 'True when collected_at came from a timestamp without timezone (Hawk folder name) and UTC was assumed.';

CREATE TYPE data_completeness AS ENUM ('full', 'partial');
CREATE TYPE time_precision AS ENUM ('second', 'minute');
CREATE TYPE mail_access_type AS ENUM ('bind', 'sync');
CREATE TYPE file_item_type AS ENUM ('file', 'folder', 'page', 'list', 'other');
CREATE TYPE link_type AS ENUM ('anonymous', 'company', 'specific_people', 'direct', 'other');
CREATE TYPE share_permission AS ENUM ('view', 'edit', 'other');
CREATE TYPE search_workload AS ENUM ('exchange', 'sharepoint');

CREATE TABLE ual_events (
    record_id UUID PRIMARY KEY,
    collection_id BIGINT NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    time_tz_assumed BOOLEAN NOT NULL,
    time_precision time_precision NOT NULL,
    record_type SMALLINT,
    record_type_name VARCHAR,
    workload VARCHAR,
    operation VARCHAR,
    result_status VARCHAR,
    user_upn VARCHAR,
    user_type SMALLINT,
    user_key VARCHAR,
    client_ip VARCHAR,
    user_agent VARCHAR,
    session_id VARCHAR,
    app_id VARCHAR,
    client_app_id VARCHAR,
    object_id VARCHAR,
    organization_id UUID,
    mailbox_upn VARCHAR,
    parameters MAP(VARCHAR, VARCHAR),
    audit_data JSON NOT NULL,
    data_completeness data_completeness NOT NULL,
    synthetic_id BOOLEAN NOT NULL
);

CREATE TABLE mail_items_accessed (
    record_id UUID,
    item_ordinal INTEGER NOT NULL,
    collection_id BIGINT NOT NULL,
    access_type mail_access_type,
    folder_path VARCHAR,
    internet_message_id VARCHAR,
    size_bytes BIGINT,
    is_throttled BOOLEAN,
    operation_count INTEGER
);

CREATE TABLE file_events (
    record_id UUID NOT NULL,
    collection_id BIGINT NOT NULL,
    workload VARCHAR,
    site_url VARCHAR,
    relative_url VARCHAR,
    file_name VARCHAR,
    file_ext VARCHAR,
    item_type file_item_type NOT NULL,
    is_onenote BOOLEAN NOT NULL,
    application_name VARCHAR,
    platform VARCHAR,
    device_name VARCHAR,
    list_id VARCHAR,
    list_item_id VARCHAR
);

CREATE TABLE sharing_events (
    record_id UUID NOT NULL,
    collection_id BIGINT NOT NULL,
    link_type link_type NOT NULL,
    target_user VARCHAR,
    target_email VARCHAR,
    permission share_permission,
    is_external BOOLEAN
);

CREATE TABLE search_queries (
    record_id UUID NOT NULL,
    collection_id BIGINT NOT NULL,
    workload search_workload NOT NULL,
    query_text VARCHAR,
    scope VARCHAR
);

COMMENT ON TABLE ual_events IS 'Unified audit log events (one row per AuditData Id) from every source: Hawk raw/expanded/flattened files and Purview audit search exports. All sightings are in record_sources (table_name = ''ual_events'').';
COMMENT ON COLUMN ual_events.record_id IS 'AuditData Id (natural key). When a record has no valid Id, a UUIDv5 of its canonical AuditData (see synthetic_id).';
COMMENT ON COLUMN ual_events.collection_id IS 'Collection in which the record was first loaded.';
COMMENT ON COLUMN ual_events.event_time IS 'AuditData CreationTime (UTC); falls back to the export''s CreationDate when CreationTime is missing.';
COMMENT ON COLUMN ual_events.time_tz_assumed IS 'True when the source timestamp had no timezone and UTC was assumed (normal for AuditData CreationTime).';
COMMENT ON COLUMN ual_events.time_precision IS 'second, or minute when the source dropped seconds (Hawk Converted_Authentication_Logs).';
COMMENT ON COLUMN ual_events.record_type IS 'AuditLogRecordType number (e.g. 1 ExchangeAdmin, 2 ExchangeItem, 15 AzureActiveDirectoryStsLogon).';
COMMENT ON COLUMN ual_events.record_type_name IS 'AuditLogRecordType name for record_type (Microsoft Management Activity API schema).';
COMMENT ON COLUMN ual_events.workload IS 'AuditData Workload (Exchange, SharePoint, OneDrive, AzureActiveDirectory, ...).';
COMMENT ON COLUMN ual_events.operation IS 'AuditData Operation (e.g. New-InboxRule, MailItemsAccessed, FileDownloaded, UserLoggedIn).';
COMMENT ON COLUMN ual_events.result_status IS 'AuditData ResultStatus as recorded (Succeeded, Success, True, Failed, ...).';
COMMENT ON COLUMN ual_events.user_upn IS 'AuditData UserId, lower-cased (usually a UPN; may be a service name).';
COMMENT ON COLUMN ual_events.user_type IS 'AuditData UserType (0 Regular, 2 Admin, 4 System, 5 Application, 6 ServicePrincipal, 10 Guest, ...).';
COMMENT ON COLUMN ual_events.user_key IS 'AuditData UserKey (PUID or other stable user identifier).';
COMMENT ON COLUMN ual_events.client_ip IS 'First of ClientIP, ClientIPAddress, ActorIpAddress; port and brackets removed, IPv6 lower-cased and compressed.';
COMMENT ON COLUMN ual_events.user_agent IS 'UserAgent, else the ExtendedProperties UserAgent entry, else ClientInfoString.';
COMMENT ON COLUMN ual_events.session_id IS 'AuditData SessionId, else AppAccessContext.AADSessionId.';
COMMENT ON COLUMN ual_events.app_id IS 'AuditData AppId, else ApplicationId.';
COMMENT ON COLUMN ual_events.client_app_id IS 'AuditData ClientAppId, else AppAccessContext.ClientAppId.';
COMMENT ON COLUMN ual_events.object_id IS 'AuditData ObjectId (target object: mailbox\rule, file URL, ...).';
COMMENT ON COLUMN ual_events.organization_id IS 'AuditData OrganizationId (tenant id).';
COMMENT ON COLUMN ual_events.mailbox_upn IS 'AuditData MailboxOwnerUPN, lower-cased (mailbox the action touched).';
COMMENT ON COLUMN ual_events.parameters IS 'Cmdlet Parameters, OperationProperties and flattened Param_* values as name -> value (first occurrence wins), e.g. parameters[''ForwardTo''].';
COMMENT ON COLUMN ual_events.audit_data IS 'The AuditData object as loaded (for partial rows: the flattened or CSV record).';
COMMENT ON COLUMN ual_events.data_completeness IS 'full when AuditData was complete; partial when only a lossy form was available (CSV with @{...}/System.Object[] cells, Simple_* flattening, Hawk application audit, Converted_Authentication_Logs). A later full copy replaces a partial row.';
COMMENT ON COLUMN ual_events.synthetic_id IS 'True when record_id was derived from content because the record had no valid Id.';

COMMENT ON TABLE mail_items_accessed IS 'MailItemsAccessed details: one row per accessed item (or one row per folder/record when items are not listed). Child of ual_events.';
COMMENT ON COLUMN mail_items_accessed.record_id IS 'Parent ual_events.record_id (NULL for Extractor Suite MessageIDs rows in a later phase).';
COMMENT ON COLUMN mail_items_accessed.item_ordinal IS '0-based position of the row within its parent record.';
COMMENT ON COLUMN mail_items_accessed.collection_id IS 'Collection of the parent record.';
COMMENT ON COLUMN mail_items_accessed.access_type IS 'bind (item opened) or sync (folder synchronized) from OperationProperties MailAccessType.';
COMMENT ON COLUMN mail_items_accessed.folder_path IS 'Folders[].Path of the accessed folder.';
COMMENT ON COLUMN mail_items_accessed.internet_message_id IS 'FolderItems[].InternetMessageId of the accessed message.';
COMMENT ON COLUMN mail_items_accessed.size_bytes IS 'FolderItems[].SizeInBytes of the accessed message.';
COMMENT ON COLUMN mail_items_accessed.is_throttled IS 'OperationProperties IsThrottled when present (throttled records under-report accesses).';
COMMENT ON COLUMN mail_items_accessed.operation_count IS 'AuditData OperationCount (accesses aggregated into the record).';

COMMENT ON TABLE file_events IS 'SharePoint / OneDrive file operation details. Child of ual_events.';
COMMENT ON COLUMN file_events.record_id IS 'Parent ual_events.record_id.';
COMMENT ON COLUMN file_events.collection_id IS 'Collection of the parent record.';
COMMENT ON COLUMN file_events.workload IS 'SharePoint or OneDrive.';
COMMENT ON COLUMN file_events.site_url IS 'AuditData SiteUrl.';
COMMENT ON COLUMN file_events.relative_url IS 'AuditData SourceRelativeUrl (folder of the item).';
COMMENT ON COLUMN file_events.file_name IS 'AuditData SourceFileName.';
COMMENT ON COLUMN file_events.file_ext IS 'SourceFileExtension (or the file name extension), lower-case.';
COMMENT ON COLUMN file_events.item_type IS 'file, folder, page, list or other, from AuditData ItemType.';
COMMENT ON COLUMN file_events.is_onenote IS 'True for OneNote items (.one/.onetoc2/.onepkg or a OneNote application/user agent) - a common BEC lure.';
COMMENT ON COLUMN file_events.application_name IS 'AuditData ApplicationDisplayName.';
COMMENT ON COLUMN file_events.platform IS 'AuditData Platform when present.';
COMMENT ON COLUMN file_events.device_name IS 'AuditData DeviceDisplayName when present.';
COMMENT ON COLUMN file_events.list_id IS 'AuditData ListId.';
COMMENT ON COLUMN file_events.list_item_id IS 'AuditData ListItemUniqueId.';

COMMENT ON TABLE sharing_events IS 'SharePoint / OneDrive sharing operations (links, invitations, direct shares). Child of ual_events.';
COMMENT ON COLUMN sharing_events.record_id IS 'Parent ual_events.record_id.';
COMMENT ON COLUMN sharing_events.collection_id IS 'Collection of the parent record.';
COMMENT ON COLUMN sharing_events.link_type IS 'anonymous (Anyone link), company, specific_people (secure link), direct (SharingSet/invitations) or other (access requests, inheritance).';
COMMENT ON COLUMN sharing_events.target_user IS 'AuditData TargetUserOrGroupName.';
COMMENT ON COLUMN sharing_events.target_email IS 'target_user lower-cased when it is an e-mail address.';
COMMENT ON COLUMN sharing_events.permission IS 'view, edit or other, inferred from EventData / SharingType text; NULL when absent.';
COMMENT ON COLUMN sharing_events.is_external IS 'From TargetUserOrGroupType: Guest = true, Member = false, otherwise NULL. Tenant-domain based classification arrives with tenant_domains.';

COMMENT ON TABLE search_queries IS 'Mailbox and SharePoint search query events. Child of ual_events.';
COMMENT ON COLUMN search_queries.record_id IS 'Parent ual_events.record_id.';
COMMENT ON COLUMN search_queries.collection_id IS 'Collection of the parent record.';
COMMENT ON COLUMN search_queries.workload IS 'exchange (SearchQueryInitiated) or sharepoint (SharepointSearchQueryInitiated).';
COMMENT ON COLUMN search_queries.query_text IS 'Query text when the record carries one (QueryText, SearchQuery or Query; not documented by Microsoft).';
COMMENT ON COLUMN search_queries.scope IS 'Query source or scope when present (QuerySource, Scope or SearchScope).';
