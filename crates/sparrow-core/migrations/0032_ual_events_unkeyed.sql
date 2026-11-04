-- Migration 32: ual_events without its PRIMARY KEY (record_id). DuckDB holds a key index in memory and never spills it
-- (about 43 B a key: 1.2 GB for 28M random ids; random ids keep the whole index resident on insert), so at the 2 GB
-- memory limit every further UAL file failed with "Out of Memory" once a case held about 35M UAL records (measured
-- with 3 GB portal UAL exports of random ids), however the files were split. The ingest keeps record_id unique itself
-- (the UAL merge writes one row per record_id not stored yet; the first copy staged wins among equals). DuckDB cannot
-- drop a constraint in place, so the table is rebuilt: same columns, same NOT NULLs, same rows (in the same order: DuckDB
-- preserves insertion order), same comments. The views that read it (timeline, auth_events) bind by name and need no
-- change; its child tables (mail_items_accessed, file_events, sharing_events, search_queries) have no foreign key.
-- The migration runner applies this in one transaction: a failure leaves the case as it was.
CREATE TABLE ual_events_v32 (
    record_id UUID NOT NULL,
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
INSERT INTO ual_events_v32
SELECT record_id, collection_id, event_time, time_tz_assumed, time_precision, record_type, record_type_name, workload,
       operation, result_status, user_upn, user_type, user_key, client_ip, user_agent, session_id, app_id,
       client_app_id, object_id, organization_id, mailbox_upn, parameters, audit_data, data_completeness, synthetic_id
FROM ual_events;
DROP TABLE ual_events;
ALTER TABLE ual_events_v32 RENAME TO ual_events;

COMMENT ON TABLE ual_events IS 'Unified audit log events (one row per AuditData Id) from every source: Hawk raw/expanded/flattened files and Purview audit search exports. All sightings are in record_sources (table_name = ''ual_events''). record_id is unique: the ingest writes each record once (there is no key index).';
COMMENT ON COLUMN ual_events.record_id IS 'AuditData Id (natural key, unique: the ingest writes each record_id once; there is no key index). When a record has no valid Id, a UUIDv5 of its canonical AuditData (see synthetic_id).';
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
COMMENT ON COLUMN ual_events.client_ip IS 'First of ClientIP, ClientIPAddress, ActorIpAddress; port and brackets removed, IPv6 lower-cased and compressed, IPv4-mapped IPv6 (::ffff:a.b.c.d) written as plain IPv4.';
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
