-- Migration 24: message_trace_events, one row per delivery event of the Exchange admin center message trace DETAIL
-- ("extended") report. The same report is also collapsed into message_trace (one row per message and recipient), so
-- consumers of message_trace need no change. Nothing existing is rewritten.
CREATE TABLE message_trace_events (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    event_time TIMESTAMPTZ, time_tz_assumed BOOLEAN, network_message_id VARCHAR, internal_message_id VARCHAR,
    internet_message_id VARCHAR, event_id VARCHAR, source VARCHAR, source_context VARCHAR, sender VARCHAR,
    recipients JSON, related_recipient VARCHAR, recipient_status VARCHAR, client_ip VARCHAR,
    client_hostname VARCHAR, server_ip VARCHAR, server_hostname VARCHAR, original_client_ip VARCHAR,
    original_server_ip VARCHAR, connector_id VARCHAR, total_bytes BIGINT, recipient_count INTEGER,
    reference VARCHAR, subject VARCHAR, return_path VARCHAR, message_info VARCHAR, directionality VARCHAR,
    tenant_id VARCHAR, custom_data VARCHAR, raw JSON, column_collections JSON, tz_assumed JSON
);

COMMENT ON TABLE message_trace_events IS 'Delivery events of the Exchange admin center message trace detail ("extended") report (MTDetail_*.csv): one row per event (RECEIVE, SUBMIT, EXPAND, DELIVER, SENDEXTERNAL, REDIRECT, DUPLICATEREDIRECT, DROP, FAIL, ...), so a message has many rows. Shows what the summary report cannot: mailbox forwarding (DUPLICATEREDIRECT events whose source_context is Forwarding SMTP Address or Forwarding Address, with the destination in related_recipient), drops, external sends and the submitting client address. The report has no event id: the same event downloaded twice (identical cells; columns may be ordered differently) is one row with two sightings. The events of each message are also collapsed into message_trace, one row per message and recipient.';
COMMENT ON COLUMN message_trace_events.record_key IS 'csvrow: followed by the SHA-256 hex of the row''s non-empty cells sorted by lower-case header, each written as <byte length of header>:<header><byte length of value>:<value>. The report has no event id.';
COMMENT ON COLUMN message_trace_events.collection_id IS 'Collection in which the row was first loaded.';
COMMENT ON COLUMN message_trace_events.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN message_trace_events.raw IS 'Source row as first loaded, every column with its original text (addresses before normalization included); later copies add only the keys it lacks (json_merge_patch).';
COMMENT ON COLUMN message_trace_events.column_collections IS 'Object {column: collection_id} naming the collection that supplied each column. Evidence is never overwritten: a later copy of the row only fills columns that are still NULL.';
COMMENT ON COLUMN message_trace_events.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC. Per column like column_collections: the load that writes a column sets or clears its entry. The detail report writes a Z, so it is normally empty.';
COMMENT ON COLUMN message_trace_events.event_time IS 'date_time_utc: when the event happened (UTC, 7 fractional digits in the report).';
COMMENT ON COLUMN message_trace_events.time_tz_assumed IS 'True when the source time had no zone and UTC was assumed (the report writes a Z).';
COMMENT ON COLUMN message_trace_events.network_message_id IS 'network_message_id, lower-case: the message trace id that ties the events of one message together (message_trace.message_trace_id).';
COMMENT ON COLUMN message_trace_events.internal_message_id IS 'internal_message_id as written (Exchange''s numeric id of the message inside the service).';
COMMENT ON COLUMN message_trace_events.internet_message_id IS 'message_id: the Internet message id (<...@...>).';
COMMENT ON COLUMN message_trace_events.event_id IS 'event_id as written: RECEIVE, SUBMIT, DELIVER, SENDEXTERNAL, TRANSFER, EXPAND, RESOLVE, REDIRECT, DUPLICATEREDIRECT, DUPLICATEDELIVER, DUPLICATEEXPAND, RESUBMIT, AGENTINFO, RECIPIENTINFO, DROP, FAIL, DEFER, SETROUTE, ... Open text.';
COMMENT ON COLUMN message_trace_events.source IS 'source: the Exchange component that logged the event (STOREDRIVER, RESOLVER, AGENT, ROUTING, SMTP, ...).';
COMMENT ON COLUMN message_trace_events.source_context IS 'source_context: free text about the event; Forwarding SMTP Address or Forwarding Address on a DUPLICATEREDIRECT event marks mailbox forwarding.';
COMMENT ON COLUMN message_trace_events.sender IS 'sender_address, lower-case.';
COMMENT ON COLUMN message_trace_events.recipients IS 'JSON array of the addresses in recipient_address (several are separated by ; in the report), lower-case, in the order written, empty entries dropped. NULL when the event names no recipient.';
COMMENT ON COLUMN message_trace_events.related_recipient IS 'related_recipient_address, lower-case: for EXPAND the distribution group, for a forwarding DUPLICATEREDIRECT the forwarding destination.';
COMMENT ON COLUMN message_trace_events.recipient_status IS 'recipient_status as written: free text, often empty, ; or an SMTP reply such as 250 2.1.5 Recipient OK.';
COMMENT ON COLUMN message_trace_events.client_ip IS 'client_ip, normalized. NULL when the report gives an address that is not a plain IPv4/IPv6 address (for example a link-local address with a %zone); the original text is in raw.';
COMMENT ON COLUMN message_trace_events.client_hostname IS 'client_hostname.';
COMMENT ON COLUMN message_trace_events.server_ip IS 'server_ip, normalized (often a Microsoft address). NULL when it is not a plain IP address; the original text is in raw.';
COMMENT ON COLUMN message_trace_events.server_hostname IS 'server_hostname.';
COMMENT ON COLUMN message_trace_events.original_client_ip IS 'original_client_ip, normalized: the address the message was submitted from (often empty). NULL when it is not a plain IP address; the original text is in raw.';
COMMENT ON COLUMN message_trace_events.original_server_ip IS 'original_server_ip, normalized. NULL when it is not a plain IP address; the original text is in raw.';
COMMENT ON COLUMN message_trace_events.connector_id IS 'connector_id.';
COMMENT ON COLUMN message_trace_events.total_bytes IS 'total_bytes: message size at this event.';
COMMENT ON COLUMN message_trace_events.recipient_count IS 'recipient_count.';
COMMENT ON COLUMN message_trace_events.reference IS 'reference as written.';
COMMENT ON COLUMN message_trace_events.subject IS 'message_subject.';
COMMENT ON COLUMN message_trace_events.return_path IS 'return_path as written.';
COMMENT ON COLUMN message_trace_events.message_info IS 'message_info as written: a long ;-separated S:Key=Value string.';
COMMENT ON COLUMN message_trace_events.directionality IS 'directionality: Incoming, Originating, Undefined, or NULL when empty.';
COMMENT ON COLUMN message_trace_events.tenant_id IS 'tenant_id as written (GUID).';
COMMENT ON COLUMN message_trace_events.custom_data IS 'custom_data as written: a long ;-separated S:Key=Value string.';

COMMENT ON TABLE message_trace IS 'Exchange Online message trace: Hawk 3 Message_Trace (Get-MessageTrace), Exchange admin center message trace summary reports, and the events of the message trace detail report collapsed to one row per message and recipient (the events themselves are in message_trace_events). One row per message and recipient; a copy from another source only fills NULL columns.';
COMMENT ON COLUMN message_trace.status IS 'Delivery status (Delivered, Failed, FilteredAsSpam, ...; the status part of a recipient_status entry). From the detail report: the event_id of the last event (by time, ties by file order) that names the recipient and is one of DELIVER, SENDEXTERNAL, FAIL, DROP, REDIRECT, DUPLICATEREDIRECT, DEFER, EXPAND or DUPLICATEDELIVER, stored as recorded (for example DELIVER); NULL when the message has none.';

COMMENT ON COLUMN tenant.tenant_id_source IS 'Which evidence column supplied tenant_id: ual_organization_id, signin_resource_tenant, message_trace_tenant (message_trace_events.tenant_id, from the message trace detail report) or directory_audit_actor_home_tenant (the ActorHomeTenantId cell of a portal Entra audit CSV row whose ActorType is User, read from raw; a fallback: counted only for a collection that has no evidence from the other sources, and only through files recognised as portal.entra_audit, because a guest actor''s home tenant can differ). Per collection the source with most sighted rows wins, ties by that order.';
