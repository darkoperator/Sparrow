-- Migration 25: events, one row per event record of every event evidence table, with normalized account, IP, device
-- and Entra session columns. Generalizes the timeline view (migration 0009) into a materialized table: the investigate
-- grid pages, filters and draws a histogram over it, which a view over millions of UAL rows cannot do in about a second.
-- Derived like ip_intel: rewritten by every profile run (case::events::rebuild, called right after ip_intel). Evidence
-- tables are never written; analyst marks (a later migration) key on (source_table, record_key) and survive a rebuild.
CREATE TABLE events (
    source_table VARCHAR NOT NULL, record_key VARCHAR NOT NULL, source VARCHAR NOT NULL,
    event_time TIMESTAMPTZ, time_tz_assumed BOOLEAN, tenant_key VARCHAR, workload VARCHAR, category event_category NOT NULL,
    operation VARCHAR, result VARCHAR, actor_upn VARCHAR, owner_upn VARCHAR, target VARCHAR,
    ip VARCHAR, ip_prefix VARCHAR, ip_country VARCHAR, asn INTEGER, asn_org VARCHAR, ip_kind VARCHAR,
    device_id VARCHAR, device_name VARCHAR, device_object_id VARCHAR, entra_session_id VARCHAR,
    user_agent VARCHAR, app_id VARCHAR, summary VARCHAR,
    PRIMARY KEY (source_table, record_key)
);
CREATE INDEX events_event_time ON events (event_time);

COMMENT ON TABLE events IS 'One row per event record: ual_events, parent-less mail_items_accessed, signins (interactive and non-interactive), directory_audits, message_trace, message_trace_events, mailbox_audit_legacy, admin_audit_events, risk_detections, azure_activity and security_alerts. Derived: DELETE and re-INSERT by every profile run (after ip_intel), never written by anything else. The timeline view stays as it is; events adds the normalized actor/owner, IP prefix and intel, device and Entra session columns, and message_trace_events rows.';
COMMENT ON COLUMN events.source_table IS 'Evidence table the row came from: ual_events, mail_items_accessed, signins, directory_audits, message_trace, message_trace_events, mailbox_audit_legacy, admin_audit_events, risk_detections, azure_activity or security_alerts. With record_key, the primary key.';
COMMENT ON COLUMN events.record_key IS 'Key of the record in source_table, as in the timeline view: record_id text for ual_events, item_key for mail_items_accessed, record_key elsewhere.';
COMMENT ON COLUMN events.source IS 'Grid source: ual, signin_interactive, signin_noninteractive (non-interactive user sign-ins and any sign-in of unknown type), signin_service (event_type service_principal or managed_identity, whatever is_interactive says), mail_items_accessed, message_trace, message_trace_event, entra_audit, mailbox_audit, admin_audit, risk_detection, azure_activity or security_alert.';
COMMENT ON COLUMN events.event_time IS 'Event time (UTC), from the same column as the timeline view; for message_trace_events, event_time.';
COMMENT ON COLUMN events.time_tz_assumed IS 'True when the source time had no timezone and UTC was assumed (false for risk_detections and security_alerts, as in the timeline view).';
COMMENT ON COLUMN events.tenant_key IS 'collections.tenant_key of the collection that first delivered the row (NULL when the collection has no tenant).';
COMMENT ON COLUMN events.workload IS 'Workload as in the timeline view; Exchange for message_trace_events.';
COMMENT ON COLUMN events.category IS 'Not in the original column plan; the grid''s default timeline phase uses it. event_category from operation_catalog (workload-specific match wins), computed once per distinct (source table, workload, operation); else auth for signins/risk_detections, mail_flow for message_trace/message_trace_events, config_change for azure_activity, other otherwise. Same fallback as the timeline view.';
COMMENT ON COLUMN events.operation IS 'Operation, as in the timeline view (SignInSucceeded/SignInFailed, MessageTrace, MailItemsAccessed, directory_audits.activity, cmdlet, ...); the event_id (RECEIVE, DELIVER, ...) for message_trace_events.';
COMMENT ON COLUMN events.result IS 'Outcome as the source writes it: ual_events.result_status, signins.status, directory_audits.result, message_trace.status, mailbox_audit_legacy.operation_result, Succeeded/Failed from admin_audit_events.succeeded, risk_detections.risk_state, azure_activity.status, security_alerts.status, message_trace_events.recipient_status; NULL for mail_items_accessed.';
COMMENT ON COLUMN events.actor_upn IS 'Who performed the action, lower-cased; the timeline view''s actor (falls back to an app or service name where the source has no user).';
COMMENT ON COLUMN events.owner_upn IS 'Lower-cased. The mailbox owner for MailItemsAccessed (ual_events.mailbox_upn; the user of a parent-less mail_items_accessed row, which comes from a per-mailbox Sessions report) and for mailbox_audit_legacy (mailbox_upn); the recipient for message_trace and the first recipient of a message_trace_events row; otherwise NULL.';
COMMENT ON COLUMN events.target IS 'What the action touched, as in the timeline view; the recipient for message_trace_events.';
COMMENT ON COLUMN events.ip IS 'Client IP, normalize_ip form (the source tables already store it that way; a value that does not parse is kept lower-cased).';
COMMENT ON COLUMN events.ip_prefix IS 'a.b.c.0/24 for an IPv4 address, the /48 network text (2001:db8:abcd::/48) for an IPv6 address, NULL when ip is NULL or not an address.';
COMMENT ON COLUMN events.ip_country IS 'ip_intel.country_iso for the row''s raw IP text.';
COMMENT ON COLUMN events.asn IS 'ip_intel.asn.';
COMMENT ON COLUMN events.asn_org IS 'ip_intel.asn_org.';
COMMENT ON COLUMN events.ip_kind IS 'private (ip_intel.is_private), else microsoft (is_microsoft), else hosting (is_hosting), else NULL. vpn is added later by the VPN-provider list queue item.';
COMMENT ON COLUMN events.device_id IS 'Lower-cased Entra DEVICE id (devices.device_id, what sign-ins carry), never the all-zero GUID: signins.device.device_id; the Id entry of DeviceProperties in AzureActiveDirectory ual_events; for a directory_audits row, in order: its DeviceId / TargetId.DeviceId modified property (the logic of case::devices), else devices.device_id of the row''s device target object id, else NULL. NULL as well when the audit row targets several different devices (ambiguous).';
COMMENT ON COLUMN events.device_name IS 'Display name of that device: signins.device.display_name, the DisplayName entry of DeviceProperties, the display name of the directory_audits Device target. NULL for an audit row that targets several different devices.';
COMMENT ON COLUMN events.device_object_id IS 'Lower-cased directory OBJECT id of the device (not the Entra device id): the Id of the directory_audits row''s Device target, with a Device_ prefix stripped (Device_<oid> and the bare oid are the same device). Two targets that are the same device are one device; targets of several different devices make the row ambiguous and device_id, device_object_id and device_name are all NULL. NULL for every other source (sign-ins and UAL carry the device id). A device tab matches device_id OR device_object_id.';
COMMENT ON COLUMN events.entra_session_id IS 'Lower-cased Entra session id, first present of: (1) ual_events audit_data AppAccessContext.AADSessionId; (2) ual_events audit_data DeviceProperties entry SessionId (STS logon records); (3) signins.session_id. A given row uses only the sources of its own table (UAL: 1 then 2; sign-ins: 3). NOT ual_events.session_id (it prefers the top-level SessionId, an Exchange session on mailbox events), mail_items_accessed.session_id or mailbox_audit_legacy.session_id (Exchange sessions): NULL for those.';
COMMENT ON COLUMN events.user_agent IS 'User agent, when the source records one (as in the timeline view).';
COMMENT ON COLUMN events.app_id IS 'Application id: ual_events.app_id, signins.app_id, directory_audits.initiated_by_app_id, mailbox_audit_legacy.app_id, admin_audit_events.app_id; NULL elsewhere.';
COMMENT ON COLUMN events.summary IS 'One-line description, as in the timeline view; for message_trace_events event_id, source_context and subject.';
