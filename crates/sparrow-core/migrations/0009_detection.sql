-- Migration 9: detection (Phase 6). Findings, their evidence, the run log and the case indicators.
-- Later tasks append sections under `-- Task N:`.

-- Task 3: detection runs, findings, finding evidence, case indicators.
CREATE TYPE detection_status AS ENUM ('ran', 'not_applicable', 'error');
CREATE TYPE finding_status AS ENUM ('new', 'in_review', 'confirmed', 'false_positive', 'benign', 'needs_more_data');
CREATE TYPE finding_creator AS ENUM ('rule', 'analyst', 'agent');
CREATE TYPE evidence_role AS ENUM ('trigger', 'context');
CREATE TYPE indicator_type AS ENUM ('ip', 'upn', 'app_id', 'domain', 'user_agent', 'rule_name', 'email', 'url', 'hash');
CREATE TYPE indicator_verdict AS ENUM ('malicious', 'suspicious', 'benign');

CREATE TABLE detection_runs (
    run_id BIGINT NOT NULL,
    tenant_key VARCHAR NOT NULL,
    rule_id VARCHAR NOT NULL,
    rule_version INTEGER NOT NULL,
    rule_sha256 VARCHAR NOT NULL,
    status detection_status NOT NULL,
    reason VARCHAR,
    hits BIGINT NOT NULL,
    duration_ms BIGINT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE findings (
    finding_id VARCHAR NOT NULL,
    fingerprint VARCHAR NOT NULL,
    tenant_key VARCHAR NOT NULL,
    rule_id VARCHAR,
    rule_version INTEGER,
    rule_sha256 VARCHAR,
    severity VARCHAR NOT NULL,
    title VARCHAR NOT NULL,
    actor_upn VARCHAR,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    status finding_status NOT NULL DEFAULT 'new',
    disposition_reason VARCHAR,
    created_by finding_creator NOT NULL,
    assigned_to VARCHAR,
    rule_updated BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE finding_evidence (
    finding_id VARCHAR NOT NULL,
    source_table VARCHAR NOT NULL,
    record_key VARCHAR NOT NULL,
    event_time TIMESTAMPTZ,
    role evidence_role NOT NULL,
    context JSON,
    added_run_id BIGINT NOT NULL
);

CREATE TABLE case_indicators (
    indicator_id VARCHAR NOT NULL,
    tenant_key VARCHAR,
    type indicator_type NOT NULL,
    value VARCHAR NOT NULL,
    verdict indicator_verdict NOT NULL,
    note VARCHAR,
    added_by VARCHAR NOT NULL,
    added_at TIMESTAMPTZ NOT NULL
);

COMMENT ON TABLE detection_runs IS 'One row per (tenant, rule) attempt of a detection run: whether the rule ran, was not applicable (a required capability or evidence is missing) or failed, with its hit count. Written only by detection. All rows of one run share run_id.';
COMMENT ON COLUMN detection_runs.run_id IS 'Detection run number: max(run_id) + 1 at the start of the run; shared by every rule and tenant of that run.';
COMMENT ON COLUMN detection_runs.tenant_key IS 'Tenant the rule ran for (tenant.tenant_key, the key collections.tenant_key uses; the spec''s tenant_id).';
COMMENT ON COLUMN detection_runs.rule_id IS 'Rule id (SPW-<CATEGORY>-<NNN>).';
COMMENT ON COLUMN detection_runs.rule_version IS 'The rule''s version field when it ran.';
COMMENT ON COLUMN detection_runs.rule_sha256 IS 'Hash of the rule text and the static lists it references. For a rule using @list:case_iocs.*, sha256 of that hash plus the sorted "type<TAB>value" lines of the case indicators it read, so adding or removing an indicator changes it.';
COMMENT ON COLUMN detection_runs.status IS 'ran, not_applicable (reason names the missing capability or evidence) or error (reason holds the message).';
COMMENT ON COLUMN detection_runs.reason IS 'Why the rule was not applicable, or the error message; NULL when it ran.';
COMMENT ON COLUMN detection_runs.hits IS 'Rows the rule returned (0 unless status is ran).';
COMMENT ON COLUMN detection_runs.duration_ms IS 'Wall time of the rule query in milliseconds (not asserted by tests).';
COMMENT ON COLUMN detection_runs.started_at IS 'Start of the detection run (DetectOptions.now, else the wall clock); the same for every row of a run.';

COMMENT ON TABLE findings IS 'Detection findings. fingerprint = sha256 hex of rule_id, tenant_key and the rule''s group_by values joined by the byte 0x1f (a NULL value is the byte 0x00); finding_id is its first 16 hex characters, so a re-run finds the same finding. Phase 6 writes only status = ''new'' and created_by = ''rule''; status, disposition_reason and assigned_to are the analyst''s (Phase 7) and detection never writes them. Findings are never deleted.';
COMMENT ON COLUMN findings.finding_id IS 'First 16 hex characters of the fingerprint.';
COMMENT ON COLUMN findings.fingerprint IS 'sha256 hex of rule_id 0x1f tenant_key 0x1f value1 0x1f value2 ... (group_by values in order; NULL is 0x00).';
COMMENT ON COLUMN findings.tenant_key IS 'Tenant the finding belongs to (tenant.tenant_key; the spec''s tenant_id). A fingerprint includes it, so two tenants never share a finding.';
COMMENT ON COLUMN findings.rule_id IS 'Rule that raised the finding; NULL for an analyst-created finding (Phase 7).';
COMMENT ON COLUMN findings.rule_version IS 'Rule version at the latest run that hit this finding.';
COMMENT ON COLUMN findings.rule_sha256 IS 'Rule hash (see detection_runs.rule_sha256) at the latest run; a difference from the current hash sets rule_updated.';
COMMENT ON COLUMN findings.severity IS 'info, low, medium, high or critical, from the rule at the latest run.';
COMMENT ON COLUMN findings.title IS 'The rule''s title at the latest run.';
COMMENT ON COLUMN findings.actor_upn IS 'The first actor UPN among the finding''s hits (NULL when none has one).';
COMMENT ON COLUMN findings.first_seen IS 'Earliest hit time; only ever widened by later runs.';
COMMENT ON COLUMN findings.last_seen IS 'Latest hit time; only ever widened by later runs.';
COMMENT ON COLUMN findings.status IS 'Analyst workflow status (Phase 7). Detection inserts ''new'' and never changes it.';
COMMENT ON COLUMN findings.disposition_reason IS 'Analyst note for the disposition (Phase 7). Never written by detection.';
COMMENT ON COLUMN findings.created_by IS 'rule (Phase 6 always), analyst or agent (Phase 7).';
COMMENT ON COLUMN findings.assigned_to IS 'Analyst assignee (Phase 7). Never written by detection.';
COMMENT ON COLUMN findings.rule_updated IS 'True once a later run found the rule (or the case indicators it read) changed since the finding was raised; the analyst should re-review. Never reset by detection.';
COMMENT ON COLUMN findings.created_at IS 'Start of the run that first raised the finding.';
COMMENT ON COLUMN findings.updated_at IS 'Start of the latest run that changed the finding (not touched by a no-op re-run).';

COMMENT ON TABLE finding_evidence IS 'The evidence rows behind a finding: one per (finding_id, source_table, record_key), appended by every run that hits new rows and never removed.';
COMMENT ON COLUMN finding_evidence.finding_id IS 'findings.finding_id.';
COMMENT ON COLUMN finding_evidence.source_table IS 'Evidence table of the hit (ual_events, signins, ...).';
COMMENT ON COLUMN finding_evidence.record_key IS 'Key of the hit row in source_table (record_id text for ual_events).';
COMMENT ON COLUMN finding_evidence.event_time IS 'Time of the hit row.';
COMMENT ON COLUMN finding_evidence.role IS 'trigger for rows the rule returned; context is reserved for Phase 7.';
COMMENT ON COLUMN finding_evidence.context IS 'The rule''s JSON context for the hit (NULL for match rules).';
COMMENT ON COLUMN finding_evidence.added_run_id IS 'detection_runs.run_id of the run that added the row.';

COMMENT ON TABLE case_indicators IS 'Indicators the analyst has marked (ip, upn, ...). Rules read them through @list:case_iocs.<type> (malicious and suspicious verdicts). Written only through sparrow_core::case::indicators.';
COMMENT ON COLUMN case_indicators.indicator_id IS 'First 16 hex characters of sha256(tenant_key, type, lower-cased value): adding the same indicator again updates it.';
COMMENT ON COLUMN case_indicators.tenant_key IS 'Tenant the indicator applies to; NULL applies to every tenant of the case.';
COMMENT ON COLUMN case_indicators.type IS 'ip, upn, app_id, domain, user_agent, rule_name, email, url or hash.';
COMMENT ON COLUMN case_indicators.value IS 'The indicator value (matched case-insensitively by rules).';
COMMENT ON COLUMN case_indicators.verdict IS 'malicious or suspicious feed rule lists; benign is an allow-list marker rules do not read.';
COMMENT ON COLUMN case_indicators.note IS 'Analyst note.';
COMMENT ON COLUMN case_indicators.added_by IS 'Who added it: analyst:<name> (see case::indicators::Actor).';
COMMENT ON COLUMN case_indicators.added_at IS 'When it was added or last updated.';

-- Task 4: the timeline gains finding_count / finding_ids (0008's definition verbatim plus the finding join).
CREATE OR REPLACE VIEW timeline AS
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
    UNION ALL
    SELECT a.event_time, a.time_tz_assumed, 'azure_activity', a.record_key, 'Azure', a.operation_name,
           a.caller, a.resource_id, a.ip, NULL, a.operation_name || ' ' || a.status
    FROM azure_activity a
    UNION ALL
    SELECT coalesce(s.event_time, s.created_time), false, 'security_alerts', s.record_key, NULL, s.title,
           s.affected_users[1], NULL, s.affected_ips[1], NULL, s.severity || ': ' || s.title
    FROM security_alerts s
)
SELECT ev.event_time, ev.time_tz_assumed, ev.source_table, ev.record_key,
       coalesce(
           (SELECT o.category FROM operation_catalog o
            WHERE o.operation_key = lower(trim(rtrim(trim(ev.operation), '.')))
              AND (o.workload IS NULL OR lower(o.workload) = lower(ev.workload))
            ORDER BY o.workload NULLS LAST LIMIT 1),
           CASE ev.source_table WHEN 'signins' THEN 'auth' WHEN 'risk_detections' THEN 'auth'
                                WHEN 'message_trace' THEN 'mail_flow'
                                WHEN 'azure_activity' THEN 'config_change' ELSE 'other' END::event_category
       ) AS category,
       ev.operation, ev.actor_upn, ev.target, ev.ip, i.country_iso AS ip_country, i.asn_org AS ip_asn_org,
       ev.user_agent, ev.summary, refs.source_refs,
       coalesce(f.finding_count, 0) AS finding_count, coalesce(f.finding_ids, CAST([] AS VARCHAR[])) AS finding_ids
FROM ev
LEFT JOIN ip_intel i ON i.ip = ev.ip
LEFT JOIN record_source_refs refs ON refs.table_name = ev.source_table AND refs.record_key = ev.record_key
LEFT JOIN (SELECT source_table, record_key, CAST(count(DISTINCT finding_id) AS INTEGER) AS finding_count, list(DISTINCT finding_id ORDER BY finding_id) AS finding_ids FROM finding_evidence GROUP BY source_table, record_key) f
       ON f.source_table = ev.source_table AND f.record_key = ev.record_key;
COMMENT ON VIEW timeline IS 'One row per event record: the union of ual_events, parent-less mail_items_accessed rows, signins, directory_audits, message_trace, mailbox_audit_legacy, admin_audit_events, risk_detections, azure_activity and security_alerts, with category from operation_catalog, IP country/ASN from ip_intel, source_refs, and finding_count / finding_ids (the findings whose evidence cites the record). Deviation from spec 5.3: a time_tz_assumed column is added; category gains the value mail_flow for message trace rows (the spec category list has nothing for mail delivery).';
COMMENT ON COLUMN timeline.event_time IS 'Event time (UTC): ual_events.event_time, mail_items_accessed.event_time, signins.event_time, directory_audits.event_time, message_trace.received, mailbox_audit_legacy.event_time, admin_audit_events.run_time, coalesce(risk_detections.activity_time, risk_detections.detected_time), azure_activity.event_time, or coalesce(security_alerts.event_time, security_alerts.created_time).';
COMMENT ON COLUMN timeline.time_tz_assumed IS 'True when the source time had no timezone and UTC was assumed. Always false for risk_detections and security_alerts (no time_tz_assumed column: their times are Graph UTC); azure_activity carries its own time_tz_assumed.';
COMMENT ON COLUMN timeline.source_table IS 'Evidence table the row came from: ual_events, mail_items_accessed, signins, directory_audits, message_trace, mailbox_audit_legacy, admin_audit_events, risk_detections, azure_activity or security_alerts.';
COMMENT ON COLUMN timeline.record_key IS 'Key of the record in source_table (record_sources.record_key), joined against record_source_refs and, via that, verify.';
COMMENT ON COLUMN timeline.category IS 'From operation_catalog (matched on operation_key = operation_key(operation) and workload, case-insensitively, most specific workload match wins); else auth for signins/risk_detections, mail_flow for message_trace, config_change for azure_activity, other otherwise.';
COMMENT ON COLUMN timeline.operation IS 'Operation name: ual_events.operation, MailItemsAccessed for a parent-less mail_items_accessed row, SignInSucceeded/SignInFailed (Sparrow timeline name) for signins, directory_audits.activity, MessageTrace (Sparrow timeline name) for message_trace, mailbox_audit_legacy.operation, admin_audit_events.cmdlet, risk_detections.risk_event_type, azure_activity.operation_name, or security_alerts.title.';
COMMENT ON COLUMN timeline.actor_upn IS 'Who performed the action, from the source row (falls back to an app/service name where the source has no user).';
COMMENT ON COLUMN timeline.target IS 'What the action touched, from the source row. For directory_audits: TargetResources[0]''s UPN, else display name, matching either casing (Hawk''s Get-MgAuditLogDirectoryAudit is PascalCase; Microsoft-Extractor-Suite''s Graph REST JSON is camelCase).';
COMMENT ON COLUMN timeline.ip IS 'Client IP text as the source table stores it; join key into ip_intel.';
COMMENT ON COLUMN timeline.ip_country IS 'ip_intel.country_iso for ip.';
COMMENT ON COLUMN timeline.ip_asn_org IS 'ip_intel.asn_org for ip.';
COMMENT ON COLUMN timeline.user_agent IS 'User agent, when the source table records one.';
COMMENT ON COLUMN timeline.summary IS 'Short human-readable summary built from the source row''s own fields.';
COMMENT ON COLUMN timeline.source_refs IS 'record_source_refs.source_refs for (source_table, record_key); empty for a row provenance could not resolve (should not occur for ingested evidence).';
COMMENT ON COLUMN timeline.finding_count IS 'Number of distinct findings whose finding_evidence cites this record (source_table, record_key); 0 when none.';
COMMENT ON COLUMN timeline.finding_ids IS 'The finding_id of each such finding, sorted; empty when none.';
