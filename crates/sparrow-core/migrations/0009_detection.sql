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
