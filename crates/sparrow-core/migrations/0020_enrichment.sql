-- Migration 20: derived facts for triage (agent accuracy round). Both tables are rebuilt from scratch, in one
-- transaction, at the end of every detection run (sparrow_core::detect::enrich); nothing else writes them, and
-- review decisions do not change them. A case detected before this migration has them empty until its next
-- detection run.

CREATE TABLE finding_facts (
    finding_id VARCHAR PRIMARY KEY,
    facts_version INTEGER NOT NULL,
    facts JSON NOT NULL,
    computed_run_id BIGINT NOT NULL
);

CREATE TABLE account_rollup (
    tenant_key VARCHAR NOT NULL,
    upn VARCHAR NOT NULL,
    worst_severity VARCHAR NOT NULL,
    finding_count INTEGER NOT NULL,
    by_severity JSON NOT NULL,
    stages JSON NOT NULL,
    first_suspicious TIMESTAMPTZ,
    rules JSON NOT NULL,
    addresses JSON NOT NULL,
    addresses_total INTEGER NOT NULL,
    addresses_truncated BOOLEAN NOT NULL,
    computed_run_id BIGINT NOT NULL,
    PRIMARY KEY (tenant_key, upn)
);

COMMENT ON TABLE finding_facts IS 'Computed, checkable facts about one finding (no verdict, label or score), one row per finding whose rule''s stage: includes persistence, consent or mfa_change. Rebuilt from scratch at the end of every detection run, in one transaction; when that rebuild fails the previous rows stay and case_meta.enrichment_error holds the message. Every "before" fact means "within the capture": the capture starts at window_start.';
COMMENT ON COLUMN finding_facts.finding_id IS 'findings.finding_id.';
COMMENT ON COLUMN finding_facts.facts_version IS 'Version of the facts JSON shape (1).';
COMMENT ON COLUMN finding_facts.facts IS 'JSON object. window_start: the tenant''s first sign-in of any kind (min signins.event_time over the tenant''s collections; null when the tenant has no sign-ins). actor_ips: one entry per distinct address on the finding''s evidence rows (the timeline ip of each row; state rows such as inbox_rules and mailboxes have none), ordered by its first evidence time then address: {ip, asn, asn_org, is_hosting (ip_intel), spray_source (in the tenant''s spray_sources), user_signin_days_before (distinct UTC days on which the finding''s actor_upn had a successful sign-in, error_code 0 or NULL, from that address strictly before the earliest evidence event from it), user_first_signin (the first such sign-in, null when none)}. other_signals: {total, items} - the other findings of the same tenant and actor (case-insensitive, never this one), items at most 5 in finding-list order (severity, last_seen descending, finding_id), each {rule_id (empty for an analyst finding), severity, first_seen}; total 0 when the finding has no actor. targets (only when the evidence carries a forwarding or redirect address): every address in inbox_rules forward_to / forward_as_attachment_to / redirect_to, mailboxes forwarding_smtp_address / forwarding_address, transport_rules redirect_to / blind_copy_to / copy_to / add_to_recipients, or the UAL / admin audit cmdlet parameters ForwardingSmtpAddress, ForwardingAddress, ForwardTo, ForwardAsAttachmentTo, RedirectTo, RedirectMessageTo, BlindCopyTo, CopyTo, AddToRecipients; deduplicated, lower-case, smtp: prefix and display name removed, trailing dots stripped, sorted; a value with no address (a display name, a distinguished name, an empty value) is not a target. Each {address, domain, scope, prior_messages}: scope internal when the address is the actor''s own (its UPN or mailbox primary address) or its domain or a parent domain is in tenant_domains for the tenant (which includes analyst overrides), else external; prior_messages = message_trace rows of the tenant between the actor (UPN or primary address) and that address, either direction, received strictly before the earliest evidence event carrying the address; null when the case has no message_trace rows at all, the finding has no actor, or that evidence has no time.';
COMMENT ON COLUMN finding_facts.computed_run_id IS 'detection_runs.run_id of the run whose enrichment wrote the row.';

COMMENT ON TABLE account_rollup IS 'One row per tenant and account (lower-case actor_upn) with at least one finding: what the account''s findings say together, as facts. Rebuilt from scratch with finding_facts at the end of every detection run, in the same transaction. Findings without an actor are attributed to no account.';
COMMENT ON COLUMN account_rollup.tenant_key IS 'findings.tenant_key.';
COMMENT ON COLUMN account_rollup.upn IS 'The findings'' actor_upn, lower-case.';
COMMENT ON COLUMN account_rollup.worst_severity IS 'Highest severity among the account''s findings (critical > high > medium > low > info).';
COMMENT ON COLUMN account_rollup.finding_count IS 'Number of the account''s findings.';
COMMENT ON COLUMN account_rollup.by_severity IS 'JSON object severity -> number of the account''s findings (only severities present).';
COMMENT ON COLUMN account_rollup.stages IS 'JSON array of stage names in fixed order (suspicious_sign_in, credential_takeover, persistence, mail_access, sending, consent, mfa_change): the union of the stage: fields of the rules of the account''s findings, plus credential_takeover when an SPW-ID-005 evidence row of the account has context takeover = true.';
COMMENT ON COLUMN account_rollup.first_suspicious IS 'Earliest first_seen among the account''s findings of severity medium or higher; NULL when it has none.';
COMMENT ON COLUMN account_rollup.rules IS 'JSON array of the distinct rule ids of the account''s findings, sorted.';
COMMENT ON COLUMN account_rollup.addresses IS 'JSON array, at most 20, of addresses worth a look for the account: {ip, reasons, tables, first_seen, last_seen, asn, asn_org, is_hosting, spray_source, in_user_signins}. Reasons: finding_evidence (on one of the account''s findings'' evidence rows), acts_without_signin (acts for the account in ual_events, mail_items_accessed, mailbox_audit_legacy or message_trace but never appears in the account''s sign-ins), hosting (ip_intel.is_hosting), spray_source (in the tenant''s spray_sources), risky_signin (a sign-in of the account from it with sign-in or user risk medium or high, or a risk_detections row for the account and address). Ordered by strongest reason (finding_evidence, then acts_without_signin, then the others), then first_seen, then ip.';
COMMENT ON COLUMN account_rollup.addresses_total IS 'Number of qualifying addresses before the cap of 20.';
COMMENT ON COLUMN account_rollup.addresses_truncated IS 'True when addresses_total exceeds the 20 listed.';
COMMENT ON COLUMN account_rollup.computed_run_id IS 'detection_runs.run_id of the run whose enrichment wrote the row.';

COMMENT ON TABLE case_meta IS 'Case-level constants and profile state, one row per key. case_id: random UUID set by migration 16, the audit chain genesis. audit_head: the head (seq and hash) the last audit insert left. post_migration_pending: present while a migrated case still owes its post-migration step; the value is the schema version before the migration. credential_failure_codes: JSON array of integers, the codes the last profile run derived spray_sources and cloud_services with. first_party_apps: JSON array of lower-case application ids, the microsoft_first_party_apps list the last profile run built cloud_services with. An upgrade reuses the two stored lists, so it never swaps a case''s custom lists for the environment''s. enrichment_run_id: the detection run whose enrichment last rebuilt finding_facts and account_rollup (absent before the first one). enrichment_error: present while the latest enrichment failed, with its message; the two tables then still hold the rows of enrichment_run_id.';
