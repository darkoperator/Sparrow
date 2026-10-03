# Sparrow case report

- **Sparrow version:** 0.1.0
- **Rule pack SHA-256:** 77e0b0c20e1bf86f766f67d5ff2397568f144ee823d750d8df2fdcae9214b39e
- **Generated at:** 2026-10-03 00:00:00 UTC
- **Audit chain:** ok (15 entries)
- **Audit head hash:** 3b29b96056052d23170e9071f3c5e7b436cd3666e8b70cb20f5ac18732f547ec
- **Decisions:** AI-decided, not reviewed 7; recorded before the audit trail 0; accepted 1; discarded 1
- **Decisions shown:** all, each labelled with its review state (an agent decision nobody has reviewed says so)

## Scope

### Tenant dfbdfe90-22c0-4154-b41b-ebdee4faea7e

- Tenant key: dfbdfe90-22c0-4154-b41b-ebdee4faea7e
- Tenant id: dfbdfe90-22c0-4154-b41b-ebdee4faea7e
- Domains: contoso.example
- Collection 1: invictus, collected 2026-09-10T16:15:00Z

| Evidence table | Rows | First | Last |
| --- | ---: | --- | --- |
| azure_activity | 4 | 2026-08-06T09:05:00Z | 2026-08-09T11:07:00Z |
| directory_audits | 20 | 2026-08-12T16:00:00Z | 2026-09-09T20:08:41Z |
| mailbox_audit_legacy | 1774 | 2026-08-01T08:38:17Z | 2026-09-10T01:55:36Z |
| message_trace | 2261 | 2026-08-01T04:17:34Z | 2026-09-09T23:55:36Z |
| risk_detections | 4 | 2026-08-04T12:50:10Z | 2026-08-21T19:12:00Z |
| security_alerts | 1 | 2026-08-04T10:00:00Z | 2026-08-04T10:00:00Z |
| signins | 1286 | 2026-08-11T14:24:08Z | 2026-09-09T23:49:44Z |
| ual_events | 5890 | 2026-08-01T00:19:21Z | 2026-09-09T23:59:59Z |

## Executive summary

_Analyst to write._

## Timeline by phase

### initial access

- **2026-08-21 09:47:00 UTC** — Sign-in from the proxy[^1]
  The attacker replays the session.
  - Decision: _AI decision — not reviewed_ (decided by agent:claude on behalf of analyst:carlos at 2026-10-02 12:00:06 UTC)

### defense evasion

- **2026-08-21 12:12:00 UTC** — Inbox rule created[^2]
  A rule hides replies.
  - Decision: _AI decision — not reviewed_ (decided by agent:claude on behalf of analyst:carlos at 2026-10-02 12:00:08 UTC)

### collection

- **2026-08-21 09:37:00 UTC** — Mailbox read[^3]
  The mailbox is read in bulk.
  - Decision: _AI decision — not reviewed_ (decided by agent:claude on behalf of analyst:carlos at 2026-10-02 12:00:10 UTC)

## Findings

### high — User inbox rule deletes, forwards or redirects mail

- Finding `1c8b18eff09c880c` · rule `SPW-HAWK-010` · status **confirmed** · user marlowe.rhodes@contoso.example
- Seen 2026-08-21 09:47:00 to 2026-09-10 16:15:00 UTC
- Reason: replayed session from the proxy address
- Decision: _accepted by analyst:dana at 2026-10-02 12:00:13 UTC_ (decided by agent:claude on behalf of analyst:carlos at 2026-10-02 12:00:00 UTC)
- Reviewer comment: agreed
- Notes:
  - Note by agent:claude on behalf of analyst:carlos at 2026-10-02 12:00:12 UTC: Reviewed the sign-in by hand.
- Evidence (6 rows):
  - 2026-08-21 09:47:00 UTC · mail_rule · New-InboxRule · marlowe.rhodes@contoso.example · 203.0.113.2 · Exchange New-InboxRule on marlowe.rhodes@contoso.example\AP[^1]
  - 2026-08-21 12:12:00 UTC · mail_rule · UpdateInboxRules · marlowe.rhodes@contoso.example · 203.0.113.2 · Exchange UpdateInboxRules[^2]
  - inbox_rules:inbox|marlowe.rhodes@contoso.example|1117600807597104896[^4]
  - inbox_rules:inbox|marlowe.rhodes@contoso.example|1239425345399972642[^5]
  - inbox_rules:inbox|marlowe.rhodes@contoso.example|AAMkow1wHgwwG4WuzrXPcuNEEBq1RYckVZsyyuWHnFV3==[^6]
  - inbox_rules:inbox|marlowe.rhodes@contoso.example|AAMkuNYJSJpDA9UCLeHEoSFfHDBRa5kqmFuDtYveXYip==[^7]

## Indicators

| Type | Value | Verdict | Note | Decision |
| --- | --- | --- | --- | --- |
| ip | 203.0.113.9 | malicious | AiTM proxy | AI decision — not reviewed (decided by agent:claude on behalf of analyst:carlos at 2026-10-02 12:00:03 UTC) |
| domain | login-example.test | suspicious | look-alike sign-in page | AI decision — not reviewed (decided by agent:claude on behalf of analyst:carlos at 2026-10-02 12:00:04 UTC) |

## Evidence gaps

| Tenant | Evidence | Status | Why | Remediation |
| --- | --- | --- | --- | --- |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Exchange admin audit log | available_not_collected | not in the case; it can still be collected (Microsoft keeps it 90 days) | Microsoft-Extractor-Suite: Get-UAL -StartDate 2026-06-13 -EndDate 2026-09-11 -RecordType ExchangeAdmin \| Hawk: Start-HawkTenantInvestigation |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Application and service principal credentials | available_not_collected | not in the case; it can still be collected | Hawk: Get-HawkTenantAppAndSPNCredentialDetail |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Entra ID audit logs | partial | the window starts before the 30-day retention at collection time | Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -startDate 2026-08-12 -endDate 2026-09-11 \| Hawk: Get-HawkTenantEntraIDAuditLog \| portal: Entra admin center > Audit logs > Download |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Defender for Office 365 email threat events | available_not_collected | no collector exports it; not in the case; it can still be collected (Microsoft keeps it 30 days) | portal: Defender portal > Explorer / Real-time detections, or Advanced hunting EmailEvents (30 days) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Mobile devices attached to mailboxes | available_not_collected | not in the case; it can still be collected | Hawk: Get-HawkUserMobileDevice -UserPrincipalName <upn> |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Admin role assignments (Entra ID, Exchange, eDiscovery) | partial | 1 files failed to parse (see the ingest report / parse_errors) | Microsoft-Extractor-Suite: Get-AdminUsers \| Hawk: Get-HawkTenantEntraIDAdmin; Get-HawkTenantEXOAdmin |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Entra ID sign-in logs | partial | the window starts before the 30-day retention at collection time | Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -startDate 2026-08-12 -endDate 2026-09-11 \| Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName <upn> \| portal: Entra admin center > Sign-in logs > Download (works on every edition) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Defender for Office 365 Safe Links URL clicks | available_not_collected | no collector exports it; not in the case; it can still be collected (Microsoft keeps it 30 days) | portal: Defender portal > Explorer > URL clicks, or Advanced hunting UrlClickEvents (30 days) |

## Method and integrity

Sparrow ingested the collector output into a case database, enriched it and ran its detection rules. Findings, indicators and timeline entries were triaged by an AI agent through the command line: every such decision is recorded in a hash-chained audit trail with who made it and when, and starts as an AI decision that no analyst has reviewed. Review happens outside Sparrow; an item shows `accepted` or `discarded` only when a reviewer's decision was recorded.

- Sparrow version: 0.1.0
- Rule pack SHA-256: 77e0b0c20e1bf86f766f67d5ff2397568f144ee823d750d8df2fdcae9214b39e
- Generated at: 2026-10-03 00:00:00 UTC
- Audit chain: ok (15 entries)
- Audit head hash: 3b29b96056052d23170e9071f3c5e7b436cd3666e8b70cb20f5ac18732f547ec
- Decisions: AI-decided, not reviewed 7; recorded before the audit trail 0; accepted 1; discarded 1

## Evidence references

[^1]: ual_events:02a13335-5a42-4ce8-9f05-5b5f0f489146 — Output/Contoso_Example/UnifiedAuditLog/20260910-161616/20260910161616-victims-UnifiedAuditLog.json:166272-166322; Output/Contoso_Example/UnifiedAuditLog/20260910-161713/20260910161713-victims-UnifiedAuditLog.jsonl:2520; Output/Triage-Contoso_Example/New-InboxRule.json:118-167 (+2 more sightings)
[^2]: ual_events:38f3aef6-68f9-4842-ace1-4d564480e6f8 — Output/Contoso_Example/UnifiedAuditLog/20260910-161616/20260910161616-victims-UnifiedAuditLog.json:173191-173247; Output/Contoso_Example/UnifiedAuditLog/20260910-161713/20260910161713-victims-UnifiedAuditLog.jsonl:2620; Output/Contoso_Example/Mailbox Audit Log/20260910-172259/UnifiedAuditLog/20260910-172300/UAL-20260821000000-20260822000000.csv:59-61 (+2 more sightings)
[^3]: ual_events:4d75bb52-f616-430e-b482-5240e43756ae — Output/Contoso_Example/UnifiedAuditLog/20260910-161616/20260910161616-victims-UnifiedAuditLog.json:166073-166139; Output/Contoso_Example/UnifiedAuditLog/20260910-161713/20260910161713-victims-UnifiedAuditLog.jsonl:2517; Output/Triage-Contoso_Example/New-InboxRule.json:52-117 (+2 more sightings)
[^4]: inbox_rules:inbox|marlowe.rhodes@contoso.example|1117600807597104896 — Output/Contoso_Example/Rules/20260910-173429/20260910-173429-MailboxRules.csv:66-73
[^5]: inbox_rules:inbox|marlowe.rhodes@contoso.example|1239425345399972642 — Output/Contoso_Example/Rules/20260910-173429/20260910-173429-MailboxRules.csv:60-65
[^6]: inbox_rules:inbox|marlowe.rhodes@contoso.example|AAMkow1wHgwwG4WuzrXPcuNEEBq1RYckVZsyyuWHnFV3== — Output/Contoso_Example/Rules/20260910-173438/20260910-173438-MailboxRulesGraph.csv:12
[^7]: inbox_rules:inbox|marlowe.rhodes@contoso.example|AAMkuNYJSJpDA9UCLeHEoSFfHDBRa5kqmFuDtYveXYip== — Output/Contoso_Example/Rules/20260910-173438/20260910-173438-MailboxRulesGraph.csv:13
