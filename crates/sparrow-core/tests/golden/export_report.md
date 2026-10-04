# Sparrow case report

- **Sparrow version:** <VERSION>
- **Rule pack SHA-256:** <RULE_PACK_SHA256>
- **Generated at:** 2026-10-03 00:00:00 UTC
- **Audit chain:** ok (15 entries)
- **Audit head hash:** 6dcebb2f2e14f084b0daf325dd84ff8a3ba31989e9109f11d932b54fcbeea09d
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
| azure\_activity | 4 | 2026-08-06T09:05:00Z | 2026-08-09T11:07:00Z |
| directory\_audits | 22 | 2026-08-12T16:00:00Z | 2026-09-09T20:08:41Z |
| mailbox\_audit\_legacy | 1776 | 2026-08-01T08:38:17Z | 2026-09-10T01:55:36Z |
| message\_trace | 2261 | 2026-08-01T04:17:34Z | 2026-09-09T23:55:36Z |
| risk\_detections | 4 | 2026-08-04T12:50:10Z | 2026-08-21T19:12:00Z |
| security\_alerts | 1 | 2026-08-04T10:00:00Z | 2026-08-04T10:00:00Z |
| signins | 1294 | 2026-08-11T14:24:08Z | 2026-09-09T23:49:44Z |
| ual\_events | 5901 | 2026-08-01T00:19:21Z | 2026-09-09T23:59:59Z |

## Executive summary

_Analyst to write._

## Timeline by phase

### initial access

- **2026-08-11 14:24:08 UTC** — Sign-in from the proxy[^1]
  The attacker replays the session.
  - Decision: _AI decision — not reviewed_ (decided by agent:claude on behalf of analyst:example at 2026-10-02 12:00:06 UTC)

### defense evasion

- **2026-08-13 10:00:00 UTC** — Inbox rule created[^2]
  A rule hides replies.
  - Decision: _AI decision — not reviewed_ (decided by agent:claude on behalf of analyst:example at 2026-10-02 12:00:08 UTC)

### collection

- **2026-08-01 00:24:21 UTC** — Mailbox read[^3]
  The mailbox is read in bulk.
  - Decision: _AI decision — not reviewed_ (decided by agent:claude on behalf of analyst:example at 2026-10-02 12:00:10 UTC)

## Findings

### high — User inbox rule deletes, forwards or redirects mail

- Finding `1c8b18eff09c880c` · rule `SPW-HAWK-010` · status **confirmed** · user marlowe.rhodes@contoso.example
- Seen 2026-08-21 09:47:00 to 2026-09-10 16:15:00 UTC
- Reason: replayed session from the proxy address
- Decision: _accepted by analyst:reviewer at 2026-10-02 12:00:13 UTC_ (decided by agent:claude on behalf of analyst:example at 2026-10-02 12:00:00 UTC)
- Reviewer comment: agreed
- Notes:
  - agent note — not reviewed (agent:claude on behalf of analyst:example at 2026-10-02 12:00:12 UTC): Reviewed the sign-in by hand.
- Evidence (6 rows):
  - 2026-08-21 09:47:00 UTC · mail\_rule · New-InboxRule · marlowe.rhodes@contoso.example · 203.0.113.2 · Exchange New-InboxRule on marlowe.rhodes@contoso.example\\AP[^4]
  - 2026-08-21 12:12:00 UTC · mail\_rule · UpdateInboxRules · marlowe.rhodes@contoso.example · 203.0.113.2 · Exchange UpdateInboxRules[^5]
  - inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|1117600807597104896[^6]
  - inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|1239425345399972642[^7]
  - inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|AAMkow1wHgwwG4WuzrXPcuNEEBq1RYckVZsyyuWHnFV3==[^8]
  - inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|AAMkuNYJSJpDA9UCLeHEoSFfHDBRa5kqmFuDtYveXYip==[^9]

## Indicators

| Type | Value | Verdict | Note | Decision |
| --- | --- | --- | --- | --- |
| ip | 203.0.113.9 | malicious | AiTM proxy | AI decision — not reviewed \(decided by agent:claude on behalf of analyst:example at 2026-10-02 12:00:03 UTC\) |
| domain | login-example.test | suspicious | look-alike sign-in page | AI decision — not reviewed \(decided by agent:claude on behalf of analyst:example at 2026-10-02 12:00:04 UTC\) |

## Evidence gaps

| Tenant | Evidence | Status | Why | Remediation |
| --- | --- | --- | --- | --- |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Exchange admin audit log | available\_not\_collected | not in the case; it can still be collected \(Microsoft keeps it 90 days\) | Microsoft-Extractor-Suite: Get-UAL -StartDate 2026-06-13 -EndDate 2026-09-11 -RecordType ExchangeAdmin \| Hawk: Start-HawkTenantInvestigation |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Application and service principal credentials | available\_not\_collected | not in the case; it can still be collected | Hawk: Get-HawkTenantAppAndSPNCredentialDetail |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Entra ID audit logs | partial | the window starts before the 30-day retention at collection time | Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -startDate 2026-08-12 -endDate 2026-09-11 \| Hawk: Get-HawkTenantEntraIDAuditLog \| portal: Entra admin center &gt; Audit logs &gt; Download |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Defender for Office 365 email threat events | available\_not\_collected | no collector exports it; not in the case; it can still be collected \(Microsoft keeps it 30 days\) | portal: Defender portal &gt; Explorer / Real-time detections, or Advanced hunting EmailEvents \(30 days\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Mobile devices attached to mailboxes | available\_not\_collected | not in the case; it can still be collected | Hawk: Get-HawkUserMobileDevice -UserPrincipalName &lt;upn&gt; |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Admin role assignments \(Entra ID, Exchange, eDiscovery\) | partial | 1 files lost records in the collector's own output \(failure placeholders or a collector defect; see the ingest report\) | Microsoft-Extractor-Suite: Get-AdminUsers \| Hawk: Get-HawkTenantEntraIDAdmin; Get-HawkTenantEXOAdmin |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Entra ID sign-in logs | partial | the window starts before the 30-day retention at collection time | Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -startDate 2026-08-12 -endDate 2026-09-11 \| Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName &lt;upn&gt; \| portal: Entra admin center &gt; Sign-in logs &gt; Download \(works on every edition\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Defender for Office 365 Safe Links URL clicks | available\_not\_collected | no collector exports it; not in the case; it can still be collected \(Microsoft keeps it 30 days\) | portal: Defender portal &gt; Explorer &gt; URL clicks, or Advanced hunting UrlClickEvents \(30 days\) |

## Method and integrity

Sparrow ingested the collector output into a case database, enriched it and ran its detection rules. Findings, indicators and timeline entries were triaged by an AI agent through the command line: every such decision is recorded in a hash-chained audit trail with who made it and when, and starts as an AI decision that no analyst has reviewed. Review happens outside Sparrow; an item shows `accepted` or `discarded` only when a reviewer's decision was recorded, and a review covers the latest decision on each object (an earlier decision that a later one replaced was not itself reviewed). Notes carry no review state and are labelled as agent notes.

- Sparrow version: <VERSION>
- Rule pack SHA-256: <RULE_PACK_SHA256>
- Generated at: 2026-10-03 00:00:00 UTC
- Audit chain: ok (15 entries)
- Audit head hash: 6dcebb2f2e14f084b0daf325dd84ff8a3ba31989e9109f11d932b54fcbeea09d
- Decisions: AI-decided, not reviewed 7; recorded before the audit trail 0; accepted 1; discarded 1

## Evidence references

[^1]: signins:2e1c9d42-6a92-419c-b21a-9d2fb256a795 — Output/Contoso\_Example/Sign-In logs/EntraID/20260910-161751-SignInLogs/interactiveUser &amp; nonInteractiveUser/20260910161757-interactiveUser-nonInteractiveUser-SignInLogs.json:19706-19772
[^2]: ual\_events:74b0d0cd-8b08-4d7d-b5ce-e5a2784cf1d1 — Output/Contoso\_Example/UnifiedAuditLog/20260910-161616/20260910161616-victims-UnifiedAuditLog.json:96863-96913; Output/Contoso\_Example/UnifiedAuditLog/20260910-161713/20260910161713-victims-UnifiedAuditLog.jsonl:1470; Output/Triage-Contoso\_Example/New-InboxRule.json:2-51 (+2 more sightings)
[^3]: ual\_events:5ae56966-7d51-4d2d-900d-196664d6118e — Output/Contoso\_Example/UnifiedAuditLog/20260910-161616/20260910161616-victims-UnifiedAuditLog.json:89-161; Output/Contoso\_Example/UnifiedAuditLog/20260910-161713/20260910161713-victims-UnifiedAuditLog.jsonl:2; Output/Triage-Contoso\_Example/MailItemsAccessed.json:2-73 (+3 more sightings)
[^4]: ual\_events:02a13335-5a42-4ce8-9f05-5b5f0f489146 — Output/Contoso\_Example/UnifiedAuditLog/20260910-161616/20260910161616-victims-UnifiedAuditLog.json:166272-166322; Output/Contoso\_Example/UnifiedAuditLog/20260910-161713/20260910161713-victims-UnifiedAuditLog.jsonl:2520; Output/Triage-Contoso\_Example/New-InboxRule.json:118-167 (+2 more sightings)
[^5]: ual\_events:38f3aef6-68f9-4842-ace1-4d564480e6f8 — Output/Contoso\_Example/UnifiedAuditLog/20260910-161616/20260910161616-victims-UnifiedAuditLog.json:173191-173247; Output/Contoso\_Example/UnifiedAuditLog/20260910-161713/20260910161713-victims-UnifiedAuditLog.jsonl:2620; Output/Contoso\_Example/Mailbox Audit Log/20260910-172259/UnifiedAuditLog/20260910-172300/UAL-20260821000000-20260822000000.csv:59-61 (+2 more sightings)
[^6]: inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|1117600807597104896 — Output/Contoso\_Example/Rules/20260910-173429/20260910-173429-MailboxRules.csv:66-73
[^7]: inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|1239425345399972642 — Output/Contoso\_Example/Rules/20260910-173429/20260910-173429-MailboxRules.csv:60-65
[^8]: inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|AAMkow1wHgwwG4WuzrXPcuNEEBq1RYckVZsyyuWHnFV3== — Output/Contoso\_Example/Rules/20260910-173438/20260910-173438-MailboxRulesGraph.csv:12
[^9]: inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|AAMkuNYJSJpDA9UCLeHEoSFfHDBRa5kqmFuDtYveXYip== — Output/Contoso\_Example/Rules/20260910-173438/20260910-173438-MailboxRulesGraph.csv:13
