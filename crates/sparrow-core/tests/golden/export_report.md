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

## Accounts

_Computed by Sparrow from every finding of the case, whatever its decision: facts, not decisions. "Reviewed" counts the account's findings with an accepted review._

| Tenant | Account | Worst severity | Stages | First suspicious (UTC) | Sign-in coverage (UTC) | Reviewed | Addresses |
| --- | --- | --- | --- | --- | --- | ---: | --- |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | marlowe.rhodes@contoso.example | high | suspicious\_sign\_in, persistence, mail\_access, sending, consent, mfa\_change | 2026-08-21 09:12:00 | sign-ins 2026-08-11 14:42:01 to 2026-09-09 18:17:59 | 1 | 203.0.113.1 \(finding\_evidence, hosting, risky\_signin\)<br>203.0.113.2 \(finding\_evidence, hosting, risky\_signin\)<br>203.0.113.4 \(finding\_evidence, acts\_without\_signin, hosting\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | vance.ingram@contoso.example | high | suspicious\_sign\_in, persistence | 2026-09-07 11:05:00 | sign-ins 2026-08-11 14:38:02 to 2026-09-09 16:29:32 | 0 | 203.0.113.6 \(finding\_evidence\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | admin@contoso.example | high | persistence | 2026-08-20 15:00:00 | sign-ins 2026-08-12 14:37:11 to 2026-09-09 23:49:44 | 0 | 203.0.113.2 \(finding\_evidence, acts\_without\_signin, hosting\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | ollie.carter@contoso.example | high | suspicious\_sign\_in | 2026-08-25 11:00:00 | sign-ins 2026-08-12 00:37:15 to 2026-09-09 07:03:15 | 0 | 203.0.113.1 \(finding\_evidence, hosting, risky\_signin\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | xander.irwin@contoso.example | high | suspicious\_sign\_in | 2026-08-25 11:00:00 | sign-ins 2026-08-11 16:11:54 to 2026-09-09 12:44:47 | 0 | 203.0.113.1 \(finding\_evidence, hosting, risky\_signin\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | frances.rourke@contoso.example | high | suspicious\_sign\_in | 2026-08-27 10:00:00 | sign-ins 2026-08-12 00:22:04 to 2026-09-09 07:51:48 | 0 | 203.0.113.1 \(finding\_evidence, hosting, risky\_signin\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | gale.yates@contoso.example | medium | consent | 2026-08-09 14:00:00 | sign-ins 2026-08-12 00:10:52 to 2026-09-09 04:57:21 | 0 | 192.0.2.9 \(finding\_evidence\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | ocean.vincent@contoso.example | medium | persistence | 2026-08-14 16:00:00 | sign-ins 2026-08-12 00:26:51 to 2026-09-09 05:46:15 | 0 | 192.0.2.7 \(finding\_evidence\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | cameron.tucker@contoso.example | medium | sending | 2026-08-15 12:34:05 | sign-ins 2026-08-11 14:24:08 to 2026-09-09 14:01:26 | 0 | 198.51.100.3 \(finding\_evidence\) |

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
- Facts:
  - Address 203.0.113.2 — this user signed in from it on 1 earlier day(s) within the capture (since 2026-08-11). It is in a hosting provider network (Vultr \(The Constant Company\)).
  - Other findings on this account: 23 (SPW-MAIL-003 high, SPW-MAIL-004 high, SPW-HAWK-008 high, SPW-HAWK-009 high, SPW-FILE-003 high, +18 more).
  - Target invoices@exfil-mail.test — external; 0 earlier message(s) with this user.
  - Target kai.ingram@contoso.example — internal; 6 earlier message(s) with this user.
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

## Devices to contain

| Status | Device | Name | Last active | Users | Malicious IPs | Other IPs |
| --- | --- | --- | --- | --- | --- | --- |
| not\_in\_latest\_inventory — treat as active — collect Get-Devices to confirm | 76f8b195-1701-47c6-b6fe-f4065afcc88e | VANCE.INGRAM-LAPTOP | 2026-09-09 16:29:32 UTC \(Output/Contoso\_Example/Sign-In logs/EntraID/20260910-161751-SignInLogs/interactiveUser &amp; nonInteractiveUser/20260910161754-interactiveUser-nonInteractiveUser-SignInLogs.json:608-674\) | vance.ingram@contoso.example | 203.0.113.6 | 192.0.2.17 \(Documentation ISP 3, DE\); 192.0.2.18 \(Documentation ISP 3, DE\); 203.0.113.5 \(Documentation ISP 7, CA\) |

## Evidence gaps

| Tenant | Evidence | Status | Why | Remediation |
| --- | --- | --- | --- | --- |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Exchange admin audit log | available\_not\_collected | not in the case; it can still be collected \(Microsoft keeps it 90 days\) | Microsoft-Extractor-Suite: Get-UAL -StartDate 2026-06-13 -EndDate 2026-09-11 -RecordType ExchangeAdmin \| Hawk: Start-HawkTenantInvestigation |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Application and service principal credentials | available\_not\_collected | not in the case; it can still be collected | Hawk: Get-HawkTenantAppAndSPNCredentialDetail |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Entra ID audit logs | partial | the window starts before the 30-day retention at collection time | Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -startDate 2026-08-12 -endDate 2026-09-11 \| Hawk: Get-HawkTenantEntraIDAuditLog \| portal: Entra admin center &gt; Audit logs &gt; Download |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Defender for Office 365 email threat events | available\_not\_collected | no collector exports it; not in the case; it can still be collected \(Microsoft keeps it 30 days\) | portal: Defender portal &gt; Explorer / Real-time detections, or Advanced hunting EmailEvents \(30 days\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Exchange Online message trace events \(detail report\) | available\_not\_collected | not in the case; it can still be collected | portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace &gt; Report type Extended |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Mobile devices attached to mailboxes | available\_not\_collected | not in the case; it can still be collected | Hawk: Get-HawkUserMobileDevice -UserPrincipalName &lt;upn&gt; |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Admin role assignments \(Entra ID, Exchange, eDiscovery\) | partial | 1 files lost records in the collector's own output \(failure placeholders or a collector defect; see the ingest report\) | Microsoft-Extractor-Suite: Get-AdminUsers \| Hawk: Get-HawkTenantEntraIDAdmin; Get-HawkTenantEXOAdmin |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Entra ID sign-in logs | partial | the window starts before the 30-day retention at collection time | Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -startDate 2026-08-12 -endDate 2026-09-11 \| Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName &lt;upn&gt; \| portal: Entra admin center &gt; Sign-in logs &gt; Download \(works on every edition\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | Defender for Office 365 Safe Links URL clicks | available\_not\_collected | no collector exports it; not in the case; it can still be collected \(Microsoft keeps it 30 days\) | portal: Defender portal &gt; Explorer &gt; URL clicks, or Advanced hunting UrlClickEvents \(30 days\) |

## Method and integrity

Sparrow ingested the collector output into a case database, enriched it and ran its detection rules. Findings, indicators and timeline entries were triaged by decisions, each recorded in a hash-chained audit trail with who made it and when. A decision is either an agent decision, made by an AI agent through the command line, which stays an AI decision that no analyst has reviewed until a reviewer accepts or discards it, or an analyst decision, made by an analyst in the review app and reviewed when made. An item shows `accepted` or `discarded` only when a reviewer's decision was recorded, and a review covers the latest decision on each object (an earlier decision that a later one replaced was not itself reviewed). Notes carry no review state: agent notes are never reviewed and are left out of a reviewed-only report; analyst notes are an analyst's own words and are kept.

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
