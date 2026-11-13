# Sparrow case report

- **Sparrow version:** <VERSION>
- **Rule pack SHA-256:** <RULE_PACK_SHA256>
- **Generated at:** 2026-10-03T00:00:00Z
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
| directory\_audits | 24 | 2026-08-12T16:00:00Z | 2026-09-09T20:08:41Z |
| mailbox\_audit\_legacy | 1778 | 2026-08-01T08:38:17Z | 2026-09-10T01:55:36Z |
| message\_trace | 2270 | 2026-08-01T04:17:34Z | 2026-09-09T23:55:36Z |
| risk\_detections | 4 | 2026-08-04T12:50:10Z | 2026-08-21T19:12:00Z |
| security\_alerts | 1 | 2026-08-04T10:00:00Z | 2026-08-04T10:00:00Z |
| signins | 1309 | 2026-08-11T14:24:08Z | 2026-09-09T23:49:44Z |
| ual\_events | 5913 | 2026-08-01T00:19:21Z | 2026-09-09T23:59:59Z |

## Executive summary

_Analyst to write._

## Accounts

_Computed by Sparrow from every finding of the case, whatever its decision: facts, not decisions. "Reviewed" counts the account's findings with an accepted review._

| Tenant | Account | Worst severity | Stages | First suspicious (UTC) | Sign-in coverage (UTC) | Reviewed | Addresses |
| --- | --- | --- | --- | --- | --- | ---: | --- |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | marlowe.rhodes@contoso.example | high | suspicious\_sign\_in, persistence, mail\_access, sending, consent, mfa\_change | 2026-08-21T09:12:00Z | sign-ins 2026-08-11T14:42:01Z to 2026-09-09T18:17:59Z | 1 | 203.0.113.1 \(finding\_evidence, hosting, risky\_signin\)<br>203.0.113.2 \(finding\_evidence, hosting, risky\_signin\)<br>203.0.113.4 \(finding\_evidence, acts\_without\_signin, hosting\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | ollie.carter@contoso.example | high | suspicious\_sign\_in, persistence | 2026-08-25T11:00:00Z | sign-ins 2026-08-12T00:37:15Z to 2026-09-09T07:03:15Z | 0 | 203.0.113.1 \(finding\_evidence, hosting, risky\_signin\)<br>203.0.113.2 \(finding\_evidence, hosting\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | vance.ingram@contoso.example | high | suspicious\_sign\_in, persistence | 2026-08-31T11:00:00Z | sign-ins 2026-08-11T14:38:02Z to 2026-09-09T16:29:32Z | 0 | 203.0.113.6 \(finding\_evidence\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | admin@contoso.example | high | persistence | 2026-08-20T15:00:00Z | sign-ins 2026-08-12T14:37:11Z to 2026-09-09T23:49:44Z | 0 | 203.0.113.2 \(finding\_evidence, acts\_without\_signin, hosting\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | xander.irwin@contoso.example | high | suspicious\_sign\_in | 2026-08-25T11:00:00Z | sign-ins 2026-08-11T16:11:54Z to 2026-09-09T12:44:47Z | 0 | 203.0.113.1 \(finding\_evidence, hosting, risky\_signin\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | frances.rourke@contoso.example | high | suspicious\_sign\_in | 2026-08-27T10:00:00Z | sign-ins 2026-08-12T00:22:04Z to 2026-09-09T07:51:48Z | 0 | 203.0.113.1 \(finding\_evidence, hosting, risky\_signin\)<br>2001:db8:12::a \(acts\_without\_signin\)<br>2001:db8:12::b \(acts\_without\_signin\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | gale.yates@contoso.example | medium | consent | 2026-08-09T14:00:00Z | sign-ins 2026-08-12T00:10:52Z to 2026-09-09T04:57:21Z | 0 | 192.0.2.9 \(finding\_evidence\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | ocean.vincent@contoso.example | medium | persistence | 2026-08-14T16:00:00Z | sign-ins 2026-08-12T00:26:51Z to 2026-09-09T05:46:15Z | 0 | 192.0.2.7 \(finding\_evidence\) |
| dfbdfe90-22c0-4154-b41b-ebdee4faea7e | cameron.tucker@contoso.example | medium | sending | 2026-08-15T12:34:05Z | sign-ins 2026-08-11T14:24:08Z to 2026-09-09T14:01:26Z | 0 | 198.51.100.3 \(finding\_evidence\) |

## Timeline by phase

### initial access

- **2026-08-11T14:24:08Z** — Sign-in from the proxy[^1]
  The attacker replays the session.
  - Decision: _AI decision — not reviewed_ (decided by agent:claude on behalf of analyst:example at 2026-10-02T12:00:06Z)

### defense evasion

- **2026-08-13T10:00:00Z** — Inbox rule created[^2]
  A rule hides replies.
  - Decision: _AI decision — not reviewed_ (decided by agent:claude on behalf of analyst:example at 2026-10-02T12:00:08Z)

### collection

- **2026-08-01T00:24:21Z** — Mailbox read[^3]
  The mailbox is read in bulk.
  - Decision: _AI decision — not reviewed_ (decided by agent:claude on behalf of analyst:example at 2026-10-02T12:00:10Z)

## Findings

### high — User inbox rule deletes, forwards or redirects mail

- Finding `1c8b18eff09c880c` · rule `SPW-HAWK-010` · status **confirmed** · user marlowe.rhodes@contoso.example
- Seen 2026-08-21T09:47:00Z to 2026-09-10T16:15:00Z
- Reason: replayed session from the proxy address
- Decision: _accepted by analyst:reviewer at 2026-10-02T12:00:13Z_ (decided by agent:claude on behalf of analyst:example at 2026-10-02T12:00:00Z)
- Reviewer comment: agreed
- Notes:
  - agent note — not reviewed (agent:claude on behalf of analyst:example at 2026-10-02T12:00:12Z): Reviewed the sign-in by hand.
- Facts:
  - Address 203.0.113.2 — this user signed in from it on 1 earlier day(s) within the capture (since 2026-08-11). It is in a hosting provider network (Vultr \(The Constant Company\)).
  - Other findings on this account: 25 (SPW-MAIL-003 high, SPW-MAIL-004 high, SPW-HAWK-008 high, SPW-HAWK-009 high, SPW-FILE-003 high, +20 more).
  - Target invoices@exfil-mail.test — external; 0 earlier message(s) with this user.
  - Target kai.ingram@contoso.example — internal; 6 earlier message(s) with this user.
- Evidence (6 rows):
  - 2026-08-21T09:47:00Z · mail\_rule · New-InboxRule · marlowe.rhodes@contoso.example · 203.0.113.2 · Exchange New-InboxRule on marlowe.rhodes@contoso.example\\AP[^4]
  - 2026-08-21T12:12:00Z · mail\_rule · UpdateInboxRules · marlowe.rhodes@contoso.example · 203.0.113.2 · Exchange UpdateInboxRules[^5]
  - inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|1117600807597104896[^6]
  - inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|1239425345399972642[^7]
  - inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|AAMkow1wHgwwG4WuzrXPcuNEEBq1RYckVZsyyuWHnFV3==[^8]
  - inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|AAMkuNYJSJpDA9UCLeHEoSFfHDBRa5kqmFuDtYveXYip==[^9]

## Indicators

| Type | Value | Verdict | Note | Decision |
| --- | --- | --- | --- | --- |
| ip | 203.0.113.9 | malicious | AiTM proxy | AI decision — not reviewed \(decided by agent:claude on behalf of analyst:example at 2026-10-02T12:00:03Z\) |
| domain | login-example.test | suspicious | look-alike sign-in page | AI decision — not reviewed \(decided by agent:claude on behalf of analyst:example at 2026-10-02T12:00:04Z\) |

## Devices to contain

| Status | Analyst | Device | Name | Last active | Users | Malicious IPs | Other IPs |
| --- | --- | --- | --- | --- | --- | --- | --- |
| not\_in\_latest\_inventory — treat as active — collect Get-Devices to confirm |  | 76f8b195-1701-47c6-b6fe-f4065afcc88e | VANCE.INGRAM-LAPTOP | 2026-09-09T16:29:32Z \(Output/Contoso\_Example/Sign-In logs/EntraID/20260910-161751-SignInLogs/interactiveUser &amp; nonInteractiveUser/20260910161754-interactiveUser-nonInteractiveUser-SignInLogs.json:608-674\) | vance.ingram@contoso.example | 203.0.113.6 | 192.0.2.17 \(Documentation ISP 3, DE\); 192.0.2.18 \(Documentation ISP 3, DE\); 203.0.113.5 \(Documentation ISP 7, CA\) |
| not\_in\_latest\_inventory — treat as active — collect Get-Devices to confirm |  | 2035f0d9-04d3-4b55-9e3e-e59bda35d3b6 | OLLIE.CARTER-LAPTOP | 2026-09-09T07:03:15Z \(Output/Contoso\_Example/Sign-In logs/EntraID/20260910-161751-SignInLogs/interactiveUser &amp; nonInteractiveUser/20260910161754-interactiveUser-nonInteractiveUser-SignInLogs.json:2956-3022\) | ollie.carter@contoso.example | 203.0.113.2 | 192.0.2.21 \(Documentation ISP 5, JP\); 192.0.2.22 \(Documentation ISP 5, JP\); 203.0.113.5 \(Documentation ISP 7, CA\) |

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

## Evidence coverage and what to request

_Per account: the rows each source holds and the dates they span (UTC). The reference window runs from 30 days before the account's first finding (else its first row) to the tenant's last event. A source that is absent, starts after the window starts, ends before it ends, or came from a capped export (sampled) does not show that nothing happened on the dates in its gaps._

**marlowe.rhodes@contoso.example** (tenant dfbdfe90-22c0-4154-b41b-ebdee4faea7e): window 2026-07-22 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 539 | 2026-08-01T14:48:57Z | 2026-09-09T23:46:03Z | 38 | no | before 2026-07-22 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 56 | 2026-08-11T14:42:01Z | 2026-09-09T18:17:59Z | 29 | no | before 2026-07-22 to 2026-08-10; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 48 | 2026-08-12T17:59:16Z | 2026-09-08T14:40:53Z | 15 | no | before 2026-07-22 to 2026-08-11; after 2026-09-09 to 2026-09-10 |
| MailItemsAccessed | 128 | 2026-08-01T14:49:41Z | 2026-09-09T20:53:55Z | 38 | no | before 2026-07-22 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Message trace | 249 | 2026-08-01T06:38:17Z | 2026-09-09T23:46:03Z | 33 | no | before 2026-07-22 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 8 | 2026-08-18T19:24:22Z | 2026-08-21T19:12:00Z | 2 | no | before 2026-07-22 to 2026-08-17; after 2026-08-22 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 132 | 2026-08-03T21:53:43Z | 2026-09-10T01:46:03Z | 35 | no | before 2026-07-22 to 2026-08-02 |

What to request:

- Unified audit log, 2026-07-22 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = marlowe.rhodes@contoso.example, date range 2026-07-22 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds marlowe.rhodes@contoso.example -StartDate 2026-07-22 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-22 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = marlowe.rhodes@contoso.example and Date 2026-07-22 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName marlowe.rhodes@contoso.example \(Hawk sets the window when it starts, 2026-07-22 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds marlowe.rhodes@contoso.example -startDate 2026-07-22 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-22 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = marlowe.rhodes@contoso.example and Date 2026-07-22 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds marlowe.rhodes@contoso.example -startDate 2026-07-22 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-22 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = marlowe.rhodes@contoso.example, Activities = MailItemsAccessed, date range 2026-07-22 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName marlowe.rhodes@contoso.example \(Hawk sets the window when it starts, 2026-07-22 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds marlowe.rhodes@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-22 -EndDate 2026-09-11
- Message trace, 2026-07-22 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = marlowe.rhodes@contoso.example, then again with Recipient = marlowe.rhodes@contoso.example, dates 2026-07-22 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName marlowe.rhodes@contoso.example \(cannot serve 2026-07-22 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds marlowe.rhodes@contoso.example -StartDate 2026-07-22 -EndDate 2026-09-11
- Entra audit log, 2026-07-22 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-22 to 2026-09-10, filter Initiated by \(actor\) = marlowe.rhodes@contoso.example, Download &gt; JSON; repeat with the Target filter = marlowe.rhodes@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-22 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds marlowe.rhodes@contoso.example -startDate 2026-07-22 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-22 to 2026-08-02 (before)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity marlowe.rhodes@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-22 -EndDate 2026-08-03 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds marlowe.rhodes@contoso.example -StartDate 2026-07-22 -EndDate 2026-08-03

**ollie.carter@contoso.example** (tenant dfbdfe90-22c0-4154-b41b-ebdee4faea7e): window 2026-07-26 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 455 | 2026-08-01T00:41:54Z | 2026-09-09T18:46:29Z | 38 | no | before 2026-07-26 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 64 | 2026-08-12T00:37:15Z | 2026-09-09T07:03:15Z | 28 | no | before 2026-07-26 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 41 | 2026-08-12T02:25:33Z | 2026-09-09T01:43:22Z | 18 | no | before 2026-07-26 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 121 | 2026-08-01T00:43:15Z | 2026-09-09T18:46:29Z | 38 | no | before 2026-07-26 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Message trace | 263 | 2026-08-03T01:02:45Z | 2026-09-09T18:29:58Z | 33 | no | before 2026-07-26 to 2026-08-02; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 4 | 2026-08-12T20:07:00Z | 2026-09-08T15:12:00Z | 3 | no | before 2026-07-26 to 2026-08-11; after 2026-09-09 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 139 | 2026-08-03T03:20:27Z | 2026-09-09T09:51:41Z | 29 | no | before 2026-07-26 to 2026-08-02; after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = ollie.carter@contoso.example, date range 2026-07-26 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds ollie.carter@contoso.example -StartDate 2026-07-26 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = ollie.carter@contoso.example and Date 2026-07-26 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName ollie.carter@contoso.example \(Hawk sets the window when it starts, 2026-07-26 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds ollie.carter@contoso.example -startDate 2026-07-26 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = ollie.carter@contoso.example and Date 2026-07-26 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds ollie.carter@contoso.example -startDate 2026-07-26 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = ollie.carter@contoso.example, Activities = MailItemsAccessed, date range 2026-07-26 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName ollie.carter@contoso.example \(Hawk sets the window when it starts, 2026-07-26 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds ollie.carter@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-26 -EndDate 2026-09-11
- Message trace, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = ollie.carter@contoso.example, then again with Recipient = ollie.carter@contoso.example, dates 2026-07-26 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName ollie.carter@contoso.example \(cannot serve 2026-07-26 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds ollie.carter@contoso.example -StartDate 2026-07-26 -EndDate 2026-09-11
- Entra audit log, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-26 to 2026-09-10, filter Initiated by \(actor\) = ollie.carter@contoso.example, Download &gt; JSON; repeat with the Target filter = ollie.carter@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-26 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds ollie.carter@contoso.example -startDate 2026-07-26 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity ollie.carter@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-26 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds ollie.carter@contoso.example -StartDate 2026-07-26 -EndDate 2026-09-11

**vance.ingram@contoso.example** (tenant dfbdfe90-22c0-4154-b41b-ebdee4faea7e): window 2026-08-01 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 438 | 2026-08-01T07:26:52Z | 2026-09-09T16:32:11Z | 37 | no | after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 53 | 2026-08-12T07:24:40Z | 2026-09-09T16:29:32Z | 28 | no | before 2026-08-01 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 37 | 2026-08-11T14:38:02Z | 2026-09-07T13:35:23Z | 18 | no | before 2026-08-01 to 2026-08-10; after 2026-09-08 to 2026-09-10 |
| MailItemsAccessed | 116 | 2026-08-01T07:28:31Z | 2026-09-09T14:44:51Z | 37 | no | after 2026-09-10 to 2026-09-10 |
| Message trace | 279 | 2026-08-03T07:54:35Z | 2026-09-09T15:34:22Z | 35 | no | before 2026-08-01 to 2026-08-02; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 2 | 2026-08-26T17:48:16Z | 2026-09-02T14:02:19Z | 2 | no | before 2026-08-01 to 2026-08-25; after 2026-09-03 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 158 | 2026-08-03T11:03:06Z | 2026-09-09T18:32:11Z | 29 | no | before 2026-08-01 to 2026-08-02; after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-09-10 to 2026-09-10 (after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = vance.ingram@contoso.example, date range 2026-09-10 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds vance.ingram@contoso.example -StartDate 2026-09-10 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-08-01 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = vance.ingram@contoso.example and Date 2026-08-01 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName vance.ingram@contoso.example \(Hawk sets the window when it starts, 2026-08-01 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds vance.ingram@contoso.example -startDate 2026-08-01 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-08-01 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = vance.ingram@contoso.example and Date 2026-08-01 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds vance.ingram@contoso.example -startDate 2026-08-01 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-09-10 to 2026-09-10 (after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = vance.ingram@contoso.example, Activities = MailItemsAccessed, date range 2026-09-10 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName vance.ingram@contoso.example \(Hawk sets the window when it starts, 2026-09-10 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds vance.ingram@contoso.example -Operations MailItemsAccessed -StartDate 2026-09-10 -EndDate 2026-09-11
- Message trace, 2026-08-01 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = vance.ingram@contoso.example, then again with Recipient = vance.ingram@contoso.example, dates 2026-08-01 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName vance.ingram@contoso.example \(cannot serve 2026-08-01 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds vance.ingram@contoso.example -StartDate 2026-08-01 -EndDate 2026-09-11
- Entra audit log, 2026-08-01 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-08-01 to 2026-09-10, filter Initiated by \(actor\) = vance.ingram@contoso.example, Download &gt; JSON; repeat with the Target filter = vance.ingram@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-08-01 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds vance.ingram@contoso.example -startDate 2026-08-01 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-08-01 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity vance.ingram@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-08-01 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds vance.ingram@contoso.example -StartDate 2026-08-01 -EndDate 2026-09-11

**admin@contoso.example** (tenant dfbdfe90-22c0-4154-b41b-ebdee4faea7e): window 2026-07-21 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 459 | 2026-08-02T14:54:14Z | 2026-09-09T23:59:59Z | 39 | no | before 2026-07-21 to 2026-08-01; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 53 | 2026-08-12T14:37:11Z | 2026-09-09T22:49:42Z | 29 | no | before 2026-07-21 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 59 | 2026-08-13T19:40:35Z | 2026-09-09T23:49:44Z | 20 | no | before 2026-07-21 to 2026-08-12; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 109 | 2026-08-02T14:56:40Z | 2026-09-09T23:59:59Z | 39 | no | before 2026-07-21 to 2026-08-01; after 2026-09-10 to 2026-09-10 |
| Message trace | 221 | 2026-08-02T21:09:04Z | 2026-09-09T23:55:36Z | 33 | no | before 2026-07-21 to 2026-08-01; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 14 | 2026-08-12T16:00:00Z | 2026-09-09T20:08:41Z | 11 | no | before 2026-07-21 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 121 | 2026-08-03T18:46:27Z | 2026-09-10T01:55:36Z | 32 | no | before 2026-07-21 to 2026-08-02 |

What to request:

- Unified audit log, 2026-07-21 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = admin@contoso.example, date range 2026-07-21 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds admin@contoso.example -StartDate 2026-07-21 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-21 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = admin@contoso.example and Date 2026-07-21 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName admin@contoso.example \(Hawk sets the window when it starts, 2026-07-21 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds admin@contoso.example -startDate 2026-07-21 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-21 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = admin@contoso.example and Date 2026-07-21 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds admin@contoso.example -startDate 2026-07-21 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-21 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = admin@contoso.example, Activities = MailItemsAccessed, date range 2026-07-21 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName admin@contoso.example \(Hawk sets the window when it starts, 2026-07-21 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds admin@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-21 -EndDate 2026-09-11
- Message trace, 2026-07-21 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = admin@contoso.example, then again with Recipient = admin@contoso.example, dates 2026-07-21 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName admin@contoso.example \(cannot serve 2026-07-21 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds admin@contoso.example -StartDate 2026-07-21 -EndDate 2026-09-11
- Entra audit log, 2026-07-21 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-21 to 2026-09-10, filter Initiated by \(actor\) = admin@contoso.example, Download &gt; JSON; repeat with the Target filter = admin@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-21 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds admin@contoso.example -startDate 2026-07-21 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-21 to 2026-08-02 (before)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity admin@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-21 -EndDate 2026-08-03 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds admin@contoso.example -StartDate 2026-07-21 -EndDate 2026-08-03

**xander.irwin@contoso.example** (tenant dfbdfe90-22c0-4154-b41b-ebdee4faea7e): window 2026-07-26 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 438 | 2026-08-01T07:42:59Z | 2026-09-09T23:49:52Z | 39 | no | before 2026-07-26 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 48 | 2026-08-11T16:11:54Z | 2026-09-09T11:34:23Z | 29 | no | before 2026-07-26 to 2026-08-10; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 41 | 2026-08-12T07:59:55Z | 2026-09-09T12:44:47Z | 17 | no | before 2026-07-26 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 116 | 2026-08-01T07:47:54Z | 2026-09-09T23:49:52Z | 39 | no | before 2026-07-26 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Message trace | 274 | 2026-08-01T08:36:36Z | 2026-09-09T23:46:03Z | 35 | no | before 2026-07-26 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 2 | 2026-08-27T11:00:00Z | 2026-08-27T11:00:00Z | 1 | no | before 2026-07-26 to 2026-08-26; after 2026-08-28 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 150 | 2026-08-01T10:36:36Z | 2026-09-10T01:46:03Z | 34 | no | before 2026-07-26 to 2026-07-31 |

What to request:

- Unified audit log, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = xander.irwin@contoso.example, date range 2026-07-26 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds xander.irwin@contoso.example -StartDate 2026-07-26 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = xander.irwin@contoso.example and Date 2026-07-26 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName xander.irwin@contoso.example \(Hawk sets the window when it starts, 2026-07-26 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds xander.irwin@contoso.example -startDate 2026-07-26 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = xander.irwin@contoso.example and Date 2026-07-26 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds xander.irwin@contoso.example -startDate 2026-07-26 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = xander.irwin@contoso.example, Activities = MailItemsAccessed, date range 2026-07-26 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName xander.irwin@contoso.example \(Hawk sets the window when it starts, 2026-07-26 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds xander.irwin@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-26 -EndDate 2026-09-11
- Message trace, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = xander.irwin@contoso.example, then again with Recipient = xander.irwin@contoso.example, dates 2026-07-26 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName xander.irwin@contoso.example \(cannot serve 2026-07-26 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds xander.irwin@contoso.example -StartDate 2026-07-26 -EndDate 2026-09-11
- Entra audit log, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-26 to 2026-09-10, filter Initiated by \(actor\) = xander.irwin@contoso.example, Download &gt; JSON; repeat with the Target filter = xander.irwin@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-26 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds xander.irwin@contoso.example -startDate 2026-07-26 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-26 to 2026-07-31 (before)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity xander.irwin@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-26 -EndDate 2026-08-01 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds xander.irwin@contoso.example -StartDate 2026-07-26 -EndDate 2026-08-01

**frances.rourke@contoso.example** (tenant dfbdfe90-22c0-4154-b41b-ebdee4faea7e): window 2026-07-28 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 454 | 2026-08-01T00:42:39Z | 2026-09-09T15:30:48Z | 40 | no | before 2026-07-28 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 69 | 2026-08-12T00:22:04Z | 2026-09-09T07:10:31Z | 29 | no | before 2026-07-28 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 44 | 2026-08-12T00:35:36Z | 2026-09-09T07:51:48Z | 19 | no | before 2026-07-28 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 110 | 2026-08-01T00:46:53Z | 2026-09-09T15:30:48Z | 40 | no | before 2026-07-28 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Message trace | 222 | 2026-08-01T06:54:20Z | 2026-09-09T15:16:32Z | 34 | no | before 2026-07-28 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 1 | 2026-09-04T08:00:00Z | 2026-09-04T08:00:00Z | 1 | no | before 2026-07-28 to 2026-09-03; after 2026-09-05 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 141 | 2026-08-01T08:54:20Z | 2026-09-09T17:16:32Z | 33 | no | before 2026-07-28 to 2026-07-31; after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = frances.rourke@contoso.example, date range 2026-07-28 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds frances.rourke@contoso.example -StartDate 2026-07-28 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = frances.rourke@contoso.example and Date 2026-07-28 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName frances.rourke@contoso.example \(Hawk sets the window when it starts, 2026-07-28 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds frances.rourke@contoso.example -startDate 2026-07-28 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = frances.rourke@contoso.example and Date 2026-07-28 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds frances.rourke@contoso.example -startDate 2026-07-28 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = frances.rourke@contoso.example, Activities = MailItemsAccessed, date range 2026-07-28 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName frances.rourke@contoso.example \(Hawk sets the window when it starts, 2026-07-28 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds frances.rourke@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-28 -EndDate 2026-09-11
- Message trace, 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = frances.rourke@contoso.example, then again with Recipient = frances.rourke@contoso.example, dates 2026-07-28 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName frances.rourke@contoso.example \(cannot serve 2026-07-28 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds frances.rourke@contoso.example -StartDate 2026-07-28 -EndDate 2026-09-11
- Entra audit log, 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-28 to 2026-09-10, filter Initiated by \(actor\) = frances.rourke@contoso.example, Download &gt; JSON; repeat with the Target filter = frances.rourke@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-28 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds frances.rourke@contoso.example -startDate 2026-07-28 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity frances.rourke@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-28 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds frances.rourke@contoso.example -StartDate 2026-07-28 -EndDate 2026-09-11

**gale.yates@contoso.example** (tenant dfbdfe90-22c0-4154-b41b-ebdee4faea7e): window 2026-07-10 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 467 | 2026-08-01T00:28:27Z | 2026-09-09T08:38:28Z | 38 | no | before 2026-07-10 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 53 | 2026-08-12T00:10:52Z | 2026-09-09T00:54:51Z | 28 | no | before 2026-07-10 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 56 | 2026-08-12T00:26:23Z | 2026-09-09T04:57:21Z | 20 | no | before 2026-07-10 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 121 | 2026-08-01T00:33:03Z | 2026-09-09T08:28:14Z | 38 | no | before 2026-07-10 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Message trace | 252 | 2026-08-01T08:36:36Z | 2026-09-09T08:07:00Z | 35 | no | before 2026-07-10 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 0 |  |  | 0 | no | absent 2026-07-10 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 126 | 2026-08-03T03:27:33Z | 2026-09-09T10:29:06Z | 30 | no | before 2026-07-10 to 2026-08-02; after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-07-10 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = gale.yates@contoso.example, date range 2026-07-10 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds gale.yates@contoso.example -StartDate 2026-07-10 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-10 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = gale.yates@contoso.example and Date 2026-07-10 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName gale.yates@contoso.example \(Hawk sets the window when it starts, 2026-07-10 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds gale.yates@contoso.example -startDate 2026-07-10 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-10 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = gale.yates@contoso.example and Date 2026-07-10 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds gale.yates@contoso.example -startDate 2026-07-10 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-10 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = gale.yates@contoso.example, Activities = MailItemsAccessed, date range 2026-07-10 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName gale.yates@contoso.example \(Hawk sets the window when it starts, 2026-07-10 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds gale.yates@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-10 -EndDate 2026-09-11
- Message trace, 2026-07-10 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = gale.yates@contoso.example, then again with Recipient = gale.yates@contoso.example, dates 2026-07-10 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName gale.yates@contoso.example \(cannot serve 2026-07-10 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds gale.yates@contoso.example -StartDate 2026-07-10 -EndDate 2026-09-11
- Entra audit log, 2026-07-10 to 2026-09-10 (absent)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-10 to 2026-09-10, filter Initiated by \(actor\) = gale.yates@contoso.example, Download &gt; JSON; repeat with the Target filter = gale.yates@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-10 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds gale.yates@contoso.example -startDate 2026-07-10 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-10 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity gale.yates@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-10 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds gale.yates@contoso.example -StartDate 2026-07-10 -EndDate 2026-09-11

**ocean.vincent@contoso.example** (tenant dfbdfe90-22c0-4154-b41b-ebdee4faea7e): window 2026-07-15 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 432 | 2026-08-01T00:19:21Z | 2026-09-09T07:37:17Z | 38 | no | before 2026-07-15 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 54 | 2026-08-12T00:26:51Z | 2026-09-09T05:46:15Z | 28 | no | before 2026-07-15 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 51 | 2026-08-12T06:48:15Z | 2026-09-09T04:42:14Z | 19 | no | before 2026-07-15 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 111 | 2026-08-01T00:24:21Z | 2026-09-09T07:37:17Z | 38 | no | before 2026-07-15 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Message trace | 256 | 2026-08-01T04:17:34Z | 2026-09-09T07:25:14Z | 36 | no | before 2026-07-15 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 1 | 2026-09-07T20:36:42Z | 2026-09-07T20:36:42Z | 1 | no | before 2026-07-15 to 2026-09-06; after 2026-09-08 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 125 | 2026-08-01T08:38:17Z | 2026-09-09T05:43:13Z | 31 | no | before 2026-07-15 to 2026-07-31; after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = ocean.vincent@contoso.example, date range 2026-07-15 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds ocean.vincent@contoso.example -StartDate 2026-07-15 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = ocean.vincent@contoso.example and Date 2026-07-15 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName ocean.vincent@contoso.example \(Hawk sets the window when it starts, 2026-07-15 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds ocean.vincent@contoso.example -startDate 2026-07-15 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = ocean.vincent@contoso.example and Date 2026-07-15 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds ocean.vincent@contoso.example -startDate 2026-07-15 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = ocean.vincent@contoso.example, Activities = MailItemsAccessed, date range 2026-07-15 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName ocean.vincent@contoso.example \(Hawk sets the window when it starts, 2026-07-15 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds ocean.vincent@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-15 -EndDate 2026-09-11
- Message trace, 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = ocean.vincent@contoso.example, then again with Recipient = ocean.vincent@contoso.example, dates 2026-07-15 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName ocean.vincent@contoso.example \(cannot serve 2026-07-15 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds ocean.vincent@contoso.example -StartDate 2026-07-15 -EndDate 2026-09-11
- Entra audit log, 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-15 to 2026-09-10, filter Initiated by \(actor\) = ocean.vincent@contoso.example, Download &gt; JSON; repeat with the Target filter = ocean.vincent@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-15 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds ocean.vincent@contoso.example -startDate 2026-07-15 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity ocean.vincent@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-15 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds ocean.vincent@contoso.example -StartDate 2026-07-15 -EndDate 2026-09-11

**cameron.tucker@contoso.example** (tenant dfbdfe90-22c0-4154-b41b-ebdee4faea7e): window 2026-07-16 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 420 | 2026-08-01T08:53:28Z | 2026-09-09T20:24:19Z | 38 | no | before 2026-07-16 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 53 | 2026-08-12T08:15:03Z | 2026-09-09T14:01:26Z | 28 | no | before 2026-07-16 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 46 | 2026-08-11T14:24:08Z | 2026-09-08T17:34:45Z | 19 | no | before 2026-07-16 to 2026-08-10; after 2026-09-09 to 2026-09-10 |
| MailItemsAccessed | 110 | 2026-08-01T08:58:39Z | 2026-09-09T20:24:19Z | 38 | no | before 2026-07-16 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Message trace | 266 | 2026-08-01T12:05:46Z | 2026-09-09T19:59:21Z | 36 | no | before 2026-07-16 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 0 |  |  | 0 | no | absent 2026-07-16 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 128 | 2026-08-01T14:05:46Z | 2026-09-09T19:41:38Z | 33 | no | before 2026-07-16 to 2026-07-31; after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-07-16 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = cameron.tucker@contoso.example, date range 2026-07-16 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds cameron.tucker@contoso.example -StartDate 2026-07-16 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-16 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = cameron.tucker@contoso.example and Date 2026-07-16 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName cameron.tucker@contoso.example \(Hawk sets the window when it starts, 2026-07-16 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds cameron.tucker@contoso.example -startDate 2026-07-16 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-16 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = cameron.tucker@contoso.example and Date 2026-07-16 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds cameron.tucker@contoso.example -startDate 2026-07-16 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-16 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = cameron.tucker@contoso.example, Activities = MailItemsAccessed, date range 2026-07-16 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName cameron.tucker@contoso.example \(Hawk sets the window when it starts, 2026-07-16 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds cameron.tucker@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-16 -EndDate 2026-09-11
- Message trace, 2026-07-16 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = cameron.tucker@contoso.example, then again with Recipient = cameron.tucker@contoso.example, dates 2026-07-16 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName cameron.tucker@contoso.example \(cannot serve 2026-07-16 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds cameron.tucker@contoso.example -StartDate 2026-07-16 -EndDate 2026-09-11
- Entra audit log, 2026-07-16 to 2026-09-10 (absent)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-16 to 2026-09-10, filter Initiated by \(actor\) = cameron.tucker@contoso.example, Download &gt; JSON; repeat with the Target filter = cameron.tucker@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-16 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds cameron.tucker@contoso.example -startDate 2026-07-16 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-16 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity cameron.tucker@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-16 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds cameron.tucker@contoso.example -StartDate 2026-07-16 -EndDate 2026-09-11

## Method and integrity

Sparrow ingested the collector output into a case database, enriched it and ran its detection rules. Findings, indicators and timeline entries were triaged by decisions, each recorded in a hash-chained audit trail with who made it and when. A decision is either an agent decision, made by an AI agent through the command line, which stays an AI decision that no analyst has reviewed until a reviewer accepts or discards it, or an analyst decision, made by an analyst in the review app and reviewed when made. An item shows `accepted` or `discarded` only when a reviewer's decision was recorded, and a review covers the latest decision on each object (an earlier decision that a later one replaced was not itself reviewed). Notes carry no review state: agent notes are never reviewed and are left out of a reviewed-only report; analyst notes are an analyst's own words and are kept.

- Sparrow version: <VERSION>
- Rule pack SHA-256: <RULE_PACK_SHA256>
- Generated at: 2026-10-03T00:00:00Z
- Audit chain: ok (15 entries)
- Audit head hash: 6dcebb2f2e14f084b0daf325dd84ff8a3ba31989e9109f11d932b54fcbeea09d
- Decisions: AI-decided, not reviewed 7; recorded before the audit trail 0; accepted 1; discarded 1

## Evidence references

[^1]: signins:2e1c9d42-6a92-419c-b21a-9d2fb256a795 — Output/Contoso\_Example/Sign-In logs/EntraID/20260910-161751-SignInLogs/interactiveUser &amp; nonInteractiveUser/20260910161757-interactiveUser-nonInteractiveUser-SignInLogs.json:20711-20777
[^2]: ual\_events:74b0d0cd-8b08-4d7d-b5ce-e5a2784cf1d1 — Output/Contoso\_Example/UnifiedAuditLog/20260910-161616/20260910161616-victims-UnifiedAuditLog.json:96863-96913; Output/Contoso\_Example/UnifiedAuditLog/20260910-161713/20260910161713-victims-UnifiedAuditLog.jsonl:1470; Output/Triage-Contoso\_Example/New-InboxRule.json:2-51 (+2 more sightings)
[^3]: ual\_events:5ae56966-7d51-4d2d-900d-196664d6118e — Output/Contoso\_Example/UnifiedAuditLog/20260910-161616/20260910161616-victims-UnifiedAuditLog.json:89-161; Output/Contoso\_Example/UnifiedAuditLog/20260910-161713/20260910161713-victims-UnifiedAuditLog.jsonl:2; Output/Triage-Contoso\_Example/MailItemsAccessed.json:2-73 (+3 more sightings)
[^4]: ual\_events:02a13335-5a42-4ce8-9f05-5b5f0f489146 — Output/Contoso\_Example/UnifiedAuditLog/20260910-161616/20260910161616-victims-UnifiedAuditLog.json:166338-166388; Output/Contoso\_Example/UnifiedAuditLog/20260910-161713/20260910161713-victims-UnifiedAuditLog.jsonl:2521; Output/Triage-Contoso\_Example/New-InboxRule.json:118-167 (+2 more sightings)
[^5]: ual\_events:38f3aef6-68f9-4842-ace1-4d564480e6f8 — Output/Contoso\_Example/UnifiedAuditLog/20260910-161616/20260910161616-victims-UnifiedAuditLog.json:173315-173371; Output/Contoso\_Example/UnifiedAuditLog/20260910-161713/20260910161713-victims-UnifiedAuditLog.jsonl:2622; Output/Contoso\_Example/Mailbox Audit Log/20260910-172259/UnifiedAuditLog/20260910-172300/UAL-20260821000000-20260822000000.csv:59-61 (+2 more sightings)
[^6]: inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|1117600807597104896 — Output/Contoso\_Example/Rules/20260910-173429/20260910-173429-MailboxRules.csv:66-73
[^7]: inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|1239425345399972642 — Output/Contoso\_Example/Rules/20260910-173429/20260910-173429-MailboxRules.csv:60-65
[^8]: inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|AAMkow1wHgwwG4WuzrXPcuNEEBq1RYckVZsyyuWHnFV3== — Output/Contoso\_Example/Rules/20260910-173438/20260910-173438-MailboxRulesGraph.csv:12
[^9]: inbox\_rules:inbox\|marlowe.rhodes@contoso.example\|AAMkuNYJSJpDA9UCLeHEoSFfHDBRa5kqmFuDtYveXYip== — Output/Contoso\_Example/Rules/20260910-173438/20260910-173438-MailboxRulesGraph.csv:13
