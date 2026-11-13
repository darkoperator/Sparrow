# Sparrow case report

- **Sparrow version:** <VERSION>
- **Rule pack SHA-256:** <RULE_PACK_SHA256>
- **Generated at:** 2026-10-03T00:00:00Z
- **Audit chain:** ok (0 entries)
- **Audit head hash:** none
- **Decisions:** AI-decided, not reviewed 0; recorded before the audit trail 0; accepted 0; discarded 0
- **Decisions shown:** all, each labelled with its review state (an agent decision nobody has reviewed says so)

## Scope

### Tenant f8ff8c86-40d4-4634-b6fa-5e29a28c1d80

- Tenant key: f8ff8c86-40d4-4634-b6fa-5e29a28c1d80
- Tenant id: f8ff8c86-40d4-4634-b6fa-5e29a28c1d80
- Domains: contoso.example
- Collection 1: invictus, collected 2026-09-10T16:15:00Z

| Evidence table | Rows | First | Last |
| --- | ---: | --- | --- |
| azure\_activity | 4 | 2026-08-06T09:05:00Z | 2026-08-09T11:07:00Z |
| directory\_audits | 19 | 2026-08-11T22:00:34Z | 2026-09-08T20:47:38Z |
| mailbox\_audit\_legacy | 1831 | 2026-08-01T05:21:24Z | 2026-09-10T01:35:52Z |
| message\_trace | 2325 | 2026-08-01T03:21:24Z | 2026-09-09T23:19:19Z |
| risk\_detections | 4 | 2026-08-04T16:44:48Z | 2026-08-21T19:12:00Z |
| security\_alerts | 1 | 2026-08-04T10:00:00Z | 2026-08-04T10:00:00Z |
| signins | 1303 | 2026-08-11T14:51:33Z | 2026-09-09T22:58:26Z |
| ual\_events | 5809 | 2026-08-01T00:21:42Z | 2026-09-09T23:35:52Z |

## Executive summary

_Analyst to write._

## Accounts

_Computed by Sparrow from every finding of the case, whatever its decision: facts, not decisions. "Reviewed" counts the account's findings with an accepted review._

| Tenant | Account | Worst severity | Stages | First suspicious (UTC) | Sign-in coverage (UTC) | Reviewed | Addresses |
| --- | --- | --- | --- | --- | --- | ---: | --- |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | finley.mathis@contoso.example | high | suspicious\_sign\_in, persistence, mail\_access, sending, consent, mfa\_change | 2026-08-21T09:12:00Z | sign-ins 2026-08-11T15:54:34Z to 2026-09-09T21:16:51Z | 0 | 203.0.113.1 \(finding\_evidence, hosting, risky\_signin\)<br>203.0.113.2 \(finding\_evidence, hosting, risky\_signin\)<br>203.0.113.4 \(finding\_evidence, acts\_without\_signin, hosting\) |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | kendall.james@contoso.example | high | suspicious\_sign\_in, persistence | 2026-09-07T11:05:00Z | sign-ins 2026-08-12T07:25:13Z to 2026-09-09T15:41:07Z | 0 | 203.0.113.6 \(finding\_evidence\) |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | admin@contoso.example | high | persistence | 2026-08-20T15:00:00Z | sign-ins 2026-08-11T14:51:33Z to 2026-09-09T22:58:26Z | 0 | 203.0.113.2 \(finding\_evidence, acts\_without\_signin, hosting\) |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | jamie.adams@contoso.example | high | suspicious\_sign\_in | 2026-08-25T11:00:00Z | sign-ins 2026-08-12T07:35:34Z to 2026-09-09T11:47:21Z | 0 | 203.0.113.1 \(finding\_evidence, hosting, risky\_signin\) |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | ollie.james@contoso.example | high | suspicious\_sign\_in | 2026-08-25T11:00:00Z | sign-ins 2026-08-12T00:45:34Z to 2026-09-09T08:06:39Z | 0 | 203.0.113.1 \(finding\_evidence, hosting, risky\_signin\) |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | jamie.prescott@contoso.example | high | suspicious\_sign\_in | 2026-08-27T10:00:00Z | sign-ins 2026-08-12T00:44:15Z to 2026-09-09T07:18:57Z | 0 | 203.0.113.1 \(finding\_evidence, hosting, risky\_signin\) |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | val.bennett@contoso.example | medium | consent | 2026-08-09T14:00:00Z | sign-ins 2026-08-12T00:04:50Z to 2026-09-09T06:47:49Z | 0 | 192.0.2.9 \(finding\_evidence\) |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | hayden.james@contoso.example | medium | persistence | 2026-08-14T16:00:00Z | sign-ins 2026-08-12T00:00:14Z to 2026-09-09T05:28:00Z | 0 | 192.0.2.7 \(finding\_evidence\) |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | bryce.knox@contoso.example | medium | sending | 2026-09-05T09:17:37Z | sign-ins 2026-08-11T15:55:44Z to 2026-09-09T11:59:18Z | 0 | 198.51.100.7 \(finding\_evidence\)<br>192.0.2.4 \(risky\_signin\) |

## Timeline by phase

_No verified timeline entries._

## Findings

_No confirmed findings._

## Indicators

_No malicious or suspicious indicators._

## Devices to contain

No device was seen on a malicious IP.

## Evidence gaps

| Tenant | Evidence | Status | Why | Remediation |
| --- | --- | --- | --- | --- |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | Exchange admin audit log | available\_not\_collected | not in the case; it can still be collected \(Microsoft keeps it 90 days\) | Microsoft-Extractor-Suite: Get-UAL -StartDate 2026-06-13 -EndDate 2026-09-11 -RecordType ExchangeAdmin \| Hawk: Start-HawkTenantInvestigation |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | Application and service principal credentials | available\_not\_collected | not in the case; it can still be collected | Hawk: Get-HawkTenantAppAndSPNCredentialDetail |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | Entra ID audit logs | partial | the window starts before the 30-day retention at collection time | Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -startDate 2026-08-12 -endDate 2026-09-11 \| Hawk: Get-HawkTenantEntraIDAuditLog \| portal: Entra admin center &gt; Audit logs &gt; Download |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | Defender for Office 365 email threat events | available\_not\_collected | no collector exports it; not in the case; it can still be collected \(Microsoft keeps it 30 days\) | portal: Defender portal &gt; Explorer / Real-time detections, or Advanced hunting EmailEvents \(30 days\) |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | Exchange Online message trace events \(detail report\) | available\_not\_collected | not in the case; it can still be collected | portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace &gt; Report type Extended |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | Mobile devices attached to mailboxes | available\_not\_collected | not in the case; it can still be collected | Hawk: Get-HawkUserMobileDevice -UserPrincipalName &lt;upn&gt; |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | Admin role assignments \(Entra ID, Exchange, eDiscovery\) | partial | 1 files lost records in the collector's own output \(failure placeholders or a collector defect; see the ingest report\) | Microsoft-Extractor-Suite: Get-AdminUsers \| Hawk: Get-HawkTenantEntraIDAdmin; Get-HawkTenantEXOAdmin |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | Entra ID sign-in logs | partial | the window starts before the 30-day retention at collection time | Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -startDate 2026-08-12 -endDate 2026-09-11 \| Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName &lt;upn&gt; \| portal: Entra admin center &gt; Sign-in logs &gt; Download \(works on every edition\) |
| f8ff8c86-40d4-4634-b6fa-5e29a28c1d80 | Defender for Office 365 Safe Links URL clicks | available\_not\_collected | no collector exports it; not in the case; it can still be collected \(Microsoft keeps it 30 days\) | portal: Defender portal &gt; Explorer &gt; URL clicks, or Advanced hunting UrlClickEvents \(30 days\) |

## Evidence coverage and what to request

_Per account: the rows each source holds and the dates they span (UTC). The reference window runs from 30 days before the account's first finding (else its first row) to the tenant's last event. A source that is absent, starts after the window starts, ends before it ends, or came from a capped export (sampled) does not show that nothing happened on the dates in its gaps._

**finley.mathis@contoso.example** (tenant f8ff8c86-40d4-4634-b6fa-5e29a28c1d80): window 2026-07-22 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 543 | 2026-08-01T14:44:27Z | 2026-09-09T21:45:32Z | 38 | no | before 2026-07-22 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 59 | 2026-08-11T16:29:16Z | 2026-09-09T14:33:56Z | 29 | no | before 2026-07-22 to 2026-08-10; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 56 | 2026-08-11T15:54:34Z | 2026-09-09T21:16:51Z | 20 | no | before 2026-07-22 to 2026-08-10; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 126 | 2026-08-01T14:47:16Z | 2026-09-09T17:25:44Z | 38 | no | before 2026-07-22 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Message trace | 287 | 2026-08-03T07:06:37Z | 2026-09-09T20:58:16Z | 33 | no | before 2026-07-22 to 2026-08-02; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 7 | 2026-08-21T09:24:00Z | 2026-08-21T19:12:00Z | 1 | no | before 2026-07-22 to 2026-08-20; after 2026-08-22 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 145 | 2026-08-03T16:17:57Z | 2026-09-09T22:58:16Z | 35 | no | before 2026-07-22 to 2026-08-02; after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-07-22 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = finley.mathis@contoso.example, date range 2026-07-22 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds finley.mathis@contoso.example -StartDate 2026-07-22 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-22 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = finley.mathis@contoso.example and Date 2026-07-22 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName finley.mathis@contoso.example \(Hawk sets the window when it starts, 2026-07-22 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds finley.mathis@contoso.example -startDate 2026-07-22 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-22 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = finley.mathis@contoso.example and Date 2026-07-22 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds finley.mathis@contoso.example -startDate 2026-07-22 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-22 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = finley.mathis@contoso.example, Activities = MailItemsAccessed, date range 2026-07-22 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName finley.mathis@contoso.example \(Hawk sets the window when it starts, 2026-07-22 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds finley.mathis@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-22 -EndDate 2026-09-11
- Message trace, 2026-07-22 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = finley.mathis@contoso.example, then again with Recipient = finley.mathis@contoso.example, dates 2026-07-22 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName finley.mathis@contoso.example \(cannot serve 2026-07-22 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds finley.mathis@contoso.example -StartDate 2026-07-22 -EndDate 2026-09-11
- Entra audit log, 2026-07-22 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-22 to 2026-09-10, filter Initiated by \(actor\) = finley.mathis@contoso.example, Download &gt; JSON; repeat with the Target filter = finley.mathis@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-22 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds finley.mathis@contoso.example -startDate 2026-07-22 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-22 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity finley.mathis@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-22 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds finley.mathis@contoso.example -StartDate 2026-07-22 -EndDate 2026-09-11

**kendall.james@contoso.example** (tenant f8ff8c86-40d4-4634-b6fa-5e29a28c1d80): window 2026-08-08 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 428 | 2026-08-01T07:57:54Z | 2026-09-09T15:41:07Z | 39 | no | after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 56 | 2026-08-12T07:25:13Z | 2026-09-09T15:41:07Z | 28 | no | before 2026-08-08 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 45 | 2026-08-12T07:25:13Z | 2026-09-09T13:16:06Z | 19 | no | before 2026-08-08 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 112 | 2026-08-01T08:00:39Z | 2026-09-09T13:19:02Z | 39 | no | after 2026-09-10 to 2026-09-10 |
| Message trace | 253 | 2026-08-01T03:21:24Z | 2026-09-09T14:51:59Z | 34 | no | after 2026-09-10 to 2026-09-10 |
| Entra audit log | 1 | 2026-08-20T16:49:20Z | 2026-08-20T16:49:20Z | 1 | no | before 2026-08-08 to 2026-08-19; after 2026-08-21 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 134 | 2026-08-03T12:11:36Z | 2026-09-09T16:51:59Z | 30 | no | after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-09-10 to 2026-09-10 (after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = kendall.james@contoso.example, date range 2026-09-10 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds kendall.james@contoso.example -StartDate 2026-09-10 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-08-08 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = kendall.james@contoso.example and Date 2026-08-08 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName kendall.james@contoso.example \(Hawk sets the window when it starts, 2026-08-08 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds kendall.james@contoso.example -startDate 2026-08-08 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-08-08 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = kendall.james@contoso.example and Date 2026-08-08 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds kendall.james@contoso.example -startDate 2026-08-08 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-09-10 to 2026-09-10 (after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = kendall.james@contoso.example, Activities = MailItemsAccessed, date range 2026-09-10 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName kendall.james@contoso.example \(Hawk sets the window when it starts, 2026-09-10 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds kendall.james@contoso.example -Operations MailItemsAccessed -StartDate 2026-09-10 -EndDate 2026-09-11
- Message trace, 2026-09-10 to 2026-09-10 (after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = kendall.james@contoso.example, then again with Recipient = kendall.james@contoso.example, dates 2026-09-10 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName kendall.james@contoso.example \(cannot serve 2026-09-10 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds kendall.james@contoso.example -StartDate 2026-09-10 -EndDate 2026-09-11
- Entra audit log, 2026-08-08 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-08-08 to 2026-09-10, filter Initiated by \(actor\) = kendall.james@contoso.example, Download &gt; JSON; repeat with the Target filter = kendall.james@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-08-08 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds kendall.james@contoso.example -startDate 2026-08-08 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-09-10 to 2026-09-10 (after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity kendall.james@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-09-10 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds kendall.james@contoso.example -StartDate 2026-09-10 -EndDate 2026-09-11

**admin@contoso.example** (tenant f8ff8c86-40d4-4634-b6fa-5e29a28c1d80): window 2026-07-21 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 435 | 2026-08-01T14:50:09Z | 2026-09-09T22:49:45Z | 39 | no | before 2026-07-21 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 50 | 2026-08-11T14:51:33Z | 2026-09-09T14:54:19Z | 28 | no | before 2026-07-21 to 2026-08-10; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 38 | 2026-08-12T22:55:59Z | 2026-09-09T22:58:26Z | 18 | no | before 2026-07-21 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 119 | 2026-08-01T14:52:46Z | 2026-09-09T21:02:19Z | 38 | no | before 2026-07-21 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Message trace | 275 | 2026-08-02T23:17:22Z | 2026-09-09T23:19:19Z | 35 | no | before 2026-07-21 to 2026-08-01; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 11 | 2026-08-11T22:00:34Z | 2026-09-08T20:47:38Z | 9 | no | before 2026-07-21 to 2026-08-10; after 2026-09-09 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 138 | 2026-08-03T18:38:11Z | 2026-09-10T00:49:45Z | 35 | no | before 2026-07-21 to 2026-08-02 |

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

**jamie.adams@contoso.example** (tenant f8ff8c86-40d4-4634-b6fa-5e29a28c1d80): window 2026-07-26 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 427 | 2026-08-02T07:58:10Z | 2026-09-09T16:52:38Z | 38 | no | before 2026-07-26 to 2026-08-01; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 49 | 2026-08-12T07:35:34Z | 2026-09-09T07:48:24Z | 28 | no | before 2026-07-26 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 51 | 2026-08-12T07:35:34Z | 2026-09-09T11:47:21Z | 21 | no | before 2026-07-26 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 113 | 2026-08-02T08:03:06Z | 2026-09-09T16:06:25Z | 38 | no | before 2026-07-26 to 2026-08-01; after 2026-09-10 to 2026-09-10 |
| Message trace | 253 | 2026-08-02T16:13:34Z | 2026-09-09T15:39:03Z | 36 | no | before 2026-07-26 to 2026-08-01; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 4 | 2026-08-11T22:00:34Z | 2026-08-27T11:00:00Z | 3 | no | before 2026-07-26 to 2026-08-10; after 2026-08-28 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 142 | 2026-08-03T10:03:42Z | 2026-09-09T17:04:56Z | 33 | no | before 2026-07-26 to 2026-08-02; after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = jamie.adams@contoso.example, date range 2026-07-26 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds jamie.adams@contoso.example -StartDate 2026-07-26 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = jamie.adams@contoso.example and Date 2026-07-26 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName jamie.adams@contoso.example \(Hawk sets the window when it starts, 2026-07-26 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds jamie.adams@contoso.example -startDate 2026-07-26 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = jamie.adams@contoso.example and Date 2026-07-26 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds jamie.adams@contoso.example -startDate 2026-07-26 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = jamie.adams@contoso.example, Activities = MailItemsAccessed, date range 2026-07-26 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName jamie.adams@contoso.example \(Hawk sets the window when it starts, 2026-07-26 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds jamie.adams@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-26 -EndDate 2026-09-11
- Message trace, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = jamie.adams@contoso.example, then again with Recipient = jamie.adams@contoso.example, dates 2026-07-26 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName jamie.adams@contoso.example \(cannot serve 2026-07-26 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds jamie.adams@contoso.example -StartDate 2026-07-26 -EndDate 2026-09-11
- Entra audit log, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-26 to 2026-09-10, filter Initiated by \(actor\) = jamie.adams@contoso.example, Download &gt; JSON; repeat with the Target filter = jamie.adams@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-26 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds jamie.adams@contoso.example -startDate 2026-07-26 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity jamie.adams@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-26 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds jamie.adams@contoso.example -StartDate 2026-07-26 -EndDate 2026-09-11

**ollie.james@contoso.example** (tenant f8ff8c86-40d4-4634-b6fa-5e29a28c1d80): window 2026-07-26 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 437 | 2026-08-01T00:21:42Z | 2026-09-09T11:40:57Z | 39 | no | before 2026-07-26 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 56 | 2026-08-12T00:45:34Z | 2026-09-09T01:51:01Z | 28 | no | before 2026-07-26 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 41 | 2026-08-12T05:23:30Z | 2026-09-09T08:06:39Z | 19 | no | before 2026-07-26 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 113 | 2026-08-01T00:23:27Z | 2026-09-09T11:40:57Z | 39 | no | before 2026-07-26 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Message trace | 233 | 2026-08-01T04:20:40Z | 2026-09-09T22:49:45Z | 35 | no | before 2026-07-26 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 2 | 2026-09-08T15:10:00Z | 2026-09-08T15:12:00Z | 1 | no | before 2026-07-26 to 2026-09-07; after 2026-09-09 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 121 | 2026-08-01T06:52:14Z | 2026-09-09T13:20:18Z | 31 | no | before 2026-07-26 to 2026-07-31; after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = ollie.james@contoso.example, date range 2026-07-26 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds ollie.james@contoso.example -StartDate 2026-07-26 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = ollie.james@contoso.example and Date 2026-07-26 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName ollie.james@contoso.example \(Hawk sets the window when it starts, 2026-07-26 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds ollie.james@contoso.example -startDate 2026-07-26 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = ollie.james@contoso.example and Date 2026-07-26 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds ollie.james@contoso.example -startDate 2026-07-26 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = ollie.james@contoso.example, Activities = MailItemsAccessed, date range 2026-07-26 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName ollie.james@contoso.example \(Hawk sets the window when it starts, 2026-07-26 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds ollie.james@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-26 -EndDate 2026-09-11
- Message trace, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = ollie.james@contoso.example, then again with Recipient = ollie.james@contoso.example, dates 2026-07-26 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName ollie.james@contoso.example \(cannot serve 2026-07-26 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds ollie.james@contoso.example -StartDate 2026-07-26 -EndDate 2026-09-11
- Entra audit log, 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-26 to 2026-09-10, filter Initiated by \(actor\) = ollie.james@contoso.example, Download &gt; JSON; repeat with the Target filter = ollie.james@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-26 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds ollie.james@contoso.example -startDate 2026-07-26 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-26 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity ollie.james@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-26 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds ollie.james@contoso.example -StartDate 2026-07-26 -EndDate 2026-09-11

**jamie.prescott@contoso.example** (tenant f8ff8c86-40d4-4634-b6fa-5e29a28c1d80): window 2026-07-28 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 444 | 2026-08-01T00:35:06Z | 2026-09-09T18:11:22Z | 39 | no | before 2026-07-28 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 49 | 2026-08-12T00:44:15Z | 2026-09-09T00:33:54Z | 28 | no | before 2026-07-28 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 53 | 2026-08-12T00:44:15Z | 2026-09-09T07:18:57Z | 21 | no | before 2026-07-28 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 113 | 2026-08-01T00:38:12Z | 2026-09-09T18:11:22Z | 39 | no | before 2026-07-28 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Message trace | 269 | 2026-08-01T04:52:14Z | 2026-09-09T17:42:46Z | 34 | no | before 2026-07-28 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 1 | 2026-09-08T20:47:38Z | 2026-09-08T20:47:38Z | 1 | no | before 2026-07-28 to 2026-09-07; after 2026-09-09 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 153 | 2026-08-03T03:29:47Z | 2026-09-09T07:48:00Z | 31 | no | before 2026-07-28 to 2026-08-02; after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = jamie.prescott@contoso.example, date range 2026-07-28 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds jamie.prescott@contoso.example -StartDate 2026-07-28 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = jamie.prescott@contoso.example and Date 2026-07-28 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName jamie.prescott@contoso.example \(Hawk sets the window when it starts, 2026-07-28 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds jamie.prescott@contoso.example -startDate 2026-07-28 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = jamie.prescott@contoso.example and Date 2026-07-28 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds jamie.prescott@contoso.example -startDate 2026-07-28 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = jamie.prescott@contoso.example, Activities = MailItemsAccessed, date range 2026-07-28 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName jamie.prescott@contoso.example \(Hawk sets the window when it starts, 2026-07-28 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds jamie.prescott@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-28 -EndDate 2026-09-11
- Message trace, 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = jamie.prescott@contoso.example, then again with Recipient = jamie.prescott@contoso.example, dates 2026-07-28 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName jamie.prescott@contoso.example \(cannot serve 2026-07-28 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds jamie.prescott@contoso.example -StartDate 2026-07-28 -EndDate 2026-09-11
- Entra audit log, 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-28 to 2026-09-10, filter Initiated by \(actor\) = jamie.prescott@contoso.example, Download &gt; JSON; repeat with the Target filter = jamie.prescott@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-28 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds jamie.prescott@contoso.example -startDate 2026-07-28 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-28 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity jamie.prescott@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-28 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds jamie.prescott@contoso.example -StartDate 2026-07-28 -EndDate 2026-09-11

**val.bennett@contoso.example** (tenant f8ff8c86-40d4-4634-b6fa-5e29a28c1d80): window 2026-07-10 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 480 | 2026-08-01T00:59:22Z | 2026-09-09T16:06:36Z | 37 | no | before 2026-07-10 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 50 | 2026-08-12T00:04:50Z | 2026-09-09T06:47:49Z | 26 | no | before 2026-07-10 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 46 | 2026-08-12T00:17:06Z | 2026-09-09T06:09:33Z | 17 | no | before 2026-07-10 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 124 | 2026-08-01T01:01:18Z | 2026-09-09T16:06:36Z | 37 | no | before 2026-07-10 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Message trace | 252 | 2026-08-01T03:21:24Z | 2026-09-09T15:44:56Z | 36 | no | before 2026-07-10 to 2026-07-31; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 0 |  |  | 0 | no | absent 2026-07-10 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 138 | 2026-08-01T05:21:24Z | 2026-09-09T10:10:26Z | 33 | no | before 2026-07-10 to 2026-07-31; after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-07-10 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = val.bennett@contoso.example, date range 2026-07-10 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds val.bennett@contoso.example -StartDate 2026-07-10 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-10 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = val.bennett@contoso.example and Date 2026-07-10 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName val.bennett@contoso.example \(Hawk sets the window when it starts, 2026-07-10 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds val.bennett@contoso.example -startDate 2026-07-10 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-10 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = val.bennett@contoso.example and Date 2026-07-10 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds val.bennett@contoso.example -startDate 2026-07-10 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-10 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = val.bennett@contoso.example, Activities = MailItemsAccessed, date range 2026-07-10 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName val.bennett@contoso.example \(Hawk sets the window when it starts, 2026-07-10 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds val.bennett@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-10 -EndDate 2026-09-11
- Message trace, 2026-07-10 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = val.bennett@contoso.example, then again with Recipient = val.bennett@contoso.example, dates 2026-07-10 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName val.bennett@contoso.example \(cannot serve 2026-07-10 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds val.bennett@contoso.example -StartDate 2026-07-10 -EndDate 2026-09-11
- Entra audit log, 2026-07-10 to 2026-09-10 (absent)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-10 to 2026-09-10, filter Initiated by \(actor\) = val.bennett@contoso.example, Download &gt; JSON; repeat with the Target filter = val.bennett@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-10 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds val.bennett@contoso.example -startDate 2026-07-10 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-10 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity val.bennett@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-10 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds val.bennett@contoso.example -StartDate 2026-07-10 -EndDate 2026-09-11

**hayden.james@contoso.example** (tenant f8ff8c86-40d4-4634-b6fa-5e29a28c1d80): window 2026-07-15 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 442 | 2026-08-02T00:26:45Z | 2026-09-09T16:36:44Z | 38 | no | before 2026-07-15 to 2026-08-01; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 42 | 2026-08-12T00:00:14Z | 2026-09-09T00:24:33Z | 28 | no | before 2026-07-15 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 44 | 2026-08-12T03:55:37Z | 2026-09-09T05:28:00Z | 17 | no | before 2026-07-15 to 2026-08-11; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 119 | 2026-08-02T00:28:45Z | 2026-09-09T16:36:44Z | 38 | no | before 2026-07-15 to 2026-08-01; after 2026-09-10 to 2026-09-10 |
| Message trace | 248 | 2026-08-02T04:15:09Z | 2026-09-09T16:20:29Z | 37 | no | before 2026-07-15 to 2026-08-01; after 2026-09-10 to 2026-09-10 |
| Entra audit log | 1 | 2026-09-03T16:46:48Z | 2026-09-03T16:46:48Z | 1 | no | before 2026-07-15 to 2026-09-02; after 2026-09-04 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 148 | 2026-08-03T03:33:40Z | 2026-09-09T18:20:29Z | 33 | no | before 2026-07-15 to 2026-08-02; after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = hayden.james@contoso.example, date range 2026-07-15 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds hayden.james@contoso.example -StartDate 2026-07-15 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = hayden.james@contoso.example and Date 2026-07-15 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName hayden.james@contoso.example \(Hawk sets the window when it starts, 2026-07-15 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds hayden.james@contoso.example -startDate 2026-07-15 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = hayden.james@contoso.example and Date 2026-07-15 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds hayden.james@contoso.example -startDate 2026-07-15 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = hayden.james@contoso.example, Activities = MailItemsAccessed, date range 2026-07-15 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName hayden.james@contoso.example \(Hawk sets the window when it starts, 2026-07-15 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds hayden.james@contoso.example -Operations MailItemsAccessed -StartDate 2026-07-15 -EndDate 2026-09-11
- Message trace, 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = hayden.james@contoso.example, then again with Recipient = hayden.james@contoso.example, dates 2026-07-15 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName hayden.james@contoso.example \(cannot serve 2026-07-15 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds hayden.james@contoso.example -StartDate 2026-07-15 -EndDate 2026-09-11
- Entra audit log, 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-07-15 to 2026-09-10, filter Initiated by \(actor\) = hayden.james@contoso.example, Download &gt; JSON; repeat with the Target filter = hayden.james@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-07-15 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds hayden.james@contoso.example -startDate 2026-07-15 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-07-15 to 2026-09-10 (before, after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity hayden.james@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-07-15 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds hayden.james@contoso.example -StartDate 2026-07-15 -EndDate 2026-09-11

**bryce.knox@contoso.example** (tenant f8ff8c86-40d4-4634-b6fa-5e29a28c1d80): window 2026-08-06 to 2026-09-10

| Source | Rows | First (UTC) | Last (UTC) | Days | Sampled | Gaps |
| --- | ---: | --- | --- | ---: | --- | --- |
| Unified audit log | 419 | 2026-08-01T08:01:55Z | 2026-09-09T17:42:46Z | 39 | no | after 2026-09-10 to 2026-09-10 |
| Sign-ins \(interactive\) | 55 | 2026-08-11T15:55:44Z | 2026-09-09T08:55:00Z | 29 | no | before 2026-08-06 to 2026-08-10; after 2026-09-10 to 2026-09-10 |
| Sign-ins \(non-interactive\) | 65 | 2026-08-11T17:21:55Z | 2026-09-09T11:59:18Z | 22 | no | before 2026-08-06 to 2026-08-10; after 2026-09-10 to 2026-09-10 |
| MailItemsAccessed | 117 | 2026-08-01T08:06:07Z | 2026-09-09T16:03:58Z | 39 | no | after 2026-09-10 to 2026-09-10 |
| Message trace | 260 | 2026-08-02T12:28:13Z | 2026-09-09T17:42:46Z | 37 | no | after 2026-09-10 to 2026-09-10 |
| Entra audit log | 0 |  |  | 0 | no | absent 2026-08-06 to 2026-09-10 |
| Mailbox audit log \(legacy\) | 131 | 2026-08-02T14:28:13Z | 2026-09-09T19:42:46Z | 35 | no | after 2026-09-10 to 2026-09-10 |

What to request:

- Unified audit log, 2026-09-10 to 2026-09-10 (after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = bryce.knox@contoso.example, date range 2026-09-10 to 2026-09-10, Search, then Export \(a per-user search stays under the 1,000,000-row cap\)
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-UAL -UserIds bryce.knox@contoso.example -StartDate 2026-09-10 -EndDate 2026-09-11
- Sign-ins \(interactive\), 2026-08-06 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(interactive\) tab: filter User = bryce.knox@contoso.example and Date 2026-08-06 to 2026-09-10, Download &gt; JSON
  - Hawk: Get-HawkUserEntraIDSignInLog -UserPrincipalName bryce.knox@contoso.example \(Hawk sets the window when it starts, 2026-08-06 to 2026-09-10; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed\)
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds bryce.knox@contoso.example -startDate 2026-08-06 -endDate 2026-09-11 -EventTypes interactiveUser
- Sign-ins \(non-interactive\), 2026-08-06 to 2026-09-10 (before, after)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Sign-in logs &gt; User sign-ins \(non-interactive\) tab: filter User = bryce.knox@contoso.example and Date 2026-08-06 to 2026-09-10, Download &gt; JSON
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-GraphEntraSignInLogs -UserIds bryce.knox@contoso.example -startDate 2026-08-06 -endDate 2026-09-11 -EventTypes nonInteractiveUser
- MailItemsAccessed, 2026-09-10 to 2026-09-10 (after)
  - Admin portal: Purview portal &gt; Audit &gt; Search: Users = bryce.knox@contoso.example, Activities = MailItemsAccessed, date range 2026-09-10 to 2026-09-10, Search, then Export
  - Hawk: Get-HawkUserMailItemsAccessed -UserPrincipalName bryce.knox@contoso.example \(Hawk sets the window when it starts, 2026-09-10 to 2026-09-10\)
  - Microsoft-Extractor-Suite: Get-UAL -UserIds bryce.knox@contoso.example -Operations MailItemsAccessed -StartDate 2026-09-10 -EndDate 2026-09-11
- Message trace, 2026-09-10 to 2026-09-10 (after)
  - Admin portal: Exchange admin center &gt; Mail flow &gt; Message trace &gt; Start a trace: Sender = bryce.knox@contoso.example, then again with Recipient = bryce.knox@contoso.example, dates 2026-09-10 to 2026-09-10, report type Extended report, then download it
  - Hawk: Get-HawkUserMessageTrace -UserPrincipalName bryce.knox@contoso.example \(cannot serve 2026-09-10 to 2026-09-10: it ignores dates and returns only the messages the account sent in roughly the last 7 days; useful only when the range falls inside that\)
  - Microsoft-Extractor-Suite: Get-MessageTraceLog -UserIds bryce.knox@contoso.example -StartDate 2026-09-10 -EndDate 2026-09-11
- Entra audit log, 2026-08-06 to 2026-09-10 (absent)
  - Admin portal: Entra admin center &gt; Monitoring &amp; health &gt; Audit logs: Date 2026-08-06 to 2026-09-10, filter Initiated by \(actor\) = bryce.knox@contoso.example, Download &gt; JSON; repeat with the Target filter = bryce.knox@contoso.example
  - Hawk: Get-HawkTenantEntraIDAuditLog \(whole tenant; ignores dates and always returns the last 30 days up to now, so it serves 2026-08-06 to 2026-09-10 only inside that\)
  - Microsoft-Extractor-Suite: Get-GraphEntraAuditLogs -UserIds bryce.knox@contoso.example -startDate 2026-08-06 -endDate 2026-09-11 \(rows where the account is only the target are not returned; -All adds them but ignores the dates for target matches, so filter those by date after collecting\)
- Mailbox audit log \(legacy\), 2026-09-10 to 2026-09-10 (after)
  - Admin portal: Exchange admin center has no export for the legacy mailbox audit log; use Exchange Online PowerShell: Search-MailboxAuditLog -Identity bryce.knox@contoso.example -LogonTypes Delegate,Admin,Owner -StartDate 2026-09-10 -EndDate 2026-09-11 -ShowDetails -ResultSize 250000
  - Hawk: none
  - Microsoft-Extractor-Suite: Get-MailboxAuditLogLegacy -UserIds bryce.knox@contoso.example -StartDate 2026-09-10 -EndDate 2026-09-11

## Method and integrity

Sparrow ingested the collector output into a case database, enriched it and ran its detection rules. Findings, indicators and timeline entries were triaged by decisions, each recorded in a hash-chained audit trail with who made it and when. A decision is either an agent decision, made by an AI agent through the command line, which stays an AI decision that no analyst has reviewed until a reviewer accepts or discards it, or an analyst decision, made by an analyst in the review app and reviewed when made. An item shows `accepted` or `discarded` only when a reviewer's decision was recorded, and a review covers the latest decision on each object (an earlier decision that a later one replaced was not itself reviewed). Notes carry no review state: agent notes are never reviewed and are left out of a reviewed-only report; analyst notes are an analyst's own words and are kept.

- Sparrow version: <VERSION>
- Rule pack SHA-256: <RULE_PACK_SHA256>
- Generated at: 2026-10-03T00:00:00Z
- Audit chain: ok (0 entries)
- Audit head hash: none
- Decisions: AI-decided, not reviewed 0; recorded before the audit trail 0; accepted 0; discarded 0
