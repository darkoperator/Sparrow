# What to collect, by licence

Sparrow does not collect evidence: it reads what Hawk, Microsoft-Extractor-Suite and the admin portals export. What
those can export depends on the tenant's licences, and much of it expires. This page is for planning the first
collection, before there is a case. Once a collection is ingested, the case answers the same questions for that
tenant and its users, and the case wins over this page:

```bash
sparrow capabilities --case case.duckdb --json     # each licence and evidence source: collected, not licensed, beyond retention...
sparrow coverage --case case.duckdb --user user@contoso.example --json   # per account: missing dates, and the command to fetch them
```

Every fact here comes from Sparrow's own data: licences and retention from
[`data/capabilities.yaml`](../data/capabilities.yaml), where each one cites Microsoft Learn and the date it was checked
(September 2026); collector commands from Sparrow's evidence definitions and
[`rules/lists/collection_hints.yaml`](../rules/lists/collection_hints.yaml); what Sparrow reads from the
[Reference](REFERENCE.md#inputs). Microsoft changes licensing; when this page and the data disagree, the data is what
Sparrow uses. A test checks that every capability in the file has a row here with its retention; the rest of the page is
kept by review.

## First: pull what expires soonest

Ask for the licence list early (Microsoft-Extractor-Suite `Get-Licenses` and `Get-LicensesByUser`): it tells you which
row below applies. Without it, assume the least and pull in this order:

1. **Entra ID sign-in and audit logs.** 7 days on Entra ID Free, 30 days with P1/P2. On Free, Microsoft Graph refuses
   sign-in downloads, so Hawk and Microsoft-Extractor-Suite get none: download them from the Entra admin center
   (Sign-in logs > Download; for the audit log choose JSON). Do this on day one whatever else is pending.
2. **Defender for Office 365 data**, when licensed: 30 days. Portal only, and Sparrow cannot read it yet: export it
   (Explorer, or Advanced hunting `EmailEvents` and `UrlClickEvents`) and keep it with the case.
3. **Message trace and the Exchange mailbox and admin audit logs**: 90 days.
4. **The unified audit log**: 180 days on Audit (Standard), 365 days for the Entra ID, Exchange, OneDrive and
   SharePoint records of users with Audit (Premium).
5. **Current state** (inbox rules, forwarding, OAuth grants, mailbox permissions, roles, MFA methods): it does not
   expire, but it shows only what is there now. Capture it **before anyone remediates**: a deleted rule is gone from
   the state; the unified audit log still records that it was created and changed, so preserve and check it.

## What each licence level gives you

Licences apply per user, not per tenant: a tenant on Microsoft 365 E3 with a few E5 users has 365-day audit records
for those users only. The licence names below are Microsoft's; the capability ids are what `sparrow capabilities`
reports.

| Capability | Comes with | What it gives an investigation | Kept | How to pull it |
| --- | --- | --- | --- | --- |
| `ual_standard` Audit (Standard) | Every tenant with Exchange Online: Microsoft 365 E3/A3/A1/G3/F3/F1, Office 365 E3/E1/A3/A1/G3/G1/F3, Business Basic/Standard/Premium | The unified audit log: mailbox and admin actions, rule changes, SharePoint and OneDrive, and (since 2024) MailItemsAccessed, Send and search queries | 180 days (90 days for records before 2023-10-17) | Microsoft-Extractor-Suite `Get-UAL`; Purview portal > Audit > search, export; Hawk `Start-HawkTenantInvestigation` (selected operations only) |
| `audit_premium` Audit (Premium) | Microsoft 365 E5/A5/G5/E7, Office 365 E5/A5/G5, Microsoft 365 E5 Compliance, the eDiscovery and Audit add-ons | Longer retention of the same log for licensed users | 365 days for Entra ID, Exchange, OneDrive and SharePoint records (other workloads 180) | As Audit (Standard) |
| `entra_signin_logs` Entra sign-in logs | Every edition | Sign-ins: address, app, client, result, MFA detail, session id | 7 days on Entra ID Free | Entra admin center > Sign-in logs > Download (every edition); Graph needs P1/P2 (see `entra_id_p1`) |
| `entra_audit_logs` Entra audit logs | Every edition | Directory changes: MFA methods, app consents and credentials, roles, password resets | 7 days on Entra ID Free | Entra admin center > Audit logs > Download (JSON); Microsoft-Extractor-Suite `Get-GraphEntraAuditLogs`; Hawk `Get-HawkTenantEntraIDAuditLog` |
| `entra_id_p1` Entra ID P1 | Microsoft 365 E3/E5/A3/A5/G3/G5/F1/F3, Business Premium, EMS E3/E5, Entra ID P1/P2. **Not** Office 365 E3/E5 or Business Basic/Standard | Sign-in and audit logs kept longer, sign-ins through Graph (so the collectors can fetch them), Conditional Access policies | 30 days | Microsoft-Extractor-Suite `Get-GraphEntraSignInLogs`, `Get-ConditionalAccessPolicies`; Hawk `Get-HawkUserEntraIDSignInLog` |
| `identity_protection` Entra ID Protection | Entra ID P2: Microsoft 365 E5/A5/G5, EMS E5, Entra ID P2, Microsoft 365 E5 Security | Risk detections and risky users in full (below P2, sign-in risk reads "hidden" and premium detections "generic") | 90 days for risky sign-ins (7 and 30 days on Free and P1); risky users until remediated | Microsoft-Extractor-Suite `Get-RiskyDetections`, `Get-RiskyUsers`; Hawk `Get-HawkTenantRiskDetections`, `Get-HawkTenantRiskyUsers` |
| `mdo_p1` Defender for Office 365 Plan 1 | Business Premium; Office 365 E3 and Microsoft 365 E3 from 2026-07-01 (not the "no Teams" E3 variants); every Plan 2 SKU | Real-time detections and the email entity page | 30 days | Defender portal only (neither collector exports it; Sparrow cannot read it yet) |
| `mdo_p2` Defender for Office 365 Plan 2 | Microsoft 365 and Office 365 E5/A5/G5, Microsoft 365 E5 Security | Threat Explorer, including Safe Links URL clicks; advanced hunting `EmailEvents` and `UrlClickEvents` | 30 days | Defender portal only (as Plan 1) |
| `message_trace` Message trace | Every organization with cloud mailboxes | Who mailed whom, when, and what happened to each message (the Extended report adds every delivery event: forwarding, drops) | 90 days (10 days and 5,000 results per query) | Microsoft-Extractor-Suite `Get-MessageTraceLog`; Exchange admin center > Mail flow > Message trace (Extended report); Hawk `Get-HawkUserMessageTrace` (only roughly the last 7 days of mail the account sent) |
| `mailbox_audit_legacy` Mailbox audit log | Every tenant | Owner, delegate and admin actions in a mailbox (the same actions are in the unified audit log; this search is being deprecated) | 90 days by default (`Set-Mailbox -AuditLogAgeLimit`) | Microsoft-Extractor-Suite `Get-MailboxAuditLogLegacy`; Exchange Online PowerShell `Search-MailboxAuditLog` |
| `exchange_admin_audit` Exchange admin audit log | Every tenant | Exchange admin cmdlets (also in the unified audit log as ExchangeAdmin records) | 90 days by default (`Set-AdminAuditLogConfig -AdminAuditLogAgeLimit`) | Microsoft-Extractor-Suite `Get-UAL -RecordType ExchangeAdmin`; Hawk `Start-HawkTenantInvestigation` |

### Common tenants at a glance

What each base plan brings. Add-ons and per-user licences change it: the licence list decides.

| The tenant is on | Sign-in and Entra audit logs | Unified audit log | Risk detail | Defender email data |
| --- | --- | --- | --- | --- |
| Business Basic/Standard, Office 365 E1 | 7 days; sign-ins by portal download only | 180 days | Limited, 7 days | None |
| Office 365 E3 | 7 days; sign-ins by portal download only | 180 days | Limited, 7 days | Plan 1 (from 2026-07-01; not the "no Teams" E3) |
| Microsoft 365 E3, Business Premium | 30 days; collectors can fetch sign-ins | 180 days | Limited, 30 days | Plan 1 (Microsoft 365 E3 from 2026-07-01; not the "no Teams" E3) |
| Office 365 E5 | 7 days; sign-ins by portal download only (no Entra ID P1/P2) | 365 days for licensed users | Limited, 7 days | Plan 2 |
| Microsoft 365 E5 | 30 days; collectors can fetch sign-ins | 365 days for licensed users | Full, 90 days | Plan 2 |

Risk detail below Entra ID P2 is limited: sign-in risk levels read "hidden", premium detections "generic", and risky
users show medium and high only. The days are how long risky sign-ins are kept.

Office 365 E5 is the trap: it brings Audit (Premium) and Defender Plan 2 but no Entra ID P1/P2, so its sign-in logs
last 7 days and the collectors cannot fetch them. Hawk's log line "M365 License type detected: E5" matches it too, so
treat Hawk's tier as a hint and confirm with the licence list.

## Current state: no retention, but capture it before remediation

| Evidence | Microsoft-Extractor-Suite | Hawk |
| --- | --- | --- |
| Inbox and sweep rules | `Get-MailboxRules` | `Get-HawkUserInboxRule` |
| Mailbox forwarding, auto-reply, auditing | `Get-MailboxAuditStatus` | `Get-HawkUserConfiguration` |
| Mailbox permissions | `Get-MailboxPermissions` | none |
| OAuth grants, applications and service principals | `Get-OAuthPermissionsGraph` | `Get-HawkTenantConsentGrant`, `Get-HawkTenantAppAndSPNCredentialDetail` |
| Admin role assignments | `Get-AdminUsers` | `Get-HawkTenantEntraIDAdmin`, `Get-HawkTenantEXOAdmin` |
| MFA registration | `Get-MFA` | none |
| Conditional Access policies (Entra ID P1) | `Get-ConditionalAccessPolicies` | none |
| Users, devices, groups | `Get-Users`, `Get-Devices`, `Get-Groups` | `Get-HawkTenantEntraIDUser` |
| Transport rules | `Get-TransportRules` | `Get-HawkTenantConfiguration` |
| Licences | `Get-Licenses`, `Get-LicensesByUser` | none (only its log line) |

## Traps that cost evidence

- **MailItemsAccessed.** Since 2024 it is an Audit (Standard) event, but one Microsoft Learn page still says it needs
  E5. A missing MailItemsAccessed for a non-E5 user is a caveat, not proof the licence lacks it.
- **Date windows in the collectors.** Hawk's per-user cmdlets take no dates: they use the window Hawk was started
  with. Hawk's sign-in pull covers at most the last 14 days in Graph; `Get-HawkUserMessageTrace` ignores dates and
  returns roughly the last 7 days of sent mail; `Get-HawkTenantEntraIDAuditLog` returns the whole tenant's last 30
  days. Microsoft-Extractor-Suite reads `-EndDate` as that day's midnight, so to cover a last day pass the day after.
- **Export caps.** A Purview audit search export is capped; a capped export loads as sampled, and `sparrow coverage`
  flags it. Split the search by user or by date until each export is under the cap.

After the first ingest, `sparrow coverage --user` writes these commands for each account with its exact dates.
