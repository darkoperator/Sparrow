# Sparrow

Ingests Microsoft 365 evidence collected with **Hawk** or **Microsoft-Extractor-Suite** into a DuckDB case
database for Business Email Compromise investigations. Every record keeps its source file, line range, byte
range and hash so an analyst can verify it.

## Inputs

- **Hawk** 3.x and 4.x output folders, found by content (`Hawk.log`, a `Tenant` folder or `<user>@<domain>`
  folders with known Hawk files). The folder name does not matter.
- **Microsoft-Extractor-Suite** 4.x Output roots (a folder of `<Component>/<yyyyMMdd-HHmmss>` run folders, with
  or without `LogFile.txt`). One root is one collection, however many runs it holds.
- **Portal exports** recognized by their header wherever they are: Purview audit log search CSV, Entra ID
  sign-in CSV or XLSX, Exchange admin center message trace. A folder holding only such files is ingested as a
  `portal_export` collection.

Unified audit log records from every source (raw, expanded, `Simple_*`, Purview) land in `ual_events`, one row per
AuditData `Id`, with every sighting in `record_sources`. JSON files are preferred over their CSV twins and raw
files over derived ones (`skipped_superseded`). Hawk 3 admin-audit files (Search-AdminAuditLog) load into
`admin_audit_events`, one row per command whatever the copy (JSON, CSV, Format-List, `_Investigate_`, `Simple_*`
summary).

Hawk identity, configuration and state artifacts load into state tables: `users`, `role_assignments`
(Entra and Exchange admins, eDiscovery and ApplicationImpersonation assignments), `oauth_grants`,
`app_credentials`, `inbox_rules` (inbox and sweep rules), `mailboxes` (forwarding, identity, client protocols and
auto-reply, merged from several files), `audit_config`, `tenant_settings` (every AdminAuditLogConfig,
OrganizationConfig and TransportConfig property, and Exchange role entries), `transport_rules`, `remote_domains`,
`mobile_devices`, `risky_users` and `risk_detections`. When several collections of the same case hold the same
entity, the newest collection's values win whatever the ingest order. Records Hawk itself flagged
(`_Investigate_*` files, `_Investigate.txt`) are in `collector_flags`, linked to the flagged row.

Event evidence loads into `signins` (Hawk Entra sign-in logs and Entra admin center sign-in exports, CSV or
XLSX), `directory_audits` (Hawk `EntraIDAuditLogs`), `message_trace` (Hawk 3 `Message_Trace` and Exchange admin
center summary reports), `mailbox_audit_legacy` (Hawk 3 `Exchange_Mailbox_Audit`) and `admin_audit_events`.
The same event from several files or collections is one row: the first copy's values are kept and later copies
only fill values it lacks (a portal export adds the session id, ASN and MFA detail to a Graph sign-in). Hawk 3
`Hawk.log` and PSFramework `<date>_logs.csv` load into `collection_log`. When every culture date in a small file
is ambiguous, the day/month order the rest of its collection shows is used and the file gets a warning. XLSX rows
are verified by sheet row.

Microsoft-Extractor-Suite output loads into the same tables:
- `ual_events`: every Get-UAL format (CSV, JSON, JSONL, SOF-ELK), including the nested Mailbox Audit Log run.
  `Merged/` copies are `skipped_superseded` when their per-window or per-page files are present.
- `signins` and `directory_audits`: Graph sign-in and audit logs; `event_type` comes from the beta
  `signInEventTypes`.
- `message_trace`.
- `mailboxes`: audit settings, bypass and effective audit state, from MailboxAuditStatus.
- `mailbox_permissions`: one row per FullAccess, SendAs, SendOnBehalf or folder grant.
- `tenant_settings` and `audit_config`: security defaults, and organization auditing as reported by the collector.
- MailItemsAccessed Sessions / MessageIDs: a row whose raw UAL record is loaded adds a sighting to it. Other
  Sessions rows load as partial `ual_events` records; other MessageIDs rows load as parent-less
  `mail_items_accessed` rows (no `record_id`, with their own time, user and IP).

Repeated runs of a cmdlet merge by entity, and the latest run's values win. `collector_runs` lists every run
folder with its file count, so a run that returned nothing is visible. Empty exports (0 bytes or a bare BOM) get a
warning. Artifacts with no parser yet (users, roles, MFA, Conditional Access, devices, groups, risk, alerts,
secure score, licences, inbox and transport rules, activity logs, Get-UALGraph, QuickUAL) are reported
`not_supported`.

## Build

```bash
cargo build --release   # first build compiles DuckDB (several minutes)
```

## Use

```bash
sparrow discover /evidence                        # what was found and how each file is classified
sparrow ingest /evidence --case case.duckdb       # add --culture en-US|en-GB|... if dates are ambiguous
sparrow schema --case case.duckdb                 # tables and column descriptions
sparrow upgrade --case case.duckdb                # bring a case made by an older sparrow up to date
sparrow verify ual_events <record-id> --case case.duckdb [--root /moved/Hawk_folder]
```

Add `--json` to any command for machine-readable output. `ingest` exits with code 2 when it completed but a file
failed, a record could not be parsed, or a file's record counts did not reconcile; `verify` exits with code 2 when
a record no longer matches its source. With `--json`, fatal errors (exit code 1) are also printed to stdout as `{"error": "..."}`.
