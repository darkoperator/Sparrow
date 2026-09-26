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

## Tenant profile and enrichment

After loading, `sparrow ingest` runs the profile step (again at any time with `sparrow profile --case C`):
- `tenant` / `collections.tenant_key`: tenants are told apart by the tenant id in the evidence (UAL
  OrganizationId, sign-in resource tenant); one case may hold several. Org-level settings are kept per
  collection and merged per tenant in `tenant_audit_config` and `tenant_settings_current`.
- `tenant_domains`: domains that count as internal, from user UPNs and message trace; change them with
  `sparrow tenant domains add|remove|list`.
- `licenses`: today only Hawk's licence line (low confidence: Hawk matches SKU-name substrings, so "E5" is
  also logged for Office 365 E5, which has no Entra ID P1/P2). Microsoft-Extractor-Suite licence exports
  are not parsed yet.
- `capabilities` and `tenant_capabilities`: which Microsoft 365 features the tenant has, from licences,
  evidence (visible sign-in risk levels, Graph sign-in downloads, UAL records older than 180 days) and
  baseline assumptions. The facts live in `data/capabilities.yaml`, each with its Microsoft Learn source.
- `evidence_availability` / `sparrow capabilities`: per evidence source, collected, partial, not
  licensed, not enabled, beyond retention, available but not collected, or unknown, with the reason and
  the collector command that would fill the gap. Agents should call `sparrow capabilities --json` first.
- `ip_intel`: MaxMind GeoLite2 City and ASN (`--geoip-dir DIR` holding the `.mmdb` files; without it
  there is no geolocation), Microsoft 365 service ranges (bundled snapshot) and hosting-provider ASNs
  (`rules/lists/hosting_asns.yaml`).
- `identities` / `identity_aliases`: one identity per actor across UPN, object id, UAL PUID and app id.
- `operation_catalog`, `timeline` and `auth_events`: every event in one time-ordered view with category,
  IP country and ASN, and `source_refs` pointing at the original lines.
- `state_absent_in_newer`: state rows (inbox rules, permissions, ...) that a newer capture no longer has.
- `sparrow summary`: tenant, licences, coverage, top actors and evidence gaps.

`--data DIR` (or `SPARROW_DATA`) and `--rules DIR` (or `SPARROW_RULES`) override the embedded
`capabilities.yaml`, `operation_catalog.yaml`, `ms365_ip_ranges.json` and `lists/hosting_asns.yaml`.

## Build

```bash
cargo build --release   # first build compiles DuckDB (several minutes)
```

## Use

```bash
sparrow discover /evidence                        # what was found and how each file is classified
sparrow ingest /evidence --case case.duckdb       # add --culture en-US|en-GB|... if dates are ambiguous;
                                                  # --geoip-dir DIR for IP geolocation
sparrow profile --case case.duckdb                # re-run the profile step (same --data/--rules/--geoip-dir)
sparrow capabilities --case case.duckdb           # what evidence the case holds, what is missing and why
sparrow summary --case case.duckdb                # tenant, licences, coverage, top actors, gaps
sparrow tenant domains list --case case.duckdb    # also add|remove <domain> [--tenant KEY] [--analyst NAME]
sparrow schema --case case.duckdb                 # tables and column descriptions
sparrow upgrade --case case.duckdb                # bring a case made by an older sparrow up to date
sparrow verify ual_events <record-id> --case case.duckdb [--root /moved/Hawk_folder]
```

Add `--json` to any command for machine-readable output. `ingest` exits with code 2 when it completed but a file
failed, a record could not be parsed, or a file's record counts did not reconcile; `verify` exits with code 2 when
a record no longer matches its source. With `--json`, fatal errors (exit code 1) are also printed to stdout as `{"error": "..."}`.
