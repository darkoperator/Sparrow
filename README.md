# Sparrow

Ingests Microsoft 365 evidence collected with **Hawk** or **Microsoft-Extractor-Suite** into a DuckDB case
database for Business Email Compromise investigations. Every record keeps its source file, line range, byte
range and hash so an analyst can verify it.

## Inputs

- **Hawk** 3.x and 4.x output folders, found by content (`Hawk.log`, a `Tenant` folder or `<user>@<domain>`
  folders with known Hawk files). The folder name does not matter.
- **Microsoft-Extractor-Suite** 4.x Output roots (a folder of `<Component>/<yyyyMMdd-HHmmss>` run folders, with
  or without `LogFile.txt`). One root is one collection, however many runs it holds. Parsed components include
  Get-UAL (CSV, JSON, JSONL and SOF-ELK, per-window, merged and Get-UALGraph), Graph sign-ins and audit logs,
  Azure and directory activity logs, message trace, mailbox audit logs, MailItemsAccessed Sessions/MessageIDs,
  mailbox and transport rules (Exchange and Graph), exported e-mail headers, Tenant/UserLicenses, mailbox audit
  status and permissions, MFA registration and methods, Conditional Access, users, admins/roles/PIM, OAuth
  grants, service principals, app registrations, user applications, devices, groups and members, risky users,
  risk detections, security alerts and secure score.
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
(`_Investigate_*` files, `_Investigate.txt`) are in `collector_flags`, linked to the flagged row. The
Microsoft-Extractor-Suite state artifacts add `mfa_registration`, `ca_policies`, `applications` (service
principals, app registrations and user applications), `devices`, `groups` and `group_members`,
`security_alerts` and `secure_score`.

Event evidence loads into `signins` (Hawk Entra sign-in logs and Entra admin center sign-in exports, CSV or
XLSX), `directory_audits` (Hawk `EntraIDAuditLogs`), `message_trace` (Hawk 3 `Message_Trace` and Exchange admin
center summary reports), `mailbox_audit_legacy` (Hawk 3 `Exchange_Mailbox_Audit`) and `admin_audit_events`; Azure
activity logs load into `azure_activity`.
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
warning. Exported e-mail headers load into `email_artifacts` (keyed by Message-ID) and the messages Hawk flagged
into `inbox_rules` with `source = 'hawk'` (Microsoft-Extractor-Suite rules use `source = 'graph'` or `'exo'`).
Hawk artifacts with no parser (`hawk.xml`, mailbox-statistics text, raw message headers, forwarding-recipient
reports, the unique-user IP file) are reported `not_supported`; every Microsoft-Extractor-Suite and portal
artifact listed above now has one.

## Tenant profile and enrichment

After loading, `sparrow ingest` runs the profile step (again at any time with `sparrow profile --case C`):
- `tenant` / `collections.tenant_key`: tenants are told apart by the tenant id in the evidence (UAL
  OrganizationId, sign-in resource tenant); one case may hold several. Org-level settings, transport rules
  and remote domains are kept per collection and merged per tenant in `tenant_audit_config`,
  `tenant_settings_current`, `transport_rules_current` and `remote_domains_current`.
- `tenant_domains`: domains that count as internal, from user UPNs and message trace; change them with
  `sparrow tenant domains add|remove|list`.
- `licenses`: Hawk's licence line (low confidence: Hawk matches SKU-name substrings, so "E5" is also logged
  for Office 365 E5, which has no Entra ID P1/P2), and Microsoft-Extractor-Suite `TenantLicenses.csv`
  (source `invictus_tenant_licenses`, high confidence, `ServicePlans` split on `;`). `user_licenses` holds
  the per-user `UserLicenses.csv` rows.
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

## Detection

`rules/` holds the detection rules; [`rules/README.md`](rules/README.md) is the rule format (operators,
`@list:`, the `sql:` contract, `threshold:`, `baseline_allow`, custom rule directories). Detection runs
**automatically as the last step of `sparrow ingest` and `sparrow profile`**, and on demand with
`sparrow detect`.

```bash
sparrow detect --case case.duckdb                   # every rule, every tenant
sparrow detect --case case.duckdb --rule SPW-MAIL-003   # one rule (repeatable)
sparrow detect --case case.duckdb --tag correlation     # rules with a tag (repeatable)
```

`--data DIR` / `--rules DIR` (repeatable, or `$SPARROW_DATA` / `$SPARROW_RULES`) override the embedded
data files and add or replace rules. `--no-detect` on `ingest` and `profile` skips the detection run
that follows the profile step.

Every attempt of every rule is recorded in `detection_runs`, one row per (tenant, rule):

```console
$ sparrow detect --case case.duckdb
detection: run 2, 27 rule runs (4 not applicable, 0 errors), 0 new findings, 0 updated, 0 evidence rows
  SPW-APP-001    91de958c-…  ran              2 hits
  SPW-APP-002    91de958c-…  not_applicable   0 hits  (no GeoIP data)
  SPW-CFG-001    91de958c-…  ran              0 hits
  SPW-ID-002     91de958c-…  not_applicable   0 hits  (no GeoIP data)
  SPW-ID-003     91de958c-…  not_applicable   0 hits  (no GeoIP data)
  SPW-ID-010     91de958c-…  not_applicable   0 hits  (no GeoIP data)
  SPW-MAIL-003   91de958c-…  ran              2 hits
  SPW-MAIL-005   91de958c-…  ran              12 hits
```

(that run is a `bec-aitm` Hawk 4 tree ingested **without** `--geoip-dir`, so the four rules that
read `ip_intel` are not applicable; the same run with `--geoip-dir` reports
`27 rule runs (0 not applicable, 0 errors)`. The listing is an excerpt: `sparrow detect` prints
one line per (rule, tenant), so a case with several tenants prints several lines per rule, and the
tenant key is shown in full.)

The other two reasons come from a `business-basic` tree, where organization mailbox auditing is
disabled and there is no GeoIP either:

```console
$ sparrow detect --case case.duckdb
detection: run 2, 27 rule runs (6 not applicable, 0 errors), 0 new findings, 0 updated, 0 evidence rows
  SPW-MAIL-005   91de958c-…  not_applicable   0 hits  (evidence mail_items_accessed is not_enabled)
  SPW-MAIL-006   91de958c-…  not_applicable   0 hits  (evidence mail_send is not_enabled)
```

A rule is never silently empty. It is `not_applicable` with a **reason** when a `requires` capability
is `not_licensed`, a `requires_evidence` source is `not_licensed` / `not_enabled`, or a
`needs_geoip` rule has no GeoIP data for the tenant; `error` with the message when it fails to run
(the other rules still run). Rules run per tenant on a locked, read-only instance scoped to that
tenant, so two tenants' evidence never combines into one finding.

### Findings

`findings` holds one row per finding, with its trigger records in `finding_evidence`.

- **`fingerprint`** = `sha256(rule_id 0x1f tenant_key 0x1f <group_by values>)`, where `group_by`
  defaults to `record_key`. **`finding_id`** is the first 16 hex characters of the fingerprint.
- **Findings are stable across re-runs.** Re-running adds new evidence to the existing finding,
  widens `first_seen` / `last_seen`, refreshes `severity` and `title`, and **never deletes** a
  finding. Re-running unchanged rules on unchanged evidence is a no-op:

```console
$ sparrow detect --case case.duckdb
detection: run 2, 27 rule runs (0 not applicable, 0 errors), 0 new findings, 0 updated, 0 evidence rows
```

- **`rule_updated`** — when a rule's hash changes under a finding (its text, or a static list it
  references, or the case indicators a `@list:case_iocs.*` list read), the finding is flagged
  `rule_updated = true` for re-review, even if the run did not hit it again.
- **The analyst's columns are never written by detection**: `status` (which detection always inserts
  as `new`), `disposition_reason` and `assigned_to`. Phase 7 owns every analyst write.
- The `timeline` view gained `finding_count` and `finding_ids`: for each event row, the findings
  whose evidence cites it.

### Rule tooling

```bash
sparrow rules lint                              # compile, shape, tests and the coverage cross-check
sparrow rules test [--rule SPW-MAIL-003]        # the rules' own inline fixtures
sparrow rules list [--requires CAP] [--tag TAG] # id, severity, status, title, requires
```

### Case indicators

`sparrow ioc add|list|remove` manages the `case_indicators` that a rule reads through
`@list:case_iocs.<type>` (`ip`, `upn`, `app_id`, `domain`, `user_agent`, `rule_name`, `email`, `url`,
`hash`). Only `malicious` and `suspicious` indicators reach a rule.

```console
$ sparrow ioc add --case case.duckdb --type ip --value 203.0.113.50 --verdict malicious --note "attacker proxy"
a4d22a34c6847a00  ip 203.0.113.50  malicious
$ sparrow ioc list --case case.duckdb
a4d22a34c6847a00  ip         malicious  203.0.113.50  by agent:unnamed  (attacker proxy)
1 indicators
$ sparrow ioc remove --case case.duckdb --id a4d22a34c6847a00
removed a4d22a34c6847a00
```

(the `id` is derived from the indicator, so it differs per case and value).

`add` and `remove` are agent decisions: `--agent ID` (or `$SPARROW_AGENT`, default `unnamed`) names the
agent, recorded as `agent:<id>`, and `--analyst NAME` (or `$SPARROW_ANALYST`, optional) names the analyst the
decision is made on behalf of: its reviewer, not an identity claim. Each write records `decided_by`,
`on_behalf_of` and `review_state = pending_review` on the indicator and appends an audit entry. `ioc set-verdict
--id ID --verdict V [--note N]` changes a verdict. `remove` is a soft delete: rules stop reading the indicator,
and `ioc list --include-removed` still shows it. `--tenant KEY` scopes an indicator to one tenant; without
it it applies to every tenant of the case.

## Build

```bash
cargo build --release   # first build compiles DuckDB (several minutes)
```

## Testing

```bash
cargo test --workspace                    # the default job: every test except the heavy ones
cargo test --workspace -- --ignored       # the heavy job: every-scenario x every-collector matrices, volume and perf checks
```

Heavy tests carry `#[ignore = "heavy: run with cargo test --workspace -- --ignored"]`; each matrix keeps one
fast representative (bec-aitm for every collector) in the default job. Run both before merging.

The tests that need a generated tree, or an ingested and profiled case of one, share a cache under
`target/tmp/sparrow-cache/<build fingerprint>/` (`sparrow_synth::cache`): a tree or a case is built once per
run, whichever test binary asks first, and every test gets its own copy of the case file. The fingerprint hashes
the generator, parsers, profile, schema, rules, scenarios, lock file and compiler, so any source edit starts a new
cache; `cargo clean` removes it. `SPARROW_NO_CACHE=1 cargo test --workspace` bypasses it (every tree generated and
every case ingested in memory afresh, as before): both modes must pass with the same counts.

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
sparrow detect --case case.duckdb                 # run the rules (also the last step of ingest/profile;
                                                  # --rule ID / --tag TAG to narrow, --no-detect to skip
sparrow rules lint | test | list                   # check, test and list the rules in rules/
sparrow ioc list --case case.duckdb               # also add|set-verdict|remove [--agent ID] [--analyst NAME];
                                                  # --include-removed lists removed ones too
sparrow finding set-status ID STATUS [--reason R] --case case.duckdb   # also assign ID NAME, ack-rule-update ID
sparrow audit verify --case case.duckdb           # check the audit chain (exit 3 when broken;
                                                  # --acknowledge [--agent ID] records a break)
sparrow audit log --case case.duckdb              # the audit trail; --object TYPE:ID for one object
```

Add `--json` to any command for machine-readable output. Exit codes:

- 0: success;
- 1: any other error;
- 2: `ingest` completed but a file failed, a record could not be parsed, or a file's record counts did not
  reconcile; `verify`: a record no longer matches its source;
- 3: the audit chain is broken (`audit verify`, and any write refused because of it);
- 4: the case is open by another writer;
- 5: an invalid agent decision (a bad status or verdict, a missing reason, an unknown object); nothing was written.

With `--json`, errors are also printed to stdout as `{"error": "..."}`.

## Synthetic data

`sparrow synth` generates deterministic collector trees from a scenario and a seed, each with a ground-truth
`manifest.json`, so parsing, provenance, dedup, supersession, profiling **and detection coverage** can be tested
end to end without any customer data. It writes reserved values only (RFC 5737/RFC 3849 addresses, `*.example`/`*.test`
domains, seed-derived GUIDs) and never reads a real capture except in the aggregates-only `conformance --real` run:

```bash
sparrow synth --scenario bec-aitm --collector hawk4 --out tree       # also hawk3, invictus, portal
sparrow ingest tree --case case.duckdb --geoip-dir tree/geoip         # ingest also runs detection
sparrow synth check --manifest tree/manifest.json --case case.duckdb # manifest diff + the detection gate
sparrow synth coverage                                               # seed-rule coverage report
sparrow synth conformance --tree tree --collector hawk              # structure vs the recorded layouts
```

`sparrow synth check` closes the loop: besides diffing the case against the manifest, it runs the **detection
gate** over the case's findings, so every storyline the manifest expects to trigger its rule does, every
look-alike does not, and the benign baseline produces no finding at all. It exits 2 on any difference.

See [`crates/sparrow-synth/README.md`](crates/sparrow-synth/README.md) for the flags, the scenario and manifest
formats, the storyline kinds, the licence and audit profiles, coverage (`rules/coverage.yaml`) and conformance.
