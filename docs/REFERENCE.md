# Reference: evidence, profile, detections, synthetic data

This is the detailed reference material from the original README. For the investigator workflow, start with the [README](../README.md). For building and testing, see [DEVELOPING.md](DEVELOPING.md).

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

### Adding a follow-up pull for one user

During an investigation the analyst is often asked for more evidence about one account, such as its mailbox
audit log, message trace or MailItemsAccessed records, to see what an attacker read or sent. Run the collector for
that user, then ingest its output folder into the **same case**:

```bash
sparrow discover /evidence/followup-alice          # check that every file is recognised before loading
sparrow ingest /evidence/followup-alice --case case.duckdb
```

The pull becomes a new collection in the case. Events it shares with earlier collections are not duplicated (each
copy adds a sighting in `record_sources`), state from the newer collection wins, and profile and detection re-run
over the whole case. The case file must be outside the evidence folder.

Sparrow recognises files by their path and name, so keep the folder layout the collector wrote:

| Pull | Collector | Path Sparrow expects | Loads into |
| --- | --- | --- | --- |
| Mailbox audit log | Microsoft-Extractor-Suite `Get-MailboxAuditLog` | `Mailbox Audit Log/<yyyyMMdd-HHmmss>-Legacy/...-mailboxAuditLog-....csv` | `mailbox_audit_legacy` |
| Mailbox audit log | Hawk user investigation | `<upn>/Exchange_Mailbox_Audit_....csv` or `.json` | `mailbox_audit_legacy` |
| Message trace | Microsoft-Extractor-Suite `Get-MessageTraceLog` | `MessageTrace/<yyyyMMdd-HHmmss>/...-MessageTrace.csv` (or `-MTL.csv`) | `message_trace` |
| Message trace | Hawk user investigation | `<upn>/Message_Trace_....csv` or `.json` | `message_trace` |
| Message trace | Exchange admin center message trace report (CSV) | any folder; recognised by its header | `message_trace` |
| Mail items accessed | Microsoft-Extractor-Suite `Get-MailItemsAccessed` | `MailItemsAccessed/<yyyyMMdd-HHmmss>/...MessageIDs....csv` and `...Sessions....csv` | `mail_items_accessed` |
| Mail items accessed | Hawk user investigation | `<upn>/MailItemsAccessed_....csv` or `.json` | `ual_events` |

- A renamed or flattened file shows as `unrecognized` in `discover`. Restore the collector's layout before
  ingesting, rather than loading a partial pull.
- The legacy mailbox audit log (`Search-MailboxAuditLog`) and MailItemsAccessed are different sources.
  MailItemsAccessed shows which messages were read or synced. Since 2024 it is an Audit (Standard) event, although
  Microsoft Learn still says in places that it needs E5. `sparrow capabilities` says whether the case holds it, and
  why it may be missing.
- Ingesting the same folder again is safe: files already loaded are reported `duplicate_file`.

Then read the user's activity across every collection:

```bash
sparrow timeline --case case.duckdb --user alice@contoso.example --limit 200 --json
sparrow pivot user alice@contoso.example --case case.duckdb --cap 20 --json
sparrow schema --case case.duckdb --table message_trace      # column names before writing SQL
sparrow query "SELECT received, sender, recipient, subject, status FROM message_trace WHERE sender = 'alice@contoso.example' OR recipient = 'alice@contoso.example' ORDER BY received LIMIT 50" --case case.duckdb
```

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

`rules/` holds the detection rules; [`rules/README.md`](../rules/README.md) is the rule format (operators,
`@list:`, the `sql:` contract, `threshold:`, `computed` and `baseline_allow`, custom rule directories). Detection runs
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
sparrow schema --case case.duckdb                 # the tables and views `query` reads: comments, columns, types
                                                  # [--table T] (an unknown T exits 1 listing the names)
sparrow upgrade --case case.duckdb                # bring a case made by an older sparrow up to date (also
                                                  # rebuilds spray_sources and cloud_services from its sign-ins,
                                                  # with the codes the last profile used; a failed rebuild is
                                                  # retried by every later write, and read commands warn meanwhile)
sparrow verify ual_events <record-id> --case case.duckdb [--root /moved/Hawk_folder]
sparrow detect --case case.duckdb                 # run the rules (also the last step of ingest/profile;
                                                  # --rule ID / --tag TAG to narrow, --no-detect to skip
sparrow rules lint | test | list                   # check, test and list the rules in rules/
sparrow ioc list --case case.duckdb               # also add|set-verdict|remove [--agent ID] [--analyst NAME];
                                                  # --include-removed lists removed ones too
sparrow finding set-status ID STATUS [--reason R] --case case.duckdb   # also assign ID NAME, ack-rule-update ID
sparrow timeline-entry propose --time T --title X --phase P --evidence TABLE:KEY... --case case.duckdb
                                                  # also verify ID, reject ID --reason R,
                                                  # edit ID [--title ...] [--clear-narrative]
sparrow note add finding:ID|entry:ID|ioc:ID|TABLE:KEY --text "..." --case case.duckdb
sparrow accounts --case case.duckdb              # [--tenant T --limit N]: the accounts with findings, worst first, with
                                                  # stages and the addresses worth a look (the roll-up detection builds)
sparrow finding list --case case.duckdb           # [--status --severity MIN --rule ID... --user UPN --tenant
                                                  #  --rule-updated --review-state --limit N]; severity first,
                                                  #  then the most recent
sparrow finding show ID [ID...] --case case.duckdb  # evidence with source refs (first 50; --all), guidance, notes,
                                                  # decision, history; up to 50 ids at once
sparrow timeline --case case.duckdb               # [--user --ip --category --from --to --finding --limit 200]
sparrow timeline-entry list --case case.duckdb    # [--status --review-state]
sparrow pivot ip|user VALUE --case case.duckdb    # every section capped by --cap 50, truncation reported
sparrow query "SELECT ..." --case case.duckdb     # one read-only SELECT, --limit 1000
sparrow audit verify --case case.duckdb           # check the audit chain (exit 3 when broken;
                                                  # --acknowledge [--agent ID] records a break)
sparrow audit log --case case.duckdb              # the audit trail; --object TYPE:ID for one object
sparrow export report --format md [--out FILE] [--reviewed-only] --case case.duckdb
sparrow export timeline --format csv [--scope verified|all --from T --to T --user U --out FILE] --case case.duckdb
sparrow export workbook --format xlsx --out FILE --case case.duckdb
```

Add `--json` to any command for machine-readable output. Exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | success |
| 1 | any other error, including a refused `query` (not a single SELECT, or one that tries to write or reach outside the case) and a bad option |
| 2 | `ingest` completed but a file failed, a record could not be parsed, or a file's record counts did not reconcile; `verify`: a record no longer matches its source; `finding show` with several ids: one or more ids were not found (the others are shown, the unknown ones listed); `synth coverage` / `conformance`: a gap |
| 3 | the audit chain is broken (`audit verify`, and any write refused because of it) |
| 4 | the case is open by another writer (a write, and also a read or `audit verify` while a writer holds the case) |
| 5 | an invalid agent decision (a bad status, verdict, phase or time, a missing reason, an unknown object, an evidence reference not in the case, text over its cap: 16 KiB for notes, narratives, reasons and comments, 500 characters for titles) or an `export --out` that would overwrite the case; nothing was written |

`schema` lists exactly the tables and views `query` can read: it reads DuckDB's catalog on `query`'s own locked
connection, so it never lists a DuckDB system object. Each comes with its table comment and its columns (name,
type, comment) in ordinal order, sorted by name; `--json` is `{"tables":[{"name","comment","kind","columns":
[{"name","type","comment"}]}]}` (`kind` is `table` or `view`). Every table, view and column has a comment
(migration 19 added the last ones, on `schema_migrations`). `--table T` (or `schema T`) shows one.

`finding list` filters combine with AND, in SQL: `--user` matches `actor_upn` case-insensitively, `--rule` is an
exact rule id and repeatable (a finding of any of them), `--severity` is the minimum (info < low < medium < high <
critical), and `--limit N` keeps the first N of the filtered list. `--json` is `{"findings":[...],"total":N,
"truncated":bool}` (`total` counts every match); plain output ends `… K more (truncated)` when capped, then `N
findings` with the total. Findings carry no address field, so there is no `--ip` (use `timeline --ip` or `pivot ip`).

`finding show` with one id prints exactly what it always has, and an unknown id is an error (exit 1). With several
(at most 50; more exits 1), it shows each found finding in argument order, a repeated id once: `--json` is
`{"findings":[<each as the one-id form>],"missing":[<unknown ids>]}`, plain output separates the findings with a
rule line and ends `not found: <ids>`; exit 2 when any id is missing.

`sparrow accounts` prints the account roll-up that detection rebuilds after every run (`account_rollup`), ordered by
worst severity, then the number of stages (descending), then the first suspicious time, then the UPN. `--json` is
`{"accounts":[...],"total":N,"truncated":bool,"warnings":[...]}`: each account has `tenant_key`, `upn`,
`worst_severity`, `finding_count`, `by_severity`, `stages`, `first_suspicious`, `rules`, `addresses` (at most 20, each
`{ip, reasons, tables, first_seen, last_seen, asn, asn_org, is_hosting, spray_source, in_user_signins}`),
`addresses_total` and `addresses_truncated`; `total` counts the accounts before `--limit`. Plain output is one block
per account (up to 5 addresses with their reasons, then `+N more addresses`) and ends `K of N accounts`. When the
enrichment is not current (a case detected before the roll-up existed, a detection run newer than the enrichment, or
a failed enrichment) the list is empty, exit 0, and `warnings` (stderr in plain output) names the reason and the fix,
`sparrow detect`; stale rows are never offered.

`finding show` adds `facts` for a finding detection stored facts for (the stored `finding_facts`: `window_start`,
`actor_ips` with `user_signin_days_before`, `other_signals`, and `targets` for forwarding findings; a null count means
it cannot be compared, shown as "unknown" in plain output, never 0). Detection decides which findings get facts (rules
whose `stage:` includes persistence, consent or mfa_change), so stored facts are shown whatever `--rules` the reader
loads. When the facts are not current (detection has not run since this version, the last enrichment failed, or it is
from an older run), a finding whose rule is in those stages per the loaded rules, or whose rule is not loaded at all
(noted "(rule not in the loaded rule set)"), gets `facts_unavailable` with the reason instead; other findings have
neither key. Every evidence row also carries `context` (what the rule stored with the row; `null` when none). `pivot
user` adds an `addresses` section: the account's roll-up addresses. When the roll-up is not current the section is
empty and carries `unavailable` with the reason (plain output: `addresses unavailable: <reason>`); an empty section
without `unavailable` means the current roll-up has no address for that account.

Read commands open the case read-only. `query` runs exactly one SELECT (checked by DuckDB's own parser) on a
separate in-memory DuckDB that attaches the case read-only, with external access (files, network, environment) and
extension loading off and the configuration locked. It sees every table and view, including `case_meta` (the case
id, the audit chain's `audit_head`/`audit_verified` bookkeeping, `post_migration_pending` while an upgrade's
post-migration step has not completed, and the `credential_failure_codes` the last profile used); that is harmless, since they are not secret and
reading them changes nothing.

Agent text is stored as given. Plain (non-`--json`) output shows control characters and Unicode format characters
(bidi overrides, zero-width characters) as `\u{XXXX}`; values printed on one line escape newlines too, so text cannot
forge an output line.

With `--json`, errors are also printed to stdout as `{"error": "..."}`.

While an upgrade's post-migration step is pending (a failed rebuild, retried by the next write), every read
command prints `warning: case has a pending post-migration step; run `sparrow upgrade`` to stderr, and its `--json`
output (an error too) carries it in a top-level `warnings` array.

`audit verify` walks the whole SHA-256 chain: an edited, deleted, reordered or rewritten entry is reported at its
seq. Deleting the newest entries is detected against the head the last write recorded in `case_meta`, unless
`case_meta` was edited too; the head hash printed by `audit verify` (and by the exports) is the anchor to keep
outside the case. A break blocks every write until `audit verify --acknowledge` records it as an audit entry.
Indicators from a case made before the audit trail get one reviewable `legacy_decision` entry each on `upgrade`.

### Environment variables

| Variable | Used by | Meaning |
| --- | --- | --- |
| `SPARROW_DATA` | ingest, profile, detect, rules, finding show | Default for `--data DIR` (data files overriding the embedded ones) |
| `SPARROW_RULES` | ingest, profile, detect, rules, finding show | Default for `--rules DIR` (rule directories; several separated by the platform path separator) |
| `SPARROW_AGENT` | every write | Default for `--agent ID` (`unnamed` when unset) |
| `SPARROW_ANALYST` | every write | Default for `--analyst NAME` |
| `SPARROW_INGEST_CHECKPOINT` | ingest | DuckDB's `checkpoint_threshold` while the files load. Unset: the case's `memory_limit` / 8, at most 1 GB, never below DuckDB's own 16 MiB (a limit that cannot be read keeps 16 MiB). A size (`256MB`, `1GiB`, ...) sets it; `default` keeps DuckDB's own value. Anything else stops the ingest before a file is loaded (exit 1). The previous threshold is restored afterwards, and one `CHECKPOINT` runs at the end. A bigger threshold avoids repeated checkpoints inside the per-file commits (180 s → 104 s on a 1M-row tree) and costs memory: the WAL's changes stay in memory until the checkpoint |
| `SPARROW_INGEST_PROFILE` | ingest | `1`: print stage spans and per-file timings to stderr (off by default; the output on stdout is unchanged) |

## Agent workflow

The CLI is the AI agent's tool. An agent (any program that can run a command and read JSON) drives a case from
evidence to deliverables with `--json` on every command; nothing else is needed, and there is no server.

```bash
sparrow ingest /evidence --case case.duckdb --json          # ingest, profile and detect (exit 2: some file failed)
sparrow capabilities --case case.duckdb --json              # what the case can and cannot show
sparrow accounts --case case.duckdb --json                 # the accounts to look at first, with their addresses
sparrow finding list --case case.duckdb --json --severity high
sparrow finding show 1c8b18eff09c880c --case case.duckdb --json   # evidence rows (with context), facts, guidance, notes, history
sparrow pivot ip 203.0.113.2 --case case.duckdb --json     # everything about an IP, section by section
sparrow query "SELECT operation, count(*) FROM timeline GROUP BY 1" --case case.duckdb --json

export SPARROW_AGENT=claude SPARROW_ANALYST=example         # or --agent / --analyst on each write
sparrow finding set-status 1c8b18eff09c880c confirmed --reason "hides mail from the owner" --case case.duckdb
sparrow ioc add --type ip --value 203.0.113.2 --verdict malicious --note "AiTM relay" --case case.duckdb
sparrow timeline-entry propose --time 2026-08-21T09:47:00Z --title "Inbox rule created" --phase persistence \
        --evidence ual_events:02a13335-5a42-4ce8-9f05-5b5f0f489146 --case case.duckdb
sparrow timeline-entry verify 69d952e3c22b --case case.duckdb
sparrow note add finding:1c8b18eff09c880c --text "rule forwards to an outside address" --case case.duckdb

sparrow audit verify --case case.duckdb --json              # ok, entry count, head hash
sparrow export report --out report.md --case case.duckdb
sparrow export timeline --out timeline.csv --case case.duckdb
sparrow export workbook --out case.xlsx --case case.duckdb
```

With `--json`, a write prints its audit entry (`seq`, `action`, `object_id`, `before`, `after`, ...). A command that
creates an object also names its id: `timeline-entry propose` and `edit` add `entry_id` (`edit` of a verified entry
returns the successor's id, with the edited one in `supersedes`), `note add` adds `annotation_id`, and `ioc add`
prints `indicator_id` with the entry under `audit`.

Every command above is listed under [Use](#use) with its options. The same flow is exercised end to end, through
the binary, by `crates/sparrow-cli/tests/agent_workflow_e2e.rs`.

**Provenance.** Every write through the CLI is an agent decision. It is recorded on the object as `decided_by`
(`agent:<id>`), `decided_at`, `on_behalf_of` (`analyst:<name>`, the analyst who should review it; not an identity
claim) and `review_state = pending_review`, and in the audit trail with the object's state before and after. A new
agent decision on an object that was reviewed sets it back to `pending_review`. Decisions take effect at once:
a malicious or suspicious indicator is read by the rules, a finding's status shows in every listing. A rule that
fires again after an agent closed a finding widens its evidence but never reopens it or touches the decision.

**Review happens outside the CLI.** There is no review command. Either a future UI writes reviews back through the
core functions (`sparrow_core::case::review::review_accept` / `review_discard`, which take the audit `seq` of the
decision being reviewed and fail if the object changed since), or the analyst works on the exported files and writes
nothing back. Discarding a decision restores the fields it changed. The exports therefore label every decision: an
agent decision nobody has reviewed is "AI decision — not reviewed", and `export report --reviewed-only` keeps accepted
decisions only (pending items and agent notes are left out).

**The audit trail** is append-only and hash-chained (SHA-256 over the previous hash and the canonical JSON of the
entry). It holds one entry per state-changing write and per review; a write that changes nothing (removing an
inactive indicator) adds none, and detection and exports add none. `audit verify` reports the first bad `seq`
(exit 3); a break blocks writes until `audit verify --acknowledge` records it.

Limits you should know about:

- **The CLI cannot prove who ran a command.** Anyone who can run `sparrow` can claim any `--agent` and `--analyst`.
  The trail records what the command line said, not who typed it, and review is out-of-band by design. Treat the
  analyst name as "please review this", not as an authentication.
- **Truncation is detected only against `case_meta`.** Deleting the newest audit entries is caught because each
  append records the expected head (seq and hash) in `case_meta`. Someone who can edit the case file can rewrite
  `case_meta` too, or put back an older copy of the file. The head hash printed by `audit verify` and written into
  every export is the anchor: keep it outside the case (in the ticket, the report, a message) and compare.
- **CSV formula neutralisation changes some cells.** In the Timeline Explorer CSV a text cell that starts with `=`
  `+` `-` `@`, a tab or a carriage return gets a leading `'`, so a spreadsheet will not run it. The Timestamp and
  FindingIds columns are left alone. The workbook writes text as strings, never as formulas; numbers, booleans and dates are typed cells.
- **Times in exports are UTC**, whatever the machine or the DuckDB session time zone: `yyyy-MM-dd HH:mm:ss` in the
  CSV, ` UTC` in the report, UTC date cells in the workbook.

## Exports

`sparrow export` writes the deliverables from a case, read-only (no audit row): the Markdown report, the Timeline
Explorer CSV and the XLSX workbook. Every export carries the Sparrow version, the rule-pack hash, the generation
time, the audit-chain status, the head hash and the decision counts, and labels every decision: an agent decision
nobody has reviewed is "AI decision — not reviewed".

The CSV is UTF-8 with a BOM; its cells keep the stored text, with one exception: cells beginning with `=` `+` `-`
`@` (or a tab or carriage return) are prefixed with `'` to stop spreadsheet formula execution, because evidence
text (rule names, subjects, user agents, display names) can be attacker-controlled. The Timestamp and id columns
are left as they are. The workbook writes text as strings, never as formulas; numbers, booleans and dates are typed cells.

The report has an "Accounts" section after the executive-summary placeholder: one row per tenant and account, worst
severity first, with its stages, first suspicious time, how many of its findings have an accepted review
("Reviewed") and its top addresses with their reasons. A `--reviewed-only` report has no table there, only the line
"Account roll-up omitted: it is computed from all findings, including ones not yet reviewed." Under each confirmed
finding that has stored facts there is a "Facts" list (fixed sentences: the addresses the user signed in from on
earlier days within the capture, the account's other findings, the targets of a forwarding with their scope and
earlier messages). They are facts computed by detection, never a verdict; a count that cannot be compared reads
"unknown", and when the enrichment is not current the section and each such finding say "unavailable" with the
reason (run `sparrow detect`). The workbook has an "Accounts" sheet (with a "Reviewed" column) and a `Facts` column
(compact JSON) on the Findings sheet. `export report` and `export workbook` take `--data` and `--rules` (default
`$SPARROW_DATA` / `$SPARROW_RULES`) like `finding show`: the rules are read only when the enrichment is not
current, to tell which findings should have facts; stored current facts are shown whatever rules are on disk, and
rules that cannot be loaded never abort an export (the finding says so).

The Markdown report escapes all evidence and agent text as Markdown and HTML (so a rule named `x <!--` cannot hide
the rest of the report, and `[text](url)`, `![](url)` and `[^3]` stay plain text). Agent notes carry no review
state: they are labelled "agent note — not reviewed", and `--reviewed-only` leaves them out. A date Excel cannot
hold is written to the workbook as ISO text. `--out` is written through a temp file and renamed when the export
succeeds, and is refused when it is the case file, its `.wal`, or inside the test cache root (`$CARGO_TARGET_TMPDIR/sparrow-cache`, only when that variable is set) (exit 5).

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

See [`crates/sparrow-synth/README.md`](../crates/sparrow-synth/README.md) for the flags, the scenario and manifest
formats, the storyline kinds, the licence and audit profiles, coverage (`rules/coverage.yaml`) and conformance.
