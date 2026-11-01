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
  sign-in CSV or XLSX, Entra ID audit log CSV or JSON, Exchange admin center message trace. A folder holding only
  such files is ingested as a `portal_export` collection. For the Entra audit log (Entra admin center > Monitoring >
  Audit logs > Download) ask for the **JSON**: it keeps every field and the audit id. The CSV has no audit id and
  stops at 3 targets x 5 modified properties and 6 additional details, so its rows load as `partial`.

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
center summary reports), `message_trace_events` (the Exchange admin center detail, "extended", report: one row per
delivery event, so forwarding, drops and external sends are visible; also collapsed into `message_trace`, one row per
message and recipient), `mailbox_audit_legacy` (Hawk 3 `Exchange_Mailbox_Audit`) and `admin_audit_events`; Azure
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
| Message trace | Exchange admin center message trace report (CSV), summary | any folder; recognised by its header | `message_trace` |
| Message trace events | Exchange admin center message trace report (CSV), extended (`MTDetail_*.csv`, UTF-16, one row per delivery event) | any folder; recognised by its header | `message_trace_events`, and `message_trace` (one row per message and recipient) |
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
- `sparrow summary`: tenant, licences, coverage, top actors and evidence gaps. It also points to the first triage
  command: `--json` adds `next` (an array of `{"command", "about"}` objects; the first `command` is the runnable
  `sparrow accounts --case '<case>' --json`, with the case path shell-quoted: single quotes with `'\''` for a quote, or an
  ANSI-C `$'...'` word when the path has control characters; `about` says what it shows) and `top_accounts` (up to 3 rows of the roll-up in `sparrow accounts` order: `upn`, `tenant_key`,
  `worst_severity`, `stages`, `first_suspicious`, `addresses_total`), or `top_accounts_unavailable` with the same
  reason `sparrow accounts` gives when the roll-up is not current; plain output ends with an `Accounts` block (tenant and UPN of each row, escaped like `sparrow accounts`)
  and `Next: <command>` with the `about` text on the next line. `sparrow capabilities --json` adds the same `next` (no account data: it stays about evidence).

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

### Finding facts and the account roll-up

After every detection run (in the same writer session, after the findings are merged) detection rebuilds two derived
tables from scratch, in one transaction: `finding_facts` and `account_rollup`. They hold computed, checkable FACTS,
never a verdict, label or score. If the rebuild fails, detection still succeeds, the previous rows stay,
`case_meta.enrichment_error` holds the message, and readers say "facts unavailable"; a case detected before this
feature has no `case_meta.enrichment_run_id` and reads the same (fix: `sparrow detect`). Review decisions never change
them. Readers: `sparrow accounts`, `finding show` (`facts`), `pivot user` (`addresses`). Every "before" fact means before, **within the capture**: the capture starts at
`window_start`, the tenant's first sign-in of any kind (the same start `cloud_services` uses).

**Rule `stage:`.** A rule may declare `stage:` (one name or a list) from `suspicious_sign_in`, `credential_takeover`,
`persistence`, `mail_access`, `sending`, `consent`, `mfa_change`. It feeds the roll-up and decides which findings get
facts (`persistence`, `consent`, `mfa_change`); it is not part of the rule's hash and changes no detection result.
`sparrow rules lint` lists rules without a stage as warnings.

**`finding_facts`** (one row per finding of those rules): `finding_id`, `facts_version` (1), `facts` (JSON),
`computed_run_id`. The `facts` object:

| Key | Meaning |
| --- | --- |
| `window_start` | The tenant's first sign-in of any kind (null when it has none). |
| `actor_ips[]` | One entry per distinct address on the finding's evidence rows (the `timeline` ip of each row; state rows such as `inbox_rules` and `mailboxes` have none), by first evidence time: `ip`, `asn`, `asn_org`, `is_hosting` (`ip_intel`), `spray_source` (in the tenant's `spray_sources`), `user_signin_days_before`, `user_first_signin`. |
| `user_signin_days_before` | Distinct UTC days on which the finding's actor had a SUCCESSFUL sign-in (`error_code` 0 or NULL) from that address strictly before the earliest evidence event from it; `user_first_signin` is the first such sign-in (null when none). A sprayer's failures never make an address look familiar. Null means it cannot be compared (shown "unknown", never 0). |
| `other_signals` | `{total, items}`: the actor's other findings of the tenant (case-insensitive, never this one), at most 5 in `finding list` order, each `{rule_id, severity, first_seen}`; `total` 0 when the finding has no actor. |
| `targets[]` | Only when the evidence carries a forwarding or redirect address: every address in `inbox_rules` `forward_to`, `forward_as_attachment_to`, `redirect_to`; `mailboxes` `forwarding_smtp_address`, `forwarding_address`; `transport_rules` `redirect_to`, `blind_copy_to`, `copy_to`, `add_to_recipients`; or the UAL and admin-audit cmdlet parameters (`ForwardingSmtpAddress`, `ForwardingAddress`, `ForwardTo`, `ForwardAsAttachmentTo`, `RedirectTo`, `RedirectMessageTo`, `BlindCopyTo`, `CopyTo`, `AddToRecipients`). Deduplicated, lower-case, `smtp:` prefix and display name removed, trailing dots stripped, sorted; a value with no address is not a target. Each `{address, domain, scope, prior_messages}`: `scope` is `internal` when the address is the actor's own (UPN or mailbox primary address) or its domain, or a parent domain, is in `tenant_domains` (analyst overrides included), else `external`; `prior_messages` counts the tenant's `message_trace` rows between the actor and the address, either direction, received strictly before the earliest evidence event carrying it; null = unknown / not comparable (the tenant has no message trace at all, OR the finding has no actor, OR that evidence has no event time), never 0. |

**`account_rollup`** (one row per tenant and lower-case account with at least one finding; findings without an actor
make no row and their addresses are attributed to nobody): `tenant_key`, `upn`, `worst_severity` (critical > high >
medium > low > info), `finding_count`, `by_severity` (JSON, only severities present), `stages` (JSON array in the fixed
order above: the union of the `stage:` of the rules of the account's findings, plus `credential_takeover` when an
SPW-ID-005 evidence row of the account has context `takeover = true`), `first_suspicious` (earliest `first_seen` among
the account's findings of severity medium or higher; null when none), `rules` (distinct rule ids, sorted),
`signins_first` / `signins_last` (the first and last sign-in of the account in the case, over every `signins` row of the
tenant and account, any result and type; null when the case holds none, and for rows built before schema 23 until the
next detection run), `addresses` (at most 20), `addresses_total`, `addresses_truncated`, `computed_run_id`. Each address
`{ip, reasons, tables, first_seen, last_seen, asn, asn_org, is_hosting, spray_source, in_user_signins}`; the reasons:

| Reason | The address... |
| --- | --- |
| `finding_evidence` | is on the evidence rows of one of the account's findings. |
| `acts_without_signin` | is one the account ACTS from and the account's sign-ins (any result) never carry, judged only against the account's sign-in window: the account must have sign-ins, and at least one of the address's acts must have a time from `signins_first` to `signins_last`, inclusive. An account whose sign-ins were never collected (sign-ins are often pulled only for the investigated users) has no window, so no address gets this reason for it; an act with no time, or outside the window, does not count. "Acts" is exactly: a `ual_events` record whose UserId is the account; a parent-less `mail_items_accessed` row (`record_id` null); a `mailbox_audit_legacy` row with `logon_type` Owner on the account's mailbox; a `message_trace` row the account SENT (`sender`, `from_ip`). A Microsoft-service address (`ip_intel.is_microsoft`) or a private one (`ip_intel.is_private`, or RFC 1918 / RFC 4193 / loopback / link-local by its text) NEVER gets this reason (service and message-trace origins are often Exchange's own addresses); it can still be listed for another reason. |
| `hosting` | has `ip_intel.is_hosting`. |
| `spray_source` | is in the tenant's `spray_sources`. |
| `risky_signin` | signed the account in with a sign-in or user risk of medium or high, or has a `risk_detections` row for the account and address. |

`hosting`, `spray_source` and `risky_signin` apply only to an address that appears for the account in one of the above
tables, a sign-in, a risk detection, a directory audit (initiator), an admin audit (caller) or an Azure activity (caller).
Addresses are ordered by their strongest reason (`finding_evidence`, then `acts_without_signin`, then the others), then
`first_seen`, then address; `in_user_signins` is true when the account's sign-ins carry it. Accounts are read worst
severity first, then more stages, then earlier `first_suspicious`, then UPN.

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
sparrow mark flag --row TABLE:KEY... --level suspicious|malicious|clear --case case.duckdb
                                                  # or --value KIND=V [--scope KIND=V] for a standing flag on a value
                                                  # (KIND ip|ip_prefix|account|asn|device|session; scope kinds
                                                  # account|ip|device|session); [--agent ID] [--analyst NAME]
sparrow mark tag --row TABLE:KEY... --tag NAME [--remove] --case case.duckdb   # an agent's new tag starts `ai:`
sparrow mark list --case case.duckdb             # [--pending] [--kind flag|tag] [--agent ID]: value flags (not
                                                  # removed), row flags and tags, with level or tag, scope, who
                                                  # decided and when, review state; read-only (`{"marks": [...]}`)
sparrow accounts --case case.duckdb              # [--tenant T --limit N]: the accounts with findings, worst first, with
                                                  # stages and the addresses worth a look (the roll-up detection builds)
sparrow coverage --case case.duckdb              # [--tenant T --user UPN... --rules DIR...]: per account, the rows and dates each
                                                  # source holds, the dates it does not cover, and what to request next
sparrow access --case case.duckdb                # [--account UPN] [--csv FILE | --markdown]: what the attacker reached
                                                  # through each account, from the accepted malicious flags
sparrow finding list --case case.duckdb           # [--status --severity MIN --rule ID... --user UPN --tenant
                                                  #  --rule-updated --review-state --limit N]; severity first,
                                                  #  then the most recent
sparrow finding show ID [ID...] --case case.duckdb  # evidence with source refs (first 50; --all), guidance, notes,
                                                  # decision, history; up to 50 ids at once
sparrow timeline --case case.duckdb               # [--user --ip --category --from --to --finding --limit 200]
sparrow events --case case.duckdb                 # the Events grid: [--user V|--ip V|--device V|--session V] [--where FIELD=TEXT]...
                                                  # [--search S --from T --to T --flag suspicious|malicious --offset N
                                                  #  --limit 200 --csv PATH]
sparrow entity --case case.duckdb --user|--ip|--device|--session V   # [--from T --to T]: tiles, every pivot, findings
sparrow timeline-entry list --case case.duckdb    # [--status --review-state]
sparrow pivot ip|user VALUE --case case.duckdb    # every section capped by --cap 50, truncation reported
sparrow query "SELECT ..." --case case.duckdb     # one read-only SELECT, --limit 1000
sparrow notebook list --case case.duckdb          # SQL notebooks: the built-in one, then the case's, with [placeholders]
sparrow notebook show|run NOTEBOOK QUERY --case case.duckdb   # a saved query's text, or run it (--limit 1000)
sparrow notebook add --notebook NAME --sql TEXT|--file F [--create] --case case.duckdb   # agent decision
sparrow notebook import --file F --case case.duckdb             # a notebook file as a new case notebook
sparrow notebook export NOTEBOOK --out F [--force] --case case.duckdb  # exit 5 when it holds case values
sparrow audit verify --case case.duckdb           # check the audit chain (exit 3 when broken;
                                                  # --acknowledge [--agent ID] records a break)
sparrow audit log --case case.duckdb              # the audit trail; --object TYPE:ID for one object
sparrow export report --format md [--out FILE] [--reviewed-only] --case case.duckdb
sparrow export timeline --format csv [--scope verified|all --from T --to T --user U --out FILE] --case case.duckdb
sparrow export workbook --format xlsx --out FILE --case case.duckdb
```

Add `--json` to any command for machine-readable output. More options work on every command: `--no-bridge`
(never send the command to the app, see [Agent bridge](#agent-bridge)), `--snapshot`, and `--timings`: per-phase
durations on stderr (`timing  <phase>  <seconds> s`) and `"timings": [{"phase", "ms"}]` in `--json`, for `access`
(`accounts`, `attribution`, `items`, `coverage`), `investigate` (`open`, `investigate`), `entity` (`open`, `summary`,
`pivots`, `findings`), `detect`
(`open`, `detect`) and `export` (`open`, `write`); other commands record none.

**`--snapshot`** (or `SPARROW_SNAPSHOT=1`) lets a read-only command read a case another program holds (the review
app, when its agent bridge cannot serve: it is importing, an older build, or not answering). Without it such a read
exits 4 and the message names the option. With it the CLI copies the case (its WAL first, then the database), checks
that neither file changed during the copy (else it copies again, three times at most, then exits 4), opens the copy
read-only, runs the command and deletes the copy. The copy goes in a hidden `.sparrow-snapshot-<pid>-<random>/` beside
the case (the same volume), else in the system temp directory, and is refused when it would leave less than 10% of that
volume free. A run stopped before it could delete its copy (Ctrl-C, a kill) leaves it behind. The next `--snapshot` run
of the same case removes such a directory only when its marker file (`.sparrow-snapshot.json`, written first) names
this case and a process that has ended, you own it, and it holds nothing but the copy (and DuckDB's spill folder);
it says so on stderr (`note: removed <dir>, ...`). A directory beside the case that may be a leftover but is not proven one is never deleted:
a `warning: <dir> may be a snapshot copy left by an interrupted run; not removed (<why>)` line asks you to check it.
(On Windows leftovers are neither removed nor reported: delete `.sparrow-snapshot-*` directories by hand.) Every
snapshot read says so: a stderr line `note: read a snapshot of <case> taken <time> ...` and, with `--json`,
`"snapshot": {"case": …, "taken_at": …}`. Writes never use a copy: with the case held they still exit 4. A free
case is read directly, as without the option.

Exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | success |
| 1 | any other error, including a refused `query` (not a single SELECT, or one that tries to write or reach outside the case) and a bad option |
| 2 | `ingest` completed but a file failed, a record could not be parsed, or a file's record counts did not reconcile; `verify`: a record no longer matches its source; `finding show` with several ids: one or more ids were not found (the others are shown, the unknown ones listed); `synth coverage` / `conformance`: a gap |
| 3 | the audit chain is broken (`audit verify`, and any write refused because of it) |
| 4 | the case is open by another writer (a write, and also a read or `audit verify` while a writer holds the case: `--snapshot` reads a copy instead); through the app's agent bridge: refused (a heavy command, another version), busy, or stopped by a close |
| 5 | an invalid agent decision (a bad status, verdict, phase or time, a missing reason, an unknown object, an evidence reference not in the case, text over its cap: 16 KiB for notes, narratives, reasons and comments, 500 characters for titles) or an `export --out` that would overwrite the case; nothing was written |
| 6 | `ingest` completed and the only records not loaded are ones the collector lost: it wrote placeholder or error rows instead of data (their `parse_errors` start `collector lost the record: `). Any file, parse or reconciliation problem makes it 2 instead. The plain line of such a file says `N records rejected (M lost by the collector)`, or `M records lost by the collector` when all are; `--json` has `records_error` and `records_collector_lost` per file |

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
`worst_severity`, `finding_count`, `by_severity`, `stages`, `first_suspicious`, `rules`, `signins_first` and
`signins_last` (null when the case holds no sign-ins of the account), `addresses` (at most 20, each
`{ip, reasons, tables, first_seen, last_seen, asn, asn_org, is_hosting, spray_source, in_user_signins}`),
`addresses_total` and `addresses_truncated`; `total` counts the accounts before `--limit`. Plain output is one block
per account (a header with its stages and first suspicious time and its sign-in coverage, `sign-ins <first> to <last>` or
`no sign-ins collected`; up to 5 addresses with their reasons, `(never a sign-in of this account)` noted only for an
account with sign-ins; then `+N more addresses`) and ends `K of N accounts`. When the
enrichment is not current (a case detected before the roll-up existed, a detection run newer than the enrichment, or
a failed enrichment) the list is empty, exit 0, and `warnings` (stderr in plain output) names the reason and the fix,
`sparrow detect`; stale rows are never offered.

`sparrow coverage --case C [--tenant T] [--user UPN]... [--rules DIR]... [--json]` says, per account, which evidence
covers it and over what dates, so "no event" is not read as "did not happen", and what to request next. Read-only; it
adds no audit entry. Accounts are those in the roll-up (accounts with findings), or only the `--user`s given (lower-cased,
repeatable; a user the case has nothing on is still listed, every source absent), once per tenant. Sources per account:
`ual` (`ual_events.user_upn`), `signins_interactive` and `signins_noninteractive` (`signins.user_upn` by `event_type`;
service principal and managed identity sign-ins count in neither), `mail_items_accessed` (the `MailItemsAccessed`
operation in `ual_events` plus the parent-less `mail_items_accessed` rows, as in `evidence_availability`), `message_trace`
(`sender` or `recipient`, a message once), `entra_audit` (`directory_audits.initiated_by_upn` or a
`targets[].userPrincipalName`, key matched case-insensitively) and `mailbox_audit` (`mailbox_audit_legacy.mailbox_upn`).
Per source: `rows`, `first` and `last` (UTC), `days` (distinct UTC dates with a row) and `sampled` (any of the rows was
sighted in a file whose warnings name a known export cap, the rule `evidence_availability` uses for `truncated`).
The reference `window` (UTC dates) runs from the earliest `first_seen` of the account's findings (else its earliest
row in any source; else, for a user with nothing, the tenant's earliest event) minus 30 days (nothing is subtracted
from the tenant's earliest event) to the date of the tenant's latest event in any source; it is null when the tenant has
no events. `gaps` per source are inclusive date ranges with a `reason`: `absent` (no rows: the whole window), `before`
(window start to the day before the first row), `after` (the day after the last row to the window end) and `sampled`
(first to last row of a capped export: the absence of an event there proves nothing). Quiet days between the first and
last row are not gaps. `--json` is `{"accounts":[{"tenant_key","upn","window":{"start","end"},"sources":[{"source",
"title","rows","first","last","days","sampled","gaps":[{"from","to","reason"}]}]}],"requests":[{"tenant_key","user",
"source","title","from","to","reasons","console","hawk","invictus"}],"warnings":[]}`. `requests` has one entry per
account and source with gaps, over the earliest `from` to the latest `to` of its gaps; `console`, `hawk` and `invictus`
are the portal path, the Hawk command and the Microsoft-Extractor-Suite cmdlet with the user and dates filled in (Extractor end dates are the day after `to`, since it reads them as midnight; hints for commands that ignore dates say so), or
`null` when that collector has no command for the source (never a guess). They come from `rules/lists/collection_hints.yaml`
(embedded; `--rules DIR` with `lists/collection_hints.yaml` replaces entries by `source`). Plain output is, per account,
a header `upn  tenant  window <start>..<end>`, one line per source (`ual  rows 1,234  2026-06-01..2026-10-25  48 days
SAMPLED`, or `ual  absent`) and its `Request:` lines. The Markdown report has the same facts as the section "Evidence
coverage and what to request". With no roll-up current, `warnings` says to run `sparrow detect`.

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
| `SPARROW_INGEST_CHECKPOINT` | ingest | DuckDB's `checkpoint_threshold` while the files load. Unset: the case's `memory_limit` / 8 (500 MB under the default 4 GB cap, see `SPARROW_MEMORY_LIMIT`), at most 1 GB, never below DuckDB's own 16 MiB (a limit that cannot be read keeps 16 MiB). A size (`256MB`, `1GiB`, ...) sets it; `default` keeps DuckDB's own value. Anything else stops the ingest before a file is loaded (exit 1). The previous threshold is restored afterwards, and one `CHECKPOINT` runs at the end. A bigger threshold avoids repeated checkpoints inside the per-file commits (180 s → 104 s on a 1M-row tree) and costs memory: the WAL's changes stay in memory until the checkpoint |
| `SPARROW_MEMORY_LIMIT` | every command that opens a case, and the app | DuckDB's `memory_limit` on every instance Sparrow opens on a case (the writer, read-only opens, the detection rule instance, the locked `query` instance). Unset: 4 GB, or DuckDB's own 80% of RAM when that is smaller. A size (`2GB`, `8GiB`, ...) sets it; `default` keeps DuckDB's own. Anything else fails the open (exit 1). Above the limit DuckDB spills to disk (beside the case file, or a private directory under the system temp directory for the in-memory rule and query instances, removed when they close). Uncapped, DuckDB's cache grows toward 80% of RAM: `detect` on a 3.47M-event case peaked at 17 GB, 6.2 GB capped; the ingest's checkpoint threshold follows the limit (`memory_limit` / 8: 500 MB) |
| `SPARROW_BRIDGE` | every command that opens a case | `off`: never use the app's [agent bridge](#agent-bridge) (as `--no-bridge`) |
| `SPARROW_BRIDGE_DIR` | the CLI and the app (macOS, Linux) | Directory of the bridge's discovery file instead of `Sparrow/` in the per-user local data directory |
| `SPARROW_SNAPSHOT` | read-only commands | `1`: as `--snapshot` |
| `SPARROW_BRIDGE_TIMEOUT` | reads through the bridge | Seconds a read may run in the app before it is stopped (default 120, at most 86400) |
| `SPARROW_INGEST_PROFILE` | ingest | `1`: print stage spans and per-file timings to stderr (off by default; the output on stdout is unchanged) |

## Events, entities and marks

`events` and `entity` read the `events` table (one row per event record of every event table, rebuilt with `ip_intel`
by `profile`); they open the case read-only. `mark` writes. Times are ISO 8601 UTC (`2026-09-01T10:00:00Z`).

In the app, the Events window's From and To boxes are UTC and inclusive. Type ISO 8601 (`2026-10-23`,
`2026-10-23T14:30`, `…:36Z`) or US month/day/year (`10/23/2026`, `10/23/2026 9:05`), or pick a date and an optional
24-hour `HH:MM` with the calendar beside each box. A date alone covers the whole day; a To with minutes and no seconds covers
its whole minute (`14:30` runs to `14:30:59.999999Z`). Applying the calendar unchanged leaves the box as it was, so a
range with seconds (a pivot's, the histogram's) is not rounded.

**`sparrow events`** lists the events that match all the options: an entity (`--user` for the actor or mailbox owner,
`--ip`, `--device` for a device id or directory object id (not a name), or `--session`; at most one), `--where FIELD=TEXT`
(repeatable; FIELD `source`, `operation`, `account`, `ip`, `country`, `asn`, `device`, `session`, `tag` or `rule`),
`--search`,
`--from`/`--to` (RFC 3339, inclusive) and `--flag`. A device name goes in `--where device=NAME`: that field matches the
device id, the object id or the name. `rule` matches the rule id of an open finding (not closed as `false_positive` or
`benign`) that has the row as evidence (case-insensitive: `--where rule=spw-id-004`). TEXT is Harrier's list syntax: comma separates values (any of),
`!value` excludes, `*` is a case-insensitive wildcard, a list of only excludes means everything except those. A value
in double quotes is literal: commas, `*`, a leading `!` and outer spaces are part of it, and `""` inside it is one
quote (`--where 'operation="a,b"'`, `--where 'operation=!"*"'`); a quote anywhere but at the start of a value is an
ordinary character. A lone `!`, only commas, a quote that is not closed or text after a closing quote is refused
(exit 1). Rows come newest first; `--offset` and `--limit` (default 200) page them.
Plain output is a header line, then one line per row, columns two spaces apart with `-` for none:

```
total 3  showing 3 from offset 0
2026-09-01T10:10:00Z  signin_interactive  UserLoggedIn  jdoe@contoso.example  198.51.100.7  JDOE-LAPTOP  7a7a…0b0b  -  -  SPW-ID-004
```

The columns are time, source, operation, account (the actor, else the owner), IP, device (name, else id), Entra session
(first and last four characters), flag (`suspicious`, `malicious`, with ` (ai)` while an agent's flag awaits the
analyst), tags (comma separated, ` (ai)` likewise) and rules (the rule ids of the open findings with the row as
evidence, comma separated: the rule labels the app's Rules column shows). The header says `total N (capped)` when the count stopped at its
cap. `--json` prints `{"rows": [...], "offset", "total", "total_capped"}`; a row has `source_table`, `record_key`, `source`,
`event_time`, `time_tz_assumed`, `tenant_key`, `workload`, `category`, `operation`, `result`, `actor_upn`, `owner_upn`,
`target`, `ip`, `ip_prefix`, `ip_country`, `asn`, `asn_org`, `ip_kind`, `device_id`, `device_name`, `device_object_id`,
`entra_session_id`, `user_agent`, `app_id`, `summary`, `finding_count`, `tags` (`[{"name", "ai"}]`), `rules` (rule ids),
`flag`, `flag_ai`,
`latest_note` and `note_count` (every field of the row).
`--csv PATH` writes every matching row (not a page; a `rules` column after `tags`, ids separated by `|`; UTF-8 with a BOM, formula-looking text prefixed with `'`) and
prints `wrote N rows to PATH` (`--json`: `{"csv", "rows"}`).

**`sparrow entity`** takes exactly one of `--user`, `--ip`, `--device`, `--session` and an optional `--from`/`--to`.
It prints the tiles (events, first and last seen, distinct counts, open findings by severity, roles matched, the
IP's `ip_intel` or the device's details), then each pivot table the kind has, then the open findings that cite the
entity's events. A pivot shows at most 500 rows; the heading says `showing N of TOTAL` when it is cut. `--json`
prints `{"summary": {...}, "pivots": {"ips": {"rows": [...], "total": N}, ...}, "findings": [...]}`. An account has
the pivots `devices`, `ips`, `sessions`; an IP `accounts`, `devices`, `sessions`; a device `accounts`, `device_changes`,
`ips`, `sessions`; a session `accounts`, `devices`, `ips`. The spelling of the value does not matter (case, IPv6
form): `Jdoe@Contoso.example` and `jdoe@contoso.example` are one entity.

**`sparrow mark flag`** flags rows (`--row TABLE:KEY`, repeatable) or every event with a value (`--value KIND=V`,
KIND `ip`, `ip_prefix`, `account`, `asn`, `device` or `session`; a standing flag that also covers events ingested
later; `--scope KIND=V` with KIND `account`, `ip`, `device` or `session` limits it to that entity's events) to
`--level suspicious`, `malicious` or `clear`. A malicious `ip` or `account` flag also adds an indicator. **`sparrow
mark tag`** adds a tag to rows, or with `--remove` takes it off. Tag names are stored trimmed and lower-cased. Each
call is one transaction and writes one audit entry (not one per row). Like every CLI write these are agent decisions
(`--agent`/`--analyst`, `$SPARROW_AGENT`/`$SPARROW_ANALYST`): pending review, visible at once, confirmed or discarded by
the analyst in the app. An agent may flag or tag at most 1,000 rows per call, may create only tags starting `ai:`
(or use a tag already in use), and may clear or remove only its own pending marks. Plain output is the object id,
what was done and the provenance (`... flag malicious on 2 row(s) (decided by agent:triage for analyst:carlos,
pending review)`); `--json` prints the audit entry. Evidence tables are never written.

Exit codes are those of the other writes: 4 while another writer holds the case (nothing is written), 5 for a row
that is not in the case, a malformed `TABLE:KEY`, or a tag name an agent may not create, 1 for a bad option, level, kind,
a `--where` the grammar refuses, or `--csv` together with `--offset` or `--limit`.

## Agent workflow

The CLI is the AI agent's tool. An agent (any program that can run a command and read JSON) drives a case from
evidence to deliverables with `--json` on every command; nothing else is needed. When the analyst has the case open in
the review app, the same commands run through the app ([Agent bridge](#agent-bridge)).

```bash
sparrow ingest /evidence --case case.duckdb --json          # ingest, profile and detect (exit 2: some file failed; 6: only collector-lost records)
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
decisions only (pending items and agent notes are left out). The review app (Phase 8) also writes analyst
decisions (`analyst:<name>`), reviewed when made; an analyst cannot write over a pending agent decision until it is
accepted or discarded.

**Sharing work between analysts.** The review app exports an analyst's reviewed work as a share bundle (a JSON
file; send its SHA-256 separately so the receiver can compare it): the accepted findings, indicators and verified or
rejected timeline entries, and the analyst's own notes, with the case's evidence identity (the SHA-256 of every
parsed source file and the rule set of the last detection run). A bundle imports only into a case built from the
same evidence; a different rule set is a warning. Import stores each item as a proposal and changes nothing else:
an item is new, agrees with this case, conflicts with it, or is missing (its finding or evidence does not exist
here). Accepting a proposal applies it as your own analyst decision, with the source analyst and bundle in the audit
reason, and is refused if the object changed since the import; discarding one is audited too. Importing the same
bundle again changes nothing, and a newer bundle from the same analyst supersedes that analyst's open proposals for
the same items. A bundle says what the other analyst concluded, not how; their trail stays in their case.

**The audit trail** is append-only and hash-chained (SHA-256 over the previous hash and the canonical JSON of the
entry). It holds one entry per state-changing write and per review; a write that changes nothing (removing an
inactive indicator) adds none, and detection and exports add none. `audit verify` reports the first bad `seq`
(exit 3); a break blocks writes until `audit verify --acknowledge` records it.

### Agent bridge

While a case is open in the review app, the app serves it to `sparrow` commands on the same computer: an agent works
on the case the analyst is looking at, without copying it and without the "case is open by another writer" error
(exit 4). Nothing changes in how commands are typed: before opening a case, the CLI reads the app's discovery file
and, when the app is alive and has that same case open, sends the whole command to the app and prints what comes back
(output and exit code identical to a direct run). Otherwise it opens the file as before. `--no-bridge` (or
`SPARROW_BRIDGE=off`) always opens the file directly.

- **Reads** (`summary`, `accounts`, `events`, `entity`, `access`, `query`, exports, ...) run on a second connection
  to the app's database, so the analyst's screen stays usable; a read stops at its time limit
  (`SPARROW_BRIDGE_TIMEOUT` seconds, default 120, at most a day) with exit 1.
- **Writes** (`mark`, `note`, `finding set-status|assign|ack-rule-update`, `ioc`, `timeline-entry`,
  `notebook add|import`)
  wait for the app's own case lock (at most 30 s: "the app is busy", exit 4), so they queue with the analyst's
  actions. They stay agent decisions (`--agent`, pending review), always on behalf of the app's analyst: a different
  `--analyst` or `SPARROW_ANALYST` is replaced, with a note on stderr, and with no analyst name set in the app a
  write is refused (exit 5). The app refreshes the screen it shows (keeping filters, range and selection) and the
  header shows an Agent chip with the last request.
- **Refused through the bridge** (exit 4, "run it from the app, or with the case closed in the app"): `ingest`,
  `profile`, `detect`, `upgrade`, `synth` and `audit verify --acknowledge`, which hold the case for minutes.
  `tenant domains add|remove` too (exit 4): it is signed as an analyst, not as an agent, so it is the analyst's to make.
- Requests run one at a time. Closing or switching the case, or starting an import, stops the running request at
  once: the CLI gets exit 4, "the analyst closed the case (or started an import) while this ran; nothing was
  written".
- A CLI and an app of different versions refuse ("update the CLI or the app", exit 4).

How it is reached: the app listens on `127.0.0.1` on a port the OS picks, only while a case is open, and writes
`bridge.json` (port, a random per-session token, the case, the app's process id, version) to `Sparrow/` in the
per-user local data directory: `~/Library/Application Support/Sparrow` on macOS, `$XDG_DATA_HOME/Sparrow` or
`~/.local/share/Sparrow` on Linux, `%LOCALAPPDATA%\Sparrow` on Windows (`SPARROW_BRIDGE_DIR` overrides it on macOS
and Linux). The file is readable by your account only (0600), and every request must start with its token, so only
your own programs can use the bridge; a request with a wrong token gets no answer. The file is deleted when the case
closes, when the app quits and when the bridge itself fails; one left by an app that crashed (its process is gone) is
ignored. When the file names a process that is running but nothing answers on its port (the bridge is gone, or the pid
was reused), the CLI notes "refused the connection" on stderr and runs the command itself: a free case is read
directly, and a case the app holds exits 4 as without the bridge, naming `--snapshot`.

An agent in a sandbox (Claude Code's on macOS and Linux) needs two allowances: network access to `localhost` /
`127.0.0.1` (any port), and read access to the discovery directory above. Without the first the CLI says it "may not
connect to its agent bridge" (or notes the bridge "refused the connection" and opens the case directly); without
the second it notes that it "cannot read" the discovery file and opens the case
directly (exit 4 while the app holds it). Either way, `--snapshot` reads a copy instead (reads only).

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

## Access report

`sparrow access --case C [--account UPN] [--include-pending] [--ip IP] [--prefix CIDR] [--session ID] [--device ID]
[--brief | --category CAT [--limit N] [--offset N]] [--csv FILE | --markdown] [--json]` answers "what did the attacker get?" per
compromised account: mail read and sent, attachments, SharePoint/OneDrive files, Teams, Copilot and other apps.
Read-only; no audit entry. `--csv` is refused (exit 5) when it names the case or its `.wal`, and is written through a
temp file; `--json` cannot be combined with `--csv` or `--markdown`. In the app, Access opens in its own tab (scope chips,
the seven tiles, the coverage line and a table per category, with "Export CSV" for what the tab shows): from an account
tab's one-line summary ("Open access"); from a device or IP tab as a what-if ("Access (what-if)": what that value alone
would have reached if it were the attacker, ignoring the case's other flags, `--ip`/`--device` with the accepted flags
left out); and from the Events window for the whole case ("Access (all malicious)", whatever Events is filtered to). A
tab that spans accounts shows one list with an Account column and an Account filter; its CSV is the whole tab. The
export menu has "Access CSV (all accounts)" and "Access summary (Markdown)", and the account list badges accounts the
report lists as "Malicious".

- **Scope.** Only accepted (or analyst-made), not removed, malicious flags count; pending agent flags are counted
  (`pending_flags`) and attribute nothing. A record is attributed `session` (a flagged Entra session on the record or
  its UAL `SessionId`, or a UAL record sharing an Exchange `SessionId` with a directly attributed record of the same
  account when it has no Entra session and no IP of its own or that record's IP: Exchange sessions can last weeks, so
  a record from another, unflagged IP in the session is the real user's and stays out; propagated records never open
  a time window), `row` (the record itself flagged), `device`, or `ip` (a flagged IP or prefix, or an ASN flagged for the
  account; a case-wide ASN flag attributes nothing). A malicious `account` flag only puts the account on the report.
  An account scope on a flag matches the record's actor, never its mailbox owner. Items are filed under the actor.
- **Preview** (agents asking "what would this reach?" before the analyst reviews). `--include-pending` counts pending
  (not removed, not discarded) malicious flags too; `--ip`, `--prefix`, `--session` and `--device` (repeatable) add
  ad-hoc values, as if flagged malicious and accepted, case-wide (`--account` still limits the report; a value that is
  not an address, network or id of its kind is refused, exit 1). Ad-hoc values are bound parameters, never SQL text.
  Every item and scope value then carries `basis` (`accepted`, `pending` or `adhoc`; the strongest wins when several
  match; a message seen several times is listed as its accepted sighting when it has one, so a preview's accepted
  items are exactly the reviewed report's), and when any is not `accepted` the report is a preview: `"preview": true` in JSON, a first line `PREVIEW:
  includes pending or ad-hoc scope; not the reviewed report` in the text, the CSV message and the Markdown, scope lines
  prefixed `PENDING` / `AD-HOC`, and the CSV's last column `basis`. Without these options (and in the app's export
  menu) the report is the reviewed one.
- **By time.** A record of the account with no IP and no Entra session (Teams Graph reads, most Copilot records) is
  attributed `time` when it falls in a window of the account's malicious activity: per flagged value, bursts of its
  sightings split at gaps over an hour, each from the first sighting to the last plus an hour. A record with an
  unflagged IP or session never is. Time never adds an account. Tiles count `direct · by time` separately.
- **Categories.** `mail_read` (MailItemsAccessed Bind items, one per message and account, direct winning, subject,
  sender, recipients and sent time from the message trace; Sync rows are `synced` folder items), `mail_sent` (Send,
  SendAs, SendOnBehalf; UAL and legacy mailbox audit), `attachment` (AttachmentAccess: Graph only), `file` (a
  `file_events` or `sharing_events` child; sharing targets in the note), `teams` (workload MicrosoftTeams),
  `copilot` (one item per `CopilotEventData.AccessedResources` entry, or one `prompt`), `other` (everything else but
  sign-ins and mail flow). Someone else's data reached through the account (a delegated or shared mailbox, send as)
  stays under the account, with `owner` and a `note` ("in mailbox ...", "sent as ...").
- **Reads without a message id** (a Bind item or legacy MessageBind that names none) are `read (no message id)`
  items, counted apart from the messages (the tile qualifier says how many).
- **Coverage.** Each tile carries its source's `evidence_availability` status for the account's tenant
  (`mail_items_accessed` or `mailbox_audit_legacy` for mail read, `mail_send` for mail sent, `ual` otherwise; `none`
  when the case has no row). A zero is "none seen" only when the source was collected, or partial and the capture holds
  the category's operations for that account; otherwise the tile gives the status. Mail read is partial when
  MailItemsAccessed was throttled for the account (the per-message list is incomplete), and mail read or sent are
  partial when the account's mailbox (`mailboxes`) has an audit bypass or does not audit the action for its owner. Every account lists the gaps
  Microsoft never logs (Teams app reads, Outlook-synced mail, attachments opened in Outlook/OWA, Exchange searches
  without Audit Premium).
- **Compact output** (for agents). `--brief`: per account the tiles and the scope values with only their windows
  `count`, `first` and `last` time; no items. `--category CAT` (`mail_read`, `mail_sent`, `attachment`, `file`,
  `teams`, `copilot`, `other`): per account `{account, category, total, items}`, the items of that category only, at
  most `--limit` (default 100) after `--offset` (an offset past the end gives no items and the right `total`). In
  JSON the four gaps Microsoft never logs are listed once, as the report's `never_logged` (each account's `gaps` hold
  its own coverage reasons), and every item has `row`, `<source_table>:<record_key>`, the exact argument of
  `sparrow mark flag --row`, `note add` and `timeline-entry propose --evidence`.
- **Exports.** `--csv` writes one row per item (columns `account, category, attribution, accessed_utc, action, item,
  location, from, to, size_bytes, item_time_utc, app, ip, session_id, owner, note, source, record_id, basis`; UTF-8 with a BOM,
  ISO 8601 UTC, formula-like cells prefixed with `'`). `--markdown` prints a table (one row per account, a cell per
  category: `48`, `48 (+3 by time)`, `0 (1 folder synced)`, `0 none seen` or `0 (<status>)`), the coverage gaps
  per account, and once the gaps Microsoft never logs.

## Investigate one account

`sparrow investigate --case C --user UPN (--from T --to T | --on YYYY-MM-DD [--pad 1d|12h|30m]) [--json]` answers
"what happened to this account in this window" in one call; read-only. The window comes from you (the customer's
dates; `--on` is that UTC day, widened by `--pad` on both sides; `--to` is exclusive), never from the command: widen
or move it as evidence comes in. It reports facts, no verdict:

- **Sessions**: one per Entra session id of the account's events in the window, else per UAL Exchange `SessionId`
  (`exchange:<id>`; a UAL record whose Exchange session also appears on a record of an Entra session, with no IP of its
  own or one of that record's, belongs to the Entra session, as in the access report), else per IP (`ip:<address>`).
  Each has its first and last event, the IPs with ASN, country and kind, and whether each IP or ASN is new for the
  account (first seen after the account's first day, in any of its events: the entity pivots' `is_new` rule, so an
  address that appeared yesterday is still new today), devices, user agents, sign-in result codes, value flags on the
  session, its IPs or devices (where the flag's scope holds), the findings whose evidence includes one of its events,
  and `reach`: what the session would reach if it were flagged, the access report's items per category with that
  session (or IP) as the only scope (the case's accepted flags left out), limited to the window.
- **Mail**: message trace to the account from 24 hours before the window to its end (a lure is in view), and mail it
  sent in the window, at most 200 each (`mail_truncated`).
- **Config changes**: the account's `config_change` events in the window, with their `row`.
- **Findings**: every finding of the account with its first and last time, also when the window holds no event (then
  the text says so and these times help to move it).
- **Next**: ready commands per session (`sparrow access ... --brief`, `sparrow mark flag --value session=...|ip=...
  --level malicious`), with the case path quoted for a POSIX shell.

## SQL notebooks

A notebook is a named list of saved queries. Each query is plain DuckDB SQL that opens with a `--` comment block: its
first line is the query's title in lists, the rest says what it finds and how to use it. A value that differs per case
is written as a `[name]` placeholder (`actor_upn = lower('[account]')`) and replaced by hand before running.

- **The built-in notebook** ships with Sparrow: twelve triage queries (sign-ins by country and network, IPs shared by
  accounts, sign-in results per day, hosting-provider sign-ins, first use of each client and device, mail read per
  mailbox, every operation rarest first, forwarding and hiding inbox rules, OAuth grants with mail or offline access,
  new MFA methods, credentials and roles, values flagged malicious, everything one IP touched). It is not stored in the
  case, so every case shows the current release's queries, and nothing writes to it: saving into it, renaming or
  deleting it, or naming a case notebook `Built-in` is refused ("the built-in notebook cannot be changed"). Each runs
  on a case that lacks the tables it reads (an empty result, not an error).
- **Case notebooks** are stored in the case (migration 29: `notebooks`, `notebook_queries`). Names are unique ignoring
  case, one line, at most 500 characters, and never `Built-in` or `builtin` (the built-in notebook's name and id, in
  any case: a name always means one notebook); a notebook holds at most 200 queries of at most 64 KiB each. Each saved
  query records who saved it (`decided_by`, `decided_at`, `on_behalf_of`); it asserts nothing about the case, so it is
  never pending review. Every change is one audit-trail entry (`create_notebook`, `add_notebook_query`,
  `rename_notebook`, `delete_notebook`, `delete_notebook_query`, `move_notebook_query`, `import_notebook`). An
  import's entry holds each query it added (`query_id`, `position`, `sql`) as well as the notebook's and the file's
  names, so the trail alone shows what came in.
- **Who may change what.** An agent may create a notebook, add queries and import a notebook file. Renaming,
  reordering and deleting are the analyst's, in the app (an agent is refused: "only the analyst can ...").

**Placeholders.** `[` then a letter, then letters, digits or `_`, then `]`, with no spaces. They are found anywhere in
the SQL, inside string literals and quoted identifiers too, but not in `--` or `/* */` comments (so the comment block
can name them). All of DuckDB's string forms are read as strings: `'…'`, `E'…'` (backslash escapes) and dollar quotes
(`$$…$$`, `$tag$…$tag$`). DuckDB list syntax (`[1, 2]`, `arr[1]`) is not a placeholder; a string literal that happens to look
like `'[abc]'` is, and the refusal names it. Running a query that still holds one is refused before DuckDB sees it,
naming each: "Fill in [account] and [ip] first". When one is inside a string literal the refusal adds how to keep it
as text: split the string after the bracket, so a query that really looks for `subject LIKE '%[EXTERNAL]%'` writes
`subject LIKE '%[' || 'EXTERNAL]%'`. The SQL screen's Run and CSV export refuse it (`invalid`), as does
`sparrow notebook run` (exit 1); `sparrow query` runs any SELECT as given.

**The SQL screen.** The side has two tabs, Notebook (first) and Schema. Notebook has a picker (the built-in notebook,
then the case's, and New notebook…), the chosen notebook's queries with their placeholders (`[ip]`) and, for an
agent's query, `by <agent>`, and Export…, Import… and Save as…. Clicking a query puts its text in the editor; it does
not run. When the editor holds other unsaved text, a bar asks "Replace the editor's text?" first. The loaded query is
marked `edited` once its text changes. Save as adds the editor's text as a new query to a case notebook (never the
built-in one), or to a new notebook named there (created with its first query in one write, so a refused query makes
no notebook); it never overwrites a query. A case notebook's queries move up and
down and are deleted with an inline confirmation; the notebook is renamed or deleted (with its queries) from the
picker row. A notebook just made (New notebook… or Save as) is chosen at once, before the list reloads with it;
until then it shows Loading… and offers no rename, delete or export. The list reloads when an agent writes through
the bridge, keeping the chosen notebook and the editor.

**Files.** Export writes one notebook (the built-in one too) as a readable `.sql` file:

```text
-- sparrow notebook: <name>
-- exported by Sparrow <version> at <time>
-- ==== query ====
<query 1>
-- ==== query ====
<query 2>
```

A query's trailing blank lines and trailing whitespace are dropped on the way; a query cannot hold the line
`-- ==== query ====`. Import reads such a file (at most 4 MiB, UTF-8, CRLF accepted) into the open case as a new
notebook, never merged into another: it takes the file's name, `Built-in (copy)` for the built-in one (`builtin (copy)` for one named `builtin`), and then
` (2)`, ` (3)`... until free (the name is shortened to keep within 500 characters). A file that does not start with the
header line, has SQL before the first separator, holds no query, has a query that ends inside a string or comment (a
separator inside a query's text), or breaks a cap is refused with the line it failed on, and nothing is written.

**The export check.** Before writing, the queries' text (comments included) is checked against the case: account
UPNs, IPs, device ids and Entra session ids as the Events grid holds them (ignoring case), the tenant's own domains
(`tenant_domains`, as a whole name), and IP ranges written as a prefix (`'203.0.113.%'`) or a CIDR
(`'203.0.113.0/24'`, `/48` for IPv6) that the case's `events.ip_prefix` holds. A complete address is matched only
exactly. The app lists each query's values and asks to Export anyway or Cancel; `sparrow notebook export` prints them
on stderr and exits 5 with nothing written, unless `--force` (then they are warnings). The check never warns about a
value the case does not hold, and the built-in queries hold none.

**CLI.** `notebook list` shows each notebook (`builtin` or its id, name, query count) and its queries (`N. title
[placeholders] (by agent:<id>)`); `--json` is `{"notebooks": [...]}`. `notebook show NOTEBOOK QUERY` prints the text
(escaped like other agent text; `--json` adds the summary fields), NOTEBOOK being an id or a name (`builtin` for the
built-in one) and QUERY a query id or its position (1, 2, ...). `notebook run` runs it exactly as `sparrow query`
would. `notebook add` (`--sql` or `--file`, `--create` to make the notebook in the same transaction) and `notebook
import --file` are agent decisions (`--agent`, `--analyst`), sent through the app's bridge while it has the case open
(the screen's list updates: `case-changed` with `notebooks`). An unknown notebook without `--create`, a refused query,
or a file whose content is refused (a bad header, a cap, a separator inside a query) is exit 5; a file that cannot be
read, is not UTF-8 or is over 4 MiB is exit 1.

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
