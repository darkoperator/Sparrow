# sparrow-synth

`sparrow-synth` is Sparrow's synthetic-collector generator (spec Addendum B). It renders a
plausible Microsoft 365 tenant as the trees **Hawk** 3.x/4.x,
**Microsoft-Extractor-Suite** 4.1.0 and the **Entra / Purview / Exchange portal exports** would
produce, together with a ground-truth `manifest.json`. The CLI is `sparrow synth`; the library
is `sparrow_synth`.

It exists so that parsing, provenance, dedup, supersession, profiling and detection coverage can
be tested **end to end without any customer data**, and so the Microsoft-Extractor-Suite
artifacts that have no real sample get parsers validated against generated data.

## Hard rules

These are not suggestions; the generator and its tests enforce them (spec B.4):

- **Reserved values only.** Domains are `*.example`, `*.test` or `example.com`/`net`/`org`;
  IPv4 addresses come from the RFC 5737 ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) and IPv6 from RFC 3849 (`2001:db8::/32`); GUIDs are seed-derived; person
  names come from `sparrow_synth::names`; the only fixed GUIDs are the documented Microsoft
  product constants in `sparrow_synth::reserved::WELL_KNOWN_GUIDS`. `reserved::scan_text` runs
  over every generated file in the matrix tests.
- **No value from a real capture ever** enters the generator, its data files, its tests or a
  commit. Shape knowledge comes from the research documents (structure only) and the collector
  source. `invictus/SNUS_TEST` and `hawk test captures/` are never read by the tests; the
  controller may run `sparrow synth conformance --real` against them locally.
- **Determinism.** Same scenario + seed + options → byte-identical files and manifest. Only
  ordered collections (`BTreeMap`/`BTreeSet`/`Vec`) are iterated, the clock/environment/host
  locale are never read, dates come from the scenario, and zip entries are sorted, stored and
  timestamped 1980-01-01.
- **`--real` prints aggregates only.** Conformance against a real capture stores artifact ids,
  formats, encodings, line ends, header/key names (masked when they could carry a value) and
  date-form classes — never a path, a file name or a value.

## Usage

```text
sparrow synth --scenario <name|file> --collector hawk3|hawk4|invictus|portal [--ps 5.1|7]
              [--culture en-US|en-GB|de-DE|ja-JP] [--seed N] --out DIR [--zip]
              [--ual-format csv|csv-auditdataonly|json|json-auditdataonly|sof-elk|jsonl]
              [--signin-export csv|xlsx] [--hawk-mixed-editions] [--non-windows]
              [--no-licence-list] [--devices-json] [--ual-rows N] [--signins N]
sparrow synth check --manifest M --case C
sparrow synth coverage [--seed N]
sparrow synth conformance (--tree DIR | --real DIR) --collector hawk|invictus|portal [--seed N]
sparrow synth list
```

`--scenario`, `--collector` and `--out` are required for generation. The output directory is
created if missing and must be empty.

| Flag | Meaning |
| --- | --- |
| `--scenario` | A built-in name (see `sparrow synth list`) or a path to a scenario YAML file. |
| `--collector` | `hawk3`, `hawk4`, `invictus` (alias `microsoft-extractor-suite`) or `portal`. |
| `--ps` | PowerShell edition that wrote the files: `7` (default) or `5.1`. |
| `--culture` | Host culture of the collecting machine: `en-US` (default), `en-GB`, `de-DE`, `ja-JP`. |
| `--seed` | u64 seed (default `1`). Changes every value the generator derives. |
| `--out` | Output directory. |
| `--zip` | Also pack the directory into `<out>.zip` (sorted, stored, fixed timestamps; includes `manifest.json`). |
| `--ual-format` | Microsoft-Extractor-Suite `Get-UAL` output format (default `csv`). |
| `--signin-export` | Portal Entra sign-in export file type: `csv` (default) or `xlsx`. |
| `--hawk-mixed-editions` | Hawk 4 only: tenant files written by PowerShell 7, per-user files by Windows PowerShell 5.1 (two sessions, as in capture D). |
| `--non-windows` | PowerShell 7 on macOS/Linux: LF line ends, Hawk's literal `\Tenant` folder name, and Microsoft-Extractor-Suite's `Output\LogFile.txt` written as one file name containing a backslash, next to `Output/`. |
| `--no-licence-list` | Microsoft-Extractor-Suite: do not write `TenantLicenses.csv` / `UserLicenses.csv` (reproduces the sample, which holds security defaults only). |
| `--devices-json` | Microsoft-Extractor-Suite `Get-Devices -Output JSON`: write JSON into the `.csv` path (a bare object for one device, an array otherwise). |
| `--ual-rows` | Scale knob: total benign UAL rows (see the note under *Scale*). |
| `--signins` | Scale knob: total benign sign-ins (see the note under *Scale*). |

`sparrow synth list` prints the built-in scenarios and the licence/audit profiles; `--json` is
accepted by every `synth` command.

### Examples

Each of these was run against a temporary directory while writing this file.

```bash
# Hawk 4 (the default PS 7), with a check against the manifest.
sparrow synth --scenario audit-tamper --collector hawk4 --out /tmp/tree
sparrow ingest /tmp/tree --case /tmp/case.duckdb --geoip-dir /tmp/tree/geoip
sparrow synth check --manifest /tmp/tree/manifest.json --case /tmp/case.duckdb

# Hawk 3, Windows PowerShell 5.1, day-first host culture.
sparrow synth --scenario audit-tamper --collector hawk3 --ps 5.1 --culture de-DE --out /tmp/tree3

# Microsoft-Extractor-Suite Get-UAL as JSON, without the licence lists.
sparrow synth --scenario audit-tamper --collector invictus --ual-format json \
    --no-licence-list --out /tmp/inv

# Portal sign-in export as XLSX, packed into a deterministic zip.
sparrow synth --scenario audit-tamper --collector portal --signin-export xlsx --zip --out /tmp/portal

# Hawk 4 mixed editions on a non-Windows host.
sparrow synth --scenario audit-tamper --collector hawk4 --hawk-mixed-editions --non-windows \
    --out /tmp/mixed

# Microsoft-Extractor-Suite Get-Devices JSON-in-CSV variant.
sparrow synth --scenario audit-tamper --collector invictus --devices-json --out /tmp/devjson

# Coverage, list and conformance (conformance against a generated tree).
sparrow synth list
sparrow synth coverage
sparrow synth conformance --tree /tmp/tree --collector hawk
```

`sparrow synth conformance --real "some/real/capture" --collector hawk` is the same check run
against a real capture (aggregates only); run it only against captures the controller has
approved.

Some built-in trees deliberately reproduce collector-side lookup failures (for example an
AllRoles row whose `Get-MgUser` returned `Error retrieving data`). `sparrow ingest` reports
those rows as `records_error` and exits 2, while `sparrow synth check` still passes: the parser
is expected to reject exactly those rows.

### Exit codes

- `sparrow synth` generation: 0, or 1 on a bad scenario/flag.
- `sparrow synth check`: 0 when the manifest matches, 2 when there are problems, 1 on errors.
- `sparrow synth coverage`: 0, or 2 when any rule has a gap.
- `sparrow synth conformance`: 0, or 2 when there are findings.

### Output layout

```text
<out>/
  <root>/              # one collection the collector wrote
  geoip/               # GeoLite2-ASN.mmdb and GeoLite2-City.mmdb for the reserved IPs
  manifest.json        # the ground truth (pretty JSON, LF, final newline)
```

`<root>` is what `writers::root_name` decides:

- Hawk 3/4: `Hawk_<tenant folder name>_<yyyyMMdd_HHmmss>`;
- Microsoft-Extractor-Suite: `Output` (with the collector's `<Tenant>/...` run folders below it);
- portal: `Portal_<tenant folder name>_<yyyyMMdd>` (Sparrow recognises portal files by their
  header, so the folder name is free).

With `--zip`, `<out>.zip` holds the same entries under their relative paths (the `manifest.json`
included) with sorted entries, `Stored` compression and the fixed timestamp 1980-01-01.

## Scenarios

A scenario is a built-in name (embedded at compile time) or a YAML file path. The built-ins are:

| Name | Description |
| --- | --- |
| `audit-tamper` | E5 tenant where an attacker tampers with audit configuration mid-window. |
| `bec-aitm` | Adversary-in-the-middle sign-in and the full BEC kill chain on an E5 tenant. |
| `bec-e3-audit-gaps` | E3 tenant where owner actions were customized before on-by-default auditing, so `MailItemsAccessed` and `Send` go unaudited and Entra ID risk levels stay hidden without Identity Protection. |
| `bec-o365-no-p1` | Office 365 E3 tenant without Entra ID P1, so Graph sign-in downloads are refused and identity risk evidence is unavailable. |
| `business-basic` | Business Basic tenant with organization mailbox auditing disabled. |
| `hawk-investigate` | Office 365 E5 tenant (Audit Premium and MDO P2, but no Entra ID P1/P2) exercising every condition `Start-HawkUserInvestigation` checks. |
| `volume` | Large E5 tenant used as the base scenario for scale testing. |

### Format

```yaml
name: bec-aitm
description: Adversary-in-the-middle sign-in and the full BEC kill chain.
tenant:
  name: Contoso Example
  domains: [contoso.example, contoso-finance.test]
  users: 12
  admins: 1
  licence_profile: m365_e5
  audit_profile: search_audited
  host_utc_offset_minutes: 120
  hawk_users: [1, 2, 3]        # optional; Hawk collects per-user files only for these
  role_group_member: false     # test-only; AllRoles group-member carry-over
window:
  start: 2026-08-01T00:00:00Z
  days: 40
  collected_at: 2026-09-10T14:15:00Z
baseline:
  signins_per_user_day: 4.0
  ual_per_user_day: 12.0
  messages_per_user_day: 6.0
  work_hours: [8, 18]
  weekend_factor: 0.1
scale:                         # optional; same as --ual-rows / --signins
  ual_rows: 0
  signins: 0
storylines:
  - {kind: aitm_signin, id: s-aitm, actor: 1, at: {day: 20, hour: 9, minute: 12}}
  - {kind: confirmed_compromised, id: s-comp, actor: 1, at: {after: s-aitm, minutes: 600}}
lookalikes:
  - {kind: plausible_travel, id: l-travel, actor: 4, at: {day: 5, hour: 7}}
pin_ambiguous_dates: false      # test-only, see below
```

Every top-level field is required unless it has a default:

- `name` (required), `description` (default empty);
- `tenant`:
  - `name` (required): the display name the Hawk folder and log use;
  - `domains` (required, non-empty; every entry must be a reserved domain): the primary domain
    is the first;
  - `users` (required, 2..=100000) and `admins` (default 1);
  - `licence_profile` and `audit_profile` (required): ids from the built-in profile tables;
  - `host_utc_offset_minutes` (default 0);
  - `hawk_users` (default empty): the user numbers Hawk collects per-user files for;
  - `role_group_member` (default false): test-only, makes the Finance group a direct member of
    the activated "User Administrator" role so the AllRoles group-member carry-over is reproduced.
- `window`:
  - `start` (RFC 3339 UTC), `days` (1..=180), `collected_at` (must be ≥ `start + days`);
- `baseline` (all optional): `signins_per_user_day`, `ual_per_user_day`,
  `messages_per_user_day` (defaults 4.0/12.0/6.0), `work_hours` (default `[8, 18]`),
  `weekend_factor` (default 0.1). Rates must be ≥ 0 and `work_hours` must satisfy
  `start < end <= 24`.
- `scale` (`ual_rows`, `signins`, both default 0): the scenario-level scale knobs.
- `storylines` / `lookalikes` (default empty): each entry has `kind`, `id` (unique across both
  lists), optional `actor`/`target` (user numbers in `1..=users`) and `at`.
  - `at: {day, hour, minute}` (minute default 0) resolves to `start + day + hour + minute`;
    `day` must be `< days` and `hour`/`minute` in range.
  - `at: {after: <id>, minutes}` resolves relative to another storyline; `after` must name a
    known id and cycles are rejected.
  - A positive `kind` in `storylines` or a look-alike `kind` in `lookalikes` is a validation
    error, and every resolved time must be before `start + days`.
- `pin_ambiguous_dates` (default false): test-only; aligns historical state dates to day 1 of
  their month so a day/month-order culture can never read them as decisive.

Scenario loading validates all of the above and returns `Error::Scenario` with the offending
field. Unknown YAML fields are rejected (`deny_unknown_fields`).

### Storyline kinds

`storylines` are the positive kill-chain steps; `lookalikes` are the benign events a rule must
**not** fire on. Each kind draws from its own RNG stream `story/<id>`, so adding one never
changes another.

Positives:

| Kind | Emits |
| --- | --- |
| `aitm_signin` | The user's own sign-in, a proxied MFA sign-in from a hosting ASN, a token replay by a script from another hosting ASN, a mailbox logon, and an Identity Protection detection. |
| `confirmed_compromised` | An admin confirming the user compromised in Identity Protection. |
| `mfa_method_added` | The Authenticator app registered for the user from the attacker's replay address. |
| `oauth_consent` | An unverified mail app granted mail, files and offline access, then used a minute later. |
| `app_credential_added` | A password credential added to a service principal from the attacker's address. |
| `domain_federation` | An admin session from the attacker's address adds, verifies and federates a domain. |
| `new_mobile_device` | A new iPhone starts syncing the mailbox over ActiveSync. |
| `inbox_rule_finance` | The victim's own finance-keyword rule: finance mail marked read and hidden in RSS Feeds. |
| `admin_inbox_rule` | An admin creates a forwarding-and-deleting rule on another mailbox, edits it, and creates/removes a throw-away rule. |
| `forwarding_mailbox` | `Set-Mailbox -ForwardingSmtpAddress` to the attacker's address. |
| `forwarding_inbox_rule` | The victim's rule forwarding a vendor's invoices to the attacker. |
| `forwarding_transport_rule` | An admin adds a transport rule blind-copying all outbound mail to the attacker. |
| `mailbox_permission_grant` | An admin grants the story's user FullAccess and SendAs on another mailbox. |
| `mia_burst` | The attacker reads mail through a consented app: 12 `Bind` records over ten minutes. |
| `send_new_ip` | The user sends mail from the attacker's send address via OWA. |
| `search_finance` | Finance-keyword searches in Exchange and SharePoint from the attacker's address. |
| `autoreply_enabled` | The user's automatic reply changed to point at the attacker's payment address. |
| `header_spoof` | A message impersonating an admin that fails SPF and DMARC. |
| `ediscovery_search` | An admin creates, runs and exports a content search from the attacker's address. |
| `mass_download` | A script downloads 60 invoices from the Finance site in twelve minutes. |
| `anonymous_link` | An anyone-with-the-link view link on a Finance document. |
| `lure_share` | A OneNote lure and PDF uploaded to the victim's OneDrive, shared externally, and mailed to 15 recipients. |
| `audit_tamper` | Auditing turned off step by step (mailbox, bypass, organization, UAL ingestion) from the attacker's address. |

Look-alikes:

| Kind | Emits |
| --- | --- |
| `risk_dismissed` | A low unfamiliar-features detection an admin dismissed. |
| `mfa_new_hire` | A new starter with no second factor registers the Authenticator app on their own phone. |
| `low_risk_consent` | A verified lunch-poll app granted only sign-in and profile scopes. |
| `app_signin_existing_consent` | A sign-in to an app consented to before the window. |
| `cert_rotation` | An admin rotates the payroll app's certificate. |
| `domain_property_update` | An admin marks the primary domain as the default. |
| `old_mobile_device` | A long-standing phone, first synced 200 days before the window. |
| `microsoft_asn_signin` | A sign-in from a Cloud PC: a Microsoft address at the user's home. |
| `plausible_travel` | A flight home 14 hours before, then a far city a plane could reach in the time. |
| `same_ip_token_use` | An interactive sign-in and its token refresh 20 minutes later, same IP and client. |
| `vendor_filing_rule` | The user files a vendor's mail into a folder. |
| `admin_benign_rule` | The admin files processed mail on a shared mailbox with `DeleteMessage False`. |
| `internal_forwarding` | Forwarding to another user of the same tenant. |
| `forwarding_removed` | Forwarding removed, then `Set-Mailbox` clearing it. |
| `set_mailbox_other_param` | `Set-Mailbox` changing an unrelated parameter. |
| `permission_system_discovery` | Exchange's own FullAccess grant on the discovery mailbox for Discovery Management. |
| `mia_sync` | Outlook desktop synchronising twelve folders over ten minutes from the office. |
| `send_known_ip` | The user sends mail from the office via Outlook desktop. |
| `search_benign` | A harmless Exchange search from the office. |
| `autoreply_disabled` | The user's automatic reply is disabled. |
| `header_clean` | A vendor newsletter that passes SPF, DKIM and DMARC. |
| `ediscovery_view_only` | An admin views a content search but does not export. |
| `normal_download` | Five downloads from the Finance site over four hours from the office. |
| `anonymous_link_benign` | An anyone-with-the-link view link on a Marketing document. |
| `internal_docx_share` | The user shares a plan with a colleague. |
| `audit_config_benign` | The admin lengthens audit retention and adds an audited owner action. |

### Licence profiles

`crates/sparrow-synth/data/licence_profiles.yaml` holds the SKUs of a tenant and, written by
hand from the licensing research (Microsoft Learn, `as_of` recorded), the exact
`tenant_capabilities` outcome Sparrow must derive for each kind of delivered licence evidence.
The six profiles are `m365_e5`, `m365_e3`, `o365_e3`, `o365_e5`, `business_premium` and
`business_basic`. A profile's `expect` map is keyed by `Delivery`: `invictus_list`,
`invictus_nolist` (Microsoft-Extractor-Suite with/without the licence list), `hawk4`, `hawk3`
and `portal`.

`tenants[].licence_profile` names one of these ids. The generator never computes expectations
from Sparrow's code — the table **is** the oracle, so a `synth check` diff means one of the two
is wrong.

### Audit profiles

`crates/sparrow-synth/data/audit_profiles.yaml` holds organization and mailbox audit settings:
`unified_audit_log_ingestion_enabled`, `org_audit_disabled`, `admin_audit_log_enabled`, and the
`customized_owner`, `bypass` and `search_query_owner` user selectors (`none`, `all`, `victims`
or a list of user numbers; `victims` = the actors and targets of every storyline). The six
profiles are `default`, `search_audited`, `customized_owner`, `bypass_victims`,
`org_audit_disabled` and `ual_disabled`. What Microsoft 365 *logs* is decided at world-build
time from this profile, separately from what a collector can *fetch*.

## manifest.json

The manifest is the independent oracle `sparrow synth check` compares a case against. It is
pretty JSON with LF line ends and a final newline (the manifest is not collector output).

Top-level fields:

| Field | Meaning |
| --- | --- |
| `format` | Manifest format version (1). |
| `generator` | `sparrow-synth <crate version>`. |
| `scenario` | The scenario's `name`. |
| `options` | The full `GenerateOptions` (collector, PS edition, culture, seed, UAL format, sign-in export, variants, scale). |
| `root` | The collection root folder, relative to the output directory. |
| `geoip_dir` | The GeoIP folder (`geoip`). |
| `ingest_culture` | The `--culture` an ingest needs, when the tree proves no day/month order. |
| `window_start`, `window_end`, `collected_at` | The collection window (UTC). |
| `licence_profile`, `audit_profile` | The scenario's profile ids. |
| `files` | One `FileExpect` per file. |
| `empty_dirs` | Directories the collector created and left empty. |
| `tables` | One `TableExpect` per state/event table. |
| `tenant` | The `TenantExpect`. |
| `capabilities` | Expected `(status, confidence)` per capability. |
| `evidence` | Allowed availability statuses per evidence id. |
| `storylines` | One `StoryExpect` per storyline/look-alike. |
| `rules` | One `RuleExpect` per (rule, storyline) pair. |

`FileExpect`:

| Field | Meaning |
| --- | --- |
| `rel_path` | Path within the collection root, `/`-separated. |
| `artifact_id` | The registry artifact id, or `null` when unrecognized. |
| `status` | `parsed`, `duplicate_file`, `skipped_superseded`, `unrecognized`, `not_supported` or `error`. |
| `source_derived` | The writer derived this file from another file of the tree (Hawk `Simple_*`, merged copies). |
| `encoding` | The encoding the file was written in (`ps::Encoding::name`). |
| `bytes` | File size. |
| `sha256` | Lower-case hex SHA-256 of the bytes. |
| `date_evidence` | `{culture_dates, decisive}` for the file's culture-rendered dates, or `null`. |

`TableExpect`:

| Field | Meaning |
| --- | --- |
| `rows` | Expected row count. |
| `exact` | True when `rows` is exact; false when it is a lower bound. |
| `keys_sha256` | SHA-256 of the sorted unique record keys joined by `\n`, or `null` for a count-only table. |
| `keys` | The sorted unique record keys, listed only when there are at most 5,000; a key may carry the `{cid}` placeholder for the collection id. |

Row keys are each table's `record_key`, documented in that table's
`COMMENT ON COLUMN ... record_key`, except:

- `ual_events` is keyed by the lower-case `record_id`;
- `mail_items_accessed` is count-only;
- `email_artifacts` is keyed by the lower-case Message-ID without its angle brackets (a message
  with no Message-ID falls back to the SHA-256 hex of the file);
- `applications` is keyed by the lower-case app id, and a `UserApplications` row adds
  `|<lower AssociationType>|<lower AssociatedUser>` to it.

`TenantExpect { tenant_id, name, domains }`: `name` is the Hawk tenant name (Hawk only); the
domains are the ones Sparrow must derive, per collector (Hawk: every delivered user UPN domain;
Microsoft-Extractor-Suite: every mailbox UPN domain; portal: the primary domain plus home-tenant
interactive sign-in UPN domains).

`EvidenceExpect { allowed, why }`: the evidence ids the tree predicts (a few per tree) and the
statuses the scenario allows, with the reason. `check` evaluates availability with
`as_of = collected_at + 1 day`.

`StoryExpect { id, kind, polarity, actor, time, evidence }`; each evidence ref is
`{what, logged, delivered}` where `delivered` lists `{table, record_key, rel_path, line_start,
line_end}`. `logged` is false for a UAL record Microsoft 365 did not record under the audit
profile.

`RuleExpect { rule_id, storyline, outcome, reason, tables }` with `outcome` one of `hit`,
`no_hit`, `not_applicable` or `no_evidence`, and `tables` the rule tables the storyline's
evidence reached.

### `sparrow synth check`

`sparrow synth check --manifest M --case C` opens the case read-only (it does not ingest) and
diffs it against the manifest, one line per difference, at most 20 example keys per table:

1. The one collection whose `root_path` ends with `/<root>` (or `\<root>`).
2. Every `FileExpect`: a `source_files` row with that `rel_path`, `status` and `artifact_type`;
   any recorded file the manifest does not list is an extra.
3. Every `TableExpect`, case-wide (tables merge across collections): an exact table compares
   `count(*)` and the record-key set (by `keys_sha256` when the keys are not listed, else by
   listing missing/extra keys); a non-exact table requires at least `rows`; a count-only table
   compares `count(*)`.
4. The tenant id (case-insensitive) and the expected domains.
5. Every listed capability's `(status, confidence)`.
6. Evidence availability at `collected_at + 1 day` against the allowed status sets.
7. For every delivered storyline sighting, a `record_sources` row with the table, key, file id
   and line span.

Rule expectations are not checked until Phase 6 (the detection engine); the report counts them
in `rules_unchecked`.

## `sparrow synth coverage` and `rules/coverage.yaml`

`rules/coverage.yaml` (committed, embedded at compile time) is the single source of the
rule ↔ storyline map for the spec §8.5 seed-rule pack (31 rules). Per rule it holds `id`,
`title`, `category`, `severity`, the Hawk investigate condition it covers (`hawk`), the intended
`logic` Phase 6 must implement, the `tables` it reads (the first is where a hit lands), the
`requires` capability ids and `requires_evidence` evidence ids that make it `not_applicable`,
`needs_geoip`, the `collectors` that can supply a positive's evidence, the
`lookalike_collectors` that can supply a look-alike's (defaults to `collectors`), the `positives`
and `lookalikes` storyline kinds, and optional `evidence_all_of`: a list of groups where each
group is a list of tables and reaching **any** table in a group satisfies that group. A rule that
correlates two kinds of evidence sets `evidence_all_of`; absent, it defaults to one group equal
to `tables`.

`sparrow synth coverage [--seed N]` generates every built-in scenario (except `volume`) for
every collector into memory and aggregates the manifests' rule outcomes into a report with, per
rule, the `hit`, `no_hit`, `not_applicable` and `no_evidence` exercises and any `gaps`:

- no hit in any tree, or no look-alike `no_hit` in any tree;
- no hit through any `collectors` entry, or no `no_hit` through any `lookalike_collectors` entry;
- `requires`/`requires_evidence` set but no `not_applicable` anywhere;
- `needs_geoip` but its hits all come from trees without GeoIP.

A hit/`no_hit` is only counted when the storyline reached every `evidence_all_of` group; a
correlated rule that reached only part of its evidence is reported as `no_evidence`.

## `sparrow synth conformance`

`conformance/layouts.yaml` records the real collector layouts as **structure only**,
transcribed from the research surveys: artifact id, collector, source, formats, encodings,
line ends, accepted CSV headers, required columns, JSON keys, and the observed date-form classes
per column/key (`inferred: true` marks an inferred form). No values.

- `sparrow synth conformance --tree DIR --collector C` profiles a generated tree and compares
  it with the recorded layouts: every listed artifact must match a header variant (or contain
  the required columns), use a listed format/encoding/line ending, carry the listed JSON keys,
  and use only listed date forms. Artifacts with no recorded layout are counted under
  `not checked` (source-derived).
- `sparrow synth conformance --real DIR --collector C [--seed N]` profiles a real capture and
  compares it with generated trees for that collector (both PS editions, three cultures, every
  built-in scenario). Findings are aggregates only: artifact ids, masked column/key names,
  encodings, JSON shapes, date forms and counts.

The profile masks a column or key name containing `@` or matching an IPv4/IPv6 address as
`<masked>`, because a real export can put a value in a dynamic column name. Reports never
contain a path, a file name or a value.

## Scale

`World::apply_scale` spreads the effective filler — `--ual-rows` or the scenario's
`scale.ual_rows`, and `--signins` or `scale.signins` — evenly over the window's days, streamed
day by day, so a million-row tree is written in bounded memory. Manifest keys for large tables
are kept only as the digest (the sorted `Vec` is used up to 5,000 keys). The library entry point
is `scale::run_perf`, which generates, ingests, profiles and computes capabilities with timings.

Note: the `--ual-rows` / `--signins` **CLI flags are accepted but currently refused** — the
generation path exits 1 with "not supported until the scale knobs land". The scale knobs work in
the library and are exercised by the `sparrow-synth` `perf` test; the CLI wiring is a Phase 5
follow-up.

Performance harness (the ignored test prints `Timings::to_text`):

```bash
cargo test -p sparrow-synth --release --test perf -- --ignored --nocapture
```

The fast, non-ignored `scale_knobs_add_exact_filler_and_stay_checkable` test verifies that the
knobs add exactly the requested rows and stay checkable.

## Deviations from the original plan

Documented here because the code, not the plan, is the reference:

- **`--ual-rows` / `--signins` are refused by the CLI.** `GenerateOptions` and
  `World::apply_scale` support them and the `perf` test exercises them, but `sparrow synth`
  exits 1 with "not supported until the scale knobs land" (a CLI test pins the refusal).
- **`rules/coverage.yaml` gained `evidence_all_of`.** A correlated rule lists the evidence
  halves a storyline must reach; `sparrow synth coverage` reports a storyline that reached only
  some halves as `no_evidence`, not as a hit/no-hit.
- **`conformance/layouts.yaml` has `inferred: true` entries** for date forms the survey saw on
  one PowerShell edition only (the Microsoft-Extractor-Suite MailItemsAccessed PS 5.1 forms).
- **The PS 7 Microsoft-Extractor-Suite writer emits the `DirectoryActivityLogs` JSON and JSONL
  files byte-identically**, so the second is `duplicate_file`; the CSV twin carries PowerShell
  placeholder values (`System.Object[]`, `@{...}`, `.NET` type names), loads no rows and gets a
  warning.
- **`email_artifacts` is keyed by the normalized Message-ID** (lower-case, angle brackets
  stripped; a missing Message-ID falls back to the file's SHA-256).
- **`applications` gives a `UserApplications` row its own key** by appending
  `|<lower AssociationType>|<lower AssociatedUser>` to the app id.
- **`inbox_rules.source`** is `hawk` for Hawk's files and `graph`/`exo` for the
  Microsoft-Extractor-Suite Graph/Exchange cmdlets.
- **`source_derived` in the manifest means "this file was derived from another file of the
  tree"** (Hawk `Simple_*`, merged copies). The "source-derived, no real sample" list in the
  section below is a different thing: an artifact with no recorded layout.

## Source-derived artifacts

An artifact is **source-derived** when it has no recorded real layout in
`conformance/layouts.yaml`; its writer and parser are validated against generated trees only.
For Microsoft-Extractor-Suite that is most of the Phase 5 additions:

- `inv.activity`, `inv.directory_activity`, `inv.admins`, `inv.admins.merged`, `inv.roles.all`,
  `inv.roles.pim`, `inv.users`, `inv.groups`, `inv.group_members`, `inv.dynamic_groups`,
  `inv.devices`, `inv.ca`, `inv.mfa.methods`, `inv.mfa.registration`, `inv.oauth`,
  `inv.service_principals`, `inv.app_registrations`, `inv.user_applications`,
  `inv.risk_detections`, `inv.risky_users`, `inv.security_alerts`, `inv.secure_score`,
  `inv.licenses.tenant`, `inv.licenses.user`, `inv.mailbox_rules`, `inv.transport_rules`,
  `inv.mailbox_audit_legacy`, `inv.email`, `inv.logfile`, `inv.ual.graph`,
  `inv.quickual.operation`, `inv.quickual.combined`, `inv.entra_audit.merged`,
  `inv.signins.merged`;
- Hawk's text/log artifacts (`hawk.log`, `hawk.psframework_log`, `hawk.investigate_file`,
  `hawk.investigate_txt`, `hawk.user.mailbox_txt`, `hawk.user.autoreply`,
  `hawk.tenant.org_config`, `hawk.tenant.admin_audit_log_config`,
  `hawk.tenant.ediscovery_roles`, `hawk.message.header_findings`) are parsed against the
  capture survey's structure descriptions rather than a column-list layout.

Portal exports and the surveyed Hawk CSV/JSON artifacts are conformance-checked.
