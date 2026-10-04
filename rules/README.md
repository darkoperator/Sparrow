# rules/

The detection rules (spec §8, Addendum C). One rule per YAML file, plus the static lists a rule
references through `@list:`.

```text
rules/
  mail/       SPW-MAIL-*, SPW-HAWK-014.yaml
  identity/   SPW-ID-*, SPW-HAWK-008, SPW-HAWK-009, SPW-HAWK-012, SPW-HAWK-013
  apps/       SPW-APP-*, SPW-HAWK-006, SPW-HAWK-007
  config/     SPW-CFG-*, SPW-HAWK-004, SPW-HAWK-005
  # files/ does not exist yet: the three SPW-FILE-* rules have no rule file.
  hawk/       SPW-HAWK-001..003, SPW-HAWK-010, SPW-HAWK-011, SPW-HAWK-015
  lists/      finance_keywords, hiding_folders, hosting_asns, risky_scopes, suspicious_user_agents
  schema/     rule.schema.json
  coverage.yaml   the rule ↔ storyline test matrix (embedded; `sparrow synth coverage`)
```

The six `hawk/` files are the Hawk-parity rules, which span categories (H01-H15 are investigate
conditions, not an evidence kind), so they are grouped by their source rather than by the table
they read.

The **built-in** rules and lists are embedded in the binary by `build.rs`, like `data/`, so a
release `sparrow` needs no `rules/` folder. A checkout keeps them in the tree so they are edited,
reviewed and linted in the open; the embedded copy is what runs.

`rules/coverage.yaml` is the *test matrix* (which storyline must trigger which rule, which must
not, what the rule needs). The rule files hold the *logic*. `sparrow rules lint` cross-checks the
two; see [Coverage cross-check](#coverage-cross-check).

## Rule file

```yaml
id: SPW-HAWK-011               # ^SPW-[A-Z]+-[0-9]{3}$
title: Mailbox forwarding configured
version: 1                     # bump when the logic changes
status: stable                 # experimental | stable | deprecated
severity: medium               # info | low | medium | high | critical
confidence: medium
mitre: [T1114.003]
tags: [bec, forwarding]
requires: []                   # capability ids (data/capabilities.yaml)
requires_evidence: []          # evidence ids (evidence_availability)
needs_geoip: false
source: mailboxes              # the hit table — see "Three kinds of rule"
match:                         # the condition — see "Conditions"
  any:
    - forwarding_smtp_address: {exists: true}
    - forwarding_address: {exists: true}
group_by: [actor_upn]           # what makes a hit *this* finding
analyst_guidance: |             # required, free text
  Confirm the forwarding target is expected rather than an attacker redirecting mail. …
false_positives:               # optional
  - Legitimate forwarding to another internal mailbox.
references:                    # optional
  - https://learn.microsoft.com/en-us/purview/audit-log-activities
author: Sparrow                # optional
tests:                         # required, >= 1
  - name: mailbox forwards mail to an external address
    records:
      - table: mailboxes
        upn: alice@contoso.example
        forwarding_smtp_address: external@example.net
    expect_hits: 1
  - name: forwarding was removed
    records:
      - table: mailboxes
        upn: bob@contoso.example
        forwarding_smtp_address: ""
        forwarding_address: ""
    expect_hits: 0
```

`rules/schema/rule.schema.json` is the JSON Schema (editor autocomplete, and the shape lint
checks). The typed serde model in `crates/sparrow-core/src/detect/rule.rs` is authoritative: it
requires `id`, `title`, `version`, `status`, `severity`, `analyst_guidance` and `tests`, and
everything else has a default.

## Three kinds of rule

A rule carries **exactly one** of `source:` + `match:`, `sources:`, or `sql:`.

### 1. `source:` + `match:` — one table, declarative

Compiles to a single `SELECT` over that table. `source:` must name a **hit table** (below); the
compiler rejects a table it cannot key and time.

```yaml
source: ual_events
match:
  all:
    - operation: {in: [New-InboxRule, Set-InboxRule, UpdateInboxRules]}
    - any:
        - parameters.SubjectOrBodyContainsWords: {contains_any: "@list:finance_keywords"}
        - parameters.MoveToFolder: {in: "@list:hiding_folders"}
```

### 2. `sources:` — several tables, one union

Each arm is `{source, match}`; the arms are `UNION ALL`ed and each hit keeps the `source_table` it
came from. Use it when the same judgement applies to two or more tables.

```yaml
sources:
  - source: ual_events
    match:
      operation: {in: ["Consent to application.", "Add delegated permission grant."]}
  - source: directory_audits
    match:
      activity: {in: ["Consent to application", "Add delegated permission grant"]}
```

(`rules/apps/SPW-HAWK-006.yaml`.)

### 3. `sql:` — a correlation the declarative form cannot express

Raw DuckDB SQL for rules that need a window over a user's events, a join, or arithmetic. The
contract is strict; see [`sql:` rules](#sql-rules). Roughly a third of the pack needs it, and each
one carries a header comment explaining the thresholds it uses and why.

## Conditions

`match:` is `all:` / `any:` / `not:`, or a **leaf** — a single `field: {operator: value}` pair.
A leaf has exactly one field and exactly one operator; an error names the path
(`SPW-X-1: match.all[2].f: unknown operator "eqq"`).

```yaml
match:
  all:                       # every child must hold
    - a: {eq: 1}
  any:                       # at least one child must hold
    - b: {exists: true}
  not:                       # negate one child
    any: [ … ]
  c: {in: "@list:hiding_folders"}   # a leaf
```

### Operators

| Operator | Value | Meaning |
| --- | --- | --- |
| `eq` | scalar or list | Equal (case-insensitive on text; typed on numbers and timestamps) |
| `neq` | scalar | Not equal — **see the NULL rule below** |
| `in` | list or `@list:<name>` | The value is one of the list's entries |
| `contains` | scalar | Substring (case-insensitive) |
| `contains_any` | list or `@list:<name>` | Substring of at least one entry |
| `startswith` / `endswith` | scalar | Prefix / suffix (case-insensitive) |
| `regex` | scalar | DuckDB `regexp_matches`; **case-sensitive** (use `(?i)` for insensitive) |
| `cidr` | range, list of ranges, or `@list:<name>` | IPv4 in the range |
| `gt` / `gte` / `lt` / `lte` | number, or RFC 3339 timestamp / date | Ordered comparison |
| `exists` | `true` / `false` | Whether the field has a value — the explicit absence test |
| `eq_field` / `neq_field` | the name of **another field** | Compare two columns of the same row |

`contains`, `startswith` and `endswith` reject an empty value at compile time (it would match
every row). `eq`, `neq`, `contains` and friends reject a `@list:` value: use `in` or
`contains_any`.

### Three-valued NULL semantics

**A field that is absent or NULL makes every comparison leaf NULL, and NULL is not a match.** So a
`neq` on a missing value does *not* match — the row simply fails the rule. This is deliberate: it
stops a rule from claiming "the value is not X" about a row that never had an X.

`exists` is the explicit, **two-valued** test for absence. Use it when you mean "missing":

| Field state | `{neq: "Get"}` | `{eq: "Get"}` | `{exists: false}` | `{exists: true}` |
| --- | --- | --- | --- | --- |
| `operation = 'New-InboxRule'` | match | no | no | **match** |
| `operation` absent / NULL | no | no | **match** | no |
| `operation = ''` (empty text) | match | no | **match** | no |

The first three rows are pinned by the compiler tests in
`crates/sparrow-core/tests/detect_compile.rs` (`match_leaf_operators_compile_and_run`), where a
`neq` on a missing `parameters.ForwardTo` matches nothing and `exists: false` matches the rows
that lack it. The last row is worth noting because the inline-test inserter defaults an omitted
`VARCHAR` to `''`, and `exists: false` matches it.

### Field paths

A field is a column name, optionally dotted into a container. The path is resolved against the
table's real schema at compile time, so a typo or a renamed column is a **lint error**, not a
silently empty rule.

| Path | Reads |
| --- | --- |
| `operation` | a scalar column |
| `parameters.ForwardTo` | a key of a `MAP` column |
| `context.some_member` | a member of a `STRUCT` column |
| `audit_data.$.Activity` | a `JSON` column by JSON path (`$.` optional) |
| `location` | a `JSON` column whole (cast to text) |

**MAP keys are matched case-insensitively** — `parameters.movetofolder` finds `MoveToFolder`,
which is what the UAL and Exchange cmdlets disagree about. `STRUCT` member names and JSON path
segments are case-sensitive (DuckDB's own semantics).

The comparison itself is case-insensitive for text unless a list says otherwise (see below).
`match` and `sources` arms may also read `ual_events` columns when the source is a side table
(`file_events`, `search_queries`, `sharing_events`), which carry no time or actor of their own.

### `eq_field` / `neq_field`

Compare two columns of the same row instead of a literal. The value is a **field path**, not a
constant, and both sides are lower-cased:

```yaml
match:
  user_upn: {eq_field: mailbox_upn}   # the actor is the mailbox owner
```

A `NULL` on either side makes it NULL, so it is not a match — the same three-valued rule as
everywhere else. A `VARCHAR[]` column cannot be compared this way.

### `cidr`

`{cidr: "203.0.113.0/24"}`, a list of ranges, or `@list:<name>`. The ranges are computed at
compile time and compared as IPv4 integers, because the `inet` extension is not bundled with the
pinned `duckdb` crate. The address column is normalised first: `[v6]:port` brackets, a
`::ffff:` prefix and a `:port` suffix are stripped, and anything that is not four octets in
`0..=255` yields NULL (no match, never a different address). **IPv6 CIDRs are a compile error** —
`{cidr: "2001:db8::/32"}` will not compile, by design.

### `threshold:`

A burst: rows that match, counted in a **sliding window** on `event_time` per group. The window
is `RANGE BETWEEN <window> PRECEDING AND CURRENT ROW`, so a group needs `count` rows inside
`window`; **every row inside such a window is returned**, not just the row that crossed the
threshold. Groups never mix.

```yaml
threshold:
  group_by: [actor_upn]   # output columns only
  window: 10m             # ^[0-9]+(m|h|d)$
  count: ">= 50"          # ^(>=|>|=) ?[0-9]+$
```

`threshold.group_by` is a separate list from the rule's own `group_by`: it may only name the
output columns `record_key`, `source_table`, `event_time`, `actor_upn`, `ip`. An empty
`threshold.group_by` counts the whole case in one window.

No built-in rule uses `threshold:` — the bursts that exist are written in `sql:` because they also
correlate (see `rules/mail/SPW-MAIL-005.yaml`, the MailItemsAccessed burst). The compiler and its
tests are complete; a future burst rule can use it.

### `group_by`

What turns hits into **findings**. The fingerprint is
`sha256(rule_id | tenant_key | the group_by values)`, so a rule with `group_by: [actor_upn]`
collapses every hit by the same actor into one finding that carries all the evidence — which is
what an analyst wants from "this mailbox was forwarded to an attacker address".

A rule **without** `group_by` groups by `record_key`: one finding per triggering record.

`group_by` may only name the six output columns (`record_key`, `source_table`, `event_time`,
`actor_upn`, `ip`). For a `sql:` rule it may additionally name a key of the JSON `context` it
projects, which is how a correlation rule keeps its "other end" out of the fingerprint. (No
built-in rule does this yet; all of them use `group_by: [actor_upn]`.)

## Lists

`rules/lists/<name>.yaml`:

```yaml
name: finance_keywords
description: >-
  Generic public finance and payment terms used in business-email-compromise lures;
  contains no customer or capture data.
values:
  - invoice
  - payment
  - wire
```

`description` is required, so a list says what it is for. `hosting_asns.yaml` has its own shape
(`version` + `asns: [{asn, name, kind}]`), shared with `data::hosting_asns`, and resolves to the
list of ASN numbers.

**Lists are compared case-insensitively by default.** A list that needs exact matching says so:

```yaml
name: ci
description: A case-sensitive list.
case_sensitive: true
values: [Invoice]
```

With `case_sensitive: true` a row's `invoice` does **not** match the entry `Invoice`; without it,
both sides are lower-cased and it does.

A `@list:` value is **bound as a query parameter**, never interpolated into the SQL text, so a
list value can never change the query's shape.

### `@list:case_iocs.<type>`

Reads the case's **indicators** (`case_indicators`, `sparrow ioc add`) at run time:

```yaml
source: ual_events
match:
  client_ip: {in: "@list:case_iocs.ip"}
```

Only active indicators (not removed: `removed_at` is NULL) whose `type` matches and whose verdict
is `malicious` or `suspicious` are used; `benign` ones are excluded. An indicator with no `tenant_key` applies to every tenant, otherwise
only to its own. The types are `ip`, `upn`, `app_id`, `domain`, `user_agent`, `rule_name`,
`email`, `url` and `hash`.

Because the contents of a `case_iocs` list are **not** in the rule file, they are folded into the
run's hash (see [The rule hash](#the-rule-hash)): adding or removing an indicator changes
`rule_sha256` and marks the affected findings `rule_updated`, because it can change what the rule
finds. No built-in rule reads `case_iocs` yet.

## `sql:` rules

A `sql:` rule must be a **single `SELECT`** and must project the output contract. The compiler
validates all of this against an empty in-memory database with the case's tables, so lint never
touches the case or a file.

| Column | Type | Required | Meaning |
| --- | --- | --- | --- |
| `record_key` | `VARCHAR` | yes | the row's `record_key` (for `ual_events`, `lower(record_id)`) |
| `source_table` | `VARCHAR` | yes | the table this hit came from — see below |
| `event_time` | `TIMESTAMP WITH TIME ZONE` | yes | when it happened |
| `actor_upn` | `VARCHAR` | no | the actor; omitted columns are filled with `CAST(NULL AS …)` |
| `ip` | `VARCHAR` | no | the address |
| `context` | `JSON` | no | anything else the analyst needs |

The validation is deliberately strict, and each of these is a compile-time error:

| Rejected | Message |
| --- | --- |
| `FROM main.ual_events` | `schema-qualified reference to main.ual_events: use the plain table name (the tenant scope replaces it)` |
| `FROM read_csv(…)` | `table function read_csv is not allowed in a rule (allowed: unnest, generate_series, range, json_each, json_tree)` |
| `DELETE FROM ual_events` | `sql rule is not a SELECT statement or does not parse: …` |
| a projection named `k` instead of `record_key` | `sql rule must project record_key (VARCHAR)` |
| `CAST(u.event_time AS VARCHAR) AS event_time` | `sql rule column event_time must be TIMESTAMP WITH TIME ZONE, found VARCHAR` |
| `'mail_items_accessed' AS source_table` | `sql rule: source_table "mail_items_accessed" is not a hit table` |
| a column or a concatenation as `source_table` | `sql rule: source_table must be a string literal or a CASE whose every branch is a string literal` |

### `source_table` must be statically known

The rule's hit tables drive the coverage cross-check, so `source_table` has to be known without
running the query. It must be a **string literal**, or a `CASE` **every** branch of which is a
string literal (a `CASE` with no `ELSE` is rejected). Each literal must name a hit table.
`rules/identity/SPW-ID-010.yaml` is the worked example:

```sql
SELECT r.record_key,
       CASE WHEN r.is_ual THEN 'ual_events' ELSE 'admin_audit_events' END AS source_table,
       r.event_time, r.actor_upn, r.ip,
       json_object('signin_id', s.id, 'asn_org', i.asn_org) AS context
FROM rule_events r
JOIN risky_signins s ON …
```

Each `UNION` arm is checked independently, so a three-arm union may name three different tables.

### `$tenant`

A `sql:` rule may reference the parameter `$tenant`; the runner binds it to the tenant being
evaluated. It is **optional** — the tenant scope is *structural*, not a predicate:

- rules execute on a **separate, locked, read-only DuckDB instance** that `ATTACH`es the case file
  `READ_ONLY`;
- before any rule runs, every tenant-aware table is shadowed by a `TEMP VIEW` of the same name
  filtered to that tenant (tables with `tenant_key` filter on it, tables with `collection_id`
  filter on the tenant's collections). DuckDB resolves temp objects before `main`, so a rule that
  reads `ual_events` sees only its tenant's rows;
- because the views replace the tables, a `sql:` rule may **not** schema-qualify a table name
  (that is how it would reach around the view);
- the instance runs with `enable_external_access = false` and `lock_configuration = true`, so
  `read_csv`, `glob`, `ATTACH`, `COPY` and turning external access back on all fail;
- the case's own writer connection is released while the rules run and reopened afterwards.

Evidence of two tenants therefore never combines into one finding, and the tenant predicate is
not something a rule can forget to write.

Only `ip_intel`, `capabilities` and `operation_catalog` are readable: the shared reference data
that is identical for every tenant. A table with neither `collection_id` nor `tenant_key` is
rejected as unreadable.

## `requires`, `requires_evidence`, `needs_geoip`

Three ways a rule can be **not applicable** to a tenant. Every attempt of every rule is recorded in
`detection_runs` with a `reason` — a rule is never silently empty.

| Field | Source | `not_applicable` when | Reason recorded |
| --- | --- | --- | --- |
| `requires` | capability ids from `data/capabilities.yaml` | any one is `not_licensed` in `tenant_capabilities` | `capability identity_protection is not_licensed` |
| `requires_evidence` | evidence ids from `evidence_availability` | any one is `not_licensed` or `not_enabled` | `evidence mail_items_accessed is not_enabled` |
| `needs_geoip: true` | `ip_intel` | none of the tenant's sign-in / UAL / directory-audit / admin-audit IPs has an ASN, a country or a latitude | `no GeoIP data` |

`needs_geoip` is judged **per tenant**, on that tenant's own IPs: `ip_intel` is shared by the case,
so a tenant ingested without `--geoip-dir` (or one whose addresses are all private or unresolved)
has none.

A rule that fails to run is `error` with the message; the other rules still run and still merge
their findings.

A compile error is a **lint** error too, so a broken rule should never reach a run.

## Inline tests

Every rule carries its own fixtures. `sparrow rules test` runs each in a fresh in-memory case with
one collection and the tenant `test`, through the production path (the same locked rule connection
the real run uses).

```yaml
tests:
  - name: New-InboxRule with finance keywords only
    records:
      - table: ual_events
        operation: New-InboxRule
        user_upn: alice@contoso.example
        parameters: {Name: AP, SubjectContainsWords: "Overdue invoice"}
    expect_hits: 1
```

Each `records` entry is `{table: <table>, <column>: <value>, …}`. Columns the entry leaves out get
a neutral default (empty text, `0`, `false`, `2026-01-01T00:00:00Z`, or a seed-derived UUID), so
a fixture states only what it is about. `collection_id` defaults to the tenant's test collection.
An unknown table or column is an error, not a skipped row.

`expect_hits` is the **number of rows the rule returns**, not the number of findings. A threshold
rule that returns the whole window therefore expects the window's size.

**Lint requires at least one test with `expect_hits >= 1` and at least one with `expect_hits == 0`**
(a positive and a look-alike). That is why every rule file above shows a `expect_hits: 0` case: it
is the guard against a rule that fires on everything.

```bash
sparrow rules test                     # every rule
sparrow rules test --rule SPW-HAWK-011 # one rule
```

## The rule hash

`rule_sha256` = SHA-256 over the rule's **normalized form** (its serde JSON, so comments and key
order do not matter) followed by **every static list it references**, sorted, with a
`case_sensitive` / `case_insensitive` marker per list.

Editing a list is therefore a rule change: `SPW-MAIL-003` moves from version 1 to a new
`rule_sha256` when a keyword is added to `finance_keywords`, and every finding it raised is marked
`rule_updated` for re-review. A `sql:` rule's lists are found by scanning the query text for
`@list:`.

`rule_sha256` is written to `detection_runs.rule_sha256` and to the findings the run hit. On a
later run, a finding whose stored hash differs from the current one gets `rule_updated = true` —
including findings the run did **not** hit this time, so a rule change never hides a finding that
is no longer reproducible. Detection never resets `rule_updated`; clearing it is an analyst action.

## `group_by` → findings, and what a re-run does

`findings.finding_id` is the **first 16 hex characters of the fingerprint**, so a re-run finds the
same finding. The fingerprint is

```text
sha256( rule_id 0x1f tenant_key 0x1f value1 0x1f value2 … )
```

with the rule's `group_by` values in order (a NULL value is the single byte `0x00`).

A re-run **merges**, it never rewrites:

- a new trigger record is appended to the finding's `finding_evidence`; an existing
  `(finding, source_table, record_key)` row is not duplicated;
- `first_seen` / `last_seen` only ever widen;
- `severity` and `title` are refreshed from the rule;
- **the analyst's columns are never written**: `status`, `disposition_reason` and `assigned_to`;
- findings are never deleted.

Re-running unchanged rules on unchanged evidence is a **no-op**: no new finding, no updated
finding, no new evidence row.

```console
$ sparrow detect --case case.duckdb
detection: run 1, 27 rule runs (0 not applicable, 0 errors), 33 new findings, 0 updated, 71 evidence rows
$ sparrow detect --case case.duckdb
detection: run 2, 27 rule runs (0 not applicable, 0 errors), 0 new findings, 0 updated, 0 evidence rows
```
## Coverage cross-check

`rules/coverage.yaml` is the matrix of which storyline must (and must not) trigger which rule.
`sparrow rules lint` cross-checks it against the rule files and reports:

- a built-in rule with **no coverage entry** → error;
- a coverage entry with **no rule file yet** → warning (`coverage entry has no rule file yet`);
- `requires` / `requires_evidence` / `needs_geoip` differing from the coverage entry → error;
- the rule's hit table not being the **first** entry of the coverage `tables` → error. For a
  `sql:` rule, every table it emits as `source_table` must be in `tables`, and the first one must
  be among them.

Coverage entries also carry the evidence each rule needs, which is what `sparrow synth coverage`
and the `sparrow synth check` detection gate use:

- `evidence_all_of` — the **evidence halves** a storyline must reach for a hit or no-hit to count.
  A list of groups; reaching any table in a group satisfies that group. Absent, it is one group
  equal to `tables`. Set it for a rule whose logic correlates two kinds of evidence.
- `correlation_negatives` — **required for every rule with `evidence_all_of`**. These are
  look-alike kinds (also listed under `lookalikes`) whose storyline delivers *both* evidence halves
  but fails the rule's **time or actor condition** — both halves are present, the correlation is
  not. The rule must not fire. This is what closes the Phase 5 partial-guard caveat: a guard that
  only proved "the second half was missing" does not prove the join. `sparrow synth coverage`
  reports the gap `correlated rule has no correlation negative` without one.

### `computed`

Some storyline kinds trigger a rule only under facts the generator draws per seed and scenario,
so their outcome cannot be a fixed per-kind `hit`. A stale risky sign-in from a hosting address is
an impossible-travel pair only when the user's seeded home is far enough from it. A stolen session
is visible only where the collector delivers the creating MFA sign-in with its session id. For
those, the rule lists the kind under `computed`, naming the condition the generator evaluates:

```yaml
- id: SPW-ID-004
  …
  computed:
    - kind: inbox_rule_finance
      condition: aitm_indicators
      reason: "the storyline reuses the AiTM sign-in session from another address; it fires only
             where the creating MFA sign-in is delivered with its session id"
```

Per tree, `sparrow-synth`'s `oracle` evaluates the rule's logic over the rows that tree delivers.
Its inputs are:

- the world's events, filtered to the record keys the parsed files load;
- what each collector's rows carry;
- the generated GeoIP locations;
- the shipped data lists;
- the spray sources and cloud services, recomputed from the same rows.

The oracle writes `hit` or `no_hit` into the manifest (`no_evidence` when nothing was delivered),
and the detection gate checks it exactly: a computed `hit` must be found and a computed `no_hit`
must not be.

Each condition models one rule:

- `impossible_travel`: SPW-ID-003;
- `aitm_indicators`: SPW-ID-004;
- `new_network_send`: SPW-MAIL-006;
- `risky_rule_correlation`: SPW-ID-010.

The thresholds are read from the rule's own SQL, so a changed threshold is picked up and a
rewritten rule fails generation instead of drifting. A kind is never both computed and a positive
or look-alike of the same rule.

### `baseline_allow`

The detection gate requires that **every** finding of a rule cite the records of a storyline
whose expected outcome is `hit`: the benign baseline must produce zero findings for every rule.
`baseline_allow` is the escape hatch for a rule that genuinely fires on activity whose outcome
cannot be computed:

```yaml
  baseline_allow:
    - kind: <storyline kind, or `baseline` for background activity>
      reason: "…"
```

`reason` is required, and every entry needs an architect ruling reported to the user. Prefer
`computed`, which checks the outcome exactly; a tolerated finding cannot catch a regression that
adds or drops it. **The shipped matrix has no `baseline_allow` entry**: the former exceptions
(SPW-MAIL-006, SPW-ID-003, SPW-ID-004 and SPW-ID-010) are all computed, and a test keeps it that way.

`rules lint` does **not** list these entries. They are read out of `rules/coverage.yaml` and
enforced by the `sparrow synth check` detection gate.

## Custom rule directories

`--rules DIR` (repeatable) or `SPARROW_RULES` adds a directory to the built-in set. Inside it:

- `**/SPW-*.yaml` and `**/*.rule.yaml` are rules (`lists/` and `schema/` are skipped);
- `lists/*.yaml` overlays a built-in list **or adds a new one** by the same rules — a custom list
  with a built-in name replaces it;
- directories are overlaid in the order given.

A custom rule **adds** to the built-in set. A custom rule whose id matches a built-in
**replaces** it, with a lint warning, so a site can correct a rule without forking the binary:

```console
$ sparrow rules lint --rules ./rules
warning: custom rule SPW-MAIL-003 replaces the built-in rule
```

Because the replacement is a different rule text, its `rule_sha256` differs, and the next run
marks the existing findings `rule_updated` instead of silently re-baselining them:

```console
$ sparrow detect --case case.duckdb --rules ./rules --rule SPW-MAIL-003
detection: run 2, 1 rule runs (0 not applicable, 0 errors), 0 new findings, 1 updated, 0 evidence rows
  warning: custom rule SPW-MAIL-003 replaces the built-in rule
  SPW-MAIL-003   91de958c-e6a3-4936-a34d-e68332c57c1d ran             0 hits
```

(The case is a `bec-aitm` Hawk 4 tree ingested with the **built-in** rules, which left
`SPW-MAIL-003` with one finding — its two hits belong to one actor, and the rule groups by
`actor_upn`. The run above is the first with the replacement, so it updates that finding and adds
none. The numbers are this tree's: a tree where the built-in rule hit two actors would report
`2 updated`, and one where it hit nobody would report `0 updated`.)

Custom rules take part in everything: they run in `sparrow detect`, their inline tests run in
`sparrow rules test`, they are compiled and checked in `sparrow rules lint`, and the detection gate
in `sparrow synth check` uses whichever set ran. A custom rule with **no** coverage entry is not an
error (only built-in rules need one).

`--data DIR` / `SPARROW_DATA` is the equivalent for `data/capabilities.yaml`,
`operation_catalog.yaml` and `ms365_ip_ranges.json`.

## Commands

Every flag below is from `--help`; `--json` is global and works on all of them.

```console
$ sparrow rules lint [--data DIR] [--rules DIR]…   # exit 1 on an error
$ sparrow rules test [--rule ID] [--data DIR] [--rules DIR]…   # exit 1 when a test fails
$ sparrow rules list [--requires CAP] [--tag TAG] [--data DIR] [--rules DIR]…
$ sparrow detect --case CASE [--rule ID]… [--tag TAG]… [--data DIR] [--rules DIR]…
$ sparrow ioc add --case CASE --type T --value V --verdict VERDICT [--note N] [--tenant KEY] [--agent ID] [--analyst NAME]
$ sparrow ioc list --case CASE [--tenant KEY]
$ sparrow ioc set-verdict --case CASE --id ID --verdict VERDICT [--note N] [--agent ID] [--analyst NAME]
$ sparrow ioc remove --case CASE --id ID [--agent ID] [--analyst NAME]
```

`rules lint` reports, per rule: a compile error (column, list, regex, CIDR, threshold, SQL
contract), a missing positive or look-alike test, a `group_by` that is not an output column, and
the coverage cross-check. `rules test` prints one line per fixture
(`ok`/`FAIL`, expected, got, and the error when it failed). `rules list` prints
`id, severity, status, title, [requires …]`.

`ioc add` and `ioc remove` are agent decisions: `--agent` (or `SPARROW_AGENT`, default `unnamed`)
names the agent and `--analyst` (or `SPARROW_ANALYST`, optional) the analyst it acts on behalf of.
`ioc remove` is a soft delete: a rule reads only active indicators.

## Hit tables

A `source:` or a `sources:` arm may only name a table that has a record key, a time and (where it
has one) an actor — the output contract needs all three. The compiler knows the mapping from each
table to `record_key`, `event_time`, `actor_upn` and `ip` in `detect::compile::OUTPUT_COLUMNS`.

`mail_items_accessed` is **not** a hit table: one UAL record fans out into many rows and the table
has no `record_key` of its own. Hit `ual_events` instead — naming it is a compile error that
says so.

## Known gaps

Stated so nothing here reads as finished when it is not:

- **27 of the 31 coverage entries have a rule file.** `SPW-ID-001`, `SPW-FILE-001`,
  `SPW-FILE-002` and `SPW-FILE-003` have no rule file yet; `sparrow rules lint` reports each as
  `coverage entry has no rule file yet`, and `sparrow synth check` counts their expectations as
  unchecked.
- **No built-in rule uses `threshold:`** or reads `@list:case_iocs.*`. Both are implemented and
  tested; no shipped rule needs them yet.
- The `sql` field's description in `rule.schema.json` still says a `sql:` rule "must reference
  `$tenant`". It does not: `$tenant` is available but optional, because the tenant scope is
  structural.

## See also

- [`../README.md`](../README.md) — the CLI, findings and the testing jobs.
- [`../crates/sparrow-synth/README.md`](../crates/sparrow-synth/README.md) — the storyline
  coverage matrix, the detection gate and `sparrow synth conformance`.
- `rules/schema/rule.schema.json` — the JSON Schema.
- `crates/sparrow-core/src/detect/` — the loader, compiler, runner, findings merge, lint and the
  inline-test runner.
