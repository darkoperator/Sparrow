# Adding a detection rule

The steps for a new seed rule in `rules/`, in order. Each step ends on the check that says it is done. `docs/RULES.md` is the rule reference (format, fields, the per-rule sections); this file is the workflow and the gotchas the code does not confess.

## 1. Write the rule file

`rules/<category>/SPW-<CAT>-NNN.yaml`, with `status: experimental` and `version: 1`, plus `analyst_guidance`, `false_positives`, and `mitre`.

- **Stage**: `stage:` must be one of the values in `rules/schema/rule.schema.json` (`$defs.stage`). The schema has no `initial_access`. A rule whose hits are not a compromise of the recipient (inbound mail, like SPW-HAWK-014 and SPW-MAIL-009) has no `stage:` and is added to the stageless list in `crates/sparrow-core/tests/detect_compile.rs`. Every finding of medium or higher still moves the account's `first_suspicious`, staged or not.
- **UAL SQL**: write a CTE over `ual_events` with `lower(operation) IN (...)` and read fields with `json_extract_string(audit_data, '$.Field')`. Read lists with `from_json(json_extract(...), '["VARCHAR"]')`. Static lists are `@list:name`, used inside `list_filter(@list:name, k -> ...)`.
- **Matching**: match free text on word boundaries with regex-escaped keywords (`ach` must not match `attached`). Compare UPNs with `lower(trim(...))`. Group session ids on the whole value, never on a prefix.
- **System actors**: exclude them with `user_type = 4 OR user_upn ILIKE 'NT AUTHORITY%' OR user_upn ILIKE 'S-1-5-%'`.
- **Scale**: a join between two sets of distinct values (domains, IPs, users) needs a key that bounds it, such as an equi-join or a blocking key. The synthetic cases hold tens of values and real cases hold tens of thousands, so time the query on 10,000+ distinct values with the `duckdb` CLI before you finish.

Done when: the rule has at least 1 positive and 2 negative inline tests, and each guard has been removed once to confirm a test goes red. `sparrow rules lint` reports 0 errors.

## 2. Add the coverage entry

Add an entry to `rules/coverage.yaml`. The header of that file defines the fields: `positives`, `lookalikes`, `computed`, `baseline_allow`, `collectors`, `requires_evidence`.

- `collectors` lists only the collectors that deliver the rule's tables. Add a comment naming the reason for each collector left out.
- A rule with `requires_evidence: [ual]` needs a positive in a scenario where UAL is off (`audit-tamper`).
- An existing storyline that legitimately fires the new rule is declared `computed`, with an oracle condition in `crates/sparrow-synth/src/oracle.rs`. That condition re-implements the rule in Rust over the delivered rows, and it reads only the rule's thresholds, not its SQL.

Done when: the synth coverage test (`sparrow-synth --test coverage`) passes. The rule count asserts read the rule files, so no count needs editing. The README counts are checked by `readme_rule_counts_match_the_rule_files` in `crates/sparrow-cli/tests/cli.rs`.

## 3. Write the storylines

Register the positive and look-alike kinds in `story_kind!` in `crates/sparrow-synth/src/scenario.rs`. Write the emitters in `src/story/<area>.rs` and place them in a scenario YAML (`scenarios/bec-aitm.yaml`).

- **Reuse an actor already in the victim set** (`compute_victims` in `src/world.rs`) or one already storylined. A new victim actor changes every collector's population, which changes record counts and report sections across every golden.
- Use fixed documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and `.example` domains. Shared pools such as `ctx.shared.next_ip()` shift every later draw.

Done when: `sparrow-synth --test detect_gate` and `--test coverage` pass.

## 4. Re-record the goldens

Run the affected test binaries once with `SPARROW_RECORD_GOLDEN=1`: `coverage_golden`, `export_formats` and `perf_equivalence`. Then read every changed golden file.

- Each delta must trace to the new rule or its storylines. That means added rows, one finding per hit, `other_signals` cross-links, and an account's window moving because of a new earlier finding. A delta you cannot trace is a regression, not a golden to keep.
- `crates/sparrow-synth/tests/detect_stable.rs` pins digests that include every rule's `rule_sha256`. Edit those pins by hand, and only after checking that the digest with the new rule's rows removed (or with the old hash swapped back) equals the old pin.

Done when: every changed golden file and field is listed in the commit body, with the account names and numbers checked against the diff.

## 5. Document and run the suite

Add a row to the rule table in `docs/RULES.md` and a section for the rule.

Fast loop while iterating:

```
scripts/test-summary.sh -p sparrow-core --test detect_compile shipped_rule_samples
scripts/test-summary.sh -p sparrow-synth --test coverage
scripts/test-summary.sh -p sparrow-synth --test detect_stable
```

Then run the full suite once before committing: `scripts/test-summary.sh --workspace`.

Done when: the full suite has 0 failures and `sparrow rules lint` reports 0 errors.
