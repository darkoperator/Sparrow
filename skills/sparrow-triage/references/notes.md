# Notes: scope, traps, verification, decisions

## Reading `capabilities` and `summary`

`capabilities` has two lists per tenant: `capabilities` (licences and features, with a `status` such as licensed or
not_licensed and the `basis`) and `evidence` (each source such as the unified audit log, sign-ins or mailbox rules,
with a `status` of collected, partial, available_not_collected, not_licensed, not_enabled or unknown, a `reason`,
the row count and the time range). A source that was not collected, or whose licence or audit setting stops it,
means the rules that need it cannot fire: that is a gap, not a clean result. `summary` gives the tenant, the
collections, the first and last event per table (`coverage`), row counts, the top actors and the `gaps`. A capture
is a time window.

## Findings, show and pivot shapes

- A finding has `finding_id`, `rule_id`, `severity`, `title`, `actor_upn`, `first_seen`, `last_seen`, `status` and
  `evidence_count`. A finding is a lead, not a verdict: several rules fire on benign look-alikes (a connector's
  hosting sign-ins, a user's own filing rule). A look-alike is counter-evidence, not clearance: see `bec-triage`.
- `finding show` evidence rows have `source_table`, `record_key`, `event_time`, `source_refs` (file and line) and a
  `timeline` object. Several ids return `{"findings": [...], "missing": [...]}`. Plain output prints 50 evidence rows;
  `--json` has all of them.
- `pivot user` returns sections identity, directory, roles, mfa, timeline, findings, indicators. `pivot ip` returns
  ip_intel (country, ASN, hosting), spray_source, timeline, findings, indicators. Each section has `rows`, `total`
  and `truncated`; raise `--cap` only when you need more than 50 rows of one section.

## Traps

- `query` accepts ONE `SELECT` (or `WITH ... SELECT`). No `;` second statement, no `PRAGMA`, no file functions. A
  refusal exits 1.
- `query --limit` defaults to 1000 rows; the JSON has `"truncated": true` when it cut. A truncated answer does not
  prove absence: narrow the query (a user, a time range, a `GROUP BY`) instead of raising the limit.
- Query rows come back as arrays aligned with `columns`, not objects.
- A finding's `actor_upn` is the first actor among its hits. Other accounts may be in the evidence: look at the
  `timeline.actor_upn` of each evidence row and at the sessions, not only at the title.
- IPv6 is lower-case and compressed. `signins.location` and `device` are structs.
- Some sources do not exist in every capture (no sign-in log, no unified audit log). Check `capabilities` before you
  conclude that something did not happen.
- Do not paste whole tables into your reasoning. Query counts and the few rows you need.

## Checking a suspect against Sparrow data

Is the application a `cloud_services` row (a possible connector)? Is the address in `spray_sources` or an office
shared by many users? Does a rule come from the owner's usual network (`ual_events.client_ip`)? Query for it; do not
assume. These are counter-evidence only: apply the extended check of `bec-triage` just to accounts whose evidence is
mixed.

## Verify a record against its source file

```bash
sparrow verify --case case.duckdb <TABLE> <RECORD_KEY> --json
```

Use the `source_table` and `record_key` of a finding's evidence row.

## Recording decisions (only if the task asks)

```bash
sparrow finding set-status --case case.duckdb <ID> confirmed --reason "attacker session, rule from the same address" --agent triage
sparrow ioc add --case case.duckdb --type ip --value 203.0.113.7 --verdict malicious --note "takeover address" --agent triage
```

`finding set-status`, `ioc add`, `note add` and `timeline-entry` write agent decisions into the audit trail as
pending review. `--reason` is required for confirmed, false_positive and benign. Do not run them otherwise.
