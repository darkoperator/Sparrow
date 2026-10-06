---
name: sparrow-triage
description: Triage a Microsoft 365 business email compromise with the Sparrow CLI over an ingested case database (DuckDB) - efficient command workflow from capabilities and summary to findings, pivots, read-only SQL and source verification, with the traps that waste turns (guessed column names, shell loops, piping JSON). Use when a case.duckdb exists or collector output (Hawk, Microsoft-Extractor-Suite, portal exports) was ingested with sparrow, and you must find compromised accounts, attacker IPs, malicious inbox rules, forwarding or OAuth apps, or confirm a finding is benign. Pairs with the bec-triage playbook.
license: MIT
metadata:
  scope: sparrow-cli-m365-bec
  requires: sparrow
---

# Sparrow triage workflow

How to do an M365 BEC triage efficiently with `sparrow`. For WHAT counts as a compromise and how to clear the
benign look-alikes, read the `bec-triage` skill first (or alongside); this skill is the tool side.

Every command takes `--case case.duckdb` and `--json`. Use `--json` always: you get small, parseable answers.
Replace `case.duckdb` with the case file and the `<PLACEHOLDERS>` with real values.

References (load when needed):
- [references/commands.md](references/commands.md): question to exact command, with output shapes and ready SQL.
- [references/tables.md](references/tables.md): the key tables and their real columns.

## Rules for this tool

1. **One command per call.** No `for`/`while` loops, no `$(...)`, no `jq` pipelines, no `;` chains. They are denied
   in many sandboxes and waste a turn. Need several things? Use a filter, a SQL `IN (...)`, or `finding show` with
   several ids, or just call the command again.
2. **Never guess a table or column.** Look it up: `sparrow schema` is the source of truth (below). A guessed column
   gives a SQL error and a lost turn.
3. **Do not re-run `finding list --json` and filter it.** Filter at the source (`--severity`, `--rule`, `--user`) or
   query the `findings` table.
4. **Do not stop without the answer.** If you have about five turns left, write the answer you have.
5. **Read-only unless asked.** `finding set-status`, `ioc add`, `note add` and `timeline-entry` write agent decisions
   into the case. Do not run them unless the task asks you to record a decision.

## The workflow

1. **What does the case hold?**

```bash
sparrow capabilities --case case.duckdb --json
sparrow summary --case case.duckdb --json
```

   `capabilities` has two lists per tenant: `capabilities` (licences and features, with a `status` such as
   licensed or not_licensed and the `basis`) and `evidence` (each source such as the unified audit log, sign-ins or
   mailbox rules, with a `status` of collected, partial, available_not_collected, not_licensed, not_enabled or unknown,
   a `reason`, the row count and the time range). A source that was not collected, or whose licence or audit setting
   stops it, means the rules that need it cannot fire: that is a gap, not a clean result. `summary` gives the
   tenant, the collections, the first and last event per table (`coverage`), row counts, the top actors and the
   `gaps`. Note the window: a capture is a time window.

2. **What did the detections find?**

```bash
sparrow finding list --case case.duckdb --severity high --json
sparrow finding list --case case.duckdb --user <UPN> --json
```

   Each finding has `finding_id`, `rule_id`, `severity`, `title`, `actor_upn`, `first_seen`, `last_seen`, `status`
   and `evidence_count`. High findings first, then medium. A finding is a lead, not a verdict: several rules fire on
   benign look-alikes (a connector's hosting sign-ins, a user's own filing rule).

3. **Read the findings that matter.**

```bash
sparrow finding show --case case.duckdb <ID> --json
sparrow finding show --case case.duckdb <ID1> <ID2> <ID3> --json
```

   `evidence[]` has `source_table`, `record_key`, `event_time`, `source_refs` (file and line) and a `timeline` object
   with the actor, target, IP, country, ASN organisation, user agent and a summary. `analyst_guidance` tells you what
   to check and what the known false positives are. Read the guidance.

4. **Pivot on each lead.**

```bash
sparrow pivot user <UPN> --case case.duckdb --json
sparrow pivot ip <IP> --case case.duckdb --json
```

   `pivot user` returns sections: identity, directory, roles, mfa, timeline, findings, indicators. `pivot ip` returns
   ip_intel (country, ASN, hosting), spray_source, timeline, findings, indicators. Each section has `rows`, `total` and
   `truncated`; raise `--cap` only when you need more than 50 rows of one section.

5. **Check the persistence state with SQL** (rules, forwarding, consents). `finding show` points at the record; the
   state itself is in tables. Ready queries are in [references/commands.md](references/commands.md).

```bash
sparrow query --case case.duckdb --json --limit 100 "SELECT mailbox, name, forward_to, redirect_to, delete_message, mark_as_read, move_to_folder FROM inbox_rules WHERE forward_to IS NOT NULL OR redirect_to IS NOT NULL OR delete_message OR mark_as_read ORDER BY mailbox, name"
```

6. **Try to clear every suspect.** Use the look-alike list of `bec-triage`. In Sparrow: is the application a
   `cloud_services` row (a connector)? Is the address in `spray_sources` or an office shared by many users? Does the
   rule come from the owner's usual network (`ual_events.client_ip`)? Query for it; do not assume.

7. **Verify what you will cite.** `sparrow verify` re-reads the original source file lines of a record:

```bash
sparrow verify --case case.duckdb <TABLE> <RECORD_KEY> --json
```

8. **Answer.** Follow the output format the task asks for. Name an account only with evidence, list what you cleared
   and why, and say what you could not check.

## Look up columns instead of guessing

```bash
sparrow schema --case case.duckdb --json
sparrow schema --case case.duckdb --table signins --json
```

The first lists every table with its comment; the second one table with its columns, types and comments. The
common tables are summarised in [references/tables.md](references/tables.md); the command is the authority.
Timestamps are UTC. Array columns (`forward_to`, `auth_methods`) are lists: test them with `IS NOT NULL` or
`list_contains(forward_to, 'x@example.com')`.

## Traps

- `query` accepts ONE `SELECT` (or `WITH ... SELECT`). No `;` second statement, no `PRAGMA`, no file functions. A
  refusal exits 1.
- `query --limit` defaults to 1000 rows; the JSON has `"truncated": true` when it cut. A truncated answer does not
  prove absence: narrow the query (a user, a time range, a `GROUP BY`) instead of raising the limit.
- Query rows come back as arrays aligned with `columns`, not objects.
- A finding's `actor_upn` is the first actor among its hits. Other accounts may be in the evidence: look at the
  `timeline.actor_upn` of each evidence row and at the sessions, not only at the title.
- `finding show` plain output prints 50 evidence rows; `--json` always has all of them.
- `ip` columns are text. Compare with quotes: `WHERE ip = '203.0.113.7'`. IPv6 is lower-case and compressed.
- `signins.error_code = 0` is success; 50126 is an invalid password. `signins.location` and `device` are structs.
- Some sources do not exist in every capture (no sign-in log, no unified audit log). Check `capabilities` before you
  conclude that something did not happen.
- Do not paste whole tables into your reasoning. Query counts and the few rows you need.

## Recording decisions (only if asked)

```bash
sparrow finding set-status --case case.duckdb <ID> confirmed --reason "attacker session, rule from the same address" --agent triage
sparrow ioc add --case case.duckdb --type ip --value 203.0.113.7 --verdict malicious --note "takeover address" --agent triage
```

These are agent decisions: each is recorded in the audit trail as pending review. `--reason` is required for
confirmed, false_positive and benign.
