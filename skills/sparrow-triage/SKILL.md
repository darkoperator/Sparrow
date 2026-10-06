---
name: sparrow-triage
description: Triage a Microsoft 365 business email compromise with the Sparrow CLI over an ingested case database (DuckDB) - efficient command workflow from capabilities and summary to findings, pivots, read-only SQL and source verification, with the traps that waste turns (guessed column names, shell loops, piping JSON). Use when a case.duckdb exists or collector output (Hawk, Microsoft-Extractor-Suite, portal exports) was ingested with sparrow, and you must find compromised accounts, attacker IPs, malicious inbox rules, forwarding or OAuth apps, or confirm a finding is benign. Pairs with the bec-triage playbook.
license: MIT
metadata:
  scope: sparrow-cli-m365-bec
  requires: sparrow
---

# Sparrow triage: fast path

Triage an M365 BEC with `sparrow`. FEWER COMMANDS is the goal: every call re-sends the whole conversation. Every
command takes `--case case.duckdb` and `--json` (always use `--json`). One command per call: no `for` loops, no
`$(...)`, no `jq` pipes, no `;` chains. A typical case needs 10-20 commands; **if you are past 25, stop exploring
and answer with what the evidence shows.** What counts as a compromise and when to dig deeper is in the
`bec-triage` skill.

## Fast path

1. **Scope** (one call each):

```bash
sparrow capabilities --case case.duckdb --json
sparrow summary --case case.duckdb --json
```

2. **Findings.** `--severity` is a minimum: `medium` returns critical, high and medium.

```bash
sparrow finding list --case case.duckdb --severity medium --json
```

3. **Read them ALL in one call** (up to 50 ids). Each finding's `evidence[].timeline` has the actor, target, IP,
   country, ASN organisation, user agent and summary; `analyst_guidance` names the known false positives.

```bash
sparrow finding show --case case.duckdb <ID1> <ID2> <ID3> --json
```

4. **Group by account** (the finding's `actor_upn` and each evidence row's `timeline.actor_upn`). Decide per account
   using the table in `bec-triage`: clear attacker evidence, name it; no attacker signal, leave it; mixed, check.
5. **Only for an account you will NAME or CLEAR as borderline**, one pivot (and `pivot ip` for an address shared by
   several accounts):

```bash
sparrow pivot user <UPN> --case case.duckdb --json
sparrow pivot ip <IP> --case case.duckdb --json
```

6. **SQL only for what no finding shows** (the state of a rule, a forward target, a consent). Look up columns
   first; never `SELECT *` to discover them:

```bash
sparrow schema --case case.duckdb --table inbox_rules --json
sparrow query --case case.duckdb --json --limit 100 "SELECT mailbox, name, forward_to, redirect_to, delete_message, mark_as_read, move_to_folder FROM inbox_rules WHERE forward_to IS NOT NULL OR redirect_to IS NOT NULL OR delete_message OR mark_as_read ORDER BY mailbox, name"
```

7. **Write the answer** in the format the task asks for. Name an account only with evidence, say what you cleared
   in one line each, and what you could not check. Never stop without the answer.

Prefer a finding's evidence to ad-hoc SQL. Never re-run `finding list` to filter it: use `--severity`, `--rule`,
`--user`.

## Column cheat-sheet (real names; `sparrow schema --table T --json` is the authority)

- **signins**: event_time, user_upn, app_id, app_name, ip, asn, user_agent, client_app, status, error_code (0 =
  success, 50126 = invalid password), risk_level_during, risk_state, auth_requirement, session_id, is_interactive,
  location (struct), device (struct).
- **ual_events**: event_time, operation (New-InboxRule, UpdateInboxRules, MailItemsAccessed, Consent to
  application., ...), user_upn, mailbox_upn, client_ip, user_agent, session_id, app_id, object_id, result_status,
  parameters (map, e.g. `parameters['ForwardTo']`).
- **inbox_rules**: mailbox, name, enabled, forward_to[], redirect_to[], forward_as_attachment_to[], delete_message,
  mark_as_read, move_to_folder, subject_or_body_contains[], from_addresses[]. The state has no creator or time: use
  `ual_events` for those.
- **mailboxes**: upn, primary_smtp_address, forwarding_smtp_address, forwarding_address, deliver_and_forward.
  (`forward_to` is NOT here: it is in `inbox_rules`.)
- **oauth_grants**: client_id, client_name, permission, consent_type, principal_upn, principal_name, publisher,
  verified_publisher, risk_category, created. (NOT `app_id` / `app_name`.)

Arrays (`[]`) are lists: `forward_to IS NOT NULL`, `list_contains(forward_to, 'x@example.com')`. `ip` columns are
text: `WHERE ip = '203.0.113.7'`. Times are UTC. Other tables: [references/tables.md](references/tables.md).

## References (load only when the fast path is not enough)

- [references/commands.md](references/commands.md): question to exact command, output shapes and ready SQL
  (persistence sweep, one user, one address, sessions, spray, connectors).
- [references/tables.md](references/tables.md): the key tables and their columns.
- [references/notes.md](references/notes.md): reading `capabilities` and `summary`, traps, source verification,
  recording decisions.
