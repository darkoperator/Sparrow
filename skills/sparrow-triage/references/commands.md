# Sparrow recipes: question to command

Every command takes `--case case.duckdb` and `--json`. One command per call. Replace `<UPN>`, `<IP>`, `<ID>`,
`<TABLE>`, `<RECORD_KEY>` with real values. All SQL below was run against a synthetic case; column names come from
`sparrow schema` (see [tables.md](tables.md)). Timestamps print as UTC text.

## Agent bridge (the app has the case open)

Nothing to do: every command that names the case the app has open runs in the app and prints the same output and
exit code. Writes are signed on behalf of the app's analyst (your `--analyst` is replaced, with a note on stderr) and
stay pending review; with no analyst name set in the app they are refused (exit 5). `ingest`, `profile`, `detect`,
`upgrade`, `synth` and `audit verify --acknowledge` are refused (exit 4). A read stops after
`SPARROW_BRIDGE_TIMEOUT` seconds (default 120). `--no-bridge` opens the file directly (exit 4 while the app holds it).

When the bridge cannot serve (the app is importing, or older, or a sandbox blocks it), a read with `--snapshot` reads a
private copy of the case instead (stderr says so, `--json` has `snapshot.taken_at`); writes then wait until the
analyst closes the case or the import ends.

A sandboxed agent needs, once: network access to `localhost` (any port), and read access to the app's
discovery directory: `~/Library/Application Support/Sparrow` (macOS), `~/.local/share/Sparrow` or
`$XDG_DATA_HOME/Sparrow` (Linux), `%LOCALAPPDATA%\Sparrow` (Windows). The error names which one is missing.

## Output shapes

`query` returns rows as arrays aligned with `columns`:

```json
{"columns": ["mailbox", "name"], "rows": [["alice@contoso.example", "."]], "truncated": false}
```

`finding list` returns `{"findings": [ {finding_id, rule_id, severity, title, actor_upn, first_seen, last_seen,
status, evidence_count, ...} ]}`. `finding show` returns `{"finding": {...}, "evidence": [ {source_table,
record_key, role, event_time, source_refs, timeline: {actor_upn, target, ip, ip_country, ip_asn_org, user_agent,
summary, ...}} ], "analyst_guidance": "...", "notes": [], "audit": []}`. With several ids it returns
`{"findings": [...], "missing": [...]}` (at most 50 ids). `pivot` returns `{"sections": [ {name, rows, total,
truncated} ]}`.

## Orientation

| Question | Command |
| --- | --- |
| What evidence is in the case, and what is missing? | `sparrow capabilities --case case.duckdb --json` |
| Tenant, window, row counts, top actors, gaps? | `sparrow summary --case case.duckdb --json` |
| Which accounts have findings, what stages, which addresses? | `sparrow accounts --case case.duckdb --json` |
| Which evidence covers each account, over which dates, and what should I request next? | `sparrow coverage --case case.duckdb --json` |
| What did the attacker read, send or open through each compromised account? | `sparrow access --case case.duckdb --json` |
| Which tables and columns exist? | `sparrow schema --case case.duckdb --json` |
| Columns of one table? | `sparrow schema --case case.duckdb --table signins --json` |
| Ready-made triage queries? | `sparrow notebook list --case case.duckdb --json`, then `sparrow notebook run builtin N --case case.duckdb --json` |

```bash
sparrow capabilities --case case.duckdb --json
sparrow summary --case case.duckdb --json
sparrow accounts --case case.duckdb --json
sparrow accounts --case case.duckdb --limit 5 --json
sparrow coverage --case case.duckdb --json
sparrow coverage --case case.duckdb --user alice@contoso.example --json
sparrow schema --case case.duckdb --json
sparrow schema --case case.duckdb --table signins --json
```

`summary --json` also carries `next` (objects `{"command": "sparrow accounts --case '<case>' --json", "about": "..."}`
with the case path shell-quoted: run `command` as given) and `top_accounts` (up to
3 accounts: upn, tenant_key, worst_severity, stages, first_suspicious, addresses_total) or `top_accounts_unavailable:
<reason>`; `capabilities --json` carries `next` too.

## Evidence coverage

`sparrow coverage` is read-only. Per account (accounts with findings, or only each `--user`) and source (`ual`,
`signins_interactive`, `signins_noninteractive`, `mail_items_accessed`, `message_trace`, `entra_audit`, `mailbox_audit`)
it gives `rows`, `first`, `last`, `days` and `sampled` (rows from a capped export), and `gaps`
(`{from, to, reason}` with reason `absent`, `before`, `after` or `sampled`) against the account's `window`
(30 days before its first finding, to the tenant's last event). No event inside a gap proves nothing. `requests`
lists what to ask for, one per account and source with gaps, with `console` (admin portal), `hawk` and `invictus`
(Microsoft-Extractor-Suite) commands filled in with the user and dates; `null` means that collector has no command for it.

## Investigate one account

When the analyst names an account and a date ("phished on the 23rd"), start here: one call for its sessions (what
each reached), the mail around the window (the lure the day before), config changes and findings' times. The window
is required; widen it with `--pad` or move it as the evidence says.

```bash
sparrow investigate --case case.duckdb --user alice@contoso.example --on 2026-08-21 --pad 12h --json
sparrow investigate --case case.duckdb --user alice@contoso.example --from 2026-08-21T06:00:00Z --to 2026-08-22T00:00:00Z --json
```

Read `sessions[].ips[].new_for_account`, `reach` and `findings`; `next` holds the flag and access commands per
session. Facts only: you decide which session is the attacker's.

## Access report

`sparrow access` is read-only. From the accepted malicious flags (pending agent flags do not count until accepted) it
lists, per compromised account, the items the attacker reached by category (`mail_read`, `mail_sent`, `attachment`,
`file`, `teams`, `copilot`, `other`), each with `attribution` (`session`, `row`, `device`, `ip`, or `time` for records
with no IP and no session inside a window of malicious activity), and per category a tile with `direct`, `by_time`,
`coverage` (the source's status) and `none_seen` (a zero is a finding only when that is true). `--account UPN` limits it;
`--csv FILE` writes one row per item; `--markdown` prints the summary table. Flag the attacker's sessions and IPs first
(`sparrow mark flag`), and have them accepted, or the report is empty. Before review, `--include-pending` counts your
own pending flags and `--ip/--prefix/--session/--device VALUE` asks "what would this reach?" without flagging; such a
report is a PREVIEW (`"preview": true`, every item and scope value has `basis` `pending` or `adhoc`): say so when you
quote it.

```bash
sparrow access --case case.duckdb --account alice@contoso.example --include-pending --brief --json
sparrow access --case case.duckdb --ip 203.0.113.7 --brief --json
sparrow access --case case.duckdb --account alice@contoso.example --category mail_read --limit 50 --json
```

Start with `--brief` (tiles and scope, no items), then page the one category you need with `--category`
(`total` says how many there are; `--offset` for the next page). Each item's `row` is what `mark flag --row` and
`note add` take. The gaps Microsoft never logs are listed once, as `never_logged`.

## Events, entities, marks

`sparrow events` is the Events grid: one row per event record of every event table, with account, IP, device and Entra
session. `sparrow entity` is one account, IP, device or session. Both are read-only.

```bash
sparrow events --case case.duckdb --user alice@contoso.example --from 2026-08-21T00:00:00Z --json
sparrow events --case case.duckdb --ip 203.0.113.7 --where operation=New-InboxRule,Set-InboxRule --limit 50 --json
sparrow events --case case.duckdb --where source=ual --where operation=!MailItemsAccessed --search forward --json
sparrow events --case case.duckdb --session 4f1c8d3e-1111-4222-8333-444455559a2e --json
sparrow events --case case.duckdb --flag malicious --csv events.csv
sparrow entity --case case.duckdb --user alice@contoso.example --json
sparrow entity --case case.duckdb --ip 203.0.113.7 --from 2026-08-21T00:00:00Z --to 2026-08-22T00:00:00Z --json
```

- `events --json` returns `{"rows": [...], "offset": N, "total": N, "total_capped": bool}`; each row has `source_table`,
  `record_key`, `source`, `event_time`, `operation`, `actor_upn`, `owner_upn`, `ip`, `ip_country`, `asn`,
  `device_id`, `device_name`, `entra_session_id`, `finding_count`, `tags` (`[{name, ai}]`), `rules` (rule ids of the
  open findings with the row as evidence), `flag` (`suspicious`,
  `malicious` or null) and `flag_ai` (the flag is an agent's and no analyst has confirmed it). `--limit` defaults to
  200. `source_table` and `record_key` are what `mark` and `note add` take as `TABLE:KEY`.
- `--where FIELD=TEXT` (repeatable). FIELD is `source`, `operation`, `account`, `ip`, `country`, `asn`, `device`,
  `session`, `tag` or `rule` (the rule id of an open finding citing the row). TEXT: comma separates values (any of), `!value` excludes, `*` is a wildcard; a list of only
  excludes means everything except those. A value in double quotes is literal (commas, `*`, a leading `!` included;
  `""` is one quote): `--where 'operation="a,b"'`. A lone `!`, `,,` or an unclosed quote is refused (exit 1), never
  read as "everything".
  Without `*` a value matches exactly. `message_trace_event` rows are left out unless `source` names them.
- `--user`, `--ip`, `--device` and `--session` take one entity per call (two are refused, exit 1): narrow by a second
  one with `--where`, e.g. `--user alice@contoso.example --where ip=203.0.113.7`.
- `--csv PATH` writes every matching row (not a page) and prints the row count.
- `entity --json` returns `{"summary": {entity, first_seen, last_seen, events, distinct, open_findings, roles_matched,
  ip_intel, device}, "pivots": {"ips": {rows, total}, ...}, "findings": [...]}`. An account has the `ips`, `devices`
  and `sessions` pivots; an IP `accounts`, `devices`, `sessions`; a device `accounts`, `ips`, `sessions`,
  `device_changes`; a session `accounts`, `ips`, `devices`. A pivot holds at most 500 rows: compare `rows` with `total`.
  Spellings do not matter: `Alice@Contoso.example` and `alice@contoso.example` are one account.

### Marks: flag, tag, note

```bash
sparrow mark flag --case case.duckdb --row ual_events:<RECORD_KEY> --row signins:<RECORD_KEY> --level suspicious
sparrow mark flag --case case.duckdb --value ip=203.0.113.7 --level malicious
sparrow mark flag --case case.duckdb --value ip_prefix=203.0.113.0/24 --scope account=alice@contoso.example --level suspicious
sparrow mark flag --case case.duckdb --row ual_events:<RECORD_KEY> --level clear
sparrow mark tag --case case.duckdb --row ual_events:<RECORD_KEY> --tag ai:forwarding-rule
sparrow mark tag --case case.duckdb --row ual_events:<RECORD_KEY> --tag ai:forwarding-rule --remove
sparrow mark list --case case.duckdb --pending --agent claude --json
sparrow note add ual_events:<RECORD_KEY> --text "creates the rule 3 minutes after the sign-in" --case case.duckdb
```

- `mark list --pending` lists what still waits for the analyst (`--agent ID` yours only, `--kind flag|tag`): end a
  triage with it so the analyst knows what to review.
- Use `--agent` / `--analyst` (or `$SPARROW_AGENT` / `$SPARROW_ANALYST`) as for every write. Marks are agent
  decisions: they show at once (`flag_ai`, tag `ai: true`) and wait for the analyst to confirm or remove them in
  the app. There is no CLI confirm. Tell the analyst where: flags and tags in the Events grid (tick the rows, then
  Confirm AI marks or Remove AI marks); the indicator a malicious `ip` or `account` flag adds, in the Review queue.
- **Flag** a row or value when it is the attacker's, or you cannot rule it out: `suspicious` for a lead, `malicious`
  for a confirmed attacker IP or account (a malicious `ip` or `account` flag also adds a pending indicator). `--value`
  flags every event with that value, also ones ingested later; `--scope KIND=VALUE` (account, ip, device, session)
  limits it to that entity's events. `--level clear` removes the flag. `--value` kinds: `ip`, `ip_prefix`, `account`,
  `asn`, `device`, `session`.
- **Tag** to group rows under a name for the analyst's filter (`--where tag=ai:forwarding-rule`). An agent may create
  only tags starting `ai:`, or use a tag that already exists; any other new name is refused (exit 5). An agent may
  remove only its own unconfirmed tags.
- **Note** (`note add`) to say why. Flag and tag say what; a note carries the reasoning, so add one to anything you
  flag as malicious.
- A call takes at most 1,000 rows from an agent (use a `--value` flag for more) and writes one audit entry, not one per
  row. A row that does not exist in the case is refused (exit 5); nothing is written. Another writer holding the case
  gives exit 4, as for every write.

## Accounts (the roll-up) and facts

`sparrow accounts` returns `{"accounts": [...], "total": N, "truncated": bool, "warnings": [...]}`. Each account:

```json
{"tenant_key": "...", "upn": "bryce.jacoby@contoso.example", "worst_severity": "high", "finding_count": 24,
 "by_severity": {"high": 16, "medium": 7, "low": 1},
 "stages": ["suspicious_sign_in", "persistence", "mail_access", "sending", "consent", "mfa_change"],
 "first_suspicious": "2026-08-21T09:12:00.000000Z", "rules": ["SPW-ID-002", "SPW-MAIL-004"],
 "signins_first": "2026-08-01T07:00:00.000000Z", "signins_last": "2026-08-25T18:30:00.000000Z",
 "addresses": [{"ip": "203.0.113.4", "reasons": ["finding_evidence", "acts_without_signin", "hosting"],
   "tables": ["ual_events"], "first_seen": "...", "last_seen": "...", "asn": 14061, "asn_org": "DigitalOcean",
   "is_hosting": true, "spray_source": false, "in_user_signins": false}],
 "addresses_total": 3, "addresses_truncated": false}
```

- Order: worst severity, then more stages, then earlier `first_suspicious`, then UPN. `stages` = the union of the
  `stage:` of the rules of the account's findings (suspicious_sign_in, credential_takeover, persistence, mail_access,
  sending, consent, mfa_change), plus `credential_takeover` when an SPW-ID-005 evidence row of the account has context
  `takeover = true` (so that stage can appear with no rule declaring it).
- `addresses` (at most 20, strongest reason first). Reasons:
  - `finding_evidence`: on the evidence rows of one of the account's findings.
  - `acts_without_signin`: the account ACTS from it, at a time inside the account's sign-in window
    (`signins_first` to `signins_last`, inclusive), and no sign-in of the account (any result) ever came from it. An
    account with `signins_first` null has no sign-ins in the case (they were not collected): nothing is compared, so
    no address gets this reason, and its absence says nothing. "Acts"
    means exactly: a `ual_events` record of the account (UserId); a parent-less `mail_items_accessed` row (a
    MailItemsAccessed record is in `ual_events` too); a `mailbox_audit_legacy` OWNER logon on the account's mailbox;
    a `message_trace` row the account SENT (sender only, not received mail). A Microsoft-service address
    (`ip_intel.is_microsoft`) or a private one (RFC 1918, RFC 4193, loopback, link-local) NEVER gets this reason:
    Exchange's own addresses are the origin of much service and message-trace traffic. Such an address can still be
    listed for another reason. Report an `acts_without_signin` address as an attacker candidate.
  - `hosting` (`ip_intel.is_hosting`), `spray_source` (in the tenant's `spray_sources`), `risky_signin` (a sign-in of
    the account from it with sign-in or user risk medium or high, or a `risk_detections` row for the account and
    address): only for an address that appears for the account in a sign-in, an acting table above, a risk detection,
    a directory audit (initiator), an admin audit (caller) or an Azure activity (caller).
  - `in_user_signins` false means no sign-in of this account came from it. An address is a lead, not a verdict: read
    its reasons and its history.
- An empty list with a warning: the case was detected before the roll-up existed, or the enrichment failed or is
  stale. Run `sparrow detect --case case.duckdb` and ask again.

`finding show` adds `facts` for persistence, consent and MFA findings (and a `context` on each evidence row):

```json
{"facts_version": 1, "window_start": "2026-08-11T14:19:03.000000Z",
 "actor_ips": [{"ip": "203.0.113.2", "asn": 20473, "asn_org": "Vultr", "is_hosting": true, "spray_source": false,
   "user_signin_days_before": 1, "user_first_signin": "2026-08-21T09:15:00.000000Z"}],
 "other_signals": {"total": 23, "items": [{"rule_id": "SPW-MAIL-003", "severity": "high", "first_seen": "..."}]},
 "targets": [{"address": "colleague@contoso.example", "domain": "contoso.example", "scope": "internal", "prior_messages": 4},
             {"address": "invoices@exfil-mail.test", "domain": "exfil-mail.test", "scope": "external", "prior_messages": 0}]}
```

- `window_start`: the tenant's first sign-in of any kind. Every "before" is "before, within the capture".
- `user_signin_days_before`: distinct UTC days the finding's actor had a SUCCESSFUL sign-in from that address before
  the evidence event; null = cannot be compared (unknown, never zero). `user_first_signin`: the first such sign-in.
- `other_signals`: the actor's other findings (not this one), at most 5 in finding-list order, with the total.
- `targets` (forwarding findings): every forward, redirect, copy or blind-copy address of the evidence; `scope`
  internal (the actor's own address or a tenant domain) or external. `prior_messages` = message-trace rows between the
  actor and the address before the event. **null = unknown / not comparable**, never zero: the tenant has no message
  trace at all, OR the finding has no actor, OR that evidence has no event time. (Check `capabilities` for the trace
  before you hunt for a missing file: with a trace present, a null means no actor or no time.) List EVERY target of an
  attacker rule, internal ones included.
- `facts_unavailable: <reason>` instead of `facts` means the enrichment is not current: run `sparrow detect`.
- Facts are counter-evidence: "an address used on 9 earlier days" lowers suspicion, "never used before in this capture"
  raises it, neither decides it (see `bec-triage`).

`pivot user` has an `addresses` section: the same list as `accounts` (with `unavailable: <reason>` when the roll-up
is not current).

## Findings

```bash
sparrow finding list --case case.duckdb --json
sparrow finding list --case case.duckdb --severity high --json
sparrow finding list --case case.duckdb --user <UPN> --json
sparrow finding list --case case.duckdb --rule SPW-MAIL-003 --json
sparrow finding list --case case.duckdb --rule SPW-MAIL-003 --rule SPW-MAIL-004 --json
sparrow finding show --case case.duckdb <ID> --json
sparrow finding show --case case.duckdb <ID1> <ID2> <ID3> --json
```

Count findings by rule without listing them:

```bash
sparrow query --case case.duckdb --json "SELECT rule_id, severity, count(*) AS n FROM findings GROUP BY ALL ORDER BY n DESC"
```

Evidence rows of one finding (table, key, role, time):

```bash
sparrow query --case case.duckdb --json "SELECT source_table, record_key, role, event_time FROM finding_evidence WHERE finding_id = '<ID>' ORDER BY event_time"
```

## Persistence sweep (rules, forwarding, consents, MFA, permissions)

One timeline query shows every persistence-type event, with time, actor, target and address:

```bash
sparrow query --case case.duckdb --json --limit 200 "SELECT event_time, category, operation, actor_upn, target, ip, summary FROM timeline WHERE category IN ('mail_rule', 'forwarding', 'app_consent', 'app_credential', 'mfa_change', 'permission') ORDER BY event_time"
```

The state itself:

```bash
sparrow query --case case.duckdb --json --limit 200 "SELECT mailbox, name, forward_to, redirect_to, forward_as_attachment_to, delete_message, mark_as_read, move_to_folder, enabled FROM inbox_rules WHERE forward_to IS NOT NULL OR redirect_to IS NOT NULL OR forward_as_attachment_to IS NOT NULL OR delete_message OR mark_as_read ORDER BY mailbox, name"
sparrow query --case case.duckdb --json "SELECT mailbox, name, move_to_folder FROM inbox_rules WHERE length(trim(name)) <= 2 ORDER BY mailbox"
sparrow query --case case.duckdb --json "SELECT upn, forwarding_smtp_address, forwarding_address, deliver_and_forward FROM mailboxes WHERE forwarding_smtp_address IS NOT NULL OR forwarding_address IS NOT NULL"
sparrow query --case case.duckdb --json --limit 200 "SELECT client_name, client_id, permission, consent_type, principal_upn, risk_category, publisher, verified_publisher, created FROM oauth_grants WHERE permission ILIKE 'Mail%' OR permission ILIKE 'Files%' OR permission ILIKE '%offline_access%' ORDER BY created DESC"
```

Who created a rule, from which address (the audit record, not the state):

```bash
sparrow query --case case.duckdb --json "SELECT event_time, operation, client_ip, object_id, user_agent FROM ual_events WHERE user_upn = '<UPN>' AND operation IN ('New-InboxRule', 'Set-InboxRule', 'UpdateInboxRules', 'Set-Mailbox', 'Consent to application.') ORDER BY event_time"
```

A Hawk 3 case has no sign-in log and keeps Exchange admin commands in `admin_audit_events` (`cmdlet`, `caller`,
`client_ip`, `run_time`).

## One user

```bash
sparrow pivot user <UPN> --case case.duckdb --json
sparrow timeline --case case.duckdb --user <UPN> --from 2026-08-01T00:00:00Z --to 2026-08-31T23:59:59Z --limit 100 --json
sparrow timeline --case case.duckdb --user <UPN> --category mail_rule --json
```

Which networks a user signs in from, with first and last time (the usual network versus a new one):

```bash
sparrow query --case case.duckdb --json "SELECT s.ip, i.country_iso, i.asn, i.asn_org, i.is_hosting, count(*) AS n, min(s.event_time) AS first_seen, max(s.event_time) AS last_seen FROM signins s LEFT JOIN ip_intel i ON i.ip = s.ip WHERE s.user_upn = '<UPN>' AND s.error_code = 0 GROUP BY ALL ORDER BY first_seen"
```

Mail reads by address (a burst from an unusual address is a signal; a Sync from the user's device is not):

```bash
sparrow query --case case.duckdb --json "SELECT client_ip, count(*) AS n, min(event_time) AS first_seen, max(event_time) AS last_seen FROM ual_events WHERE user_upn = '<UPN>' AND operation = 'MailItemsAccessed' GROUP BY client_ip ORDER BY n DESC"
```

## One address

```bash
sparrow pivot ip <IP> --case case.duckdb --json
sparrow timeline --case case.duckdb --ip <IP> --limit 100 --json
```

Who signed in, who failed, who succeeded from an address (spray versus office NAT):

```bash
sparrow query --case case.duckdb --json "SELECT user_upn, count(*) FILTER (WHERE error_code = 0) AS ok, count(*) FILTER (WHERE error_code <> 0) AS failed FROM signins WHERE ip = '<IP>' GROUP BY user_upn ORDER BY failed DESC"
```

First time the case sees an address:

```bash
sparrow query --case case.duckdb --json "SELECT min(event_time) AS first_seen, count(*) AS n FROM timeline WHERE ip = '<IP>'"
```

## Takeover and session signals

Sessions used from more than one address (AiTM and replay candidates):

```bash
sparrow query --case case.duckdb --json --limit 100 "SELECT session_id, count(DISTINCT ip) AS ips, min(event_time) AS first_seen, max(event_time) AS last_seen, list(DISTINCT ip) AS addresses FROM signins WHERE session_id IS NOT NULL GROUP BY session_id HAVING count(DISTINCT ip) > 1 ORDER BY first_seen"
```

Spray sources the profile found (address, users targeted, how many were taken over):

```bash
sparrow query --case case.duckdb --json "SELECT ip, users_targeted, failures, failed_only_users, success_users, takeover_users, first_failure FROM spray_sources ORDER BY sprayed_users DESC"
```

Addresses with credential failures across many users, even when no source was flagged:

```bash
sparrow query --case case.duckdb --json --limit 50 "SELECT ip, count(DISTINCT user_upn) AS users, count(*) AS failures FROM signins WHERE error_code IN (50126, 50053, 50057, 50034) GROUP BY ip ORDER BY users DESC"
```

## Testing a look-alike (counter-evidence, not a verdict)

Is an application a tenant-wide cloud service (a SaaS connector on a hosting ASN)? Listed services:

```bash
sparrow query --case case.duckdb --json "SELECT app_id, asn, hosting_users, hosting_days FROM cloud_services ORDER BY hosting_users DESC"
```

Applications many users sign in to from one address or ASN (a connector or a shared egress):

```bash
sparrow query --case case.duckdb --json --limit 50 "SELECT app_name, app_id, ip, count(DISTINCT user_upn) AS users, count(*) AS n FROM signins WHERE error_code = 0 GROUP BY ALL HAVING count(DISTINCT user_upn) >= 5 ORDER BY users DESC"
```

Is an address hosting, Microsoft, private, in which country and ASN?

```bash
sparrow query --case case.duckdb --json "SELECT ip, country_iso, city, asn, asn_org, is_hosting, is_microsoft, is_private FROM ip_intel WHERE ip = '<IP>'"
```

## Source check

```bash
sparrow verify --case case.duckdb <TABLE> <RECORD_KEY> --json
```

Use the `source_table` and `record_key` of a finding's evidence row. The answer shows whether the original file
lines still match the stored record.

## Notebooks

The built-in notebook holds twelve triage queries (sign-ins by country, IPs shared by accounts, hosting sign-ins,
forwarding rules, risky OAuth grants, new MFA methods and roles, what one IP touched, ...). `run` refuses a query that
still holds a `[placeholder]` (exit 1): read it with `show`, fill the value in and run the SQL with `sparrow query`. A
query worth keeping for the analyst goes into a case notebook with `add` (an agent decision, never pending review);
agents cannot rename, reorder or delete.

- Open it with a `--` comment block: the first line is its title in the analyst's list, the rest says what it finds.
- Write case values as placeholders (`actor_upn = lower('[account]')`, `ip = '[ip]'`), not this case's UPNs and IPs:
  the query then serves other cases, and `notebook export` refuses (exit 5) a notebook holding this case's values.
- Bracket text the SQL really looks for reads as a placeholder (`LIKE '%[EXTERNAL]%'` is saved, then refused on run):
  split the string after the bracket, `LIKE '%[' || 'EXTERNAL]%'`. The refusal says so too.

```bash
sparrow notebook list --case case.duckdb --json
sparrow notebook run builtin 8 --case case.duckdb --json --limit 100
sparrow notebook show builtin 12 --case case.duckdb
sparrow notebook add --case case.duckdb --notebook "Agent queries" --create --file query.sql --agent claude
```
