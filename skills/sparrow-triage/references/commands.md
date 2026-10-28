# Sparrow recipes: question to command

Every command takes `--case case.duckdb` and `--json`. One command per call. Replace `<UPN>`, `<IP>`, `<ID>`,
`<TABLE>`, `<RECORD_KEY>` with real values. All SQL below was run against a synthetic case; column names come from
`sparrow schema` (see [tables.md](tables.md)). Timestamps print as UTC text.

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
| Which tables and columns exist? | `sparrow schema --case case.duckdb --json` |
| Columns of one table? | `sparrow schema --case case.duckdb --table signins --json` |

```bash
sparrow capabilities --case case.duckdb --json
sparrow summary --case case.duckdb --json
sparrow accounts --case case.duckdb --json
sparrow accounts --case case.duckdb --limit 5 --json
sparrow schema --case case.duckdb --json
sparrow schema --case case.duckdb --table signins --json
```

`summary --json` also carries `next` (objects `{"command": "sparrow accounts --case '<case>' --json", "about": "..."}`
with the case path shell-quoted: run `command` as given) and `top_accounts` (up to
3 accounts: upn, tenant_key, worst_severity, stages, first_suspicious, addresses_total) or `top_accounts_unavailable:
<reason>`; `capabilities --json` carries `next` too.

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
