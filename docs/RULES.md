# Detection rules reference

Every built-in detection rule Sparrow ships: what it matches, what evidence it reads, when it cannot
run, how to triage a finding and its known false positives. Use it as a lookup while reviewing
findings.

This page describes the rules. For the rule **file format** (operators, `@list:`, the `sql:`
contract, `threshold:`, inline tests, custom rule directories), see
[`rules/README.md`](../rules/README.md). For how detection runs and how findings are merged, see
[Detection in REFERENCE.md](REFERENCE.md#detection).

The source of truth is the rule files under `rules/` (the logic) and `rules/coverage.yaml` (the
intended behaviour and test matrix). If this page and a rule file disagree, the rule file wins.

## Contents

- [Reading this page](#reading-this-page)
- [Shared concepts](#shared-concepts)
- [Summary table](#summary-table)
- [Mail](#mail)
- [Identity and sign-ins](#identity-and-sign-ins)
- [Applications and consent](#applications-and-consent)
- [Tenant configuration](#tenant-configuration)
- [Files and sharing](#files-and-sharing)
- [Hawk parity rules](#hawk-parity-rules)
- [Static lists](#static-lists)
- [Running a subset of rules](#running-a-subset-of-rules)

## Reading this page

Each rule entry lists:

| Field | Meaning |
| --- | --- |
| **Severity / confidence** | `info` · `low` · `medium` · `high` · `critical`. Confidence is how often a hit is malicious. |
| **Stage** | The attack stage(s) a finding stands for: `suspicious_sign_in`, `persistence`, `mail_access`, `sending`, `consent`, `mfa_change` (`credential_takeover` is derived from SPW-ID-005). The account roll-up uses it. It does not change detection. |
| **MITRE** | ATT&CK technique ids. |
| **Reads** | The evidence tables the rule looks at. The first one is usually where the hit lands. |
| **Finding per** | The `group_by` key: hits with the same key update one finding instead of creating new ones. |
| **Needs** | Conditions that make the rule `not_applicable` for a tenant (with a recorded reason) instead of running empty. |

When a rule is **not applicable**:

- `requires: [identity_protection]`: the tenant's Entra ID Protection capability is `not_licensed`.
- `requires_evidence: [x]`: the evidence source `x` (for example `ual`, `signins`,
  `mail_items_accessed`, `mail_send`, `search_queries`) is `not_licensed` or `not_enabled`.
- **GeoIP**: none of the tenant's addresses has an ASN, country or location. Ingest with
  `--geoip-dir` to enable these rules.
- **≥ 5 sign-in users**: the sign-ins cover fewer than 5 distinct users. A password spray cannot be
  told apart from one user's mistakes without that population.

`sparrow detect` prints one line per (rule, tenant). `detection_runs` in the case records the
outcome and reason for every rule.

## Shared concepts

Several correlation rules rely on facts the profile step computes once per case:

- **Hosting ASN**: an address whose autonomous system is in
  [`rules/lists/hosting_asns.yaml`](../rules/lists/hosting_asns.yaml) (cloud, VPS and hosting
  providers). Microsoft AS8075 and Cloudflare AS13335 are deliberately absent.
- **Microsoft service address** (`ip_intel.is_microsoft`): Microsoft 365 service ranges. Rules
  that compare networks ignore these, because the Exchange back end and Graph show up there.
- **Password-spray source** (`spray_sources`): an address with interactive credential failures
  (see [`credential_failure_codes`](#static-lists)) against at least 5 users, where the
  sprayed users outnumber the users who signed in successfully from it. Because of this, an office
  NAT or VPN egress is not counted as a source.
- **Tenant-wide cloud service** (`cloud_services`): an (application, hosting ASN) pair seen with at
  least 5 users on at least 3 days, carrying at least 80 % of the application's successful
  sign-ins. These are SaaS connectors signing in from their own back end. Their sign-ins to that
  application from that ASN are excused by SPW-ID-002, SPW-ID-003 and SPW-ID-010. A pair is
  never a service when sprayed users make up ≥ 20 % (or ≥ 3) of its users, or when ≥ 3 users had
  an interactive credential failure to it from that ASN. A Microsoft first-party application
  ([`microsoft_first_party_apps`](#static-lists)) is never a service.
- **Successful sign-in**: a `signins` row with `error_code` 0 or NULL, or a UAL `UserLoggedIn`
  that is not `Failed`. SPW-ID-005 is the exception: it ignores NULL results.
- **Collection window**: the start and end of the capture (`collections.window_start` /
  `window_end`). Captures are time windows, so "first seen" means first seen in this case.

## Summary table

| ID | Title | Sev. | Conf. | Stage | Needs |
| --- | --- | --- | --- | --- | --- |
| [SPW-MAIL-003](#spw-mail-003) | Inbox rule with finance keywords or a hiding folder | high | medium | persistence | |
| [SPW-MAIL-004](#spw-mail-004) | External forwarding through the mailbox, an inbox rule or a transport rule | high | medium | persistence | |
| [SPW-MAIL-005](#spw-mail-005) | MailItemsAccessed bind burst | high | medium | mail_access | evidence `mail_items_accessed` |
| [SPW-MAIL-006](#spw-mail-006) | Mail sent from an IP address the user never used before | medium | low | sending | evidence `mail_send` |
| [SPW-MAIL-007](#spw-mail-007) | Mailbox or SharePoint search for finance keywords | medium | medium | mail_access | evidence `search_queries` |
| [SPW-MAIL-008](#spw-mail-008) | Mail deleted by a delegate from an unusual network or with a finance subject | high | medium | mail_access | evidence `ual` |
| [SPW-HAWK-014](#spw-hawk-014) | Message header sender mismatch or failed / anonymous authentication | medium | medium | — | |
| [SPW-ID-001](#spw-id-001) | MFA method registered after a risky sign-in | high | medium | suspicious_sign_in, mfa_change | GeoIP |
| [SPW-ID-002](#spw-id-002) | Sign-in from a hosting-provider ASN | medium | medium | suspicious_sign_in | GeoIP |
| [SPW-ID-003](#spw-id-003) | Impossible travel | medium | low | suspicious_sign_in | GeoIP |
| [SPW-ID-004](#spw-id-004) | Adversary-in-the-middle indicators | high | medium | suspicious_sign_in | |
| [SPW-ID-005](#spw-id-005) | Successful sign-in from a password-spray source | high | medium | suspicious_sign_in | ≥ 5 sign-in users |
| [SPW-ID-006](#spw-id-006) | Password spray against the tenant | low | high | — | ≥ 5 sign-in users |
| [SPW-ID-007](#spw-id-007) | Persistence within 60 minutes of the first sign-in from a new same-country network | high | medium | suspicious_sign_in, persistence | GeoIP |
| [SPW-ID-010](#spw-id-010) | Inbox rule created within 60 minutes of a risky or hosting-ASN sign-in | high | medium | suspicious_sign_in, persistence | GeoIP |
| [SPW-ID-011](#spw-id-011) | Refresh-token replay after revocation | high | medium | persistence | GeoIP |
| [SPW-HAWK-008](#spw-hawk-008) | Risky or confirmed-compromised user | high | medium | — | capability `identity_protection` |
| [SPW-HAWK-009](#spw-hawk-009) | Entra ID Protection risk detection | high | medium | suspicious_sign_in | capability `identity_protection` |
| [SPW-HAWK-012](#spw-hawk-012) | Risky Entra sign-in | high | medium | suspicious_sign_in | capability `identity_protection`, evidence `signins` |
| [SPW-HAWK-013](#spw-hawk-013) | Mobile device first synced inside the investigation window | medium | medium | persistence | |
| [SPW-APP-001](#spw-app-001) | Consent to an app with Mail.\*, Files.\* or offline_access | high | medium | consent | |
| [SPW-APP-002](#spw-app-002) | New credential on an application or service principal | high | medium | persistence | GeoIP |
| [SPW-HAWK-006](#spw-hawk-006) | OAuth consent granted | medium | medium | consent | |
| [SPW-HAWK-007](#spw-hawk-007) | Consent grant in a risky category | high | medium | consent | |
| [SPW-CFG-001](#spw-cfg-001) | Audit logging tampered with | **critical** | high | — | |
| [SPW-HAWK-004](#spw-hawk-004) | eDiscovery search created, run or exported | medium | medium | mail_access | evidence `ual` |
| [SPW-HAWK-005](#spw-hawk-005) | Domain added, verified or federated | high | medium | persistence | |
| [SPW-FILE-001](#spw-file-001) | Mass file download | medium | medium | — | evidence `ual` |
| [SPW-FILE-002](#spw-file-002) | Anonymous sharing link created after a compromise indicator | high | medium | — | evidence `ual`, GeoIP |
| [SPW-FILE-003](#spw-file-003) | OneNote or PDF lure uploaded and shared | high | medium | — | evidence `ual` |
| [SPW-HAWK-001](#spw-hawk-001) | Admin changed another user's inbox rule that forwards, redirects or deletes | high | medium | persistence | evidence `ual` |
| [SPW-HAWK-002](#spw-hawk-002) | FullAccess, SendAs or recipient permission granted | high | medium | persistence | |
| [SPW-HAWK-003](#spw-hawk-003) | Mailbox forwarding parameter changed | medium | medium | persistence | evidence `ual` |
| [SPW-HAWK-010](#spw-hawk-010) | User inbox rule deletes, forwards or redirects mail | high | medium | persistence | |
| [SPW-HAWK-011](#spw-hawk-011) | Mailbox forwarding configured | medium | medium | persistence | |
| [SPW-HAWK-015](#spw-hawk-015) | Automatic reply enabled | low | low | — | |

36 rules. Tags you can filter on with `--tag` include `bec`, `correlation`, `inbox-rule`,
`forwarding`, `oauth-consent`, `identity-protection`, `password-spray` and `sign-in`.

---

## Mail

Files under `rules/mail/`.

### SPW-MAIL-003

**Inbox rule with finance keywords or a hiding folder**: high / medium · stage `persistence` ·
MITRE T1564.008, T1114.003

**Detects.** An inbox rule, either collected (`inbox_rules`) or written in the audit log
(UAL or Hawk 3 admin audit `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`), that matches
either of these:

- `SubjectContainsWords`, `BodyContainsWords` or `SubjectOrBodyContainsWords` contain a word from
  [`finance_keywords`](#static-lists);
- `MoveToFolder` is one of [`hiding_folders`](#static-lists) (RSS Feeds, RSS Subscriptions,
  Conversation History, Archive, Junk Email, Deleted Items) or a single-character folder name.

**Reads** `inbox_rules`, `ual_events`, `admin_audit_events` · **Finding per** actor.

**Triage.** Read the rule's conditions and action, who created it and from where, and whether
mail it caught was later read or forwarded.

**False positives.** A finance user's own rule that files invoices into Archive. A rule that
moves newsletters into Junk Email or Deleted Items.

### SPW-MAIL-004

**External forwarding through the mailbox, an inbox rule or a transport rule**: high / medium ·
stage `persistence` · MITRE T1114.003

**Detects.** A forwarding target outside the tenant's domains (`tenant_domains`), from any of:

- mailbox `forwarding_smtp_address` / `forwarding_address`;
- inbox rule `forward_to` / `forward_as_attachment_to` / `redirect_to`;
- transport rule `blind_copy_to` / `redirect_to` / `copy_to` / `add_to_recipients`;
- the UAL events that set them (`Set-Mailbox`, `New-/Set-InboxRule`, `New-/Set-TransportRule`).

**Reads** `mailboxes`, `inbox_rules`, `transport_rules`, `ual_events`, `admin_audit_events` ·
**Finding per** actor.

**Triage.** Read the destination, who set it and from where, and what mail matched (a rule's
conditions, a transport rule's scope). A forward in collected state was active when the data
was collected. The audit log shows who created it.

**False positives.** Forwarding to a partner, a leaver's personal address or a sister company.
A journaling or archiving transport rule that copies mail to a compliance vendor.

### SPW-MAIL-005

**MailItemsAccessed bind burst**: high / medium · stage `mail_access` · MITRE T1114.002 ·
needs evidence `mail_items_accessed`

**Detects.** At least **5** `MailItemsAccessed` records with `MailAccessType` Bind, or at least
**100** accessed items, for one mailbox from one client IP within **30 minutes**. A burst counts
only if the address meets one of these:

- it is a hosting ASN or a password-spray source; or
- its network (ASN, else the address) is not one the user signed in from successfully on at
  least 3 distinct UTC days **before** the burst's day. A user with fewer than 3 prior days is
  judged by the hosting and spray tests alone.

Sync records and Microsoft service addresses never count.

**Reads** `ual_events`, `mail_items_accessed` · **Finding per** mailbox and UTC day.

**Triage.** Compare the client IP and app id with the user's normal sign-ins, check which
folders were read, and look for a preceding risky sign-in or a new app consent.

**False positives.** A migration or backup tool reading through a service account. A user's own
device after a long offline period (mostly Sync, which never counts).

### SPW-MAIL-006

**Mail sent from an IP address the user never used before**: medium / low · stage `sending` ·
MITRE T1114, T1534 · needs evidence `mail_send`

**Detects.** A UAL `Send`, `SendAs` or `SendOnBehalf` from an address the user never used on an
**earlier** UTC day (activity on the same day never counts as history), when either:

- the address is a hosting ASN or a password-spray source, whatever the user's history. This
  catches a brand-new account's first send too; or
- the user has activity on at least 3 earlier UTC days, the network (ASN, else the address) is
  new, **and** one of these holds: the country is new for the user, there was a medium/high risk
  sign-in in the previous 24 hours, or GeoIP has no country for the address (so partial GeoIP
  never suppresses a hit).

Microsoft service addresses never count.

**Reads** `ual_events` · **Finding per** actor.

**Triage.** It matters most when the address is that of the suspect sign-in, or when the send
follows a new inbox rule or MFA change. Check recipients and subject through the message trace.

**False positives.** Travel or a first-time VPN (hosting ASN). A tenant captured without GeoIP,
where every new address is judged on history alone. A new employee whose VPN or virtual desktop
egresses from a cloud provider.

### SPW-MAIL-007

**Mailbox or SharePoint search for finance keywords**: medium / medium · stage `mail_access` ·
MITRE T1114.002, T1114.003 · needs evidence `search_queries`

**Detects.** A `search_queries` row, or a UAL `SearchQueryInitiatedExchange` /
`SearchQueryInitiatedSharePoint`, whose query text contains a word from
[`finance_keywords`](#static-lists).

**Reads** `ual_events`, `search_queries` · **Finding per** actor.

**Triage.** A search for invoice, payment, wire or bank is BEC reconnaissance: the actor is
looking for a thread to hijack. Check who ran it, from where, and what followed (a reply, a
rule, a forward).

**False positives.** A finance or payroll user searching for those terms as part of their job.

### SPW-MAIL-008

**Mail deleted by a delegate from an unusual network or with a finance subject**: high / medium ·
stage `mail_access` · MITRE T1070.008, T1114.002 · needs evidence `ual`

**Detects.** A UAL `SoftDelete`, `HardDelete` or `MoveToDeletedItems` made by a delegate or admin
in another user's mailbox (the mailbox differs from the actor, or `LogonType` 1 or 2; system actors
never count) from a hosting address (`ip_intel.is_hosting`) or on an item whose subject contains a
word from [`finance_keywords`](#static-lists). One finding hit per delete record; the finding
context `severity_reason` says which condition held.

**Reads** `ual_events` · **Finding per** actor.

**Triage.** Deleting the genuine invoice or wire thread from someone else's mailbox is how a BEC
actor hides the original once a look-alike copy is in place. Check whose mailbox it was, who holds
the delegate permission and the actor's sign-in for that session, then look in Recoverable Items.

**False positives.** An assistant who manages an executive's mailbox and deletes an invoice they
have processed; an admin or owner of a finance shared mailbox cleaning it.

### SPW-HAWK-014

**Message header sender mismatch (P1/P2) or failed / anonymous authentication**: medium /
medium · no stage · MITRE T1566.002

**Detects.** An `email_artifacts` row (exported message headers) matching any of:

- the From address (inside `<>`) differs from Return-Path;
- `Authentication-Results` show spf, dkim or dmarc `fail`;
- `X-MS-Exchange-Organization-AuthAs` is `Anonymous` while the From domain is internal.

Hawk `Message_Header_Findings` rows with a "P1 P2 Match" of "don't Match" count too.

**Reads** `email_artifacts` · **Finding per** actor.

**Triage.** Check the hops and the originating IP, and whether the internal mailbox it names had
a rule, forwarding or consent added around that time.

**False positives.** A mailing list or vendor whose domain fails dmarc alignment. A forwarded
internal message whose Return-Path is the forwarding service.

---

## Identity and sign-ins

Files under `rules/identity/`.

### SPW-ID-001

**MFA method registered after a risky sign-in**: high / medium · stages `suspicious_sign_in`,
`mfa_change` · MITRE T1098.005 · needs GeoIP

**Detects.** A directory audit `User registered security info`, or `Update user` with
`StrongAuthentication*` modified properties (or the same as a UAL `Update user.`), within **24
hours after** a sign-in of the same user that was rated medium/high risk or came from a hosting
ASN.

**Reads** `directory_audits`, `ual_events`, `signins` · **Finding per** actor.

**Triage.** Compare the registration IP and device name with the user's normal sign-ins. Check
whether the user was travelling or newly hired.

**False positives.** A new hire registering MFA during onboarding from the corporate network. A
user who registers a new phone after clearing a risk detection themselves.

### SPW-ID-002

**Sign-in from a hosting-provider ASN**: medium / medium · stage `suspicious_sign_in` · MITRE
T1078.004, T1090 · needs GeoIP

**Detects.** A successful sign-in (`signins`, or UAL `UserLoggedIn`) from an address on a
[hosting ASN](#shared-concepts).

**Excused.** Sign-ins of a [tenant-wide cloud service](#shared-concepts) to its own application
from its own ASN, interactive or not (the portal export records a connector's back end as
interactive). The service's UAL `UserLoggedIn` records (matched on `ual_events.app_id`) are
excused the same way.

**Always counted.** The same service from another ASN, another application, any sign-in from a
password-spray source, and a UAL `UserLoggedIn` with no application id.

**Residual risk (by design).** An attacker using the same third-party application from the same
cloud ASN as an established connector is excused, and so are a connector's first days (there is
no cold start). Such an attacker still needs a consent, which SPW-APP-001, SPW-APP-002 and the
consent rules report. Phished accounts used from a VPS usually sign in to first-party apps such as
OfficeHome or Outlook. Those apps are never treated as a service.

**Reads** `signins`, `ual_events` · **Finding per** actor.

**Triage.** Compare the address with the user's usual ones, check whether MFA was satisfied, and
look for a risk detection or mailbox logon from the same address.

**False positives.** A commercial VPN or cloud-hosted desktop. A corporate proxy hosted at a
cloud provider. A SaaS connector whose users the capture barely covers: with Hawk's per-user
sign-ins, fewer than 5 of its users are visible, so it cannot be established as a service. Check
the application's publisher, and add a tenant-wide sign-in export to the case.

### SPW-ID-003

**Impossible travel**: medium / low · stage `suspicious_sign_in` · MITRE T1078.004 · needs GeoIP

**Detects.** Two successful sign-ins of one user whose GeoIP locations imply a speed above **900
km/h** and are at least **500 km** apart.

- A pair in the **same country** counts only if one end is a hosting address or a password-spray
  source.
- A cross-country pair, or a pair where a country is unknown, always counts.
- Sign-ins of a [tenant-wide cloud service](#shared-concepts) to its application from its ASN
  (and its UAL `UserLoggedIn` records) form no pair. Another ASN, a UAL record with no
  application id, and spray-source sign-ins always do.

The hit is the later sign-in. When only the earlier one is a hosting address, the hit is the
hosting one instead. The finding context gives the distance, the implied speed and the other
sign-in.

**Reads** `signins`, `ual_events` · **Finding per** actor.

**Triage.** First rule out VPN or mobile-carrier egress in another region, and two devices on
different networks. An attacker usually shows more around the session: an unfamiliar device or
user agent, a hosting address, a risk detection, or a mailbox logon from the far address.

**False positives.** VPN or carrier egress far from the user. Two devices of one user on
different networks with unknown or different countries. A barely-covered SaaS connector (see
SPW-ID-002).

### SPW-ID-004

**Adversary-in-the-middle indicators**: high / medium · stage `suspicious_sign_in` · MITRE
T1557, T1550.004

**Detects** either of two things.

1. **Session moved.** A session (`session_id` / `AADSessionId`) created by an interactive (or
   unknown-kind) sign-in that satisfied MFA, then used within **1 hour** from a different
   network. "Different network" means one of:
   - the country differs;
   - the ASN differs and the use or the creating sign-in is a hosting ASN or a spray source;
   - the use is a medium/high risk sign-in;
   - the ASN differs and the OS or browser differs from the creating sign-in's.

   A successful UAL `UserLoggedIn` (session id from `DeviceProperties`) also creates a session,
   so a case with only audit logs still sees the move. A Microsoft service address on either side
   never counts. An address change inside one ASN is not a move: IPv6 privacy rotation, carrier
   pools, or a Wi-Fi to cellular switch in one country. If the ASN is missing on either side, the
   address difference alone counts, unless both countries are known and differ.
2. **Scripted client.** A successful or unknown-result sign-in, or a UAL `UserLoggedIn`,
   `MailboxLogin` or `MailItemsAccessed`, whose user agent is in
   [`suspicious_user_agents`](#static-lists) (axios, python-requests, curl, Go-http-client, ...).
   A failed scripted sign-in, such as a legacy-auth spray, is not reported.

**Reads** `signins`, `ual_events` · **Finding per** actor.

**Triage.** Read the two addresses and whether the second is a hosting provider, then check the
risk detections and what the session did next (mailbox logon, rules).

**False positives.** A phone moving from Wi-Fi to cellular on a long-lived session, when no GeoIP
is loaded. Legitimate automation using a scripted client that succeeds.

### SPW-ID-005

**Successful sign-in from a password-spray source**: high / medium · stage `suspicious_sign_in`
(feeds `credential_takeover`) · MITRE T1110.003, T1078 · needs ≥ 5 sign-in users

**Detects.** A successful sign-in (`signins` `error_code` 0, or UAL `UserLoggedIn`) from an
address in the tenant's [password-spray sources](#shared-concepts). It fires whether the success
came before or after the source's first failure, because the address is attacker infrastructure
either way. A NULL-result sign-in is ignored on purpose (it could be a failure, and the rule is
high severity).

How a spray source is established:

- Credential failures come from [`credential_failure_codes`](#static-lists), interactive rows
  only (an unknown kind counts as interactive). 50055, an expired password, is in the list.
- At least 5 **sprayed** users. A failed user is excused only by a known success from that
  address before their first failure there, or within 30 minutes after one of their failures
  there. A later success is a takeover and does not excuse.
- Sprayed users must outnumber the excusing users, so an office NAT stays out and a proxy that
  takes accounts over stays in.
- Any network type. No GeoIP needed.

The context gives the source's users and failures, its first and last failure, whether this user
was sprayed (`takeover`), and whether the success preceded the first failure.

**Reads** `signins`, `ual_events` · **Finding per** actor.

**Triage.** Treat the account as compromised until proven otherwise. Read the session (mailbox
logon, inbox rules, MFA changes), reset the credential and revoke tokens. A success for a user the
address never failed against means the credential came from somewhere else.

**False positives.** An address reassigned to a legitimate user after the spray (carrier-grade
NAT, a mobile pool). A small office or VPN egress where ≥ 5 stale devices keep failing while
fewer users succeed.

### SPW-ID-006

**Password spray against the tenant**: low / high · no stage · MITRE T1110.003 · needs ≥ 5
sign-in users

**Detects.** One finding per tenant per **UTC day** on which a password-spray source had
credential failures (interactive only; Conditional Access blocks, token-refresh errors and MFA
prompts are not failures). The finding has no actor. Its context holds the sources, users
targeted, failures, top error codes, hosting vs other-network source counts, and
`any_source_later_succeeded`.

**Reads** `signins` · **Finding per** day.

**Triage.** Spraying is background noise on the internet, so read the day's picture: the
dominant codes (50053 lockout, 50126 invalid password) and whether the sources are hosting
providers or residential ISPs. If `any_source_later_succeeded` is true, SPW-ID-005 has the
success. Otherwise confirm legacy authentication is blocked and smart lockout is on.

**False positives.** An office egress whose misconfigured sync client retries a stale password
for many accounts. An authorised scanner or penetration test.

### SPW-ID-007

**Persistence within 60 minutes of the user's first sign-in from a new same-country network**:
high / medium · stages `suspicious_sign_in`, `persistence` · MITRE T1078.004, T1098, T1564.008 ·
needs GeoIP

**Detects.** A persistence action at most **60 minutes** (inclusive) after the user's **first**
successful sign-in from an ASN they had not used on an earlier day. This is a replayed session
coming from a residential proxy or compromised router near the victim, which hosting-ASN rules
cannot see.

The persistence actions:

- UAL / Hawk 3 admin audit: `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`,
  `Add-MailboxPermission`, `Add-RecipientPermission`, `Add-MailboxFolderPermission`,
  `Set-MailboxFolderPermission`, `New-TransportRule`, `Set-TransportRule`,
  `Set-MailboxJunkEmailConfiguration`, `Set-Mailbox` setting a non-empty `ForwardingSmtpAddress`
  or `ForwardingAddress`.
- Directory audit / UAL: Consent to application, Add app role assignment grant to user, Add app
  role assignment to service principal, User registered (all required) security info, Add member
  to role, Register device, Add device, Add registered owner/users to device, Add service principal
  credentials, Update application – Certificates and secrets management, Update user of the
  strong-authentication details.

The new-network sign-in must be:

- from a country the user signed in from on an earlier UTC day;
- not a hosting ASN and not a Microsoft address, with ASN and country known;
- not rated medium/high by any Entra sign-in of the user from the same address within 120 seconds;
- by a user with successful sign-ins on at least 3 distinct UTC days before that day. A user's
  first three active days are never judged.

**Network tie.** When the persistence record carries a non-Microsoft address with a known ASN, it
counts only if that ASN is the new network's, a hosting ASN, or the address is a spray source. A
record with no address, an unknown ASN or a Microsoft address counts.

The trigger is the persistence record. The new-network sign-in is in the context.

**Reads** `ual_events`, `admin_audit_events`, `directory_audits`, `signins` · **Finding per**
actor.

**Triage.** Ask the user whether they were on that network (new carrier, hotel, relative's Wi-Fi)
and whether they made the change. Read the change itself: rule actions, grantee, app scopes, the
new authenticator's device.

**False positives.** A user on a new carrier or in a new place who legitimately edits a rule
within the hour. An admin making routine role changes from a new network. Another of the user's
devices whose records carry no address or a Microsoft one, so the networks cannot be compared.

### SPW-ID-010

**Inbox rule created within 60 minutes of a risky or hosting-ASN sign-in**: high / medium ·
stages `suspicious_sign_in`, `persistence` · MITRE T1564.008, T1114.003 · needs GeoIP

**Detects.** A UAL `New-InboxRule`, `Set-InboxRule` or `UpdateInboxRules`, or the Hawk 3.1 admin
audit equivalent, by an actor who in the preceding **60 minutes** had either:

- **Risk arm:** a sign-in with `risk_level_during` medium/high (any result, no network tie); or
- **Hosting arm:** a successful or unknown-result sign-in (or a non-Failed UAL `UserLoggedIn`)
  from a hosting ASN, excluding a [tenant-wide cloud service's](#shared-concepts) own sign-ins
  unless the address is a spray source. The rule record must tie to that infrastructure: if it
  carries a non-Microsoft address with a known ASN, that ASN must be the sign-in's, any hosting
  ASN, or a spray source. A record with no address, an unknown ASN or a Microsoft address counts.

**Residual risk.** A VPS sign-in followed within the hour by a rule created from a residential
proxy is not reported here. SPW-ID-002 reports the VPS sign-in, and SPW-ID-007 or SPW-ID-004 may
see the proxy.

**Reads** `ual_events`, `signins`, `admin_audit_events` · **Finding per** actor.

**Triage.** Read the rule's conditions and actions (forward, delete, hiding folder), compare the
sign-in IP with the rule's IP, and check what mail the rule touched.

**False positives.** A VPN or cloud-desktop user creating a rule from the same hosting ASN. A rule
created soon after a SaaS connector's sign-in that the case has not established as a service.
Risk detections Entra later dismisses.

### SPW-ID-011

**Refresh-token replay after revocation**: high / medium · stage `persistence` · MITRE T1550.001 ·
needs GeoIP

**Detects.** Sign-ins failing with error `50173` (the refresh token no longer works: the sessions
were revoked or the password reset) from a network the user never signed in from successfully, or
from a hosting address (`ip_intel.is_hosting`), when the user has **5 or more** such rows within 24
hours. The network is the ASN from `ip_intel`, else the address; the history is every successful
sign-in (`error_code` 0 or NULL) of the user in the case, at any time. Every qualifying row of such a
burst is a hit. `50173` is deliberately not a credential failure, so no spray rule sees it.
Finding context: UTC day, count, distinct ASNs, first and last time.

**Residual risk.** Fewer than 5 replays in 24 hours, and a replay from an ASN the user has signed in
from, are not reported.

**Reads** `signins` · **Finding per** actor.

**Triage.** Compare the addresses with the user's usual networks, confirm the sessions were revoked
and the password reset, and look for tokens a session revocation does not cancel (consents, app
credentials).

**False positives.** The user's own devices failing after a reset on a network the case has no
successful sign-in from yet; a hosting-address VPN or cloud desktop; a shared gateway egress.

### SPW-HAWK-008

**Risky or confirmed-compromised user**: high / medium · no stage · MITRE T1078.004 · needs
capability `identity_protection` · Hawk H08, H09

**Detects.** A `risky_users` row with `risk_state` `confirmedCompromised`, or `atRisk` with
`risk_level` low, medium or high. Dismissed, remediated or none are not hits.

**Reads** `risky_users` · **Finding per** actor.

**Triage.** Check the sign-ins and tokens around the flag, the risk detail, and whether a
mailbox rule, forwarding or consent appeared at the same time.

**False positives.** An unfamiliar network an admin confirmed as legitimate. Remediated risk
whose row still shows `atRisk`.

### SPW-HAWK-009

**Entra ID Protection risk detection**: high / medium · stage `suspicious_sign_in` · MITRE
T1078.004 · needs capability `identity_protection` · Hawk H10, H11

**Detects.** A `risk_detections` row with `risk_state` `atRisk` or `confirmedCompromised` and
`risk_level` low, medium or high.

**Reads** `risk_detections` · **Finding per** actor.

**Triage.** Check the risk event type, the IP and location against the user's normal sign-ins,
and the sign-ins and tokens that follow.

**False positives.** A detection later dismissed or remediated (the row would then show that state).

### SPW-HAWK-012

**Risky Entra sign-in**: high / medium · stage `suspicious_sign_in` · MITRE T1078.004 · needs
capability `identity_protection` and evidence `signins` · Hawk H14

**Detects.** A `signins` row with `risk_level_during` or `risk_level_aggregated` in low, medium,
high (`none` and `hidden` are not hits).

**Reads** `signins` · **Finding per** actor **and IP**.

**Triage.** Check the risk detail and event types, the IP and location, and whether the session
led to a mailbox rule, forwarding or consent.

**False positives.** A corporate network or new country the user confirms.

### SPW-HAWK-013

**Mobile device first synced inside the investigation window**: medium / medium · stage
`persistence` · MITRE T1078 · Hawk H15

**Detects.** A `mobile_devices` row whose `first_sync` is inside the collection window.

**Reads** `mobile_devices` · **Finding per** actor.

**Triage.** Check the device model and compare the sync time with the sign-ins and rule changes
that follow. Check whether the device is shared or stolen hardware.

**False positives.** A user replacing or re-enrolling a phone during the window.

---

## Applications and consent

Files under `rules/apps/`.

### SPW-APP-001

**Consent to an app with Mail.\*, Files.\* or offline_access**: high / medium · stage `consent` ·
MITRE T1098.003

**Detects.** A consent in the window (an `oauth_grants` row created in the window, a directory
audit `Consent to application`, or UAL `Consent to application.`) whose permissions include a
`Mail.*` or `Files.*` scope. `offline_access` counts only together with one of those. Alone it
only keeps a refresh token usable.

**Reads** `oauth_grants`, `directory_audits`, `ual_events` · **Finding per** actor.

**Triage.** Check the app's publisher and whether the grant sits next to a mailbox rule, a
forwarding change or a risky sign-in.

**False positives.** A user consenting to a known first-party or line-of-business app from the
office.

### SPW-APP-002

**New credential on an application or service principal**: high / medium · stage `persistence` ·
MITRE T1098.001 · needs GeoIP

**Detects.** A directory audit or UAL `Add service principal credentials` or `Update application –
Certificates and secrets management` that either:

- adds a **password** credential to a service principal; or
- adds **any** credential when the actor had a risky or hosting-ASN sign-in in the preceding 24
  hours.

`app_credentials` rows whose start falls in the window support the hit.

**Reads** `directory_audits`, `ual_events`, `app_credentials` · **Finding per** actor.

**Triage.** A new secret lets whoever holds it sign in as the app long after the user's session is
reset. Read who added it and from where, which application and what permissions it holds, and
compare the key id with `app_credentials`.

**False positives.** Planned secret or certificate rotation. A deployment pipeline registering a
credential when it creates an app.

### SPW-HAWK-006

**OAuth consent granted**: medium / medium · stage `consent` · MITRE T1098.003 · Hawk H06

**Detects.** In the window: UAL `Consent to application.`, `Add delegated permission grant.` or
`Add OAuth2PermissionGrant.`, or directory audit `Consent to application` / `Add delegated
permission grant`. A sign-in to an app consented before the window does not count.

**Reads** `ual_events`, `directory_audits` · **Finding per** actor.

**Triage.** Check which app, which scopes, whether the publisher is verified, and whether the
consent came from the office or a new address. A consent right before a mailbox rule or forwarding
change is the BEC pattern.

**False positives.** A known first-party or line-of-business app consented from the office.

### SPW-HAWK-007

**Consent grant in a risky category (broad scope, extremely dangerous, high risk)**: high /
medium · stage `consent` · MITRE T1098.003, T1528 · Hawk H07

**Detects.** An `oauth_grants` row granted in the window where:

- `consent_type` is `AllPrincipals`, or the permission ends in `.All` (broad scope); or
- the permission is `AppRoleAssignment.ReadWrite.All` or `RoleManagement.ReadWrite.Directory`
  (extremely dangerous); or
- the permission is one of `BitlockerKey.Read.All`, `Chat.*`, `Directory.ReadWrite.All`,
  `eDiscovery.*`, `Files.*`, `MailboxSettings.ReadWrite`, `Mail.ReadWrite`, `Mail.Send`, `Sites.*`,
  `User.ReadWrite*`, `User.Read.All` (high risk).

Unlike Hawk, `User.Read` / `User.ReadBasic.All` alone are not high risk. Grants that existed before
the window (first-party apps, the AllPrincipals Microsoft Office grant) are context, not hits.

**Reads** `oauth_grants`, `directory_audits`, `ual_events` · **Finding per** actor.

**Triage.** For a consent, the scopes matter more than the app. Check the publisher, who
consented, from where, and whether the app was used immediately afterwards.

**False positives.** An admin's tenant-wide consent to a first-party app (it predates the window).
A line-of-business app that legitimately needs `Files.*` or `Mail.ReadWrite`.

---

## Tenant configuration

Files under `rules/config/`.

### SPW-CFG-001

**Audit logging tampered with**: **critical** / high · no stage · MITRE T1562.008

**Detects** any of:

- `Set-Mailbox -AuditEnabled $false`;
- `Set-MailboxAuditBypassAssociation -AuditBypassEnabled $true`;
- `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false` or `-AdminAuditLogEnabled $false`;
- `Set-OrganizationConfig -AuditDisabled $true`;
- collected state showing the same: `audit_config` with `unified_audit_log_ingestion_enabled`
  false or `audit_disabled` true, or a mailbox with `audit_bypass_enabled` true.

Changing the audit age limit or adding audited actions is not tampering.

**Reads** `ual_events`, `admin_audit_events`, `audit_config`, `mailboxes` · **Finding per** actor.

**Triage.** Assume everything after the change may be missing from the logs. Check who made the
change and from where, which mailboxes are bypassed, and whether unified audit ingestion is still
off. Collected state shows the setting at collection, whoever set it.

**False positives.** A documented, reviewed audit bypass for a service account. A planned change
during a tenant migration.

### SPW-HAWK-004

**eDiscovery search created, run or exported**: medium / medium · stage `mail_access` · MITRE
T1213 · needs evidence `ual` · Hawk H01

**Detects.** A UAL record of RecordType Discovery (24) with operation `SearchCreated`,
`SearchStarted`, `SearchExported`, `SearchExportDownloaded`, `SearchPreviewed`, `CaseAdded` or
`HoldCreated`. Viewing a search (`SearchViewed`) is not enough, unlike Hawk, which flags any
Discovery record.

**Reads** `ual_events` · **Finding per** actor.

**Triage.** Check who ran it, the case and the time range, and whether a hold or export followed.

**False positives.** A legitimate compliance investigation with a case and documented custodian.

### SPW-HAWK-005

**Domain added, verified or federated**: high / medium · stage `persistence` · MITRE T1583.001,
T1606.002 · Hawk H05

**Detects.** UAL AzureActiveDirectory `Add domain to company.`, `Verify domain.`, `Set domain
authentication.`, `Set federation settings on domain.`, or the directory audit activities Add
unverified domain, Verify domain, Set domain authentication, Set federation settings on domain.
`Update domain.` alone does not count.

**Reads** `ual_events`, `directory_audits` · **Finding per** actor.

**Triage.** Whoever owns the domain gains control of mail flow or the tenant's identity. Check the
actor, from where, and whether federation or a mail-flow rule followed.

**False positives.** A planned, documented domain migration for a domain the tenant owns.

---

## Files and sharing

Files under `rules/files/`.

### SPW-FILE-001

**Mass file download**: medium / medium · no stage · MITRE T1530 · needs evidence `ual`

**Detects.** At least **30** `FileDownloaded` / `FileSyncDownloadedFull` records by one user
within **15 minutes**. This is the only built-in rule that uses `threshold:`.

**Reads** `ual_events` · **Finding per** actor.

**Triage.** Check the client IP and user agent, the site the files came from, and whether the
user signed in from a hosting provider shortly before.

**False positives.** OneDrive syncing a library to a new laptop. A migration or backup tool under
the user's account.

### SPW-FILE-002

**Anonymous sharing link created after a compromise indicator**: high / medium · no stage ·
MITRE T1567 · needs evidence `ual`, GeoIP

**Detects.** `AnonymousLinkCreated` (`sharing_events` `link_type` anonymous) by a user who had a
risky or hosting-ASN sign-in in the preceding **24 hours**.

**Reads** `ual_events`, `sharing_events`, `signins` · **Finding per** actor.

**Triage.** Open the shared document, check who used the link, and compare the creating IP with
the user's normal sign-ins.

**False positives.** Sharing a public document right after a VPN sign-in. Risk detections Entra
later dismisses.

### SPW-FILE-003

**OneNote or PDF lure uploaded and shared**: high / medium · no stage · MITRE T1566.002,
T1204.002 · needs evidence `ual`

**Detects.** `FileUploaded` of a `.one`, `.onetoc2`, `.onepkg` or `.pdf` file, followed within
**24 hours** by a sharing event on the same file (`SharingSet`, `SharingInvitationCreated`,
`CompanyLinkCreated`, `AnonymousLinkCreated`) that reaches an external target or is a
company-wide link.

**Reads** `ual_events`, `file_events`, `sharing_events` · **Finding per** actor.

**Triage.** This is the lure for a phishing wave sent from a trusted sender. Open the file, list
who received the link, and check mail sent around the same time.

**False positives.** A PDF shared with a partner or company-wide. A OneNote notebook shared with an
external collaborator.

---

## Hawk parity rules

Files under `rules/hawk/` (plus the HAWK-numbered rules filed with their category above). The
SPW-HAWK-001..015 rules together cover every Hawk 4.0 *investigate* condition (H01–H15), with the
deliberate differences noted in each entry.

| Hawk | Rule |
| --- | --- |
| H01 | [SPW-HAWK-004](#spw-hawk-004) eDiscovery |
| H02 | [SPW-HAWK-001](#spw-hawk-001) admin-written inbox rule |
| H03 | [SPW-HAWK-002](#spw-hawk-002) mailbox permissions |
| H04 | [SPW-HAWK-003](#spw-hawk-003) forwarding parameter changed |
| H05 | [SPW-HAWK-005](#spw-hawk-005) domains |
| H06 | [SPW-HAWK-006](#spw-hawk-006) consent |
| H07 | [SPW-HAWK-007](#spw-hawk-007) risky consent |
| H08, H09 | [SPW-HAWK-008](#spw-hawk-008) risky user |
| H10, H11 | [SPW-HAWK-009](#spw-hawk-009) risk detection |
| H12 | [SPW-HAWK-010](#spw-hawk-010) inbox rule deletes/forwards |
| H13 | [SPW-HAWK-011](#spw-hawk-011) forwarding configured |
| H14 | [SPW-HAWK-012](#spw-hawk-012) risky sign-in |
| H15 | [SPW-HAWK-013](#spw-hawk-013) new mobile device |
| — | [SPW-HAWK-014](#spw-hawk-014) header findings, [SPW-HAWK-015](#spw-hawk-015) auto-reply (content-derived) |

### SPW-HAWK-001

**Admin created, changed or removed another user's inbox rule that forwards, redirects or
deletes**: high / medium · stage `persistence` · MITRE T1114.003, T1564.008 · needs evidence
`ual` · Hawk H02

**Detects.** ExchangeAdmin `New-InboxRule`, `Set-InboxRule` or `Remove-InboxRule` where the rule's
mailbox (the `Mailbox` parameter, else the mailbox part of `Identity`) differs from the actor
(`UserId`), and either `ForwardTo`, `ForwardAsAttachmentTo` or `RedirectTo` is non-empty,
`DeleteMessage` is True, or `MoveToFolder` is Deleted Items. Unlike Hawk, the text `"False"` is
false. Hawk 3 `admin_audit_events` rows with the same cmdlets and parameters count too.

**Reads** `ual_events`, `admin_audit_events` · **Finding per** actor.

**Triage.** This is what a stolen admin account does to redirect a victim's mail without touching
the victim's session. Read the rule's target and conditions, the admin's sign-in and address, and
whether the mailbox owner knows about the rule.

**False positives.** A helpdesk or migration admin setting up forwarding at the owner's request.
An admin managing a shared mailbox's rules.

### SPW-HAWK-002

**FullAccess, SendAs or recipient permission granted (not the SYSTEM discovery grant)**: high /
medium · stage `persistence` · MITRE T1098.002 · Hawk H03

**Detects.** `Add-MailboxPermission` with AccessRights containing FullAccess or SendAs,
`Add-RecipientPermission`, or `Add-ADPermission`, excluding the
`NT AUTHORITY\SYSTEM (Microsoft.Exchange.ServiceHost)` grant on a DiscoverySearchMailbox for
Discovery Management. A collected `mailbox_permissions` full_access / send_as row whose grantee is
a tenant user created in the window also counts, even when the grant itself is not in the log.

**Reads** `ual_events`, `admin_audit_events`, `mailbox_permissions` · **Finding per** actor.

**Triage.** Check who granted it and from where, whether the grantee is a new account, and what
the grantee did with the access.

**False positives.** A delegate given access to a shared or executive mailbox. A migration or
backup service account with FullAccess across mailboxes.

### SPW-HAWK-003

**Mailbox forwarding parameter changed**: medium / medium · stage `persistence` · MITRE T1114.003
· needs evidence `ual` · Hawk H04

**Detects.** `Set-Mailbox`, `Set-MailUser`, `Set-RemoteMailbox` or `Enable-RemoteMailbox` with any
of `ForwardingAddress`, `ForwardingSmtpAddress`, `DeliverToMailboxAndForward`,
`ExternalEmailAddress`, `RedirectTo`, with any value, including clearing it.

**Reads** `ual_events`, `admin_audit_events` · **Finding per** actor.

**Triage.** Read the new value. An address outside the tenant, or one the owner does not know, is
the classic exfiltration step. A cleared value is still a change (evidence removal or
remediation), so check the neighbouring events.

**False positives.** Forwarding set up or removed for a leaver or a shared mailbox. Migration or
hybrid tooling that sets `ExternalEmailAddress`.

### SPW-HAWK-010

**User inbox rule deletes, forwards or redirects mail**: high / medium · stage `persistence` ·
MITRE T1114.003, T1564.008 · Hawk H12

**Detects.** An `inbox_rules` row with `delete_message` true or a non-empty `forward_to`,
`forward_as_attachment_to` or `redirect_to`. A UAL `New-InboxRule`, `Set-InboxRule` or
`UpdateInboxRules` (or the admin audit equivalent) creating such a rule also counts.

**Reads** `inbox_rules`, `ual_events`, `admin_audit_events` · **Finding per** actor.

**Triage.** Read the conditions (sender, subject words) and the target. A forward to an external
address or a delete of everything from one sender is the pattern. Check who created it and what
sign-in preceded it.

**False positives.** A user forwarding a shared mailbox's mail to a colleague. An out-of-office
style redirect to a delegate.

### SPW-HAWK-011

**Mailbox forwarding configured**: medium / medium · stage `persistence` · MITRE T1114.003 ·
Hawk H13

**Detects.** A `mailboxes` row, as collected, with `forwarding_smtp_address` or
`forwarding_address` set.

**Reads** `mailboxes` · **Finding per** actor.

**Triage.** Confirm the target is expected (a delegate, a migration artefact). Check the mailbox's
inbox rules, the owner's sign-ins around the change, and whether mail left the tenant.

**False positives.** Internal forwarding. Migration forwarding left in place.

### SPW-HAWK-015

**Automatic reply enabled**: low / low · no stage

**Detects.** A `mailboxes` row with `auto_reply_state` Enabled or Scheduled, or a UAL
`Set-MailboxAutoReplyConfiguration` with `AutoReplyState` Enabled or Scheduled.

**Reads** `mailboxes`, `ual_events` · **Finding per** actor.

**Triage.** An attacker may enable an auto-reply to buy time or harvest replies. Read the reply
text and audience (internal or external), and compare when it was enabled with nearby sign-ins and
rule changes.

**False positives.** A user going on leave.

---

## Static lists

Rules reference these through `@list:<name>`. They live in `rules/lists/`, are embedded in the
binary, and can be extended or replaced with `--rules DIR`.

| List | Used by | Contents |
| --- | --- | --- |
| `finance_keywords` | SPW-MAIL-003, SPW-MAIL-007 | invoice, payment, wire, bank, remittance, iban, swift, ach, payroll, w-2, w2, tax, refund, purchase order, overdue |
| `hiding_folders` | SPW-MAIL-003 | RSS Feeds, RSS Subscriptions, Conversation History, Archive, Junk Email, Deleted Items |
| `suspicious_user_agents` | SPW-ID-004 | axios, python-requests, python-urllib, go-http-client, curl, okhttp, BAV2ROPC |
| `risky_scopes` | consent rules | Mail.Read, Mail.ReadWrite, Mail.Send, Files.Read.All, Files.ReadWrite.All, offline_access, MailboxSettings.ReadWrite, full_access_as_user, EWS.AccessAsUser.All |
| `credential_failure_codes` | spray sources, SPW-ID-005, SPW-ID-006 | 50126, 50053, 50034, 50056, 50064, 50055, 50057 (rejected credentials only; not CA blocks 53003, token-refresh 70043/50173 or MFA prompts) |
| `hosting_asns` | every hosting-ASN test | 24 cloud / VPS / hosting ASNs (AWS, Google Cloud, Oracle, ...). Excludes Microsoft AS8075 and Cloudflare AS13335 |
| `microsoft_first_party_apps` | `cloud_services` (SPW-ID-002, -003, -010) | Microsoft first-party application ids, each taken from a public Microsoft Learn page |
| `collection_hints` | `sparrow coverage` | How to request more evidence per source from each collector (not used by detection) |

A case's own indicators are available to custom rules as `@list:case_iocs.<type>` (see
[`rules/README.md`](../rules/README.md#listcase_iocstype)). No built-in rule uses them.

## Running a subset of rules

```bash
sparrow detect --case case.duckdb                       # every rule, every tenant
sparrow detect --case case.duckdb --rule SPW-ID-005     # one rule (repeatable)
sparrow detect --case case.duckdb --tag correlation     # rules with a tag (repeatable)
sparrow rules lint                                      # validate rules and the coverage matrix
```

Add or override rules with `--rules DIR` (or `$SPARROW_RULES`). A rule file with the same `id`
replaces the built-in one. See
[Custom rule directories](../rules/README.md#custom-rule-directories).
