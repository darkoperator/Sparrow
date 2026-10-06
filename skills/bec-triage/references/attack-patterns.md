# What a BEC compromise looks like

Each pattern lists the evidence that establishes it. A pattern alone is rarely enough: pair it with a
persistence step or a second signal, and run the look-alike list ([lookalikes.md](lookalikes.md)) before you
conclude.

## Entry

### Token theft / adversary-in-the-middle (AiTM)

A phishing proxy relays the real sign-in, steals the session cookie, and replays it.
- The victim signs in (often with MFA satisfied) and, minutes later, the **same session** is used from a
  different network: another IP, usually another ASN or country, often a hosting or proxy provider.
- The replayed sign-in claims MFA without a prompt (the claim travels in the stolen token).
- The user agent may change between the two halves, or be a scripted client.
- Risk: the sign-in may be rated medium or high, or the user marked at risk or confirmed compromised.
- Evidence that confirms: two sign-ins, one session id, two networks, within an hour; followed by persistence.

### Password spray, then takeover

One address tries one or two passwords against many accounts.
- Many distinct users fail (invalid password) from one address in a short period.
- A **success** from that same address for one of those users (sometimes hours or days later) is the takeover.
- Users who only failed were sprayed, not compromised. A user who succeeded from the address before their
  first failure, or within minutes after a typo, was just mistyping on their own network.

### Session replay from an ordinary ISP

A stolen session or token is used from a residential or mobile network in the user's own country, with no risk
rating, no hosting ASN, and no impossible travel.
- Signal: the user's first successful sign-in from a network they never used before, followed within the hour
  by a persistence action (rule, forwarding, consent, MFA method) from the new network or from the attacker's
  infrastructure.
- A new network alone proves nothing: people change ISPs, phones and offices. The persistence that follows is
  what makes it an attack.

### Sign-in from hosting infrastructure

A successful sign-in from a cloud or VPS provider (a hosting ASN) by a person who normally signs in from a
home or office ISP. Check the look-alike list (SaaS connectors, cloud desktops) first.

## Persistence

### Inbox rules

Rules that hide the victim's view of the attacker's mail:
- Names that are a single character, dots, or empty-looking (`.`, `..`).
- Actions: move to a rarely used folder (RSS Feeds, Archive, Conversation History, Junk), delete, mark as
  read, stop processing.
- Conditions on finance words (invoice, payment, wire, bank, remittance, IBAN) or on security-vendor senders.
- Forward or redirect to an external address.
- Created from the attacker's address or session, in the minutes after the entry sign-in. A rule that is created
  from the owner's own usual network and a normal client is probably the owner's.

### Forwarding

- Mailbox forwarding address set to an external address (with or without keeping a copy).
- A rule that forwards or redirects, or a tenant-wide transport rule.
- Who set it, from where, when: an admin or the owner from the usual network can be legitimate; an attacker
  sets it from attacker infrastructure shortly after the takeover.

### OAuth consent

- A user consents to an application with mail or file scopes (Mail.Read, Mail.ReadWrite, Mail.Send,
  Files.*, offline_access). Offline access gives the attacker a token that survives a password reset.
- Suspicious: a new application, unverified or unknown publisher, consent by one user shortly after a risky
  sign-in, broad scopes.
- A new credential (secret or certificate) added to an application or service principal is the app-level form.

### MFA changes

A new authentication method registered right after a risky or hosting sign-in, so the attacker keeps access.
A new employee registering MFA in their first days is normal.

### Other

- Mailbox permissions granted to another account (FullAccess, SendAs).
- Audit logging disabled or narrowed.
- Mail sent from an address the user never used (a fraud message to a customer).
- Bursts of mail item reads (MailItemsAccessed bind) from the attacker's address, or mass downloads, or
  anonymous sharing links created shortly after the takeover.

## Timing

The first compromise time is the first attacker-side action as that account, in UTC. If the first thing you can
see is a persistence action, the sign-in before it (same session, same address, within the hour) is earlier.
Say how sure you are of the time.
