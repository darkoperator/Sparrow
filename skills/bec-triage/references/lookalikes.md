# Benign look-alikes: counter-evidence, not verdicts

These patterns look like an attack in one signal. A benign pattern is **counter-evidence that lowers suspicion; it
is never a verdict by itself.** To clear a candidate you need BOTH:

- **(a)** the benign explanation's own positive evidence (not merely that the pattern fits), AND
- **(b)** the absence of the attacker signals around it: a session or device change, a replayed session, a risky
  or new-network sign-in just before, other persistence on the same account (rules, forwarding, consent, MFA
  method, permission), and nearby suspicious actions (mail reads from an unusual address, sends, downloads).

If (a) is missing or any signal in (b) is present, the candidate stays open: report it as suspicious with what
would settle it. An attacker who replays a victim's session acts AS the owner, from the owner's session, so a
familiar account, client or address never authenticates who was at the keyboard.

For each look-alike below: what makes it look bad, the benign evidence to look for, what is NOT enough, and the
attack contrast.

## External forwarding that may be authorised

Looks like: mailbox or rule forwarding to an external address.
Benign evidence (a): the owner set it in their own session from their usual network and client; the target is a
stable address the user or colleagues use elsewhere; there is a history of mail to that target; it matches a known
business reason (a partner, an assistant, a personal address documented by the owner or admin).
Check (b): the session's preceding use, any device or session change before it, a new-network or hosting sign-in
shortly before, the target's history in the tenant (first use?), hiding rules, consent, MFA change or mail reads
near it.
Not enough: the owner's UPN on the action, a familiar address, or a personal-looking target. An attacker also uses
the owner's session and personal mail providers.
Attack contrast: set within the hour after a new network or hosting sign-in, to an address nobody in the tenant
has used, together with hiding rules or other persistence.

## Vendor and filing rules

Looks like: an inbox rule that moves mail.
Benign evidence (a): it files a specific named sender or list into an ordinary project or invoice folder, does
not delete, forward, redirect or mark finance mail as read, and was created from Outlook on the owner's own
computer (client string, usual address) in a session with normal earlier use.
Check (b): no session or device change before it, no other rule or forwarding on the mailbox, no finance-keyword
condition, no hiding folder.
Not enough: an innocent folder name. Read the conditions, the actions and the creating address.
Attack contrast: a one-character or dot name, finance keywords as conditions, move to RSS Feeds or Archive, mark
as read, created from an address or session that appeared minutes earlier.

## Possible SaaS connector on a hosting ASN

Looks like: successful sign-ins from a hosting provider (a cloud ASN) to a third-party application, every day.
Treat it as a **possible connector**, not as cleared. The sign-in pattern alone cannot tell a connector from
several phished accounts used from one VPS: five or more accounts, one cloud ASN, several days and no failures can
look identical either way (and tools that excuse connectors will excuse that attack too).
Independent legitimacy (a), at least one: the application's publisher or verified publisher; a consent history
(who consented, admin consent, when, scopes that fit the product); long-standing tenant-wide use (the application
was already in use before the capture window, or appears for the tenants' users in many roles); an owner or
admin who deployed it.
Check (b) for EVERY account that uses it, not only the group: a replayed session, a sign-in from another network
for the same session, an inbox rule or forwarding, an MFA method or consent, mail reads from an unusual address.
Not enough: the user count, the number of days, a scripted user agent or the absence of failures. A connector
onboarded in the middle of the capture also looks like this, so do not demand day-one presence; ask for the
legitimacy evidence instead.
Residual to name in the report: several phished accounts of a third-party application on one VPS with no failures
can be indistinguishable from a connector by sign-in rows alone.
Attack contrast: Office or Outlook (first-party apps are never a connector), one or a few accounts, failures
first, the same application from a different ASN than the usual one, or persistence on any account that uses it.

## Plausible travel

Looks like: sign-ins from two places far apart.
Benign evidence (a): the time between them allows the trip; the device, user agent and MFA claim are the same;
later sign-ins stay in the new place; the user's calendar, mail or other activity fits.
Check (b): no replayed session id across the two places, no hosting address at one end, no persistence after.
Attack contrast: two places within minutes or hours, different devices or agents, the same session id at both,
persistence after.

## Office network and NAT mistypes

Looks like: many failed sign-ins from one address (a spray).
Benign evidence (a): the address is an office or shared egress where many users also **succeed**, mostly before
the failures and for days; each failure is a mistype followed by a success within minutes by the same user.
Check (b): no user succeeded from it only after a long gap; no account failed from it and then signed in from
another network; no persistence on a user who failed there.
Attack contrast: many users fail and almost none ever succeed from that address; or one succeeds hours later.

## Stale devices and departed accounts

Looks like: repeated failures (invalid password, disabled or deleted account) from one device.
Benign evidence (a): one or two users, the same device or user agent every time, often a phone with an old
password, a known departure.
Check (b): no success from another network after the failures; a departed account that suddenly succeeds is a
signal, not a stale device.

## MailItemsAccessed from sync

Looks like: a burst of mail item reads.
Benign evidence (a): the operation is a **Sync** (the client downloading folders) from the user's own device,
usual client and address, or a Bind burst from the user's Outlook right after they sign in at work.
Check (b): the session is the user's normal one, no new network or replay before it, no finance search, send or
download after it.
Attack contrast: binds from a hosting or new address, in a session that appeared after a takeover, with finance
searches or sends.

## Microsoft addresses and cloud PCs

Looks like: a sign-in from a cloud address in another country.
A Microsoft-owned address (a service range, a cloud PC, the Exchange back end) lowers the value of an IP-only
"hosting" signal: it is not a VPS the attacker rents. It does **not** clear a sign-in or an action: a compromised
cloud PC, or a Microsoft-hosted service abused by an attacker, can act from Microsoft addresses. Corroborate with
the session (who owned it, since when), the device, the application and the surrounding activity before you
dismiss it.

## First-time registrations and consents

- A new employee registering MFA or signing in from a new office in their first days.
- A low-risk consent (basic profile scopes) or a sign-in to an application consented long ago.
- A certificate rotation on an application by its owner.
- A risk detection that was dismissed as safe, with no further signal.
Benign evidence (a): the owner or admin context, a fitting timeline (first days, a known rotation window), the
consent's age. Check (b): not after a risky sign-in, no second signal on the account.

## Gateways and conference networks

A secure web gateway or conference network shared by many users (Conditional Access blocks, token-refresh errors,
a few mistyped passwords) is shared infrastructure, not a spray. Benign evidence (a): the number of users and the
successes from the same address. Check (b) for each user who failed there.

## The test for any look-alike

1. State the benign explanation and name its positive evidence. If you cannot, it is not cleared.
2. List the attacker signals you looked for around it (session or device change, replay, preceding risky or
   new-network sign-in, other persistence, nearby suspicious actions) and what you found.
3. If both hold, say it is cleared and why in one line. If not, say what is still open.
