# Benign look-alikes, and the evidence that clears each

These look like an attack in one signal. For each one, the table says what makes it look bad, what concrete
evidence clears it, and what would NOT clear it. Look for the clearing evidence deliberately before you accuse.

## Authorised external forwarding

Looks like: mailbox or rule forwarding to an external address.
Clear it when: it was set from the owner's usual network and client in their own normal session (no new network,
no hosting address, no risky sign-in before it), the target is a stable business or personal address the user
uses elsewhere, and nothing else suspicious (hiding rules, consent, MFA change) is near it.
Not cleared by: the target looking like a personal mail provider. An attacker also uses those.
Attack contrast: set within the hour after a new network or hosting sign-in, to an address no one else in the
tenant has used, together with hiding rules.

## Vendor and filing rules

Looks like: an inbox rule that moves mail.
Clear it when: it files a specific named sender or list into an ordinary project or invoice folder, does not
delete, forward, redirect or mark finance mail as read, and was created from Outlook on the owner's own computer
at their usual address.
Not cleared by: the folder name sounding innocent. Check the conditions and the actions, and the creating
address.
Attack contrast: a one-character or dot name, finance keywords as conditions, move to RSS Feeds or Archive,
mark as read, created from the attacker's address or session.

## SaaS connectors on hosting ASNs

Looks like: successful sign-ins from a hosting provider (a cloud ASN) to a third-party application, every day.
Clear it when: the same application signs **many** users in (five or more) from the same cloud ASN on several
days, with a scripted or service user agent, no failures, and it is a third-party application (not Office or
Outlook). A connector that was onboarded in the middle of the capture still looks exactly like this: do not
require it to be there on day one.
Not cleared by: a single user on a VPS, or phished accounts using Office or Outlook from a VPS. Microsoft
first-party applications are never a connector.
Attack contrast: one or a few accounts, an Office or Outlook application, failures first, or the same
application from a different hosting ASN than the connector's.

## Plausible travel

Looks like: sign-ins from two places far apart.
Clear it when: the time between them allows the trip (a flight), the device, user agent and MFA are the same,
the later sign-ins stay in the new place, and no persistence follows.
Attack contrast: two places within minutes or hours, different devices or agents, a hosting ASN at one end,
persistence after.

## Office network and NAT mistypes

Looks like: many failed sign-ins from one address (a spray).
Clear it when: the address is an office or shared egress where many users also **succeed**, mostly before the
failures and for days, the failures are a mistype followed by a success within minutes by the same user, and no
user succeeded from it only after a long gap.
Attack contrast: many users fail and almost none ever succeed from that address; or one succeeds hours later.

## Stale devices and departed accounts

Looks like: repeated failures (invalid password, disabled or deleted account) from one device.
Clear it when: one or two users, the same device or user agent every time, often a phone with an old password,
no success from another network.

## MailItemsAccessed from sync

Looks like: a burst of mail item reads.
Clear it when: the operation is a **Sync** (the client downloading folders) from the user's own device, usual
client and address, or a Bind burst from the user's Outlook at their usual address after they sign in at work.
Attack contrast: binds from a hosting or new address, in the attacker's session, after a takeover, and with
finance searches or sends.

## Microsoft addresses and cloud PCs

Looks like: a sign-in from a cloud address in another country.
Clear it when: the address belongs to Microsoft's own service ranges (a cloud PC, Exchange back end, Graph). These
are not attacker infrastructure. Microsoft's ASN is not a hosting provider here.

## First-time registrations and consents

- A new employee registering MFA or signing in from a new office in their first days.
- A low-risk consent (basic profile scopes) or a sign-in to an app consented long ago.
- A certificate rotation on an application by its owner.
- A risk detection that was dismissed as safe, with no further signal.
Clear each one by its owner, its timing (not after a risky sign-in) and the absence of a second signal.

## Gateways and conference networks

A secure web gateway or conference network shared by many users (Conditional Access blocks, token-refresh errors,
a few mistyped passwords) is shared infrastructure, not a spray. Clear it by the number of users and by the
successes from the same address.

## The test for any look-alike

Ask: is the actor the owner, from their usual network and client? Do many unrelated users do the same thing
from the same place (shared infrastructure)? Is there a second attacker-side signal (risky sign-in, hosting
address, hiding rule, consent, MFA change) within the hour? If the owner and a usual network explain it and
there is no second signal, clear it and say why.
