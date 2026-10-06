---
name: bec-triage
description: Playbook for triaging a Microsoft 365 business email compromise (BEC) from collector evidence (sign-in logs, unified audit log, inbox rules, mailbox forwarding, OAuth consents, MFA changes): what account takeover and persistence look like, how to clear the common benign look-alikes, and how to report. Use when asked to investigate a suspected M365 or Entra ID compromise, find compromised accounts, attacker IPs, malicious inbox rules, forwarding or OAuth apps, or to decide whether a finding is an attack or benign. Works on raw Hawk, Microsoft-Extractor-Suite or portal exports, or with any tool.
license: MIT
metadata:
  scope: m365-bec-triage
  tool-neutral: "true"
---

# M365 BEC triage

A playbook for deciding which accounts in a Microsoft 365 tenant were taken over, what the attacker did, and
what only looks suspicious. It is tool-neutral: apply it to raw collector files (Hawk, Microsoft-Extractor-Suite,
portal exports) or to whatever query tool you have. The evidence you need is in the checklist below; the
look-alike list is in [references/lookalikes.md](references/lookalikes.md) and the attack patterns in
[references/attack-patterns.md](references/attack-patterns.md). Read the look-alike list before you accuse
anyone.

## Working rules

1. **Name an account only with evidence.** Each account you call compromised needs at least one concrete,
   attacker-side fact (a sign-in, a session, a rule, a consent) that you can point to. A benign look-alike
   pattern is counter-evidence that lowers suspicion; it is never a verdict by itself. To clear a candidate you
   need both the benign explanation's own positive evidence and the absence of attacker signals around it
   (session or device change, replay, a preceding risky sign-in, other persistence, nearby suspicious actions).
   If the evidence is thin, say "suspicious, not established" and explain what is missing. A false accusation
   costs more than a hedged line, and so does clearing a real compromise.
2. **One command per call.** No shell loops, no `for`/`while`, no command substitution, no chained pipelines
   of many tools. Sandboxes often deny them, and a denied call wastes a turn. Run the same simple command again
   with a different argument instead.
3. **Do not guess names.** Look up a table, column or field name before you use it; do not invent it. When a
   command fails, read the error, fix the one thing it names, and retry once. Do not switch to a different
   approach five times in a row.
4. **Never stop without the answer.** If you are running out of turns or a tool keeps failing, write the best
   answer you have now, marked with what you could not check. A partial, honest answer beats none.
5. **A capture is a time window.** Absence in the file is not absence in life. "First seen in the capture" is
   not "first ever". Do not call something new or unusual because it starts at the edge of the window, and do
   not call it benign because it is not repeated inside it.
6. **Check availability first.** Know which evidence the capture holds (sign-ins? unified audit log? mailbox
   rules? Entra risk detections?) and what is missing. A rule that cannot fire because the evidence is absent is
   a gap, not a clean bill of health. Say so.

## Triage in six steps

1. **Scope.** What tenant, which window, which evidence kinds, which gaps. Which findings or alerts already
   exist (from a tool, or the collector's own risk and alert files)?
2. **Candidates.** From alerts and from the persistence artefacts: accounts with a new inbox rule, a forwarding
   address, a recent OAuth consent, an added MFA method, a risky or confirmed-compromised state, or a sign-in
   from hosting infrastructure or a country the user never used.
3. **Per candidate, build the story.** Entry (how the attacker got in: stolen session, spray success, phished
   password), the attacker's network (IP, ASN, country, user agent), the first attacker action time, then the
   persistence and the mail or file activity that followed. Use [references/attack-patterns.md](references/attack-patterns.md).
4. **Try to clear it, and try to break the clearance.** For every candidate, walk the look-alike list and look
   for the benign explanation's positive evidence on purpose (the application's publisher and consent history,
   the vendor sender, the owner's usual network). Then look for the attacker signals around it. A familiar
   account, client or address is not proof of who was acting: a replayed session acts as the owner.
5. **Pivot from the confirmed attacker infrastructure.** Every address and ASN of a confirmed takeover: which
   other accounts did it touch? Another account that signed in successfully from the same attacker address is
   a candidate, and one that only failed from it was sprayed, not taken over.
6. **Report** (below).

## What to extract per confirmed account

- The account (UPN) and the **first time** the attacker acted as it (UTC). Use the first attacker-side
  sign-in or action, not the first alert.
- The attacker IPs and their ASNs (the set seen acting as that account, not the user's own addresses).
- Malicious inbox rules: mailbox and rule name as shown (names like `.`, `..` or a single character, and rules
  that hide, delete, mark read or forward finance mail, are typical).
- Forwarding: mailbox and external target address (mailbox forwarding, rule forward or redirect, transport rule).
- OAuth applications the attacker consented to or registered: the application id and name.
- Anything else the attacker did that the question asks for (mail read, files downloaded, links shared).

## Reporting

- Follow the output format the task asks for exactly (for example one fenced JSON block at the end). Add one
  short evidence line per account in the free text before it.
- State what you **cleared** and why in one line each (account or artefact, the look-alike, the evidence).
  Reviewers want to see that you saw it and ruled it out.
- State what you could not determine and why (a missing source, a thin capture, a command that failed).
- Do not pad. Do not list every address in the case. Do not repeat raw logs; cite the record, the time and the
  fact.
- Keep to what the evidence shows. No speculation about who the attacker is.
