---
name: bec-triage
description: Playbook for triaging a Microsoft 365 business email compromise (BEC) from collector evidence (sign-in logs, unified audit log, inbox rules, mailbox forwarding, OAuth consents, MFA changes): what account takeover and persistence look like, how to clear the common benign look-alikes, and how to report. Use when asked to investigate a suspected M365 or Entra ID compromise, find compromised accounts, attacker IPs, malicious inbox rules, forwarding or OAuth apps, or to decide whether a finding is an attack or benign. Works on raw Hawk, Microsoft-Extractor-Suite or portal exports, or with any tool.
license: MIT
metadata:
  scope: m365-bec-triage
  tool-neutral: "true"
---

# M365 BEC triage

A playbook for deciding which accounts in a Microsoft 365 tenant were taken over, what the attacker did, and what
only looks suspicious. Tool-neutral: use it on raw collector files (Hawk, Microsoft-Extractor-Suite, portal
exports) or with any query tool. Fewer, targeted steps beat exhaustive ones: dig deep only where the evidence is
mixed.

## Working rules

1. **Name an account only with evidence**: at least one concrete attacker-side fact (a sign-in, a session, a rule, a
   consent) you can point to. If the evidence is thin, say "suspicious, not established" and what is missing.
2. **One command per call.** No shell loops, no `for`/`while`, no command substitution. Sandboxes often deny them
   and a denied call wastes a turn.
3. **Do not guess names.** Look up a table, column or field before you use it. When a command fails, fix the one
   thing the error names and retry once.
4. **Never stop without the answer.** Out of turns or a failing tool: write the best answer now, marked with what
   you could not check. A typical case needs 10-20 commands; past 25, answer with what the evidence shows.
5. **A capture is a time window.** "First seen in the capture" is not "first ever"; absence in the file is not
   absence in life.
6. **Check what evidence exists first.** A rule that cannot fire because its source is missing is a gap, not a
   clean result. Say so.

## How deep to look: decide per account

A benign look-alike is counter-evidence that lowers suspicion, never a verdict. Use the full check only where the
evidence is mixed:

| What the account shows | Do |
| --- | --- |
| Clear attacker evidence (a sign-in from attacker infrastructure or a new network, then persistence) | Name it. No extended procedure. |
| Mixed: a benign pattern fits AND something suspicious is there | Run the full check in [references/lookalikes.md](references/lookalikes.md): the benign explanation's own positive evidence AND no attacker signals around it. Then name it or clear it. |
| A benign-looking event and NO attacker signal on its account | Leave it. No deep dive. |

A familiar account, client or address is not proof of who was acting: a replayed session acts as the owner.

## What to extract per confirmed account

- The account (UPN) and the **first time** the attacker acted as it (UTC): the first attacker-side sign-in or
  action, not the first alert.
- The attacker IPs and ASNs seen acting as that account.
- Malicious inbox rules (mailbox and rule name as shown), forwarding (mailbox and external target), and OAuth
  applications the attacker consented to or registered (application id and name).
- Anything else the question asks for (mail read, files downloaded, links shared).

## Reporting

Follow the output format the task asks for exactly (for example one fenced JSON block at the end), with one short
evidence line per account before it. Say in one line each what you cleared and why, and what you could not
determine. No padding, no raw log dumps, no speculation about who the attacker is.

## References (load when needed)

- [references/workflow.md](references/workflow.md): the six triage steps (scope, candidates, story, clear or
  confirm, pivot from attacker infrastructure, report) and reporting detail.
- [references/attack-patterns.md](references/attack-patterns.md): what takeover and persistence look like.
- [references/lookalikes.md](references/lookalikes.md): the benign look-alikes and the full check.
