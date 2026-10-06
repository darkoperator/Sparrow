# The triage steps

1. **Scope.** What tenant, which window, which evidence kinds, which gaps. Which findings or alerts already exist
   (from a tool, or the collector's own risk and alert files)?
2. **Candidates.** From alerts and from the persistence artefacts: accounts with a new inbox rule, a forwarding
   address, a recent OAuth consent, an added MFA method, a risky or confirmed-compromised state, or a sign-in from
   hosting infrastructure or a country the user never used. Group the leads by account.
3. **Per account you will name or clear as borderline, build the story.** Entry (how the attacker got in: stolen
   session, spray success, phished password), the attacker's network (IP, ASN, country, user agent), the first
   attacker action time, then the persistence and the mail or file activity that followed. See
   [attack-patterns.md](attack-patterns.md).
4. **Confirm or clear, in proportion.** Clear attacker evidence: name the account. Mixed evidence: run the full
   look-alike check ([lookalikes.md](lookalikes.md)): look for the benign explanation's positive evidence on purpose
   (the application's publisher and consent history, the vendor sender, the owner's usual network), then for the
   attacker signals around it. No attacker signal on the account: leave it alone.
5. **Pivot from confirmed attacker infrastructure.** Every address and ASN of a confirmed takeover: which other
   accounts did it touch? Another account that signed in successfully from the same attacker address is a
   candidate; one that only failed from it was sprayed, not taken over.
6. **Report.**

## Reporting detail

- Follow the task's output format exactly. Add one short evidence line per account in the free text before it.
- State what you **cleared** and why in one line each (account or artefact, the look-alike, the evidence), so a
  reviewer sees you saw it and ruled it out.
- State what you could not determine and why (a missing source, a thin capture, a command that failed).
- Do not list every address in the case. Cite the record, the time and the fact; do not repeat raw logs.
