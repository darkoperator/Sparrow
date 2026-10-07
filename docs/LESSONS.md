# Lessons: building tools that AI agents use well

What we learned building Sparrow (an M365 BEC evidence ingester an AI agent drives through a CLI) and measuring it
against an agent working on the raw collector files. The principles are general; the numbers are Sparrow's.

All measurements: synthetic M365 captures with known ground truth, Claude Code headless, 5 seeds per cell, medians.
Treat them as indicative (one product, two models, synthetic data), not universal.

## 1. What the measurements showed

| Medium tree (500 users, 30 days) | Raw files | Sparrow |
|---|---|---|
| Sonnet: compromised-account F1 | 0.86 | **1.00** |
| Sonnet: total tokens | 868K | **427K (49%)** |
| Sonnet: agent turns | 27 | **18** |
| Sonnet: false accusations | 0 | 0 |
| Haiku: compromised-account F1 | 0.67 | 0.67 |
| Haiku: tokens | 2.24M | 2.26M (101%) |
| Haiku: false accusations (5 runs) | 11 | 6 |
| Sonnet + skill + account roll-up: tokens | — | **237K (27%)** |
| Haiku + skill + account roll-up: F1 / tokens | 0.67 / 2.25M (with playbook) | **1.00 / 869K** |

Across all sizes with Sonnet (no skills), the raw-file agent missed at least one compromised account in 10 of 15 runs; the
Sparrow agent missed none in the runs that produced an answer. On the largest tree the one-time ingest (159 s then; about 90 s after the ingest work below) cost
more than the whole raw run, although the agent part was faster.

## 2. Designing the tool itself

1. **Turns are the cost, not bytes.** Each agent turn re-sends the whole conversation; most "tokens" are cached context
   read again. A tool saves money by letting the agent finish in fewer calls, not only by returning smaller output.
   Sparrow's win was 18 turns instead of 27, more than smaller payloads.
2. **Do the expensive reasoning once, in the tool.** Parse once into typed, related tables; run detections in the
   store; hand the agent findings with evidence references. The agent then confirms leads instead of discovering them.
3. **Make the tool describe itself.** A `capabilities` view (what evidence exists and what does not) and a `schema`
   command with a comment on every column. Agents that cannot see the schema guess column names and burn turns on
   `SELECT * ... LIMIT 1`.
4. **Batch every lookup an agent will want to repeat.** Sandboxed agents cannot run shell loops; agents that try give up
   or waste turns. `finding show ID ID ID...` replaced a loop; it was used immediately.
5. **Filter in the tool, not in the agent.** `--user`, `--rule`, `--severity` on the list replaced repeated
   `... | jq 'select(...)'` calls. Every filter the agent writes in jq is a turn.
6. **Compact, stable JSON with explicit limits.** Every list has a limit and says when it truncated (`total`,
   `truncated`). An agent that does not know a list was cut draws wrong conclusions.
7. **Always offer a way back to the source.** `verify` takes the agent to the original file and line, so a conclusion
   can be checked without trusting the tool blindly.
8. **Safe by construction for an autonomous caller.** Read-only query on a locked connection; every agent write
   tagged as an AI decision pending human review; exit codes that distinguish "failed" from "completed with problems".
9. **Detections must not be the only door.** Findings are leads; the agent still needs pivots and SQL for what no rule
   covers. Strong models used both; the tool must make both cheap.

10. **Roll the case up per entity.** One `accounts` call (stages, first suspicious time, every address worth a look across
   all tables) replaced a findings → show → pivot chain. With it, both models found the attacker address that only
   appeared in mail-access records (Sonnet had missed it in every earlier run) and every forwarding target.
11. **Give facts, not verdicts, on the findings that are easy to misjudge.** Persistence findings now carry checkable facts
   (did this user sign in from the change's IP earlier in the capture; other findings on the account; each forwarding
   target internal or external, with prior messages). "Unknown" is never shown as zero, and stale facts are never
   shown at all. Haiku's false accusations of benign look-alikes fell from 6 to 3 without a skill.
12. **A capability the agent cannot discover does not exist.** Without the skill, no agent called `sparrow accounts`
   in 10 runs; the starting commands and the tool's own output never pointed to it. Point to new capabilities from
   the commands agents already run first (summary, capabilities, help).
13. **Profile before optimising the tool itself.** We assumed single-threaded parsing made ingest slow. A per-stage
   profile showed the embedded database's automatic checkpoint (every 16 MB of log, slower as the file grew) took half
   the time and software SHA-256 another eighth. One connection setting (a larger checkpoint threshold, scaled to the
   machine's memory, then one checkpoint at the end), hardware hashing and streaming the hash of skipped duplicate files
   halved ingest (190 s to 90 s) with less memory and byte-identical output; the parsing pipeline was left for later.

## 3. Model capability changes everything

- A strong model turns compact answers into savings. A weak model (Haiku) explored the same way it does on raw files —
  guessing, re-querying, 40-70 turns — and saved nothing.
- A tool cannot supply judgement. Haiku's errors were false accusations of planted benign look-alikes; better
  information halved them but did not remove them. Do not promise that a tool lets a small model replace a strong one
  without measuring it.

- With the account roll-up, facts and a lean skill, the same small model caught up on accuracy: Haiku found every
  compromised account (F1 1.00, was 0.67) and every attacker IP, with half the tokens (869K, was 1.83M). The tool
  could not supply judgement on its own, but a well-shaped tool plus instructions moved much of it out of the model.

## 4. Skills (agent instructions shipped with the tool)

1. **Use the open standard.** A `SKILL.md` per the Agent Skills spec (agentskills.io) works unchanged in Claude Code,
   Codex, OpenCode, Gemini CLI, Pi and others. Standard frontmatter only, actions as shell commands, no agent-specific
   tool names, one canonical copy installed into each agent's skills directory.
2. **Test skills against the real tool.** A drift test runs every command line in the skill through the real argument
   parser; a skill that teaches a flag the tool no longer has is worse than no skill.
3. **Discovery by description is unreliable for weak models.** Haiku never loaded a skill on its own. One explicit line
   ("load the skills available to you") fixed that. In real use, name the skill in the request.
4. **Agents read SKILL.md but rarely open references.** Put what the agent needs on every run (the 5 most-used tables'
   columns, the fast path) in SKILL.md itself; keep references for the rare cases.
5. **Every "always check X" rule costs turns.** Our first skill told the agent to treat every benign-looking pattern as
   counter-evidence and check session, device, history and nearby actions. It was correct, and it doubled Sonnet's
   tokens (18 → 29 turns) with no accuracy gain. Scope thoroughness: apply the deep check only before naming or clearing
   an account whose evidence is mixed. Give the agent a turn budget and a stop rule.
   The leaner v2 (a fast path first, the top columns inline, a 3-row "name / full check / leave it" table, a 25-command
   budget) brought the same agent to 17 turns and **295K tokens** with F1 1.00 on all 5 seeds:

   | Sonnet + Sparrow, medium | no skill | skill v1 | skill v2 |
   |---|---|---|---|
   | tokens (median) | 427K | 904K | **295K** |
   | turns (median) | 18 | 29 | **17** |
   | account F1 | 1.00 | 1.00 | 1.00 |

6. **A good playbook helps the baseline too.** The tool-neutral v2 playbook also cut the raw-file agent from 868K to
   542K tokens. When you measure a tool, give both arms the same playbook, and report the tool's gain against both the
   un-helped baseline (34% of its tokens here) and the helped one (55%).
7. **Write skills so they never teach dismissal of real attacks (and review them for it).** A look-alike is counter-evidence, never a verdict
   (a replayed session acts AS the owner; several phished accounts on one VPS can look like a SaaS connector). Have an
   independent reviewer read the skill specifically for "what would this make an agent wrongly ignore".

## 5. Benchmarking an agent tool honestly

1. **Decide the pass rule before the first run and do not move it.** Report extra views (agent time vs one-time
   ingest) as information rows, never as a changed verdict.
2. **Ground truth from the generator, never hand-written.** Derive it from the same world that wrote the evidence;
   test that every truth item is actually observable in the evidence, and that every entity type has all its aliases
   (an app has an app id, a service principal id and an object id — the agents answered with the "other" id).
3. **Hunt for synthetic tells — they are everywhere.** Each of these let an agent find the attacker without
   investigating, and each was found only by looking:
   - attacker addresses in their own documentation /24 (`203.0.113.x`) — the raw agent grepped `^203\.`;
   - a literal `exfil-mail.test` forwarding domain;
   - attacker-only ISP/ASN numbers and cities;
   - planted events on whole minutes while background traffic had random seconds;
   - every external forward belonging to an attacker (no benign one existed).
   Fix them behind a benchmark-only generator switch so existing test fixtures stay byte-identical.
4. **Isolate the agent at the OS level.** File tools take absolute paths; a restricted PATH does not stop `Read` on the
   answer file. Use an OS sandbox that denies the whole home directory and re-allows only the run's folders, an empty
   agent config (no user memory, CLAUDE.md, plugins), and probes before every paid run that prove the truth, the repo
   and the user's files are unreadable.
5. **Audit the session's start-up record.** Built-in plugins and bundled skills appear even in a clean config; accept
   them by explicit list, fail on anything else, and fail when an expected skill did NOT load.
6. **Detect escapes precisely.** Flag programs that ran, not words inside quoted arguments; still scan `$(...)` and
   backticks inside double quotes; report denied attempts separately.
7. **Parse transcripts loudly.** Missing usage is "unknown", never zero; a timed-out run without a result event is
   recorded as incomplete and left out of token medians but counted as a failure.
8. **Compare like with like.** Cohorts keyed by model, code version, scenario and variant; identical seeds in both
   arms; duplicates are an error.
9. **Pilot first, then scale.** Our pilot exposed a blocked shell scratch directory, built-in plugins failing
   isolation, the address-block tell and the app-id alias — before the money was spent on the full set.
10. **Use an adversarial reviewer on every round.** Independent review found the answer-file read path, the
    unfair byte count, coincidental coverage matches, pooled cohorts and three of the five synthetic tells.

## 6. Checklist for the next tool

- [ ] Typed store, parsed once; detections produce leads with evidence references.
- [ ] `capabilities` and `schema` (with comments); stable compact JSON; limits with `truncated`.
- [ ] Batch forms for every repeated lookup; server-side filters for every common question.
- [ ] A way back to the source record.
- [ ] A short skill per the open standard: fast path with exact commands, top columns inline, a turn budget and a stop
      rule, scoped thoroughness; a drift test against the real CLI; a reviewer pass for "what could it make an agent
      ignore".
- [ ] A benchmark with generator-derived truth, a leak hunt, OS isolation, a fixed pass rule, a pilot, and at least a
      strong and a weak model.
