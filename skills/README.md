# Agent skills for Sparrow triage

Two portable [Agent Skills](https://agentskills.io/specification) for investigating a Microsoft 365 business email
compromise. They use only the standard `SKILL.md` format (name, description, license, metadata), so the same
folders work unchanged in Claude Code, Codex, OpenCode and Pi. Actions are plain shell commands.

| Skill | What it is |
| --- | --- |
| [`bec-triage`](bec-triage/SKILL.md) | A tool-neutral playbook: what a compromise looks like, how to clear the common benign look-alikes, and how to report. Works on raw collector files or any tool. |
| [`sparrow-triage`](sparrow-triage/SKILL.md) | The efficient workflow with the `sparrow` CLI: exact commands, ready SQL, the key tables and their columns, and the traps that waste turns. |

Install both: the Sparrow skill points at the playbook for the judgement calls.

## Install

The `sparrow` binary carries the skills it was built with, so the commands they teach always match it:

```bash
sparrow skills install
sparrow skills status
```

`install` writes both skills for Claude Code, Codex/OpenCode and Pi, for your user; `status` says where they are and
whether each copy matches this binary. `--agent claude` (repeatable; `claude`, `agents` for Codex and OpenCode, or
`pi`) limits either to one agent, and `--project DIR` uses a project's folders instead of your home folder:

| Agent | Your user | A project |
| --- | --- | --- |
| Claude Code (`claude`) | `~/.claude/skills` | `.claude/skills` |
| Codex, OpenCode and others reading `.agents/skills` (`agents`) | `~/.agents/skills` | `.agents/skills` |
| Pi (`pi`) | `~/.pi/agent/skills` | `.pi/skills` |

After you update Sparrow, run `sparrow skills install` again: it updates the copies an earlier Sparrow installed
(`status` shows them as `stale`). It never overwrites a skill folder you edited or one Sparrow did not write
(`modified`, `foreign`; exit 1, `--force` replaces them), and never touches a symlink (`linked`). Each installed
folder holds `.sparrow-skill.json`, the Sparrow version and each file's SHA-256, which is how it tells them apart.

### From a checkout instead

This folder is the canonical copy. To follow a checkout as it changes, link it instead (`sparrow skills install`
then leaves the links alone); replace `/path/to/sparrow` with your checkout:

```bash
mkdir -p ~/.claude/skills
ln -s /path/to/sparrow/skills/bec-triage ~/.claude/skills/bec-triage
ln -s /path/to/sparrow/skills/sparrow-triage ~/.claude/skills/sparrow-triage
```

The same for `~/.agents/skills` or `~/.pi/agent/skills` (or a project's folders in the table above).

## Measured trade-off

On a benchmark (medium synthetic tree, five seeds, Sonnet), the first version of the skills kept the accuracy of the
Sparrow arm (F1 1.00) but raised its cost from 18 to 29 turns and from about 427K to 904K tokens: the agent applied
the full look-alike check to every lead, and every turn re-sends the whole conversation. Skills raise thoroughness;
this version targets turns. `sparrow-triage` opens with a fast path (scope, one `finding list`, one multi-id
`finding show`, pivots only for accounts it will name or clear as borderline, SQL only for what no finding shows) and
`bec-triage` runs the extended look-alike check only on accounts with mixed evidence. Smaller models also guessed
column names, so the common columns are inlined in `sparrow-triage`.

## What the skills need

`sparrow-triage` needs the `sparrow` binary on the `PATH` and a case database made with `sparrow ingest`. The
playbook needs nothing. The commands in the skills are checked against the CLI by a test
(`crates/sparrow-cli/tests/skills.rs`), so they do not drift.

## Maintaining

- Keep `name` equal to the folder name, `description` under 1024 characters, and each `SKILL.md` under 500 lines.
- The binary embeds every file here (`crates/sparrow-cli/src/cmd/skills.rs`); a test fails until a new or removed
  file is listed there too.
- Put detail in `references/`, one level deep, and link it with a relative path.
- Examples use reserved `.example` / `.test` domains and documentation IP ranges only; no customer data.
- A fenced command line that starts with `sparrow ` is parsed against the real CLI by the test: write real values
  or `<PLACEHOLDERS>` for the variable parts.
