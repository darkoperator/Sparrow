# Agent skills for Sparrow triage

Two portable [Agent Skills](https://agentskills.io/specification) for investigating a Microsoft 365 business email
compromise. They use only the standard `SKILL.md` format (name, description, license, metadata), so the same
folders work unchanged in Claude Code, Codex, OpenCode and Pi. Actions are plain shell commands.

| Skill | What it is |
| --- | --- |
| [`bec-triage`](bec-triage/SKILL.md) | A tool-neutral playbook: what a compromise looks like, how to clear the common benign look-alikes, and how to report. Works on raw collector files or any tool. |
| [`sparrow-triage`](sparrow-triage/SKILL.md) | The efficient workflow with the `sparrow` CLI: exact commands, ready SQL, the key tables and their columns, and the traps that waste turns. |

Install both: the Sparrow skill points at the playbook for the judgement calls.

This folder is the one canonical copy. Install by **symlink** (stays current with the repository) or **copy**. Replace
`/path/to/sparrow` with your checkout.

## Claude Code

Personal (all projects):

```bash
mkdir -p ~/.claude/skills
ln -s /path/to/sparrow/skills/bec-triage ~/.claude/skills/bec-triage
ln -s /path/to/sparrow/skills/sparrow-triage ~/.claude/skills/sparrow-triage
```

Per project: the same into `.claude/skills/` of the project.

## Codex, OpenCode and other agents that read `.agents/skills`

```bash
mkdir -p ~/.agents/skills
ln -s /path/to/sparrow/skills/bec-triage ~/.agents/skills/bec-triage
ln -s /path/to/sparrow/skills/sparrow-triage ~/.agents/skills/sparrow-triage
```

Per project: `.agents/skills/` of the project.

## Pi

```bash
mkdir -p ~/.pi/agent/skills
ln -s /path/to/sparrow/skills/bec-triage ~/.pi/agent/skills/bec-triage
ln -s /path/to/sparrow/skills/sparrow-triage ~/.pi/agent/skills/sparrow-triage
```

Per project: `.pi/skills/` of the project.

## Copy instead of linking

```bash
cp -R /path/to/sparrow/skills/bec-triage ~/.claude/skills/
cp -R /path/to/sparrow/skills/sparrow-triage ~/.claude/skills/
```

Re-copy after you update Sparrow, so the commands in the skill match your binary.

## What the skills need

`sparrow-triage` needs the `sparrow` binary on the `PATH` and a case database made with `sparrow ingest`. The
playbook needs nothing. The commands in the skills are checked against the CLI by a test
(`crates/sparrow-cli/tests/skills.rs`), so they do not drift.

## Maintaining

- Keep `name` equal to the folder name, `description` under 1024 characters, and each `SKILL.md` under 500 lines.
- Put detail in `references/`, one level deep, and link it with a relative path.
- Examples use reserved `.example` / `.test` domains and documentation IP ranges only; no customer data.
- A fenced command line that starts with `sparrow ` is parsed against the real CLI by the test: write real values
  or `<PLACEHOLDERS>` for the variable parts.
