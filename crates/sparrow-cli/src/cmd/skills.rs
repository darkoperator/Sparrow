//! `sparrow skills`: the agent skills in `skills/`, built into the binary so the commands they teach match it.
//! `install` writes them where Claude Code, Codex/OpenCode (`.agents/skills`) and Pi look for skills; `status` says
//! whether each copy is missing, current, from another Sparrow, edited, someone else's folder or a symlink. Each
//! installed folder holds `.sparrow-skill.json` (the Sparrow version and each file's SHA-256): a folder without it, or
//! whose files no longer match it, is never overwritten without `--force`, and a symlink is never touched.

use anyhow::{Context, Result, bail};
use clap::{Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use sparrow_core::hash::sha256_hex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Every file of every skill, as `<skill>/<path>`; a test checks this list against `skills/` in the repository.
const FILES: &[(&str, &str)] = &[
    (
        "bec-triage/SKILL.md",
        include_str!("../../../../skills/bec-triage/SKILL.md"),
    ),
    (
        "bec-triage/references/attack-patterns.md",
        include_str!("../../../../skills/bec-triage/references/attack-patterns.md"),
    ),
    (
        "bec-triage/references/lookalikes.md",
        include_str!("../../../../skills/bec-triage/references/lookalikes.md"),
    ),
    (
        "bec-triage/references/workflow.md",
        include_str!("../../../../skills/bec-triage/references/workflow.md"),
    ),
    (
        "sparrow-triage/SKILL.md",
        include_str!("../../../../skills/sparrow-triage/SKILL.md"),
    ),
    (
        "sparrow-triage/references/commands.md",
        include_str!("../../../../skills/sparrow-triage/references/commands.md"),
    ),
    (
        "sparrow-triage/references/notes.md",
        include_str!("../../../../skills/sparrow-triage/references/notes.md"),
    ),
    (
        "sparrow-triage/references/tables.md",
        include_str!("../../../../skills/sparrow-triage/references/tables.md"),
    ),
];

const SKILLS: [&str; 2] = ["bec-triage", "sparrow-triage"];
const MARKER: &str = ".sparrow-skill.json";

#[derive(Subcommand)]
pub enum SkillsCommand {
    /// Install the skills (or update a copy an earlier Sparrow installed). A folder Sparrow did not write, or one
    /// edited since, is kept unless --force; a symlink is never touched
    Install {
        /// Only this agent (repeatable): claude (~/.claude/skills), agents (~/.agents/skills: Codex, OpenCode) or
        /// pi (~/.pi/agent/skills); default all three
        #[arg(long = "agent", value_enum)]
        agents: Vec<Agent>,
        /// Into this project's .claude/skills, .agents/skills and .pi/skills instead of your home folder
        #[arg(long)]
        project: Option<PathBuf>,
        /// Replace a folder Sparrow did not write or one edited since it did (never a symlink)
        #[arg(long)]
        force: bool,
    },
    /// Where the skills are installed and whether each copy matches this binary. Read-only
    Status {
        #[arg(long = "agent", value_enum)]
        agents: Vec<Agent>,
        #[arg(long)]
        project: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Agent {
    Claude,
    Agents,
    Pi,
}

impl Agent {
    fn name(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Agents => "agents",
            Agent::Pi => "pi",
        }
    }

    /// The skills folder: in the home folder, or in a project.
    fn dir(self, base: &Path, project: bool) -> PathBuf {
        match (self, project) {
            (Agent::Claude, _) => base.join(".claude/skills"),
            (Agent::Agents, _) => base.join(".agents/skills"),
            (Agent::Pi, false) => base.join(".pi/agent/skills"),
            (Agent::Pi, true) => base.join(".pi/skills"),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Marker {
    sparrow: String,
    /// Path inside the skill folder -> SHA-256 of the file as installed.
    files: BTreeMap<String, String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum State {
    /// Not there.
    Missing,
    /// Installed by Sparrow, unedited, the same as this binary's.
    Current,
    /// Installed by another Sparrow, unedited: install updates it.
    Stale,
    /// Installed by Sparrow, edited since: kept unless --force.
    Modified,
    /// A folder Sparrow did not write: kept unless --force.
    Foreign,
    /// A symlink (e.g. to a checkout), or under one: never touched.
    Linked,
}

#[derive(Serialize)]
struct Row {
    agent: &'static str,
    skill: &'static str,
    path: String,
    state: State,
    /// `install` only: installed, updated, replaced, unchanged, kept or linked.
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<&'static str>,
}

/// This binary's files of one skill, keyed by their path inside the skill folder.
fn bundled(skill: &str) -> BTreeMap<String, &'static str> {
    let prefix = format!("{skill}/");
    FILES
        .iter()
        .filter_map(|(p, text)| p.strip_prefix(&prefix).map(|rel| (rel.to_string(), *text)))
        .collect()
}

fn bundled_hashes(skill: &str) -> BTreeMap<String, String> {
    bundled(skill)
        .into_iter()
        .map(|(rel, text)| (rel, sha256_hex(text.as_bytes())))
        .collect()
}

/// Every file under `dir` but the marker, as path inside it -> SHA-256.
fn disk_hashes(dir: &Path) -> Result<BTreeMap<String, String>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) -> Result<()> {
        for e in std::fs::read_dir(dir).with_context(|| dir.display().to_string())? {
            let p = e?.path();
            let rel = p.strip_prefix(root)?.to_string_lossy().replace('\\', "/");
            if rel == MARKER {
                continue;
            }
            if std::fs::symlink_metadata(&p)?.is_dir() {
                walk(root, &p, out)?;
            } else {
                out.insert(rel, sha256_hex(&std::fs::read(&p)?));
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out)?;
    Ok(out)
}

fn state_of(dir: &Path, skill: &str) -> Result<State> {
    let Ok(meta) = std::fs::symlink_metadata(dir) else {
        return Ok(State::Missing);
    };
    if meta.file_type().is_symlink() {
        return Ok(State::Linked);
    }
    if !meta.is_dir() {
        return Ok(State::Foreign);
    }
    let Ok(text) = std::fs::read_to_string(dir.join(MARKER)) else {
        return Ok(State::Foreign);
    };
    let Ok(marker) = serde_json::from_str::<Marker>(&text) else {
        return Ok(State::Foreign);
    };
    if disk_hashes(dir)? != marker.files {
        return Ok(State::Modified);
    }
    Ok(if marker.files == bundled_hashes(skill) {
        State::Current
    } else {
        State::Stale
    })
}

/// A name beside `dir` that no other run and nothing of the user's holds: `.<skill>.sparrow-<what>-<pid>-<n>`.
fn scratch(dir: &Path, skill: &str, what: &str) -> PathBuf {
    let parent = dir.parent().unwrap_or(dir);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    (0u32..)
        .map(|i| {
            parent.join(format!(
                ".{skill}.sparrow-{what}-{}-{stamp}-{i}",
                std::process::id()
            ))
        })
        .find(|p| std::fs::symlink_metadata(p).is_err())
        .unwrap_or_else(|| parent.join(format!(".{skill}.sparrow-{what}")))
}

/// Remove a file or a folder (not following a symlink).
fn remove_any(p: &Path) -> std::io::Result<()> {
    if std::fs::symlink_metadata(p)?.is_dir() {
        std::fs::remove_dir_all(p)
    } else {
        std::fs::remove_file(p)
    }
}

/// Write this binary's copy of `skill` at `dir`, replacing what is there (never a symlink: the caller checks).
fn write(dir: &Path, skill: &str) -> Result<()> {
    let parent = dir.parent().context("skill folder has no parent")?;
    std::fs::create_dir_all(parent).with_context(|| parent.display().to_string())?;
    // Build the new copy in a folder of our own beside it (created here, so never someone else's), then swap.
    let tmp = scratch(dir, skill, "new");
    std::fs::create_dir(&tmp).with_context(|| tmp.display().to_string())?;
    let built = (|| -> Result<()> {
        for (rel, text) in bundled(skill) {
            let path = tmp.join(&rel);
            std::fs::create_dir_all(path.parent().unwrap_or(&tmp))?;
            std::fs::write(&path, text)?;
        }
        let marker = Marker {
            sparrow: crate::bridge::VERSION.to_string(),
            files: bundled_hashes(skill),
        };
        std::fs::write(tmp.join(MARKER), serde_json::to_string_pretty(&marker)?)?;
        Ok(())
    })();
    if let Err(e) = built {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }
    swap(dir, &tmp, skill, &|from, to| std::fs::rename(from, to))
}

/// Put `tmp` at `dir`. What was at `dir` is moved aside first and removed only once `tmp` is in place; if that move
/// fails it goes back, so a failure never loses the old copy.
fn swap(
    dir: &Path,
    tmp: &Path,
    skill: &str,
    rename: &dyn Fn(&Path, &Path) -> std::io::Result<()>,
) -> Result<()> {
    let old = if std::fs::symlink_metadata(dir).is_ok() {
        let aside = scratch(dir, skill, "old");
        if let Err(e) = rename(dir, &aside) {
            let _ = std::fs::remove_dir_all(tmp);
            return Err(e).with_context(|| dir.display().to_string());
        }
        Some(aside)
    } else {
        None
    };
    if let Err(e) = rename(tmp, dir) {
        let _ = std::fs::remove_dir_all(tmp);
        if let Some(aside) = &old
            && rename(aside, dir).is_err()
        {
            return Err(e).with_context(|| {
                format!(
                    "{}: not replaced, and the previous copy could not be put back: it is at {}",
                    dir.display(),
                    aside.display()
                )
            });
        }
        return Err(e).with_context(|| dir.display().to_string());
    }
    if let Some(aside) = old {
        remove_any(&aside).with_context(|| aside.display().to_string())?;
    }
    Ok(())
}

/// Whether a folder between `base` and `root` (inclusive) is a symlink: such a target is not followed.
fn linked_on_the_way(base: &Path, root: &Path) -> bool {
    let Ok(rest) = root.strip_prefix(base) else {
        return true;
    };
    let mut at = base.to_path_buf();
    rest.components().any(|c| {
        at.push(c);
        std::fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_symlink())
    })
}

/// Each agent asked for, with its skills folder and whether a symlink lies on the way to it.
fn targets(agents: &[Agent], project: Option<&Path>) -> Result<Vec<(Agent, PathBuf, bool)>> {
    let (base, in_project) = match project {
        Some(p) => (p.to_path_buf(), true),
        None => (
            // Not `dirs::home_dir`: on Windows it asks the system and ignores `%USERPROFILE%`.
            std::env::home_dir().context("no home folder: pass --project DIR")?,
            false,
        ),
    };
    let all = [Agent::Claude, Agent::Agents, Agent::Pi];
    Ok(all
        .into_iter()
        .filter(|a| agents.is_empty() || agents.contains(a))
        .map(|a| {
            let root = a.dir(&base, in_project);
            let linked = linked_on_the_way(&base, &root);
            (a, root, linked)
        })
        .collect())
}

pub fn run(command: SkillsCommand, json: bool) -> Result<ExitCode> {
    let (rows, refused) = match command {
        SkillsCommand::Status { agents, project } => {
            let mut rows = Vec::new();
            for (agent, root, linked) in targets(&agents, project.as_deref())? {
                for skill in SKILLS {
                    let dir = root.join(skill);
                    rows.push(Row {
                        agent: agent.name(),
                        skill,
                        state: if linked {
                            State::Linked
                        } else {
                            state_of(&dir, skill)?
                        },
                        path: dir.display().to_string(),
                        action: None,
                    });
                }
            }
            (rows, 0)
        }
        SkillsCommand::Install {
            agents,
            project,
            force,
        } => {
            if let Some(p) = &project
                && !p.is_dir()
            {
                bail!("--project {}: not a folder", p.display());
            }
            let mut rows = Vec::new();
            let mut refused = 0;
            for (agent, root, linked) in targets(&agents, project.as_deref())? {
                for skill in SKILLS {
                    let dir = root.join(skill);
                    let before = if linked {
                        State::Linked
                    } else {
                        state_of(&dir, skill)?
                    };
                    let action = match before {
                        State::Current => "unchanged",
                        State::Linked => "linked",
                        State::Modified | State::Foreign if !force => {
                            refused += 1;
                            "kept"
                        }
                        State::Missing => {
                            write(&dir, skill)?;
                            "installed"
                        }
                        State::Stale => {
                            write(&dir, skill)?;
                            "updated"
                        }
                        State::Modified | State::Foreign => {
                            write(&dir, skill)?;
                            "replaced"
                        }
                    };
                    rows.push(Row {
                        agent: agent.name(),
                        skill,
                        state: if linked {
                            State::Linked
                        } else {
                            state_of(&dir, skill)?
                        },
                        path: dir.display().to_string(),
                        action: Some(action),
                    });
                }
            }
            (rows, refused)
        }
    };
    if json {
        crate::print_json(&serde_json::json!({
            "sparrow": crate::bridge::VERSION,
            "skills": rows,
        }))?;
    } else {
        for r in &rows {
            let what = r.action.unwrap_or(match r.state {
                State::Missing => "missing",
                State::Current => "current",
                State::Stale => "stale (from another Sparrow; install updates it)",
                State::Modified => "modified (edited since installed; kept, --force replaces it)",
                State::Foreign => "foreign (not installed by Sparrow; kept, --force replaces it)",
                State::Linked => "linked (a symlink, or under one; never touched)",
            });
            crate::outln!("{:<7} {:<15} {:<10} {}", r.agent, r.skill, what, r.path);
        }
    }
    if refused > 0 {
        crate::errln!(
            "{refused} skill folder(s) kept: edited since installed, or not installed by Sparrow; --force replaces them"
        );
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// When the new copy cannot be moved into place, the old one goes back and the scratch copy is removed.
    #[test]
    fn a_failed_swap_puts_the_old_copy_back() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("bec-triage");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), "the analyst's edit").unwrap();
        let tmp = root.path().join("new");
        std::fs::create_dir(&tmp).unwrap();
        std::fs::write(tmp.join("SKILL.md"), "new").unwrap();
        let calls = std::cell::Cell::new(0);
        let rename = |from: &Path, to: &Path| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                return Err(std::io::Error::other("disk full"));
            }
            std::fs::rename(from, to)
        };
        assert!(swap(&dir, &tmp, "bec-triage", &rename).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join("SKILL.md")).unwrap(),
            "the analyst's edit"
        );
        assert!(!tmp.exists());
        let names: Vec<String> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["bec-triage"]);
    }

    /// When putting the old copy back fails too, the error says where it is.
    #[test]
    fn a_failed_rollback_names_where_the_old_copy_is() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("bec-triage");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), "the analyst's edit").unwrap();
        let tmp = root.path().join("new");
        std::fs::create_dir(&tmp).unwrap();
        let calls = std::cell::Cell::new(0);
        let rename = |from: &Path, to: &Path| {
            calls.set(calls.get() + 1);
            if calls.get() >= 2 {
                return Err(std::io::Error::other("disk full"));
            }
            std::fs::rename(from, to)
        };
        let err = format!("{:#}", swap(&dir, &tmp, "bec-triage", &rename).unwrap_err());
        let aside = std::fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.to_string_lossy().contains(".bec-triage.sparrow-old-"))
            .expect("the old copy, moved aside");
        assert!(err.contains(&aside.display().to_string()), "{err}");
        assert_eq!(
            std::fs::read_to_string(aside.join("SKILL.md")).unwrap(),
            "the analyst's edit"
        );
    }

    /// The built-in list is every file of every skill in the repository, and nothing else.
    #[test]
    fn the_bundled_files_are_the_repositorys() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skills");
        let mut on_disk = Vec::new();
        for skill in SKILLS {
            for rel in disk_hashes(&root.join(skill)).unwrap().into_keys() {
                on_disk.push(format!("{skill}/{rel}"));
            }
        }
        on_disk.sort();
        let mut bundled: Vec<String> = FILES.iter().map(|(p, _)| p.to_string()).collect();
        bundled.sort();
        assert_eq!(bundled, on_disk);
        let dirs: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        let mut dirs = dirs;
        dirs.sort();
        assert_eq!(dirs, SKILLS);
    }
}
