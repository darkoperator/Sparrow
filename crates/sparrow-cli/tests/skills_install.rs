//! `sparrow skills install|status`: the agent skills built into the binary, installed for Claude Code, Codex/OpenCode
//! (`.agents/skills`) and Pi. A folder Sparrow did not write, or one edited since, is never overwritten without
//! `--force`; a symlink (a checkout someone links to) is never touched.

use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};

const SKILLS: [&str; 2] = ["bec-triage", "sparrow-triage"];

fn repo_skills() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skills")
}

/// `sparrow skills ARGS --json` with HOME at `home`; the exit code and the JSON.
fn skills(home: &Path, args: &[&str]) -> (i32, Value) {
    let out = Command::cargo_bin("sparrow")
        .unwrap()
        .env("HOME", home)
        .env_remove("SPARROW_BRIDGE")
        .arg("skills")
        .args(args)
        .arg("--json")
        .output()
        .unwrap();
    let json = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), json)
}

/// The state `status` reports for one agent's copy of one skill.
fn state(json: &Value, agent: &str, skill: &str) -> String {
    json["skills"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["agent"] == agent && s["skill"] == skill)
        .unwrap_or_else(|| panic!("no {agent}/{skill} in {json}"))["state"]
        .as_str()
        .unwrap()
        .to_string()
}

fn homes(home: &Path) -> [(&'static str, PathBuf); 3] {
    [
        ("claude", home.join(".claude/skills")),
        ("agents", home.join(".agents/skills")),
        ("pi", home.join(".pi/agent/skills")),
    ]
}

fn same_tree(installed: &Path, skill: &str) {
    let repo = repo_skills().join(skill);
    for f in walk(&repo) {
        let rel = f.strip_prefix(&repo).unwrap();
        assert_eq!(
            std::fs::read(installed.join(rel)).unwrap(),
            std::fs::read(&f).unwrap(),
            "{}",
            rel.display()
        );
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[test]
fn install_writes_every_skill_for_every_agent_and_status_says_current() {
    let home = tempfile::tempdir().unwrap();
    let (code, json) = skills(home.path(), &["status"]);
    assert_eq!(code, 0);
    assert_eq!(state(&json, "claude", "sparrow-triage"), "missing");
    let (code, _) = skills(home.path(), &["install"]);
    assert_eq!(code, 0);
    for (agent, dir) in homes(home.path()) {
        for skill in SKILLS {
            same_tree(&dir.join(skill), skill);
            assert!(dir.join(skill).join(".sparrow-skill.json").is_file());
        }
        let (_, json) = skills(home.path(), &["status"]);
        for skill in SKILLS {
            assert_eq!(state(&json, agent, skill), "current");
        }
    }
    // Installing again changes nothing and succeeds.
    let (code, json) = skills(home.path(), &["install"]);
    assert_eq!(code, 0);
    assert!(
        json["skills"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["action"] == "unchanged"),
        "{json}"
    );
}

#[test]
fn an_edited_copy_is_kept_unless_forced() {
    let home = tempfile::tempdir().unwrap();
    skills(home.path(), &["install", "--agent", "claude"]);
    let skill_md = home.path().join(".claude/skills/sparrow-triage/SKILL.md");
    std::fs::write(&skill_md, "my own notes").unwrap();
    let (_, json) = skills(home.path(), &["status", "--agent", "claude"]);
    assert_eq!(state(&json, "claude", "sparrow-triage"), "modified");
    assert_eq!(state(&json, "claude", "bec-triage"), "current");
    // Refused: exit 1, the edit kept, the other skill still fine.
    let (code, json) = skills(home.path(), &["install", "--agent", "claude"]);
    assert_eq!(code, 1, "{json}");
    assert_eq!(std::fs::read_to_string(&skill_md).unwrap(), "my own notes");
    // An extra file is an edit too.
    std::fs::write(
        &skill_md,
        std::fs::read(repo_skills().join("sparrow-triage/SKILL.md")).unwrap(),
    )
    .unwrap();
    std::fs::write(skill_md.with_file_name("mine.md"), "x").unwrap();
    let (_, json) = skills(home.path(), &["status", "--agent", "claude"]);
    assert_eq!(state(&json, "claude", "sparrow-triage"), "modified");
    // --force puts the built-in copy back, extra file gone.
    let (code, _) = skills(home.path(), &["install", "--agent", "claude", "--force"]);
    assert_eq!(code, 0);
    same_tree(
        &home.path().join(".claude/skills/sparrow-triage"),
        "sparrow-triage",
    );
    assert!(!skill_md.with_file_name("mine.md").exists());
}

#[test]
fn a_copy_from_an_older_sparrow_is_updated() {
    let home = tempfile::tempdir().unwrap();
    skills(home.path(), &["install", "--agent", "pi"]);
    let dir = home.path().join(".pi/agent/skills/bec-triage");
    // As an older release would have left it: different SKILL.md, its marker recording that text.
    std::fs::write(dir.join("SKILL.md"), "older text").unwrap();
    let marker = dir.join(".sparrow-skill.json");
    let mut m: Value = serde_json::from_str(&std::fs::read_to_string(&marker).unwrap()).unwrap();
    m["files"]["SKILL.md"] = Value::from(sparrow_core::hash::sha256_hex(b"older text"));
    m["sparrow"] = Value::from("0.0.1");
    std::fs::write(&marker, serde_json::to_string(&m).unwrap()).unwrap();
    let (_, json) = skills(home.path(), &["status", "--agent", "pi"]);
    assert_eq!(state(&json, "pi", "bec-triage"), "stale");
    let (code, json) = skills(home.path(), &["install", "--agent", "pi"]);
    assert_eq!(code, 0, "{json}");
    same_tree(&dir, "bec-triage");
    let (_, json) = skills(home.path(), &["status", "--agent", "pi"]);
    assert_eq!(state(&json, "pi", "bec-triage"), "current");
}

#[test]
fn a_folder_sparrow_did_not_write_and_a_symlink_are_left_alone() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join(".agents/skills");
    std::fs::create_dir_all(dir.join("bec-triage")).unwrap();
    std::fs::write(dir.join("bec-triage/SKILL.md"), "someone else's").unwrap();
    let checkout = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(checkout.path(), dir.join("sparrow-triage")).unwrap();
    let (_, json) = skills(home.path(), &["status", "--agent", "agents"]);
    assert_eq!(state(&json, "agents", "bec-triage"), "foreign");
    #[cfg(unix)]
    assert_eq!(state(&json, "agents", "sparrow-triage"), "linked");
    let (code, _) = skills(home.path(), &["install", "--agent", "agents"]);
    assert_eq!(code, 1);
    assert_eq!(
        std::fs::read_to_string(dir.join("bec-triage/SKILL.md")).unwrap(),
        "someone else's"
    );
    // --force replaces the foreign folder but never follows or replaces a symlink.
    let (_, json) = skills(home.path(), &["install", "--agent", "agents", "--force"]);
    same_tree(&dir.join("bec-triage"), "bec-triage");
    #[cfg(unix)]
    {
        assert_eq!(state(&json, "agents", "sparrow-triage"), "linked");
        assert!(
            std::fs::symlink_metadata(dir.join("sparrow-triage"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_dir(checkout.path()).unwrap().count(), 0);
    }
}

#[test]
fn project_installs_go_into_the_project_only() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let (code, _) = skills(
        home.path(),
        &["install", "--project", project.path().to_str().unwrap()],
    );
    assert_eq!(code, 0);
    for rel in [".claude/skills", ".agents/skills", ".pi/skills"] {
        for skill in SKILLS {
            same_tree(&project.path().join(rel).join(skill), skill);
        }
    }
    assert!(!home.path().join(".claude").exists());
}

#[test]
fn one_agent_touches_only_its_folder() {
    let home = tempfile::tempdir().unwrap();
    let (code, json) = skills(home.path(), &["install", "--agent", "claude"]);
    assert_eq!(code, 0);
    assert!(
        home.path()
            .join(".claude/skills/bec-triage/SKILL.md")
            .is_file()
    );
    assert!(!home.path().join(".agents").exists() && !home.path().join(".pi").exists());
    assert!(
        json["skills"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["agent"] == "claude")
    );
}

#[test]
fn skills_never_go_through_the_app() {
    let args = |v: &[&str]| v.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
    let seen = sparrow_cli::inspect(&args(&["sparrow", "skills", "install"]));
    assert!(matches!(seen.kind, sparrow_cli::Kind::Local));
}

#[test]
fn other_entries_beside_the_skills_survive_an_install() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join(".claude/skills");
    // Names an older build used for its scratch copy, and any other dot folder: not Sparrow's to remove.
    for name in [
        ".bec-triage.sparrow-tmp",
        ".sparrow-triage.sparrow-tmp",
        ".mine",
    ] {
        std::fs::create_dir_all(dir.join(name)).unwrap();
        std::fs::write(dir.join(name).join("keep.txt"), "keep").unwrap();
    }
    skills(home.path(), &["install", "--agent", "claude"]);
    skills(home.path(), &["install", "--agent", "claude", "--force"]);
    for name in [
        ".bec-triage.sparrow-tmp",
        ".sparrow-triage.sparrow-tmp",
        ".mine",
    ] {
        assert_eq!(
            std::fs::read_to_string(dir.join(name).join("keep.txt")).unwrap(),
            "keep",
            "{name}"
        );
    }
    // Nothing of Sparrow's own scratch is left behind.
    let left: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with('.') && n.contains(".sparrow-") && !n.ends_with(".sparrow-tmp"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

#[cfg(unix)]
#[test]
fn a_symlink_on_the_way_to_the_skills_folder_is_not_followed() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), project.path().join(".agents")).unwrap();
    let p = project.path().to_str().unwrap();
    let (_, json) = skills(
        home.path(),
        &["status", "--project", p, "--agent", "agents"],
    );
    assert_eq!(state(&json, "agents", "bec-triage"), "linked");
    let (code, json) = skills(home.path(), &["install", "--project", p, "--force"]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(state(&json, "agents", "sparrow-triage"), "linked");
    assert_eq!(std::fs::read_dir(elsewhere.path()).unwrap().count(), 0);
    // The other agents' folders, which are real, are installed.
    same_tree(
        &project.path().join(".claude/skills/bec-triage"),
        "bec-triage",
    );
}

#[test]
fn a_file_where_the_skill_folder_goes_is_foreign_and_force_replaces_it() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join(".pi/agent/skills");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("bec-triage"), "a file").unwrap();
    let (_, json) = skills(home.path(), &["status", "--agent", "pi"]);
    assert_eq!(state(&json, "pi", "bec-triage"), "foreign");
    let (code, _) = skills(home.path(), &["install", "--agent", "pi"]);
    assert_eq!(code, 1);
    assert_eq!(
        std::fs::read_to_string(dir.join("bec-triage")).unwrap(),
        "a file"
    );
    let (code, json) = skills(home.path(), &["install", "--agent", "pi", "--force"]);
    assert_eq!(code, 0, "{json}");
    same_tree(&dir.join("bec-triage"), "bec-triage");
}
