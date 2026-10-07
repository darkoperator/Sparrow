//! The portable Agent Skills under `skills/` at the repository root: the frontmatter follows the open
//! Agent Skills specification, every relative link resolves, every `sparrow ...` command line in a fenced block
//! still parses against the real CLI (the drift test), and no skill file holds a non-reserved address, domain
//! or URL host.

use assert_cmd::Command;
use std::path::{Path, PathBuf};

fn skills_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skills")
}

/// Every file under `dir` (recursively) whose name ends with `.md`, sorted.
fn markdown_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "md") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The skill folders: every directory of `skills/` (each must hold a SKILL.md).
fn skill_dirs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(skills_root())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    v.sort();
    v
}

struct Frontmatter {
    /// Top-level keys in file order.
    keys: Vec<String>,
    name: String,
    description: String,
    /// The text after the closing `---`.
    body: String,
}

/// The frontmatter of a SKILL.md: a `---` fence, `key: value` lines (a key with no value opens an indented
/// map such as `metadata`), a closing `---`. Only the single-line scalar form is used by these skills.
fn frontmatter(path: &Path) -> Frontmatter {
    let text = std::fs::read_to_string(path).unwrap();
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some("---"),
        "{}: no opening fence",
        path.display()
    );
    let (mut keys, mut name, mut description) = (Vec::new(), String::new(), String::new());
    let mut closed = false;
    let mut consumed = 1;
    for l in lines.by_ref() {
        consumed += 1;
        if l == "---" {
            closed = true;
            break;
        }
        if l.starts_with(' ') || l.starts_with('\t') {
            continue; // a child of the previous map key
        }
        let (k, v) = l
            .split_once(':')
            .unwrap_or_else(|| panic!("{}: not a key: {l:?}", path.display()));
        keys.push(k.to_string());
        let v = v.trim();
        match k {
            "name" => name = v.to_string(),
            "description" => description = v.to_string(),
            _ => {}
        }
    }
    assert!(closed, "{}: no closing fence", path.display());
    let body = text.lines().skip(consumed).collect::<Vec<_>>().join("\n");
    Frontmatter {
        keys,
        name,
        description,
        body,
    }
}

#[test]
fn there_are_skills_and_each_folder_holds_a_skill_md() {
    let dirs = skill_dirs();
    let names: Vec<_> = dirs
        .iter()
        .map(|d| d.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["bec-triage", "sparrow-triage"]);
    for d in &dirs {
        assert!(d.join("SKILL.md").is_file(), "{}", d.display());
    }
    assert!(skills_root().join("README.md").is_file());
}

/// The Agent Skills specification: `name` is 1-64 characters of lowercase letters, digits and hyphens, no
/// leading, trailing or doubled hyphen, equal to the folder; `description` is 1-1024 characters; only the
/// standard keys; the file stays under 500 lines.
#[test]
fn every_skill_has_valid_frontmatter() {
    const STANDARD: [&str; 6] = [
        "name",
        "description",
        "license",
        "compatibility",
        "metadata",
        "allowed-tools",
    ];
    for d in skill_dirs() {
        let folder = d.file_name().unwrap().to_string_lossy().into_owned();
        let path = d.join("SKILL.md");
        let fm = frontmatter(&path);
        let n = &fm.name;
        assert!(
            !n.is_empty() && n.len() <= 64,
            "{folder}: name length {}",
            n.len()
        );
        assert!(
            n.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "{folder}: name {n:?}"
        );
        assert!(
            !n.starts_with('-') && !n.ends_with('-') && !n.contains("--"),
            "{folder}: name {n:?}"
        );
        assert_eq!(n, &folder, "name must equal the folder");
        let len = fm.description.chars().count();
        assert!(
            (1..=1024).contains(&len),
            "{folder}: description is {len} characters"
        );
        for k in &fm.keys {
            assert!(
                STANDARD.contains(&k.as_str()),
                "{folder}: non-standard key {k:?}"
            );
        }
        assert!(fm.keys.iter().filter(|k| *k == "name").count() == 1);
        let lines = std::fs::read_to_string(&path).unwrap().lines().count();
        assert!(lines < 500, "{folder}: SKILL.md has {lines} lines");
        assert!(
            fm.body.lines().count() > 20,
            "{folder}: body is suspiciously short"
        );
        // The description says what and when: it carries a trigger phrase.
        assert!(
            fm.description.contains("Use when"),
            "{folder}: description has no 'Use when'"
        );
    }
}

/// References are one level deep: `references/` holds files only.
#[test]
fn references_are_one_level_deep() {
    for d in skill_dirs() {
        let r = d.join("references");
        if r.is_dir() {
            for e in std::fs::read_dir(&r).unwrap() {
                assert!(
                    e.unwrap().path().is_file(),
                    "{}: nested folder",
                    r.display()
                );
            }
        }
    }
}

/// Every relative Markdown link of every skill file resolves from the file's own folder.
#[test]
fn every_relative_link_resolves() {
    let link = regex_lite_links();
    let mut checked = 0;
    for f in markdown_files(&skills_root()) {
        let text = std::fs::read_to_string(&f).unwrap();
        for target in link(&text) {
            if target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with('#')
            {
                continue;
            }
            let path = target.split('#').next().unwrap();
            let resolved = f.parent().unwrap().join(path);
            assert!(resolved.exists(), "{}: broken link {target}", f.display());
            checked += 1;
        }
    }
    assert!(checked >= 6, "only {checked} relative links checked");
}

/// The targets of `](...)` in Markdown text (no regex crate in this test target).
fn regex_lite_links() -> impl Fn(&str) -> Vec<String> {
    |text: &str| {
        let mut out = Vec::new();
        let mut rest = text;
        while let Some(i) = rest.find("](") {
            let after = &rest[i + 2..];
            if let Some(j) = after.find(')') {
                out.push(after[..j].to_string());
                rest = &after[j + 1..];
            } else {
                break;
            }
        }
        out
    }
}

/// No tool, hook, slash command or subagent that only one agent product has.
#[test]
fn skills_name_no_agent_specific_features() {
    for d in skill_dirs() {
        for f in markdown_files(&d) {
            let text = std::fs::read_to_string(&f).unwrap().to_ascii_lowercase();
            for bad in [
                "subagent",
                "slash command",
                "sessionstart",
                "webfetch",
                "askuserquestion",
                "allowed-tools",
                "pretooluse",
            ] {
                assert!(!text.contains(bad), "{}: mentions {bad}", f.display());
            }
        }
    }
}

// ------------------------------------------------------------------ drift: the commands still parse

/// Every line that starts with `sparrow ` inside a fenced code block of a skill file, with its file.
fn command_lines() -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    for f in markdown_files(&skills_root()) {
        let text = std::fs::read_to_string(&f).unwrap();
        let mut fenced = false;
        for l in text.lines() {
            if l.trim_start().starts_with("```") {
                fenced = !fenced;
            } else if fenced && l.starts_with("sparrow ") {
                out.push((f.clone(), l.to_string()));
            }
        }
    }
    out
}

/// Split a command line into words, honouring single and double quotes (no escapes, no expansion).
fn words(line: &str) -> Vec<String> {
    let (mut out, mut cur, mut quote, mut has) = (Vec::new(), String::new(), None, false);
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                has = true;
            }
            (None, c) if c.is_whitespace() => {
                if has || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    assert!(quote.is_none(), "unbalanced quote in {line:?}");
    if has || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Replace every `<PLACEHOLDER>` by a valid dummy.
fn substitute(word: &str) -> String {
    let mut out = String::new();
    let mut rest = word;
    while let Some(i) = rest.find('<') {
        match rest[i..].find('>') {
            Some(j) => {
                out.push_str(&rest[..i]);
                out.push_str("dummy");
                rest = &rest[i + j + 1..];
            }
            None => break,
        }
    }
    out.push_str(rest);
    out
}

/// Options that take a value, to count a command's positionals.
const VALUE_FLAGS: &[&str] = &[
    "--case",
    "--data",
    "--rules",
    "--limit",
    "--cap",
    "--severity",
    "--user",
    "--rule",
    "--status",
    "--tenant",
    "--table",
    "--from",
    "--to",
    "--ip",
    "--category",
    "--finding",
    "--type",
    "--value",
    "--verdict",
    "--note",
    "--reason",
    "--agent",
    "--analyst",
    "--root",
    "--text",
    "--review-state",
    "--rule-updated",
];

/// The commands cli-agent-aids adds (not in this CLI yet): `schema --table`, `finding show` with several ids,
/// `finding list` with a repeated `--rule`. Their lines are checked by the ignored test below.
fn uses_new_command(w: &[String]) -> bool {
    let positionals = |from: usize| {
        let mut n = 0;
        let mut i = from;
        while i < w.len() {
            if w[i].starts_with("--") {
                i += if VALUE_FLAGS.contains(&w[i].as_str()) {
                    2
                } else {
                    1
                };
            } else {
                n += 1;
                i += 1;
            }
        }
        n
    };
    match (w.get(1).map(String::as_str), w.get(2).map(String::as_str)) {
        (Some("schema"), _) => w.iter().any(|x| x == "--table"),
        (Some("finding"), Some("show")) => positionals(3) >= 2,
        (Some("finding"), Some("list")) => w.iter().filter(|x| *x == "--rule").count() >= 2,
        _ => false,
    }
}

/// Run `sparrow <words after the first> --help`: the parser accepts the subcommand, every option and every
/// value, or exits with a usage error (code 2).
fn parses(line: &str) -> Result<(), String> {
    let w: Vec<String> = words(line).iter().map(|x| substitute(x)).collect();
    assert_eq!(w[0], "sparrow");
    let out = Command::cargo_bin("sparrow")
        .unwrap()
        .args(&w[1..])
        .arg("--help")
        .output()
        .unwrap();
    if out.status.code() == Some(0) {
        Ok(())
    } else {
        Err(format!(
            "{line}\n  exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .next()
                .unwrap_or("")
        ))
    }
}

fn check(lines: Vec<(PathBuf, String)>) -> usize {
    let n = lines.len();
    let bad: Vec<String> = lines
        .iter()
        .filter_map(|(f, l)| parses(l).err().map(|e| format!("{}: {e}", f.display())))
        .collect();
    assert!(
        bad.is_empty(),
        "commands that no longer parse:\n{}",
        bad.join("\n")
    );
    n
}

#[test]
fn the_skills_commands_still_parse_against_the_cli() {
    let (new, current): (Vec<_>, Vec<_>) = command_lines()
        .into_iter()
        .partition(|(_, l)| uses_new_command(&words(l)));
    // Not vacuous: the skills carry many commands, and the three new commands are the ones set aside.
    assert!(current.len() >= 40, "only {} commands found", current.len());
    assert!(
        !new.is_empty(),
        "no line uses a new command: the ignored test would check nothing"
    );
    check(current);
}

/// The drift test covers `sparrow accounts`: the skill shows it (in the fast path and in the recipes), the fast path
/// reaches it before the findings, and every such line parses.
#[test]
fn the_fast_path_starts_from_sparrow_accounts() {
    let lines = command_lines();
    let accounts: Vec<_> = lines
        .iter()
        .filter(|(_, l)| l.starts_with("sparrow accounts "))
        .cloned()
        .collect();
    assert!(accounts.len() >= 3, "{} accounts lines", accounts.len());
    assert!(accounts.iter().all(|(_, l)| !uses_new_command(&words(l))));
    check(accounts);
    let skill = std::fs::read_to_string(skills_root().join("sparrow-triage/SKILL.md")).unwrap();
    let at = |needle: &str| {
        skill
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} not in SKILL.md"))
    };
    assert!(at("sparrow summary") < at("sparrow accounts"));
    assert!(at("sparrow accounts") < at("sparrow finding list"));
    assert!(at("sparrow finding list") < at("sparrow finding show"));
    assert!(at("sparrow finding show") < at("sparrow pivot user"));
    assert!(
        skill.lines().count() <= 110,
        "SKILL.md has {} lines",
        skill.lines().count()
    );
}

/// The lines that use the three commands cli-agent-aids added (schema --table, finding show with several ids,
/// a repeated finding list --rule).
#[test]
fn the_skills_lines_using_the_new_commands_parse_against_the_cli() {
    let new: Vec<_> = command_lines()
        .into_iter()
        .filter(|(_, l)| uses_new_command(&words(l)))
        .collect();
    assert!(new.len() >= 3, "{}", new.len());
    check(new);
}

/// The classification itself: it sets aside exactly the new forms.
#[test]
fn the_new_command_classifier_is_exact() {
    let c = |s: &str| uses_new_command(&words(s));
    assert!(c("sparrow schema --case c.duckdb --table signins --json"));
    assert!(!c("sparrow schema --case c.duckdb --json"));
    assert!(c("sparrow finding show --case c.duckdb a b --json"));
    assert!(!c("sparrow finding show --case c.duckdb a --json"));
    assert!(c("sparrow finding list --case c.duckdb --rule A --rule B"));
    assert!(!c(
        "sparrow finding list --case c.duckdb --rule A --user x@contoso.example"
    ));
    assert!(!c("sparrow query --case c.duckdb --json \"SELECT 1\""));
    assert_eq!(
        words("sparrow query --case c \"SELECT a, b FROM t WHERE x = 'y'\""),
        vec![
            "sparrow",
            "query",
            "--case",
            "c",
            "SELECT a, b FROM t WHERE x = 'y'"
        ]
    );
}

/// The parser check can fail: an unknown option, a bad subcommand and a stray extra argument are all errors.
#[test]
fn the_parse_check_rejects_a_wrong_command() {
    assert!(parses("sparrow finding list --case c.duckdb --json").is_ok());
    assert!(parses("sparrow finding list --case c.duckdb --no-such-flag").is_err());
    assert!(parses("sparrow findings list --case c.duckdb").is_err());
    assert!(parses("sparrow summary --case c.duckdb extra-argument").is_err());
}

// ------------------------------------------------------------------ privacy

/// The skills carry only reserved values: documentation addresses, `.example` / `.test` / `example.*` domains.
/// The one allowed link is the Agent Skills specification.
#[test]
fn the_skills_hold_only_reserved_values() {
    let mut scanned = 0;
    for f in markdown_files(&skills_root()) {
        let text = std::fs::read_to_string(&f)
            .unwrap()
            .replace("https://agentskills.io/specification", " ");
        let found = sparrow_synth::reserved::scan_text(&text);
        assert!(
            found.is_empty(),
            "{}: non-reserved values {found:?}",
            f.display()
        );
        scanned += 1;
    }
    assert!(scanned >= 6, "{scanned} files scanned");
    // The scan can fail: a real-looking address is caught.
    assert!(
        !sparrow_synth::reserved::scan_text("mail admin@corp-real.com from 8.8.8.8").is_empty()
    );
}
