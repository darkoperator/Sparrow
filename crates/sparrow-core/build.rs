//! Embeds `rules/**/SPW-*.yaml` (rules) and `rules/lists/*.yaml` (lists) into the binary
//! (spec §8.1, Addendum C.2) and generates `$OUT_DIR/builtin_rules.rs`, so a new rule file
//! needs no Rust change.

use std::fs;
use std::path::{Path, PathBuf};

/// Lists live under `lists/`; rules are `SPW-*.yaml` anywhere else. `coverage.yaml` and the
/// editor schema are therefore skipped.
fn embedded(p: &Path) -> bool {
    if p.extension().and_then(|e| e.to_str()) != Some("yaml") {
        return false;
    }
    let lists = p
        .parent()
        .and_then(|d| d.file_name())
        .and_then(|n| n.to_str())
        == Some("lists");
    let rule = p
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("SPW-"));
    lists || rule
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            collect(&p, out);
        } else if embedded(&p) {
            out.push(p);
        }
    }
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    println!("cargo:rerun-if-changed={}", root.display());
    let mut files = Vec::new();
    collect(&root, &mut files);
    files.sort();
    let (mut rules, mut lists) = (String::new(), String::new());
    for p in &files {
        let rel = p
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let include =
            format!("include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../../rules/{rel}\"))");
        let line = format!("    ({rel:?}, {include}),\n");
        if rel.starts_with("lists/") {
            lists.push_str(&line);
        } else {
            rules.push_str(&line);
        }
    }
    let body = format!(
        "pub const BUILTIN_RULES: &[(&str, &str)] = &[\n{rules}];\npub const BUILTIN_LISTS: &[(&str, &str)] = &[\n{lists}];\n"
    );
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("builtin_rules.rs");
    fs::write(out, body).unwrap();
}
