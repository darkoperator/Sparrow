//! Embeds `rules/**/SPW-*.yaml` (rules) and `rules/lists/*.yaml` (lists) into the binary
//! (spec §8.1, Addendum C.2) and generates `$OUT_DIR/builtin_rules.rs`, so a new rule file
//! needs no Rust change.

use std::fs;
use std::path::{Path, PathBuf};

/// Lists live under `lists/`; rules are `SPW-*.yaml` anywhere else. `coverage.yaml` and the
/// editor schema are therefore skipped.
fn embedded(root: &Path, p: &Path) -> bool {
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
    // Built-in rules live only in the category folders (not schema/, not a stray draft folder).
    let category = p
        .strip_prefix(root)
        .ok()
        .and_then(|r| r.components().next())
        .and_then(|c| c.as_os_str().to_str())
        .is_some_and(|c| ["mail", "identity", "apps", "files", "config", "hawk"].contains(&c));
    lists || (rule && category)
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            collect(root, &p, out);
        } else if embedded(root, &p) {
            out.push(p);
        }
    }
}

/// How this crate is compiled, for the test cache key (profile, optimisation, debug assertions,
/// enabled features, rustflags): anything here can change what ingest and profile produce.
fn build_config() -> String {
    let var = |k: &str| std::env::var(k).unwrap_or_default();
    let mut features: Vec<String> = std::env::vars()
        .filter_map(|(k, _)| k.strip_prefix("CARGO_FEATURE_").map(str::to_string))
        .collect();
    features.sort();
    format!(
        "profile={};opt={};debug={};debug_assertions={};features={};rustflags={}",
        var("PROFILE"),
        var("OPT_LEVEL"),
        var("DEBUG"),
        std::env::var_os("CARGO_CFG_DEBUG_ASSERTIONS").is_some(),
        features.join(","),
        var("CARGO_ENCODED_RUSTFLAGS").replace('\x1f', " "),
    )
}

fn main() {
    println!(
        "cargo:rustc-env=SPARROW_CORE_BUILD_CONFIG={}",
        build_config()
    );
    // Run-time lookup (not `env!`): a cached build script must not keep the path of the
    // checkout (or deleted worktree) it was first compiled in.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo");
    let root = Path::new(&manifest).join("../../rules");
    println!("cargo:rerun-if-changed={}", root.display());
    let mut files = Vec::new();
    collect(&root, &root, &mut files);
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
