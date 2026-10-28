//! Loading the built-in and custom rules and lists (spec §8.1, Addendum C.2). Built-ins are
//! embedded by `build.rs`; every directory in `DataDirs::rules` is then overlaid in order.

use crate::data::DataDirs;
use crate::detect::rule::{Cond, Rule, Stage};
use crate::{Error, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

include!(concat!(env!("OUT_DIR"), "/builtin_rules.rs"));

#[derive(Debug, Clone)]
pub struct LoadedRule {
    pub rule: Rule,
    /// `builtin:hawk/SPW-HAWK-011.yaml` for an embedded rule, else the file path.
    pub path: String,
    /// Hex SHA-256 of the normalized rule plus every static list it references.
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    /// Sorted by rule id.
    pub rules: Vec<LoadedRule>,
    /// Resolved static lists by name (`hosting_asns` included).
    pub lists: BTreeMap<String, Vec<String>>,
    /// Comparison metadata per list (`lists` keys).
    pub list_meta: BTreeMap<String, ListMeta>,
    pub warnings: Vec<String>,
}

/// Per-list metadata. List matching is case-insensitive unless `case_sensitive` is set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListMeta {
    pub case_sensitive: bool,
}

type ParsedList = (String, Vec<String>, ListMeta);

/// The shape of `rules/lists/<name>.yaml` other than `hosting_asns`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListFile {
    name: String,
    description: String,
    #[serde(default)]
    case_sensitive: bool,
    values: Vec<String>,
}

/// `rules/lists/hosting_asns.yaml` has its own shape (shared with `data::hosting_asns`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostingAsnsListFile {
    version: u32,
    asns: Vec<HostingAsnListEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostingAsnListEntry {
    asn: u32,
    name: String,
    kind: String,
}

fn parse_yaml<T: for<'de> Deserialize<'de>>(text: &str, origin: &str) -> Result<T> {
    serde_norway::from_str(text).map_err(|e| Error::Invalid(format!("{origin}: {e}")))
}

/// Parse a rule file. The condition shapes are checked first so an error names the rule id and
/// the path (`SPW-X-1: match.all[2].f: unknown operator "eqq"`) instead of a generic
/// untagged-enum failure.
pub(crate) fn parse_rule(text: &str, origin: &str) -> Result<Rule> {
    let value: serde_json::Value = parse_yaml(text, origin)?;
    let id = value.get("id").and_then(|v| v.as_str()).unwrap_or("?");
    if let Some(stage) = value.get("stage") {
        let names: Vec<&serde_json::Value> = match stage {
            serde_json::Value::Array(items) => items.iter().collect(),
            v => vec![v],
        };
        for v in names {
            let known = v
                .as_str()
                .is_some_and(|s| Stage::ALL.iter().any(|st| st.as_str() == s));
            if !known {
                let all: Vec<&str> = Stage::ALL.iter().map(|s| s.as_str()).collect();
                return Err(Error::Invalid(format!(
                    "{origin}: {id}: stage: unknown stage {v} (one of {})",
                    all.join(", ")
                )));
            }
        }
    }
    let check = |v: &serde_json::Value, path: &str| {
        Cond::from_json(v, path)
            .map(|_| ())
            .map_err(|e| Error::Invalid(format!("{id}: {e}")))
    };
    if let Some(m) = value.get("match") {
        check(m, "match")?;
    }
    if let Some(sources) = value.get("sources").and_then(|v| v.as_array()) {
        for (i, s) in sources.iter().enumerate() {
            if let Some(m) = s.get("match") {
                check(m, &format!("sources[{i}].match"))?;
            }
        }
    }
    serde_json::from_value(value).map_err(|e| Error::Invalid(format!("{origin}: {e}")))
}

/// Flatten one list file into `(name, values)`. `stem` is the file name without `.yaml`; a
/// `hosting_asns` file is parsed in its own shape and yields the ASN numbers as strings.
fn parse_list(text: &str, origin: &str, stem: &str) -> Result<ParsedList> {
    if stem == "hosting_asns" {
        let f: HostingAsnsListFile = parse_yaml(text, origin)?;
        if f.version != 1 {
            return Err(Error::Invalid(format!(
                "{origin}: unsupported version {}",
                f.version
            )));
        }
        let mut values = Vec::with_capacity(f.asns.len());
        for a in &f.asns {
            if a.name.trim().is_empty() || a.kind.trim().is_empty() {
                return Err(Error::Invalid(format!(
                    "{origin}: ASN {} needs a name and a kind",
                    a.asn
                )));
            }
            values.push(a.asn.to_string());
        }
        return Ok(("hosting_asns".to_string(), values, ListMeta::default()));
    }
    if stem == "collection_hints" {
        // Structured data for `sparrow coverage` (see `data::collection_hints`), not a value list.
        return Ok((stem.to_string(), Vec::new(), ListMeta::default()));
    }
    let f: ListFile = parse_yaml(text, origin)?;
    if f.description.trim().is_empty() {
        return Err(Error::Invalid(format!(
            "{origin}: list {:?} needs a description",
            f.name
        )));
    }
    Ok((
        f.name,
        f.values,
        ListMeta {
            case_sensitive: f.case_sensitive,
        },
    ))
}

fn yaml_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let entries =
        std::fs::read_dir(dir).map_err(|e| Error::Invalid(format!("{}: {e}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| Error::Invalid(format!("{}: {e}", dir.display())))?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// The built-in lists, overlaid by `<dir>/lists/*.yaml` of each rule directory in order.
type Lists = (BTreeMap<String, Vec<String>>, BTreeMap<String, ListMeta>);

/// The values of the built-in or custom list `name` (rules/lists), for code that must share a rule
/// list's definition (the profile step's derived relations read the same list the rules do).
pub fn list_values(dirs: &DataDirs, name: &str) -> Result<Vec<String>> {
    let (lists, _) = load_lists(dirs)?;
    lists
        .get(name)
        .cloned()
        .ok_or_else(|| Error::Invalid(format!("list {name} not found")))
}

fn load_lists(dirs: &DataDirs) -> Result<Lists> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut meta: BTreeMap<String, ListMeta> = BTreeMap::new();
    for (rel, text) in BUILTIN_LISTS {
        let origin = format!("built-in rules/{rel}");
        let stem = rel
            .rsplit('/')
            .next()
            .unwrap_or(rel)
            .trim_end_matches(".yaml");
        let (name, values, m) = parse_list(text, &origin, stem)?;
        meta.insert(name.clone(), m);
        out.insert(name, values);
    }
    for dir in &dirs.rules {
        let lists = dir.join("lists");
        if !lists.is_dir() {
            continue;
        }
        for path in yaml_files(&lists)? {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))?;
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let (name, values, m) = parse_list(&text, &path.display().to_string(), stem)?;
            meta.insert(name.clone(), m);
            out.insert(name, values);
        }
    }
    Ok((out, meta))
}

/// `**/SPW-*.yaml` and `**/*.rule.yaml` under a custom rule directory, sorted.
fn custom_rule_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    // `lists/` and `schema/` hold no rules.
    let walker = walkdir::WalkDir::new(dir).into_iter().filter_entry(|e| {
        !(e.depth() == 1
            && e.file_type().is_dir()
            && ["lists", "schema"].contains(&e.file_name().to_string_lossy().as_ref()))
    });
    for entry in walker {
        let entry = entry.map_err(|e| Error::Invalid(format!("{}: {e}", dir.display())))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if (name.starts_with("SPW-") && name.ends_with(".yaml")) || name.ends_with(".rule.yaml") {
            out.push(entry.into_path());
        }
    }
    out.sort();
    Ok(out)
}

/// Built-in rules, overlaid by every `DataDirs::rules` directory in order (a custom rule with a
/// built-in id replaces it and warns).
pub fn load_rules(dirs: &DataDirs) -> Result<RuleSet> {
    let (lists, list_meta) = load_lists(dirs)?;
    let mut by_id: BTreeMap<String, LoadedRule> = BTreeMap::new();
    let mut warnings = Vec::new();

    for (rel, text) in BUILTIN_RULES {
        let origin = format!("built-in rules/{rel}");
        let rule = parse_rule(text, &origin)?;
        let sha256 = rule_sha256(&rule, &lists, &list_meta);
        by_id.insert(
            rule.id.clone(),
            LoadedRule {
                rule,
                path: format!("builtin:{rel}"),
                sha256,
            },
        );
    }

    for dir in &dirs.rules {
        for path in custom_rule_files(dir)? {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))?;
            let rule = parse_rule(&text, &path.display().to_string())?;
            if by_id
                .get(&rule.id)
                .is_some_and(|e| e.path.starts_with("builtin:"))
            {
                warnings.push(format!(
                    "custom rule {} replaces the built-in rule",
                    rule.id
                ));
            }
            let sha256 = rule_sha256(&rule, &lists, &list_meta);
            by_id.insert(
                rule.id.clone(),
                LoadedRule {
                    rule,
                    path: path.display().to_string(),
                    sha256,
                },
            );
        }
    }

    Ok(RuleSet {
        rules: by_id.into_values().collect(),
        lists,
        list_meta,
        warnings,
    })
}

/// Hex SHA-256 over the normalized rule (its serde JSON) followed by every referenced static list
/// (`name \n value \n ...`, both sorted). Editing a list is therefore a rule change.
pub fn rule_sha256(
    rule: &Rule,
    lists: &BTreeMap<String, Vec<String>>,
    list_meta: &BTreeMap<String, ListMeta>,
) -> String {
    // The stage is roll-up metadata, not detection logic: hashing the rule without it keeps
    // every hash (and so `rule_updated`) as it was before rules carried one.
    let rule = &Rule {
        stage: Vec::new(),
        ..rule.clone()
    };
    let value = serde_json::to_value(rule).expect("a rule serializes to JSON");
    let mut refs = BTreeSet::new();
    collect_list_refs(&value, &mut refs);

    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(rule).expect("a rule serializes to JSON"));
    for name in refs {
        let Some(values) = lists.get(&name) else {
            continue;
        };
        hasher.update(name.as_bytes());
        hasher.update(b"\n");
        let cs = list_meta.get(&name).is_some_and(|m| m.case_sensitive);
        hasher.update(if cs {
            &b"case_sensitive\n"[..]
        } else {
            &b"case_insensitive\n"[..]
        });
        let mut sorted: Vec<&str> = values.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        for value in sorted {
            hasher.update(value.as_bytes());
            hasher.update(b"\n");
        }
    }
    hex::encode(hasher.finalize())
}

fn collect_list_refs(value: &serde_json::Value, out: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::String(s) => {
            if let Some(name) = s.strip_prefix("@list:") {
                out.insert(name.to_string());
            }
            // A `sql:` rule names its lists inside the query text.
            if s.contains("@list:") {
                for m in sql_list_token().captures_iter(s) {
                    out.insert(m[1].to_string());
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_list_refs(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                collect_list_refs(item, out);
            }
        }
        _ => {}
    }
}

fn sql_list_token() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"@list:([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)").unwrap()
    })
}
