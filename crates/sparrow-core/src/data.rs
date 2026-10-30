//! Embedded data files (`data/`, `rules/lists/`) and their external overrides (spec §2, §13):
//! built-ins are compiled in; `--data DIR` / `SPARROW_DATA` (and `--rules DIR` /
//! `SPARROW_RULES` for `lists/`) supply files of the same name that replace built-in entries
//! by id or add new ones. `--rules` / `SPARROW_RULES` may name several directories.

use crate::{Error, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const CAPABILITIES: &str = include_str!("../../../data/capabilities.yaml");
const MS365_RANGES: &str = include_str!("../../../data/ms365_ip_ranges.json");
const HOSTING_ASNS: &str = include_str!("../../../rules/lists/hosting_asns.yaml");
const COLLECTION_HINTS: &str = include_str!("../../../rules/lists/collection_hints.yaml");
const OPERATION_CATALOG: &str = include_str!("../../../data/operation_catalog.yaml");

#[derive(Debug, Clone, Default)]
pub struct DataDirs {
    pub data: Option<PathBuf>,
    /// Rule directories, in load order: built-ins first, then each directory here (later
    /// directories replace earlier entries by id). Empty means only the built-in rules and lists.
    pub rules: Vec<PathBuf>,
}

impl DataDirs {
    /// `SPARROW_DATA` / `SPARROW_RULES` (the latter split on the platform path separator).
    pub fn from_env() -> DataDirs {
        DataDirs::with_env_fallback(None, Vec::new())
    }

    /// Explicit directories (CLI flags) win over the environment.
    pub fn with_env_fallback(data: Option<PathBuf>, rules: Vec<PathBuf>) -> DataDirs {
        DataDirs::with_lookup(data, rules, |k| std::env::var_os(k))
    }

    /// [`DataDirs::with_env_fallback`] reading the variables through `var` (the CLI run's own environment when the
    /// app's agent bridge runs it).
    pub fn with_lookup(
        data: Option<PathBuf>,
        rules: Vec<PathBuf>,
        var: impl Fn(&str) -> Option<std::ffi::OsString>,
    ) -> DataDirs {
        let env = |k: &str| var(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        let rules = if rules.is_empty() {
            var("SPARROW_RULES")
                .filter(|v| !v.is_empty())
                .map(|v| std::env::split_paths(&v).collect())
                .unwrap_or_default()
        } else {
            rules
        };
        DataDirs {
            data: data.or_else(|| env("SPARROW_DATA")),
            rules,
        }
    }
}

/// The external copy of `rel` under `dir`, if it exists.
fn external(dir: Option<&Path>, rel: &str) -> Option<PathBuf> {
    dir.map(|d| d.join(rel)).filter(|p| p.is_file())
}

/// Built-in text and, when an external file of the same name exists, its text and path.
pub fn read_overlay(dir: Option<&Path>, rel: &str) -> Result<Option<(String, PathBuf)>> {
    match external(dir, rel) {
        Some(p) => std::fs::read_to_string(&p)
            .map(|t| Some((t, p.clone())))
            .map_err(|e| Error::Invalid(format!("{}: {e}", p.display()))),
        None => Ok(None),
    }
}

fn parse_yaml<T: for<'de> Deserialize<'de>>(text: &str, name: &str) -> Result<T> {
    serde_norway::from_str(text).map_err(|e| Error::Invalid(format!("{name}: {e}")))
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDef {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub baseline: bool,
    #[serde(default)]
    pub unlocked_by_service_plans: Vec<String>,
    #[serde(default)]
    pub hawk_license_tiers: Vec<String>,
    pub retention_days: Option<u32>,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub notes: String,
    pub sources: Vec<String>,
    pub as_of: String,
    /// `builtin` or the external file's path (not in the YAML).
    #[serde(skip)]
    pub origin: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilitiesFile {
    version: u32,
    capabilities: Vec<CapabilityDef>,
}

fn capabilities_file(text: &str, name: &str, origin: &str) -> Result<Vec<CapabilityDef>> {
    let f: CapabilitiesFile = parse_yaml(text, name)?;
    if f.version != 1 {
        return Err(Error::Invalid(format!(
            "{name}: unsupported version {}",
            f.version
        )));
    }
    let mut out = f.capabilities;
    for c in &mut out {
        if c.id.trim().is_empty() || c.sources.is_empty() {
            return Err(Error::Invalid(format!(
                "{name}: capability {:?} needs an id and at least one source",
                c.id
            )));
        }
        if chrono::NaiveDate::parse_from_str(&c.as_of, "%Y-%m-%d").is_err() {
            return Err(Error::Invalid(format!(
                "{name}: capability {} as_of must be yyyy-mm-dd",
                c.id
            )));
        }
        c.origin = origin.to_string();
    }
    Ok(out)
}

/// Replace entries of `base` by id with those of `extra`; append new ids in `extra`'s order.
pub fn overlay_by<T>(mut base: Vec<T>, extra: Vec<T>, id: impl Fn(&T) -> &str) -> Vec<T> {
    for e in extra {
        match base.iter().position(|b| id(b) == id(&e)) {
            Some(i) => base[i] = e,
            None => base.push(e),
        }
    }
    base
}

/// Same merge as `overlay_by`, keyed by a `PartialEq` value instead of a borrowed `&str` (the
/// `&str` case needs the narrower signature above so the borrow checker accepts the closure).
pub fn overlay_by_key<T, K: PartialEq>(
    mut base: Vec<T>,
    extra: Vec<T>,
    id: impl Fn(&T) -> K,
) -> Vec<T> {
    for e in extra {
        match base.iter().position(|b| id(b) == id(&e)) {
            Some(i) => base[i] = e,
            None => base.push(e),
        }
    }
    base
}

/// Capability definitions: built-in, overlaid by `<data>/capabilities.yaml`.
pub fn capabilities(dirs: &DataDirs) -> Result<Vec<CapabilityDef>> {
    let base = capabilities_file(CAPABILITIES, "built-in data/capabilities.yaml", "builtin")?;
    match read_overlay(dirs.data.as_deref(), "capabilities.yaml")? {
        Some((text, path)) => {
            let name = path.display().to_string();
            let extra = capabilities_file(&text, &name, &name)?;
            Ok(overlay_by(base, extra, |c| c.id.as_str()))
        }
        None => Ok(base),
    }
}

// Task 7: Microsoft 365 service ranges and hosting ASNs (ip_intel).

#[derive(Debug, Clone, Deserialize)]
pub struct MsRange {
    pub cidr: String,
    pub service_area: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MsRanges {
    pub version: String,
    pub retrieved: String,
    pub ranges: Vec<MsRange>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostingAsn {
    pub asn: u32,
    pub name: String,
    pub kind: String,
}

fn parse_json<T: for<'de> Deserialize<'de>>(text: &str, name: &str) -> Result<T> {
    serde_json::from_str(text).map_err(|e| Error::Invalid(format!("{name}: {e}")))
}

fn ms_ranges_file(text: &str, name: &str) -> Result<MsRanges> {
    let ranges: MsRanges = parse_json(text, name)?;
    for r in &ranges.ranges {
        r.cidr.parse::<ipnet::IpNet>().map_err(|e| {
            Error::Invalid(format!(
                "{name}: range {:?} is not a valid CIDR: {e}",
                r.cidr
            ))
        })?;
    }
    Ok(ranges)
}

/// Microsoft 365 service front-end IP ranges (spec §5.3 `ip_intel.is_microsoft`): the embedded
/// snapshot, or, when `<data>/ms365_ip_ranges.json` exists, that file in its place (a snapshot
/// is all-or-nothing, unlike `capabilities.yaml`'s per-id overlay).
pub fn ms365_ranges(dirs: &DataDirs) -> Result<MsRanges> {
    match read_overlay(dirs.data.as_deref(), "ms365_ip_ranges.json")? {
        Some((text, path)) => ms_ranges_file(&text, &path.display().to_string()),
        None => ms_ranges_file(MS365_RANGES, "built-in data/ms365_ip_ranges.json"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostingAsnsFile {
    version: u32,
    asns: Vec<HostingAsn>,
}

fn hosting_asns_file(text: &str, name: &str) -> Result<Vec<HostingAsn>> {
    let f: HostingAsnsFile = parse_yaml(text, name)?;
    if f.version != 1 {
        return Err(Error::Invalid(format!(
            "{name}: unsupported version {}",
            f.version
        )));
    }
    Ok(f.asns)
}

/// Hosting/cloud/VPS autonomous systems (spec §5.3 `ip_intel.is_hosting`): built-in, overlaid by
/// `<rules>/lists/hosting_asns.yaml` (entries replace built-ins by `asn`). Several rule
/// directories apply in order, so a later directory wins.
pub fn hosting_asns(dirs: &DataDirs) -> Result<Vec<HostingAsn>> {
    let mut base = hosting_asns_file(HOSTING_ASNS, "built-in rules/lists/hosting_asns.yaml")?;
    for dir in &dirs.rules {
        let path = dir.join("lists/hosting_asns.yaml");
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))?;
        let name = path.display().to_string();
        let extra = hosting_asns_file(&text, &name)?;
        base = overlay_by_key(base, extra, |a| a.asn);
    }
    Ok(base)
}

/// How to request one evidence source with each collector (`rules/lists/collection_hints.yaml`). A collector
/// without a cmdlet for the source is `None`, never a guess. Templates use `{upn}`, `{from}` and `{to}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionHint {
    pub source: String,
    #[serde(default)]
    pub console: Option<String>,
    #[serde(default)]
    pub hawk: Option<String>,
    #[serde(default)]
    pub invictus: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectionHintsFile {
    version: u32,
    sources: Vec<CollectionHint>,
}

fn collection_hints_file(text: &str, name: &str) -> Result<Vec<CollectionHint>> {
    let f: CollectionHintsFile = parse_yaml(text, name)?;
    if f.version != 1 {
        return Err(Error::Invalid(format!(
            "{name}: unsupported version {}",
            f.version
        )));
    }
    Ok(f.sources)
}

/// Collection hints per evidence source: built-in, overlaid by `<rules>/lists/collection_hints.yaml`
/// (entries replace built-ins by `source`; a later directory wins).
pub fn collection_hints(dirs: &DataDirs) -> Result<Vec<CollectionHint>> {
    let mut base = collection_hints_file(
        COLLECTION_HINTS,
        "built-in rules/lists/collection_hints.yaml",
    )?;
    for dir in &dirs.rules {
        let path = dir.join("lists/collection_hints.yaml");
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))?;
        let extra = collection_hints_file(&text, &path.display().to_string())?;
        base = overlay_by_key(base, extra, |h| h.source.clone());
    }
    Ok(base)
}

// Task 9: operation catalog (timeline categories, ATT&CK techniques).

/// `event_category` enum values (migration 0007, Task 9).
const CATEGORIES: &[&str] = &[
    "auth",
    "mail_read",
    "mail_send",
    "mail_rule",
    "forwarding",
    "permission",
    "app_consent",
    "app_credential",
    "role_change",
    "mfa_change",
    "file_access",
    "file_download",
    "file_share",
    "lure_staging",
    "search",
    "ediscovery",
    "audit_tamper",
    "config_change",
    "device",
    "mail_flow",
    "other",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationDef {
    pub operation: String,
    pub workload: Option<String>,
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub mitre: Vec<String>,
    /// `builtin` or the external file's path (not in the YAML).
    #[serde(skip)]
    pub origin: String,
}

/// Matching key of an operation name: lower-case, trimmed, trailing "." removed. UAL writes some
/// operations (e.g. `Consent to application.`) with a trailing full stop that Graph's own name
/// for the same activity does not have.
pub fn operation_key(op: &str) -> String {
    op.trim().trim_end_matches('.').trim().to_lowercase()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationCatalogFile {
    version: u32,
    operations: Vec<OperationDef>,
}

fn operation_catalog_file(text: &str, name: &str, origin: &str) -> Result<Vec<OperationDef>> {
    let f: OperationCatalogFile = parse_yaml(text, name)?;
    if f.version != 1 {
        return Err(Error::Invalid(format!(
            "{name}: unsupported version {}",
            f.version
        )));
    }
    let mut out = f.operations;
    for o in &mut out {
        if !CATEGORIES.contains(&o.category.as_str()) {
            return Err(Error::Invalid(format!(
                "{name}: operation {:?} has unknown category {:?}",
                o.operation, o.category
            )));
        }
        o.origin = origin.to_string();
    }
    Ok(out)
}

/// Operation catalog (spec §5.3): built-in, overlaid by `<data>/operation_catalog.yaml` (entries
/// replace by `(operation_key, lower-case workload)`; new entries are appended).
pub fn operation_catalog(dirs: &DataDirs) -> Result<Vec<OperationDef>> {
    let base = operation_catalog_file(
        OPERATION_CATALOG,
        "built-in data/operation_catalog.yaml",
        "builtin",
    )?;
    match read_overlay(dirs.data.as_deref(), "operation_catalog.yaml")? {
        Some((text, path)) => {
            let name = path.display().to_string();
            let extra = operation_catalog_file(&text, &name, &name)?;
            Ok(overlay_by_key(base, extra, |o| {
                (
                    operation_key(&o.operation),
                    o.workload.as_deref().map(str::to_lowercase),
                )
            }))
        }
        None => Ok(base),
    }
}
