//! Embedded data files (`data/`, `rules/lists/`) and their external overrides (spec §2, §13):
//! built-ins are compiled in; `--data DIR` / `SPARROW_DATA` (and `--rules DIR` /
//! `SPARROW_RULES` for `lists/`) supply files of the same name that replace built-in entries
//! by id or add new ones.

use crate::{Error, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const CAPABILITIES: &str = include_str!("../../../data/capabilities.yaml");
const MS365_RANGES: &str = include_str!("../../../data/ms365_ip_ranges.json");
const HOSTING_ASNS: &str = include_str!("../../../rules/lists/hosting_asns.yaml");

#[derive(Debug, Clone, Default)]
pub struct DataDirs {
    pub data: Option<PathBuf>,
    pub rules: Option<PathBuf>,
}

impl DataDirs {
    /// `SPARROW_DATA` / `SPARROW_RULES`.
    pub fn from_env() -> DataDirs {
        DataDirs::with_env_fallback(None, None)
    }

    /// Explicit directories (CLI flags) win over the environment.
    pub fn with_env_fallback(data: Option<PathBuf>, rules: Option<PathBuf>) -> DataDirs {
        let env = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        DataDirs {
            data: data.or_else(|| env("SPARROW_DATA")),
            rules: rules.or_else(|| env("SPARROW_RULES")),
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
/// `<rules>/lists/hosting_asns.yaml` (entries replace built-ins by `asn`).
pub fn hosting_asns(dirs: &DataDirs) -> Result<Vec<HostingAsn>> {
    let base = hosting_asns_file(HOSTING_ASNS, "built-in rules/lists/hosting_asns.yaml")?;
    match read_overlay(dirs.rules.as_deref(), "lists/hosting_asns.yaml")? {
        Some((text, path)) => {
            let name = path.display().to_string();
            let extra = hosting_asns_file(&text, &name)?;
            Ok(overlay_by_key(base, extra, |a| a.asn))
        }
        None => Ok(base),
    }
}
