//! Embedded data files (`data/`, `rules/lists/`) and their external overrides (spec §2, §13):
//! built-ins are compiled in; `--data DIR` / `SPARROW_DATA` (and `--rules DIR` /
//! `SPARROW_RULES` for `lists/`) supply files of the same name that replace built-in entries
//! by id or add new ones.

use crate::{Error, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const CAPABILITIES: &str = include_str!("../../../data/capabilities.yaml");

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
