//! Locate Hawk and Microsoft-Extractor-Suite collection roots under a path.

use crate::{Error, Result};
use regex::Regex;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tool {
    Hawk,
    Invictus,
}

impl Tool {
    pub fn as_str(self) -> &'static str {
        match self {
            Tool::Hawk => "hawk",
            Tool::Invictus => "invictus",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredCollection {
    pub tool: Tool,
    pub root: PathBuf,
    pub tenant_hint: Option<String>,
    pub started_hint: Option<String>,
}

/// Top-level component folders written by Microsoft-Extractor-Suite (`Init-OutputDir`).
pub const INVICTUS_COMPONENTS: &[&str] = &[
    "UnifiedAuditLog",
    "EntraID",
    "Users",
    "Admins",
    "MFA",
    "ConditionalAccessPolicies",
    "Device Information",
    "Groups",
    "Roles",
    "RiskyEvents",
    "SecurityAlerts",
    "SecureScore",
    "Licenses",
    "Audit Status",
    "Rules",
    "MessageTrace",
    "Mailbox Permissions",
    "Mailbox Audit Log",
    "MailItemsAccessed",
    "Email Export",
    "Activity Logs",
    "Directory Activity Logs",
    "Sign-In logs",
    "Audit logs",
    "QuickUAL",
    "Applications",
];

const MAX_DEPTH: usize = 4;

fn re_hawk_root() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^Hawk_(.+)_(\d{8}_\d{6})$").expect("valid regex"))
}

fn re_invictus_stamp() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^\d{8}-\d{6}").expect("valid regex"))
}

pub fn discover_collections(path: &Path) -> Result<Vec<DiscoveredCollection>> {
    let meta = std::fs::metadata(path).map_err(|e| Error::io(path, e))?;
    if !meta.is_dir() {
        return Err(Error::Invalid(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    let mut found = Vec::new();
    visit(path, 0, &mut found)?;
    found.sort_by(|a, b| a.root.cmp(&b.root));
    Ok(found)
}

fn visit(dir: &Path, depth: usize, found: &mut Vec<DiscoveredCollection>) -> Result<()> {
    if let Some(c) = as_hawk_root(dir) {
        found.push(c);
        return Ok(());
    }
    if is_invictus_root(dir)? {
        found.push(DiscoveredCollection {
            tool: Tool::Invictus,
            root: dir.to_path_buf(),
            tenant_hint: None,
            started_hint: None,
        });
        return Ok(());
    }
    if depth >= MAX_DEPTH {
        return Ok(());
    }
    for sub in subdirs(dir)? {
        visit(&sub, depth + 1, found)?;
    }
    Ok(())
}

fn as_hawk_root(dir: &Path) -> Option<DiscoveredCollection> {
    let name = dir.file_name()?.to_str()?;
    let caps = re_hawk_root().captures(name)?;
    let looks_like_hawk =
        dir.join("Hawk.log").is_file() || dir.join("Tenant").is_dir();
    if !looks_like_hawk {
        return None;
    }
    Some(DiscoveredCollection {
        tool: Tool::Hawk,
        root: dir.to_path_buf(),
        tenant_hint: Some(caps[1].to_string()),
        started_hint: Some(caps[2].to_string()),
    })
}

fn is_invictus_root(dir: &Path) -> Result<bool> {
    if dir.join("LogFile.txt").is_file() {
        return Ok(true);
    }
    for sub in subdirs(dir)? {
        let Some(name) = sub.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !INVICTUS_COMPONENTS
            .iter()
            .any(|c| c.eq_ignore_ascii_case(name))
        {
            continue;
        }
        let stamped = subdirs(&sub)?.iter().any(|d| {
            d.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| re_invictus_stamp().is_match(n))
        });
        if stamped {
            return Ok(true);
        }
    }
    Ok(false)
}

fn subdirs(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| Error::io(dir, e))? {
        let entry = entry.map_err(|e| Error::io(dir, e))?;
        let path = entry.path();
        if path.is_dir() {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}
