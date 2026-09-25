//! Locate Hawk and Microsoft-Extractor-Suite collection roots under a path.

use crate::discovery::registry::Registry;
use crate::{Error, Result};
use regex::Regex;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Tool {
    #[serde(rename = "hawk")]
    Hawk,
    #[serde(rename = "invictus")]
    Invictus,
    /// Files an analyst exported from the Purview, Entra or Exchange admin portals.
    #[serde(rename = "portal_export")]
    PortalExport,
}

impl Tool {
    pub fn as_str(self) -> &'static str {
        match self {
            Tool::Hawk => "hawk",
            Tool::Invictus => "invictus",
            Tool::PortalExport => "portal_export",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredCollection {
    pub tool: Tool,
    pub root: PathBuf,
    pub tenant_hint: Option<String>,
    pub started_hint: Option<String>,
    /// List only the files directly in `root` (portal export folders).
    pub shallow: bool,
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
    // The top-level path itself must be readable; unreadable folders below it are skipped.
    std::fs::read_dir(path).map_err(|e| Error::io(path, e))?;
    let mut found = Vec::new();
    visit(path, 0, &mut found);
    found.sort_by(|a, b| a.root.cmp(&b.root));
    Ok(found)
}

fn visit(dir: &Path, depth: usize, found: &mut Vec<DiscoveredCollection>) {
    if let Some(c) = as_hawk_root(dir) {
        found.push(c);
        return;
    }
    if is_invictus_root(dir) {
        found.push(DiscoveredCollection {
            tool: Tool::Invictus,
            root: dir.to_path_buf(),
            tenant_hint: None,
            started_hint: crate::discovery::runs::earliest_run_stamp(dir),
            shallow: false,
        });
        return;
    }
    if has_portal_files(dir) {
        found.push(DiscoveredCollection {
            tool: Tool::PortalExport,
            root: dir.to_path_buf(),
            tenant_hint: None,
            started_hint: None,
            shallow: true,
        });
    }
    if depth >= MAX_DEPTH {
        return;
    }
    for sub in subdirs(dir) {
        visit(&sub, depth + 1, found);
    }
}

/// Hawk roots are recognized by content (Addendum A.2). The `Hawk_<tenant>_<ts>` folder
/// name, when present, only supplies tenant and timestamp hints.
fn as_hawk_root(dir: &Path) -> Option<DiscoveredCollection> {
    let is_hawk =
        dir.join("Hawk.log").is_file() || has_hawk_tenant_dir(dir) || has_hawk_user_dir(dir);
    if !is_hawk {
        return None;
    }
    let caps = dir_name(dir).and_then(|n| re_hawk_root().captures(n));
    Some(DiscoveredCollection {
        tool: Tool::Hawk,
        root: dir.to_path_buf(),
        tenant_hint: caps.as_ref().map(|c| c[1].to_string()),
        started_hint: caps.as_ref().map(|c| c[2].to_string()),
        shallow: false,
    })
}

fn dir_name(p: &Path) -> Option<&str> {
    p.file_name().and_then(|n| n.to_str())
}

/// `Tenant`, or `\Tenant` as PowerShell 7 on macOS/Linux names it.
fn is_tenant_dir_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("Tenant") || name.eq_ignore_ascii_case("\\Tenant")
}

/// A Tenant folder holding at least one known Hawk tenant artifact.
fn has_hawk_tenant_dir(dir: &Path) -> bool {
    subdirs(dir)
        .iter()
        .filter(|d| dir_name(d).is_some_and(is_tenant_dir_name))
        .any(|d| {
            file_names(d).iter().any(|f| {
                Registry::builtin()
                    .classify(Tool::Hawk, &format!("Tenant/{f}"))
                    .is_some_and(|c| {
                        c.artifact_id.starts_with("hawk.tenant.")
                            || c.artifact_id == "hawk.investigate_file"
                    })
            })
        })
}

/// A `<user>@<domain>` folder holding at least one known Hawk per-user artifact. A folder
/// that is itself a capture (own Hawk.log or Tenant folder) is not a user folder.
fn has_hawk_user_dir(dir: &Path) -> bool {
    subdirs(dir).iter().any(|d| {
        let Some(name) = dir_name(d) else {
            return false;
        };
        if !name.contains('@')
            || d.join("Hawk.log").is_file()
            || subdirs(d)
                .iter()
                .any(|s| dir_name(s).is_some_and(is_tenant_dir_name))
        {
            return false;
        }
        file_names(d).iter().any(|f| {
            Registry::builtin()
                .classify(Tool::Hawk, &format!("{name}/{f}"))
                .is_some_and(|c| c.artifact_id.starts_with("hawk.user."))
        })
    })
}

/// A folder directly containing a CSV recognized as a portal export by its header.
fn has_portal_files(dir: &Path) -> bool {
    file_names(dir).iter().any(|f| {
        Registry::builtin()
            .classify_file(Tool::PortalExport, f, &dir.join(f))
            .is_some()
    })
}

/// Names of the readable regular files directly in `dir`, sorted.
fn file_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect();
    out.sort();
    out
}

fn is_invictus_root(dir: &Path) -> bool {
    if dir.join("LogFile.txt").is_file() {
        return true;
    }
    for sub in subdirs(dir) {
        let Some(name) = sub.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !INVICTUS_COMPONENTS
            .iter()
            .any(|c| c.eq_ignore_ascii_case(name))
        {
            continue;
        }
        let stamped = subdirs(&sub).iter().any(|d| {
            d.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| re_invictus_stamp().is_match(n))
        });
        if stamped {
            return true;
        }
    }
    false
}

/// Readable subdirectories of `dir`, sorted. Unreadable directories and entries are skipped:
/// they simply are not searched for collections.
fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    out.sort();
    out
}
