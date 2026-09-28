//! Choosing which copy of the same evidence to parse (spec §4 "superseded artifacts",
//! Addendum A.4 "prefer JSON over CSV") and warning about row counts at export caps (A.5).

use crate::discovery::Registry;
use std::collections::{HashMap, HashSet};

/// Stems of the raw files that make a derived Hawk artifact redundant.
/// `Simple_X` → `X` (and `Xs`: Hawk 3 `Simple_New_InboxRule` pairs with `New_InboxRules`),
/// `ExchangeItem[Group]_Simple_U` → `ExchangeItem[Group]_Logs_U`,
/// `Converted_Authentication_Logs_U` → `Raw_Authentication_Logs_U`.
pub fn counterpart_stems(stem: &str) -> Vec<String> {
    let lower = stem.to_ascii_lowercase();
    let rest = |prefix: &str| stem[prefix.len()..].to_string();
    if lower.starts_with("exchangeitemgroup_simple_") {
        vec![format!(
            "ExchangeItemGroup_Logs_{}",
            rest("exchangeitemgroup_simple_")
        )]
    } else if lower.starts_with("exchangeitem_simple_") {
        vec![format!(
            "ExchangeItem_Logs_{}",
            rest("exchangeitem_simple_")
        )]
    } else if lower.starts_with("converted_authentication_logs_") {
        vec![format!(
            "Raw_Authentication_Logs_{}",
            rest("converted_authentication_logs_")
        )]
    } else if lower.starts_with("simple_") {
        let r = rest("simple_");
        vec![r.clone(), format!("{r}s")]
    } else {
        Vec::new()
    }
}

/// Files of the current collection already handled successfully (`parsed` or
/// `duplicate_file`), keyed by lower-cased relative path, and the files that failed or
/// are still pending (their records may exist only in a `Merged` copy).
#[derive(Debug, Default)]
pub struct Handled {
    by_lower: HashMap<String, String>,
    failed: HashSet<String>,
    /// Lower-cased relative path → artifact id, recorded for every listed file whether or not
    /// it parses, for the rules that must know which files are QuickUAL exports.
    artifacts: HashMap<String, String>,
}

impl Handled {
    pub fn insert(&mut self, rel: &str) {
        let lower = rel.to_lowercase();
        self.failed.remove(&lower);
        self.by_lower.insert(lower, rel.to_string());
    }

    /// Record a file that failed (error, not supported, every record failed) or was
    /// deferred: a `Merged` copy of its folder is then parsed.
    pub fn insert_failed(&mut self, rel: &str) {
        let lower = rel.to_lowercase();
        if !self.by_lower.contains_key(&lower) {
            self.failed.insert(lower);
        }
    }

    /// Record a listed file's artifact id (before it is handled).
    pub fn note_artifact(&mut self, rel: &str, artifact: &'static str) {
        self.artifacts
            .insert(rel.to_lowercase(), artifact.to_string());
    }

    /// The `inv.quickual.operation` file directly in `dir` that makes a combined export
    /// redundant: `Some` only when at least one exists and none failed. A per-operation JSON and
    /// its CSV twin are one export, so the CSV's `skipped_superseded` (its JSON parsed) still
    /// counts; a failed file means the combined export is the only surviving copy of its
    /// records, so it must be parsed. The smallest parsed path is named, for a stable message.
    fn quickual_operations_all_parsed(&self, dir: &str) -> Option<&str> {
        let prefix = format!("{}/", dir.to_lowercase());
        let ops: Vec<&String> = self
            .artifacts
            .iter()
            .filter(|(k, a)| a.as_str() == "inv.quickual.operation" && directly_in(k, &prefix))
            .map(|(k, _)| k)
            .collect();
        if ops.is_empty() {
            return None;
        }
        let mut named: Option<&String> = None;
        for k in &ops {
            let key: &String = k;
            if self.failed.contains(key) {
                return None;
            }
            if self.by_lower.contains_key(key) && named.is_none_or(|n| key < n) {
                named = Some(key);
            }
        }
        let named = named.or_else(|| ops.iter().min().copied())?;
        Some(
            self.by_lower
                .get(named)
                .map_or(named.as_str(), String::as_str),
        )
    }

    fn get(&self, rel: &str) -> Option<&str> {
        self.by_lower.get(&rel.to_lowercase()).map(String::as_str)
    }

    /// The handled file that makes `rel` redundant: the JSON twin of a CSV (same folder and
    /// stem; the CSV keeps only the first record's columns and flattens objects), or for a
    /// derived artifact its raw counterpart in the same folder. A derived file in a `Merged`
    /// folder (Microsoft-Extractor-Suite `Merge-OutputFiles`) is made redundant by the handled
    /// files directly in the folder above it, unless one of the files there failed (spec A.4:
    /// the copy is parsed when the original is missing or fails).
    pub fn superseded_by(&self, rel: &str, derived: bool) -> Option<String> {
        let (dir, file) = match rel.rsplit_once('/') {
            Some((d, f)) => (Some(d), f),
            None => (None, rel),
        };
        let (stem, ext) = file.rsplit_once('.')?;
        let join = |name: String| match dir {
            Some(d) => format!("{d}/{name}"),
            None => name,
        };
        if ext.eq_ignore_ascii_case("csv") {
            if let Some(t) = self.get(&join(format!("{stem}.json"))) {
                return Some(t.to_string());
            }
        }
        if derived {
            for c in counterpart_stems(stem) {
                for e in ["json", "csv"] {
                    if let Some(t) = self.get(&join(format!("{c}.{e}"))) {
                        return Some(t.to_string());
                    }
                }
            }
            // The combined export is redundant only when the QuickUAL per-operation files of
            // its triage root exist and none failed (a JSON/CSV twin counts as the export);
            // otherwise the combined file is the only copy of some records and must be parsed
            // (its records dedupe by id).
            if stem.eq_ignore_ascii_case("UAL-Operations-Combined")
                && self.artifacts.get(&rel.to_lowercase()).map(String::as_str)
                    == Some("inv.quickual.combined")
            {
                if let Some(dir) = dir {
                    if let Some(t) = self.quickual_operations_all_parsed(dir) {
                        return Some(t.to_string());
                    }
                }
            }
        }
        if derived {
            if let Some(p) = dir.and_then(merged_parent) {
                if !self.any_failed_in(p) {
                    if let Some(t) = self.any_file_in(p) {
                        return Some(t.to_string());
                    }
                }
            }
        }
        None
    }

    /// A handled file directly in `dir` (the smallest path, for a stable message).
    fn any_file_in(&self, dir: &str) -> Option<&str> {
        let prefix = format!("{}/", dir.to_lowercase());
        self.by_lower
            .iter()
            .filter(|(k, _)| directly_in(k, &prefix))
            .map(|(_, v)| v.as_str())
            .min()
    }

    /// True when a failed or pending file sits directly in `dir`.
    fn any_failed_in(&self, dir: &str) -> bool {
        let prefix = format!("{}/", dir.to_lowercase());
        self.failed.iter().any(|k| directly_in(k, &prefix))
    }
}

/// True when lower-cased `path` is a file directly below lower-cased `prefix` (`dir/`).
fn directly_in(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| !rest.contains('/'))
}

/// `dir` without its last component when that component is `Merged` (any case).
fn merged_parent(dir: &str) -> Option<&str> {
    let (parent, last) = dir.rsplit_once('/')?;
    last.eq_ignore_ascii_case("merged").then_some(parent)
}

/// Sort key for processing a collection: raw before derived, JSON before CSV, then path.
pub fn processing_key(rel: &str, derived: bool) -> (bool, bool, String) {
    (
        derived,
        rel.to_ascii_lowercase().ends_with(".csv"),
        rel.to_string(),
    )
}

/// Hawk artifacts holding event records, where a round row count means a paged pull was
/// cut off. State dumps (users, settings) are not paged at 5000.
fn is_event_artifact(artifact_id: &str) -> bool {
    Registry::builtin()
        .defs()
        .find(|d| d.id == artifact_id)
        .is_some_and(|d| {
            matches!(
                d.target,
                "ual_events"
                    | "message_trace"
                    | "signins"
                    | "directory_audits"
                    | "mailbox_audit_legacy"
            )
        })
}

/// Warning when a file's record count sits exactly at a known platform cap.
pub fn truncation_warning(artifact_id: &str, records: u64) -> Option<String> {
    if artifact_id == "inv.ual.window" && records == 5_000 {
        return Some(
            "row count equals the 5000-record Search-UnifiedAuditLog page Get-UAL requests per window — the collector writes partial data when it cannot shrink the window further; check LogFile.txt for \"SOME EVENTS IN THIS RANGE ARE NOT CAPTURED\"".into(),
        );
    }
    let cap = match artifact_id {
        "portal.ual" => Some(50_000),
        "portal.entra_signins" => Some(100_000),
        _ => None,
    };
    if let Some(cap) = cap {
        return (records == cap).then(|| {
            format!("row count equals known export cap {cap} — results likely truncated")
        });
    }
    if artifact_id.starts_with("hawk.")
        && is_event_artifact(artifact_id)
        && records > 0
        && records % 5_000 == 0
    {
        return Some(format!(
            "row count {records} is a multiple of 5000 (Exchange Online result page size) — results may be truncated"
        ));
    }
    None
}
