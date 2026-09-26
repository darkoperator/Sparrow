//! The ground-truth manifest written next to every generated tree (spec Addendum B): what each
//! file is and the status Sparrow must give it, the rows each table must hold, the tenant, the
//! expected capability and evidence-availability outcomes, where every storyline's evidence
//! landed, and the outcome each seed rule must have on each storyline. `sparrow synth check`
//! compares a case ingested from the tree against it.

pub use crate::profiles::CapExpect;

use crate::options::GenerateOptions;
use crate::ps::DateEvidence;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One generated tree's ground truth.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest format version (1).
    pub format: u32,
    pub generator: String,
    pub scenario: String,
    pub options: GenerateOptions,
    /// The collection root folder, relative to the output directory.
    pub root: String,
    /// The folder holding the generated GeoLite2 databases, relative to the output directory.
    pub geoip_dir: Option<String>,
    /// The `--culture` the ingest must pass, when the tree proves no day/month order.
    pub ingest_culture: Option<String>,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub collected_at: DateTime<Utc>,
    pub licence_profile: String,
    pub audit_profile: String,
    pub files: Vec<FileExpect>,
    pub empty_dirs: Vec<String>,
    pub tables: BTreeMap<String, TableExpect>,
    pub tenant: TenantExpect,
    pub capabilities: BTreeMap<String, CapExpect>,
    pub evidence: BTreeMap<String, EvidenceExpect>,
    pub storylines: Vec<StoryExpect>,
    pub rules: Vec<RuleExpect>,
}

impl Manifest {
    /// Pretty JSON with a final newline (the manifest is not collector output, so LF).
    pub fn to_json_pretty(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).expect("manifest serializes");
        s.push('\n');
        s
    }

    pub fn from_json(text: &str) -> Result<Manifest> {
        serde_json::from_str(text).map_err(Error::from)
    }
}

/// One file of the tree and the `source_files` row Sparrow must write for it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileExpect {
    /// Path within the collection root, `/`-separated.
    pub rel_path: String,
    pub artifact_id: Option<String>,
    /// `parsed`, `duplicate_file`, `skipped_superseded`, `unrecognized`, `not_supported` or
    /// `error`.
    pub status: String,
    /// The writer derived the file from another one of the tree (Hawk `Simple_*`, merged copies).
    pub source_derived: bool,
    /// `ps::Encoding::name` of the encoding the file was written in.
    pub encoding: String,
    pub bytes: u64,
    /// Lower-case hex SHA-256 of the file's bytes.
    pub sha256: String,
    pub date_evidence: Option<DateEvidence>,
}

/// The rows one table must hold after ingest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TableExpect {
    pub rows: u64,
    /// False when `rows` is a lower bound.
    pub exact: bool,
    /// SHA-256 of the sorted unique record keys joined by `\n` (`{cid}` unreplaced); `None`
    /// for a count-only table (rows without keys).
    pub keys_sha256: Option<String>,
    /// The sorted unique record keys, listed only when there are at most 5000; a key may hold
    /// the placeholder `{cid}` for the collection id.
    pub keys: Vec<String>,
}

/// Where a record was seen: a file and its 1-based physical line span.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Sighting {
    pub rel_path: String,
    pub line_start: u32,
    pub line_end: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantExpect {
    pub tenant_id: String,
    pub name: Option<String>,
    pub domains: Vec<String>,
}

/// The `profile::availability` statuses allowed for one evidence id, and why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceExpect {
    pub allowed: Vec<String>,
    pub why: String,
}

/// One storyline or look-alike and where its evidence landed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoryExpect {
    pub id: String,
    pub kind: String,
    pub polarity: String,
    pub actor: String,
    pub time: DateTime<Utc>,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// `Debug` text of the `story::Evidence`.
    pub what: String,
    /// Whether Microsoft 365 recorded it (UAL records under the tenant's audit settings).
    pub logged: bool,
    /// (table, sighting) for every parsed file that carries it.
    pub delivered: Vec<(String, Sighting)>,
}

/// The outcome one seed rule must have on one storyline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleExpect {
    pub rule_id: String,
    pub storyline: String,
    pub outcome: RuleOutcome,
    pub reason: String,
    pub tables: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleOutcome {
    Hit,
    NoHit,
    NotApplicable,
    NoEvidence,
}
