//! The ground-truth manifest written next to every generated tree (spec Addendum B): what each
//! file is and the status Sparrow must give it, the rows each table must hold, the tenant, the
//! expected capability and evidence-availability outcomes, where every storyline's evidence
//! landed, and the outcome each seed rule must have on each storyline. `sparrow synth check`
//! compares a case ingested from the tree against it.

pub use crate::profiles::CapExpect;

use crate::events::SignInType;
use crate::keys;
use crate::options::{Collector, GenerateOptions};
use crate::ps::DateEvidence;
use crate::scenario::Polarity;
use crate::story::{Evidence, StoryRecord};
use crate::tree::TreeOutcome;
use crate::world::World;
use crate::writers::window_days;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    /// The account roll-up rows the detection gate expects (`expect::account_expectations`): one per
    /// actor of a positive storyline some rule is expected to hit. Absent in a manifest of a scenario
    /// with none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<AccountExpect>,
}

/// One account the roll-up (`account_rollup`) must list after detection, computed by the generator
/// from the tree's own facts (never from Sparrow's output).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountExpect {
    /// Lower-case UPN of the storylines' actor.
    pub upn: String,
    /// The positive storylines that make the account expected (each has a rule expected to hit).
    pub storylines: Vec<String>,
    /// Stages the roll-up row must include: those of the rules expected to hit these storylines
    /// (`Stage` names, in the stage enum's order).
    pub stages: Vec<String>,
    /// Addresses the row must list with the reason `acts_without_signin`: MailItemsAccessed records of
    /// these storylines from an address the account never signs in from. Sorted, canonical text.
    pub addresses: Vec<String>,
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
    /// Every parsed file row that carries it.
    pub delivered: Vec<Landed>,
}

/// One place storyline evidence landed: the table, the row's record key there (`keys::
/// for_evidence`; `None` when no key function covers the pairing yet) and the file lines.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Landed {
    pub table: String,
    pub record_key: Option<String>,
    #[serde(flatten)]
    pub sighting: Sighting,
}

/// The outcome one seed rule must have on one storyline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleExpect {
    pub rule_id: String,
    pub storyline: String,
    pub outcome: RuleOutcome,
    pub reason: String,
    pub tables: Vec<String>,
    /// A correlated rule (`evidence_all_of` with several groups): whether DISTINCT delivered
    /// evidence items cover every group. `false` when a half was lost (one record cannot stand
    /// for both). Always `true`, and not written, for an uncorrelated rule.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub complete: bool,
    /// The condition (`oracle::Condition`) the outcome was computed with, for a kind
    /// `rules/coverage.yaml` lists under the rule's `computed`; absent for a fixed per-kind outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computed: Option<String>,
}

fn yes() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleOutcome {
    Hit,
    NoHit,
    NotApplicable,
    NoEvidence,
}

/// The tenant Sparrow must profile the tree as: the world's tenant id; the name the collector
/// reports (Hawk's folder / log: the tenant name; others none); and the domains Sparrow derives
/// (`derived_upn`: UPN domains of users, mailboxes and home-tenant sign-ins; plus
/// `message_trace_org`). The portal delivers no user or mailbox list and its message trace
/// summary has no organization column, so its domains are the primary domain and those of the
/// interactive sign-in rows of home-tenant users (Sparrow does not derive domains from UAL user ids, which include
/// guests and external senders). Microsoft-Extractor-Suite lists every mailbox, so its domains are
/// the mailboxes' UPN domains; Hawk lists every user (EntraIDUsers, AzureADUsers), so its
/// domains are the users' UPN domains.
pub fn tenant_expect(world: &World, opts: &GenerateOptions) -> TenantExpect {
    let name = matches!(opts.collector, Collector::Hawk3 | Collector::Hawk4)
        .then(|| world.tenant.name.clone());
    let mut domains = BTreeSet::new();
    if opts.collector == Collector::Invictus {
        // Every mailbox is listed (MailboxAuditStatus, MailboxPermissions).
        for upn in world.mailboxes.keys() {
            if let Some((_, d)) = upn.rsplit_once('@') {
                domains.insert(d.to_lowercase());
            }
        }
    }
    if matches!(opts.collector, Collector::Hawk3 | Collector::Hawk4) {
        // EntraIDUsers (Hawk 4) / AzureADUsers (Hawk 3) lists every user.
        for u in world.all_people() {
            if let Some((_, d)) = u.upn.rsplit_once('@') {
                domains.insert(d.to_lowercase());
            }
        }
    }
    if opts.collector == Collector::Portal {
        domains.insert(world.primary_domain().to_lowercase());
        for day in window_days(world) {
            for s in &day.signins {
                if s.event_type == SignInType::Interactive
                    && s.home_tenant_id == world.tenant.tenant_id
                {
                    if let Some((_, d)) = s.user.rsplit_once('@') {
                        domains.insert(d.to_lowercase());
                    }
                }
            }
        }
    }
    TenantExpect {
        tenant_id: world.tenant.tenant_id.to_string(),
        name,
        domains: domains.into_iter().collect(),
    }
}

/// Every storyline and look-alike with its evidence: whether Microsoft 365 logged each item
/// (`World::logged` for UAL records; everything else is recorded) and where the tree delivered
/// it.
pub fn story_expects(
    world: &World,
    records: &[StoryRecord],
    out: &TreeOutcome,
) -> Vec<StoryExpect> {
    records
        .iter()
        .map(|r| StoryExpect {
            id: r.id.clone(),
            kind: r.kind.as_str().to_string(),
            polarity: match r.polarity {
                Polarity::Positive => "positive",
                Polarity::Lookalike => "lookalike",
            }
            .to_string(),
            actor: r.actor.clone(),
            time: r.time,
            evidence: r
                .evidence
                .iter()
                .map(|e| EvidenceRef {
                    what: format!("{e:?}"),
                    logged: match e {
                        Evidence::Ual(id) => world
                            .story
                            .ual
                            .iter()
                            .find(|u| u.id == *id)
                            .is_none_or(|u| world.logged(u)),
                        _ => true,
                    },
                    delivered: out
                        .delivered
                        .get(e)
                        .into_iter()
                        .flatten()
                        .map(|(table, sighting)| Landed {
                            table: table.clone(),
                            record_key: keys::for_evidence(world, e, table, &sighting.rel_path),
                            sighting: sighting.clone(),
                        })
                        .collect(),
                })
                .collect(),
        })
        .collect()
}
