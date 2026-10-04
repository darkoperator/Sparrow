//! The serde model of `rules/coverage.yaml` (the seed-rule coverage matrix). Lint cross-checks
//! rule files against it; `sparrow-synth` re-exports these types with its own typed collector
//! and storyline enums (`RuleDef<Collector, StoryKind>`), so the file has one definition.

use crate::{Error, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// The embedded `rules/coverage.yaml`.
pub const BUILTIN_COVERAGE_YAML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../rules/coverage.yaml"
));

/// One seed rule. `C` is the collector type and `S` the storyline-kind type (both plain strings
/// unless a caller supplies typed enums).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDef<C = String, S = String> {
    pub id: String,
    pub title: String,
    pub category: String,
    pub severity: String,
    /// The Hawk investigate condition(s) the rule covers (`H02`, `H08, H09`), if any.
    pub hawk: Option<String>,
    pub logic: String,
    pub tables: Vec<String>,
    /// Capability ids (`data/capabilities.yaml`).
    pub requires: Vec<String>,
    /// Evidence ids (`profile::availability`).
    pub requires_evidence: Vec<String>,
    pub needs_geoip: bool,
    /// The population threshold the rule needs from the sign-in source (distinct users).
    #[serde(default)]
    pub min_signin_users: Option<u32>,
    pub collectors: Vec<C>,
    /// Collectors that can supply a look-alike's evidence; the same as `collectors` when the
    /// file leaves it out.
    #[serde(default = "Vec::new")]
    pub lookalike_collectors: Vec<C>,
    /// The evidence halves a storyline must reach for a `hit`/`no_hit` to count. Each inner list
    /// is one required half; reaching any table in it satisfies that half. When the file leaves
    /// it out the rule has one group equal to `tables`.
    #[serde(default = "Vec::new")]
    pub evidence_all_of: Vec<Vec<String>>,
    /// Per positive kind, the collectors that can supply THAT kind's evidence when it is fewer than
    /// `collectors` (e.g. a session replay is visible only where the sign-in rows carry a session
    /// id). Absent kinds use `collectors`.
    #[serde(default = "BTreeMap::new")]
    pub kind_collectors: BTreeMap<String, Vec<C>>,
    pub positives: Vec<S>,
    pub lookalikes: Vec<S>,
    /// Look-alike kinds (also in `lookalikes`) that deliver both evidence halves of a
    /// correlated rule but fail its time or actor condition.
    #[serde(default = "Vec::new")]
    pub correlation_negatives: Vec<S>,
    /// Kinds whose records a finding of this rule may cite without an expected `hit`.
    #[serde(default = "Vec::new")]
    pub baseline_allow: Vec<BaselineAllow>,
    /// Kinds whose outcome for this rule depends on generated facts (locations, timings, which
    /// rows a collector delivers): the generator computes `hit` or `no_hit` per tree from the
    /// named condition, and the detection gate checks that outcome exactly.
    #[serde(default = "Vec::new")]
    pub computed: Vec<Computed<S>>,
}

/// One storyline kind whose outcome for a rule the generator computes per tree.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Computed<S = String> {
    pub kind: S,
    /// The computation (`sparrow_synth::oracle::Condition`), named after the rule logic it models.
    pub condition: String,
    /// Why the outcome cannot be fixed per kind.
    pub reason: String,
    /// The declared exception to "a computed kind hits on at least one built-in tree": why no
    /// built-in tree can make it hit. Absent for every kind that must be seen hitting.
    #[serde(default)]
    pub never_hits: Option<String>,
}

/// One documented exception to the detection gate's baseline rule.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineAllow {
    /// A storyline kind, or `baseline` for background activity no storyline produced.
    pub kind: String,
    pub reason: String,
}

/// The whole file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageMatrix<C = String, S = String> {
    pub version: u32,
    pub rules: Vec<RuleDef<C, S>>,
}

impl<C, S> CoverageMatrix<C, S>
where
    C: for<'de> Deserialize<'de>,
    S: for<'de> Deserialize<'de>,
{
    /// Parse a coverage file; rejects an unknown version and duplicate rule ids.
    pub fn from_yaml(text: &str) -> Result<Self> {
        let m: Self = serde_norway::from_str(text)
            .map_err(|e| Error::Invalid(format!("rules/coverage.yaml: {e}")))?;
        if m.version != 1 {
            return Err(Error::Invalid(
                "rules/coverage.yaml: unknown version".to_string(),
            ));
        }
        let mut seen = BTreeSet::new();
        for r in &m.rules {
            if !seen.insert(r.id.as_str()) {
                return Err(Error::Invalid(format!(
                    "rules/coverage.yaml: duplicate rule id {}",
                    r.id
                )));
            }
        }
        Ok(m)
    }
}

impl CoverageMatrix {
    /// The embedded matrix.
    pub fn builtin() -> Result<Self> {
        Self::from_yaml(BUILTIN_COVERAGE_YAML)
    }

    pub fn rule(&self, id: &str) -> Option<&RuleDef> {
        self.rules.iter().find(|r| r.id == id)
    }
}
