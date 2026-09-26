//! The seed-rule coverage matrix (`rules/coverage.yaml`): every spec §8.5 seed rule with its
//! intended logic, evidence tables, licence requirements, the collectors that can supply its
//! evidence, and the storyline kinds that must and must not trigger it. It is the single source
//! of the rule ↔ storyline mapping; Phase 6 implements the rules' `logic`.
//!
//! The file is embedded at compile time, so a malformed file is a build defect: the loader
//! panics with the offending rule id, and the tests load it.

use crate::options::Collector;
use crate::scenario::StoryKind;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::sync::OnceLock;

const COVERAGE_YAML: &str = include_str!("../../../rules/coverage.yaml");

/// One seed rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
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
    pub collectors: Vec<Collector>,
    /// Collectors that can supply a look-alike's evidence; the same as `collectors` when the
    /// file leaves it out.
    #[serde(default)]
    pub lookalike_collectors: Vec<Collector>,
    pub positives: Vec<StoryKind>,
    pub lookalikes: Vec<StoryKind>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageFile {
    version: u32,
    rules: Vec<RuleDef>,
}

fn load() -> Vec<RuleDef> {
    let file: CoverageFile = serde_norway::from_str(COVERAGE_YAML)
        .unwrap_or_else(|e| panic!("rules/coverage.yaml: {e}"));
    assert_eq!(file.version, 1, "rules/coverage.yaml: unknown version");
    let mut seen = BTreeSet::new();
    let mut rules = file.rules;
    for r in &mut rules {
        assert!(
            seen.insert(r.id.clone()),
            "rules/coverage.yaml: duplicate rule id {}",
            r.id
        );
        assert!(
            !r.positives.is_empty() && !r.lookalikes.is_empty(),
            "rules/coverage.yaml: {} needs positives and lookalikes",
            r.id
        );
        assert!(
            !r.tables.is_empty() && !r.collectors.is_empty(),
            "rules/coverage.yaml: {} needs tables and collectors",
            r.id
        );
        if r.lookalike_collectors.is_empty() {
            r.lookalike_collectors = r.collectors.clone();
        }
    }
    rules
}

/// Every seed rule, in file order.
pub fn rules() -> &'static [RuleDef] {
    static RULES: OnceLock<Vec<RuleDef>> = OnceLock::new();
    RULES.get_or_init(load)
}

/// The rule with id `id`.
pub fn rule(id: &str) -> Option<&'static RuleDef> {
    rules().iter().find(|r| r.id == id)
}

/// The ids of the rules a storyline of `kind` must trigger.
pub fn triggers(kind: StoryKind) -> Vec<&'static str> {
    rules()
        .iter()
        .filter(|r| r.positives.contains(&kind))
        .map(|r| r.id.as_str())
        .collect()
}

/// The ids of the rules a storyline of `kind` must not trigger.
pub fn must_not_trigger(kind: StoryKind) -> Vec<&'static str> {
    rules()
        .iter()
        .filter(|r| r.lookalikes.contains(&kind))
        .map(|r| r.id.as_str())
        .collect()
}
