//! The seed-rule coverage matrix (`rules/coverage.yaml`): every spec §8.5 seed rule with its
//! intended logic, evidence tables, licence requirements, the collectors that can supply its
//! evidence, and the storyline kinds that must and must not trigger it. It is the single source
//! of the rule ↔ storyline mapping; Phase 6 implements the rules' `logic`.
//!
//! The file is embedded at compile time, so a malformed file is a build defect: the loader
//! panics with the offending rule id, and the tests load it.

use crate::manifest::RuleOutcome;
use crate::options::{Collector, GenerateOptions};
use crate::scenario::StoryKind;
use crate::tree::NullSink;
use crate::{Result, generate};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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

/// One place a rule was exercised: a storyline in one built-in scenario's tree for one
/// collector, with the licence and audit profiles that tree was generated under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exercise {
    pub scenario: String,
    pub collector: Collector,
    pub storyline: String,
    pub licence_profile: String,
    pub audit_profile: String,
    pub reason: String,
}

/// Every exercise of one seed rule and the gaps left across the built-in matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCoverage {
    pub id: String,
    pub title: String,
    pub hits: Vec<Exercise>,
    pub no_hits: Vec<Exercise>,
    pub not_applicable: Vec<Exercise>,
    pub no_evidence: Vec<Exercise>,
    pub collectors_hit: BTreeSet<Collector>,
    pub collectors_no_hit: BTreeSet<Collector>,
    pub gaps: Vec<String>,
}

/// The detection-coverage report over every built-in scenario (except `volume`) × collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageReport {
    pub rules: Vec<RuleCoverage>,
    pub gaps: Vec<String>,
    pub ok: bool,
}

impl CoverageReport {
    /// The human-readable report: one block per rule, then `N rules, M gaps`.
    pub fn to_text(&self) -> String {
        fn places(v: &[Exercise]) -> String {
            if v.is_empty() {
                return "none".to_string();
            }
            v.iter()
                .map(|e| format!("{}/{}/{}", e.scenario, e.collector, e.storyline))
                .collect::<Vec<_>>()
                .join(", ")
        }
        let mut out = String::new();
        for r in &self.rules {
            out.push_str(&format!("{} {}\n", r.id, r.title));
            out.push_str(&format!("positive: {}\n", places(&r.hits)));
            out.push_str(&format!("look-alike: {}\n", places(&r.no_hits)));
            out.push_str(&format!("not applicable: {}\n", places(&r.not_applicable)));
            out.push_str(&format!(
                "gaps: {}\n",
                if r.gaps.is_empty() {
                    "none".to_string()
                } else {
                    r.gaps.join("; ")
                }
            ));
        }
        out.push_str(&format!(
            "{} rules, {} gaps\n",
            self.rules.len(),
            self.gaps.len()
        ));
        out
    }
}

/// One rule outcome in one tree, while aggregating.
struct Observed {
    outcome: RuleOutcome,
    exercise: Exercise,
    has_geoip: bool,
}

/// Generate every built-in scenario (except `volume`) for every collector into a [`NullSink`]
/// and aggregate their manifests' rule outcomes into the coverage report.
pub fn report(seed: u64) -> Result<CoverageReport> {
    let mut observed: BTreeMap<String, Vec<Observed>> = BTreeMap::new();
    for name in crate::scenario::builtin_names()
        .iter()
        .filter(|n| **n != "volume")
    {
        let scenario = crate::scenario::load(name)?;
        for collector in Collector::ALL {
            let opts = GenerateOptions::new(*collector, seed);
            let mut sink = NullSink::default();
            let manifest = generate::generate(&scenario, &opts, &mut sink)?;
            let has_geoip = manifest.geoip_dir.is_some();
            for r in &manifest.rules {
                observed
                    .entry(r.rule_id.clone())
                    .or_default()
                    .push(Observed {
                        outcome: r.outcome,
                        has_geoip,
                        exercise: Exercise {
                            scenario: name.to_string(),
                            collector: *collector,
                            storyline: r.storyline.clone(),
                            licence_profile: manifest.licence_profile.clone(),
                            audit_profile: manifest.audit_profile.clone(),
                            reason: r.reason.clone(),
                        },
                    });
            }
        }
    }
    let mut report = CoverageReport {
        rules: Vec::new(),
        gaps: Vec::new(),
        ok: true,
    };
    for rule in rules() {
        let entries = observed.remove(&rule.id).unwrap_or_default();
        let mut hits = Vec::new();
        let mut no_hits = Vec::new();
        let mut not_applicable = Vec::new();
        let mut no_evidence = Vec::new();
        let mut collectors_hit = BTreeSet::new();
        let mut collectors_no_hit = BTreeSet::new();
        let mut geoip_hits = 0usize;
        for o in entries {
            match o.outcome {
                RuleOutcome::Hit => {
                    collectors_hit.insert(o.exercise.collector);
                    if o.has_geoip {
                        geoip_hits += 1;
                    }
                    hits.push(o.exercise);
                }
                RuleOutcome::NoHit => {
                    collectors_no_hit.insert(o.exercise.collector);
                    no_hits.push(o.exercise);
                }
                RuleOutcome::NotApplicable => not_applicable.push(o.exercise),
                RuleOutcome::NoEvidence => no_evidence.push(o.exercise),
            }
        }
        let mut gaps = Vec::new();
        if hits.is_empty() {
            gaps.push(format!("{}: no hit in any tree", rule.id));
        }
        if no_hits.is_empty() {
            gaps.push(format!("{}: no no_hit in any tree", rule.id));
        }
        for c in &rule.collectors {
            if !collectors_hit.contains(c) {
                gaps.push(format!("{}: no hit through {c}", rule.id));
            }
        }
        for c in &rule.lookalike_collectors {
            if !collectors_no_hit.contains(c) {
                gaps.push(format!("{}: no no_hit through {c}", rule.id));
            }
        }
        if (!rule.requires.is_empty() || !rule.requires_evidence.is_empty())
            && not_applicable.is_empty()
        {
            gaps.push(format!("{}: no not_applicable anywhere", rule.id));
        }
        if rule.needs_geoip && !hits.is_empty() && geoip_hits == 0 {
            gaps.push(format!(
                "{}: its hits come from trees without GeoIP",
                rule.id
            ));
        }
        report.gaps.extend(gaps.iter().cloned());
        report.rules.push(RuleCoverage {
            id: rule.id.clone(),
            title: rule.title.clone(),
            hits,
            no_hits,
            not_applicable,
            no_evidence,
            collectors_hit,
            collectors_no_hit,
            gaps,
        });
    }
    report.ok = report.gaps.is_empty();
    Ok(report)
}
