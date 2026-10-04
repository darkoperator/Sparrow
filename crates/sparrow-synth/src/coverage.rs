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

/// One seed rule, with the typed collector and storyline enums of this crate. The serde model
/// lives in `sparrow_core::detect::coverage` (lint cross-checks the same file).
pub type RuleDef = sparrow_core::detect::coverage::RuleDef<Collector, StoryKind>;
pub use sparrow_core::detect::coverage::CoverageMatrix;

fn load() -> Vec<RuleDef> {
    let file = CoverageMatrix::<Collector, StoryKind>::from_yaml(
        sparrow_core::detect::coverage::BUILTIN_COVERAGE_YAML,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let mut rules = file.rules;
    for r in &mut rules {
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
        for n in &r.correlation_negatives {
            assert!(
                r.lookalikes.contains(n),
                "rules/coverage.yaml: {}: correlation negative {} must also be a look-alike",
                r.id,
                n.as_str()
            );
        }
        if r.evidence_all_of.is_empty() {
            r.evidence_all_of = vec![r.tables.clone()];
        }
        for c in &r.computed {
            assert!(
                !r.positives.contains(&c.kind) && !r.lookalikes.contains(&c.kind),
                "rules/coverage.yaml: {}: computed kind {} is also a positive or look-alike",
                r.id,
                c.kind.as_str()
            );
            let cond = crate::oracle::Condition::parse(&c.condition).unwrap_or_else(|| {
                panic!(
                    "rules/coverage.yaml: {}: unknown computed condition {}",
                    r.id, c.condition
                )
            });
            assert_eq!(
                cond.rule_id(),
                r.id,
                "rules/coverage.yaml: {}: condition {} models another rule",
                r.id,
                c.condition
            );
            assert!(
                c.never_hits.as_deref().is_none_or(|w| !w.trim().is_empty()),
                "rules/coverage.yaml: {}: computed kind {} declares never_hits without a reason",
                r.id,
                c.kind.as_str()
            );
        }
    }
    rules
}

/// Whether `delivered` (the evidence tables a storyline reached, i.e. a manifest rule's
/// `tables`) satisfies every evidence group of a correlated rule: each group needs at least one
/// of its tables delivered. A rule with no `evidence_all_of` has one group equal to its
/// `tables`, so this is true whenever any of the rule's tables was reached.
pub fn evidence_all_of_satisfied(groups: &[Vec<String>], delivered: &[String]) -> bool {
    groups
        .iter()
        .all(|group| group.iter().any(|t| delivered.iter().any(|d| d == t)))
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
    /// The rule's tables the storyline's evidence reached (the manifest rule's `tables`).
    tables: Vec<String>,
    /// The storyline's kind (`StoryKind::as_str`).
    kind: String,
    /// Distinct delivered evidence items cover every `evidence_all_of` group.
    complete: bool,
}

/// Generate every built-in scenario (except `volume`) for every collector into a [`NullSink`]
/// and aggregate their manifests' rule outcomes into the coverage report.
pub fn report(seed: u64) -> Result<CoverageReport> {
    report_with(seed, rules())
}

/// [`report`] against an explicit rule list (tests remove a rule's correlation negatives to see
/// the gap).
pub fn report_with(seed: u64, rules: &[RuleDef]) -> Result<CoverageReport> {
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
                        tables: r.tables.clone(),
                        complete: r.complete,
                        kind: manifest
                            .storylines
                            .iter()
                            .find(|st| st.id == r.storyline)
                            .map(|st| st.kind.clone())
                            .unwrap_or_default(),
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
    for rule in rules {
        let entries = observed.remove(&rule.id).unwrap_or_default();
        let mut hits = Vec::new();
        let mut no_hits = Vec::new();
        let mut not_applicable = Vec::new();
        let mut no_evidence = Vec::new();
        let mut collectors_hit = BTreeSet::new();
        let mut collectors_no_hit = BTreeSet::new();
        let mut negative_seen = false;
        let mut geoip_hits = 0usize;
        for o in entries {
            let full = o.complete && evidence_all_of_satisfied(&rule.evidence_all_of, &o.tables);
            match o.outcome {
                RuleOutcome::Hit if full => {
                    collectors_hit.insert(o.exercise.collector);
                    if o.has_geoip {
                        geoip_hits += 1;
                    }
                    hits.push(o.exercise);
                }
                RuleOutcome::NoHit if full => {
                    negative_seen |= rule
                        .correlation_negatives
                        .iter()
                        .any(|k| k.as_str() == o.kind);
                    collectors_no_hit.insert(o.exercise.collector);
                    no_hits.push(o.exercise);
                }
                // A correlated rule whose storyline reached only some of its evidence halves is
                // not a hit/no_hit through that collector: report it as no evidence instead.
                RuleOutcome::Hit | RuleOutcome::NoHit => {
                    let mut e = o.exercise;
                    e.reason = format!(
                        "{}; reached only part of {}'s correlated evidence (delivered: {})",
                        e.reason,
                        rule.id,
                        o.tables.join(", ")
                    );
                    no_evidence.push(e);
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
        if rule.evidence_all_of.len() > 1 && !negative_seen {
            gaps.push(format!(
                "{}: correlated rule has no correlation negative",
                rule.id
            ));
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
