//! Rule lint (spec §8.4): every compile error, shape checks on the rule's tests and `group_by`,
//! duplicate ids, and the cross-check against `rules/coverage.yaml`.

use crate::detect::compile::{CaseSchema, OUTPUT_FIELDS, compile_with_meta};
use crate::detect::coverage::CoverageMatrix;
use crate::detect::load::{LoadedRule, RuleSet};
use crate::detect::rule::{Rule, RuleBody};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintIssue {
    pub rule_id: String,
    pub severity: LintSeverity,
    pub message: String,
}

fn issue(rule_id: &str, severity: LintSeverity, message: impl Into<String>) -> LintIssue {
    LintIssue {
        rule_id: rule_id.to_string(),
        severity,
        message: message.into(),
    }
}

/// The table a rule's hits land in: its `source`, or the first `sources` arm. `sql:` rules have
/// none.
fn hit_table(rule: &Rule) -> Option<&str> {
    match &rule.body {
        RuleBody::Match { source, .. } => Some(source),
        RuleBody::Sources { sources } => sources.first().map(|s| s.source.as_str()),
        RuleBody::Sql { .. } => None,
    }
}

/// Lint a rule set. `coverage` enables the cross-check against the coverage matrix (a coverage
/// id without a rule file is a warning until Task 12 closes the pack, then an error).
pub fn lint(
    set: &RuleSet,
    schema: &CaseSchema,
    coverage: Option<&CoverageMatrix>,
) -> Vec<LintIssue> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for lr in &set.rules {
        let r = &lr.rule;
        if !seen.insert(r.id.as_str()) {
            out.push(issue(&r.id, LintSeverity::Error, "duplicate rule id"));
        }
        lint_rule(lr, set, schema, &mut out);
    }
    if let Some(cov) = coverage {
        cross_check(set, schema, cov, &mut out);
    }
    out
}

fn lint_rule(lr: &LoadedRule, set: &RuleSet, schema: &CaseSchema, out: &mut Vec<LintIssue>) {
    let r = &lr.rule;
    if let Err(e) = compile_with_meta(r, &set.lists, &set.list_meta, schema) {
        out.push(issue(&r.id, LintSeverity::Error, e.to_string()));
    }
    if !r.tests.iter().any(|t| t.expect_hits >= 1) {
        out.push(issue(
            &r.id,
            LintSeverity::Error,
            "needs a positive test (expect_hits >= 1)",
        ));
    }
    if !r.tests.iter().any(|t| t.expect_hits == 0) {
        out.push(issue(
            &r.id,
            LintSeverity::Error,
            "needs a look-alike test (expect_hits == 0)",
        ));
    }
    // group_by names output columns; for `sql:` rules any other name is a `context` key.
    let is_sql = matches!(r.body, RuleBody::Sql { .. });
    for g in &r.group_by {
        if !OUTPUT_FIELDS.contains(&g.as_str()) && !is_sql {
            out.push(issue(
                &r.id,
                LintSeverity::Error,
                format!(
                    "group_by {g:?} is not an output column ({})",
                    OUTPUT_FIELDS.join(", ")
                ),
            ));
        }
    }
}

fn cross_check(set: &RuleSet, schema: &CaseSchema, cov: &CoverageMatrix, out: &mut Vec<LintIssue>) {
    let ids: BTreeSet<&str> = set.rules.iter().map(|r| r.rule.id.as_str()).collect();
    for lr in &set.rules {
        let r = &lr.rule;
        let builtin = lr.path.starts_with("builtin:");
        let Some(def) = cov.rule(&r.id) else {
            if builtin {
                out.push(issue(
                    &r.id,
                    LintSeverity::Error,
                    "built-in rule has no coverage entry in rules/coverage.yaml",
                ));
            }
            continue;
        };
        let sorted = |v: &[String]| {
            let mut v = v.to_vec();
            v.sort();
            v
        };
        if sorted(&r.requires) != sorted(&def.requires) {
            out.push(issue(
                &r.id,
                LintSeverity::Error,
                format!(
                    "requires {:?} differs from coverage {:?}",
                    r.requires, def.requires
                ),
            ));
        }
        if sorted(&r.requires_evidence) != sorted(&def.requires_evidence) {
            out.push(issue(
                &r.id,
                LintSeverity::Error,
                format!(
                    "requires_evidence {:?} differs from coverage {:?}",
                    r.requires_evidence, def.requires_evidence
                ),
            ));
        }
        match hit_table(r) {
            Some(t) => {
                if !def.tables.iter().any(|x| x == t) {
                    out.push(issue(
                        &r.id,
                        LintSeverity::Error,
                        format!("hit table {t} is not in coverage tables {:?}", def.tables),
                    ));
                } else if def.tables.first().map(String::as_str) != Some(t) {
                    out.push(issue(
                        &r.id,
                        LintSeverity::Error,
                        format!(
                            "hit table {t} must be the first coverage table ({:?})",
                            def.tables.first()
                        ),
                    ));
                }
            }
            None => {
                // A sql: rule's hits land in the tables it emits as `source_table`: each must be
                // a coverage table, and the first coverage table must be one of them.
                let Ok(c) = compile_with_meta(&lr.rule, &set.lists, &set.list_meta, schema) else {
                    continue;
                };
                let emitted = c.emitted_tables;
                for t in &emitted {
                    if !def.tables.contains(t) {
                        out.push(issue(
                            &r.id,
                            LintSeverity::Error,
                            format!(
                                "sql emits source_table {t}, which is not in coverage tables {:?}",
                                def.tables
                            ),
                        ));
                    }
                }
                if let Some(first) = def.tables.first() {
                    if !emitted.contains(first) {
                        out.push(issue(
                            &r.id,
                            LintSeverity::Error,
                            format!(
                                "sql never emits the first coverage table {first} as source_table"
                            ),
                        ));
                    }
                }
            }
        }
    }
    for def in &cov.rules {
        if !ids.contains(def.id.as_str()) {
            out.push(issue(
                &def.id,
                LintSeverity::Warning,
                "coverage entry has no rule file yet",
            ));
        }
    }
}
