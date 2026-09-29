//! The declarative rule model (spec §8.2, Addendum C.2). Field names and types are the contract
//! later tasks build on.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One detection rule, as written in `rules/<category>/<id>.yaml`.
///
/// `body` is flattened: a rule carries either `source` + `match`, or `sources`, or `sql` at the
/// top level.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub version: u32,
    pub status: RuleStatus,
    pub severity: Severity,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub mitre: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Capability ids (from `data/capabilities.yaml`).
    #[serde(default)]
    pub requires: Vec<String>,
    /// Evidence ids (from `evidence_availability`) that must be present.
    #[serde(default)]
    pub requires_evidence: Vec<String>,
    #[serde(flatten)]
    pub body: RuleBody,
    #[serde(default)]
    pub group_by: Vec<String>,
    #[serde(default)]
    pub threshold: Option<Threshold>,
    pub analyst_guidance: String,
    #[serde(default)]
    pub false_positives: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub author: Option<String>,
    pub tests: Vec<RuleTest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleStatus {
    Experimental,
    Stable,
    Deprecated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// The hit expression: a single-source `match`, a multi-source `sources` union, or raw `sql`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleBody {
    Match {
        source: String,
        #[serde(rename = "match")]
        m: Cond,
    },
    Sources {
        sources: Vec<SourceMatch>,
    },
    Sql {
        sql: String,
    },
}

/// One `{source, match}` arm of a multi-source rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceMatch {
    pub source: String,
    #[serde(rename = "match")]
    pub m: Cond,
}

/// `all` / `any` / `not`, or one `field: {op: value}` leaf (a single-key map).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Cond {
    All { all: Vec<Cond> },
    Any { any: Vec<Cond> },
    Not { not: Box<Cond> },
    Leaf(BTreeMap<String, BTreeMap<Op, serde_json::Value>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Eq,
    Neq,
    In,
    Contains,
    ContainsAny,
    Startswith,
    Endswith,
    Regex,
    Cidr,
    Gt,
    Gte,
    Lt,
    Lte,
    Exists,
    EqField,
    NeqField,
}

/// A burst threshold: `count` (`">= 50"`, `"> 50"`, `"= 50"`) hits per `group_by` in `window`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Threshold {
    pub group_by: Vec<String>,
    /// `"10m"`, `"1h"`, `"1d"`.
    pub window: String,
    pub count: String,
}

/// One inline fixture: records inserted into an in-memory case, and the number of hits expected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleTest {
    pub name: String,
    pub records: Vec<serde_json::Map<String, serde_json::Value>>,
    pub expect_hits: u32,
}
