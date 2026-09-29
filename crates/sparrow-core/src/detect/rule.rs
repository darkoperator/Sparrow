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
    /// The rule reads `ip_intel` ASN / location. The runner records `not_applicable` ("no GeoIP
    /// data") for a tenant none of whose event IPs has an ASN, a country or a location.
    #[serde(default, skip_serializing_if = "is_false")]
    pub needs_geoip: bool,
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

fn is_false(b: &bool) -> bool {
    !*b
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
///
/// Deserialization is strict: a leaf has exactly one field and one operator, `all` / `any` / `not`
/// stand alone, and every other shape is an error naming the path (`match.all[2].f: ...`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Cond {
    All { all: Vec<Cond> },
    Any { any: Vec<Cond> },
    Not { not: Box<Cond> },
    Leaf(BTreeMap<String, BTreeMap<Op, serde_json::Value>>),
}

impl<'de> Deserialize<'de> for Cond {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        Cond::from_json(&v, "match").map_err(serde::de::Error::custom)
    }
}

impl Cond {
    /// Parse a condition from a JSON value; `path` prefixes every error (`match`, `match.all[2]`).
    pub fn from_json(v: &serde_json::Value, path: &str) -> Result<Cond, String> {
        let Some(map) = v.as_object() else {
            return Err(format!("{path}: a condition must be a map"));
        };
        let combinator = ["all", "any", "not"]
            .into_iter()
            .find(|k| map.contains_key(*k));
        if let Some(key) = combinator {
            if map.len() != 1 {
                return Err(format!(
                    "{path}: all/any/not cannot be combined with other keys"
                ));
            }
            let inner = &map[key];
            if key == "not" {
                let c = Cond::from_json(inner, &format!("{path}.not"))?;
                return Ok(Cond::Not { not: Box::new(c) });
            }
            let Some(items) = inner.as_array() else {
                return Err(format!("{path}.{key}: expected a list of conditions"));
            };
            let conds = items
                .iter()
                .enumerate()
                .map(|(i, c)| Cond::from_json(c, &format!("{path}.{key}[{i}]")))
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(if key == "all" {
                Cond::All { all: conds }
            } else {
                Cond::Any { any: conds }
            });
        }
        if map.len() != 1 {
            return Err(format!(
                "{path}: a leaf has exactly one field, found {}",
                map.len()
            ));
        }
        let (field, ops) = map.iter().next().expect("one entry");
        let fpath = format!("{path}.{field}");
        let Some(ops) = ops.as_object() else {
            return Err(format!("{fpath}: expected an {{operator: value}} map"));
        };
        if ops.len() != 1 {
            return Err(format!(
                "{fpath}: a leaf has exactly one operator, found {}",
                ops.len()
            ));
        }
        let (name, value) = ops.iter().next().expect("one entry");
        let op: Op = serde_json::from_value(serde_json::Value::String(name.clone()))
            .map_err(|_| format!("{fpath}: unknown operator {name:?}"))?;
        Ok(Cond::Leaf(BTreeMap::from([(
            field.clone(),
            BTreeMap::from([(op, value.clone())]),
        )])))
    }
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
