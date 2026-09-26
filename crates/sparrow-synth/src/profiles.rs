//! Licence and audit profiles for generated tenants (`data/licence_profiles.yaml`,
//! `data/audit_profiles.yaml`): the SKUs a tenant holds and the per-collector-delivery
//! capability outcome Sparrow must derive from them, hand-written from the licensing research
//! (plan Task 2) rather than computed from Sparrow's own code — so a diff against Sparrow's
//! output means one of them is wrong, not that they were built to agree.

use crate::scenario::UserSel;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;

const LICENCE_YAML: &str = include_str!("../data/licence_profiles.yaml");
const AUDIT_YAML: &str = include_str!("../data/audit_profiles.yaml");

/// Which licence evidence a tree delivers, matching the `expect` keys in
/// `data/licence_profiles.yaml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Delivery {
    #[serde(rename = "invictus_list")]
    InvictusList,
    #[serde(rename = "invictus_nolist")]
    InvictusNoList,
    #[serde(rename = "hawk4")]
    Hawk4,
    #[serde(rename = "hawk3")]
    Hawk3,
    #[serde(rename = "portal")]
    Portal,
}

/// One Graph `subscribedSkus` entry as Microsoft-Extractor-Suite's `Get-Licenses` exports it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkuSpec {
    pub sku: String,
    pub status: String,
    pub scope: String,
    pub units: u32,
    pub plans: Vec<String>,
}

/// The `tenant_capabilities` outcome Sparrow must derive for one capability under one
/// `Delivery`, parsed from an expectation string's `<capability>=<status>/<confidence>` term.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapExpect {
    pub status: String,
    pub confidence: Option<String>,
}

/// A tenant's SKUs and the hand-written capability outcome for each licence-evidence delivery.
#[derive(Debug, Clone)]
pub struct LicenceProfile {
    pub id: String,
    pub title: String,
    pub skus: Vec<SkuSpec>,
    pub expect: BTreeMap<Delivery, BTreeMap<String, CapExpect>>,
}

impl LicenceProfile {
    /// Whether any SKU carries `plan`, trimmed and compared case-insensitively.
    pub fn has_plan(&self, plan: &str) -> bool {
        let want = plan.trim();
        self.skus
            .iter()
            .flat_map(|s| s.plans.iter())
            .any(|p| p.trim().eq_ignore_ascii_case(want))
    }

    pub fn p1(&self) -> bool {
        self.has_plan("AAD_PREMIUM") || self.has_plan("AAD_PREMIUM_P2")
    }

    pub fn p2(&self) -> bool {
        self.has_plan("AAD_PREMIUM_P2")
    }

    pub fn audit_premium(&self) -> bool {
        self.has_plan("M365_ADVANCED_AUDITING")
    }

    pub fn mdo_p1(&self) -> bool {
        self.has_plan("ATP_ENTERPRISE")
    }

    pub fn mdo_p2(&self) -> bool {
        self.has_plan("THREAT_INTELLIGENCE")
    }
}

/// Organization and mailbox audit settings for a generated tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditProfile {
    pub id: String,
    pub title: String,
    pub unified_audit_log_ingestion_enabled: bool,
    pub org_audit_disabled: bool,
    pub admin_audit_log_enabled: bool,
    pub customized_owner: UserSel,
    pub bypass: UserSel,
    pub search_query_owner: UserSel,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LicenceFile {
    #[allow(dead_code)]
    version: u32,
    profiles: Vec<RawLicenceProfile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLicenceProfile {
    id: String,
    title: String,
    skus: Vec<SkuSpec>,
    expect: BTreeMap<Delivery, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditFile {
    #[allow(dead_code)]
    version: u32,
    profiles: Vec<AuditProfile>,
}

/// Parses one `<capability>=<status>/<confidence>` term (`-` = no confidence).
fn parse_cap_expect(term: &str) -> Result<(String, CapExpect)> {
    let (cap, rest) = term.split_once('=').ok_or_else(|| {
        Error::Invalid(format!(
            "licence profile: malformed capability expectation '{term}'"
        ))
    })?;
    let (status, confidence) = rest.split_once('/').ok_or_else(|| {
        Error::Invalid(format!(
            "licence profile: malformed capability expectation '{term}'"
        ))
    })?;
    let confidence = if confidence == "-" {
        None
    } else {
        Some(confidence.to_string())
    };
    Ok((
        cap.to_string(),
        CapExpect {
            status: status.to_string(),
            confidence,
        },
    ))
}

fn parse_expect_line(line: &str) -> Result<BTreeMap<String, CapExpect>> {
    line.split_whitespace().map(parse_cap_expect).collect()
}

fn licence_profiles_raw() -> &'static Vec<LicenceProfile> {
    static PROFILES: OnceLock<Vec<LicenceProfile>> = OnceLock::new();
    PROFILES.get_or_init(|| {
        let file: LicenceFile =
            serde_norway::from_str(LICENCE_YAML).expect("data/licence_profiles.yaml parses");
        file.profiles
            .into_iter()
            .map(|raw| {
                let expect = raw
                    .expect
                    .into_iter()
                    .map(|(delivery, line)| {
                        let parsed = parse_expect_line(&line)
                            .unwrap_or_else(|e| panic!("licence profile {}: {e}", raw.id));
                        (delivery, parsed)
                    })
                    .collect();
                LicenceProfile {
                    id: raw.id,
                    title: raw.title,
                    skus: raw.skus,
                    expect,
                }
            })
            .collect()
    })
}

fn audit_profiles_raw() -> &'static Vec<AuditProfile> {
    static PROFILES: OnceLock<Vec<AuditProfile>> = OnceLock::new();
    PROFILES.get_or_init(|| {
        let file: AuditFile =
            serde_norway::from_str(AUDIT_YAML).expect("data/audit_profiles.yaml parses");
        file.profiles
    })
}

pub fn licence_profiles() -> &'static [LicenceProfile] {
    licence_profiles_raw()
}

pub fn audit_profiles() -> &'static [AuditProfile] {
    audit_profiles_raw()
}

pub fn licence_profile(id: &str) -> Result<&'static LicenceProfile> {
    licence_profiles_raw()
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| Error::Scenario(format!("licence_profile: unknown profile '{id}'")))
}

pub fn audit_profile(id: &str) -> Result<&'static AuditProfile> {
    audit_profiles_raw()
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| Error::Scenario(format!("audit_profile: unknown profile '{id}'")))
}
