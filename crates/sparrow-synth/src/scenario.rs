//! The scenario format: a tenant, its benign baseline, and the storylines and look-alikes to
//! inject (spec Addendum B). A scenario is either a built-in name (embedded at compile time) or
//! a YAML file path.

use crate::profiles::{audit_profile, licence_profile};
use crate::reserved::is_reserved_domain;
use crate::{Error, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const BUILTIN: &[(&str, &str)] = &[
    (
        "audit-tamper",
        include_str!("../scenarios/audit-tamper.yaml"),
    ),
    ("bec-aitm", include_str!("../scenarios/bec-aitm.yaml")),
    (
        "bec-e3-audit-gaps",
        include_str!("../scenarios/bec-e3-audit-gaps.yaml"),
    ),
    (
        "bec-o365-no-p1",
        include_str!("../scenarios/bec-o365-no-p1.yaml"),
    ),
    (
        "business-basic",
        include_str!("../scenarios/business-basic.yaml"),
    ),
    (
        "hawk-investigate",
        include_str!("../scenarios/hawk-investigate.yaml"),
    ),
    ("password-spray", include_str!("../scenarios/password-spray.yaml")),
    ("volume", include_str!("../scenarios/volume.yaml")),
];

/// The names of the embedded built-in scenarios, in the order they're compiled in.
pub fn builtin_names() -> &'static [&'static str] {
    static NAMES: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| BUILTIN.iter().map(|(n, _)| *n).collect())
}

/// A built-in scenario by name, else a YAML file at `name_or_path`.
pub fn load(name_or_path: &str) -> Result<Scenario> {
    if let Some((_, text)) = BUILTIN.iter().find(|(n, _)| *n == name_or_path) {
        return from_yaml(text);
    }
    let text = std::fs::read_to_string(name_or_path).map_err(|e| Error::io(name_or_path, e))?;
    from_yaml(&text)
}

/// Parses and validates a scenario from YAML text.
pub fn from_yaml(text: &str) -> Result<Scenario> {
    let s: Scenario = serde_norway::from_str(text)?;
    s.validate()?;
    Ok(s)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub tenant: TenantSpec,
    pub window: WindowSpec,
    #[serde(default)]
    pub baseline: BaselineSpec,
    #[serde(default)]
    pub storylines: Vec<StorySpec>,
    #[serde(default)]
    pub lookalikes: Vec<StorySpec>,
    #[serde(default)]
    pub scale: ScaleSpec,
    /// Test-only: align the world's historical state dates to day 1 of their month, so a
    /// day/month-order culture can never read any of them as decisive. No built-in scenario sets
    /// it; it exists so the all-ambiguous culture test controls its own dates instead of the
    /// world's historical offsets being nudged whenever a writer adds a dated file.
    #[serde(default)]
    pub pin_ambiguous_dates: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantSpec {
    pub name: String,
    pub domains: Vec<String>,
    pub users: u32,
    #[serde(default = "one")]
    pub admins: u32,
    pub licence_profile: String,
    #[serde(default = "default_audit")]
    pub audit_profile: String,
    #[serde(default)]
    pub host_utc_offset_minutes: i32,
    #[serde(default)]
    pub hawk_users: Vec<u32>,
    /// Test-only: add the role-assignable Finance group as a direct member of the activated
    /// "User Administrator" directory role, reproducing the AllRoles group-member carry-over.
    /// Only `bec-aitm` sets it.
    #[serde(default)]
    pub role_group_member: bool,
}

fn one() -> u32 {
    1
}

fn default_audit() -> String {
    "default".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowSpec {
    pub start: DateTime<Utc>,
    pub days: u32,
    pub collected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BaselineSpec {
    pub signins_per_user_day: f64,
    pub ual_per_user_day: f64,
    pub messages_per_user_day: f64,
    pub work_hours: (u32, u32),
    pub weekend_factor: f64,
}

impl Default for BaselineSpec {
    fn default() -> Self {
        BaselineSpec {
            signins_per_user_day: 4.0,
            ual_per_user_day: 12.0,
            messages_per_user_day: 6.0,
            work_hours: (8, 18),
            weekend_factor: 0.1,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ScaleSpec {
    pub ual_rows: u64,
    pub signins: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorySpec {
    pub kind: StoryKind,
    pub id: String,
    #[serde(default)]
    pub actor: Option<u32>,
    #[serde(default)]
    pub target: Option<u32>,
    pub at: At,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum At {
    After {
        after: String,
        minutes: u32,
    },
    Day {
        day: u32,
        hour: u32,
        #[serde(default)]
        minute: u32,
    },
}

/// Whether a storyline kind is part of the positive kill chain, or a benign look-alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    Positive,
    Lookalike,
}

macro_rules! story_kind {
    (positive { $($p:ident => $ps:literal),+ $(,)? } lookalike { $($l:ident => $ls:literal),+ $(,)? }) => {
        /// A storyline (positive) or look-alike kind. The storyline tasks (6, 7, ...) define
        /// what each one emits; this task only needs the name and polarity.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub enum StoryKind {
            $(#[serde(rename = $ps)] $p,)+
            $(#[serde(rename = $ls)] $l,)+
        }

        impl StoryKind {
            pub const ALL: &'static [StoryKind] = &[$(StoryKind::$p,)+ $(StoryKind::$l,)+];

            pub fn as_str(self) -> &'static str {
                match self {
                    $(StoryKind::$p => $ps,)+
                    $(StoryKind::$l => $ls,)+
                }
            }

            pub fn polarity(self) -> Polarity {
                match self {
                    $(StoryKind::$p => Polarity::Positive,)+
                    $(StoryKind::$l => Polarity::Lookalike,)+
                }
            }
        }
    };
}

story_kind! {
    positive {
        AitmSignin => "aitm_signin",
        ConfirmedCompromised => "confirmed_compromised",
        MfaMethodAdded => "mfa_method_added",
        OauthConsent => "oauth_consent",
        AppCredentialAdded => "app_credential_added",
        DomainFederation => "domain_federation",
        NewMobileDevice => "new_mobile_device",
        InboxRuleFinance => "inbox_rule_finance",
        AdminInboxRule => "admin_inbox_rule",
        OutlookClientHidingRule => "outlook_client_hiding_rule",
        ForwardingMailbox => "forwarding_mailbox",
        ForwardingInboxRule => "forwarding_inbox_rule",
        ForwardingTransportRule => "forwarding_transport_rule",
        MailboxPermissionGrant => "mailbox_permission_grant",
        MiaBurst => "mia_burst",
        SendNewIp => "send_new_ip",
        SearchFinance => "search_finance",
        AutoreplyEnabled => "autoreply_enabled",
        HeaderSpoof => "header_spoof",
        EdiscoverySearch => "ediscovery_search",
        MassDownload => "mass_download",
        AnonymousLink => "anonymous_link",
        LureShare => "lure_share",
        AuditTamper => "audit_tamper",
        OrgAuditDisabledState => "org_audit_disabled_state",
        DistributedSpray => "distributed_spray",
        SpraySuccess => "spray_success",
    }
    lookalike {
        RiskDismissed => "risk_dismissed",
        MfaNewHire => "mfa_new_hire",
        LowRiskConsent => "low_risk_consent",
        AppSigninExistingConsent => "app_signin_existing_consent",
        CertRotation => "cert_rotation",
        DomainPropertyUpdate => "domain_property_update",
        OldMobileDevice => "old_mobile_device",
        MicrosoftAsnSignin => "microsoft_asn_signin",
        PlausibleTravel => "plausible_travel",
        SameIpTokenUse => "same_ip_token_use",
        VendorFilingRule => "vendor_filing_rule",
        OutlookClientFilingRule => "outlook_client_filing_rule",
        AdminBenignRule => "admin_benign_rule",
        InternalForwarding => "internal_forwarding",
        ForwardingRemoved => "forwarding_removed",
        SetMailboxOtherParam => "set_mailbox_other_param",
        PermissionSystemDiscovery => "permission_system_discovery",
        MiaSync => "mia_sync",
        SendKnownIp => "send_known_ip",
        SearchBenign => "search_benign",
        AutoreplyDisabled => "autoreply_disabled",
        HeaderClean => "header_clean",
        EdiscoveryViewOnly => "ediscovery_view_only",
        NormalDownload => "normal_download",
        AnonymousLinkBenign => "anonymous_link_benign",
        InternalDocxShare => "internal_docx_share",
        AuditConfigBenign => "audit_config_benign",
        MfaAfterStaleRisk => "mfa_after_stale_risk",
        InboxRuleAfterStaleRisk => "inbox_rule_after_stale_risk",
        AnonymousLinkAfterStaleRisk => "anonymous_link_after_stale_risk",
        LureSharedLate => "lure_shared_late",
        WifiToCellular => "wifi_to_cellular",
        Ipv6Rotation => "ipv6_rotation",
        SendNewIsp => "send_new_isp",
        OfficeNatMistypes => "office_nat_mistypes",
        PhoneStalePassword => "phone_stale_password",
        MiaHeavyDesktop => "mia_heavy_desktop",
        PasswordSpray => "password_spray",
    }
}

/// A user selector: nobody, everybody, every actor/target of a storyline or look-alike
/// ("victims"), or an explicit list of user numbers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum UserSel {
    #[default]
    None,
    All,
    Victims,
    Users(Vec<u32>),
}

impl UserSel {
    pub fn contains(&self, user: u32, victims: &BTreeSet<u32>) -> bool {
        match self {
            UserSel::None => false,
            UserSel::All => true,
            UserSel::Victims => victims.contains(&user),
            UserSel::Users(users) => users.contains(&user),
        }
    }
}

impl Serialize for UserSel {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            UserSel::None => serializer.serialize_str("none"),
            UserSel::All => serializer.serialize_str("all"),
            UserSel::Victims => serializer.serialize_str("victims"),
            UserSel::Users(users) => users.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for UserSel {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Word(String),
            List(Vec<u32>),
        }
        match Repr::deserialize(deserializer)? {
            Repr::Word(w) => match w.as_str() {
                "none" => Ok(UserSel::None),
                "all" => Ok(UserSel::All),
                "victims" => Ok(UserSel::Victims),
                other => Err(serde::de::Error::custom(format!(
                    "unknown user selector '{other}'; expected none, all, victims or a list of user numbers"
                ))),
            },
            Repr::List(users) => Ok(UserSel::Users(users)),
        }
    }
}

impl Scenario {
    /// The end of the collection window: `window.start + window.days` (exclusive).
    pub fn window_end(&self) -> DateTime<Utc> {
        self.window.start + Duration::days(i64::from(self.window.days))
    }

    /// The resolved wall-clock time of the storyline or look-alike named `id`.
    pub fn story_time(&self, id: &str) -> Result<DateTime<Utc>> {
        let all: Vec<&StorySpec> = self
            .storylines
            .iter()
            .chain(self.lookalikes.iter())
            .collect();
        self.resolve_time(id, &all, 0)
    }

    fn resolve_time(&self, id: &str, all: &[&StorySpec], depth: usize) -> Result<DateTime<Utc>> {
        if depth > all.len() {
            return Err(Error::Scenario(format!(
                "after: cycle detected resolving '{id}'"
            )));
        }
        let s = all
            .iter()
            .find(|s| s.id == id)
            .copied()
            .ok_or_else(|| Error::Scenario(format!("after: names unknown id '{id}'")))?;
        match &s.at {
            At::Day { day, hour, minute } => Ok(self.window.start
                + Duration::days(i64::from(*day))
                + Duration::hours(i64::from(*hour))
                + Duration::minutes(i64::from(*minute))),
            At::After { after, minutes } => {
                let base = self.resolve_time(after, all, depth + 1)?;
                Ok(base + Duration::minutes(i64::from(*minutes)))
            }
        }
    }

    /// Every storyline and look-alike (positives and look-alikes together), in resolved time
    /// order (`after` chains resolved), ties broken by id.
    pub fn story_order(&self) -> Result<Vec<&StorySpec>> {
        let mut items: Vec<(DateTime<Utc>, &StorySpec)> = Vec::new();
        for s in self.storylines.iter().chain(self.lookalikes.iter()) {
            items.push((self.story_time(&s.id)?, s));
        }
        items.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.id.cmp(&b.1.id)));
        Ok(items.into_iter().map(|(_, s)| s).collect())
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(Error::Scenario("name: must not be empty".into()));
        }
        if self.tenant.domains.is_empty() {
            return Err(Error::Scenario("tenant.domains: must not be empty".into()));
        }
        for d in &self.tenant.domains {
            if !is_reserved_domain(d) {
                return Err(Error::Scenario(format!(
                    "tenant.domains: '{d}' is not a reserved domain"
                )));
            }
        }
        if !(2..=100_000).contains(&self.tenant.users) {
            return Err(Error::Scenario(format!(
                "tenant.users: {} must be in 2..=100000",
                self.tenant.users
            )));
        }
        if self.tenant.admins < 1 {
            return Err(Error::Scenario("tenant.admins: must be >= 1".into()));
        }
        licence_profile(&self.tenant.licence_profile)?;
        audit_profile(&self.tenant.audit_profile)?;

        if !(1..=180).contains(&self.window.days) {
            return Err(Error::Scenario(format!(
                "window.days: {} must be in 1..=180",
                self.window.days
            )));
        }
        let end = self.window_end();
        if self.window.collected_at < end {
            return Err(Error::Scenario(
                "window.collected_at: must be >= start + days".into(),
            ));
        }

        let b = &self.baseline;
        if b.signins_per_user_day < 0.0
            || b.ual_per_user_day < 0.0
            || b.messages_per_user_day < 0.0
            || b.weekend_factor < 0.0
        {
            return Err(Error::Scenario("baseline: rates must be >= 0".into()));
        }
        if !(b.work_hours.0 < b.work_hours.1 && b.work_hours.1 <= 24) {
            return Err(Error::Scenario(format!(
                "baseline.work_hours: {:?} must satisfy start < end <= 24",
                b.work_hours
            )));
        }

        let mut seen_ids = BTreeSet::new();
        for s in self.storylines.iter().chain(self.lookalikes.iter()) {
            if !seen_ids.insert(s.id.as_str()) {
                return Err(Error::Scenario(format!(
                    "id: duplicate storyline id '{}'",
                    s.id
                )));
            }
        }
        for s in &self.storylines {
            if s.kind.polarity() != Polarity::Positive {
                return Err(Error::Scenario(format!(
                    "storylines: '{}' kind {} is a look-alike, not a positive storyline",
                    s.id,
                    s.kind.as_str()
                )));
            }
        }
        for s in &self.lookalikes {
            if s.kind.polarity() != Polarity::Lookalike {
                return Err(Error::Scenario(format!(
                    "lookalikes: '{}' kind {} is a positive storyline, not a look-alike",
                    s.id,
                    s.kind.as_str()
                )));
            }
        }

        let known_ids: BTreeSet<&str> = self
            .storylines
            .iter()
            .chain(self.lookalikes.iter())
            .map(|s| s.id.as_str())
            .collect();

        for s in self.storylines.iter().chain(self.lookalikes.iter()) {
            if let Some(actor) = s.actor {
                if !(1..=self.tenant.users).contains(&actor) {
                    return Err(Error::Scenario(format!(
                        "actor: '{}' actor {actor} must be in 1..={}",
                        s.id, self.tenant.users
                    )));
                }
            }
            if let Some(target) = s.target {
                if !(1..=self.tenant.users).contains(&target) {
                    return Err(Error::Scenario(format!(
                        "target: '{}' target {target} must be in 1..={}",
                        s.id, self.tenant.users
                    )));
                }
            }
            match &s.at {
                At::Day { day, hour, minute } => {
                    if *day >= self.window.days {
                        return Err(Error::Scenario(format!(
                            "at.day: '{}' day {day} must be < {}",
                            s.id, self.window.days
                        )));
                    }
                    if *hour >= 24 {
                        return Err(Error::Scenario(format!(
                            "at.hour: '{}' hour {hour} must be < 24",
                            s.id
                        )));
                    }
                    if *minute >= 60 {
                        return Err(Error::Scenario(format!(
                            "at.minute: '{}' minute {minute} must be < 60",
                            s.id
                        )));
                    }
                }
                At::After { after, .. } => {
                    if !known_ids.contains(after.as_str()) {
                        return Err(Error::Scenario(format!(
                            "after: '{}' names unknown id '{after}'",
                            s.id
                        )));
                    }
                }
            }
        }

        for s in self.storylines.iter().chain(self.lookalikes.iter()) {
            let t = self.story_time(&s.id)?;
            if t >= end {
                return Err(Error::Scenario(format!(
                    "at: '{}' resolved time must be before start + days",
                    s.id
                )));
            }
        }

        for h in &self.tenant.hawk_users {
            if !(1..=self.tenant.users).contains(h) {
                return Err(Error::Scenario(format!(
                    "hawk_users: {h} must be in 1..={}",
                    self.tenant.users
                )));
            }
        }

        Ok(())
    }
}
