//! The tenant as it stands at the start of the collection window: identity, domains, licences,
//! audit settings, users with their home locations and devices, mailboxes, inbox rules, apps and
//! grants, roles, MFA registrations, Conditional Access policies, Entra devices, groups, mobile
//! devices, transport rules, remote domains, secure score controls and a few benign alerts.
//! Storylines (Tasks 6-7) change it; writers (Task 8+) render its final state as collected.
//! Every id is drawn from seeded streams; every value is reserved or synthetic.

use crate::Result;
use crate::baseline;
use crate::events::{Day, DirAudit, RecordType, RiskDetection, SignIn, TraceMsg, Ual};
use crate::names::people;
use crate::profiles::{AuditProfile, LicenceProfile, audit_profile, licence_profile};
use crate::reserved::{IpAllocator, Net, WELL_KNOWN_GUIDS};
use crate::rng::{Rng, stream};
use crate::scenario::Scenario;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::LazyLock;
use uuid::Uuid;

/// Small fixed lists people are drawn from (spec Addendum B.4: no value from a real capture).
const DEPARTMENTS: &[&str] = &[
    "Sales",
    "Finance",
    "Engineering",
    "Marketing",
    "Support",
    "Operations",
    "Human Resources",
    "Legal",
];

const JOB_TITLES: &[&str] = &[
    "Account Executive",
    "Financial Analyst",
    "Software Engineer",
    "Marketing Specialist",
    "Support Engineer",
    "Operations Coordinator",
    "HR Generalist",
    "Legal Counsel",
    "Project Manager",
    "Business Analyst",
];

/// The default mailbox audit "Owner" action list (Microsoft Learn audit-mailboxes).
const OWNER_ACTIONS: &[&str] = &[
    "ApplyRecord",
    "AttachmentAccess",
    "Create",
    "HardDelete",
    "MailItemsAccessed",
    "MoveToDeletedItems",
    "Send",
    "SoftDelete",
    "Update",
    "UpdateCalendarDelegation",
    "UpdateFolderPermissions",
    "UpdateInboxRules",
];

const NEWSLETTER_VENDOR_DOMAIN: &str = "newsdigest.example";

/// A vendor's own domain for the third-party app's reply URL host (spec: reserved domains only).
const MEETING_NOTES_REPLY_URL: &str = "https://app.meetingnotespro.example/oauth/callback";

/// The tenant and every state object as it stands at the start of the collection window.
#[derive(Debug, Clone)]
pub struct World {
    pub scenario: Scenario,
    pub seed: u64,
    pub tenant: Tenant,
    pub users: Vec<User>,
    pub admins: Vec<User>,
    pub mailboxes: BTreeMap<String, Mailbox>,
    pub inbox_rules: Vec<InboxRule>,
    pub sweep_rules: Vec<SweepRule>,
    pub apps: Vec<App>,
    pub grants: Vec<Grant>,
    pub roles: Vec<RoleAssignment>,
    pub mfa: BTreeMap<String, MfaRegistration>,
    pub ca_policies: Vec<CaPolicy>,
    pub devices: Vec<Device>,
    pub groups: Vec<Group>,
    pub mobile_devices: Vec<MobileDevice>,
    pub transport_rules: Vec<TransportRule>,
    pub remote_domains: Vec<RemoteDomain>,
    pub secure_score: Vec<SecureScoreControl>,
    pub alerts: Vec<Alert>,
    pub risky_users: BTreeMap<String, RiskyUser>,
    pub mailbox_permissions: Vec<MailboxPermission>,
    pub emails: Vec<Email>,
    pub story: StoryEvents,
    pub audit: AuditState,
    pub licence: &'static LicenceProfile,
    pub audit_profile: &'static AuditProfile,
    pub attacker: Attacker,
    pub victims: BTreeSet<u32>,
}

impl World {
    /// Builds the tenant world for `scenario` under `seed`. Deterministic: two builds with the
    /// same scenario and seed produce identical `Debug` output.
    pub fn build(scenario: &Scenario, seed: u64) -> Result<World> {
        let licence = licence_profile(&scenario.tenant.licence_profile)?;
        let audit = audit_profile(&scenario.tenant.audit_profile)?;

        let tenant = build_tenant(scenario, seed);
        let (users, admins) = build_people(scenario, seed, &tenant, licence);
        let victims = compute_victims(scenario);
        let mailboxes = build_mailboxes(scenario, seed, &tenant, &users, &admins, audit, &victims);
        let (inbox_rules, sweep_rules) = build_rules(seed, &users);
        let (apps, grants) = build_apps(scenario, seed, &tenant, &users, &admins);
        let roles = build_roles(scenario, &users, &admins);
        let mfa = build_mfa(&users, &admins);
        let ca_policies = build_ca(seed, &tenant);
        let devices = build_devices(scenario, seed, &users);
        let groups = build_groups(seed, &tenant, &users);
        let mobile_devices = build_mobile_devices(scenario, seed, &users);
        let transport_rules = build_transport_rules(scenario, seed, &admins);
        let remote_domains = build_remote_domains(&tenant);
        let secure_score = build_secure_score();
        let alerts = build_alerts(scenario, seed, &users);
        let audit_state = build_audit(audit, licence);
        let mailbox_permissions = build_mailbox_permissions(scenario, &tenant, &users, &admins);
        let attacker = build_attacker(&tenant);

        Ok(World {
            scenario: scenario.clone(),
            seed,
            tenant,
            users,
            admins,
            mailboxes,
            inbox_rules,
            sweep_rules,
            apps,
            grants,
            roles,
            mfa,
            ca_policies,
            devices,
            groups,
            mobile_devices,
            transport_rules,
            remote_domains,
            secure_score,
            alerts,
            risky_users: BTreeMap::new(),
            mailbox_permissions,
            emails: Vec::new(),
            story: StoryEvents::default(),
            audit: audit_state,
            licence,
            audit_profile: audit,
            attacker,
            victims,
        })
    }

    /// The `n`-th ordinary user (1-based).
    pub fn user(&self, n: u32) -> &User {
        &self.users[(n - 1) as usize]
    }

    pub fn user_by_upn(&self, upn: &str) -> Option<&User> {
        self.all_people().find(|u| u.upn == upn)
    }

    /// Every person in the tenant: ordinary users, then admins.
    pub fn all_people(&self) -> impl Iterator<Item = &User> {
        self.users.iter().chain(self.admins.iter())
    }

    pub fn window_start(&self) -> DateTime<Utc> {
        self.scenario.window.start
    }

    pub fn window_end(&self) -> DateTime<Utc> {
        self.scenario.window_end()
    }

    pub fn collected_at(&self) -> DateTime<Utc> {
        self.scenario.window.collected_at
    }

    pub fn org_id(&self) -> Uuid {
        self.tenant.tenant_id
    }

    pub fn primary_domain(&self) -> &str {
        &self.tenant.domains[0]
    }

    /// The events of UTC day `date`: the baseline and the storylines' events of that date,
    /// UAL records filtered by `logged`, each vector sorted by `(time, id)`.
    pub fn day(&self, date: NaiveDate) -> Day {
        let mut d = baseline::day(self, date);
        d.ual.retain(|u| self.logged(u));
        d.ual.extend(
            self.story
                .ual
                .iter()
                .filter(|u| u.time.date_naive() == date && self.logged(u))
                .cloned(),
        );
        d.signins.extend(
            self.story
                .signins
                .iter()
                .filter(|s| s.time.date_naive() == date)
                .cloned(),
        );
        d.trace.extend(
            self.story
                .trace
                .iter()
                .filter(|t| t.received.date_naive() == date)
                .cloned(),
        );
        d.ual.sort_by_key(|u| (u.time, u.id));
        d.signins.sort_by_key(|s| (s.time, s.id));
        d.trace.sort_by_key(|t| (t.received, t.trace_id));
        d
    }

    /// Every directory audit of the window: the baseline's and the storylines', sorted by
    /// `(time, id)`.
    pub fn directory_audits(&self) -> Vec<DirAudit> {
        let mut v = baseline::directory_audits(self);
        v.extend(self.story.audits.iter().cloned());
        v.sort_by(|a, b| (a.time, &a.id).cmp(&(b.time, &b.id)));
        v
    }

    /// Every Identity Protection risk detection: the baseline's and the storylines', sorted by
    /// `(detected, id)`. The world holds them regardless of licence; writers expose them only
    /// with Entra ID P2.
    pub fn risk_detections(&self) -> Vec<RiskDetection> {
        let mut v = baseline::risk(self).0;
        v.extend(self.story.risk.iter().cloned());
        v.sort_by(|a, b| (a.detected, &a.id).cmp(&(b.detected, &b.id)));
        v
    }

    /// Every Identity Protection risky user, by UPN: the baseline's, overridden per user by the
    /// storylines' (`world.risky_users`). Like the detections, exposed only with Entra ID P2.
    pub fn risky_users(&self) -> BTreeMap<String, RiskyUser> {
        let mut m: BTreeMap<String, RiskyUser> = baseline::risk(self)
            .1
            .into_iter()
            .map(|r| (r.upn.clone(), r))
            .collect();
        m.extend(self.risky_users.iter().map(|(k, v)| (k.clone(), v.clone())));
        m
    }

    /// Whether Microsoft 365 recorded UAL record `u` under the tenant's audit settings at its
    /// time: never while UAL ingestion is off; mailbox-audit records (ExchangeItem,
    /// ExchangeItemGroup, ExchangeItemAggregated, and the Send / SendAs / SendOnBehalf /
    /// SearchQueryInitiatedExchange / SearchQueryInitiatedSharePoint operations) also need
    /// organization auditing on, the mailbox audited and not bypassed, and the action in its
    /// logon type's list (SharePoint searches are the owner action
    /// `SharepointSearchQueryInitiated`, Microsoft Learn audit-get-started step 3).
    pub fn logged(&self, u: &Ual) -> bool {
        if !baseline::ual_logged(self, u.time) {
            return false;
        }
        let mailbox_record = matches!(
            u.record_type,
            RecordType::ExchangeItem
                | RecordType::ExchangeItemGroup
                | RecordType::ExchangeItemAggregated
        ) || matches!(
            u.operation.as_str(),
            "Send"
                | "SendAs"
                | "SendOnBehalf"
                | "SearchQueryInitiatedExchange"
                | "SearchQueryInitiatedSharePoint"
        );
        if !mailbox_record {
            return true;
        }
        let owner = u
            .audit
            .get("MailboxOwnerUPN")
            .and_then(Value::as_str)
            .unwrap_or(&u.user_id);
        let logon_type = u
            .audit
            .get("LogonType")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let action = match u.operation.as_str() {
            "SearchQueryInitiatedExchange" => "SearchQueryInitiated",
            "SearchQueryInitiatedSharePoint" => "SharepointSearchQueryInitiated",
            op => op,
        };
        baseline::mailbox_logged(self, owner, logon_type, action, u.time)
    }
}

#[derive(Debug, Clone)]
pub struct Tenant {
    pub name: String,
    /// `name` with spaces replaced by `_`.
    pub folder_name: String,
    pub tenant_id: Uuid,
    pub domains: Vec<String>,
    /// `<first label of the primary domain>.onmicrosoft.example`.
    pub initial_domain: String,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct User {
    /// 1.. for ordinary users, 0 for admins.
    pub n: u32,
    pub is_admin: bool,
    pub upn: String,
    pub alias: String,
    pub first: String,
    pub last: String,
    pub display_name: String,
    pub object_id: Uuid,
    pub puid: String,
    pub sid: String,
    pub mailbox_guid: Uuid,
    pub department: String,
    pub job_title: String,
    pub created: DateTime<Utc>,
    pub last_password_change: DateTime<Utc>,
    pub home: Location,
    pub office_ip: IpAddr,
    pub home_ip: IpAddr,
    pub client: Client,
    pub licences: Vec<String>,
    pub on_prem_sync: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Location {
    pub city: String,
    pub state: String,
    pub country_iso: String,
    pub country: String,
    pub lat: f64,
    pub lon: f64,
    pub asn: u32,
    pub asn_org: String,
}

#[derive(Debug, Clone)]
pub struct Client {
    pub os: String,
    pub browser: String,
    pub user_agent: String,
    pub device_id: Uuid,
    pub device_name: String,
}

#[derive(Debug, Clone)]
pub struct Mailbox {
    pub upn: String,
    pub display_name: String,
    pub primary_smtp: String,
    pub guid: Uuid,
    /// `UserMailbox` | `SharedMailbox` | `DiscoveryMailbox`.
    pub recipient_type: String,
    pub forwarding_smtp: Option<String>,
    pub forwarding_address: Option<String>,
    pub deliver_and_forward: bool,
    pub audit_enabled: bool,
    pub audit_owner: Vec<String>,
    pub audit_delegate: Vec<String>,
    pub audit_admin: Vec<String>,
    pub default_audit_set: Vec<String>,
    pub bypass: bool,
    pub auto_reply: AutoReply,
    pub when_changed: DateTime<Utc>,
    pub pop: bool,
    pub imap: bool,
    pub ews: bool,
    pub owa: bool,
    pub activesync: bool,
    pub mapi: bool,
    /// Set by `audit_tamper` (Task 7); a mailbox bypassed by the audit profile has this at
    /// window start minus one day.
    pub bypass_since: Option<DateTime<Utc>>,
    /// Set by `audit_tamper` (Task 7).
    pub audit_disabled_since: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct AutoReply {
    /// `Disabled` | `Enabled` | `Scheduled`.
    pub state: String,
    pub internal: String,
    pub external: String,
    pub audience: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct InboxRule {
    pub mailbox: String,
    pub name: String,
    pub identity: u64,
    pub priority: u32,
    pub enabled: bool,
    pub from: Vec<String>,
    pub subject_contains: Vec<String>,
    pub body_contains: Vec<String>,
    pub subject_or_body_contains: Vec<String>,
    pub has_attachment: bool,
    pub move_to_folder: Option<String>,
    pub copy_to_folder: Option<String>,
    pub delete_message: bool,
    pub soft_delete: bool,
    pub forward_to: Vec<String>,
    pub forward_as_attachment_to: Vec<String>,
    pub redirect_to: Vec<String>,
    pub mark_as_read: bool,
    pub stop_processing: bool,
    pub created: DateTime<Utc>,
    pub graph_id: String,
}

impl InboxRule {
    /// EXO's multi-line `Get-InboxRule` description text.
    pub fn description(&self) -> String {
        let mut conditions = Vec::new();
        if !self.from.is_empty() {
            conditions.push(format!("From '{}'", self.from.join("' or '")));
        }
        for s in &self.subject_contains {
            conditions.push(format!("Subject contains '{s}'"));
        }
        for s in &self.body_contains {
            conditions.push(format!("Includes '{s}' in the body"));
        }
        for s in &self.subject_or_body_contains {
            conditions.push(format!("Subject or body includes '{s}'"));
        }
        if self.has_attachment {
            conditions.push("Has an attachment".to_string());
        }

        let mut actions = Vec::new();
        if let Some(folder) = &self.move_to_folder {
            actions.push(format!("Move the message to folder \"{folder}\""));
        }
        if let Some(folder) = &self.copy_to_folder {
            actions.push(format!("Copy the message to folder \"{folder}\""));
        }
        if self.delete_message {
            actions.push("Delete the message".to_string());
        }
        if self.soft_delete {
            actions.push("Move the message to Deleted Items".to_string());
        }
        for a in &self.forward_to {
            actions.push(format!("Forward the message to {a}"));
        }
        for a in &self.forward_as_attachment_to {
            actions.push(format!("Forward the message as an attachment to {a}"));
        }
        for a in &self.redirect_to {
            actions.push(format!("Redirect the message to {a}"));
        }
        if self.mark_as_read {
            actions.push("Mark the message as read".to_string());
        }
        if self.stop_processing {
            actions.push("Stop processing more rules".to_string());
        }

        format!(
            "If the message:\r\n\t{}\r\nTake the following actions:\r\n\t{}\r\n",
            conditions.join("\r\n\t"),
            actions.join("\r\n\t"),
        )
    }
}

#[derive(Debug, Clone)]
pub struct SweepRule {
    pub mailbox: String,
    pub name: String,
    pub identity: String,
    pub enabled: bool,
    pub source_folder: String,
    pub destination_folder: String,
    pub keep_latest: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredKind {
    Password,
    Certificate,
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub key_id: Uuid,
    pub kind: CredKind,
    pub display_name: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub on_service_principal: bool,
    pub added_by: Option<String>,
    pub added: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct App {
    pub app_id: Uuid,
    pub object_id: Uuid,
    pub sp_object_id: Uuid,
    pub display_name: String,
    pub publisher: String,
    pub verified_publisher: Option<String>,
    pub owner_tenant: Uuid,
    pub sign_in_audience: String,
    pub reply_urls: Vec<String>,
    pub created: DateTime<Utc>,
    pub first_party: bool,
    pub tags: Vec<String>,
    pub credentials: Vec<Credential>,
    pub owners: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantKind {
    Delegated,
    Application,
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub kind: GrantKind,
    pub client_app_id: Uuid,
    pub resource_app_id: Uuid,
    pub scope: String,
    /// `AllPrincipals` | `Principal`.
    pub consent_type: String,
    pub principal: Option<String>,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RoleAssignment {
    pub role: String,
    pub principal: String,
    /// `Permanent` | `PIM Active` | `PIM Eligible`.
    pub kind: String,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct MfaRegistration {
    pub methods: Vec<String>,
    pub default_method: Option<String>,
    pub is_admin: bool,
    pub is_mfa_registered: bool,
    pub is_mfa_capable: bool,
    pub is_sspr_registered: bool,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CaPolicy {
    pub id: Uuid,
    pub display_name: String,
    pub state: String,
    pub created: DateTime<Utc>,
    pub modified: Option<DateTime<Utc>>,
    pub include_users: Vec<String>,
    pub include_roles: Vec<String>,
    pub exclude_users: Vec<String>,
    pub include_apps: Vec<String>,
    pub client_app_types: Vec<String>,
    pub built_in_controls: Vec<String>,
    pub grant_operator: Option<String>,
    pub sign_in_risk_levels: Vec<String>,
    pub user_risk_levels: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub device_id: Uuid,
    pub object_id: Uuid,
    pub display_name: String,
    pub os: String,
    pub os_version: String,
    pub trust_type: String,
    pub is_compliant: Option<bool>,
    pub is_managed: Option<bool>,
    pub enabled: bool,
    pub registered: DateTime<Utc>,
    pub last_signin: DateTime<Utc>,
    pub owner: String,
    pub manufacturer: String,
    pub model: String,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub id: Uuid,
    pub display_name: String,
    pub mail: Option<String>,
    pub mail_enabled: bool,
    pub security_enabled: bool,
    pub group_types: Vec<String>,
    pub membership_rule: Option<String>,
    pub created: DateTime<Utc>,
    pub visibility: Option<String>,
    pub members: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MobileDevice {
    pub mailbox: String,
    /// EAS id, 32 upper-case hex.
    pub device_id: String,
    pub friendly_name: String,
    pub device_type: String,
    pub model: String,
    pub os: String,
    pub user_agent: String,
    pub client_type: String,
    pub first_sync: DateTime<Utc>,
    pub last_sync: DateTime<Utc>,
    pub access_state: String,
    pub access_reason: String,
    pub when_created: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct TransportRule {
    pub name: String,
    pub guid: Uuid,
    pub state: String,
    pub mode: String,
    pub priority: u32,
    pub created_by: String,
    pub when_changed: DateTime<Utc>,
    pub description: String,
    pub blind_copy_to: Vec<String>,
    pub redirect_to: Vec<String>,
    pub copy_to: Vec<String>,
    pub add_to_recipients: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RemoteDomain {
    pub name: String,
    pub domain: String,
    pub auto_forward_enabled: bool,
    pub allowed_ooo_type: String,
    pub when_changed: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SecureScoreControl {
    pub id: String,
    pub category: String,
    pub title: String,
    pub service: String,
    pub current: f64,
    pub max: f64,
    pub state: String,
    pub action_type: String,
    pub tier: String,
    pub rank: u32,
    pub threats: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub id: String,
    pub title: String,
    pub category: String,
    pub severity: String,
    pub status: String,
    pub created: DateTime<Utc>,
    pub event: DateTime<Utc>,
    pub affected_user: Option<String>,
    pub ip: Option<IpAddr>,
    pub provider: String,
}

#[derive(Debug, Clone)]
pub struct MailboxPermission {
    pub mailbox: String,
    pub grantee: String,
    /// `full_access` | `send_as` | `send_on_behalf` | `folder`.
    pub right: String,
    pub folder: Option<String>,
    pub access_rights: Vec<String>,
    pub deny: bool,
    pub inheritance: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Email {
    pub message_id: String,
    pub subject: String,
    pub from_display: String,
    pub from: String,
    pub return_path: String,
    pub to: Vec<String>,
    pub date: DateTime<Utc>,
    /// `Received:` header values, newest first.
    pub received: Vec<String>,
    pub auth_results: String,
    /// `Anonymous` | `Internal`.
    pub auth_as: String,
    /// `04` | `06`.
    pub auth_mechanism: String,
    pub body: String,
    pub attachment: Option<(String, Vec<u8>)>,
}

/// Events the storylines add on top of the baseline (empty after `World::build`; `story::apply` fills
/// them).
#[derive(Debug, Clone, Default)]
pub struct StoryEvents {
    pub ual: Vec<Ual>,
    pub signins: Vec<SignIn>,
    pub audits: Vec<DirAudit>,
    pub trace: Vec<TraceMsg>,
    pub risk: Vec<RiskDetection>,
}

#[derive(Debug, Clone)]
pub struct RiskyUser {
    pub upn: String,
    pub user_id: Uuid,
    pub display_name: String,
    pub level: String,
    pub state: String,
    pub detail: String,
    pub updated: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AuditState {
    pub ual_ingestion_enabled: bool,
    pub org_audit_disabled: bool,
    pub admin_audit_log_enabled: bool,
    pub admin_audit_log_age_limit: String,
    pub log_level: String,
    pub security_defaults_enabled: bool,
    pub ual_disabled_at: Option<DateTime<Utc>>,
    pub org_audit_disabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct Attacker {
    pub proxy_ip: IpAddr,
    pub replay_ip: IpAddr,
    pub send_ip: IpAddr,
    pub mailbox_ip: IpAddr,
    pub location: Location,
    pub replay_location: Location,
    pub external_domain: String,
    pub forward_address: String,
    pub lure_domain: String,
    pub user_agent_scripted: String,
    pub user_agent_axios: String,
}

#[allow(clippy::too_many_arguments)]
fn loc(
    city: &str,
    state: &str,
    country_iso: &str,
    country: &str,
    lat: f64,
    lon: f64,
    asn: u32,
    asn_org: &str,
) -> Location {
    Location {
        city: city.to_string(),
        state: state.to_string(),
        country_iso: country_iso.to_string(),
        country: country.to_string(),
        lat,
        lon,
        asn,
        asn_org: asn_org.to_string(),
    }
}

/// At least 12 synthetic cities, each with a benign documentation-ISP ASN (RFC 5398,
/// 64496..=64511). Users spread over the first 6; the last two are reserved for attacker
/// infrastructure and never a user home.
pub static LOCATIONS: LazyLock<Vec<Location>> = LazyLock::new(|| {
    vec![
        loc(
            "Northbridge",
            "NB",
            "US",
            "United States",
            41.5,
            -87.6,
            64496,
            "Documentation ISP 1",
        ),
        loc(
            "Easthaven",
            "EH",
            "GB",
            "United Kingdom",
            51.5,
            -0.1,
            64497,
            "Documentation ISP 2",
        ),
        loc(
            "Westmoor",
            "WM",
            "DE",
            "Germany",
            52.5,
            13.4,
            64498,
            "Documentation ISP 3",
        ),
        loc(
            "Port Sable",
            "PS",
            "AU",
            "Australia",
            -33.9,
            151.2,
            64499,
            "Documentation ISP 4",
        ),
        loc(
            "Kitaura",
            "KT",
            "JP",
            "Japan",
            35.7,
            139.7,
            64500,
            "Documentation ISP 5",
        ),
        loc(
            "Lindholm",
            "LH",
            "SE",
            "Sweden",
            59.3,
            18.1,
            64501,
            "Documentation ISP 6",
        ),
        loc(
            "Rivermouth",
            "RM",
            "CA",
            "Canada",
            45.4,
            -75.7,
            64502,
            "Documentation ISP 7",
        ),
        loc(
            "Suncrest",
            "SC",
            "BR",
            "Brazil",
            -23.5,
            -46.6,
            64503,
            "Documentation ISP 8",
        ),
        loc(
            "New Aldergate",
            "NA",
            "IN",
            "India",
            28.6,
            77.2,
            64504,
            "Documentation ISP 9",
        ),
        loc(
            "Fortuna Vale",
            "FV",
            "MX",
            "Mexico",
            19.4,
            -99.1,
            64505,
            "Documentation ISP 10",
        ),
        loc(
            "Sablewood",
            "SW",
            "ZA",
            "South Africa",
            -26.2,
            28.0,
            64506,
            "Documentation ISP 11",
        ),
        loc(
            "Hollow Pine",
            "HP",
            "FR",
            "France",
            48.9,
            2.4,
            64507,
            "Documentation ISP 12",
        ),
    ]
});

/// Entries of `rules/lists/hosting_asns.yaml`, so Sparrow's `is_hosting` fires.
pub const HOSTING_ASNS: &[(u32, &str)] = &[
    (14061, "DigitalOcean"),
    (20473, "Vultr (The Constant Company)"),
    (24940, "Hetzner Online"),
];

/// Deliberately absent from the hosting list.
pub const MICROSOFT_ASN: (u32, &str) = (8075, "Microsoft Corporation");

fn well_known(desc: &str) -> Uuid {
    WELL_KNOWN_GUIDS
        .iter()
        .find(|(_, d)| *d == desc)
        .unwrap_or_else(|| panic!("world: unknown well-known app '{desc}'"))
        .0
        .parse()
        .expect("well-known guid parses")
}

/// The actor/target user numbers of every storyline and look-alike (actor defaults to 1 when
/// unset).
fn compute_victims(scenario: &Scenario) -> BTreeSet<u32> {
    let mut victims = BTreeSet::new();
    for s in scenario.storylines.iter().chain(scenario.lookalikes.iter()) {
        victims.insert(s.actor.unwrap_or(1));
        if let Some(target) = s.target {
            victims.insert(target);
        }
    }
    victims
}

fn build_tenant(scenario: &Scenario, seed: u64) -> Tenant {
    let mut rng = stream(seed, "tenant");
    let tenant_id = rng.uuid();
    let domains = scenario.tenant.domains.clone();
    let primary = &domains[0];
    let first_label = primary.split('.').next().unwrap_or(primary);
    let initial_domain = format!("{first_label}.onmicrosoft.example");
    let created = scenario.window.start - Duration::days(400);
    let folder_name = scenario.tenant.name.replace(' ', "_");
    Tenant {
        name: scenario.tenant.name.clone(),
        folder_name,
        tenant_id,
        domains,
        initial_domain,
        created,
    }
}

fn pick_role(rng: &mut Rng) -> (String, String) {
    (
        rng.pick(DEPARTMENTS).to_string(),
        rng.pick(JOB_TITLES).to_string(),
    )
}

fn build_client(rng: &mut Rng, alias: &str) -> Client {
    let upper = alias.to_ascii_uppercase();
    match rng.below(4) {
        0 => Client {
            os: "Windows 11".to_string(),
            browser: "Chrome".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
                .to_string(),
            device_id: rng.uuid(),
            device_name: format!("{upper}-LAPTOP"),
        },
        1 => Client {
            os: "Windows 11".to_string(),
            browser: "Edge".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0"
                .to_string(),
            device_id: rng.uuid(),
            device_name: format!("{upper}-LAPTOP"),
        },
        2 => Client {
            os: "macOS".to_string(),
            browser: "Safari".to_string(),
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
                         (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
                .to_string(),
            device_id: rng.uuid(),
            device_name: format!("{upper}-MACBOOK"),
        },
        _ => Client {
            os: "iOS".to_string(),
            browser: "Outlook Mobile".to_string(),
            user_agent: "Outlook-iOS/709.2308.0".to_string(),
            device_id: rng.uuid(),
            device_name: format!("{upper}-IPHONE"),
        },
    }
}

fn licences_for(licence: &LicenceProfile, n: u32) -> Vec<String> {
    licence
        .skus
        .iter()
        .filter(|s| s.units > 0 && n <= s.units)
        .map(|s| s.sku.clone())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn build_people(
    scenario: &Scenario,
    seed: u64,
    tenant: &Tenant,
    licence: &LicenceProfile,
) -> (Vec<User>, Vec<User>) {
    let users_n = scenario.tenant.users;
    let admins_n = scenario.tenant.admins;
    let mut rng = stream(seed, "people");
    let drawn = people(&mut rng, (users_n + admins_n) as usize);
    let primary = tenant.domains[0].clone();

    // A shared domain-SID prefix for the tenant; only the final RID varies per person, as in a
    // real AD/Entra domain.
    let sid_prefix = format!(
        "S-1-5-21-{}-{}-{}",
        rng.digits(9),
        rng.digits(10),
        rng.digits(10)
    );

    let mut ip_alloc = IpAllocator::new();
    let locations = &*LOCATIONS;

    let mut users = Vec::with_capacity(users_n as usize);
    for i in 0..users_n {
        let person = &drawn[i as usize];
        let n = i + 1;
        let (department, job_title) = pick_role(&mut rng);
        let client = build_client(&mut rng, &person.alias);
        let office_ip = IpAddr::V4(ip_alloc.v4(Net::Office));
        let home_ip = IpAddr::V4(ip_alloc.v4(Net::Office));
        let created = tenant.created + Duration::days(i64::from(n));
        users.push(User {
            n,
            is_admin: false,
            upn: format!("{}@{primary}", person.alias),
            alias: person.alias.clone(),
            first: person.first.clone(),
            last: person.last.clone(),
            display_name: format!("{} {}", person.first, person.last),
            object_id: rng.uuid(),
            puid: format!("10032000{}", rng.hex(8).to_ascii_uppercase()),
            sid: format!("{sid_prefix}-{}", rng.digits(4)),
            mailbox_guid: rng.uuid(),
            department,
            job_title,
            created,
            last_password_change: created + Duration::days(30),
            home: locations[(i as usize) % 6].clone(),
            office_ip,
            home_ip,
            client,
            licences: licences_for(licence, n),
            on_prem_sync: false,
        });
    }

    let mut admins = Vec::with_capacity(admins_n as usize);
    let first_sku: Vec<String> = licence
        .skus
        .first()
        .map(|s| vec![s.sku.clone()])
        .unwrap_or_default();
    for j in 0..admins_n {
        let person = &drawn[(users_n + j) as usize];
        let alias = if j == 0 {
            "admin".to_string()
        } else {
            format!("admin{}", j + 1)
        };
        let client = build_client(&mut rng, &alias);
        let office_ip = IpAddr::V4(ip_alloc.v4(Net::Office));
        let home_ip = IpAddr::V4(ip_alloc.v4(Net::Office));
        let created = tenant.created + Duration::days(1);
        admins.push(User {
            n: 0,
            is_admin: true,
            upn: format!("{alias}@{primary}"),
            alias,
            first: person.first.clone(),
            last: person.last.clone(),
            display_name: format!("{} {}", person.first, person.last),
            object_id: rng.uuid(),
            puid: format!("10032000{}", rng.hex(8).to_ascii_uppercase()),
            sid: format!("{sid_prefix}-{}", rng.digits(4)),
            mailbox_guid: rng.uuid(),
            department: "IT".to_string(),
            job_title: "Global Administrator".to_string(),
            created,
            last_password_change: created + Duration::days(30),
            home: locations[0].clone(),
            office_ip,
            home_ip,
            client,
            licences: first_sku.clone(),
            on_prem_sync: false,
        });
    }

    (users, admins)
}

fn delegate_actions() -> Vec<&'static str> {
    let mut v: Vec<&str> = OWNER_ACTIONS
        .iter()
        .copied()
        .filter(|a| *a != "Send" && *a != "UpdateCalendarDelegation")
        .collect();
    v.push("SendAs");
    v.push("SendOnBehalf");
    v
}

fn admin_actions() -> Vec<&'static str> {
    let delegate = delegate_actions();
    let mut v: Vec<&str> = OWNER_ACTIONS.to_vec();
    for d in delegate {
        if !v.contains(&d) {
            v.push(d);
        }
    }
    v
}

fn owner_actions_for(customized: bool, search_query: bool) -> Vec<String> {
    let mut v: Vec<String> = OWNER_ACTIONS.iter().map(|s| s.to_string()).collect();
    if customized {
        v.retain(|a| a != "MailItemsAccessed" && a != "Send" && a != "AttachmentAccess");
    } else {
        // SharePoint search auditing is on by default (Microsoft Learn audit-get-started,
        // step 3); a list customized before on-by-default auditing lacks it.
        v.push("SharepointSearchQueryInitiated".to_string());
    }
    if search_query {
        v.push("SearchQueryInitiated".to_string());
    }
    v
}

fn disabled_auto_reply(window_start: DateTime<Utc>) -> AutoReply {
    AutoReply {
        state: "Disabled".to_string(),
        internal: String::new(),
        external: String::new(),
        audience: "None".to_string(),
        start: window_start,
        end: window_start,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_mailboxes(
    scenario: &Scenario,
    seed: u64,
    tenant: &Tenant,
    users: &[User],
    admins: &[User],
    audit: &AuditProfile,
    victims: &BTreeSet<u32>,
) -> BTreeMap<String, Mailbox> {
    let mut rng = stream(seed, "mailboxes");
    let mut map = BTreeMap::new();
    let delegate: Vec<String> = delegate_actions().into_iter().map(String::from).collect();
    let admin_list: Vec<String> = admin_actions().into_iter().map(String::from).collect();

    for user in users.iter().chain(admins.iter()) {
        let customized = audit.customized_owner.contains(user.n, victims);
        let search_query = audit.search_query_owner.contains(user.n, victims);
        let bypass = audit.bypass.contains(user.n, victims);
        let default_audit_set = if customized {
            vec!["Admin".to_string(), "Delegate".to_string()]
        } else {
            vec![
                "Admin".to_string(),
                "Delegate".to_string(),
                "Owner".to_string(),
            ]
        };
        let mailbox = Mailbox {
            upn: user.upn.clone(),
            display_name: user.display_name.clone(),
            primary_smtp: user.upn.clone(),
            guid: user.mailbox_guid,
            recipient_type: "UserMailbox".to_string(),
            forwarding_smtp: None,
            forwarding_address: None,
            deliver_and_forward: false,
            audit_enabled: true,
            audit_owner: owner_actions_for(customized, search_query),
            audit_delegate: delegate.clone(),
            audit_admin: admin_list.clone(),
            default_audit_set,
            bypass,
            auto_reply: disabled_auto_reply(scenario.window.start),
            when_changed: user.created,
            pop: true,
            imap: true,
            ews: true,
            owa: true,
            activesync: true,
            mapi: true,
            bypass_since: bypass.then_some(scenario.window.start - Duration::days(1)),
            audit_disabled_since: None,
        };
        map.insert(user.upn.clone(), mailbox);
    }

    let primary = &tenant.domains[0];
    let discovery_upn =
        format!("DiscoverySearchMailbox{{D919BA05-46A6-415f-80AD-7E09334BB852}}@{primary}");
    map.insert(
        discovery_upn.clone(),
        Mailbox {
            upn: discovery_upn.clone(),
            display_name: "Discovery Search Mailbox".to_string(),
            primary_smtp: discovery_upn,
            guid: rng.uuid(),
            recipient_type: "DiscoveryMailbox".to_string(),
            forwarding_smtp: None,
            forwarding_address: None,
            deliver_and_forward: false,
            audit_enabled: false,
            audit_owner: Vec::new(),
            audit_delegate: Vec::new(),
            audit_admin: Vec::new(),
            default_audit_set: Vec::new(),
            bypass: false,
            auto_reply: disabled_auto_reply(scenario.window.start),
            when_changed: tenant.created,
            pop: false,
            imap: false,
            ews: false,
            owa: false,
            activesync: false,
            mapi: false,
            bypass_since: None,
            audit_disabled_since: None,
        },
    );

    let ap_upn = format!("accounts-payable@{primary}");
    map.insert(
        ap_upn.clone(),
        Mailbox {
            upn: ap_upn.clone(),
            display_name: "Accounts Payable".to_string(),
            primary_smtp: ap_upn,
            guid: rng.uuid(),
            recipient_type: "SharedMailbox".to_string(),
            forwarding_smtp: None,
            forwarding_address: None,
            deliver_and_forward: false,
            audit_enabled: true,
            audit_owner: owner_actions_for(false, false),
            audit_delegate: delegate,
            audit_admin: admin_list,
            default_audit_set: vec![
                "Admin".to_string(),
                "Delegate".to_string(),
                "Owner".to_string(),
            ],
            bypass: false,
            auto_reply: disabled_auto_reply(scenario.window.start),
            when_changed: tenant.created,
            pop: false,
            imap: false,
            ews: true,
            owa: true,
            activesync: false,
            mapi: true,
            bypass_since: None,
            audit_disabled_since: None,
        },
    );

    map
}

fn graph_opaque_id(rng: &mut Rng) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut s = String::from("AAMk");
    for _ in 0..40 {
        s.push(ALPHABET[rng.below(ALPHABET.len() as u64) as usize] as char);
    }
    s.push_str("==");
    s
}

fn build_rules(seed: u64, users: &[User]) -> (Vec<InboxRule>, Vec<SweepRule>) {
    let mut rng = stream(seed, "rules");
    let mut inbox_rules = Vec::new();
    let mut sweep_rules = Vec::new();
    let mut identity = 0u64;

    for user in users {
        if user.n % 3 == 0 {
            identity += 1;
            inbox_rules.push(InboxRule {
                mailbox: user.upn.clone(),
                name: "Newsletters".to_string(),
                identity,
                priority: 0,
                enabled: true,
                from: vec![format!("news@{NEWSLETTER_VENDOR_DOMAIN}")],
                subject_contains: Vec::new(),
                body_contains: Vec::new(),
                subject_or_body_contains: Vec::new(),
                has_attachment: false,
                move_to_folder: Some("Newsletters".to_string()),
                copy_to_folder: None,
                delete_message: false,
                soft_delete: false,
                forward_to: Vec::new(),
                forward_as_attachment_to: Vec::new(),
                redirect_to: Vec::new(),
                mark_as_read: false,
                stop_processing: true,
                created: user.created + Duration::days(2),
                graph_id: graph_opaque_id(&mut rng),
            });
        }
        if user.n == 2 {
            sweep_rules.push(SweepRule {
                mailbox: user.upn.clone(),
                name: "Sweep - Newsletters to Archive".to_string(),
                identity: rng.uuid().to_string(),
                enabled: true,
                source_folder: "Inbox".to_string(),
                destination_folder: "Archive".to_string(),
                keep_latest: 10,
            });
        }
    }

    (inbox_rules, sweep_rules)
}

fn first_party_app(rng: &mut Rng, tenant: &Tenant, ms_tenant: Uuid, name: &str) -> App {
    App {
        app_id: well_known(name),
        object_id: rng.uuid(),
        sp_object_id: rng.uuid(),
        display_name: name.to_string(),
        publisher: "Microsoft Corporation".to_string(),
        verified_publisher: Some("Microsoft Corporation".to_string()),
        owner_tenant: ms_tenant,
        sign_in_audience: "AzureADMultipleOrgs".to_string(),
        reply_urls: Vec::new(),
        created: tenant.created,
        first_party: true,
        tags: Vec::new(),
        credentials: Vec::new(),
        owners: Vec::new(),
    }
}

fn build_apps(
    scenario: &Scenario,
    seed: u64,
    tenant: &Tenant,
    users: &[User],
    admins: &[User],
) -> (Vec<App>, Vec<Grant>) {
    let mut rng = stream(seed, "apps");
    let ms_tenant = well_known("Microsoft Services tenant");
    let graph_id = well_known("Microsoft Graph");
    let office_id = well_known("Microsoft Office");

    let mut apps = vec![
        first_party_app(&mut rng, tenant, ms_tenant, "Office 365 Exchange Online"),
        first_party_app(&mut rng, tenant, ms_tenant, "Microsoft Graph"),
        first_party_app(&mut rng, tenant, ms_tenant, "Microsoft Office"),
    ];

    let tenant_word = tenant.name.split_whitespace().next().unwrap_or("Tenant");
    let admin_upn = admins.first().map(|a| a.upn.clone());

    let payroll_app_id = rng.uuid();
    let payroll_created = scenario.window.start - Duration::days(200);
    apps.push(App {
        app_id: payroll_app_id,
        object_id: rng.uuid(),
        sp_object_id: rng.uuid(),
        display_name: format!("{tenant_word} Payroll Sync"),
        publisher: tenant.name.clone(),
        verified_publisher: None,
        owner_tenant: tenant.tenant_id,
        sign_in_audience: "AzureADMyOrg".to_string(),
        reply_urls: vec![format!("https://{}/auth/callback", tenant.domains[0])],
        created: payroll_created,
        first_party: false,
        tags: Vec::new(),
        credentials: vec![Credential {
            key_id: rng.uuid(),
            kind: CredKind::Certificate,
            display_name: format!("{tenant_word} Payroll Sync Certificate"),
            start: payroll_created,
            end: payroll_created + Duration::days(730),
            on_service_principal: false,
            added_by: admin_upn.clone(),
            added: payroll_created,
        }],
        owners: Vec::new(),
    });

    let helpdesk_app_id = rng.uuid();
    let helpdesk_created = scenario.window.start - Duration::days(150);
    apps.push(App {
        app_id: helpdesk_app_id,
        object_id: rng.uuid(),
        sp_object_id: rng.uuid(),
        display_name: "Helpdesk Portal".to_string(),
        publisher: tenant.name.clone(),
        verified_publisher: None,
        owner_tenant: tenant.tenant_id,
        sign_in_audience: "AzureADMyOrg".to_string(),
        reply_urls: vec![format!("https://helpdesk.{}/callback", tenant.domains[0])],
        created: helpdesk_created,
        first_party: false,
        tags: Vec::new(),
        credentials: vec![Credential {
            key_id: rng.uuid(),
            kind: CredKind::Password,
            display_name: "Helpdesk Portal Secret".to_string(),
            start: helpdesk_created,
            end: helpdesk_created + Duration::days(365),
            on_service_principal: false,
            added_by: admin_upn,
            added: helpdesk_created,
        }],
        owners: users
            .first()
            .map(|u| vec![u.upn.clone()])
            .unwrap_or_default(),
    });

    let notes_app_id = rng.uuid();
    let notes_created = scenario.window.start - Duration::days(90);
    apps.push(App {
        app_id: notes_app_id,
        object_id: rng.uuid(),
        sp_object_id: rng.uuid(),
        display_name: "Meeting Notes Pro".to_string(),
        publisher: "Notes Vendor Ltd".to_string(),
        verified_publisher: Some("Notes Vendor Ltd".to_string()),
        owner_tenant: rng.uuid(),
        sign_in_audience: "AzureADMultipleOrgs".to_string(),
        reply_urls: vec![MEETING_NOTES_REPLY_URL.to_string()],
        created: notes_created,
        first_party: false,
        tags: Vec::new(),
        credentials: Vec::new(),
        owners: Vec::new(),
    });

    let grants = vec![
        Grant {
            kind: GrantKind::Delegated,
            client_app_id: office_id,
            resource_app_id: graph_id,
            scope: "openid profile User.Read offline_access".to_string(),
            consent_type: "AllPrincipals".to_string(),
            principal: None,
            created: tenant.created,
        },
        Grant {
            kind: GrantKind::Delegated,
            client_app_id: helpdesk_app_id,
            resource_app_id: graph_id,
            scope: "User.Read".to_string(),
            consent_type: "AllPrincipals".to_string(),
            principal: None,
            created: helpdesk_created,
        },
        Grant {
            kind: GrantKind::Application,
            client_app_id: payroll_app_id,
            resource_app_id: graph_id,
            scope: "User.Read.All".to_string(),
            consent_type: "AllPrincipals".to_string(),
            principal: None,
            created: payroll_created,
        },
    ];

    (apps, grants)
}

fn build_roles(scenario: &Scenario, users: &[User], admins: &[User]) -> Vec<RoleAssignment> {
    let mut roles = Vec::new();
    if let Some(first_admin) = admins.first() {
        roles.push(RoleAssignment {
            role: "Global Administrator".to_string(),
            principal: first_admin.upn.clone(),
            kind: "Permanent".to_string(),
            start: Some(first_admin.created),
            end: None,
        });
    }
    if let Some(admin2) = admins.get(1) {
        roles.push(RoleAssignment {
            role: "Exchange Administrator".to_string(),
            principal: admin2.upn.clone(),
            kind: "PIM Eligible".to_string(),
            start: None,
            end: None,
        });
    }
    if scenario.tenant.users >= 5 {
        if let Some(user1) = users.first() {
            roles.push(RoleAssignment {
                role: "User Administrator".to_string(),
                principal: user1.upn.clone(),
                kind: "PIM Active".to_string(),
                start: Some(scenario.window.start),
                end: Some(scenario.window.collected_at + Duration::days(180)),
            });
        }
    }
    roles
}

fn build_mfa(users: &[User], admins: &[User]) -> BTreeMap<String, MfaRegistration> {
    let mut map = BTreeMap::new();
    let last = users.len() as u32;
    for user in users {
        let registered = user.n < last;
        let mut methods = vec!["password".to_string()];
        let default_method = if registered {
            methods.push("microsoftAuthenticator".to_string());
            Some("push".to_string())
        } else {
            None
        };
        map.insert(
            user.upn.clone(),
            MfaRegistration {
                methods,
                default_method,
                is_admin: false,
                is_mfa_registered: registered,
                is_mfa_capable: registered,
                is_sspr_registered: true,
                last_updated: user.created + Duration::days(5),
            },
        );
    }
    for admin in admins {
        map.insert(
            admin.upn.clone(),
            MfaRegistration {
                methods: vec![
                    "password".to_string(),
                    "microsoftAuthenticator".to_string(),
                    "fido2".to_string(),
                ],
                default_method: Some("fido2".to_string()),
                is_admin: true,
                is_mfa_registered: true,
                is_mfa_capable: true,
                is_sspr_registered: true,
                last_updated: admin.created + Duration::days(5),
            },
        );
    }
    map
}

fn build_ca(seed: u64, tenant: &Tenant) -> Vec<CaPolicy> {
    let mut rng = stream(seed, "ca");
    vec![
        CaPolicy {
            id: rng.uuid(),
            display_name: "Require MFA for admins".to_string(),
            state: "enabled".to_string(),
            created: tenant.created + Duration::days(10),
            modified: None,
            include_users: Vec::new(),
            include_roles: vec!["Global Administrator".to_string()],
            exclude_users: Vec::new(),
            include_apps: vec!["All".to_string()],
            client_app_types: vec!["all".to_string()],
            built_in_controls: vec!["mfa".to_string()],
            grant_operator: Some("OR".to_string()),
            sign_in_risk_levels: Vec::new(),
            user_risk_levels: Vec::new(),
        },
        CaPolicy {
            id: rng.uuid(),
            display_name: "Block legacy authentication".to_string(),
            state: "enabledForReportingButNotEnforced".to_string(),
            created: tenant.created + Duration::days(11),
            modified: None,
            include_users: vec!["All".to_string()],
            include_roles: Vec::new(),
            exclude_users: Vec::new(),
            include_apps: vec!["All".to_string()],
            client_app_types: vec!["exchangeActiveSync".to_string(), "other".to_string()],
            built_in_controls: vec!["block".to_string()],
            grant_operator: Some("OR".to_string()),
            sign_in_risk_levels: Vec::new(),
            user_risk_levels: Vec::new(),
        },
    ]
}

fn build_devices(scenario: &Scenario, seed: u64, users: &[User]) -> Vec<Device> {
    let mut rng = stream(seed, "devices");
    let mut devices = Vec::new();
    for user in users {
        devices.push(Device {
            device_id: rng.uuid(),
            object_id: rng.uuid(),
            display_name: format!("{}-LAPTOP", user.alias.to_ascii_uppercase()),
            os: "Windows".to_string(),
            os_version: "10.0.22631".to_string(),
            trust_type: "AzureAd".to_string(),
            is_compliant: Some(true),
            is_managed: Some(true),
            enabled: true,
            registered: user.created + Duration::days(1),
            last_signin: scenario.window.start - Duration::days(1),
            owner: user.upn.clone(),
            manufacturer: "Dell Inc.".to_string(),
            model: "Latitude 5440".to_string(),
        });
        if user.n % 2 == 0 {
            devices.push(Device {
                device_id: rng.uuid(),
                object_id: rng.uuid(),
                display_name: format!("{}-PHONE", user.alias.to_ascii_uppercase()),
                os: "iOS".to_string(),
                os_version: "17.5".to_string(),
                trust_type: "Workplace".to_string(),
                is_compliant: None,
                is_managed: Some(false),
                enabled: true,
                registered: user.created + Duration::days(3),
                last_signin: scenario.window.start - Duration::days(2),
                owner: user.upn.clone(),
                manufacturer: "Apple Inc.".to_string(),
                model: "iPhone 14".to_string(),
            });
        }
    }
    devices
}

fn build_groups(seed: u64, tenant: &Tenant, users: &[User]) -> Vec<Group> {
    let mut rng = stream(seed, "groups");
    let primary = &tenant.domains[0];
    let created = tenant.created + Duration::days(1);

    let all_staff = Group {
        id: rng.uuid(),
        display_name: "All Staff".to_string(),
        mail: Some(format!("allstaff@{primary}")),
        mail_enabled: true,
        security_enabled: false,
        group_types: vec!["Unified".to_string()],
        membership_rule: None,
        created,
        visibility: Some("Private".to_string()),
        members: users.iter().map(|u| u.upn.clone()).collect(),
    };

    let finance_count = users.len().min(3);
    let finance = Group {
        id: rng.uuid(),
        display_name: "Finance".to_string(),
        mail: None,
        mail_enabled: false,
        security_enabled: true,
        group_types: Vec::new(),
        membership_rule: None,
        created,
        visibility: None,
        members: users[..finance_count]
            .iter()
            .map(|u| u.upn.clone())
            .collect(),
    };

    let dynamic_sales = Group {
        id: rng.uuid(),
        display_name: "Dynamic Sales".to_string(),
        mail: None,
        mail_enabled: false,
        security_enabled: true,
        group_types: vec!["DynamicMembership".to_string()],
        membership_rule: Some("user.department -eq \"Sales\"".to_string()),
        created,
        visibility: None,
        members: users
            .iter()
            .filter(|u| u.department == "Sales")
            .map(|u| u.upn.clone())
            .collect(),
    };

    vec![all_staff, finance, dynamic_sales]
}

fn build_mobile_devices(scenario: &Scenario, seed: u64, users: &[User]) -> Vec<MobileDevice> {
    let mut rng = stream(seed, "mobile_devices");
    let mut out = Vec::new();
    for user in users {
        if user.n % 2 != 0 {
            continue;
        }
        let first_sync = scenario.window.start - Duration::days(rng.range(30, 300));
        let last_sync = scenario.window_end() - Duration::days(rng.range(1, 5));
        out.push(MobileDevice {
            mailbox: user.upn.clone(),
            device_id: rng.hex(32).to_ascii_uppercase(),
            friendly_name: format!("{}'s iPhone", user.first),
            device_type: "iPhone".to_string(),
            model: "iPhone 14".to_string(),
            os: "iOS 17.5".to_string(),
            user_agent: "Apple-iPhone/1401.28".to_string(),
            client_type: "OutlookMobile".to_string(),
            first_sync,
            last_sync,
            access_state: "Allowed".to_string(),
            access_reason: "Global".to_string(),
            when_created: first_sync,
        });
    }
    out
}

fn build_transport_rules(scenario: &Scenario, seed: u64, admins: &[User]) -> Vec<TransportRule> {
    let mut rng = stream(seed, "transport_rules");
    let created_by = admins
        .first()
        .map(|a| a.display_name.clone())
        .unwrap_or_default();
    let when_changed = scenario.window.start - Duration::days(30);
    vec![
        TransportRule {
            name: "Disclaimer".to_string(),
            guid: rng.uuid(),
            state: "Enabled".to_string(),
            mode: "Enforce".to_string(),
            priority: 0,
            created_by: created_by.clone(),
            when_changed,
            description: "Append a disclaimer to outbound messages.".to_string(),
            blind_copy_to: Vec::new(),
            redirect_to: Vec::new(),
            copy_to: Vec::new(),
            add_to_recipients: Vec::new(),
        },
        TransportRule {
            name: "Block executable attachments".to_string(),
            guid: rng.uuid(),
            state: "Enabled".to_string(),
            mode: "Enforce".to_string(),
            priority: 1,
            created_by,
            when_changed,
            description: "Reject messages with executable attachments.".to_string(),
            blind_copy_to: Vec::new(),
            redirect_to: Vec::new(),
            copy_to: Vec::new(),
            add_to_recipients: Vec::new(),
        },
    ]
}

fn build_remote_domains(tenant: &Tenant) -> Vec<RemoteDomain> {
    vec![RemoteDomain {
        name: "Default".to_string(),
        domain: "*".to_string(),
        auto_forward_enabled: false,
        allowed_ooo_type: "External".to_string(),
        when_changed: tenant.created,
    }]
}

#[allow(clippy::too_many_arguments)]
fn score(
    id: &str,
    category: &str,
    title: &str,
    service: &str,
    current: f64,
    max: f64,
    action_type: &str,
    tier: &str,
    rank: u32,
    threats: &[&str],
) -> SecureScoreControl {
    SecureScoreControl {
        id: id.to_string(),
        category: category.to_string(),
        title: title.to_string(),
        service: service.to_string(),
        current,
        max,
        state: "Default".to_string(),
        action_type: action_type.to_string(),
        tier: tier.to_string(),
        rank,
        threats: threats.iter().map(|t| t.to_string()).collect(),
    }
}

fn build_secure_score() -> Vec<SecureScoreControl> {
    vec![
        score(
            "MFARegistrationV2",
            "Identity",
            "Ensure all users can complete multi-factor authentication for secure access",
            "AzureActiveDirectory",
            7.0,
            9.0,
            "Review",
            "Core",
            1,
            &["accountBreach"],
        ),
        score(
            "AdminMFAV2",
            "Identity",
            "Require multi-factor authentication for administrative roles",
            "AzureActiveDirectory",
            9.0,
            9.0,
            "Config",
            "Core",
            2,
            &["accountBreach", "elevationOfPrivilege"],
        ),
        score(
            "BlockLegacyAuthentication",
            "Identity",
            "Block legacy authentication",
            "AzureActiveDirectory",
            0.0,
            1.0,
            "Config",
            "Core",
            3,
            &["accountBreach"],
        ),
        score(
            "SelfServicePasswordReset",
            "Identity",
            "Enable self-service password reset",
            "AzureActiveDirectory",
            5.0,
            9.0,
            "Config",
            "Core",
            4,
            &["accountBreach"],
        ),
        score(
            "mdo_safelinksforOfficeApps",
            "Data",
            "Enable Safe Links for Office applications",
            "Microsoft Defender for Office 365",
            0.0,
            7.0,
            "Config",
            "Advanced",
            5,
            &["phishing"],
        ),
        score(
            "mdo_atpprotection",
            "Data",
            "Ensure Safe Attachments policy is enabled",
            "Microsoft Defender for Office 365",
            0.0,
            8.0,
            "Config",
            "Advanced",
            6,
            &["malware", "ransomware"],
        ),
        score(
            "aad_admin_accounts_separate_unassigned_cloud_only",
            "Identity",
            "Ensure administrative accounts are separate and cloud-only",
            "AzureActiveDirectory",
            1.0,
            3.0,
            "Review",
            "Core",
            7,
            &["elevationOfPrivilege"],
        ),
        score(
            "IntegratedApps",
            "Apps",
            "Review and remediate risky third-party app consents",
            "Microsoft 365",
            6.0,
            6.0,
            "Review",
            "Core",
            8,
            &["dataExfiltration"],
        ),
    ]
}

fn build_alerts(scenario: &Scenario, seed: u64, users: &[User]) -> Vec<Alert> {
    let mut rng = stream(seed, "alerts");
    let user2 = &users[1];
    let created = scenario.window.start + Duration::days(3) + Duration::hours(10);
    vec![Alert {
        id: format!("alert-{}", rng.hex(24)),
        title: "Email reported by user as malware or phish".to_string(),
        category: "ThreatManagement".to_string(),
        severity: "Informational".to_string(),
        status: "Resolved".to_string(),
        created,
        event: created,
        affected_user: Some(user2.upn.clone()),
        ip: None,
        provider: "Microsoft Defender for Office 365".to_string(),
    }]
}

fn build_audit(profile: &AuditProfile, licence: &LicenceProfile) -> AuditState {
    AuditState {
        ual_ingestion_enabled: profile.unified_audit_log_ingestion_enabled,
        org_audit_disabled: profile.org_audit_disabled,
        admin_audit_log_enabled: profile.admin_audit_log_enabled,
        admin_audit_log_age_limit: "90.00:00:00".to_string(),
        log_level: "None".to_string(),
        security_defaults_enabled: !licence.p1(),
        ual_disabled_at: None,
        org_audit_disabled_at: None,
    }
}

fn build_mailbox_permissions(
    scenario: &Scenario,
    tenant: &Tenant,
    users: &[User],
    admins: &[User],
) -> Vec<MailboxPermission> {
    let primary = &tenant.domains[0];
    let discovery_upn =
        format!("DiscoverySearchMailbox{{D919BA05-46A6-415f-80AD-7E09334BB852}}@{primary}");
    let mut out = vec![MailboxPermission {
        mailbox: discovery_upn,
        grantee: "Discovery Management".to_string(),
        right: "full_access".to_string(),
        folder: None,
        access_rights: vec!["FullAccess".to_string()],
        deny: false,
        inheritance: Some("All".to_string()),
    }];

    if scenario.tenant.users >= 4 {
        out.push(MailboxPermission {
            mailbox: users[3].upn.clone(),
            grantee: users[2].upn.clone(),
            right: "folder".to_string(),
            folder: Some("calendar".to_string()),
            access_rights: vec!["Editor".to_string()],
            deny: false,
            inheritance: None,
        });
    }

    if let Some(admin) = admins.first() {
        out.push(MailboxPermission {
            mailbox: format!("accounts-payable@{primary}"),
            grantee: admin.upn.clone(),
            right: "full_access".to_string(),
            folder: None,
            access_rights: vec!["FullAccess".to_string()],
            deny: false,
            inheritance: None,
        });
    }

    out
}

fn build_attacker(tenant: &Tenant) -> Attacker {
    let mut alloc = IpAllocator::new();
    let proxy_ip = IpAddr::V4(alloc.v4(Net::Attacker));
    let replay_ip = IpAddr::V4(alloc.v4(Net::Attacker));
    let send_ip = IpAddr::V4(alloc.v4(Net::Attacker));
    let mailbox_ip = IpAddr::V4(alloc.v4(Net::Attacker));

    let locs = &*LOCATIONS;
    let n = locs.len();
    let mut location = locs[n - 1].clone();
    location.asn = HOSTING_ASNS[0].0;
    location.asn_org = HOSTING_ASNS[0].1.to_string();
    let mut replay_location = locs[n - 2].clone();
    replay_location.asn = HOSTING_ASNS[1].0;
    replay_location.asn_org = HOSTING_ASNS[1].1.to_string();

    let word = tenant
        .name
        .split_whitespace()
        .next()
        .unwrap_or("Tenant")
        .to_ascii_lowercase();

    Attacker {
        proxy_ip,
        replay_ip,
        send_ip,
        mailbox_ip,
        location,
        replay_location,
        external_domain: "exfil-mail.test".to_string(),
        forward_address: "invoices@exfil-mail.test".to_string(),
        lure_domain: format!("{word}-secure-signin.test"),
        user_agent_scripted: "python-requests/2.32.3".to_string(),
        user_agent_axios: "axios/1.7.7".to_string(),
    }
}
