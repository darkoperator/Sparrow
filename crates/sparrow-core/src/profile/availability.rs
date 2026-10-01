//! Evidence availability per tenant (spec §7 `evidence_availability`): for every tenant and
//! evidence source, whether the evidence is in the case and, if not, why (not licensed, not
//! enabled, beyond retention, not collected) and which collector command would fill the gap.
//!
//! `compute` evaluates it from the case for a given "now" (it only reads, so it works on a
//! read-only connection); the profile step stores a snapshot (`snapshot`) and
//! `sparrow capabilities` recomputes it live (`capabilities_report`).

use crate::profile::capabilities::{TenantCapability, string_list, tenant_capabilities};
use crate::{Case, Result};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use duckdb::{Connection, params};
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};

/// Event evidence has times and a retention; state evidence is a current snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Event,
    State,
}

/// One evidence source of the catalog.
#[derive(Debug)]
pub struct EvidenceDef {
    pub id: &'static str,
    pub title: &'static str,
    pub kind: Kind,
    /// `SELECT c.tenant_key, count(*), epoch_ms(min(t)), epoch_ms(max(t)), count(DISTINCT user)
    /// ... GROUP BY 1` (times NULL for state kinds without a time, users NULL without a user
    /// column). None when no collector exports the evidence.
    pub facts_sql: Option<&'static str>,
    /// `SELECT DISTINCT c.tenant_key`: tenants with rows of this evidence sighted in a file
    /// whose warnings name a known export cap (the export was likely truncated).
    pub truncated_sql: Option<&'static str>,
    /// Artifact ids of the files that carry the evidence (`*` suffix = prefix match).
    pub artifacts: &'static [&'static str],
    /// Microsoft-Extractor-Suite run folders: (component, run label prefix). `None` = a run
    /// folder without a label (no `-SubComponent`).
    pub invictus_runs: &'static [(&'static str, Option<&'static str>)],
    /// Hawk 4 `Hawk.log` message regex; group 1, when present, is the user collected for.
    pub hawk_log: Option<&'static str>,
    pub needs_ual: bool,
    pub needs_mailbox_audit: bool,
    /// Mailbox audit action (AuditOwner) the evidence needs.
    pub mailbox_action: Option<&'static str>,
    /// A full unified audit log collection holds this evidence.
    pub full_ual_covers: bool,
    /// Static note appended to every reason.
    pub note: Option<&'static str>,
    /// Microsoft-Extractor-Suite command (`{start}` / `{end}` are replaced by dates).
    pub invictus: Option<&'static str>,
    pub hawk: Option<&'static str>,
    pub portal: Option<&'static str>,
}

/// An evidence source read from `$from` (which must alias its rows `x` with a
/// `collection_id` column): `facts_sql` counts rows, times and users per tenant;
/// `truncated_sql` lists the tenants whose rows were sighted (`record_sources` table `$table`,
/// key `$key`) in a file carrying a truncation warning.
macro_rules! source {
    ($from:literal, $time:literal, $users:literal, $table:literal, $key:literal) => {
        EvidenceDef {
            facts_sql: Some(concat!(
                "SELECT c.tenant_key, count(*), epoch_ms(min(",
                $time,
                ")), epoch_ms(max(",
                $time,
                ")), ",
                $users,
                " FROM ",
                $from,
                " JOIN collections c ON c.collection_id = x.collection_id GROUP BY 1"
            )),
            truncated_sql: Some(concat!(
                "SELECT DISTINCT c.tenant_key FROM ",
                $from,
                " JOIN record_sources rs ON rs.table_name = ",
                $table,
                " AND rs.record_key = ",
                $key,
                " JOIN source_files sf ON sf.file_id = rs.file_id",
                " JOIN collections c ON c.collection_id = x.collection_id",
                " WHERE c.tenant_key IS NOT NULL",
                " AND CAST(sf.warnings AS VARCHAR) LIKE '%known export cap%'"
            )),
            ..BASE
        }
    };
}

/// Evidence template with every optional part empty.
const BASE: EvidenceDef = EvidenceDef {
    id: "",
    title: "",
    kind: Kind::State,
    facts_sql: None,
    truncated_sql: None,
    artifacts: &[],
    invictus_runs: &[],
    hawk_log: None,
    needs_ual: false,
    needs_mailbox_audit: false,
    mailbox_action: None,
    full_ual_covers: false,
    note: None,
    invictus: None,
    hawk: None,
    portal: None,
};

/// The evidence catalog. Ids match `capabilities.yaml` `evidence:` lists; artifact ids match
/// `discovery::Registry` (plus the portal ids); Invictus components / labels match
/// Microsoft-Extractor-Suite 4.1.0 `Init-OutputDir -Component/-SubComponent`; Hawk log lines
/// and commands match Hawk 4.0.0.
pub static EVIDENCE: &[EvidenceDef] = &[
    EvidenceDef {
        id: "ual",
        title: "Unified audit log",
        kind: Kind::Event,
        artifacts: &[
            "inv.ual.*",
            "inv.quickual.*",
            "portal.ual",
            "hawk.tenant.raw_ual",
            "hawk.tenant.simple_ual",
            "hawk.tenant.entra_app_audit",
            "hawk.user.raw_ual",
            "hawk.user.simple_ual",
            "hawk.user.raw_auth",
            "hawk.user.converted_auth",
            "hawk.ip.events",
            "hawk.ip.unique_users",
        ],
        invictus_runs: &[("UnifiedAuditLog", None), ("Mailbox Audit Log", None)],
        hawk_log: Some(r"^Initiating collection of .* from the UAL"),
        needs_ual: true,
        invictus: Some("Get-UAL -StartDate {start} -EndDate {end}"),
        hawk: Some("Start-HawkTenantInvestigation (Hawk searches selected operations only)"),
        portal: Some("Purview portal > Audit > New search, export (50,000 rows per export)"),
        ..source!(
            "ual_events x", "x.event_time", "count(DISTINCT lower(x.user_upn))",
            "'ual_events'", "CAST(x.record_id AS VARCHAR)"
        )
    },
    EvidenceDef {
        id: "mail_items_accessed",
        title: "MailItemsAccessed (mailbox reads)",
        kind: Kind::Event,
        artifacts: &["inv.mia.*"],
        invictus_runs: &[("MailItemsAccessed", None)],
        hawk_log: Some(r"^Initiating collection of MailItemsAccessed for (\S+)"),
        needs_ual: true,
        needs_mailbox_audit: true,
        mailbox_action: Some("MailItemsAccessed"),
        full_ual_covers: true,
        note: Some(
            "Microsoft Learn contradicts itself on the licence (Audit Standard since 2024 vs E5).",
        ),
        invictus: Some("Get-UAL -StartDate {start} -EndDate {end} -Operations MailItemsAccessed"),
        hawk: Some("Get-HawkUserMailItemsAccessed -UserPrincipalName <upn>"),
        ..source!(
            "(SELECT collection_id, event_time AS t, user_upn AS u, 'ual_events' AS tn,
                     CAST(record_id AS VARCHAR) AS k FROM ual_events
               WHERE operation = 'MailItemsAccessed'
              UNION ALL
              SELECT collection_id, event_time, user_upn, 'mail_items_accessed', item_key
                FROM mail_items_accessed
               WHERE record_id IS NULL) x",
            "x.t",
            "count(DISTINCT lower(x.u))",
            "x.tn", "x.k"
        )
    },
    EvidenceDef {
        id: "mail_send",
        title: "Mail sent (Send, SendAs, SendOnBehalf)",
        kind: Kind::Event,
        hawk_log: Some(r"^Initiating collection of mail 'Send' logs for (\S+)"),
        needs_ual: true,
        needs_mailbox_audit: true,
        mailbox_action: Some("Send"),
        full_ual_covers: true,
        invictus: Some(
            "Get-UAL -StartDate {start} -EndDate {end} -Operations Send,SendAs,SendOnBehalf",
        ),
        hawk: Some("Get-HawkUserMailSendActivity -UserPrincipalName <upn>"),
        ..source!(
            "(SELECT * FROM ual_events WHERE operation IN ('Send', 'SendAs', 'SendOnBehalf')) x",
            "x.event_time",
            "count(DISTINCT lower(x.user_upn))",
            "'ual_events'", "CAST(x.record_id AS VARCHAR)"
        )
    },
    EvidenceDef {
        id: "search_queries",
        title: "Search queries (Exchange, SharePoint)",
        kind: Kind::Event,
        hawk_log: Some(r"^Initiating collection of (?:Exchange|SharePoint) Search queries for (\S+)"),
        needs_ual: true,
        full_ual_covers: true,
        note: Some(
            "SearchQueryInitiatedExchange is logged only for mailboxes with Set-Mailbox -AuditOwner @{Add=\"SearchQueryInitiated\"}; SearchQueryInitiatedSharePoint is on by default.",
        ),
        invictus: Some(
            "Get-UAL -StartDate {start} -EndDate {end} -Operations SearchQueryInitiatedExchange,SearchQueryInitiatedSharePoint",
        ),
        hawk: Some("Get-HawkUserExchangeSearchQuery -UserPrincipalName <upn>"),
        ..source!(
            "(SELECT * FROM ual_events
               WHERE operation IN ('SearchQueryInitiatedExchange', 'SearchQueryInitiatedSharePoint')) x",
            "x.event_time",
            "count(DISTINCT lower(x.user_upn))",
            "'ual_events'", "CAST(x.record_id AS VARCHAR)"
        )
    },
    EvidenceDef {
        id: "signins",
        title: "Entra ID sign-in logs",
        kind: Kind::Event,
        artifacts: &["inv.signins*", "hawk.user.entra_signin", "portal.entra_signins"],
        invictus_runs: &[("EntraID", Some("SignInLogs"))],
        hawk_log: Some(r"^Initiating collection of sign-in logs for (\S+) from Entra ID"),
        invictus: Some("Get-GraphEntraSignInLogs -startDate {start} -endDate {end}"),
        hawk: Some("Get-HawkUserEntraIDSignInLog -UserPrincipalName <upn>"),
        portal: Some("Entra admin center > Sign-in logs > Download (works on every edition)"),
        ..source!(
            "signins x", "x.event_time", "count(DISTINCT lower(x.user_upn))",
            "'signins'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "directory_audits",
        title: "Entra ID audit logs",
        kind: Kind::Event,
        artifacts: &["inv.entra_audit*", "hawk.tenant.entra_audit"],
        invictus_runs: &[("EntraID", Some("AuditLogs"))],
        hawk_log: Some(r"^Initiating collection of Entra ID audit events"),
        invictus: Some("Get-GraphEntraAuditLogs -startDate {start} -endDate {end}"),
        hawk: Some("Get-HawkTenantEntraIDAuditLog"),
        portal: Some("Entra admin center > Audit logs > Download"),
        ..source!(
            "directory_audits x",
            "x.event_time",
            "count(DISTINCT lower(x.initiated_by_upn))",
            "'directory_audits'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "risk_detections",
        title: "Entra ID Protection risk detections",
        kind: Kind::Event,
        artifacts: &["inv.risk_detections", "hawk.tenant.risk_detections"],
        invictus_runs: &[("RiskyEvents", None)],
        hawk_log: Some(r"^Initiating collection of Risk Detection events"),
        invictus: Some("Get-RiskyDetections"),
        hawk: Some("Get-HawkTenantRiskDetections"),
        ..source!(
            "risk_detections x",
            "coalesce(x.activity_time, x.detected_time)",
            "count(DISTINCT lower(x.user_upn))",
            "'risk_detections'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "message_trace",
        title: "Exchange Online message trace",
        kind: Kind::Event,
        artifacts: &[
            "inv.message_trace",
            "hawk.user.message_trace",
            "portal.message_trace",
        ],
        invictus_runs: &[("MessageTrace", None)],
        hawk_log: Some(r"^Initiating collection of Message Trace Data for (\S+)"),
        invictus: Some("Get-MessageTraceLog -StartDate {start} -EndDate {end}"),
        hawk: Some("Get-HawkUserMessageTrace -UserPrincipalName <upn>"),
        portal: Some("Exchange admin center > Mail flow > Message trace"),
        ..source!(
            "message_trace x", "x.received", "count(DISTINCT lower(x.sender))",
            "'message_trace'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "mailbox_audit_legacy",
        title: "Mailbox audit log (Search-MailboxAuditLog)",
        kind: Kind::Event,
        artifacts: &["inv.mailbox_audit_legacy", "hawk.user.mailbox_audit_legacy"],
        invictus_runs: &[("Mailbox Audit Log", Some("Legacy"))],
        needs_mailbox_audit: true,
        invictus: Some(
            "Get-MailboxAuditLogLegacy -UserIds <upn> -StartDate {start} -EndDate {end}",
        ),
        ..source!(
            "mailbox_audit_legacy x",
            "x.event_time",
            "count(DISTINCT lower(x.mailbox_upn))",
            "'mailbox_audit_legacy'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "admin_audit",
        title: "Exchange admin audit log",
        kind: Kind::Event,
        artifacts: &["hawk.tenant.admin_audit"],
        invictus: Some("Get-UAL -StartDate {start} -EndDate {end} -RecordType ExchangeAdmin"),
        hawk: Some("Start-HawkTenantInvestigation"),
        ..source!(
            "admin_audit_events x",
            "x.run_time",
            "count(DISTINCT lower(x.caller))",
            "'admin_audit_events'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "email_threat_events",
        title: "Defender for Office 365 email threat events",
        kind: Kind::Event,
        portal: Some(
            "Defender portal > Explorer / Real-time detections, or Advanced hunting EmailEvents (30 days)",
        ),
        ..BASE
    },
    EvidenceDef {
        id: "url_clicks",
        title: "Defender for Office 365 Safe Links URL clicks",
        kind: Kind::Event,
        portal: Some(
            "Defender portal > Explorer > URL clicks, or Advanced hunting UrlClickEvents (30 days)",
        ),
        ..BASE
    },
    EvidenceDef {
        id: "risky_users",
        title: "Entra ID Protection risky users",
        kind: Kind::State,
        artifacts: &["inv.risky_users", "hawk.tenant.risky_users"],
        invictus_runs: &[("RiskyEvents", None)],
        hawk_log: Some(r"^Initiating collection of Risky Users"),
        invictus: Some("Get-RiskyUsers"),
        hawk: Some("Get-HawkTenantRiskyUsers"),
        ..source!(
            "risky_users x",
            "x.risk_last_updated",
            "count(DISTINCT lower(x.upn))",
            "'risky_users'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "inbox_rules",
        title: "Inbox and sweep rules",
        kind: Kind::State,
        artifacts: &[
            "inv.mailbox_rules*",
            "hawk.user.inbox_rules",
            "hawk.user.sweep_rules",
            "hawk.tenant.all_inbox_rules",
            "hawk.tenant.all_sweep_rules",
        ],
        invictus_runs: &[("Rules", None)],
        hawk_log: Some(r"^Initiating collection of Exchange Inbox Rules for (\S+)"),
        invictus: Some("Get-MailboxRules"),
        hawk: Some("Get-HawkUserInboxRule -UserPrincipalName <upn>"),
        ..source!(
            "inbox_rules x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "count(DISTINCT lower(x.mailbox_upn))",
            "'inbox_rules'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "mailbox_config",
        title: "Mailbox configuration (forwarding, auto-reply, auditing)",
        kind: Kind::State,
        artifacts: &[
            "inv.audit_status",
            "hawk.user.mailbox_txt",
            "hawk.user.forwarding",
            "hawk.user.autoreply",
            "hawk.tenant.user_forwarding_report",
        ],
        invictus_runs: &[("Audit Status", None)],
        hawk_log: Some(r"^Initiating collection of mailbox configuration for (\S+)"),
        invictus: Some("Get-MailboxAuditStatus"),
        hawk: Some("Get-HawkUserConfiguration -UserPrincipalName <upn>"),
        ..source!(
            "mailboxes x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "count(DISTINCT lower(x.upn))",
            "'mailboxes'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "mailbox_permissions",
        title: "Mailbox permissions",
        kind: Kind::State,
        artifacts: &["inv.mailbox_permissions"],
        invictus_runs: &[("Mailbox Permissions", None)],
        invictus: Some("Get-MailboxPermissions"),
        ..source!(
            "mailbox_permissions x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "count(DISTINCT lower(x.mailbox_upn))",
            "'mailbox_permissions'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "users",
        title: "Entra ID users",
        kind: Kind::State,
        artifacts: &[
            "inv.users",
            "hawk.tenant.entra_users",
            "hawk.tenant.azuread_users",
        ],
        invictus_runs: &[("Users", None)],
        hawk_log: Some(r"^Initiating collection of users from Entra ID"),
        invictus: Some("Get-Users"),
        hawk: Some("Get-HawkTenantEntraIDUser"),
        ..source!(
            "users x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "count(DISTINCT lower(x.upn))",
            "'users'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "role_assignments",
        title: "Admin role assignments (Entra ID, Exchange, eDiscovery)",
        kind: Kind::State,
        artifacts: &[
            "inv.admins*",
            "inv.roles.*",
            "hawk.tenant.entra_admins",
            "hawk.tenant.azuread_admins",
            "hawk.tenant.exo_admins",
            "hawk.tenant.ediscovery_roles",
            "hawk.tenant.ediscovery_role_assignments",
            "hawk.tenant.impersonation",
        ],
        invictus_runs: &[("Admins", None), ("Roles", None)],
        hawk_log: Some(
            r"^Initiating collection of (?:Microsoft Entra ID Administrators|Exchange Online Admins)",
        ),
        invictus: Some("Get-AdminUsers"),
        hawk: Some("Get-HawkTenantEntraIDAdmin; Get-HawkTenantEXOAdmin"),
        ..source!(
            "role_assignments x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "CAST(NULL AS BIGINT)",
            "'role_assignments'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "oauth_grants",
        title: "OAuth / application permission grants",
        kind: Kind::State,
        artifacts: &["inv.oauth", "hawk.tenant.consent_grants"],
        invictus_runs: &[("EntraID", Some("OAuthPermissions"))],
        hawk_log: Some(r"^Initiating collection of OAuth / Application Grants"),
        invictus: Some("Get-OAuthPermissionsGraph"),
        hawk: Some("Get-HawkTenantConsentGrant"),
        ..source!(
            "oauth_grants x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "CAST(NULL AS BIGINT)",
            "'oauth_grants'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "app_credentials",
        title: "Application and service principal credentials",
        kind: Kind::State,
        artifacts: &["hawk.tenant.app_credentials"],
        hawk_log: Some(
            r"^Initiating collection of application and service principal credentials",
        ),
        hawk: Some("Get-HawkTenantAppAndSPNCredentialDetail"),
        ..source!(
            "app_credentials x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "CAST(NULL AS BIGINT)",
            "'app_credentials'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "applications",
        title: "Applications and service principals",
        kind: Kind::State,
        artifacts: &[
            "inv.service_principals",
            "inv.app_registrations",
            "inv.user_applications",
        ],
        invictus_runs: &[
            ("EntraID", Some("ServicePrincipals")),
            ("EntraID", Some("AppRegistrations")),
        ],
        invictus: Some("Get-OAuthPermissionsGraph"),
        hawk: Some("Get-HawkTenantAppAndSPNCredentialDetail"),
        ..source!(
            "applications x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "CAST(NULL AS BIGINT)",
            "'applications'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "devices",
        title: "Entra devices",
        kind: Kind::State,
        artifacts: &["inv.devices"],
        invictus_runs: &[("Device Information", None)],
        invictus: Some("Get-Devices"),
        ..source!(
            "devices x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "CAST(NULL AS BIGINT)",
            "'devices'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "groups",
        title: "Entra groups and members",
        kind: Kind::State,
        artifacts: &["inv.groups", "inv.group_members", "inv.dynamic_groups"],
        invictus_runs: &[("Groups", None)],
        invictus: Some("Get-Groups; Get-GroupMembers; Get-DynamicGroups"),
        ..source!(
            "groups x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "CAST(NULL AS BIGINT)",
            "'groups'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "transport_rules",
        title: "Exchange transport rules",
        kind: Kind::State,
        artifacts: &["inv.transport_rules", "hawk.tenant.transport_rules"],
        invictus_runs: &[("Rules", None)],
        hawk_log: Some(r"^Gathering Transport Rules"),
        invictus: Some("Get-TransportRules"),
        hawk: Some("Get-HawkTenantConfiguration"),
        ..source!(
            "transport_rules x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "CAST(NULL AS BIGINT)",
            "'transport_rules'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "mobile_devices",
        title: "Mobile devices attached to mailboxes",
        kind: Kind::State,
        artifacts: &["hawk.user.mobile_devices"],
        hawk_log: Some(r"^Initiating collection of mobile devices attached to (\S+)"),
        hawk: Some("Get-HawkUserMobileDevice -UserPrincipalName <upn>"),
        ..source!(
            "mobile_devices x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "count(DISTINCT lower(x.mailbox))",
            "'mobile_devices'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "audit_config",
        title: "Organization audit configuration",
        kind: Kind::State,
        artifacts: &[
            "hawk.tenant.admin_audit_log_config",
            "hawk.tenant.org_config",
            "inv.audit_status",
            "inv.licenses.security_defaults",
        ],
        invictus_runs: &[("Audit Status", None)],
        hawk_log: Some(r"^Gathering Admin Audit Log"),
        invictus: Some("Get-MailboxAuditStatus; Get-EntraSecurityDefaults"),
        hawk: Some("Get-HawkTenantConfiguration"),
        ..source!(
            "audit_config x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "CAST(NULL AS BIGINT)",
            "'audit_config'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "licenses",
        title: "Tenant licences",
        kind: Kind::State,
        artifacts: &["inv.licenses.tenant", "inv.licenses.user"],
        invictus_runs: &[("Licenses", None)],
        hawk_log: Some(r"^M365 License type detected"),
        invictus: Some("Get-Licenses; Get-LicensesByUser"),
        ..source!(
            "licenses x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "CAST(NULL AS BIGINT)",
            "'licenses'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "mfa_registration",
        title: "Entra MFA registration",
        kind: Kind::State,
        artifacts: &["inv.mfa.*"],
        invictus_runs: &[("MFA", None)],
        invictus: Some("Get-MFA"),
        ..source!(
            "mfa_registration x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "count(DISTINCT lower(x.upn))",
            "'mfa_registration'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "ca_policies",
        title: "Conditional Access policies",
        kind: Kind::State,
        artifacts: &["inv.ca"],
        invictus_runs: &[("ConditionalAccessPolicies", None)],
        invictus: Some("Get-ConditionalAccessPolicies"),
        ..source!(
            "ca_policies x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "CAST(NULL AS BIGINT)",
            "'ca_policies'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "security_alerts",
        title: "Microsoft Defender security alerts",
        kind: Kind::Event,
        artifacts: &["inv.security_alerts"],
        invictus_runs: &[("SecurityAlerts", None)],
        invictus: Some("Get-SecurityAlerts"),
        ..source!(
            "security_alerts x",
            "x.created_time",
            "CAST(NULL AS BIGINT)",
            "'security_alerts'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "secure_score",
        title: "Microsoft Secure Score",
        kind: Kind::State,
        artifacts: &["inv.secure_score"],
        invictus_runs: &[("SecureScore", None)],
        invictus: Some("Get-SecureScore"),
        ..source!(
            "secure_score x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "CAST(NULL AS BIGINT)",
            "'secure_score'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "azure_activity",
        title: "Azure activity logs",
        kind: Kind::Event,
        artifacts: &["inv.activity", "inv.directory_activity"],
        invictus_runs: &[("Activity Logs", None), ("Directory Activity Logs", None)],
        invictus: Some("Get-ActivityLogs; Get-DirectoryActivityLogs"),
        ..source!(
            "azure_activity x",
            "x.event_time",
            "count(DISTINCT lower(x.caller))",
            "'azure_activity'", "x.record_key"
        )
    },
    EvidenceDef {
        id: "email_artifacts",
        title: "Exported e-mail messages",
        kind: Kind::State,
        artifacts: &[
            "inv.email",
            "hawk.message.header",
            "hawk.message.header_findings",
        ],
        invictus_runs: &[("Email Export", None)],
        hawk_log: Some(r"^Reading message header from file"),
        invictus: Some("Get-Email -UserIds <upn> -internetMessageId <id>"),
        hawk: Some("Get-HawkMessageHeader -MSGFile <file>"),
        ..source!(
            "email_artifacts x",
            "CAST(NULL AS TIMESTAMPTZ)",
            "count(DISTINCT lower(x.from_address))",
            "'email_artifacts'", "x.record_key"
        )
    },
];

/// Full unified audit log exports: evidence marked `full_ual_covers` is in them when present.
const FULL_UAL_ARTIFACTS: &[&str] = &["inv.ual.window", "inv.ual.merged", "portal.ual"];

/// One row of `evidence_availability`.
#[derive(Debug, Clone, Serialize)]
pub struct AvailabilityRow {
    pub tenant_key: String,
    pub evidence: String,
    pub title: String,
    pub status: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    pub rows: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users_covered: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<i64>,
}

/// Artifact pattern match: exact id, or prefix when the pattern ends in `*`.
fn artifact_matches(pattern: &str, id: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => id.starts_with(prefix),
        None => id == pattern,
    }
}

fn any_artifact_matches(patterns: &[&str], id: &str) -> bool {
    patterns.iter().any(|p| artifact_matches(p, id))
}

fn from_ms(ms: i64) -> Option<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp_millis(ms)
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn date(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d").to_string()
}

/// Rows of one evidence for one tenant.
#[derive(Debug, Clone, Default)]
struct Facts {
    rows: i64,
    min_ms: Option<i64>,
    max_ms: Option<i64>,
    users: Option<i64>,
    /// Some of these rows were sighted in a file carrying a truncation warning.
    truncated: bool,
}

#[derive(Debug, Clone)]
struct FileRow {
    collection_id: i64,
    tool: String,
    artifact: String,
    status: String,
    /// Records of the file that failed to parse (`source_files.records_error`).
    records_error: i64,
    warnings: Vec<String>,
    rel_path: String,
}

impl FileRow {
    fn is_empty_export(&self) -> bool {
        self.warnings
            .iter()
            .any(|w| w == crate::ingest::EMPTY_FILE_WARNING)
    }

    /// The collector wrote it and Sparrow handled it without errors: parsed (possibly 0
    /// records), a duplicate or superseded copy of a handled file, or an empty export. A file
    /// with parse errors never shows the collector "ran and found nothing" (see `failed`).
    fn shows_run(&self) -> bool {
        !self.failed()
            && (matches!(
                self.status.as_str(),
                "parsed" | "duplicate_file" | "skipped_superseded"
            ) || (self.status == "not_supported" && self.is_empty_export()))
    }

    /// Collected but Sparrow failed to parse it, wholly (status `error`) or in part
    /// (`records_error > 0`): the evidence may hold records the case lacks.
    fn failed(&self) -> bool {
        self.status == "error" || self.records_error > 0
    }

    /// Collected but not parsed by this Sparrow version (empty exports excluded).
    fn unparsed(&self) -> bool {
        self.status == "not_supported" && !self.is_empty_export()
    }
}

#[derive(Debug, Clone)]
struct RunRow {
    collection_id: i64,
    component: Option<String>,
    label: Option<String>,
    rel_dir: String,
}

#[derive(Debug, Clone)]
struct MailboxRow {
    audit_owner: Vec<String>,
    bypass: bool,
}

#[derive(Debug, Clone)]
struct CapState {
    status: String,
    basis: String,
    retention_days: Option<i64>,
}

/// Everything `compute` knows about one tenant.
#[derive(Debug, Default)]
struct TenantFacts {
    window_start_ms: Option<i64>,
    window_end_ms: Option<i64>,
    earliest_collected_ms: Option<i64>,
    has_invictus: bool,
    has_hawk: bool,
    caps: HashMap<String, CapState>,
    ual_ingestion: Option<bool>,
    audit_disabled: Option<bool>,
    mailboxes: Vec<MailboxRow>,
    files: Vec<FileRow>,
    runs: Vec<RunRow>,
    hawk_log: Vec<String>,
    /// The tenant's known users (lower-case UPNs from the `users` table).
    users: BTreeSet<String>,
    /// Sign-in rows in the case, and those with no result (`error_code` NULL): a Hawk 4
    /// `Entra_Sign_In_Log` CSV without its JSON twin (the Status cell holds a type name), or a
    /// portal row with an unknown Status.
    signins_total: i64,
    signins_unknown_result: i64,
}

struct CapDef {
    id: String,
    baseline: bool,
    evidence: Vec<String>,
}

/// Evaluate evidence availability for every tenant of the case at `as_of`. Reads only.
pub fn compute(conn: &Connection, as_of: DateTime<Utc>) -> Result<Vec<AvailabilityRow>> {
    let tenants: Vec<String> = {
        let mut stmt = conn.prepare("SELECT tenant_key FROM tenant ORDER BY tenant_key")?;
        stmt.query_map([], |r| r.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut facts_by_tenant = load_tenant_facts(conn, &tenants)?;
    let cap_defs = load_cap_defs(conn)?;
    let regexes: Vec<Option<Regex>> = EVIDENCE
        .iter()
        .map(|e| {
            e.hawk_log
                .map(|p| Regex::new(p).expect("valid catalog regex"))
        })
        .collect();

    let mut evidence_facts: Vec<HashMap<String, Facts>> = Vec::with_capacity(EVIDENCE.len());
    // The four UAL-backed evidence sources (ual, mail_items_accessed, mail_send,
    // search_queries) are computed in one grouped scan instead of one `facts_sql` each; their
    // truncation flags come from one `record_sources` join.
    let mut ual_facts = load_ual_evidence_facts(conn)?;
    let ual_trunc = load_ual_evidence_truncated(conn)?;
    for def in EVIDENCE {
        if let Some(pre) = ual_facts.remove(def.id) {
            let mut m = pre;
            if let Some(tr) = ual_trunc.get(def.id) {
                for (tenant, truncated) in tr {
                    if let Some(f) = m.get_mut(tenant) {
                        f.truncated = *truncated;
                    }
                }
            }
            evidence_facts.push(m);
        } else {
            evidence_facts.push(load_facts(conn, def)?);
        }
    }

    let mut out = Vec::new();
    for tenant_key in &tenants {
        let tf = facts_by_tenant.remove(tenant_key).unwrap_or_default();
        for (i, def) in EVIDENCE.iter().enumerate() {
            let facts = evidence_facts[i]
                .get(tenant_key)
                .cloned()
                .unwrap_or_default();
            out.push(evaluate(
                tenant_key,
                def,
                &facts,
                &tf,
                &cap_defs,
                regexes[i].as_ref(),
                as_of,
            ));
        }
    }
    Ok(out)
}

fn load_cap_defs(conn: &Connection) -> Result<Vec<CapDef>> {
    let mut stmt =
        conn.prepare("SELECT capability_id, baseline, evidence FROM capabilities ORDER BY 1")?;
    let rows = stmt.query_map([], |r| {
        Ok(CapDef {
            id: r.get(0)?,
            baseline: r.get::<_, Option<bool>>(1)?.unwrap_or(false),
            evidence: string_list(r.get(2)?),
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// The four evidence sources whose rows live in `ual_events` (plus the parent-less
/// `mail_items_accessed` rows), computed in one grouped pass per tenant.
const UAL_BACKED: &[&str] = &["ual", "mail_items_accessed", "mail_send", "search_queries"];

fn empty_ual_facts() -> HashMap<String, HashMap<String, Facts>> {
    UAL_BACKED
        .iter()
        .map(|id| ((*id).to_string(), HashMap::new()))
        .collect()
}

/// `facts_sql` of the four UAL-backed evidence sources, as one grouped scan: `(rows, min, max,
/// distinct users)` per (evidence, tenant). `ual` is the `ual_events` rows; `mail_items_accessed`
/// adds the parent-less `mail_items_accessed` rows; `mail_send`/`search_queries` are the
/// operation subsets.
fn load_ual_evidence_facts(conn: &Connection) -> Result<HashMap<String, HashMap<String, Facts>>> {
    let mut out = empty_ual_facts();
    let mut stmt = conn.prepare(
        "WITH ev AS (
             SELECT c.tenant_key, e.event_time AS t, e.user_upn AS u, e.operation AS op,
                    'ual_events' AS tn
             FROM ual_events e JOIN collections c ON c.collection_id = e.collection_id
             WHERE c.tenant_key IS NOT NULL
             UNION ALL
             SELECT c.tenant_key, m.event_time, m.user_upn, 'MailItemsAccessed', 'mail_items_accessed'
             FROM mail_items_accessed m JOIN collections c ON c.collection_id = m.collection_id
             WHERE m.record_id IS NULL AND c.tenant_key IS NOT NULL
         )
         SELECT tenant_key,
           count(*) FILTER (WHERE tn = 'ual_events'),
           epoch_ms(min(t) FILTER (WHERE tn = 'ual_events')),
           epoch_ms(max(t) FILTER (WHERE tn = 'ual_events')),
           count(DISTINCT lower(u)) FILTER (WHERE tn = 'ual_events'),
           count(*) FILTER (WHERE op = 'MailItemsAccessed'),
           epoch_ms(min(t) FILTER (WHERE op = 'MailItemsAccessed')),
           epoch_ms(max(t) FILTER (WHERE op = 'MailItemsAccessed')),
           count(DISTINCT lower(u)) FILTER (WHERE op = 'MailItemsAccessed'),
           count(*) FILTER (WHERE op IN ('Send', 'SendAs', 'SendOnBehalf')),
           epoch_ms(min(t) FILTER (WHERE op IN ('Send', 'SendAs', 'SendOnBehalf'))),
           epoch_ms(max(t) FILTER (WHERE op IN ('Send', 'SendAs', 'SendOnBehalf'))),
           count(DISTINCT lower(u)) FILTER (WHERE op IN ('Send', 'SendAs', 'SendOnBehalf')),
           count(*) FILTER (WHERE op IN ('SearchQueryInitiatedExchange', 'SearchQueryInitiatedSharePoint')),
           epoch_ms(min(t) FILTER (WHERE op IN ('SearchQueryInitiatedExchange', 'SearchQueryInitiatedSharePoint'))),
           epoch_ms(max(t) FILTER (WHERE op IN ('SearchQueryInitiatedExchange', 'SearchQueryInitiatedSharePoint'))),
           count(DISTINCT lower(u)) FILTER (WHERE op IN ('SearchQueryInitiatedExchange', 'SearchQueryInitiatedSharePoint'))
         FROM ev GROUP BY tenant_key",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            Facts {
                rows: r.get(1)?,
                min_ms: r.get(2)?,
                max_ms: r.get(3)?,
                users: r.get(4)?,
                truncated: false,
            },
            Facts {
                rows: r.get(5)?,
                min_ms: r.get(6)?,
                max_ms: r.get(7)?,
                users: r.get(8)?,
                truncated: false,
            },
            Facts {
                rows: r.get(9)?,
                min_ms: r.get(10)?,
                max_ms: r.get(11)?,
                users: r.get(12)?,
                truncated: false,
            },
            Facts {
                rows: r.get(13)?,
                min_ms: r.get(14)?,
                max_ms: r.get(15)?,
                users: r.get(16)?,
                truncated: false,
            },
        ))
    })?;
    for row in rows {
        let (tenant, ual, mia, send, search) = row?;
        for (id, f) in [
            ("ual", ual),
            ("mail_items_accessed", mia),
            ("mail_send", send),
            ("search_queries", search),
        ] {
            // A def with no rows has no `facts_sql` row (and so no `users_covered`, which
            // `Facts::default()` keeps NULL): keep it absent.
            if f.rows > 0 {
                if let Some(m) = out.get_mut(id) {
                    m.insert(tenant.clone(), f);
                }
            }
        }
    }
    Ok(out)
}

/// One `record_sources` join deciding, per (evidence, tenant), whether any sighted row came
/// from a file carrying a truncation warning (the four `truncated_sql` queries folded in).
fn load_ual_evidence_truncated(
    conn: &Connection,
) -> Result<HashMap<String, HashMap<String, bool>>> {
    let mut out: HashMap<String, HashMap<String, bool>> = UAL_BACKED
        .iter()
        .map(|id| ((*id).to_string(), HashMap::new()))
        .collect();
    let mut stmt = conn.prepare(
        "SELECT ev.tenant_key,
           coalesce(bool_or(CAST(sf.warnings AS VARCHAR) LIKE '%known export cap%')
                    FILTER (WHERE ev.tn = 'ual_events'), false),
           coalesce(bool_or(CAST(sf.warnings AS VARCHAR) LIKE '%known export cap%')
                    FILTER (WHERE (ev.tn = 'ual_events' AND ev.op = 'MailItemsAccessed')
                               OR ev.tn = 'mail_items_accessed'), false),
           coalesce(bool_or(CAST(sf.warnings AS VARCHAR) LIKE '%known export cap%')
                    FILTER (WHERE ev.tn = 'ual_events'
                              AND ev.op IN ('Send', 'SendAs', 'SendOnBehalf')), false),
           coalesce(bool_or(CAST(sf.warnings AS VARCHAR) LIKE '%known export cap%')
                    FILTER (WHERE ev.tn = 'ual_events'
                              AND ev.op IN ('SearchQueryInitiatedExchange', 'SearchQueryInitiatedSharePoint')), false)
         FROM (
             SELECT c.tenant_key, e.operation AS op, 'ual_events' AS tn,
                    CAST(e.record_id AS VARCHAR) AS k
             FROM ual_events e JOIN collections c ON c.collection_id = e.collection_id
             WHERE c.tenant_key IS NOT NULL
             UNION ALL
             SELECT c.tenant_key, 'MailItemsAccessed', 'mail_items_accessed', m.item_key
             FROM mail_items_accessed m JOIN collections c ON c.collection_id = m.collection_id
             WHERE m.record_id IS NULL AND c.tenant_key IS NOT NULL
         ) ev
         JOIN record_sources rs ON rs.table_name = ev.tn AND rs.record_key = ev.k
         JOIN source_files sf ON sf.file_id = rs.file_id
         GROUP BY ev.tenant_key",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, bool>(1)?,
            r.get::<_, bool>(2)?,
            r.get::<_, bool>(3)?,
            r.get::<_, bool>(4)?,
        ))
    })?;
    for row in rows {
        let (tenant, ual, mia, send, search) = row?;
        for (id, t) in [
            ("ual", ual),
            ("mail_items_accessed", mia),
            ("mail_send", send),
            ("search_queries", search),
        ] {
            if let Some(m) = out.get_mut(id) {
                m.insert(tenant.clone(), t);
            }
        }
    }
    Ok(out)
}

fn load_facts(conn: &Connection, def: &EvidenceDef) -> Result<HashMap<String, Facts>> {
    let Some(sql) = def.facts_sql else {
        return Ok(HashMap::new());
    };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, Option<String>>(0)?,
            Facts {
                rows: r.get(1)?,
                min_ms: r.get(2)?,
                max_ms: r.get(3)?,
                users: r.get(4)?,
                truncated: false,
            },
        ))
    })?;
    let mut out = HashMap::new();
    for row in rows {
        let (key, facts) = row?;
        if let Some(key) = key {
            out.insert(key, facts);
        }
    }
    if let Some(sql) = def.truncated_sql {
        let mut stmt = conn.prepare(sql)?;
        let keys = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for key in keys {
            if let Some(f) = out.get_mut(&key?) {
                f.truncated = true;
            }
        }
    }
    Ok(out)
}

fn load_tenant_facts(
    conn: &Connection,
    tenants: &[String],
) -> Result<HashMap<String, TenantFacts>> {
    let mut map: HashMap<String, TenantFacts> = tenants
        .iter()
        .map(|t| (t.clone(), TenantFacts::default()))
        .collect();

    // Sign-ins with no result.
    {
        let mut stmt = conn.prepare(
            "SELECT c.tenant_key, count(*), count(*) FILTER (WHERE x.error_code IS NULL)
             FROM signins x JOIN collections c ON c.collection_id = x.collection_id
             WHERE c.tenant_key IS NOT NULL GROUP BY c.tenant_key",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (tenant, total, unknown) = row?;
            if let Some(tf) = map.get_mut(&tenant) {
                tf.signins_total = total;
                tf.signins_unknown_result = unknown;
            }
        }
    }

    // Collections: window, first collection time, tools.
    {
        let mut stmt = conn.prepare(
            "SELECT tenant_key, CAST(tool AS VARCHAR), epoch_ms(window_start),
                    epoch_ms(coalesce(window_end, collected_at)), epoch_ms(collected_at)
             FROM collections WHERE tenant_key IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<i64>>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, Option<i64>>(4)?,
            ))
        })?;
        for row in rows {
            let (key, tool, start, end, collected) = row?;
            let Some(tf) = map.get_mut(&key) else {
                continue;
            };
            tf.has_invictus |= tool == "invictus";
            tf.has_hawk |= tool == "hawk";
            tf.window_start_ms = min_opt(tf.window_start_ms, start);
            tf.window_end_ms = max_opt(tf.window_end_ms, end);
            tf.earliest_collected_ms = min_opt(tf.earliest_collected_ms, collected);
        }
    }

    // Event-time fallback for tenants whose collections report no window.
    {
        let mut stmt = conn.prepare(
            "SELECT c.tenant_key, epoch_ms(min(e.t)), epoch_ms(max(e.t))
             FROM (SELECT collection_id, event_time AS t FROM ual_events
                   UNION ALL SELECT collection_id, event_time FROM signins
                   UNION ALL SELECT collection_id, event_time FROM directory_audits
                   UNION ALL SELECT collection_id, received FROM message_trace) e
             JOIN collections c ON c.collection_id = e.collection_id
             WHERE c.tenant_key IS NOT NULL
             GROUP BY 1",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<i64>>(1)?,
                r.get::<_, Option<i64>>(2)?,
            ))
        })?;
        for row in rows {
            let (key, min_t, max_t) = row?;
            if let Some(tf) = map.get_mut(&key) {
                tf.window_start_ms = tf.window_start_ms.or(min_t);
                tf.window_end_ms = tf.window_end_ms.or(max_t);
            }
        }
    }

    // Capability status.
    {
        let mut stmt = conn.prepare(
            "SELECT tenant_key, capability_id, CAST(status AS VARCHAR), basis, retention_days
             FROM tenant_capabilities",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                CapState {
                    status: r.get(2)?,
                    basis: r.get(3)?,
                    retention_days: r.get(4)?,
                },
            ))
        })?;
        for row in rows {
            let (key, cap, state) = row?;
            if let Some(tf) = map.get_mut(&key) {
                tf.caps.insert(cap, state);
            }
        }
    }

    // Organization audit settings.
    {
        let mut stmt = conn.prepare(
            "SELECT tenant_key, unified_audit_log_ingestion_enabled, audit_disabled
             FROM tenant_audit_config",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<bool>>(1)?,
                r.get::<_, Option<bool>>(2)?,
            ))
        })?;
        for row in rows {
            let (key, ual, disabled) = row?;
            if let Some(tf) = map.get_mut(&key) {
                tf.ual_ingestion = ual;
                tf.audit_disabled = disabled;
            }
        }
    }

    // Mailboxes whose owner audit actions are known.
    {
        let mut stmt = conn.prepare(
            "SELECT c.tenant_key, m.audit_owner, coalesce(m.audit_bypass_enabled, false)
             FROM mailboxes m JOIN collections c ON c.collection_id = m.collection_id
             WHERE m.audit_owner IS NOT NULL AND c.tenant_key IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                MailboxRow {
                    audit_owner: string_list(r.get(1)?),
                    bypass: r.get(2)?,
                },
            ))
        })?;
        for row in rows {
            let (key, mb) = row?;
            if let Some(tf) = map.get_mut(&key) {
                tf.mailboxes.push(mb);
            }
        }
    }

    // Classified files.
    {
        let mut stmt = conn.prepare(
            "SELECT c.tenant_key, CAST(c.tool AS VARCHAR), sf.artifact_type,
                    CAST(sf.status AS VARCHAR), CAST(sf.warnings AS VARCHAR), sf.rel_path,
                    sf.collection_id, sf.records_error
             FROM source_files sf JOIN collections c ON c.collection_id = sf.collection_id
             WHERE sf.artifact_type IS NOT NULL AND c.tenant_key IS NOT NULL
             ORDER BY sf.file_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, i64>(7)?,
            ))
        })?;
        for row in rows {
            let (key, tool, artifact, status, warnings, rel_path, collection_id, records_error) =
                row?;
            let warnings: Vec<String> = warnings
                .and_then(|w| serde_json::from_str(&w).ok())
                .unwrap_or_default();
            if let Some(tf) = map.get_mut(&key) {
                tf.files.push(FileRow {
                    collection_id,
                    tool,
                    artifact,
                    status,
                    records_error,
                    warnings,
                    rel_path,
                });
            }
        }
    }

    // Microsoft-Extractor-Suite run folders.
    {
        let mut stmt = conn.prepare(
            "SELECT c.tenant_key, r.component, r.run_label, r.rel_dir, r.collection_id
             FROM collector_runs r JOIN collections c ON c.collection_id = r.collection_id
             WHERE c.tenant_key IS NOT NULL ORDER BY r.rel_dir",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                RunRow {
                    component: r.get(1)?,
                    label: r.get(2)?,
                    rel_dir: r.get(3)?,
                    collection_id: r.get(4)?,
                },
            ))
        })?;
        for row in rows {
            let (key, run) = row?;
            if let Some(tf) = map.get_mut(&key) {
                tf.runs.push(run);
            }
        }
    }

    // Hawk log messages.
    {
        let mut stmt = conn.prepare(
            "SELECT c.tenant_key, l.message
             FROM collection_log l JOIN collections c ON c.collection_id = l.collection_id
             WHERE c.tool = 'hawk' AND c.tenant_key IS NOT NULL
             ORDER BY l.collection_id, l.record_ordinal",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (key, message) = row?;
            if let Some(tf) = map.get_mut(&key) {
                tf.hawk_log.push(message);
            }
        }
    }

    // Known users (for "Hawk collected it for n of m users").
    {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT c.tenant_key, lower(u.upn)
             FROM users u JOIN collections c ON c.collection_id = u.collection_id
             WHERE c.tenant_key IS NOT NULL AND u.upn IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (key, upn) = row?;
            if let Some(tf) = map.get_mut(&key) {
                tf.users.insert(upn);
            }
        }
    }

    Ok(map)
}

fn min_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    }
}

fn max_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, y) => x.or(y),
    }
}

/// How the capabilities that provide an evidence source stand for a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Licence {
    /// No capability gates the evidence.
    NotRequired,
    Licensed,
    NotLicensed,
    Unknown,
}

struct LicenceView {
    licence: Licence,
    /// Basis text of the deciding capabilities.
    basis: String,
    retention_days: Option<i64>,
    any_baseline: bool,
}

fn licence_view(def: &EvidenceDef, tf: &TenantFacts, cap_defs: &[CapDef]) -> LicenceView {
    let candidates: Vec<&CapDef> = cap_defs
        .iter()
        .filter(|c| c.evidence.iter().any(|e| e == def.id))
        .collect();
    let any_baseline = candidates.iter().any(|c| c.baseline);
    if candidates.is_empty() {
        return LicenceView {
            licence: Licence::NotRequired,
            basis: String::new(),
            retention_days: None,
            any_baseline,
        };
    }
    let state = |c: &CapDef| tf.caps.get(&c.id);
    let status_of = |c: &CapDef| state(c).map_or("unknown", |s| s.status.as_str());
    let describe = |cs: &[&CapDef]| {
        cs.iter()
            .map(|c| {
                let basis = state(c).map_or("no profile row", |s| s.basis.as_str());
                format!("{}: {basis}", c.id)
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    let licensed: Vec<&CapDef> = candidates
        .iter()
        .copied()
        .filter(|c| status_of(c) == "licensed")
        .collect();
    if !licensed.is_empty() {
        let retention_days = match def.kind {
            Kind::Event => licensed
                .iter()
                .filter_map(|c| state(c).and_then(|s| s.retention_days))
                .max(),
            Kind::State => None,
        };
        return LicenceView {
            licence: Licence::Licensed,
            basis: describe(&licensed),
            retention_days,
            any_baseline,
        };
    }
    let licence = if candidates.iter().all(|c| status_of(c) == "not_licensed") {
        Licence::NotLicensed
    } else {
        Licence::Unknown
    };
    LicenceView {
        licence,
        basis: describe(&candidates),
        retention_days: None,
        any_baseline,
    }
}

/// Users named by per-user Hawk log lines (group 1), lower-cased.
fn hawk_users(re: &Regex, lines: &[String]) -> BTreeSet<String> {
    lines
        .iter()
        .filter_map(|l| re.captures(l))
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
        .collect()
}

/// (known mailboxes, those lacking `action`).
fn mailbox_action_gap(tf: &TenantFacts, action: &str) -> (usize, usize) {
    let known = tf.mailboxes.len();
    let lacking = tf
        .mailboxes
        .iter()
        .filter(|m| m.bypass || !m.audit_owner.iter().any(|a| a.eq_ignore_ascii_case(action)))
        .count();
    (known, lacking)
}

/// A run folder shared by several cmdlets (Rules, RiskyEvents, Licenses, ...) counts for `def`
/// only when none of the classified files directly in it belongs to a different evidence
/// source; a folder without such files stays ambiguous and counts for every evidence of its
/// component.
fn run_belongs_elsewhere(def: &EvidenceDef, tf: &TenantFacts, run: &RunRow) -> bool {
    tf.files.iter().any(|f| {
        f.collection_id == run.collection_id
            && f.rel_path.rsplit_once('/').map(|(dir, _)| dir) == Some(run.rel_dir.as_str())
            && !any_artifact_matches(def.artifacts, &f.artifact)
            && EVIDENCE
                .iter()
                .any(|e| e.id != def.id && any_artifact_matches(e.artifacts, &f.artifact))
    })
}

/// Why the collector is known to have run, if it did.
fn collector_ran(
    def: &EvidenceDef,
    tf: &TenantFacts,
    ev_files: &[&FileRow],
    hawk_re: Option<&Regex>,
) -> Option<String> {
    if let Some(f) = ev_files.iter().find(|f| f.shows_run()) {
        return Some(format!(
            "the collector ran and returned no records (file {})",
            f.rel_path
        ));
    }
    if let Some(run) = tf.runs.iter().find(|r| {
        def.invictus_runs.iter().any(|(component, label)| {
            r.component.as_deref() == Some(*component)
                && match label {
                    Some(prefix) => r.label.as_deref().is_some_and(|l| l.starts_with(prefix)),
                    None => r.label.is_none(),
                }
        }) && !run_belongs_elsewhere(def, tf, r)
    }) {
        return Some(format!(
            "the collector ran and returned no records (Microsoft-Extractor-Suite run folder {})",
            run.rel_dir
        ));
    }
    if let Some(re) = hawk_re {
        if let Some(line) = tf.hawk_log.iter().find(|l| re.is_match(l)) {
            let first = line.lines().next().unwrap_or_default();
            return Some(format!(
                "the collector ran and returned no records (Hawk.log: {first})"
            ));
        }
    }
    if def.full_ual_covers
        && tf
            .files
            .iter()
            .any(|f| f.shows_run() && FULL_UAL_ARTIFACTS.contains(&f.artifact.as_str()))
    {
        return Some(
            "the collector ran and returned no records (the full unified audit log was collected \
             and holds none; check the collector's -Operations/-RecordType filters)"
                .to_string(),
        );
    }
    None
}

/// The remediation commands, the tenant's collector first.
fn remediation(
    def: &EvidenceDef,
    tf: &TenantFacts,
    retention_days: Option<i64>,
    as_of: DateTime<Utc>,
) -> Option<String> {
    let end = date(as_of);
    let start = match retention_days {
        Some(r) => date(as_of - Duration::days(r)),
        None => tf
            .window_start_ms
            .and_then(from_ms)
            .map(date)
            .unwrap_or_else(|| "<start>".to_string()),
    };
    let fill = |cmd: &str| cmd.replace("{start}", &start).replace("{end}", &end);
    let mes = def
        .invictus
        .map(|c| format!("Microsoft-Extractor-Suite: {}", fill(c)));
    let hawk = def.hawk.map(|c| format!("Hawk: {}", fill(c)));
    let portal = def.portal.map(|p| format!("portal: {p}"));
    let tools = if tf.has_hawk && !tf.has_invictus {
        [hawk, mes, portal]
    } else {
        [mes, hawk, portal]
    };
    let parts: Vec<String> = tools.into_iter().flatten().collect();
    (!parts.is_empty()).then(|| parts.join(" | "))
}

/// Apply the status rules to one (tenant, evidence).
fn evaluate(
    tenant_key: &str,
    def: &EvidenceDef,
    facts: &Facts,
    tf: &TenantFacts,
    cap_defs: &[CapDef],
    hawk_re: Option<&Regex>,
    as_of: DateTime<Utc>,
) -> AvailabilityRow {
    let lic = licence_view(def, tf, cap_defs);
    let retention = lic.retention_days;
    let ev_files: Vec<&FileRow> = tf
        .files
        .iter()
        .filter(|f| any_artifact_matches(def.artifacts, &f.artifact))
        .collect();
    let unparsed = ev_files.iter().filter(|f| f.unparsed()).count();
    // Files that failed to parse count like unparsed ones; for evidence a full unified audit
    // log holds, a failed full-UAL file counts too (its lost records may be this evidence).
    let failed = ev_files.iter().filter(|f| f.failed()).count()
        + if def.full_ual_covers {
            tf.files
                .iter()
                .filter(|f| {
                    f.failed()
                        && FULL_UAL_ARTIFACTS.contains(&f.artifact.as_str())
                        && !any_artifact_matches(def.artifacts, &f.artifact)
                })
                .count()
        } else {
            0
        };
    let unparsed_reason =
        || format!("{unparsed} files collected but not parsed by this Sparrow version");
    let failed_reason =
        || format!("{failed} files failed to parse (see the ingest report / parse_errors)");

    let (status, reason) = if facts.rows > 0 {
        let mut reasons: Vec<String> = Vec::new();
        if facts.truncated {
            reasons.push(
                "an export hit a known export cap (row count equals the cap; results likely truncated)"
                    .to_string(),
            );
        }
        if unparsed > 0 {
            reasons.push(unparsed_reason());
        }
        if failed > 0 {
            reasons.push(failed_reason());
        }
        let handled: Vec<&&FileRow> = ev_files
            .iter()
            .filter(|f| f.shows_run() || f.unparsed() || f.failed())
            .collect();
        let only_hawk = !handled.is_empty() && handled.iter().all(|f| f.tool == "hawk");
        if def.id == "ual" && only_hawk {
            reasons.push("Hawk searches the unified audit log for selected operations only".into());
        }
        if let Some(re) = hawk_re {
            // Per-user Hawk collection is partial unless another collector covered the tenant.
            let other_source = handled.iter().any(|f| f.tool != "hawk")
                || (def.full_ual_covers
                    && tf.files.iter().any(|f| {
                        f.tool != "hawk"
                            && f.shows_run()
                            && FULL_UAL_ARTIFACTS.contains(&f.artifact.as_str())
                    }));
            let users = hawk_users(re, &tf.hawk_log);
            // Spec §7: partial when Hawk's per-user collection covers only some users. Without
            // a user list the coverage is unknown and counts as partial.
            let covers_all = !tf.users.is_empty() && tf.users.iter().all(|u| users.contains(u));
            if !users.is_empty() && !other_source && !covers_all {
                let mut r = format!("Hawk collected it for {} users", users.len());
                if !tf.users.is_empty() {
                    r.push_str(&format!(" of {}", tf.users.len()));
                }
                reasons.push(r);
            }
        }
        if let Some(action) = def.mailbox_action {
            let (known, lacking) = mailbox_action_gap(tf, action);
            if lacking > 0 && lacking < known {
                reasons.push(format!(
                    "{lacking} of {known} mailboxes do not audit {action}"
                ));
            }
        }
        if def.kind == Kind::Event {
            if let (Some(r), Some(start), Some(collected)) =
                (retention, tf.window_start_ms, tf.earliest_collected_ms)
            {
                if start < collected - r * 86_400_000 {
                    reasons.push(format!(
                        "the window starts before the {r}-day retention at collection time"
                    ));
                }
            }
        }
        if reasons.is_empty() {
            ("collected", format!("{} rows", facts.rows))
        } else {
            ("partial", reasons.join("; "))
        }
    } else if lic.licence == Licence::NotLicensed {
        ("not_licensed", lic.basis.clone())
    } else if def.needs_ual && tf.ual_ingestion == Some(false) {
        (
            "not_enabled",
            "unified audit log ingestion is disabled (UnifiedAuditLogIngestionEnabled False)"
                .to_string(),
        )
    } else if def.needs_mailbox_audit && tf.audit_disabled == Some(true) {
        (
            "not_enabled",
            "mailbox auditing is off for the organization (AuditDisabled True)".to_string(),
        )
    } else if let Some((known, action)) = def
        .mailbox_action
        .map(|a| (mailbox_action_gap(tf, a), a))
        .filter(|((known, lacking), _)| *known > 0 && lacking == known)
        .map(|((known, _), a)| (known, a))
    {
        (
            "not_enabled",
            format!(
                "none of the {known} mailboxes audits {action} (DefaultAuditSet customized or audit bypass)"
            ),
        )
    } else if unparsed > 0 || failed > 0 {
        let mut reasons = Vec::new();
        if unparsed > 0 {
            reasons.push(unparsed_reason());
        }
        if failed > 0 {
            reasons.push(failed_reason());
        }
        ("partial", reasons.join("; "))
    } else if let Some(how) = collector_ran(def, tf, &ev_files, hawk_re) {
        ("collected", how)
    } else if let (Kind::Event, Some(r), Some(end)) =
        (def.kind, retention, tf.window_end_ms.and_then(from_ms))
    {
        if end < as_of - Duration::days(r) {
            (
                "beyond_retention",
                format!(
                    "Microsoft keeps it {r} days; the window ended {}",
                    date(end)
                ),
            )
        } else {
            not_collected(def, &lic)
        }
    } else {
        not_collected(def, &lic)
    };

    let mut reason = reason;
    let mut notes: Vec<&str> = def.note.into_iter().collect();
    if def.id == "signins"
        && tf
            .caps
            .get("entra_id_p1")
            .is_some_and(|c| c.status == "not_licensed")
    {
        notes.push("Graph downloads need Entra ID P1/P2; use the Entra portal download.");
    }
    let result_note = (def.id == "signins" && tf.signins_unknown_result > 0).then(|| {
        format!(
            "{} of {} sign-in rows have no result (error code): a Hawk 4 Entra_Sign_In_Log CSV \
             without its JSON twin holds a type name in Status; keep the JSON twin, or use the \
             Entra portal download",
            tf.signins_unknown_result, tf.signins_total
        )
    });
    for n in notes.iter().copied().chain(result_note.as_deref()) {
        reason.push_str("; ");
        reason.push_str(n);
    }

    let remediation = match status {
        "collected" | "not_licensed" | "not_enabled" => None,
        _ => remediation(def, tf, retention, as_of),
    };
    AvailabilityRow {
        tenant_key: tenant_key.to_string(),
        evidence: def.id.to_string(),
        title: def.title.to_string(),
        status: status.to_string(),
        reason,
        remediation,
        rows: facts.rows,
        min_time: facts.min_ms.and_then(from_ms).map(rfc3339),
        max_time: facts.max_ms.and_then(from_ms).map(rfc3339),
        users_covered: facts.users,
        retention_days: retention,
    }
}

/// Rules 8 and 9: unknown when the licence is unknown and nothing baseline provides it, else
/// available but not collected.
fn not_collected(def: &EvidenceDef, lic: &LicenceView) -> (&'static str, String) {
    let exported = if def.facts_sql.is_none() {
        "no collector exports it; "
    } else {
        ""
    };
    if lic.licence == Licence::Unknown && !lic.any_baseline {
        (
            "unknown",
            format!("{exported}licence unknown ({})", lic.basis),
        )
    } else {
        let within = match lic.retention_days {
            Some(r) => format!(" (Microsoft keeps it {r} days)"),
            None => String::new(),
        };
        (
            "available_not_collected",
            format!("{exported}not in the case; it can still be collected{within}"),
        )
    }
}

/// Rewrite `evidence_availability` with `compute(conn, as_of)`. Returns the row count.
pub fn snapshot(conn: &Connection, as_of: DateTime<Utc>) -> Result<usize> {
    let rows = compute(conn, as_of)?;
    conn.execute("DELETE FROM evidence_availability", [])?;
    let evaluated_at = rfc3339(as_of);
    let mut stmt = conn.prepare(
        "INSERT INTO evidence_availability (tenant_key, evidence, title, status, reason, remediation,
             rows, min_time, max_time, users_covered, retention_days, evaluated_at)
         VALUES (?, ?, ?, CAST(? AS availability_status), ?, ?, ?, CAST(? AS TIMESTAMPTZ),
                 CAST(? AS TIMESTAMPTZ), ?, ?, CAST(? AS TIMESTAMPTZ))",
    )?;
    for r in &rows {
        stmt.execute(params![
            r.tenant_key,
            r.evidence,
            r.title,
            r.status,
            r.reason,
            r.remediation,
            r.rows,
            r.min_time,
            r.max_time,
            r.users_covered,
            r.retention_days,
            evaluated_at,
        ])?;
    }
    Ok(rows.len())
}

/// `sparrow capabilities`: per tenant, its identity, domains, capabilities and evidence.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilitiesReport {
    pub as_of: String,
    /// Some collections have no tenant yet (`stale_collections`): the profile failed after an
    /// ingest or has not run since; their evidence is missing from every tenant below.
    pub stale: bool,
    /// Collections with no `tenant_key` (see `profile::unprofiled_collections`).
    pub stale_collections: Vec<i64>,
    pub tenants: Vec<TenantReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantReport {
    pub tenant_key: String,
    pub tenant_id: Option<String>,
    pub tenant_name: Option<String>,
    pub domains: Vec<String>,
    pub capabilities: Vec<TenantCapability>,
    pub evidence: Vec<AvailabilityRow>,
}

/// Evaluate the whole report at `as_of` (read-only).
pub fn capabilities_report(case: &Case, as_of: DateTime<Utc>) -> Result<CapabilitiesReport> {
    let conn = case.conn();
    let tenants: Vec<(String, Option<String>, Option<String>)> = {
        let mut stmt = conn
            .prepare("SELECT tenant_key, tenant_id, tenant_name FROM tenant ORDER BY tenant_key")?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut evidence: HashMap<String, Vec<AvailabilityRow>> = HashMap::new();
    for row in compute(conn, as_of)? {
        evidence
            .entry(row.tenant_key.clone())
            .or_default()
            .push(row);
    }
    let mut out = Vec::with_capacity(tenants.len());
    for (tenant_key, tenant_id, tenant_name) in tenants {
        let domains: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT domain FROM tenant_domains WHERE tenant_key = ? ORDER BY domain",
            )?;
            stmt.query_map(params![tenant_key], |r| r.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        out.push(TenantReport {
            capabilities: tenant_capabilities(conn, &tenant_key)?,
            evidence: evidence.remove(&tenant_key).unwrap_or_default(),
            tenant_key,
            tenant_id,
            tenant_name,
            domains,
        });
    }
    let stale_collections = crate::profile::unprofiled_collections(conn)?;
    Ok(CapabilitiesReport {
        as_of: rfc3339(as_of),
        stale: !stale_collections.is_empty(),
        stale_collections,
        tenants: out,
    })
}
