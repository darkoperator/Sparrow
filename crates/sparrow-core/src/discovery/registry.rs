//! Maps collector output files to artifact types (spec §6). Patterns are matched,
//! case-insensitively and in declaration order, against the normalized path relative
//! to the collection root. Named group `subject` captures the user/IP/message/operation.

use crate::discovery::collections::Tool;
use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy)]
pub struct ArtifactDef {
    pub id: &'static str,
    pub tool: Tool,
    pub target: &'static str,
    pub derived: bool,
    pub pattern: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Classification {
    pub artifact_id: &'static str,
    pub target: &'static str,
    pub derived: bool,
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileFormat {
    Json,
    Jsonl,
    Csv,
    Txt,
    Log,
    Eml,
    Xml,
    Unknown,
}

impl FileFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            FileFormat::Json => "json",
            FileFormat::Jsonl => "jsonl",
            FileFormat::Csv => "csv",
            FileFormat::Txt => "txt",
            FileFormat::Log => "log",
            FileFormat::Eml => "eml",
            FileFormat::Xml => "xml",
            FileFormat::Unknown => "unknown",
        }
    }
}

macro_rules! def {
    ($id:literal, $tool:ident, $target:literal, $derived:literal, $pat:literal) => {
        ArtifactDef {
            id: $id,
            tool: Tool::$tool,
            target: $target,
            derived: $derived,
            pattern: $pat,
        }
    };
}

// Fragments used below (written out in full because patterns are literals):
//   Hawk user folder:     (?P<subject>[^/]+@[^/]+)/
//   Invictus project:     (?:[^/]+/)?
//   Invictus date folder: \d{8}-\d{6}(?:-[^/]+)?/
static DEFS: &[ArtifactDef] = &[
    // ---------------- Hawk ----------------
    def!("hawk.log", Hawk, "collection_log", false, r"Hawk\.log"),
    def!(
        "hawk.investigate_txt",
        Hawk,
        "collector_flags",
        false,
        r"_Investigate\.txt"
    ),
    def!(
        "hawk.investigate_file",
        Hawk,
        "collector_flags",
        false,
        r"(?:[^/]+/)?_Investigate_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.admin_audit_log_config",
        Hawk,
        "audit_config",
        false,
        r"Tenant/AdminAuditLogConfig\.txt"
    ),
    def!(
        "hawk.tenant.org_config",
        Hawk,
        "audit_config",
        false,
        r"Tenant/OrgConfig\.txt"
    ),
    def!(
        "hawk.tenant.remote_domain",
        Hawk,
        "remote_domains",
        false,
        r"Tenant/RemoteDomain\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.transport_rules",
        Hawk,
        "transport_rules",
        false,
        r"Tenant/TransportRules\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.transport_config",
        Hawk,
        "tenant_settings",
        false,
        r"Tenant/TransportConfig\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.ediscovery_roles",
        Hawk,
        "role_assignments",
        false,
        r"Tenant/(?:Custom)?EDiscoveryRoles\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.simple_ual",
        Hawk,
        "ual_events",
        true,
        r"Tenant/Simple_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.raw_ual",
        Hawk,
        "ual_events",
        false,
        r"Tenant/(?:eDiscoveryLogs|Admin_Inbox_Rules_(?:Creation|Modification|Removal)|Mailbox_Permission_Change|Forwarding_Changes|RBAC_Changes|Domain_Changes_Audit)\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.forwarding_recipients",
        Hawk,
        "none",
        true,
        r"Tenant/Forwarding_Recipients\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.entra_app_audit",
        Hawk,
        "ual_events",
        false,
        r"Tenant/Entra_ID_Application_Audit\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.entra_audit",
        Hawk,
        "directory_audits",
        false,
        r"Tenant/EntraIDAuditLogs\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.exo_admins",
        Hawk,
        "role_assignments",
        false,
        r"Tenant/ExchangeOnlineAdministrators\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.entra_admins",
        Hawk,
        "role_assignments",
        false,
        r"Tenant/EntraIDAdministrators\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.consent_grants",
        Hawk,
        "oauth_grants",
        false,
        r"Tenant/Consent_Grants\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.risky_users",
        Hawk,
        "risky_users",
        false,
        r"Tenant/RiskyUsers\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.risk_detections",
        Hawk,
        "risk_detections",
        false,
        r"Tenant/Risk_Detections\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.app_credentials",
        Hawk,
        "app_credentials",
        false,
        r"Tenant/(?:SPN|Application)CertsAndSecrets\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.entra_users",
        Hawk,
        "users",
        false,
        r"Tenant/EntraIDUsers\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.all_sweep_rules",
        Hawk,
        "inbox_rules",
        true,
        r"Tenant/All_SweepRules\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.user_forwarding_report",
        Hawk,
        "mailboxes",
        true,
        r"Tenant/User_ForwardingReport\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.help",
        Hawk,
        "none",
        false,
        r"Tenant/Hawk_Help\.txt"
    ),
    def!(
        "hawk.user.mailbox_txt",
        Hawk,
        "mailboxes",
        false,
        r"(?P<subject>[^/]+@[^/]+)/(?:CAS_)?Mailbox_Info_[^/]+\.txt"
    ),
    def!(
        "hawk.user.mailbox_stats_txt",
        Hawk,
        "text_artifacts",
        false,
        r"(?P<subject>[^/]+@[^/]+)/Mailbox_(?:Folder_|Archive_)?Statistics_[^/]+\.txt"
    ),
    def!(
        "hawk.user.inbox_rules",
        Hawk,
        "inbox_rules",
        false,
        r"(?P<subject>[^/]+@[^/]+)/(?:All_)?InboxRules_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.user.sweep_rules",
        Hawk,
        "inbox_rules",
        false,
        r"(?P<subject>[^/]+@[^/]+)/SweepRules_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.user.forwarding",
        Hawk,
        "mailboxes",
        false,
        r"(?P<subject>[^/]+@[^/]+)/ForwardingReport_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.user.autoreply",
        Hawk,
        "mailboxes",
        false,
        r"(?P<subject>[^/]+@[^/]+)/AutoReply_[^/]+\.txt"
    ),
    def!(
        "hawk.user.entra_signin",
        Hawk,
        "signins",
        false,
        r"(?P<subject>[^/]+@[^/]+)/Entra_Sign_In_Log_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.user.converted_auth",
        Hawk,
        "ual_events",
        true,
        r"(?P<subject>[^/]+@[^/]+)/Converted_Authentication_Logs_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.user.raw_auth",
        Hawk,
        "ual_events",
        false,
        r"(?P<subject>[^/]+@[^/]+)/(?:Raw|Failed_Conversion)_Authentication_Logs_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.user.simple_ual",
        Hawk,
        "ual_events",
        true,
        r"(?P<subject>[^/]+@[^/]+)/(?:Simple_[^/]+|ExchangeItem(?:Group)?_Simple_[^/]+)\.(?:csv|json)"
    ),
    def!(
        "hawk.user.raw_ual",
        Hawk,
        "ual_events",
        false,
        r"(?P<subject>[^/]+@[^/]+)/(?:ExchangeItem(?:Group)?_Logs|User_Changes|MailItemsAccessed|ExchangeSearchQueries|SendActivity|SharePointSearches)_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.user.message_trace",
        Hawk,
        "message_trace",
        false,
        r"(?P<subject>[^/]+@[^/]+)/Message_Trace_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.user.mobile_devices",
        Hawk,
        "mobile_devices",
        false,
        r"(?P<subject>[^/]+@[^/]+)/MobileDevices_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.user.hibp",
        Hawk,
        "text_artifacts",
        false,
        r"(?P<subject>[^/]+@[^/]+)/Have_I_Been_Pwned_[^/]+\.txt"
    ),
    def!(
        "hawk.ip.events",
        Hawk,
        "ual_events",
        false,
        r"(?P<subject>[0-9A-Fa-f.]+)/(?:All|Success)_Events_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.ip.unique_users",
        Hawk,
        "ual_events",
        true,
        r"(?P<subject>[0-9A-Fa-f.]+)/Unique_Users_Attempted_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.message.header_raw",
        Hawk,
        "none",
        false,
        r"(?P<subject>[^/]+)/Message_Header_RAW_[^/]+\.txt"
    ),
    def!(
        "hawk.message.header",
        Hawk,
        "email_artifacts",
        false,
        r"(?P<subject>[^/]+)/Message_Header(?:_Findings)?_[^/]+\.csv"
    ),
    def!(
        "hawk.xml",
        Hawk,
        "none",
        false,
        r"(?:[^/]+/)?XML/[^/]+\.xml"
    ),
    // ---------------- Microsoft-Extractor-Suite (Invictus) ----------------
    def!(
        "inv.logfile",
        Invictus,
        "collection_log",
        false,
        r"(?:[^/]+/)?LogFile\.txt"
    ),
    def!(
        "inv.ual.merged",
        Invictus,
        "ual_events",
        true,
        r"(?:[^/]+/)?UnifiedAuditLog/\d{8}-\d{6}(?:-[^/]+)?/Merged/UAL-Combined\.(?:csv|json|jsonl)"
    ),
    def!(
        "inv.ual.window",
        Invictus,
        "ual_events",
        false,
        r"(?:.+/)?UnifiedAuditLog/\d{8}-\d{6}(?:-[^/]+)?/UAL-\d{14}-\d{14}\.(?:csv|json|jsonl)"
    ),
    def!(
        "inv.ual.graph",
        Invictus,
        "ual_events",
        false,
        r"(?:[^/]+/)?UnifiedAuditLog/\d{8}-\d{6}(?:-[^/]+)?/\d{14}-[^/]+-UnifiedAuditLog(?:-part\d+)?\.(?:csv|json|jsonl)"
    ),
    def!(
        "inv.quickual.combined",
        Invictus,
        "ual_events",
        true,
        r"(?:[^/]+/)?(?:QuickUAL/\d{8}_\d{6}/)?UAL-Operations-Combined\.(?:csv|json)"
    ),
    def!(
        "inv.mailbox_audit_legacy",
        Invictus,
        "mailbox_audit_legacy",
        false,
        r"(?:[^/]+/)?Mailbox Audit Log/\d{8}-\d{6}-Legacy/\d{12}-mailboxAuditLog-[^/]+\.csv"
    ),
    def!(
        "inv.mia.message_ids",
        Invictus,
        "mail_items_accessed",
        true,
        r"(?:[^/]+/)?MailItemsAccessed/\d{8}-\d{6}(?:-[^/]+)?/[^/]*MessageIDs[^/]*\.csv"
    ),
    def!(
        "inv.mia.sessions",
        Invictus,
        "ual_events",
        true,
        r"(?:[^/]+/)?MailItemsAccessed/\d{8}-\d{6}(?:-[^/]+)?/[^/]*Sessions[^/]*\.csv"
    ),
    def!(
        "inv.email",
        Invictus,
        "email_artifacts",
        false,
        r"(?:[^/]+/)?(?:Email Export|MailItemsAccessed)/\d{8}-\d{6}(?:-[^/]+)?/[^/]+\.(?:eml|txt)"
    ),
    def!(
        "inv.email.attachment",
        Invictus,
        "none",
        false,
        r"(?:[^/]+/)?(?:Email Export|MailItemsAccessed)/\d{8}-\d{6}(?:-[^/]+)?/(?:Attachments/)?[^/]+"
    ),
    def!(
        "inv.signins.merged",
        Invictus,
        "signins",
        true,
        r"(?:[^/]+/)?(?:Sign-In logs/)?EntraID/\d{8}-\d{6}-SignInLogs/[^/]+/Merged/[^/]+\.json"
    ),
    def!(
        "inv.signins",
        Invictus,
        "signins",
        false,
        r"(?:[^/]+/)?(?:Sign-In logs/)?EntraID/\d{8}-\d{6}-SignInLogs/[^/]+/\d{14}-[^/]+-SignInLogs\.json"
    ),
    def!(
        "inv.entra_audit.merged",
        Invictus,
        "directory_audits",
        true,
        r"(?:[^/]+/)?(?:Audit logs/)?EntraID/\d{8}-\d{6}-AuditLogs/Merged/[^/]+\.json"
    ),
    def!(
        "inv.entra_audit",
        Invictus,
        "directory_audits",
        false,
        r"(?:[^/]+/)?(?:Audit logs/)?EntraID/\d{8}-\d{6}-AuditLogs/\d{14}-AuditLogs\.json"
    ),
    def!(
        "inv.oauth",
        Invictus,
        "oauth_grants",
        false,
        r"(?:[^/]+/)?EntraID/\d{8}-\d{6}-OAuthPermissions/\d{8}-\d{6}-OAuthPermissions\.csv"
    ),
    def!(
        "inv.service_principals",
        Invictus,
        "applications",
        false,
        r"(?:[^/]+/)?EntraID/\d{8}-\d{6}-ServicePrincipals/\d{8}-\d{6}-ServicePrincipals\.csv"
    ),
    def!(
        "inv.app_registrations",
        Invictus,
        "applications",
        false,
        r"(?:[^/]+/)?EntraID/\d{8}-\d{6}-AppRegistrations/\d{8}-\d{6}-AppRegistrations\.csv"
    ),
    def!(
        "inv.user_applications",
        Invictus,
        "applications",
        false,
        r"(?:[^/]+/)?(?:Applications/)?\d{12}-UserApplications\.csv"
    ),
    def!(
        "inv.activity",
        Invictus,
        "azure_activity",
        false,
        r"(?:[^/]+/)?Activity Logs/\d{8}-\d{6}(?:-[^/]+)?/\d{14}-[^/]+-ActivityLog\.json"
    ),
    def!(
        "inv.directory_activity",
        Invictus,
        "azure_activity",
        false,
        r"(?:[^/]+/)?Directory Activity Logs/\d{8}-\d{6}(?:-[^/]+)?/(?:\d{14}-)?DirectoryActivityLogs\.(?:csv|json|jsonl)"
    ),
    def!(
        "inv.users",
        Invictus,
        "users",
        false,
        r"(?:[^/]+/)?Users/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-Users\.csv"
    ),
    def!(
        "inv.admins.merged",
        Invictus,
        "role_assignments",
        true,
        r"(?:[^/]+/)?Admins/\d{8}-\d{6}(?:-[^/]+)?/Merged/\d{8}-All-Administrators\.csv"
    ),
    def!(
        "inv.admins",
        Invictus,
        "role_assignments",
        false,
        r"(?:[^/]+/)?Admins/\d{8}-\d{6}(?:-[^/]+)?/\d{8}-[^/]+\.csv"
    ),
    def!(
        "inv.roles.all",
        Invictus,
        "role_assignments",
        false,
        r"(?:[^/]+/)?Roles/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-AllRoles\.csv"
    ),
    def!(
        "inv.roles.pim",
        Invictus,
        "role_assignments",
        false,
        r"(?:[^/]+/)?Roles/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-PIM-Assignments\.csv"
    ),
    def!(
        "inv.mfa.methods",
        Invictus,
        "mfa_registration",
        false,
        r"(?:[^/]+/)?MFA/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-AuthenticationMethods\.csv"
    ),
    def!(
        "inv.mfa.registration",
        Invictus,
        "mfa_registration",
        false,
        r"(?:[^/]+/)?MFA/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-UserRegistrationDetails\.csv"
    ),
    def!(
        "inv.ca",
        Invictus,
        "ca_policies",
        false,
        r"(?:[^/]+/)?ConditionalAccessPolicies/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-ConditionalAccessPolicies\.csv"
    ),
    def!(
        "inv.devices",
        Invictus,
        "devices",
        false,
        r"(?:[^/]+/)?Device Information/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-Devices\.csv"
    ),
    def!(
        "inv.group_members",
        Invictus,
        "group_members",
        false,
        r"(?:[^/]+/)?Groups/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-GroupMembers\.csv"
    ),
    def!(
        "inv.dynamic_groups",
        Invictus,
        "groups",
        false,
        r"(?:[^/]+/)?Groups/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-DynamicGroups\.csv"
    ),
    def!(
        "inv.groups",
        Invictus,
        "groups",
        false,
        r"(?:[^/]+/)?Groups/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-Groups\.csv"
    ),
    def!(
        "inv.risky_users",
        Invictus,
        "risky_users",
        false,
        r"(?:[^/]+/)?RiskyEvents/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-RiskyUsers[^/]*\.csv"
    ),
    def!(
        "inv.risk_detections",
        Invictus,
        "risk_detections",
        false,
        r"(?:[^/]+/)?RiskyEvents/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-RiskyEvents[^/]*\.csv"
    ),
    def!(
        "inv.security_alerts",
        Invictus,
        "security_alerts",
        false,
        r"(?:[^/]+/)?SecurityAlerts/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-SecurityAlerts\.csv"
    ),
    def!(
        "inv.secure_score",
        Invictus,
        "secure_score",
        false,
        r"(?:[^/]+/)?SecureScore/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-SecureScore\.csv"
    ),
    def!(
        "inv.licenses.tenant",
        Invictus,
        "licenses",
        false,
        r"(?:[^/]+/)?Licenses/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-TenantLicenses\.csv"
    ),
    def!(
        "inv.licenses.user",
        Invictus,
        "user_licenses",
        false,
        r"(?:[^/]+/)?Licenses/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-UserLicenses\.csv"
    ),
    def!(
        "inv.licenses.security_defaults",
        Invictus,
        "tenant_settings",
        false,
        r"(?:[^/]+/)?Licenses/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-EntraSecurityDefaults\.csv"
    ),
    def!(
        "inv.audit_status",
        Invictus,
        "mailboxes",
        false,
        r"(?:[^/]+/)?Audit Status/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-MailboxAuditStatus\.csv"
    ),
    def!(
        "inv.mailbox_rules",
        Invictus,
        "inbox_rules",
        false,
        r"(?:[^/]+/)?Rules/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-MailboxRules(?:Graph)?\.csv"
    ),
    def!(
        "inv.transport_rules",
        Invictus,
        "transport_rules",
        false,
        r"(?:[^/]+/)?Rules/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-TransportRules\.csv"
    ),
    def!(
        "inv.message_trace",
        Invictus,
        "message_trace",
        false,
        r"(?:[^/]+/)?MessageTrace/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-(?:MessageTrace|MTL)\.csv"
    ),
    def!(
        "inv.mailbox_permissions",
        Invictus,
        "mailbox_permissions",
        false,
        r"(?:[^/]+/)?Mailbox Permissions/\d{8}-\d{6}(?:-[^/]+)?/[^/]+-MailboxPermissions\.csv"
    ),
    // Must stay last: QuickUAL per-operation files have free-form names.
    def!(
        "inv.quickual.operation",
        Invictus,
        "ual_events",
        false,
        r"(?:[^/]+/)?(?:QuickUAL/\d{8}_\d{6}/)?(?P<subject>[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)\.(?:csv|json)"
    ),
];

pub struct Registry {
    entries: Vec<(&'static ArtifactDef, Regex)>,
}

impl Registry {
    pub fn builtin() -> &'static Registry {
        static R: OnceLock<Registry> = OnceLock::new();
        R.get_or_init(|| Registry::new(DEFS))
    }

    fn new(defs: &'static [ArtifactDef]) -> Registry {
        let entries = defs
            .iter()
            .map(|d| {
                let re = Regex::new(&format!("(?i)^(?:{})$", d.pattern))
                    .unwrap_or_else(|e| panic!("invalid pattern for {}: {e}", d.id));
                (d, re)
            })
            .collect();
        Registry { entries }
    }

    pub fn defs(&self) -> impl Iterator<Item = &'static ArtifactDef> + '_ {
        self.entries.iter().map(|(d, _)| *d)
    }

    pub fn classify(&self, tool: Tool, rel_path: &str) -> Option<Classification> {
        let norm = normalize_rel_path(rel_path);
        self.entries
            .iter()
            .filter(|(d, _)| d.tool == tool)
            .find_map(|(d, re)| {
                re.captures(&norm).map(|c| Classification {
                    artifact_id: d.id,
                    target: d.target,
                    derived: d.derived,
                    subject: c.name("subject").map(|m| m.as_str().to_string()),
                })
            })
    }
}

pub fn normalize_rel_path(p: &str) -> String {
    let replaced = p.replace('\\', "/");
    let mut s = replaced.as_str();
    loop {
        if let Some(rest) = s.strip_prefix("./") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix('/') {
            s = rest;
        } else {
            break;
        }
    }
    let mut out = String::with_capacity(s.len());
    let mut prev_slash = false;
    for ch in s.chars() {
        if ch == '/' {
            if prev_slash {
                continue;
            }
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        out.push(ch);
    }
    out
}

pub fn format_from_path(p: &str) -> FileFormat {
    let ext = p
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    if ext.contains('/') {
        return FileFormat::Unknown;
    }
    match ext.as_str() {
        "json" => FileFormat::Json,
        "jsonl" => FileFormat::Jsonl,
        "csv" => FileFormat::Csv,
        "txt" => FileFormat::Txt,
        "log" => FileFormat::Log,
        "eml" => FileFormat::Eml,
        "xml" => FileFormat::Xml,
        _ => FileFormat::Unknown,
    }
}
