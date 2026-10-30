//! Maps collector output files to artifact types (spec §6). Patterns are matched,
//! case-insensitively and in declaration order, against the normalized path relative
//! to the collection root. Named group `subject` captures the user/IP/message/operation.

use crate::discovery::collections::Tool;
use crate::readers::csv_scan::{normalize_headers, read_csv};
use crate::readers::text::decode;
use crate::readers::xlsx::xlsx_headers;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy)]
pub struct ArtifactDef {
    pub id: &'static str,
    pub tool: Tool,
    pub target: &'static str,
    pub derived: bool,
    /// Files with a higher priority are ingested after the other files of their
    /// (raw/derived, JSON/CSV) stage, so a summary that reads an earlier file's ingested row
    /// (Hawk's `Message_Header_Findings_*`) resolves it from the DB. 0 for ordinary files.
    pub priority: i16,
    pub pattern: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Classification {
    pub artifact_id: &'static str,
    pub target: &'static str,
    pub derived: bool,
    pub priority: i16,
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
    Xlsx,
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
            FileFormat::Xlsx => "xlsx",
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
            priority: 0,
            pattern: $pat,
        }
    };
}

/// A definition the ingest orders after its `priority: 0` siblings (see [`ArtifactDef::priority`]).
macro_rules! def_after {
    ($id:literal, $tool:ident, $target:literal, $derived:literal, $pat:literal) => {
        ArtifactDef {
            id: $id,
            tool: Tool::$tool,
            target: $target,
            derived: $derived,
            priority: 1,
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
        r"(?:(?P<subject>[^/]+@[^/]+)/|[^/]+/)?_Investigate_[^/]+\.(?:csv|json|txt)"
    ),
    def!(
        "hawk.psframework_log",
        Hawk,
        "collection_log",
        false,
        r"\d{4}-\d{2}-\d{2}_logs\.csv"
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
        "hawk.tenant.ediscovery_role_assignments",
        Hawk,
        "role_assignments",
        false,
        r"Tenant/EDiscoveryRoleAssignments\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.impersonation",
        Hawk,
        "role_assignments",
        false,
        r"Tenant/Impersonation_(?:Rights|Roles)\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.admin_audit",
        Hawk,
        "admin_audit_events",
        false,
        r"Tenant/(?:New|Set|Remove)_InboxRules\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.all_inbox_rules",
        Hawk,
        "inbox_rules",
        true,
        r"Tenant/All_InboxRules\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.azuread_users",
        Hawk,
        "users",
        false,
        r"Tenant/AzureADUsers\.(?:csv|json)"
    ),
    def!(
        "hawk.tenant.azuread_admins",
        Hawk,
        "role_assignments",
        false,
        r"Tenant/AzureADAdministrators\.(?:csv|json)"
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
        r"Tenant/(?:Entra_ID|Azure)_Application_Audit\.(?:csv|json)"
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
        r"(?P<subject>[^/]+@[^/]+)/(?:ExchangeItem(?:Group)?_Logs|User_Changes|MailItemsAccessed|ExchangeSearchQueries|SendActivity|SharePointSearches|Exchange_UAL_Audit)_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.user.message_trace",
        Hawk,
        "message_trace",
        false,
        r"(?P<subject>[^/]+@[^/]+)/Message_Trace_[^/]+\.(?:csv|json)"
    ),
    def!(
        "hawk.user.mailbox_audit_legacy",
        Hawk,
        "mailbox_audit_legacy",
        false,
        r"(?P<subject>[^/]+@[^/]+)/Exchange_Mailbox_Audit_[^/]+\.(?:csv|json)"
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
    // The findings file reads the sibling `Message_Header_<f>.csv`'s ingested row, so the
    // ingest parses it after its header file (`priority: 1`).
    def_after!(
        "hawk.message.header_findings",
        Hawk,
        "email_artifacts",
        false,
        r"(?P<subject>[^/]+)/Message_Header_Findings_[^/]+\.csv"
    ),
    def!(
        "hawk.message.header",
        Hawk,
        "email_artifacts",
        false,
        r"(?P<subject>[^/]+)/Message_Header_[^/]+\.csv"
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
    // Must stay last: QuickUAL per-operation files have free-form names (`Consent to
    // application_`). It requires the triage-root level QuickUAL writes at (a leading
    // `Triage-.../` directory, or the standalone `QuickUAL/<ts>/` run folder), so a file at the
    // collection root is not claimed; the parser's shape check rejects other triage-root files
    // (an analyst's own CSV/JSON) as not_supported.
    def!(
        "inv.quickual.operation",
        Invictus,
        "ual_events",
        false,
        r"(?:[^/]+/|QuickUAL/\d{8}_\d{6}/)(?P<subject>[^/]+)\.(?:csv|json)"
    ),
];

/// Bytes read from the start of a CSV file to recognize portal exports by their header.
pub const SNIFF_BYTES: usize = 64 * 1024;

/// A portal export recognized by its header row (normalized, lower-case column names).
struct PortalDef {
    id: &'static str,
    target: &'static str,
    columns: &'static [&'static str],
    /// The header must have exactly these columns.
    exact: bool,
    /// Also recognized as an Excel workbook (only exports whose parser reads XLSX rows).
    xlsx: bool,
}

static PORTAL_DEFS: &[PortalDef] = &[
    PortalDef {
        id: "portal.ual",
        target: "ual_events",
        columns: &[
            "recordid",
            "creationdate",
            "recordtype",
            "operation",
            "userid",
            "auditdata",
        ],
        exact: false,
        xlsx: false,
    },
    // The same Purview export with the plural column names (`Operations`, `UserIds`). `RecordId`
    // keeps it apart from Hawk's raw Search-UnifiedAuditLog CSVs, which have no such column.
    PortalDef {
        id: "portal.ual",
        target: "ual_events",
        columns: &[
            "recordid",
            "creationdate",
            "recordtype",
            "operations",
            "userids",
            "auditdata",
        ],
        exact: false,
        xlsx: false,
    },
    // Older Microsoft 365 audit log search export: exactly these four columns. Hawk's raw
    // Search-UnifiedAuditLog CSVs have more (RecordType, ResultIndex, ...), so they never match.
    PortalDef {
        id: "portal.ual",
        target: "ual_events",
        columns: &["creationdate", "userids", "operations", "auditdata"],
        exact: true,
        xlsx: false,
    },
    PortalDef {
        id: "portal.entra_signins",
        target: "signins",
        columns: &["date (utc)", "request id", "user agent", "correlation id"],
        exact: false,
        xlsx: true,
    },
    // Entra admin center > Audit logs > Download (CSV). The sign-in export also has `date (utc)`
    // but has `request id` and no `correlationid`/`activity` columns, so the two never overlap.
    PortalDef {
        id: "portal.entra_audit",
        target: "directory_audits",
        columns: &[
            "date (utc)",
            "correlationid",
            "activity",
            "target1modifiedproperty1name",
        ],
        exact: false,
        xlsx: false,
    },
    PortalDef {
        id: "portal.message_trace",
        target: "message_trace",
        columns: &[
            "origin_timestamp_utc",
            "sender_address",
            "recipient_status",
            "message_id",
        ],
        exact: false,
        xlsx: false,
    },
    // Exchange admin center message trace "extended" (detail) report: one row per delivery event.
    // The summary report has no `event_id` or `source_context`, so the two never overlap.
    PortalDef {
        id: "portal.message_trace_detail",
        target: "message_trace_events",
        columns: &[
            "date_time_utc",
            "network_message_id",
            "event_id",
            "source_context",
        ],
        exact: false,
        xlsx: false,
    },
];

fn portal_by_headers(headers: &HashSet<String>, xlsx: bool) -> Option<Classification> {
    PORTAL_DEFS
        .iter()
        .filter(|d| !xlsx || d.xlsx)
        .find(|d| {
            d.columns.iter().all(|c| headers.contains(*c))
                && (!d.exact || headers.len() == d.columns.len())
        })
        .map(|d| Classification {
            artifact_id: d.id,
            target: d.target,
            derived: false,
            priority: 0,
            subject: None,
        })
}

/// Recognize an analyst portal export (Purview audit search, Entra sign-ins, EAC message
/// trace) from the first bytes of a CSV file, whatever its name or location.
pub fn sniff_portal(head: &[u8]) -> Option<Classification> {
    let decoded = decode(head);
    let first_line = decoded.text.split('\n').next()?.trim_end_matches('\r');
    if first_line.trim().is_empty() {
        return None;
    }
    let headers: HashSet<String> = read_csv(&format!("{first_line}\n"))
        .headers
        .iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    portal_by_headers(&headers, false)
}

/// Recognize the Entra admin center audit log JSON download: a top-level array of Graph
/// `directoryAudit` objects, saved under any name. `head` is the start of the file; its first element must be an
/// object with the three Graph audit keys (case-insensitive).
pub fn sniff_portal_json(head: &[u8]) -> Option<Classification> {
    let decoded = decode(head);
    let rest = decoded
        .text
        .trim_start_matches('\u{feff}')
        .trim_start()
        .strip_prefix('[')?;
    // Only the first element is read; one that is cut off by the end of the head does not parse.
    let first = serde_json::Deserializer::from_str(rest)
        .into_iter::<serde_json::Value>()
        .next()?
        .ok()?;
    let keys: HashSet<String> = first
        .as_object()?
        .keys()
        .map(|k| k.to_ascii_lowercase())
        .collect();
    ["activitydatetime", "loggedbyservice", "targetresources"]
        .iter()
        .all(|k| keys.contains(*k))
        .then_some(Classification {
            artifact_id: "portal.entra_audit",
            target: "directory_audits",
            derived: false,
            priority: 0,
            subject: None,
        })
}

/// Recognize a portal export saved as an Excel workbook from its first sheet's header row.
/// `bytes` must be the whole file (the header row is inside the zip). Only exports whose
/// parser reads workbooks (`PortalDef::xlsx`) match; empty header cells are ignored.
pub fn sniff_portal_xlsx(bytes: &[u8]) -> Option<Classification> {
    let raw = xlsx_headers(bytes)?;
    let named = raw
        .iter()
        .map(String::as_str)
        .filter(|h| !h.trim().is_empty());
    let headers: HashSet<String> = normalize_headers(named)
        .into_iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    portal_by_headers(&headers, true)
}

fn read_head(abs: &Path) -> Option<Vec<u8>> {
    let file = std::fs::File::open(abs).ok()?;
    let mut buf = Vec::new();
    file.take(SNIFF_BYTES as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

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
                    priority: d.priority,
                    subject: c.name("subject").map(|m| m.as_str().to_string()),
                })
            })
    }

    /// Classify a file given its head: CSV portal exports are recognized by the header in the
    /// first `SNIFF_BYTES`, XLSX ones by their first sheet's header row (`head` is then the
    /// whole file), under any tool; then `tool`'s path patterns apply, and a JSON file they leave
    /// unclassified is sniffed for the Entra audit log download.
    pub fn classify_with_head(
        &self,
        tool: Tool,
        rel_path: &str,
        head: Option<&[u8]>,
    ) -> Option<Classification> {
        let sniffed = match format_from_path(rel_path) {
            FileFormat::Csv => head.and_then(sniff_portal),
            FileFormat::Xlsx => head.and_then(sniff_portal_xlsx),
            _ => None,
        };
        if let Some(c) = sniffed {
            return Some(c);
        }
        // JSON: path patterns win; only a file no pattern classifies is sniffed.
        let by_path = self.classify(tool, rel_path);
        if by_path.is_none() && format_from_path(rel_path) == FileFormat::Json {
            return head.and_then(sniff_portal_json);
        }
        by_path
    }

    /// `classify_with_head`, reading the head of CSV and JSON files (the whole of XLSX files) from `abs`.
    /// An XLSX larger than `ingest::DEFAULT_MAX_FILE_BYTES` is not read: it is classified by
    /// path alone (ingest then refuses it by size).
    pub fn classify_file(&self, tool: Tool, rel_path: &str, abs: &Path) -> Option<Classification> {
        let head = match format_from_path(rel_path) {
            FileFormat::Csv => read_head(abs),
            // A path pattern owns its JSON files; only the others are sniffed.
            FileFormat::Json if self.classify(tool, rel_path).is_none() => read_head(abs),
            FileFormat::Xlsx => std::fs::metadata(abs)
                .is_ok_and(|m| m.len() <= crate::ingest::DEFAULT_MAX_FILE_BYTES)
                .then(|| std::fs::read(abs).ok())
                .flatten(),
            _ => None,
        };
        self.classify_with_head(tool, rel_path, head.as_deref())
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
        "xlsx" => FileFormat::Xlsx,
        _ => FileFormat::Unknown,
    }
}
