use sparrow_core::discovery::Tool::{self, Hawk, Invictus};
use sparrow_core::discovery::registry::*;
use std::collections::HashSet;

/// (tool, relative path, expected artifact id, expected subject)
const SAMPLES: &[(Tool, &str, &str, Option<&str>)] = &[
    (Hawk, "Hawk.log", "hawk.log", None),
    (Hawk, "_Investigate.txt", "hawk.investigate_txt", None),
    (
        Hawk,
        "Tenant/_Investigate_Consent_Grants.json",
        "hawk.investigate_file",
        None,
    ),
    (
        Hawk,
        "alice@contoso.example/_Investigate_InboxRules_alice.csv",
        "hawk.investigate_file",
        None,
    ),
    (
        Hawk,
        "Tenant/AdminAuditLogConfig.txt",
        "hawk.tenant.admin_audit_log_config",
        None,
    ),
    (Hawk, "Tenant/OrgConfig.txt", "hawk.tenant.org_config", None),
    (
        Hawk,
        "Tenant/RemoteDomain.json",
        "hawk.tenant.remote_domain",
        None,
    ),
    (
        Hawk,
        "Tenant/TransportRules.csv",
        "hawk.tenant.transport_rules",
        None,
    ),
    (
        Hawk,
        "Tenant/TransportConfig.json",
        "hawk.tenant.transport_config",
        None,
    ),
    (
        Hawk,
        "Tenant/CustomEDiscoveryRoles.csv",
        "hawk.tenant.ediscovery_roles",
        None,
    ),
    (
        Hawk,
        "Tenant/Simple_Admin_Inbox_Rules_Creation.json",
        "hawk.tenant.simple_ual",
        None,
    ),
    (
        Hawk,
        "Tenant/Admin_Inbox_Rules_Creation.json",
        "hawk.tenant.raw_ual",
        None,
    ),
    (
        Hawk,
        "Tenant/Domain_Changes_Audit.csv",
        "hawk.tenant.raw_ual",
        None,
    ),
    (
        Hawk,
        "Tenant/Forwarding_Recipients.csv",
        "hawk.tenant.forwarding_recipients",
        None,
    ),
    (
        Hawk,
        "Tenant/Entra_ID_Application_Audit.json",
        "hawk.tenant.entra_app_audit",
        None,
    ),
    (
        Hawk,
        "Tenant/EntraIDAuditLogs.json",
        "hawk.tenant.entra_audit",
        None,
    ),
    (
        Hawk,
        "Tenant/ExchangeOnlineAdministrators.csv",
        "hawk.tenant.exo_admins",
        None,
    ),
    (
        Hawk,
        "Tenant/EntraIDAdministrators.json",
        "hawk.tenant.entra_admins",
        None,
    ),
    (
        Hawk,
        "Tenant/Consent_Grants.json",
        "hawk.tenant.consent_grants",
        None,
    ),
    (
        Hawk,
        "Tenant/RiskyUsers.json",
        "hawk.tenant.risky_users",
        None,
    ),
    (
        Hawk,
        "Tenant/Risk_Detections.json",
        "hawk.tenant.risk_detections",
        None,
    ),
    (
        Hawk,
        "Tenant/SPNCertsAndSecrets.csv",
        "hawk.tenant.app_credentials",
        None,
    ),
    (
        Hawk,
        "Tenant/EntraIDUsers.json",
        "hawk.tenant.entra_users",
        None,
    ),
    (
        Hawk,
        "Tenant/All_SweepRules.json",
        "hawk.tenant.all_sweep_rules",
        None,
    ),
    (
        Hawk,
        "Tenant/User_ForwardingReport.csv",
        "hawk.tenant.user_forwarding_report",
        None,
    ),
    (Hawk, "Tenant/Hawk_Help.txt", "hawk.tenant.help", None),
    (
        Hawk,
        "alice@contoso.example/Mailbox_Info_alice.txt",
        "hawk.user.mailbox_txt",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/Mailbox_Folder_Statistics_alice.txt",
        "hawk.user.mailbox_stats_txt",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/All_InboxRules_alice.json",
        "hawk.user.inbox_rules",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/SweepRules_alice.csv",
        "hawk.user.sweep_rules",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/ForwardingReport_alice.json",
        "hawk.user.forwarding",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/AutoReply_alice.txt",
        "hawk.user.autoreply",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/Entra_Sign_In_Log_alice@contoso.example_alice.json",
        "hawk.user.entra_signin",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/Converted_Authentication_Logs_alice.csv",
        "hawk.user.converted_auth",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/Raw_Authentication_Logs_alice.json",
        "hawk.user.raw_auth",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/Simple_MailItemsAccessed_alice@contoso.example_alice.json",
        "hawk.user.simple_ual",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/ExchangeItem_Simple_alice.csv",
        "hawk.user.simple_ual",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/MailItemsAccessed_alice@contoso.example_alice.json",
        "hawk.user.raw_ual",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/ExchangeItemGroup_Logs_alice.json",
        "hawk.user.raw_ual",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/Message_Trace_alice.csv",
        "hawk.user.message_trace",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/MobileDevices_alice.json",
        "hawk.user.mobile_devices",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "alice@contoso.example/Have_I_Been_Pwned_alice.txt",
        "hawk.user.hibp",
        Some("alice@contoso.example"),
    ),
    (
        Hawk,
        "203.0.113.7/All_Events_203.0.113.7.json",
        "hawk.ip.events",
        Some("203.0.113.7"),
    ),
    (
        Hawk,
        "2001.db8..1/Unique_Users_Attempted_2001.db8..1.csv",
        "hawk.ip.unique_users",
        Some("2001.db8..1"),
    ),
    (
        Hawk,
        "invoice.msg/Message_Header_RAW_invoice.msg.txt",
        "hawk.message.header_raw",
        Some("invoice.msg"),
    ),
    (
        Hawk,
        "invoice.msg/Message_Header_Findings_invoice.msg.csv",
        "hawk.message.header",
        Some("invoice.msg"),
    ),
    (Hawk, "Tenant/XML/Something.xml", "hawk.xml", None),
    (Invictus, "LogFile.txt", "inv.logfile", None),
    (
        Invictus,
        "Case1/UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv",
        "inv.ual.merged",
        None,
    ),
    (
        Invictus,
        "Case1/UnifiedAuditLog/20260910-100000/UAL-20260901000000-20260902000000.jsonl",
        "inv.ual.window",
        None,
    ),
    (
        Invictus,
        "Mailbox Audit Log/20260910-100000/UnifiedAuditLog/20260910-100001/UAL-20260901000000-20260902000000.csv",
        "inv.ual.window",
        None,
    ),
    (
        Invictus,
        "UnifiedAuditLog/20260910-100000-Hunt/20260910100000-Hunt-UnifiedAuditLog-part2.json",
        "inv.ual.graph",
        None,
    ),
    (
        Invictus,
        "Triage1/UAL-Operations-Combined.csv",
        "inv.quickual.combined",
        None,
    ),
    (
        Invictus,
        "Mailbox Audit Log/20260910-100000-Legacy/202609101000-mailboxAuditLog-alice@contoso.example.csv",
        "inv.mailbox_audit_legacy",
        None,
    ),
    (
        Invictus,
        "MailItemsAccessed/20260910-100000/20260910-100000-MessageIDs-abc.csv",
        "inv.mia.message_ids",
        None,
    ),
    (
        Invictus,
        "MailItemsAccessed/20260910-100000/Sessions-203.0.113.7.csv",
        "inv.mia.sessions",
        None,
    ),
    (
        Invictus,
        "Email Export/20260910-100000/001-20260910_100000-Invoice.eml",
        "inv.email",
        None,
    ),
    (
        Invictus,
        "Email Export/20260910-100000/Attachments/20260910_100000-Invoice-remit.pdf",
        "inv.email.attachment",
        None,
    ),
    (
        Invictus,
        "Sign-In logs/EntraID/20260910-100000-SignInLogs/interactiveUser & nonInteractiveUser/Merged/SignInLogs-interactiveUser-nonInteractiveUser-Combined.json",
        "inv.signins.merged",
        None,
    ),
    (
        Invictus,
        "EntraID/20260910-100000-SignInLogs/servicePrincipal/20260910100001-servicePrincipal-SignInLogs.json",
        "inv.signins",
        None,
    ),
    (
        Invictus,
        "Audit logs/EntraID/20260910-100000-AuditLogs/Merged/AuditLogs-Combined.json",
        "inv.entra_audit.merged",
        None,
    ),
    (
        Invictus,
        "EntraID/20260910-100000-AuditLogs/20260910100001-AuditLogs.json",
        "inv.entra_audit",
        None,
    ),
    (
        Invictus,
        "EntraID/20260910-100000-OAuthPermissions/20260910-100000-OAuthPermissions.csv",
        "inv.oauth",
        None,
    ),
    (
        Invictus,
        "EntraID/20260910-100000-ServicePrincipals/20260910-100000-ServicePrincipals.csv",
        "inv.service_principals",
        None,
    ),
    (
        Invictus,
        "EntraID/20260910-100000-AppRegistrations/20260910-100000-AppRegistrations.csv",
        "inv.app_registrations",
        None,
    ),
    (
        Invictus,
        "Triage1/202609101000-UserApplications.csv",
        "inv.user_applications",
        None,
    ),
    (
        Invictus,
        "Activity Logs/20260910-100000/20260910100000-0000-sub-ActivityLog.json",
        "inv.activity",
        None,
    ),
    (
        Invictus,
        "Directory Activity Logs/20260910-100000/DirectoryActivityLogs.JSON",
        "inv.directory_activity",
        None,
    ),
    (
        Invictus,
        "Users/20260910-100000/20260910-100000-Users.csv",
        "inv.users",
        None,
    ),
    (
        Invictus,
        "Admins/20260910-100000/Merged/20260910-All-Administrators.csv",
        "inv.admins.merged",
        None,
    ),
    (
        Invictus,
        "Admins/20260910-100000/20260910-Global_Administrator.csv",
        "inv.admins",
        None,
    ),
    (
        Invictus,
        "Roles/20260910-100000/20260910-100000-AllRoles.csv",
        "inv.roles.all",
        None,
    ),
    (
        Invictus,
        "Roles/20260910-100000/20260910-100000-PIM-Assignments.csv",
        "inv.roles.pim",
        None,
    ),
    (
        Invictus,
        "MFA/20260910-100000/20260910-100000-AuthenticationMethods.csv",
        "inv.mfa.methods",
        None,
    ),
    (
        Invictus,
        "MFA/20260910-100001/20260910-100001-UserRegistrationDetails.csv",
        "inv.mfa.registration",
        None,
    ),
    (
        Invictus,
        "ConditionalAccessPolicies/20260910-100000/20260910-100000-ConditionalAccessPolicies.csv",
        "inv.ca",
        None,
    ),
    (
        Invictus,
        "Device Information/20260910-100000/20260910-100000-Devices.csv",
        "inv.devices",
        None,
    ),
    (
        Invictus,
        "Groups/20260910-100000/20260910-100000-GroupMembers.csv",
        "inv.group_members",
        None,
    ),
    (
        Invictus,
        "Groups/20260910-100000/20260910-100000-DynamicGroups.csv",
        "inv.dynamic_groups",
        None,
    ),
    (
        Invictus,
        "Groups/20260910-100000/20260910-100000-Groups.csv",
        "inv.groups",
        None,
    ),
    (
        Invictus,
        "RiskyEvents/20260910-100000/20260910-100000-RiskyUsers.csv",
        "inv.risky_users",
        None,
    ),
    (
        Invictus,
        "RiskyEvents/20260910-100000/20260910-100000-RiskyEvents-alice.csv",
        "inv.risk_detections",
        None,
    ),
    (
        Invictus,
        "SecurityAlerts/20260910-100000/20260910-100000-SecurityAlerts.csv",
        "inv.security_alerts",
        None,
    ),
    (
        Invictus,
        "SecureScore/20260910-100000/20260910-100000-SecureScore.csv",
        "inv.secure_score",
        None,
    ),
    (
        Invictus,
        "Licenses/20260910-100000/20260910-100000-TenantLicenses.csv",
        "inv.licenses.tenant",
        None,
    ),
    (
        Invictus,
        "Licenses/20260910-100000/20260910-100000-UserLicenses.csv",
        "inv.licenses.user",
        None,
    ),
    (
        Invictus,
        "Licenses/20260910-100000/20260910-100000-EntraSecurityDefaults.csv",
        "inv.licenses.security_defaults",
        None,
    ),
    (
        Invictus,
        "Audit Status/20260910-100000/20260910-100000-MailboxAuditStatus.csv",
        "inv.audit_status",
        None,
    ),
    (
        Invictus,
        "Rules/20260910-100000/20260910-100000-MailboxRulesGraph.csv",
        "inv.mailbox_rules",
        None,
    ),
    (
        Invictus,
        "Rules/20260910-100000/20260910-100000-TransportRules.csv",
        "inv.transport_rules",
        None,
    ),
    (
        Invictus,
        "MessageTrace/20260910-100000/contoso.example-MTL.csv",
        "inv.message_trace",
        None,
    ),
    (
        Invictus,
        "Mailbox Permissions/20260910-100000/20260910-100000-MailboxPermissions.csv",
        "inv.mailbox_permissions",
        None,
    ),
    (
        Invictus,
        "Triage1/New-InboxRule.json",
        "inv.quickual.operation",
        Some("New-InboxRule"),
    ),
    (
        Invictus,
        "QuickUAL/20260910_100000/MailItemsAccessed.csv",
        "inv.quickual.operation",
        Some("MailItemsAccessed"),
    ),
];

#[test]
fn samples_classify_as_expected() {
    let reg = Registry::builtin();
    for (tool, path, id, subject) in SAMPLES {
        let c = reg
            .classify(*tool, path)
            .unwrap_or_else(|| panic!("no match for {path}"));
        assert_eq!(c.artifact_id, *id, "wrong artifact for {path}");
        assert_eq!(c.subject.as_deref(), *subject, "wrong subject for {path}");
    }
}

#[test]
fn every_definition_has_a_sample_and_ids_are_unique() {
    let reg = Registry::builtin();
    let mut ids = HashSet::new();
    for d in reg.defs() {
        assert!(ids.insert(d.id), "duplicate id {}", d.id);
        assert!(
            SAMPLES.iter().any(|(_, _, id, _)| *id == d.id),
            "definition {} has no sample",
            d.id
        );
    }
}

#[test]
fn classify_normalizes_backslashes_spaces_and_ampersands() {
    let reg = Registry::builtin();
    let c = reg.classify(Hawk, "\\Tenant\\Consent_Grants.json").unwrap();
    assert_eq!(c.artifact_id, "hawk.tenant.consent_grants");
    let c = reg
        .classify(
            Invictus,
            ".\\Sign-In logs\\EntraID\\20260910-100000-SignInLogs\\interactiveUser & nonInteractiveUser\\20260910100001-interactiveUser-nonInteractiveUser-SignInLogs.json",
        )
        .unwrap();
    assert_eq!(c.artifact_id, "inv.signins");
    let c = reg
        .classify(
            Hawk,
            "josé.núñez@contoso.example/InboxRules_josé.núñez.json",
        )
        .unwrap();
    assert_eq!(c.subject.as_deref(), Some("josé.núñez@contoso.example"));
    assert_eq!(
        reg.classify(Hawk, "TENANT/consent_grants.JSON")
            .unwrap()
            .artifact_id,
        "hawk.tenant.consent_grants"
    );
}

#[test]
fn unknown_files_and_wrong_tool_do_not_match() {
    let reg = Registry::builtin();
    assert!(reg.classify(Hawk, "notes/random.bin").is_none());
    assert!(reg.classify(Invictus, "Case1/weird.xyz").is_none());
    assert!(reg.classify(Invictus, "Hawk.log").is_none());
    assert!(reg.classify(Hawk, "LogFile.txt").is_none());
}

#[test]
fn derived_flags_and_targets() {
    let reg = Registry::builtin();
    let simple = reg
        .classify(Hawk, "Tenant/Simple_RBAC_Changes.csv")
        .unwrap();
    assert!(simple.derived);
    assert_eq!(simple.target, "ual_events");
    let raw = reg.classify(Hawk, "Tenant/RBAC_Changes.csv").unwrap();
    assert!(!raw.derived);
    assert_eq!(
        reg.classify(Hawk, "Tenant/Hawk_Help.txt").unwrap().target,
        "none"
    );
}

#[test]
fn normalization_and_formats() {
    assert_eq!(normalize_rel_path(".\\a\\\\b/c.json"), "a/b/c.json");
    assert_eq!(normalize_rel_path("/\\Tenant/x.csv"), "Tenant/x.csv");
    assert_eq!(format_from_path("x/UAL.JSONL"), FileFormat::Jsonl);
    assert_eq!(
        format_from_path("DirectoryActivityLogs.JSON"),
        FileFormat::Json
    );
    assert_eq!(format_from_path("Hawk.log"), FileFormat::Log);
    assert_eq!(format_from_path("a.eml"), FileFormat::Eml);
    assert_eq!(format_from_path("noext"), FileFormat::Unknown);
}
