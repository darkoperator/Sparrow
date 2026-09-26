//! Collector writers (Tasks 9+) share the `tree` machinery. This module also records which
//! artifacts Sparrow parses today, so a tree can predict `not_supported` for the rest.

/// Every artifact id Sparrow registers a parser for (`sparrow_core::parsers::*::register`,
/// including `ual::UAL_ARTIFACTS`), sorted. Copied by hand, not read from Sparrow (oracle
/// independence); parser tasks add the ids they register, keeping the list sorted.
pub const SPARROW_PARSED: &[&str] = &[
    "hawk.investigate_file",
    "hawk.investigate_txt",
    "hawk.ip.events",
    "hawk.log",
    "hawk.psframework_log",
    "hawk.tenant.admin_audit",
    "hawk.tenant.admin_audit_log_config",
    "hawk.tenant.all_inbox_rules",
    "hawk.tenant.all_sweep_rules",
    "hawk.tenant.app_credentials",
    "hawk.tenant.azuread_admins",
    "hawk.tenant.azuread_users",
    "hawk.tenant.consent_grants",
    "hawk.tenant.ediscovery_role_assignments",
    "hawk.tenant.ediscovery_roles",
    "hawk.tenant.entra_admins",
    "hawk.tenant.entra_app_audit",
    "hawk.tenant.entra_audit",
    "hawk.tenant.entra_users",
    "hawk.tenant.exo_admins",
    "hawk.tenant.impersonation",
    "hawk.tenant.org_config",
    "hawk.tenant.raw_ual",
    "hawk.tenant.remote_domain",
    "hawk.tenant.risk_detections",
    "hawk.tenant.risky_users",
    "hawk.tenant.simple_ual",
    "hawk.tenant.transport_config",
    "hawk.tenant.transport_rules",
    "hawk.tenant.user_forwarding_report",
    "hawk.user.autoreply",
    "hawk.user.converted_auth",
    "hawk.user.entra_signin",
    "hawk.user.forwarding",
    "hawk.user.inbox_rules",
    "hawk.user.mailbox_audit_legacy",
    "hawk.user.mailbox_txt",
    "hawk.user.message_trace",
    "hawk.user.mobile_devices",
    "hawk.user.raw_auth",
    "hawk.user.raw_ual",
    "hawk.user.simple_ual",
    "hawk.user.sweep_rules",
    "inv.audit_status",
    "inv.entra_audit",
    "inv.entra_audit.merged",
    "inv.licenses.security_defaults",
    "inv.logfile",
    "inv.mailbox_permissions",
    "inv.message_trace",
    "inv.mia.message_ids",
    "inv.mia.sessions",
    "inv.signins",
    "inv.signins.merged",
    "inv.ual.merged",
    "inv.ual.window",
    "portal.entra_signins",
    "portal.message_trace",
    "portal.ual",
];

/// Whether Sparrow has a parser for `artifact` (otherwise its files are `not_supported`).
pub fn parsed_by_sparrow(artifact: &str) -> bool {
    SPARROW_PARSED.binary_search(&artifact).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_sorted_and_unique() {
        assert!(SPARROW_PARSED.windows(2).all(|w| w[0] < w[1]));
        assert!(parsed_by_sparrow("hawk.tenant.raw_ual"));
        assert!(!parsed_by_sparrow("hawk.tenant.help"));
        assert!(!parsed_by_sparrow("inv.licenses.tenant"));
    }
}
