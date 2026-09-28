//! Collector writers (Tasks 9+) share the `tree` machinery. This module also records which
//! artifacts Sparrow parses today, so a tree can predict `not_supported` for the rest.

pub mod hawk;
pub mod invictus;
pub mod portal;

use crate::events::Day;
use crate::options::{Collector, GenerateOptions};
use crate::world::World;

/// The collection root folder a collector writes (relative to the output directory):
/// portal exports go to `Portal_<tenant folder name>_<collected yyyyMMdd>` (the analyst's
/// folder; Sparrow recognizes portal files by header, so the name is free);
/// Microsoft-Extractor-Suite writes `Output` (`invictus::root`); Hawk 3 and 4
/// `Hawk_<tenant folder name>_<yyyyMMdd_HHmmss>` (`hawk::root`).
pub fn root_name(world: &World, opts: &GenerateOptions) -> String {
    let folder = &world.tenant.folder_name;
    let collected = world.collected_at();
    match opts.collector {
        Collector::Portal => format!("Portal_{folder}_{}", collected.format("%Y%m%d")),
        Collector::Invictus => invictus::root(world, opts),
        Collector::Hawk3 | Collector::Hawk4 => hawk::root(world),
    }
}

/// The events of every UTC day of the collection window (`World::day`), each restricted to
/// `[window_start, window_end)`.
pub fn window_days(world: &World) -> Vec<Day> {
    let (start, end) = (world.window_start(), world.window_end());
    let mut out = Vec::new();
    let mut date = start.date_naive();
    while let Some(first) = date.and_hms_opt(0, 0, 0).map(|t| t.and_utc()) {
        if first >= end {
            break;
        }
        let mut d = world.day(date);
        d.ual.retain(|u| u.time >= start && u.time < end);
        d.signins.retain(|s| s.time >= start && s.time < end);
        d.trace.retain(|t| t.received >= start && t.received < end);
        out.push(d);
        date = match date.succ_opt() {
            Some(n) => n,
            None => break,
        };
    }
    out
}

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
    "inv.activity",
    "inv.admins",
    "inv.admins.merged",
    "inv.app_registrations",
    "inv.audit_status",
    "inv.ca",
    "inv.devices",
    "inv.directory_activity",
    "inv.dynamic_groups",
    "inv.entra_audit",
    "inv.entra_audit.merged",
    "inv.group_members",
    "inv.groups",
    "inv.licenses.security_defaults",
    "inv.licenses.tenant",
    "inv.licenses.user",
    "inv.logfile",
    "inv.mailbox_permissions",
    "inv.message_trace",
    "inv.mfa.methods",
    "inv.mfa.registration",
    "inv.mia.message_ids",
    "inv.mia.sessions",
    "inv.oauth",
    "inv.risk_detections",
    "inv.risky_users",
    "inv.roles.all",
    "inv.roles.pim",
    "inv.secure_score",
    "inv.security_alerts",
    "inv.service_principals",
    "inv.signins",
    "inv.signins.merged",
    "inv.ual.merged",
    "inv.ual.window",
    "inv.user_applications",
    "inv.users",
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
        assert!(parsed_by_sparrow("inv.licenses.tenant"));
        assert!(parsed_by_sparrow("inv.licenses.user"));
        assert!(parsed_by_sparrow("inv.users"));
        assert!(parsed_by_sparrow("inv.admins"));
        assert!(parsed_by_sparrow("inv.admins.merged"));
        assert!(parsed_by_sparrow("inv.roles.all"));
        assert!(parsed_by_sparrow("inv.roles.pim"));
        assert!(parsed_by_sparrow("inv.ca"));
        assert!(parsed_by_sparrow("inv.mfa.methods"));
        assert!(parsed_by_sparrow("inv.mfa.registration"));
        assert!(parsed_by_sparrow("inv.oauth"));
        assert!(parsed_by_sparrow("inv.service_principals"));
        assert!(parsed_by_sparrow("inv.app_registrations"));
        assert!(parsed_by_sparrow("inv.user_applications"));
        assert!(parsed_by_sparrow("inv.devices"));
        assert!(parsed_by_sparrow("inv.groups"));
        assert!(parsed_by_sparrow("inv.group_members"));
        assert!(parsed_by_sparrow("inv.dynamic_groups"));
        assert!(parsed_by_sparrow("inv.risk_detections"));
        assert!(parsed_by_sparrow("inv.risky_users"));
        assert!(parsed_by_sparrow("inv.security_alerts"));
        assert!(parsed_by_sparrow("inv.secure_score"));
        assert!(parsed_by_sparrow("inv.activity"));
        assert!(parsed_by_sparrow("inv.directory_activity"));
    }
}
