use sparrow_synth::reserved::{is_reserved_domain, is_reserved_ip};
use sparrow_synth::scenario::{builtin_names, load};
use sparrow_synth::world::World;
use std::collections::BTreeSet;

fn world(name: &str, seed: u64) -> World {
    World::build(&load(name).unwrap(), seed).unwrap()
}

#[test]
fn same_seed_same_world_other_seed_other_ids() {
    let a = world("bec-aitm", 42);
    let b = world("bec-aitm", 42);
    let c = world("bec-aitm", 43);
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
    assert_ne!(a.tenant.tenant_id, c.tenant.tenant_id);
}

#[test]
fn people_and_mailboxes_are_consistent() {
    let w = world("bec-aitm", 1);
    assert_eq!(w.users.len(), 12);
    assert_eq!(w.admins.len(), 1);
    let upns: BTreeSet<&str> = w.all_people().map(|u| u.upn.as_str()).collect();
    assert_eq!(upns.len(), 13);
    for u in w.all_people() {
        assert!(u.upn.ends_with("@contoso.example"), "{}", u.upn);
        assert!(w.mailboxes.contains_key(&u.upn), "{}", u.upn);
        assert!(is_reserved_ip(&u.office_ip) && is_reserved_ip(&u.home_ip));
        assert_eq!(u.puid.len(), 16);
    }
    assert!(
        w.mailboxes
            .values()
            .any(|m| m.recipient_type == "DiscoveryMailbox" && !m.audit_enabled)
    );
    assert!(is_reserved_domain(&w.tenant.initial_domain));
    assert_eq!(w.tenant.folder_name, "Contoso_Example");
}

#[test]
fn audit_profiles_shape_mailbox_audit_lists() {
    let gaps = world("bec-e3-audit-gaps", 1);
    let m = &gaps.mailboxes[&gaps.user(1).upn];
    assert!(
        !m.audit_owner
            .iter()
            .any(|a| a == "MailItemsAccessed" || a == "Send")
    );
    assert_eq!(m.default_audit_set, ["Admin", "Delegate"]);
    let aitm = world("bec-aitm", 1);
    let m = &aitm.mailboxes[&aitm.user(3).upn];
    assert!(m.audit_owner.iter().any(|a| a == "MailItemsAccessed"));
    assert_eq!(m.default_audit_set, ["Admin", "Delegate", "Owner"]);
    let off = world("business-basic", 1);
    assert!(off.audit.org_audit_disabled);
}

#[test]
fn attacker_infrastructure_is_distinct_from_users() {
    let w = world("bec-aitm", 7);
    let homes: BTreeSet<&str> = w.all_people().map(|u| u.home.city.as_str()).collect();
    assert!(!homes.contains(w.attacker.location.city.as_str()));
    assert_ne!(w.attacker.proxy_ip, w.attacker.replay_ip);
    assert!(w.attacker.forward_address.ends_with(".test"));
}

/// Every Exchange Online tenant has the `Default` remote domain (`DomainName *`); a partner
/// remote domain is added so `Get-RemoteDomain` returns several records (an array).
#[test]
fn the_tenant_has_a_default_and_a_partner_remote_domain() {
    let w = world("bec-aitm", 3);
    assert_eq!(w.remote_domains.len(), 2, "{:?}", w.remote_domains);
    assert!(w.remote_domains.iter().any(|d| d.domain == "*"));
    assert!(w.remote_domains.iter().any(|d| d.domain == "fabrikam.test"));
    assert!(
        w.remote_domains
            .iter()
            .all(|d| is_reserved_domain(&d.domain) || d.domain == "*")
    );
}

/// The survey saw 3–6 eDiscovery role assignments; the world holds a realistic set to three or
/// more principals.
#[test]
fn ediscovery_role_assignments_cover_three_principals() {
    let w = world("bec-aitm", 3);
    assert!(
        w.exchange_role_assignments.len() >= 3,
        "{:?}",
        w.exchange_role_assignments
    );
    let groups: BTreeSet<&str> = w
        .exchange_role_assignments
        .iter()
        .map(|a| a.group.as_str())
        .collect();
    assert!(groups.len() >= 3, "{groups:?}");
}

#[test]
fn every_state_collection_is_populated() {
    let w = world("bec-aitm", 3);
    assert!(!w.apps.is_empty() && !w.grants.is_empty() && !w.roles.is_empty());
    assert!(!w.ca_policies.is_empty() && !w.devices.is_empty() && !w.groups.is_empty());
    let mfa_policy = w
        .ca_policies
        .iter()
        .find(|p| p.display_name == "Require MFA for admins")
        .unwrap();
    assert_eq!(mfa_policy.include_roles, ["Global Administrator"]);
    assert!(mfa_policy.include_users.is_empty());
    assert!(!w.mobile_devices.is_empty() && !w.transport_rules.is_empty());
    assert!(!w.remote_domains.is_empty() && w.secure_score.len() == 8 && !w.alerts.is_empty());
    assert!(!w.azure.is_empty() && w.azure.iter().all(|e| e.operation.contains('/')));
    assert!(w.mfa.values().any(|m| !m.is_mfa_registered));
    let rule = w.inbox_rules.first().unwrap();
    assert!(rule.description().starts_with("If the message:\r\n\t"));
}

/// A normal tenant of any built-in plan has auditing on: the organisation's mailbox auditing,
/// the Unified audit log ingestion and the admin audit log. Mailbox auditing has been on by
/// default for Microsoft 365 tenants since January 2019
/// (https://learn.microsoft.com/purview/audit-mailboxes) and the audit log is collected
/// (https://learn.microsoft.com/purview/audit-new-search), so a scenario only opts out by
/// naming an audit profile that says so. `business-basic` does, deliberately: it is the tenant
/// where those events are never logged, the counterpart of the benign look-alikes.
#[test]
fn auditing_is_on_unless_the_scenario_opts_out() {
    // The profile a scenario gets without saying anything: auditing on.
    let mut quiet = load("bec-aitm").unwrap();
    quiet.tenant.audit_profile = "default".into();
    let w = World::build(&quiet, 42).unwrap();
    assert!(
        !w.audit.org_audit_disabled,
        "the default disables mailbox auditing"
    );
    assert!(
        w.audit.ual_ingestion_enabled,
        "the default disables the audit log"
    );
    assert!(
        w.audit.admin_audit_log_enabled,
        "the default disables the admin log"
    );

    for name in builtin_names() {
        let s = load(name).unwrap();
        let w = World::build(&s, 42).unwrap();
        let declared = s.tenant.audit_profile.as_str();
        // No profile turns the organisation's mailbox auditing or the audit log off except the
        // one named after it, and none turns the admin audit log off (a tamper storyline does,
        // at runtime, which is what the `audit-tamper` scenario is for).
        assert_eq!(
            w.audit.org_audit_disabled,
            declared == "org_audit_disabled",
            "{name}: mailbox auditing under the {declared} profile"
        );
        assert_eq!(
            w.audit.ual_ingestion_enabled,
            declared != "ual_disabled",
            "{name}: the audit log under the {declared} profile"
        );
        assert!(
            w.audit.admin_audit_log_enabled,
            "{name}: the admin audit log is off under {declared}"
        );
    }
}
