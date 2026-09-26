use sparrow_synth::reserved::{is_reserved_domain, is_reserved_ip};
use sparrow_synth::scenario::load;
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
    assert!(w.mfa.values().any(|m| !m.is_mfa_registered));
    let rule = w.inbox_rules.first().unwrap();
    assert!(rule.description().starts_with("If the message:\r\n\t"));
}
