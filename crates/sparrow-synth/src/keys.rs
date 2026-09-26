//! Sparrow record keys for world objects, one function per table, each following the table's
//! `COMMENT ON COLUMN <table>.record_key` (quoted in the doc comment). Per-collection keys carry
//! the placeholder `{cid}` for the collection id, which the manifest leaves unreplaced.

use crate::story::Evidence;
use crate::world::World;
use uuid::Uuid;

/// The placeholder for the collection id in per-collection keys.
pub const CID: &str = "{cid}";

fn lower(s: &str) -> String {
    s.to_lowercase()
}

/// `ual_events` (keyed by `record_id`): "AuditData Id (natural key)" — lower-case hyphenated.
pub fn ual(id: Uuid) -> String {
    id.to_string()
}

/// `signins`: "Sign-in id (Graph id, portal Request ID), lower-case."
pub fn signin(id: Uuid) -> String {
    id.to_string()
}

/// `directory_audits`: "Audit id, lower-case."
pub fn dir_audit(id: &str) -> String {
    lower(id)
}

/// `message_trace`: "<message_trace_id>|<recipient>, lower-case".
pub fn trace(trace_id: Uuid, recipient: &str) -> String {
    format!("{trace_id}|{}", lower(recipient))
}

/// `risk_detections`: "Lower-case detection id."
pub fn risk(id: &str) -> String {
    lower(id)
}

/// `risky_users`: "Lower-case user object id, else lower-case UPN."
pub fn risky_user(object_id: Uuid) -> String {
    object_id.to_string()
}

/// `users`: "Entra object id (lower-case), else the lower-cased UPN."
pub fn user(object_id: Uuid) -> String {
    object_id.to_string()
}

/// `mailboxes`: "Lower-case UPN (Hawk user folder name, else the record UserPrincipalName)."
pub fn mailbox(upn: &str) -> String {
    lower(upn)
}

/// `inbox_rules`: "<kind>|<lower mailbox>|<rule_identity>." (`kind` is `inbox` or `sweep`;
/// Hawk's rules carry the owner's alias as `MailboxOwnerId`).
pub fn inbox_rule(kind: &str, mailbox: &str, rule_identity: &str) -> String {
    format!("{kind}|{}|{rule_identity}", lower(mailbox))
}

/// `mailbox_permissions`: "<mailbox upn>|<permission>|<folder or empty>|<lower-case grantee>."
/// (the mailbox UPN normalized to lower case, as for `mailboxes`).
pub fn mailbox_permission(
    mailbox: &str,
    permission: &str,
    folder: Option<&str>,
    grantee: &str,
) -> String {
    format!(
        "{}|{permission}|{}|{}",
        lower(mailbox),
        folder.unwrap_or(""),
        lower(grantee)
    )
}

/// `oauth_grants`: "<client_id>|<resource_id>|<lower permission>|<principal_id or empty>."
/// (ids lower-case).
pub fn oauth_grant(
    client: &str,
    resource: &str,
    permission: &str,
    principal: Option<&str>,
) -> String {
    format!(
        "{}|{}|{}|{}",
        lower(client),
        lower(resource),
        lower(permission),
        principal.map(lower).unwrap_or_default()
    )
}

/// `app_credentials`: "<lower app_object_id>|<lower key_id>."
pub fn app_credential(app_object_id: Uuid, key_id: Uuid) -> String {
    format!("{app_object_id}|{key_id}")
}

/// `role_assignments`: "<source>|<lower role name>|<principal>: principal is the lower UPN,
/// else the object id, else the lower display name; empty for a role without members."
pub fn role(source: &str, role: &str, principal: &str) -> String {
    format!("{source}|{}|{}", lower(role), lower(principal))
}

/// `mobile_devices`: "<lower mailbox>|<lower device_id>."
pub fn mobile_device(mailbox: &str, device_id: &str) -> String {
    format!("{}|{}", lower(mailbox), lower(device_id))
}

/// `transport_rules`: "<collection_id>|<lower rule name>."
pub fn transport_rule(name: &str) -> String {
    format!("{CID}|{}", lower(name))
}

/// `remote_domains`: "<collection_id>|<lower DomainName>."
pub fn remote_domain(domain: &str) -> String {
    format!("{CID}|{}", lower(domain))
}

/// `audit_config`: "organization|<collection_id>."
pub fn audit_config() -> String {
    format!("organization|{CID}")
}

/// `tenant_settings`: "<collection_id>|<source>|<lower name>."
pub fn tenant_setting(source: &str, name: &str) -> String {
    format!("{CID}|{source}|{}", lower(name))
}

/// `licenses`: "<collection_id>|<source>|<lower sku_part_number or tier>." — a SKU row of
/// Microsoft-Extractor-Suite TenantLicenses.csv (source `invictus_tenant_licenses`).
pub fn licence(sku: &str) -> String {
    format!("{CID}|invictus_tenant_licenses|{}", lower(sku))
}

/// `licenses`: "<collection_id>|<source>|<lower sku_part_number or tier>." — the tier of the
/// Hawk.log line "M365 License type detected: <tier>" (source `hawk_log`).
pub fn licence_tier(tier: &str) -> String {
    format!("{CID}|hawk_log|{}", lower(tier))
}

/// `user_licenses`: "<collection_id>|<lower upn>|<lower sku>."
pub fn user_licence(upn: &str, sku: &str) -> String {
    format!("{CID}|{}|{}", lower(upn), lower(sku))
}

/// A mailbox permission grantee as Microsoft-Extractor-Suite's Get-MailboxPermissions exports
/// it (and `mailbox_permissions.grantee` keys it): `"<DisplayName> (<PrimarySmtpAddress>)"`
/// for a recipient (a person with a mailbox), else the raw identity (a role group such as
/// `Discovery Management`).
pub fn mailbox_grantee(world: &World, grantee: &str) -> String {
    match world.mailboxes.get(grantee) {
        Some(m) => format!("{} ({})", m.display_name, m.primary_smtp),
        None => grantee.to_string(),
    }
}

/// A folder permission grantee as Get-MailboxPermissions exports it:
/// `"<DisplayName> (<PrimarySmtpAddress>)"`, the address empty for a grantee without a mailbox.
pub fn mailbox_folder_grantee(world: &World, grantee: &str) -> String {
    match world.mailboxes.get(grantee) {
        Some(m) => format!("{} ({})", m.display_name, m.primary_smtp),
        None => format!("{grantee} ()"),
    }
}

/// The record key storyline evidence `e` has in `table`, when this module can name it (the
/// manifest's sightings carry it so `synth check` can find the provenance row); `None` for a
/// pairing no writer delivers yet. Writer tasks extend it as they deliver new pairings.
pub fn for_evidence(world: &World, e: &Evidence, table: &str) -> Option<String> {
    match (e, table) {
        (Evidence::Ual(id), "ual_events") => Some(ual(*id)),
        (Evidence::SignIn(id), "signins") => Some(signin(*id)),
        (Evidence::DirAudit(id), "directory_audits") => Some(dir_audit(id)),
        (
            Evidence::Trace {
                trace_id,
                recipient,
            },
            "message_trace",
        ) => Some(trace(*trace_id, recipient)),
        (Evidence::Risk(id), "risk_detections") => Some(risk(id)),
        (Evidence::Mailbox(upn), "mailboxes") => Some(mailbox(upn)),
        (Evidence::MobileDevice { mailbox, device_id }, "mobile_devices") => {
            Some(mobile_device(mailbox, device_id))
        }
        (Evidence::TransportRule(name), "transport_rules") => Some(transport_rule(name)),
        (
            Evidence::MailboxPermission {
                mailbox,
                grantee,
                right,
                folder,
            },
            "mailbox_permissions",
        ) => {
            let shown = if right == "folder" {
                mailbox_folder_grantee(world, grantee)
            } else {
                mailbox_grantee(world, grantee)
            };
            Some(mailbox_permission(
                mailbox,
                right,
                folder.as_deref(),
                &shown,
            ))
        }
        (Evidence::AuditConfig, "audit_config") => Some(audit_config()),
        (Evidence::RiskyUser(upn), "risky_users") => world
            .user_by_upn(upn)
            .map(|u| risky_user(u.object_id))
            .or_else(|| Some(lower(upn))),
        // Hawk's convention: Get-InboxRule's `MailboxOwnerId` is the owner's alias, which Sparrow
        // keys the rule by. Only the Hawk writers deliver inbox rules today; a collector that
        // names the owner differently must make this collector-aware.
        (Evidence::InboxRule { mailbox, identity }, "inbox_rules") => {
            let owner = world
                .user_by_upn(mailbox)
                .map_or_else(|| mailbox.clone(), |u| u.alias.clone());
            Some(inbox_rule("inbox", &owner, &identity.to_string()))
        }
        (
            Evidence::Grant {
                client_app_id,
                scope,
                principal,
            },
            "oauth_grants",
        ) => {
            let grant = world.grants.iter().find(|g| {
                g.client_app_id == *client_app_id
                    && g.principal == *principal
                    && g.scope.split(' ').any(|s| s == scope)
            })?;
            let sp = |app: Uuid| {
                world
                    .apps
                    .iter()
                    .find(|a| a.app_id == app)
                    .map(|a| a.sp_object_id.to_string())
            };
            let principal_id = principal
                .as_deref()
                .and_then(|p| world.user_by_upn(p))
                .map(|u| u.object_id.to_string());
            Some(oauth_grant(
                &sp(grant.client_app_id)?,
                &sp(grant.resource_app_id)?,
                scope,
                principal_id.as_deref(),
            ))
        }
        (
            Evidence::Credential {
                app_object_id,
                key_id,
                on_service_principal,
            },
            "app_credentials",
        ) => {
            let app = world.apps.iter().find(|a| a.object_id == *app_object_id)?;
            let owner = if *on_service_principal {
                app.sp_object_id
            } else {
                app.object_id
            };
            Some(app_credential(owner, *key_id))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::load;

    #[test]
    fn folder_grants_of_one_grantee_key_by_folder() {
        let w = World::build(&load("bec-aitm").unwrap(), 1).unwrap();
        let (mailbox, grantee) = (w.user(4).upn.clone(), w.user(3).upn.clone());
        let key = |folder: &str| {
            let e = Evidence::MailboxPermission {
                mailbox: mailbox.clone(),
                grantee: grantee.clone(),
                right: "folder".into(),
                folder: Some(folder.into()),
            };
            for_evidence(&w, &e, "mailbox_permissions").unwrap()
        };
        let shown = mailbox_folder_grantee(&w, &grantee).to_lowercase();
        assert_eq!(
            key("calendar"),
            format!("{}|folder|calendar|{shown}", mailbox.to_lowercase())
        );
        assert_eq!(
            key("inbox"),
            format!("{}|folder|inbox|{shown}", mailbox.to_lowercase())
        );
    }
}
