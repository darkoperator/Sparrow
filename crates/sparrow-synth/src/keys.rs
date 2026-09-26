//! Sparrow record keys for world objects, one function per table, each following the table's
//! `COMMENT ON COLUMN <table>.record_key` (quoted in the doc comment). Per-collection keys carry
//! the placeholder `{cid}` for the collection id, which the manifest leaves unreplaced.

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

/// `inbox_rules`: "<kind>|<lower mailbox>|<rule_identity>." (`kind` is `inbox` or `sweep`).
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
