//! Hawk 3.1.x (research hawk layouts §7; capture survey §1-§4): the same world as the Hawk 4
//! writer, rendered as `Start-HawkTenantInvestigation` then `Start-HawkUserInvestigation` of
//! Hawk 3.1.0 into `Hawk_<tenant folder name>_<yyyyMMdd_HHmmss>`:
//! - the 3.x file names and shapes: `AzureADUsers`, `AzureADAdministrators`,
//!   `Azure_Application_Audit`, `EDiscoveryRoleAssignments`, the `Impersonation_*` dumps, the
//!   8-column `eDiscoveryLogs.csv`, `Tenant/All_InboxRules`, `Forwarding_Recipients`;
//! - Exchange admin activity from `Search-AdminAuditLog` (17 columns, `CmdletParameters` a
//!   `[{Name, Value}]` list, `RunDate` a host-local `DateTime`) with Hawk's five-column
//!   `Get-SimpleAdminAuditLog` summaries, instead of UAL `ExchangeAdmin` records;
//! - per user the expanded `Exchange_UAL_Audit`, the legacy `Exchange_Mailbox_Audit`
//!   (Search-MailboxAuditLog, 55 columns), `Message_Trace` and the authentication logs
//!   without `AuditSearchRequestMetadata`; no Entra sign-ins, Graph risk data or
//!   `EntraIDAuditLogs` (new in 4.x);
//! - `Tenant/XML/*.xml` CliXml copies (`-xml`), JSON written with `Out-File`'s default
//!   encoding (UTF-16LE on 5.1), the 3.x `Hawk.log` / `_Investigate.txt` dialect and the
//!   PSFramework log export `<yyyy-MM-dd>_logs.csv`.
//!
//! Each file declares what it is to Sparrow at its call site (`Art`), from the research.

use super::log::Level;
use super::omft::{Art, Formats, HawkVersion, Written};
use super::tenant::{self, running};
use super::{
    Ctx, date, expanded_row, one_of, opt, r, register, register_flags, register_ual, s, user,
};
use crate::Result;
use crate::events::{RecordType, Ual};
use crate::keys;
use crate::options::GenerateOptions;
use crate::ps::{DateEvidence, DtKind, Encoding, PsDate, Row, Val, export_csv, note_evidence};
use crate::rng::stream;
use crate::story::Evidence;
use crate::tree::Tree;
use crate::world::{User, World};
use chrono::Duration;
use serde_json::{Value, json};
use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::net::IpAddr;

/// The module version Hawk 3.1 logs (`*** Version 3.1.0 ***`).
pub const HAWK3_VERSION: &str = "3.1.0";

/// Writes the Hawk 3.1 output folder of `world` into `tree`.
pub fn write_v3(world: &World, opts: &GenerateOptions, tree: &mut Tree<'_>) -> Result<()> {
    let mut c = Ctx::new(world, opts, HawkVersion::V3);
    header(&mut c);
    investigate_tenant(&mut c, tree)?;
    investigate_users(&mut c, tree)?;
    let enc = Encoding::out_file_default(c.tenant_host.edition);
    let nl = c.tenant_host.newline;
    c.omft.log.write(tree, enc, nl)?;
    psframework_log(&c, tree)
}

/// The start of the session (no licence detection in 3.x): the version line (research §7.1),
/// then the folder and tenant. Research knows no Hawk 3.1 window line, so none is logged: the
/// collection reports no window.
// source-derived (no 3.1 source): every message but the version line.
fn header(c: &mut Ctx<'_>) {
    let path = c.omft.file_path.clone();
    let tenant = c.world.tenant.folder_name.clone();
    let log = c.log();
    log.plain(format!("*** Version {HAWK3_VERSION} ***"));
    log.plain("Checking for latest version online");
    log.tick(1, 3);
    log.plain(format!("Found Version {HAWK3_VERSION} Online"));
    log.plain("Latest Version Installed");
    log.plain(format!("Setting Hawk output folder to {path}"));
    log.plain(format!("Investigating tenant {tenant}"));
    log.tick(5, 30);
}

/// `Running <cmdlet>.` before a collector, and the `## <Tag> ##` its notices carry.
// source-derived (no 3.1 source): research §7.1 gives only the `## <Tag> ##` shape (a tag per
// section; Sparrow's fixture uses `## Impersonation ##`); the tags name each collector's area.
fn step(c: &mut Ctx<'_>, cmdlet: &str, tag: &str) {
    running(c, cmdlet);
    c.log().section(tag);
}

// ---------------------------------------------------------------------------------------------
// Tenant

fn investigate_tenant(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    c.log().action("Starting Tenant Investigation");
    step(c, "Get-HawkTenantConfiguration", "Tenant Configuration");
    tenant::configuration(c, tree)?;
    step(c, "Get-HawkTenantEDiscoveryConfiguration", "EDiscovery");
    tenant::ediscovery_configuration(c, tree)?;
    step(c, "Get-HawkTenantEXOImpersonation", "Impersonation");
    impersonation(c, tree)?;
    step(c, "Get-HawkTenantEDiscoveryLogs", "EDiscovery Logs");
    ediscovery_logs(c, tree)?;
    step(c, "Search-HawkTenantEXOAuditLog", "Admin Inbox Rules");
    inbox_rule_changes(c, tree)?;
    step(c, "Get-HawkTenantRBACChanges", "RBAC");
    rbac_changes(c, tree)?;
    step(
        c,
        "Get-HawkTenantMailboxPermissionChanges",
        "Mailbox Permissions",
    );
    permission_changes(c, tree)?;
    step(c, "Get-HawkTenantEmailForwardingChanges", "Forwarding");
    forwarding_changes(c, tree)?;
    step(c, "Get-HawkTenantAzureAppAuditLog", "Application Audit");
    // source-derived (no 3.1 source): the collector's log lines are Hawk 4.0's wording.
    tenant::app_audit_log(c, tree, "Azure_Application_Audit")?;
    step(c, "Get-HawkTenantEXOAdmins", "Exchange Admins");
    tenant::exo_admins(c, tree)?;
    step(c, "Get-HawkTenantConsentGrants", "Consent Grants");
    consent_grants(c, tree)?;
    step(c, "Get-HawkTenantAzureADAdmins", "Azure AD Admins");
    azuread_admins(c, tree)?;
    step(
        c,
        "Get-HawkTenantAppAndSPNCredentialDetails",
        "App Credentials",
    );
    tenant::credentials(c, tree)?;
    step(c, "Get-HawkTenantAzureADUsers", "Azure AD Users");
    azuread_users(c, tree)?;
    c.log().plain("Tenant Investigation complete");
    Ok(())
}

/// The role group Exchange Online assigns `ApplicationImpersonation` to by default.
const IMPERSONATION_DEFAULT_GROUP: &str = "Hygiene Management";

/// Get-HawkTenantEXOImpersonation: the role entry and the (non-delegating) assignments of
/// `ApplicationImpersonation`. More than the default one assignment is flagged with a
/// byte-identical `_Investigate_Impersonation_Rights` copy (capture survey §2b: 1-3 records,
/// the copy in capture A only).
// source-derived (no 3.1 source): the assignments are the default group plus one per
// Exchange Administrator of the world (granted impersonation to manage mailboxes), and the
// threshold is `> 1`, so a tenant with an Exchange Administrator gives capture A's shape
// (hawk-investigate) and the others capture C's.
fn impersonation(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let world = c.world;
    let role = "ApplicationImpersonation";
    c.log().plain("Gathering Impersonation Access Rights");
    let entries = vec![tenant::role_entry(
        world,
        role,
        "Impersonate-ExchangeUser",
        &["Identity"],
    )];
    let w = c.omft.write(
        tree,
        "Impersonation_Roles",
        None,
        Art::raw("hawk.tenant.impersonation"),
        &entries,
        Formats::CSV_JSON.and_xml(),
        false,
        false,
    )?;
    tenant::register_role_entries(tree, &w, &entries);
    let mut principals = vec![IMPERSONATION_DEFAULT_GROUP.to_string()];
    let mut rights = vec![tenant::role_assignment(
        world,
        role,
        IMPERSONATION_DEFAULT_GROUP,
    )];
    for a in world
        .roles
        .iter()
        .filter(|a| a.role == "Exchange Administrator")
    {
        let mut row = tenant::role_assignment(world, role, &a.principal);
        for (k, v) in row.iter_mut() {
            match k.as_str() {
                "RoleAssigneeType" => *v = s("User"),
                "EffectiveUserName" => *v = s(a.principal.clone()),
                _ => {}
            }
        }
        principals.push(a.principal.clone());
        rights.push(row);
    }
    let key = |i: usize| Some(keys::role("exchange_rbac", role, &principals[i]));
    if rights.len() > 1 {
        c.log().notice(format!(
            "Found {} Users/Groups with Impersonation rights",
            rights.len()
        ));
        c.log()
            .notice("More than the default number of Impersonation users; please verify");
        let w = c.omft.write(
            tree,
            "_Investigate_Impersonation_Rights",
            None,
            Art::raw("hawk.investigate_file"),
            &rights,
            Formats::CSV_JSON.and_xml(),
            false,
            true,
        )?;
        register_flags(tree, &w);
    } else {
        c.log().plain("Found default number of Impersonation users");
    }
    let w = c.omft.write(
        tree,
        "Impersonation_Rights",
        None,
        Art::raw("hawk.tenant.impersonation"),
        &rights,
        Formats::CSV_JSON.and_xml(),
        false,
        false,
    )?;
    register(tree, &w, "role_assignments", key, |_| None);
    Ok(())
}

/// Get-HawkTenantEDiscoveryLogs: the Discovery records' AuditData reduced to eight columns,
/// CSV only (capture survey §2b).
fn ediscovery_logs(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let found = c.search("Search-UnifiedAuditLog -RecordType 'Discovery'", |u| {
        u.record_type == RecordType::Discovery
    });
    if found.is_empty() {
        c.log().plain("No eDiscovery Logs found");
        return Ok(());
    }
    // source-derived (no 3.1 source): the notice lines (Hawk 4's wording).
    c.log().notice("eDiscovery Logs have been found.");
    c.log()
        .notice("Please review these eDiscoveryLogs.csv to validate the activity is legitimate.");
    let columns = [
        "CreationTime",
        "Id",
        "Operation",
        "Workload",
        "UserId",
        "Case",
        "CaseID",
        "Cmdlet",
    ];
    let rows: Vec<Row> = found
        .iter()
        .map(|u| {
            let e = expanded_row(u);
            columns
                .iter()
                .map(|k| {
                    let v = e
                        .iter()
                        .find(|(n, _)| n == k)
                        .map_or(Val::Null, |(_, v)| v.clone());
                    r(k, v)
                })
                .collect()
        })
        .collect();
    let w = c.omft.write(
        tree,
        "eDiscoveryLogs",
        None,
        Art::raw("hawk.tenant.raw_ual"),
        &rows,
        Formats::CSV,
        false,
        false,
    )?;
    register_ual(tree, &w, &found);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Search-AdminAuditLog

/// `Search-AdminAuditLog` over the window: the logged Exchange admin cmdlets `keep` selects,
/// newest first.
fn admin_search(c: &mut Ctx<'_>, what: &str, keep: impl Fn(&Ual) -> bool) -> Vec<Ual> {
    c.log()
        .plain(format!("Searching Admin Audit Log for {what}"));
    let mut found: Vec<Ual> = c
        .ual
        .iter()
        .filter(|u| u.record_type == RecordType::ExchangeAdmin && keep(u))
        .cloned()
        .collect();
    found.sort_by_key(|u| Reverse((u.time, u.id)));
    c.log().tick(1, 5);
    found
}

fn audit_text(u: &Ual, key: &str) -> Option<String> {
    u.audit.get(key).and_then(Value::as_str).map(str::to_string)
}

/// The `[{Name, Value}]` parameters of a cmdlet record.
fn parameters(u: &Ual) -> Vec<(String, String)> {
    u.audit
        .get("Parameters")
        .and_then(Value::as_array)
        .map(|ps| {
            ps.iter()
                .map(|p| {
                    let text = |k: &str| p.get(k).map(super::simple::ps_text).unwrap_or_default();
                    (text("Name"), text("Value"))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn has_parameter(u: &Ual, names: &[&str]) -> bool {
    parameters(u).iter().any(|(n, _)| one_of(n, names))
}

/// One `Search-AdminAuditLog` result (17 properties). `RunDate` is a `DateTime` of the
/// collecting host (kind Local); the caller is the account that ran the cmdlet.
fn admin_row(u: &Ual) -> Row {
    let params: Vec<Value> = parameters(u)
        .into_iter()
        .map(|(n, v)| json!({"Name": n, "Value": v}))
        .collect();
    let succeeded = audit_text(u, "ResultStatus").is_none_or(|r| !r.eq_ignore_ascii_case("False"));
    vec![
        r("ObjectModified", s(keys::admin_object(u))),
        r("CmdletName", s(u.operation.clone())),
        r("CmdletParameters", Val::Raw(Value::Array(params))),
        r("ModifiedProperties", Val::Raw(json!([]))),
        r("Caller", s(u.user_id.clone())),
        r(
            "ExternalAccess",
            Val::Bool(
                u.audit
                    .get("ExternalAccess")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
        ),
        r("Succeeded", Val::Bool(succeeded)),
        r("Error", s("")),
        r("RunDate", date(u.time, DtKind::Local)),
        r("OriginatingServer", opt(audit_text(u, "OriginatingServer"))),
        r("ClientIP", opt(audit_text(u, "ClientIP"))),
        r("SessionId", opt(audit_text(u, "SessionId"))),
        r("AppId", opt(audit_text(u, "AppId"))),
        r("ClientAppId", opt(audit_text(u, "ClientAppId"))),
        r(
            "Identity",
            Val::Raw(json!({"ObjectGuid": u.id.to_string(), "Name": u.id.to_string()})),
        ),
        r("IsValid", Val::Bool(true)),
        r("ObjectState", s("Unchanged")),
    ]
}

/// `Get-SimpleAdminAuditLog`'s `FullCommand`: the cmdlet then every parameter through its
/// `switch -Regex` without `break` (Hawk `internal/functions/Get-SimpleAdminAuditLog.ps1`):
/// a value with `;` is split and each part with blanks quoted; a value with blanks is quoted;
/// `True` / `False` become `-Name:$True`; `default` only when no clause matched.
fn full_command(u: &Ual) -> String {
    let mut out = u.operation.clone();
    for (name, value) in parameters(u) {
        let mut matched = false;
        if value.contains(';') {
            matched = true;
            let parts: Vec<String> = value
                .split(';')
                .map(|p| {
                    if p.contains([' ', '\t']) {
                        format!("\"{p}\"")
                    } else {
                        p.to_string()
                    }
                })
                .collect();
            out.push_str(&format!(" -{name} {}", parts.join(";")));
        }
        if value.contains([' ', '\t']) {
            matched = true;
            out.push_str(&format!(" -{name} \"{value}\""));
        }
        if value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false") {
            matched = true;
            out.push_str(&format!(" -{name}:${value}"));
        }
        if !matched {
            out.push_str(&format!(" -{name} {value}"));
        }
    }
    out
}

/// The five-column summary of one admin audit record (`RunDate(UTC)` a UTC `DateTime`).
fn simple_admin_row(u: &Ual) -> Row {
    vec![
        r("Caller", s(keys::simple_caller(&u.user_id))),
        r("Cmdlet", s(u.operation.clone())),
        r("FullCommand", s(full_command(u))),
        r("RunDate(UTC)", date(u.time, DtKind::Utc)),
        r(
            "ObjectModified",
            s(keys::short_object(&keys::admin_object(u)).to_string()),
        ),
    ]
}

/// Every written part loads the admin audit commands `records` (same order as the rows): one
/// `admin_audit_events` row per command, the copies of one command sharing its key.
fn register_admin(tree: &mut Tree<'_>, w: &Written, records: &[Ual]) {
    register(
        tree,
        w,
        "admin_audit_events",
        |i| Some(keys::admin_audit_of(&records[i])),
        |i| Some(Evidence::Ual(records[i].id)),
    );
}

/// A search result as `Simple_<name>` (the summary, derived) and then the full records as
/// `<full>` in `formats` (the XML-only full forms are not parsed). `user` selects the user
/// folder's artifacts.
#[allow(clippy::too_many_arguments)]
fn admin_files(
    c: &mut Ctx<'_>,
    tree: &mut Tree<'_>,
    simple_prefix: &str,
    full_prefix: &str,
    full_art: Art,
    formats: Formats,
    user: Option<&str>,
    records: &[Ual],
) -> Result<()> {
    let simple_art = match user {
        None => Art::derived("hawk.tenant.simple_ual"),
        Some(_) => Art::derived("hawk.user.simple_ual"),
    };
    let simple: Vec<Row> = records.iter().map(simple_admin_row).collect();
    let w = c.omft.write(
        tree,
        simple_prefix,
        user,
        simple_art,
        &simple,
        Formats::CSV_JSON,
        false,
        false,
    )?;
    register_admin(tree, &w, records);
    let full: Vec<Row> = records.iter().map(admin_row).collect();
    let w = c.omft.write(
        tree,
        full_prefix,
        user,
        full_art,
        &full,
        formats,
        false,
        false,
    )?;
    register_admin(tree, &w, records);
    Ok(())
}

/// Search-HawkTenantEXOAuditLog: `New-`, `Set-` and `Remove-InboxRule` from the admin audit
/// log. New rules that forward, redirect or delete are copied to
/// `_Investigate_Simple_New_InboxRule` (summary) and `_Investigate_New_InboxRules` (Format-List
/// and CliXml).
fn inbox_rule_changes(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    for (cmdlet, simple, full) in [
        ("New-InboxRule", "Simple_New_InboxRule", "New_InboxRules"),
        ("Set-InboxRule", "Simple_Set_InboxRule", "Set_InboxRules"),
        (
            "Remove-InboxRule",
            "Simple_Remove_InboxRule",
            "Remove_InboxRules",
        ),
    ] {
        let found = admin_search(c, &format!("{cmdlet} events"), |u| {
            u.operation.eq_ignore_ascii_case(cmdlet)
        });
        if found.is_empty() {
            c.log().plain(format!("No {cmdlet} events found"));
            continue;
        }
        c.log()
            .plain(format!("Found {} {cmdlet} events", found.len()));
        admin_files(
            c,
            tree,
            simple,
            full,
            Art::raw("hawk.tenant.admin_audit"),
            Formats::CSV_JSON,
            None,
            &found,
        )?;
        if cmdlet != "New-InboxRule" {
            continue;
        }
        // source-derived (no 3.1 source): research names only the `_Investigate_` files; the
        // test is Hawk 4's inbox-rule test (a forwarding, redirecting or deleting parameter).
        let flagged: Vec<Ual> = found
            .iter()
            .filter(|u| {
                has_parameter(
                    u,
                    &[
                        "ForwardTo",
                        "ForwardAsAttachmentTo",
                        "RedirectTo",
                        "DeleteMessage",
                    ],
                )
            })
            .cloned()
            .collect();
        if flagged.is_empty() {
            continue;
        }
        c.log().notice(format!(
            "Found {} Inbox Rule(s) created by an administrator that forward or delete mail",
            flagged.len()
        ));
        c.log().notice("Please verify this activity is legitimate.");
        let rows: Vec<Row> = flagged.iter().map(simple_admin_row).collect();
        let w = c.omft.write(
            tree,
            "_Investigate_Simple_New_InboxRule",
            None,
            Art::raw("hawk.investigate_file"),
            &rows,
            Formats::CSV_JSON,
            false,
            true,
        )?;
        register_flags(tree, &w);
        let rows: Vec<Row> = flagged.iter().map(admin_row).collect();
        let w = c.omft.write(
            tree,
            "_Investigate_New_InboxRules",
            None,
            Art::raw("hawk.investigate_file"),
            &rows,
            Formats::TXT.and_xml(),
            false,
            true,
        )?;
        // The Format-List copy's `RunDate` is the host's local time without a zone: its flags
        // link to (and so merge with) the summary copy's only when the host runs in UTC
        // (collector_flags / admin_audit_events record_key COMMENTs).
        let merged = c.world.scenario.tenant.host_utc_offset_minutes == 0;
        for part in w.parts() {
            let n = if merged { 0 } else { part.spans.len() as u64 };
            tree.rows_counted(&part.rel, "collector_flags", n);
        }
    }
    Ok(())
}

/// Get-HawkTenantRBACChanges: the RBAC cmdlets from the admin audit log.
fn rbac_changes(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let found = admin_search(c, "RBAC changes", |u| {
        one_of(&u.operation, &tenant::RBAC_OPERATIONS)
    });
    if found.is_empty() {
        c.log().plain("No RBAC Changes found.");
        return Ok(());
    }
    c.log().plain(format!(
        "Found {} changes made to Roles Based Access Control",
        found.len()
    ));
    admin_files(
        c,
        tree,
        "Simple_RBAC_Changes",
        "RBAC_Changes",
        Art::raw("hawk.tenant.raw_ual"),
        Formats::CSV_JSON.and_xml(),
        None,
        &found,
    )
}

/// Mailbox permission grants: `Add-MailboxPermission` only (capture survey §4); the full
/// records only as CliXml.
fn permission_changes(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let found = admin_search(c, "mailbox permission changes", |u| {
        u.operation.eq_ignore_ascii_case("Add-MailboxPermission")
    });
    if found.is_empty() {
        c.log().plain("No Mailbox Permission changes found.");
        return Ok(());
    }
    admin_files(
        c,
        tree,
        "Simple_Mailbox_Permissions",
        "Mailbox_Permissions",
        Art::raw("hawk.tenant.raw_ual"),
        Formats::XML,
        None,
        &found,
    )
}

/// Forwarding changes: `Set-Mailbox` with a forwarding parameter; the full records only as
/// CliXml, and `Forwarding_Recipients`, which Hawk 3 fills with empty rows (capture survey
/// §2b, §5).
fn forwarding_changes(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let found = admin_search(c, "forwarding changes", |u| {
        u.operation.eq_ignore_ascii_case("Set-Mailbox")
            && has_parameter(
                u,
                &[
                    "ForwardingAddress",
                    "ForwardingSMTPAddress",
                    "DeliverToMailboxAndForward",
                ],
            )
    });
    if found.is_empty() {
        c.log().plain("No forwarding changes found.");
        return Ok(());
    }
    c.log().notice(format!(
        "Found {} change(s) to user email forwarding",
        found.len()
    ));
    admin_files(
        c,
        tree,
        "Simple_Forwarding_Changes",
        "Forwarding_Changes",
        Art::raw("hawk.tenant.raw_ual"),
        Formats::XML,
        None,
        &found,
    )?;
    // source-derived (no 3.1 source): one empty row per change (capture survey §2b / §5 shows
    // only empty rows), written with `-Notice` like its 4.0 counterpart.
    let rows: Vec<Row> = found
        .iter()
        .map(|_| {
            vec![
                r("UserModified", Val::Null),
                r("TargetSMTPAddress", Val::Null),
            ]
        })
        .collect();
    c.omft.write(
        tree,
        "Forwarding_Recipients",
        None,
        Art {
            id: "hawk.tenant.forwarding_recipients",
            derived: true,
            not_supported: true,
        },
        &rows,
        Formats::CSV_JSON,
        false,
        true,
    )?;
    Ok(())
}

/// Get-HawkTenantConsentGrants: Hawk 4's rows without `ConsentGrantRiskCategory` (added in 4.x).
fn consent_grants(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let grants = tenant::grant_rows(c.world);
    let rows: Vec<Row> = grants
        .iter()
        .map(|g| {
            g.row
                .iter()
                .filter(|(k, _)| k != "ConsentGrantRiskCategory")
                .cloned()
                .collect()
        })
        .collect();
    let w = c.omft.write(
        tree,
        "Consent_Grants",
        None,
        Art::raw("hawk.tenant.consent_grants"),
        &rows,
        Formats::CSV_JSON,
        false,
        false,
    )?;
    register(
        tree,
        &w,
        "oauth_grants",
        |i| Some(grants[i].key.clone()),
        |i| grants[i].evidence.clone(),
    );
    Ok(())
}

/// Get-HawkTenantAzureADAdmins: one `AdminGroupName, Members` row per active member of each
/// directory role (MSOnline; roles without members are not listed).
fn azuread_admins(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let world = c.world;
    let now = world.collected_at();
    let mut roles: Vec<String> = Vec::new();
    for a in &world.roles {
        if !roles.contains(&a.role) {
            roles.push(a.role.clone());
        }
    }
    let mut rows = Vec::new();
    let mut keyed = Vec::new();
    for role in &roles {
        for m in world
            .roles
            .iter()
            .filter(|a| &a.role == role && a.kind != "PIM Eligible")
            .filter(|a| a.start.is_none_or(|t| t <= now) && a.end.is_none_or(|t| t > now))
            .filter_map(|a| world.user_by_upn(&a.principal))
        {
            rows.push(vec![
                r("AdminGroupName", s(role.clone())),
                r("Members", s(m.upn.clone())),
            ]);
            keyed.push(keys::role("entra_directory", role, &m.upn));
        }
    }
    let w = c.omft.write(
        tree,
        "AzureADAdministrators",
        None,
        Art::raw("hawk.tenant.azuread_admins"),
        &rows,
        Formats::CSV_JSON,
        false,
        false,
    )?;
    register(
        tree,
        &w,
        "role_assignments",
        |i| Some(keyed[i].clone()),
        |_| None,
    );
    Ok(())
}

/// Get-HawkTenantAzureADUsers: every user, sorted by UPN. `DateCreated` is pre-stringified in
/// the host culture (a culture date in CSV and JSON alike), `UserStateChangedOn` ISO text.
fn azuread_users(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let world = c.world;
    let host = c.omft.host;
    let mut people: Vec<&User> = world.all_people().collect();
    people.sort_by_key(|u| u.upn.to_lowercase());
    let mut ev = DateEvidence::default();
    let rows: Vec<Row> = people
        .iter()
        .map(|u| {
            note_evidence(&host, &mut ev, &PsDate::dotnet(u.created, DtKind::Utc));
            vec![
                r("UserPrincipalname", s(u.upn.clone())),
                r("ObjectID", s(u.object_id.to_string())),
                r("UserType", s("Member")),
                r("DateCreated", s(host.culture_date(u.created, DtKind::Utc))),
                r(
                    "UserStateChangedOn",
                    s(u.created.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                ),
                r(
                    "DirSyncEnabled",
                    if u.on_prem_sync {
                        Val::Bool(true)
                    } else {
                        Val::Null
                    },
                ),
            ]
        })
        .collect();
    let w = c.omft.write(
        tree,
        "AzureADUsers",
        None,
        Art::raw("hawk.tenant.azuread_users"),
        &rows,
        Formats::CSV_JSON,
        false,
        false,
    )?;
    register(
        tree,
        &w,
        "users",
        |i| Some(keys::user(people[i].object_id)),
        |_| None,
    );
    if ev.culture_dates > 0 {
        for part in w.parts() {
            tree.date_evidence(&part.rel, ev);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Users

fn investigate_users(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    c.log().tick(20, 120);
    c.log().action("Starting User Investigation");
    let users: Vec<&User> = c.users.clone();
    for u in &users {
        step(c, "Get-HawkUserConfiguration", "User Configuration");
        user::configuration(c, tree, u)?;
        step(c, "Get-HawkUserInboxRule", "Inbox Rules");
        inbox_rules(c, tree, u)?;
        step(c, "Get-HawkUserEmailForwarding", "Forwarding");
        user::forwarding(c, tree, u)?;
        step(c, "Get-HawkUserAuthHistory", "Authentication History");
        user::ual_signins(c, tree, u)?;
        step(c, "Get-HawkUserMailboxAuditing", "Mailbox Auditing");
        mailbox_auditing(c, tree, u)?;
        step(c, "Get-HawkUserAdminAudit", "Admin Audit");
        admin_audit(c, tree, u)?;
        step(c, "Get-HawkUserMessageTrace", "Message Trace");
        user::message_trace(c, tree, u)?;
        step(c, "Get-HawkUserMobileDevice", "Mobile Devices");
        user::mobile_devices(c, tree, u)?;
    }
    c.log().plain("User Investigation complete");
    Ok(())
}

/// Get-HawkUserInboxRule: `InboxRules_<u>` and, appended per user, `Tenant/All_InboxRules`
/// (byte-identical to the first user's file while only one user is investigated; capture
/// survey §5); flagged rules appended one by one to `_Investigate_InboxRules`.
fn inbox_rules(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User) -> Result<()> {
    let world = c.world;
    let upn = u.upn.as_str();
    c.log().plain(format!("Gathering Inbox Rules: {upn}"));
    let rules: Vec<&crate::world::InboxRule> = world
        .inbox_rules
        .iter()
        .filter(|r| r.mailbox.eq_ignore_ascii_case(upn))
        .collect();
    if rules.is_empty() {
        c.log().plain(format!("No Inbox Rules found for {upn}"));
        return Ok(());
    }
    let rows: Vec<Row> = rules
        .iter()
        .map(|r| user::inbox_rule_row(world, u, r))
        .collect();
    for (rule, row) in rules.iter().zip(&rows) {
        if user::suspicious_rule(rule) {
            c.log().notice(format!(
                "Possible Investigate inbox rule found ID:{}",
                rule.identity
            ));
            let w = c.omft.write(
                tree,
                "_Investigate_InboxRules",
                Some(upn),
                Art::raw("hawk.investigate_file"),
                std::slice::from_ref(row),
                Formats::CSV_JSON,
                true,
                true,
            )?;
            register_flags(tree, &w);
        }
    }
    let key = |i: usize| {
        Some(keys::inbox_rule(
            "inbox",
            &u.alias,
            &rules[i].identity.to_string(),
        ))
    };
    let ev = |i: usize| {
        Some(Evidence::InboxRule {
            mailbox: rules[i].mailbox.clone(),
            identity: rules[i].identity,
        })
    };
    let w = c.omft.write(
        tree,
        "InboxRules",
        Some(upn),
        Art::raw("hawk.user.inbox_rules"),
        &rows,
        Formats::CSV_JSON,
        false,
        false,
    )?;
    register(tree, &w, "inbox_rules", key, ev);
    let w = c.omft.write(
        tree,
        "All_InboxRules",
        None,
        Art::derived("hawk.tenant.all_inbox_rules"),
        &rows,
        Formats::CSV_JSON,
        true,
        false,
    )?;
    register(tree, &w, "inbox_rules", key, ev);
    Ok(())
}

/// The operations Hawk 3's `Exchange_UAL_Audit` holds (capture survey §2e).
const EXCHANGE_UAL_AUDIT_OPERATIONS: [&str; 5] = [
    "Create",
    "Update",
    "MailboxLogin",
    "SendOnBehalf",
    "UpdateInboxRules",
];

/// Get-HawkUserMailboxAuditing, when the mailbox is audited: the user's ExchangeItem records
/// with AuditData expanded (`Exchange_UAL_Audit_<u>`) and `Search-MailboxAuditLog -ShowDetails`
/// of the mailbox (`Exchange_Mailbox_Audit_<u>`).
fn mailbox_auditing(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User) -> Result<()> {
    let world = c.world;
    let upn = u.upn.clone();
    if !user::mailbox(world, u).is_some_and(|m| m.audit_enabled) {
        c.log().plain(format!("Auditing not enabled for {upn}"));
        return Ok(());
    }
    let found = c.search(
        &format!("Search-UnifiedAuditLog -UserIds {upn} -RecordType ExchangeItem"),
        |x| {
            x.record_type == RecordType::ExchangeItem
                && x.user_id.eq_ignore_ascii_case(&upn)
                && one_of(&x.operation, &EXCHANGE_UAL_AUDIT_OPERATIONS)
        },
    );
    if !found.is_empty() {
        let rows: Vec<Row> = found.iter().map(expanded_row).collect();
        let w = c.omft.write(
            tree,
            "Exchange_UAL_Audit",
            Some(&upn),
            Art::raw("hawk.user.raw_ual"),
            &rows,
            Formats::CSV_JSON,
            false,
            false,
        )?;
        register_ual(tree, &w, &found);
    }
    c.log()
        .plain(format!("Searching Mailbox Audit Log for {upn}"));
    let mut records: Vec<&Ual> = c
        .ual
        .iter()
        .filter(|x| {
            matches!(
                x.record_type,
                RecordType::ExchangeItem | RecordType::ExchangeItemGroup
            ) && x
                .audit
                .get("MailboxOwnerUPN")
                .and_then(Value::as_str)
                .is_some_and(|o| o.eq_ignore_ascii_case(&upn))
        })
        .collect();
    records.sort_by_key(|x| Reverse((x.time, x.id)));
    if records.is_empty() {
        c.log().plain("No mailbox audit records found");
        return Ok(());
    }
    let rows: Vec<(Row, MailboxAuditId)> = records
        .iter()
        .map(|x| mailbox_audit_row(world, x))
        .collect();
    let distinct: BTreeSet<&MailboxAuditId> = rows.iter().map(|(_, id)| id).collect();
    let n = distinct.len() as u64;
    let rows: Vec<Row> = rows.iter().map(|(row, _)| row.clone()).collect();
    let w = c.omft.write(
        tree,
        "Exchange_Mailbox_Audit",
        Some(&upn),
        Art::raw("hawk.user.mailbox_audit_legacy"),
        &rows,
        Formats::CSV_JSON,
        false,
        false,
    )?;
    for part in w.parts() {
        tree.rows_counted(&part.rel, "mailbox_audit_legacy", n);
    }
    Ok(())
}

/// What makes two legacy mailbox audit records one `mailbox_audit_legacy` row (the table's
/// record_key COMMENT: "event time (UTC, seconds), operation, mailbox, logon user SID, client
/// IP, item ids, folder id, session id and operation result"): the event second, then
/// lower-case operation, mailbox GUID, logon SID, normalized client IP, item ids, folder id
/// and session id. The operation result is left out: every generated record `Succeeded`.
type MailboxAuditId = (i64, String, String, String, String, String, String, String);

fn logon_type_name(n: i64) -> &'static str {
    match n {
        1 => "Admin",
        2 => "Delegate",
        _ => "Owner",
    }
}

/// One `Search-MailboxAuditLog -ShowDetails` record (the 55 columns of research event-layouts
/// §4) of mailbox-audit record `u`, and its identity.
fn mailbox_audit_row(world: &World, u: &Ual) -> (Row, MailboxAuditId) {
    let a = &u.audit;
    let text = |k: &str| audit_text(u, k);
    let sub = |v: Option<&Value>, k: &str| {
        v.and_then(|x| x.get(k))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let item = a.get("Item");
    let folder = a
        .get("Folder")
        .or_else(|| item.and_then(|i| i.get("ParentFolder")));
    let dest = a.get("DestFolder");
    let affected: Vec<&Value> = a
        .get("AffectedItems")
        .and_then(Value::as_array)
        .map(|v| v.iter().collect())
        .unwrap_or_default();
    let list = |k: &str| {
        let v: Vec<String> = affected
            .iter()
            .filter_map(|x| x.get(k).and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        if v.is_empty() {
            None
        } else {
            Some(v.join(", "))
        }
    };
    let source_items: Vec<Value> = affected
        .iter()
        .map(|x| {
            json!({
                "Id": x.get("Id"),
                "Subject": x.get("Subject"),
                "InternetMessageId": x.get("InternetMessageId"),
                "FolderPathName": x.get("ParentFolder").and_then(|p| p.get("Path")),
            })
        })
        .collect();
    let logon = world.user_by_upn(&u.user_id);
    let logon_type = logon_type_name(a.get("LogonType").and_then(Value::as_i64).unwrap_or(0));
    let owner = text("MailboxOwnerUPN").unwrap_or_default();
    let owner_name = world.user_by_upn(&owner).map(|o| o.display_name.clone());
    let ip = text("ClientIPAddress").or_else(|| text("ClientIP"));
    let item_id = sub(item, "Id");
    let folder_id = sub(folder, "Id");
    let session = text("SessionId");
    let guid = text("MailboxGuid");
    let row = vec![
        r("Operation", s(u.operation.clone())),
        r("OperationResult", s("Succeeded")),
        r("LogonType", s(logon_type)),
        r(
            "ExternalAccess",
            Val::Bool(
                a.get("ExternalAccess")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
        ),
        r("DestFolderId", opt(sub(dest, "Id"))),
        r("DestFolderPathName", opt(sub(dest, "Path"))),
        r("FolderId", opt(folder_id.clone())),
        r("FolderPathName", opt(sub(folder, "Path"))),
        r("FolderName", Val::Null),
        r("MemberRights", Val::Null),
        r("MemberSid", Val::Null),
        r("MemberUpn", Val::Null),
        r("ClientInfoString", opt(text("ClientInfoString"))),
        r("ClientIPAddress", opt(ip.clone())),
        r("ClientIP", opt(ip.clone())),
        r("ClientMachineName", Val::Null),
        r("ClientProcessName", Val::Null),
        r("ClientVersion", Val::Null),
        r("InternalLogonType", s(logon_type)),
        r("MailboxOwnerUPN", s(owner.clone())),
        r("MailboxOwnerSid", opt(text("MailboxOwnerSid"))),
        r("DestMailboxOwnerUPN", Val::Null),
        r("DestMailboxOwnerSid", Val::Null),
        r("DestMailboxGuid", Val::Null),
        r("CrossMailboxOperation", Val::Null),
        r(
            "LogonUserDisplayName",
            opt(logon.map(|l| l.display_name.clone())),
        ),
        r("LogonUserSid", opt(text("LogonUserSid"))),
        r("SourceItems", Val::Raw(Value::Array(source_items))),
        r("SourceFolders", Val::Raw(json!([]))),
        r("SourceItemIdsList", opt(list("Id"))),
        r("SourceItemSubjectsList", opt(list("Subject"))),
        r("SourceItemAttachmentsList", Val::Null),
        r("SourceItemFolderPathNamesList", Val::Null),
        r("SourceFolderPathNamesList", Val::Null),
        r(
            "SourceItemInternetMessageIdsList",
            opt(list("InternetMessageId")),
        ),
        r("ItemId", opt(item_id.clone())),
        r("ItemSubject", opt(sub(item, "Subject"))),
        r("ItemAttachments", Val::Null),
        r("ItemInternetMessageId", opt(sub(item, "InternetMessageId"))),
        r("DirtyProperties", Val::Null),
        r("OriginatingServer", opt(text("OriginatingServer"))),
        r("SessionId", opt(session.clone())),
        r("OperationProperties", Val::Raw(json!([]))),
        r("AuditOperationsCountInAggregatedRecord", Val::Null),
        r("AggregatedRecordFoldersData", Val::Null),
        r("AppId", opt(text("AppId"))),
        r("ClientAppId", opt(text("ClientAppId"))),
        r("ItemIsRecord", Val::Bool(false)),
        r("ItemComplianceLabel", Val::Null),
        r("MailboxGuid", opt(guid.clone())),
        r("MailboxResolvedOwnerName", opt(owner_name)),
        r("LastAccessed", date(u.time, DtKind::Local)),
        r(
            "Identity",
            s(format!(
                "{}\\{}",
                guid.clone().unwrap_or_default(),
                u.id.simple()
            )),
        ),
        r("IsValid", Val::Bool(true)),
        r("ObjectState", s("Unchanged")),
    ];
    let mut ids: Vec<String> = item_id.into_iter().collect();
    for x in &affected {
        if let Some(i) = x.get("Id").and_then(Value::as_str) {
            if !ids.iter().any(|y| y == i) {
                ids.push(i.to_string());
            }
        }
    }
    let lower = |v: Option<String>| v.unwrap_or_default().to_lowercase();
    let id = (
        u.time.timestamp(),
        u.operation.to_lowercase(),
        lower(guid).to_string(),
        lower(text("LogonUserSid")),
        ip.map(|a| a.parse::<IpAddr>().map_or(a, |p| p.to_string()))
            .unwrap_or_default(),
        ids.join(",").to_lowercase(),
        lower(folder_id),
        lower(session),
    );
    (row, id)
}

/// Get-HawkUserAdminAudit: the admin audit log's changes to the user's mailbox
/// (`Search-AdminAuditLog -ObjectIds <mailbox>`): `Simple_User_Changes` and `User_Changes`.
// source-derived (no 3.1 source): research gives only the schema; "changes made to the
// user" (`-ObjectIds`, the mailbox or its rules) rather than "commands the user ran".
fn admin_audit(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User) -> Result<()> {
    let upn = u.upn.clone();
    let lower = upn.to_lowercase();
    let found = admin_search(c, &format!("changes made to {upn}"), |x| {
        let o = keys::admin_object(x).to_lowercase();
        o == lower || o.starts_with(&format!("{lower}\\"))
    });
    if found.is_empty() {
        c.log().plain("No User Changes found.");
        return Ok(());
    }
    c.log()
        .plain(format!("Found {} changes made to this user", found.len()));
    admin_files(
        c,
        tree,
        "Simple_User_Changes",
        "User_Changes",
        Art::raw("hawk.user.raw_ual"),
        Formats::CSV_JSON,
        Some(&upn),
        &found,
    )
}

// ---------------------------------------------------------------------------------------------
// PSFramework log export

/// `<yyyy-MM-dd>_logs.csv` in the root: PSFramework's export of every Hawk.log line (13
/// columns, `Timestamp` host-local `yyyy-MM-dd HH:mm:ss.fff`), UTF-8 with a byte-order mark
/// whatever the edition (capture survey §1).
// source-derived (no 3.1 source): research gives the columns and the timestamp format only;
// the computer, file, line, level mapping, runspace and user values are invented.
fn psframework_log(c: &Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let world = c.world;
    let host = c.tenant_host;
    let offset = Duration::minutes(world.scenario.tenant.host_utc_offset_minutes.into());
    let mut rng = stream(world.seed, "hawk3/psframework");
    let computer = format!("IR-WKS{}", rng.digits(3));
    let runspace = rng.uuid().to_string();
    let module = if c.opts.non_windows {
        format!("/usr/local/share/powershell/Modules/HAWK/{HAWK3_VERSION}")
    } else if host.edition == crate::options::PsEdition::Ps51 {
        format!("C:\\Program Files\\WindowsPowerShell\\Modules\\HAWK\\{HAWK3_VERSION}")
    } else {
        format!("C:\\Program Files\\PowerShell\\Modules\\HAWK\\{HAWK3_VERSION}")
    };
    let sep = if c.opts.non_windows { "/" } else { "\\" };
    let file = format!("{module}{sep}internal{sep}functions{sep}Out-LogFile.ps1");
    let entries = c.omft.log.entries();
    let Some(first) = entries.first() else {
        return Ok(());
    };
    let mut last = first.at + offset;
    let rows: Vec<Row> = entries
        .iter()
        .map(|e| {
            // Milliseconds within the line's second, never before the previous line's.
            let local = (e.at + offset + Duration::milliseconds(rng.range(0, 999))).max(last);
            last = local;
            let (level, kind) = match e.level {
                Level::Error => ("Warning", "Error"),
                Level::Warning => ("Warning", "Warning"),
                _ => ("Host", "Information"),
            };
            vec![
                r("ComputerName", s(computer.clone())),
                r("File", s(file.clone())),
                r("FunctionName", s("Out-LogFile")),
                r("Level", s(level)),
                r("Line", Val::Int(52)),
                r("Message", s(e.message.clone())),
                r("ModuleName", s("HAWK")),
                r("Runspace", s(runspace.clone())),
                r("Tags", s("")),
                r("TargetObject", s("")),
                r(
                    "Timestamp",
                    s(local.format("%Y-%m-%d %H:%M:%S%.3f").to_string()),
                ),
                r("Type", s(kind)),
                r("Username", s(format!("{computer}\\analyst"))),
            ]
        })
        .collect();
    let rel = format!("{}_logs.csv", (first.at + offset).format("%Y-%m-%d"));
    let text = export_csv(&host, &rows, &mut DateEvidence::default()).text;
    tree.write(
        &super::omft::spec(
            &rel,
            Encoding::Utf8Bom,
            Art::raw("hawk.psframework_log"),
            None,
        ),
        &text,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::load;

    fn cmdlet(params: Value) -> Ual {
        let w = World::build(&load("hawk-investigate").unwrap(), 1).unwrap();
        let mut u = w.story.ual.first().cloned().unwrap_or_else(|| Ual {
            id: uuid::Uuid::nil(),
            time: w.collected_at(),
            record_type: RecordType::ExchangeAdmin,
            operation: String::new(),
            user_id: String::new(),
            audit: serde_json::Map::new(),
        });
        u.operation = "New-InboxRule".into();
        u.audit.insert("Parameters".into(), params);
        u
    }

    #[test]
    fn full_command_follows_get_simple_admin_audit_log() {
        let u = cmdlet(json!([
            {"Name": "Name", "Value": "Move it"},
            {"Name": "DeleteMessage", "Value": "True"},
            {"Name": "From", "Value": "a@fabrikam.test;b c@fabrikam.test"},
            {"Name": "Mailbox", "Value": "ann"},
        ]));
        assert_eq!(
            full_command(&u),
            "New-InboxRule -Name \"Move it\" -DeleteMessage:$True -From a@fabrikam.test;\"b c@fabrikam.test\" -From \"a@fabrikam.test;b c@fabrikam.test\" -Mailbox ann"
        );
    }

    #[test]
    fn simple_caller_reduces_on_behalf_of() {
        assert_eq!(keys::simple_caller(""), "***");
        assert_eq!(
            keys::simple_caller("ann@contoso.example"),
            "ann@contoso.example"
        );
        assert_eq!(
            keys::simple_caller("a/b/c/NAMPR01 on behalf of/x/ann"),
            "NAMPR01 on behalf of ann"
        );
    }
}
