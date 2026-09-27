//! `Start-HawkUserInvestigation` (research hawk layouts §1.3, §5, §6): the fourteen user
//! collectors for each investigated user, then the summary. With `hawk_mixed_editions` the
//! analyst runs it in a second, Windows PowerShell 5.1 session.

use super::omft::{Art, Formats, HawkVersion};
use super::tenant::{non_interactive_header, running, simple_and_raw, summary};
use super::{
    Ctx, additional_properties, date, date_text, expanded_row, json_val, model, opt, r, raw_row,
    register, register_flags, register_ual, s, simple_rows,
};
use crate::Result;
use crate::events::{RecordType, SignIn, SignInType, TraceMsg, Ual};
use crate::keys;
use crate::ps::{DtKind, Row, Val};
use crate::story::Evidence;
use crate::tree::Tree;
use crate::world::{InboxRule, Mailbox, User, World};
use chrono::{Duration, NaiveDate};
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Graph's refusal of sign-in logs without Entra ID P1.
const P1_REFUSED: &str = "Neither tenant is B2C or tenant doesn't have premium license";

pub(super) fn investigate(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    if c.opts.hawk_mixed_editions {
        // A new Windows PowerShell 5.1 session a few minutes later, pointed at the same folder.
        c.log().tick(120, 600);
        c.omft.host = c.user_host;
        non_interactive_header(c);
    } else {
        c.log().tick(20, 120);
    }
    let started = c.log().now();
    c.log().action("Starting User Investigation.");
    let users: Vec<&User> = c.users.clone();
    for u in &users {
        running(c, "Get-HawkUserConfiguration");
        configuration(c, tree, u)?;
        running(c, "Get-HawkUserInboxRule");
        inbox_rules(c, tree, u)?;
        running(c, "Get-HawkUserEmailForwarding");
        forwarding(c, tree, u)?;
        running(c, "Get-HawkUserAutoReply");
        auto_reply(c, tree, u)?;
        running(c, "Get-HawkUserEntraIDSignInLog");
        entra_signins(c, tree, u)?;
        running(c, "Get-HawkUserUALSignInLog");
        ual_signins(c, tree, u)?;
        running(c, "Get-HawkUserMailboxAuditing");
        mailbox_auditing(c, tree, u)?;
        running(c, "Get-HawkUserAdminAudit");
        admin_audit(c, tree, u)?;
        running(c, "Get-HawkUserMessageTrace");
        message_trace(c, tree, u)?;
        for step in &GATED {
            running(c, step.cmdlet);
            gated(c, tree, u, step)?;
        }
        running(c, "Get-HawkUserMobileDevice");
        mobile_devices(c, tree, u)?;
    }
    let upns = users.iter().map(|u| u.upn.clone()).collect();
    summary(c, started, Some(upns));
    Ok(())
}

pub(super) fn mailbox<'w>(world: &'w World, u: &User) -> Option<&'w Mailbox> {
    world.mailboxes.get(&u.upn)
}

/// The Exchange Online directory path of the tenant (see `tenant::exo_dn`).
fn user_dn(world: &World, u: &User) -> String {
    format!(
        "CN={},OU={},OU=Microsoft Exchange Hosted Organizations,DC=NAMPR04A001,DC=prod,DC=outlook,DC=example",
        u.alias, world.tenant.initial_domain
    )
}

fn email_addresses(world: &World, u: &User) -> Val {
    Val::Raw(json!([
        format!("SMTP:{}", u.upn),
        format!("smtp:{}@{}", u.alias, world.tenant.initial_domain),
    ]))
}

/// Get-HawkUserConfiguration: Format-List dumps of Get-EXOMailbox, its statistics, its folder
/// statistics and Get-EXOCasMailbox.
pub(super) fn configuration(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User) -> Result<()> {
    let world = c.world;
    let upn = u.upn.as_str();
    c.log().action(format!(
        "Initiating collection of mailbox configuration for {upn} from Exchange Online."
    ));
    let mb = mailbox(world, u);
    let guid = mb.map_or(u.mailbox_guid, |m| m.guid);
    let info = vec![vec![
        r("ExternalDirectoryObjectId", s(u.object_id.to_string())),
        r("UserPrincipalName", s(upn)),
        r("Alias", s(u.alias.clone())),
        r("DisplayName", s(u.display_name.clone())),
        r("EmailAddresses", email_addresses(world, u)),
        r("PrimarySmtpAddress", s(upn)),
        r(
            "RecipientType",
            s(mb.map_or("UserMailbox".into(), |m| m.recipient_type.clone())),
        ),
        r(
            "RecipientTypeDetails",
            s(mb.map_or("UserMailbox".into(), |m| m.recipient_type.clone())),
        ),
        r("Identity", s(u.alias.clone())),
        r("Id", s(u.alias.clone())),
        r("Name", s(u.alias.clone())),
        r("DistinguishedName", s(user_dn(world, u))),
        r("OrganizationId", s(world.tenant.initial_domain.clone())),
        r("Guid", s(guid.to_string())),
    ]];
    let w = c.omft.write(
        tree,
        "Mailbox_Info",
        Some(upn),
        Art::raw("hawk.user.mailbox_txt"),
        &info,
        Formats::TXT,
        false,
        false,
    )?;
    register(
        tree,
        &w,
        "mailboxes",
        |_| Some(keys::mailbox(upn)),
        |_| None,
    );
    let mut rng = crate::rng::stream(world.seed, &format!("hawk/mailbox/{upn}"));
    let items = rng.range(800, 9000);
    let deleted = rng.range(20, 400);
    let stats = vec![vec![
        r("DisplayName", s(u.display_name.clone())),
        r("MailboxGuid", s(guid.to_string())),
        r("DeletedItemCount", Val::Int(deleted)),
        r("ItemCount", Val::Int(items)),
        r(
            "TotalDeletedItemSize",
            s(format!("{} MB ({} bytes)", deleted / 10, deleted * 104_857)),
        ),
        r(
            "TotalItemSize",
            s(format!("{} MB ({} bytes)", items / 10, items * 104_857)),
        ),
    ]];
    c.omft.write(
        tree,
        "Mailbox_Statistics",
        Some(upn),
        Art::not_supported("hawk.user.mailbox_stats_txt"),
        &stats,
        Formats::TXT,
        false,
        false,
    )?;
    let folders: Vec<Row> = [
        (
            "Top of Information Store",
            "/Top of Information Store",
            "Root",
        ),
        ("Inbox", "/Inbox", "Inbox"),
        ("Sent Items", "/Sent Items", "SentItems"),
        ("Deleted Items", "/Deleted Items", "DeletedItems"),
        ("Drafts", "/Drafts", "Drafts"),
        ("Archive", "/Archive", "Archive"),
    ]
    .iter()
    .map(|(name, path, kind)| {
        let n = rng.range(0, 3000);
        vec![
            r("Name", s(*name)),
            r("FolderPath", s(*path)),
            r("FolderType", s(*kind)),
            r(
                "FolderId",
                s(crate::ual::folder_id(world, upn, &path.replace('/', "\\"))),
            ),
            r("ItemsInFolder", Val::Int(n)),
            r(
                "FolderSize",
                s(format!("{} KB ({} bytes)", n * 45, n * 46_080)),
            ),
            r("ItemsInFolderAndSubfolders", Val::Int(n)),
            r("CreationTime", date_text(u.created, DtKind::Local)),
        ]
    })
    .collect();
    c.omft.write(
        tree,
        "Mailbox_Folder_Statistics",
        Some(upn),
        Art::not_supported("hawk.user.mailbox_stats_txt"),
        &folders,
        Formats::TXT,
        false,
        false,
    )?;
    c.log().action("Gathering CAS Mailbox Information");
    let flag = |f: fn(&Mailbox) -> bool| Val::Bool(mb.is_none_or(f));
    let cas = vec![vec![
        r("ExternalDirectoryObjectId", s(u.object_id.to_string())),
        r("EmailAddresses", email_addresses(world, u)),
        r("PrimarySmtpAddress", s(upn)),
        r("DisplayName", s(u.display_name.clone())),
        r("ActiveSyncEnabled", flag(|m| m.activesync)),
        r("OWAEnabled", flag(|m| m.owa)),
        r("OWAforDevicesEnabled", Val::Bool(true)),
        r("EwsEnabled", flag(|m| m.ews)),
        r("PopEnabled", flag(|m| m.pop)),
        r("ImapEnabled", flag(|m| m.imap)),
        r("MAPIEnabled", flag(|m| m.mapi)),
        r("ECPEnabled", Val::Bool(true)),
        r("UniversalOutlookEnabled", Val::Bool(true)),
        r("SmtpClientAuthenticationDisabled", Val::Null),
        r("Name", s(u.alias.clone())),
        r("Identity", s(u.alias.clone())),
        r("Guid", s(guid.to_string())),
    ]];
    let w = c.omft.write(
        tree,
        "CAS_Mailbox_Info",
        Some(upn),
        Art::raw("hawk.user.mailbox_txt"),
        &cas,
        Formats::TXT,
        false,
        false,
    )?;
    register(
        tree,
        &w,
        "mailboxes",
        |_| Some(keys::mailbox(upn)),
        |_| None,
    );
    c.log().info(format!(
        "Completed collection of mailbox configuration for {upn} from Exchange Online."
    ));
    Ok(())
}

/// Recipients as Get-InboxRule prints them: `"Name" [SMTP:address]`; null when none.
fn recipients(world: &World, list: &[String]) -> Val {
    if list.is_empty() {
        return Val::Null;
    }
    let shown: Vec<String> = list
        .iter()
        .map(|a| {
            let name = world
                .user_by_upn(a)
                .map_or_else(|| a.clone(), |u| u.display_name.clone());
            format!("\"{name}\" [SMTP:{a}]")
        })
        .collect();
    Val::Raw(json!(shown))
}

fn words(list: &[String]) -> Val {
    if list.is_empty() {
        Val::Null
    } else {
        Val::Raw(json!(list))
    }
}

/// A Get-InboxRule object; Hawk replaces the description's line breaks with spaces and drops
/// its tabs before writing.
pub(super) fn inbox_rule_row(world: &World, u: &User, rule: &InboxRule) -> Row {
    let folder = |f: &Option<String>| opt(f.as_ref().map(|f| format!("{}:\\{f}", u.alias)));
    let description = rule.description().replace("\r\n", " ").replace('\t', "");
    vec![
        r("Description", s(description)),
        r("Enabled", Val::Bool(rule.enabled)),
        r("Identity", s(format!("{}\\{}", u.alias, rule.identity))),
        r("InError", Val::Bool(false)),
        r("ErrorType", s("None")),
        r("Name", s(rule.name.clone())),
        r("Priority", Val::Int(rule.priority.into())),
        r("RuleIdentity", Val::Raw(json!(rule.identity))),
        r("SupportedByTask", Val::Bool(true)),
        r("Legacy", Val::Bool(false)),
        r("BodyContainsWords", words(&rule.body_contains)),
        r("ExceptIfBodyContainsWords", Val::Null),
        r("FlaggedForAction", Val::Null),
        r("From", recipients(world, &rule.from)),
        r("ExceptIfFrom", Val::Null),
        r("FromAddressContainsWords", Val::Null),
        r("HasAttachment", Val::Bool(rule.has_attachment)),
        r("ExceptIfHasAttachment", Val::Bool(false)),
        r("MarkImportance", Val::Null),
        r("MessageTypeMatches", Val::Null),
        r("MyNameInToOrCcBox", Val::Bool(false)),
        r("SentOnlyToMe", Val::Bool(false)),
        r("SubjectContainsWords", words(&rule.subject_contains)),
        r(
            "SubjectOrBodyContainsWords",
            words(&rule.subject_or_body_contains),
        ),
        r("WithImportance", Val::Null),
        r("WithinSizeRangeMaximum", Val::Null),
        r("WithinSizeRangeMinimum", Val::Null),
        r("ApplyCategory", Val::Null),
        r("CopyToFolder", folder(&rule.copy_to_folder)),
        r("DeleteMessage", Val::Bool(rule.delete_message)),
        r(
            "ForwardAsAttachmentTo",
            recipients(world, &rule.forward_as_attachment_to),
        ),
        r("ForwardTo", recipients(world, &rule.forward_to)),
        r("MarkAsRead", Val::Bool(rule.mark_as_read)),
        r("MoveToFolder", folder(&rule.move_to_folder)),
        r("RedirectTo", recipients(world, &rule.redirect_to)),
        r("SendTextMessageNotificationTo", Val::Raw(json!([]))),
        r("SoftDeleteMessage", Val::Bool(rule.soft_delete)),
        r("StopProcessingRules", Val::Bool(rule.stop_processing)),
        r("MailboxOwnerId", s(u.alias.clone())),
        r("IsValid", Val::Bool(true)),
        r("ObjectState", s("New")),
    ]
}

/// `Get-HawkUserInboxRule`'s investigate test (H12): DeleteMessage, or a forward / redirect
/// target (typed values: `$false` is not flagged).
pub(super) fn suspicious_rule(rule: &InboxRule) -> bool {
    rule.delete_message
        || !rule.forward_as_attachment_to.is_empty()
        || !rule.forward_to.is_empty()
        || !rule.redirect_to.is_empty()
}

/// Get-HawkUserInboxRule: inbox rules (flagged ones appended one by one to
/// `_Investigate_InboxRules`), then sweep rules.
fn inbox_rules(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User) -> Result<()> {
    let world = c.world;
    let upn = u.upn.as_str();
    c.log().action(format!(
        "Initiating collection of Exchange Inbox Rules for {upn} from Exchange Online."
    ));
    let rules: Vec<&InboxRule> = world
        .inbox_rules
        .iter()
        .filter(|r| r.mailbox.eq_ignore_ascii_case(upn))
        .collect();
    if rules.is_empty() {
        c.log().action(format!("No Inbox Rules found for {upn}"));
    } else {
        let rows: Vec<Row> = rules.iter().map(|r| inbox_rule_row(world, u, r)).collect();
        let flagged: Vec<usize> = (0..rules.len())
            .filter(|i| suspicious_rule(rules[*i]))
            .collect();
        for i in &flagged {
            let w = c.omft.write(
                tree,
                "_Investigate_InboxRules",
                Some(upn),
                Art::raw("hawk.investigate_file"),
                std::slice::from_ref(&rows[*i]),
                Formats::CSV_JSON,
                true,
                false,
            )?;
            register_flags(tree, &w);
        }
        if !flagged.is_empty() {
            c.log().notice(format!(
                "Found {} inbox rules requiring investigation for {upn}",
                flagged.len()
            ));
            c.log().notice(
                "Please verify this activity is legitimate. Details in _Investigate_InboxRules.csv/json",
            );
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
            Some(upn),
            Art::raw("hawk.user.inbox_rules"),
            &rows,
            Formats::CSV_JSON,
            true,
            false,
        )?;
        register(tree, &w, "inbox_rules", key, ev);
    }
    c.log().action(format!("Gathering Sweep Rules: {upn}"));
    let sweeps: Vec<&crate::world::SweepRule> = world
        .sweep_rules
        .iter()
        .filter(|r| r.mailbox.eq_ignore_ascii_case(upn))
        .collect();
    if sweeps.is_empty() {
        c.log().info("No Sweep Rules found");
    } else {
        let rows: Vec<Row> = sweeps
            .iter()
            .map(|sw| {
                vec![
                    r("Name", s(sw.name.clone())),
                    r("RuleId", s(sw.identity.clone())),
                    r("Enabled", Val::Bool(sw.enabled)),
                    r(
                        "SourceFolder",
                        s(format!("{}:\\{}", u.alias, sw.source_folder)),
                    ),
                    r(
                        "DestinationFolder",
                        s(format!("{}:\\{}", u.alias, sw.destination_folder)),
                    ),
                    r("Sender", Val::Null),
                    r("KeepLatest", Val::Int(sw.keep_latest.into())),
                    r("KeepForDays", Val::Null),
                    r("SystemCategory", Val::Null),
                    r("MailboxOwnerId", s(u.alias.clone())),
                    r("Identity", s(format!("{}\\{}", u.alias, sw.identity))),
                    r("IsValid", Val::Bool(true)),
                    r("ObjectState", s("New")),
                ]
            })
            .collect();
        let key = |i: usize| Some(keys::inbox_rule("sweep", &u.alias, &sweeps[i].identity));
        let w = c.omft.write(
            tree,
            "SweepRules",
            Some(upn),
            Art::raw("hawk.user.sweep_rules"),
            &rows,
            Formats::CSV_JSON,
            false,
            false,
        )?;
        register(tree, &w, "inbox_rules", key, |_| None);
        let w = c.omft.write(
            tree,
            "All_SweepRules",
            None,
            Art::derived("hawk.tenant.all_sweep_rules"),
            &rows,
            Formats::CSV_JSON,
            true,
            false,
        )?;
        register(tree, &w, "inbox_rules", key, |_| None);
    }
    c.log().info(format!(
        "Completed collection of Exchange Inbox Rules for {upn} from Exchange Online."
    ));
    Ok(())
}

/// Get-HawkUserEmailForwarding (H13): the report row goes to the user folder and, appended,
/// to `Tenant/User_ForwardingReport`; a mailbox with forwarding also to
/// `_Investigate_Users_WithForwarding`.
pub(super) fn forwarding(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User) -> Result<()> {
    let world = c.world;
    let upn = u.upn.as_str();
    c.log().action(format!(
        "Initiating collection of email forwarding configuration for {upn} from Exchange Online."
    ));
    let mb = mailbox(world, u);
    let smtp = mb.and_then(|m| m.forwarding_smtp.clone()).map(|a| {
        if a.to_lowercase().starts_with("smtp:") {
            a
        } else {
            format!("smtp:{a}")
        }
    });
    let address = mb.and_then(|m| m.forwarding_address.clone());
    let row = vec![
        r("DisplayName", s(u.display_name.clone())),
        r("UserPrincipalName", s(upn)),
        r("PrimarySmtpAddress", s(upn)),
        r("ForwardingSmtpAddress", opt(smtp.clone())),
        r("ForwardingAddress", opt(address.clone())),
        r(
            "DeliverToMailboxAndForward",
            Val::Bool(mb.is_some_and(|m| m.deliver_and_forward)),
        ),
        r(
            "WhenChangedUTC",
            date(mb.map_or(u.created, |m| m.when_changed), DtKind::Utc),
        ),
    ];
    let rows = vec![row];
    if smtp.is_none() && address.is_none() {
        c.log()
            .info("Get-HawkUserEmailForwarding completed successfully");
        c.log().action("No forwarding configuration found");
    } else {
        c.log()
            .notice(format!("Found email forwarding configured for {upn}"));
        c.log().notice("Please verify this activity is legitimate.");
        let w = c.omft.write(
            tree,
            "_Investigate_Users_WithForwarding",
            Some(upn),
            Art::raw("hawk.investigate_file"),
            &rows,
            Formats::CSV_JSON,
            true,
            true,
        )?;
        register_flags(tree, &w);
    }
    let key = |_| Some(keys::mailbox(upn));
    let ev = |_| Some(Evidence::Mailbox(upn.to_string()));
    let w = c.omft.write(
        tree,
        "User_ForwardingReport",
        None,
        Art::derived("hawk.tenant.user_forwarding_report"),
        &rows,
        Formats::CSV_JSON,
        true,
        false,
    )?;
    register(tree, &w, "mailboxes", key, ev);
    let w = c.omft.write(
        tree,
        "ForwardingReport",
        Some(upn),
        Art::raw("hawk.user.forwarding"),
        &rows,
        Formats::CSV_JSON,
        false,
        false,
    )?;
    register(tree, &w, "mailboxes", key, ev);
    c.log().info(format!(
        "Completed collection of email forwarding configuration for {upn} from Exchange Online."
    ));
    Ok(())
}

/// Get-HawkUserAutoReply: written only when auto-reply is not `Disabled`.
fn auto_reply(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User) -> Result<()> {
    let world = c.world;
    let upn = u.upn.as_str();
    c.log().action(format!(
        "Initiating collection of auto-reply configuration for {upn} from Exchange Online."
    ));
    match mailbox(world, u).map(|m| &m.auto_reply) {
        Some(a) if !a.state.eq_ignore_ascii_case("Disabled") => {
            let row = vec![
                r("AutoDeclineFutureRequestsWhenOOF", Val::Bool(false)),
                r("AutoReplyState", s(a.state.clone())),
                r("CreateOOFEvent", Val::Bool(false)),
                r("DeclineAllEventsForScheduledPeriod", Val::Bool(false)),
                r("DeclineEventsForScheduledPeriod", Val::Bool(false)),
                r("DeclineMeetingMessage", s("")),
                r("EndTime", date(a.end, DtKind::Local)),
                r("EventsToDeleteIDs", Val::Raw(json!([]))),
                r("ExternalAudience", s(a.audience.clone())),
                r("ExternalMessage", s(a.external.clone())),
                r("InternalMessage", s(a.internal.clone())),
                r("OOFEventSubject", s("")),
                r("StartTime", date(a.start, DtKind::Local)),
                r("Recipients", Val::Raw(json!([]))),
                r("ReminderMinutesBeforeStart", Val::Int(0)),
                r("ReminderMessage", s("")),
                r("MailboxOwnerId", s(u.alias.clone())),
                r("Identity", s(u.alias.clone())),
                r("IsValid", Val::Bool(true)),
                r("ObjectState", s("Unchanged")),
            ];
            let w = c.omft.write(
                tree,
                "AutoReply",
                Some(upn),
                Art::raw("hawk.user.autoreply"),
                &[row],
                Formats::TXT,
                false,
                false,
            )?;
            register(
                tree,
                &w,
                "mailboxes",
                |_| Some(keys::mailbox(upn)),
                |_| Some(Evidence::Mailbox(upn.to_string())),
            );
        }
        _ => c.log().info("AutoReply is not enabled or not configured."),
    }
    c.log().info(format!(
        "Completed collection of auto-reply configuration for {upn} from Exchange Online."
    ));
    Ok(())
}

/// A v1.0 `MicrosoftGraphSignIn` (Get-MgAuditLogSignIn).
fn signin_row(s_: &SignIn) -> Row {
    let loc = &s_.location;
    let device_id = if s_.trust_type.is_some() {
        s_.device.device_id.to_string()
    } else {
        String::new()
    };
    let failure = if s_.error_code == 0 {
        Value::Null
    } else {
        json!(s_.failure_reason)
    };
    vec![
        r("AppDisplayName", s(s_.app_name.clone())),
        r("AppId", s(s_.app_id.to_string())),
        r(
            "AppliedConditionalAccessPolicies",
            model("IMicrosoftGraphAppliedConditionalAccessPolicy[]", json!([])),
        ),
        r("ClientAppUsed", s(s_.client_app.clone())),
        r("ConditionalAccessStatus", s(s_.ca_status.clone())),
        r("CorrelationId", s(s_.correlation_id.to_string())),
        r("CreatedDateTime", date(s_.time, DtKind::Utc)),
        r(
            "DeviceDetail",
            model(
                "MicrosoftGraphDeviceDetail",
                json!({
                    "Browser": s_.device.browser,
                    "DeviceId": device_id,
                    "DisplayName": if s_.trust_type.is_some() { s_.device.device_name.clone() } else { String::new() },
                    "IsCompliant": s_.device_compliant.unwrap_or(false),
                    "IsManaged": s_.device_managed.unwrap_or(false),
                    "OperatingSystem": s_.device.os,
                    "TrustType": s_.trust_type.clone().unwrap_or_default(),
                    "AdditionalProperties": {},
                }),
            ),
        ),
        r("IPAddress", s(s_.ip.to_string())),
        r("Id", s(s_.id.to_string())),
        r(
            "IsInteractive",
            Val::Bool(s_.event_type == SignInType::Interactive),
        ),
        r(
            "Location",
            model(
                "MicrosoftGraphSignInLocation",
                json!({
                    "City": loc.city,
                    "CountryOrRegion": loc.country_iso,
                    "GeoCoordinates": {"Altitude": Value::Null, "Latitude": loc.lat,
                        "Longitude": loc.lon, "AdditionalProperties": {}},
                    "State": loc.state,
                    "AdditionalProperties": {},
                }),
            ),
        ),
        r("ResourceDisplayName", s(s_.resource_name.clone())),
        r("ResourceId", s(s_.resource_id.to_string())),
        r("RiskDetail", s(s_.risk_detail.clone())),
        r(
            "RiskEventTypes",
            Val::Model("System.String[]".into(), json!([])),
        ),
        r(
            "RiskEventTypesV2",
            Val::Model("System.String[]".into(), json!(s_.risk_event_types)),
        ),
        r("RiskLevelAggregated", s(s_.risk_aggregated.clone())),
        r("RiskLevelDuringSignIn", s(s_.risk_during.clone())),
        r("RiskState", s(s_.risk_state.clone())),
        r(
            "Status",
            model(
                "MicrosoftGraphSignInStatus",
                json!({"AdditionalDetails": Value::Null, "ErrorCode": s_.error_code,
                    "FailureReason": failure, "AdditionalProperties": {}}),
            ),
        ),
        r("UserDisplayName", s(s_.user_display.clone())),
        r("UserId", opt(s_.user_id.map(|x| x.to_string()))),
        r("UserPrincipalName", s(s_.user.clone())),
        r("AdditionalProperties", additional_properties()),
    ]
}

/// Get-HawkUserEntraIDSignInLog (H14): v1.0 sign-ins (interactive) of the last 14 days of
/// the window; Graph refuses without Entra ID P1.
fn entra_signins(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User) -> Result<()> {
    let world = c.world;
    let upn = u.upn.as_str();
    let end = world.window_end();
    let two_weeks = end - Duration::days(14);
    let start = world.window_start().max(two_weeks);
    c.log().action(format!(
        "Initiating collection of sign-in logs for {upn} from Entra ID."
    ));
    c.log()
        .info("Hawk Entra ID Sign-in logs is limited to the most recent 14 days");
    let range = format!("{} to {}", start.format("%Y-%m-%d"), end.format("%Y-%m-%d"));
    if world.window_start() < two_weeks {
        c.log().info(format!(
            "Your requested date range exceeds this limit. Data will only be available from {range}"
        ));
    } else {
        c.log().info(format!("Retrieving data from {range}"));
    }
    c.log().tick(1, 4);
    if !world.licence.p1() {
        c.log().error(format!(
            "Error retrieving sign-in logs for {upn} : {P1_REFUSED}"
        ));
        return Ok(());
    }
    let mut signins: Vec<SignIn> = c
        .days
        .iter()
        .flat_map(|d| &d.signins)
        .filter(|x| {
            x.event_type == SignInType::Interactive
                && x.user.eq_ignore_ascii_case(upn)
                && x.time >= start
                && x.time <= end
        })
        .cloned()
        .collect();
    signins.sort_by_key(|x| std::cmp::Reverse((x.time, x.id)));
    if signins.is_empty() {
        c.log().info(format!(
            "No sign-in logs found for {upn} in the specified time period"
        ));
    } else {
        c.log().info(format!(
            "Retrieved {} sign-in log entries for {upn}",
            signins.len()
        ));
        let rows: Vec<Row> = signins.iter().map(signin_row).collect();
        let prefix = format!("Entra_Sign_In_Log_{upn}");
        let w = c.omft.write(
            tree,
            &prefix,
            Some(upn),
            Art::raw("hawk.user.entra_signin"),
            &rows,
            Formats::CSV_JSON,
            false,
            false,
        )?;
        register(
            tree,
            &w,
            "signins",
            |i| Some(keys::signin(signins[i].id)),
            |i| Some(Evidence::SignIn(signins[i].id)),
        );
        let risky = |l: &str| {
            ["high", "medium", "low"]
                .iter()
                .any(|x| l.eq_ignore_ascii_case(x))
        };
        let flagged: Vec<usize> = (0..signins.len())
            .filter(|i| risky(&signins[*i].risk_during) || risky(&signins[*i].risk_aggregated))
            .collect();
        if !flagged.is_empty() {
            c.log()
                .notice(format!("Found {} risky sign-ins for {upn}", flagged.len()));
            let rows: Vec<Row> = flagged.iter().map(|i| rows[*i].clone()).collect();
            let w = c.omft.write(
                tree,
                &format!("_Investigate_Entra_Sign_In_Log_{upn}"),
                Some(upn),
                Art::raw("hawk.investigate_file"),
                &rows,
                Formats::CSV_JSON,
                false,
                true,
            )?;
            register_flags(tree, &w);
            for (field, what) in [
                (0, "sign-ins with risk level during sign-in"),
                (1, "sign-ins with aggregated risk level"),
            ] {
                let mut groups: Vec<(String, usize)> = Vec::new();
                for i in &flagged {
                    let l = if field == 0 {
                        &signins[*i].risk_during
                    } else {
                        &signins[*i].risk_aggregated
                    };
                    match groups.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(l)) {
                        Some(g) => g.1 += 1,
                        None => groups.push((l.clone(), 1)),
                    }
                }
                for (name, n) in groups.iter().filter(|(n, _)| risky(n)) {
                    c.log().notice(format!("Found {n} {what}: {name}"));
                }
            }
            c.log().notice(format!(
                "Review _Investigate_Entra_Sign_In_Log_{upn}.csv/json for complete details"
            ));
        }
    }
    c.log().info(format!(
        "Completed collection of Entra sign-in logs for {upn} from Entra ID."
    ));
    Ok(())
}

/// `"id:type,id:type"` of an Actor / Target list.
fn id_types(v: &Value) -> String {
    let items: Vec<String> = v
        .as_array()
        .map(|a| {
            a.iter()
                .map(|x| {
                    let id = x.get("ID").map(super::simple::ps_text).unwrap_or_default();
                    let ty = x
                        .get("Type")
                        .map(super::simple::ps_text)
                        .unwrap_or_default();
                    format!("{id}:{ty},")
                })
                .collect()
        })
        .unwrap_or_default();
    items.concat().trim_end_matches(',').to_string()
}

/// `Import-AzureAuthenticationLog` over the expanded records (with the geolocation columns
/// Hawk adds, null when the lookup fails): per record its AuditData properties in `Get-Member`
/// order (alphabetical), each ExtendedProperties entry as its own column and
/// ExtendedProperties itself `"Name:,Name:"` (Hawk reads `$ep.v`, never set), Actor and
/// Target as `id:type` lists, CreationTime in the host's short `g` form; the columns
/// `CreationTime, UserId, Workload, ClientIP, CountryName, KnownMicrosoftIP` first; the rows
/// sorted by the CreationTime text. Returns (rows, record index per row).
pub(super) fn converted(c: &Ctx<'_>, records: &[Ual]) -> (Vec<Row>, Vec<usize>) {
    let host = c.omft.host;
    let geo = [
        "CountryName",
        "RegionCode",
        "RegionName",
        "City",
        "KnownMicrosoftIP",
    ];
    let mut base: Vec<String> = Vec::new();
    let mut entries: Vec<Vec<(String, Val)>> = Vec::new();
    for u in records {
        let mut names: Vec<String> = u.audit.keys().cloned().collect();
        names.extend(geo.iter().map(|g| g.to_string()));
        names.sort_by_key(|n| n.to_lowercase());
        let mut e: Vec<(String, Val)> = Vec::new();
        let has =
            |e: &Vec<(String, Val)>, k: &str| e.iter().any(|(n, _)| n.eq_ignore_ascii_case(k));
        for name in names {
            if !base.iter().any(|b| b.eq_ignore_ascii_case(&name)) {
                base.push(name.clone());
            }
            let v = u.audit.get(&name);
            match name.as_str() {
                "ExtendedProperties" => {
                    if let Some(Value::Array(eps)) = v {
                        let mut shown = String::new();
                        for ep in eps {
                            let n = ep
                                .get("Name")
                                .map(super::simple::ps_text)
                                .unwrap_or_default();
                            if !base.iter().any(|b| b.eq_ignore_ascii_case(&n)) {
                                base.push(n.clone());
                            }
                            if !has(&e, &n) {
                                let val = ep.get("Value").map_or(Val::Null, json_val);
                                e.push((n.clone(), val));
                            }
                            shown.push_str(&format!("{n}:,"));
                        }
                        e.push((name.clone(), s(shown.trim_end_matches(',').to_string())));
                    }
                }
                "Actor" | "Target" => {
                    if let Some(v) = v {
                        e.push((name.clone(), s(id_types(v))));
                    }
                }
                "CreationTime" => {
                    e.push((
                        name.clone(),
                        s(host.culture_date_short(u.time, DtKind::Utc)),
                    ));
                }
                _ => {
                    if !has(&e, &name) {
                        e.push((name.clone(), v.map_or(Val::Null, json_val)));
                    }
                }
            }
        }
        entries.push(e);
    }
    let lead = [
        "CreationTime",
        "UserId",
        "Workload",
        "ClientIP",
        "CountryName",
        "KnownMicrosoftIP",
    ];
    let mut order: Vec<String> = lead
        .iter()
        .filter(|l| base.iter().any(|b| b.eq_ignore_ascii_case(l)))
        .map(|l| l.to_string())
        .collect();
    order.extend(
        base.iter()
            .filter(|b| !lead.iter().any(|l| l.eq_ignore_ascii_case(b)))
            .cloned(),
    );
    let mut rows: Vec<(Row, usize)> = entries
        .into_iter()
        .enumerate()
        .map(|(i, e)| {
            let row: Row = order
                .iter()
                .map(|k| {
                    let v = e
                        .iter()
                        .find(|(n, _)| n.eq_ignore_ascii_case(k))
                        .map_or(Val::Null, |(_, v)| v.clone());
                    (k.clone(), v)
                })
                .collect();
            (row, i)
        })
        .collect();
    let time = |r: &Row| super::text_of(r, "CreationTime").unwrap_or_default();
    rows.sort_by_key(|(r, _)| time(r));
    rows.into_iter().unzip()
}

/// Get-HawkUserUALSignInLog (Hawk 3.1: Get-HawkUserAuthHistory): three searches
/// (AccountLogon, AzureActiveDirectory, StsLogon) concatenated; `Converted_Authentication_Logs`
/// then `Raw_Authentication_Logs`. Hawk 3.1's raw records have no `AuditSearchRequestMetadata`
/// (capture survey §2e: 10 columns).
pub(super) fn ual_signins(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User) -> Result<()> {
    let upn = u.upn.clone();
    let metadata = c.omft.version == HawkVersion::V4;
    c.log().action(format!(
        "Initiating collection of Sign-In logs for {upn} from the UAL."
    ));
    let nl = c.omft.host.newline;
    let mut records: Vec<Ual> = Vec::new();
    let mut raw: Vec<Row> = Vec::new();
    for rt in [
        RecordType::AzureActiveDirectoryAccountLogon,
        RecordType::AzureActiveDirectory,
        RecordType::AzureActiveDirectoryStsLogon,
    ] {
        c.log().action(format!(
            "Searching Unified Audit log for Records of type: {}",
            rt.name()
        ));
        let found = c.search(
            &format!(
                "Search-UnifiedAuditLog -UserIds {upn} -RecordType {}",
                rt.name()
            ),
            |x| x.record_type == rt && x.user_id.eq_ignore_ascii_case(&upn),
        );
        let n = found.len();
        raw.extend(found.iter().enumerate().map(|(i, x)| {
            raw_row(x, i, n, nl)
                .into_iter()
                .filter(|(k, _)| metadata || k != "AuditSearchRequestMetadata")
                .collect::<Row>()
        }));
        records.extend(found);
    }
    if records.is_empty() {
        c.log().error(
            "No results found when searching UAL for AzureActiveDirectoryAccountLogon events",
        );
    } else {
        c.log().action("Converting AuditData");
        c.log().action("Converting to Human Readable");
        let (rows, index) = converted(c, &records);
        let w = c.omft.write(
            tree,
            "Converted_Authentication_Logs",
            Some(&upn),
            Art::derived("hawk.user.converted_auth"),
            &rows,
            Formats::CSV_JSON,
            false,
            false,
        )?;
        let ordered: Vec<Ual> = index.iter().map(|i| records[*i].clone()).collect();
        register_ual(tree, &w, &ordered);
        let w = c.omft.write(
            tree,
            "Raw_Authentication_Logs",
            Some(&upn),
            Art::raw("hawk.user.raw_auth"),
            &raw,
            Formats::CSV_JSON,
            false,
            false,
        )?;
        register_ual(tree, &w, &records);
    }
    c.log().info(format!(
        "Completed collection of Sign-In logs for {upn} from the UAL."
    ));
    Ok(())
}

/// Get-HawkUserMailboxAuditing: ExchangeItem and ExchangeItemGroup records by the user, when
/// the mailbox is audited.
fn mailbox_auditing(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User) -> Result<()> {
    let world = c.world;
    let upn = u.upn.clone();
    c.log().action(format!(
        "Initiating collection of Mailbox Audit Logs for {upn} from the UAL."
    ));
    if mailbox(world, u).is_some_and(|m| m.audit_enabled) {
        c.log().info("Mailbox Auditing is enabled.");
        c.omft.created(&upn);
        let mut total = 0;
        for (rt, simple, logs) in [
            (
                RecordType::ExchangeItem,
                "ExchangeItem_Simple",
                "ExchangeItem_Logs",
            ),
            (
                RecordType::ExchangeItemGroup,
                "ExchangeItemGroup_Simple",
                "ExchangeItemGroup_Logs",
            ),
        ] {
            c.log().action(format!(
                "Searching Unified Audit Log for {} events.",
                rt.name()
            ));
            if rt == RecordType::ExchangeItemGroup {
                c.log()
                    .action("Please be patient, this can take a while...");
            }
            let found = c.search(
                &format!(
                    "Search-UnifiedAuditLog -UserIds {upn} -RecordType {}",
                    rt.name()
                ),
                |x| x.record_type == rt && x.user_id.eq_ignore_ascii_case(&upn),
            );
            total += found.len();
            if found.is_empty() {
                if rt == RecordType::ExchangeItem {
                    c.log()
                        .info("ExchangeItem event search completed successfully");
                    c.log().action("No ExchangeItem events found.");
                } else {
                    c.log()
                        .info("ExchangeItemGroup search completed successfully");
                    c.log().action("No ExchangeItemGroup events found.");
                }
                continue;
            }
            c.log()
                .info(format!("Found {} {} events.", found.len(), rt.name()));
            if rt == RecordType::ExchangeItemGroup {
                c.log()
                    .action("Processing all ExchangeItemGroup events, this can take a while...");
            }
            simple_and_raw(c, tree, simple, logs, Some(&upn), &found, false)?;
        }
        c.log()
            .info(format!("Completed processing {total} total events."));
    } else {
        c.log().info(format!("Auditing not enabled for {upn}"));
        c.log()
            .info("Enable auditing to track mailbox access patterns.");
    }
    c.log().info(format!(
        "Completed collection of Mailbox Audit Logs for {upn} from the UAL."
    ));
    Ok(())
}

/// Get-HawkUserAdminAudit: every Exchange admin cmdlet the user ran.
fn admin_audit(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User) -> Result<()> {
    let upn = u.upn.clone();
    c.log().action(format!(
        "Initiating collection of admin audit events for {upn} from the UAL."
    ));
    let found = c.search(
        &format!("Search-UnifiedAuditLog -UserIds {upn} -RecordType ExchangeAdmin -Operations '*'"),
        |x| x.record_type == RecordType::ExchangeAdmin && x.user_id.eq_ignore_ascii_case(&upn),
    );
    if found.is_empty() {
        c.log()
            .info("Get-HawkUserAdminAudit completed successfully");
        c.log().action("No User Changes found.");
    } else {
        c.log()
            .info(format!("Found {} changes made to this user", found.len()));
        c.omft.created(&upn);
        simple_and_raw(
            c,
            tree,
            "Simple_User_Changes",
            "User_Changes",
            Some(&upn),
            &found,
            false,
        )?;
    }
    c.log().info(format!(
        "Completed collection of admin audit events for {upn} from the UAL."
    ));
    Ok(())
}

/// Get-HawkUserMessageTrace: `Get-MessageTrace -Sender <address>` with the cmdlet's default
/// window, the 48 hours before the run (not Hawk's window).
pub(super) fn message_trace(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User) -> Result<()> {
    let world = c.world;
    let upn = u.upn.as_str();
    c.log().action(format!(
        "Initiating collection of Message Trace Data for {upn} from Exchange Online."
    ));
    let sender = mailbox(world, u).map_or(upn.to_string(), |m| m.primary_smtp.clone());
    c.log()
        .action(format!("Gathering messages sent by: {sender}"));
    let now = c.log().now();
    let from = now - Duration::hours(48);
    let mut dates: BTreeSet<NaiveDate> = BTreeSet::new();
    let mut d = from.date_naive();
    while d <= now.date_naive() {
        dates.insert(d);
        d = match d.succ_opt() {
            Some(n) => n,
            None => break,
        };
    }
    let mut msgs: Vec<TraceMsg> = dates
        .into_iter()
        .flat_map(|d| world.day(d).trace)
        .filter(|t| {
            t.sender.eq_ignore_ascii_case(&sender) && t.received >= from && t.received < now
        })
        .collect();
    msgs.sort_by_key(|t| std::cmp::Reverse((t.received, t.trace_id)));
    let mut rows: Vec<Row> = Vec::new();
    let mut keyed: Vec<(String, Evidence)> = Vec::new();
    for t in &msgs {
        for (recipient, status) in &t.recipients {
            rows.push(vec![
                r("Organization", s(world.tenant.initial_domain.clone())),
                r("MessageId", s(t.internet_message_id.clone())),
                r("Received", date(t.received, DtKind::Unspecified)),
                r("SenderAddress", s(t.sender.clone())),
                r("RecipientAddress", s(recipient.clone())),
                r("Subject", s(t.subject.clone())),
                r("Status", s(status.clone())),
                r("ToIP", opt(t.to_ip.map(|ip| ip.to_string()))),
                r("FromIP", opt(t.from_ip.map(|ip| ip.to_string()))),
                r("Size", Val::Int(t.size as i64)),
                r("MessageTraceId", s(t.trace_id.to_string())),
                r("StartDate", date_text(from, DtKind::Utc)),
                r("EndDate", date_text(now, DtKind::Utc)),
                r("Index", Val::Int(rows.len() as i64)),
            ]);
            keyed.push((
                keys::trace(t.trace_id, recipient),
                Evidence::Trace {
                    trace_id: t.trace_id,
                    recipient: recipient.clone(),
                },
            ));
        }
    }
    let w = c.omft.write(
        tree,
        "Message_Trace",
        Some(upn),
        Art::raw("hawk.user.message_trace"),
        &rows,
        Formats::CSV_JSON,
        false,
        false,
    )?;
    register(
        tree,
        &w,
        "message_trace",
        |i| Some(keyed[i].0.clone()),
        |i| Some(keyed[i].1.clone()),
    );
    c.log().info(format!(
        "Completed collection of Message Trace Data for {upn} from Exchange Online."
    ));
    Ok(())
}

/// A per-operation UAL collector gated on the mailbox's AuditOwner list.
struct Gated {
    cmdlet: &'static str,
    what: &'static str,
    gate: &'static str,
    operation: &'static str,
    prefix: &'static str,
    none: &'static str,
}

const GATED: [Gated; 4] = [
    Gated {
        cmdlet: "Get-HawkUserMailItemsAccessed",
        what: "MailItemsAccessed",
        gate: "MailItemsAccessed",
        operation: "MailItemsAccessed",
        prefix: "MailItemsAccessed",
        none: "No MailItemsAccessed found for",
    },
    Gated {
        cmdlet: "Get-HawkUserExchangeSearchQuery",
        what: "Exchange Search queries",
        gate: "SearchQueryInitiated",
        operation: "SearchQueryInitiatedExchange",
        prefix: "ExchangeSearchQueries",
        none: "No Exchange Search Queries found for",
    },
    Gated {
        cmdlet: "Get-HawkUserMailSendActivity",
        what: "mail 'Send' logs",
        gate: "Send",
        operation: "Send",
        prefix: "SendActivity",
        none: "No mail 'Send' logs found for",
    },
    Gated {
        cmdlet: "Get-HawkUserSharePointSearchQuery",
        what: "SharePoint Search queries",
        gate: "SearchQueryInitiated",
        operation: "SearchQueryInitiatedSharePoint",
        prefix: "SharePointSearches",
        none: "No SharePoint Search Queries found for",
    },
];

/// Get-HawkUserMailItemsAccessed / ExchangeSearchQuery / MailSendActivity /
/// SharePointSearchQuery: when the mailbox's AuditOwner holds the gate action, the expanded
/// AuditData (`<Prefix>_<UPN>_<u>`) and its Simple twin.
fn gated(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User, step: &Gated) -> Result<()> {
    let world = c.world;
    let upn = u.upn.clone();
    c.log().action(format!(
        "Initiating collection of {} for {upn} from the UAL.",
        step.what
    ));
    c.log().info("Please be patient, this can take a while...");
    let enabled = mailbox(world, u).is_some_and(|m| {
        m.audit_owner
            .iter()
            .any(|a| a.eq_ignore_ascii_case(step.gate))
    });
    if enabled {
        c.log().info(format!(
            "Operation '{}' verified enabled for {upn}.",
            step.gate
        ));
        let op = step.operation;
        let found = c.search(
            &format!("Search-UnifiedAuditLog -Operations '{op}' -UserIds {upn}"),
            |x| x.operation.eq_ignore_ascii_case(op) && x.user_id.eq_ignore_ascii_case(&upn),
        );
        if found.is_empty() {
            c.log().info(format!("{} {upn}.", step.none));
        } else {
            c.omft.created(&upn);
            let nl = c.omft.host.newline;
            let raw = super::raw_rows(&found, nl);
            let label = format!("{upn}/Simple_{}_{upn}", step.prefix);
            let simple = simple_rows(world, &raw, &found, &label);
            let expanded: Vec<Row> = found.iter().map(expanded_row).collect();
            let w = c.omft.write(
                tree,
                &format!("{}_{upn}", step.prefix),
                Some(&upn),
                Art::raw("hawk.user.raw_ual"),
                &expanded,
                Formats::CSV_JSON,
                false,
                false,
            )?;
            register_ual(tree, &w, &found);
            let w = c.omft.write(
                tree,
                &format!("Simple_{}_{upn}", step.prefix),
                Some(&upn),
                Art::derived("hawk.user.simple_ual"),
                &simple,
                Formats::CSV_JSON,
                false,
                false,
            )?;
            register_ual(tree, &w, &found);
        }
    } else {
        c.log().info(format!(
            "Operation '{}' is not enabled for {upn}.",
            step.gate
        ));
        c.log().info(format!("No data recorded for {upn}."));
    }
    c.log().info(format!(
        "Completed collection of {} for {upn} from the UAL.",
        step.what
    ));
    Ok(())
}

/// Get-HawkUserMobileDevice (H15): devices first synced after Hawk's start date are appended
/// one by one to `_Investigate_MobileDevice`.
pub(super) fn mobile_devices(c: &mut Ctx<'_>, tree: &mut Tree<'_>, u: &User) -> Result<()> {
    let world = c.world;
    let upn = u.upn.as_str();
    c.log().action(format!(
        "Initiating collection of mobile devices attached to {upn} inbox from Exchange Online."
    ));
    c.log()
        .action(format!("Gathering Mobile Devices for: {upn}"));
    let devices: Vec<&crate::world::MobileDevice> = world
        .mobile_devices
        .iter()
        .filter(|d| d.mailbox.eq_ignore_ascii_case(upn))
        .collect();
    if devices.is_empty() {
        c.log()
            .action(format!("No mobile devices found for user: {upn}"));
    } else {
        c.log().info(format!("Found {} Devices", devices.len()));
        let rows: Vec<Row> = devices
            .iter()
            .map(|d| {
                let identity = format!(
                    "{}\\ExchangeActiveSyncDevices\\{}\u{00A7}{}",
                    u.alias, d.device_type, d.device_id
                );
                vec![
                    r("FriendlyName", s(d.friendly_name.clone())),
                    r("DeviceId", s(d.device_id.clone())),
                    r("DeviceImei", Val::Null),
                    r("DeviceMobileOperator", Val::Null),
                    r("DeviceOS", s(d.os.clone())),
                    r("DeviceOSLanguage", s("en-US")),
                    r("DeviceTelephoneNumber", Val::Null),
                    r("DeviceType", s(d.device_type.clone())),
                    r("DeviceUserAgent", s(d.user_agent.clone())),
                    r("DeviceModel", s(d.model.clone())),
                    r("FirstSyncTime", date(d.first_sync, DtKind::Utc)),
                    r("UserDisplayName", s(u.display_name.clone())),
                    r("DeviceAccessState", s(d.access_state.clone())),
                    r("DeviceAccessStateReason", s(d.access_reason.clone())),
                    r("DeviceAccessControlRule", Val::Null),
                    r("ClientVersion", s("1.0")),
                    r("ClientType", s(d.client_type.clone())),
                    r("IsManaged", Val::Bool(false)),
                    r("IsCompliant", Val::Bool(false)),
                    r("IsDisabled", Val::Bool(false)),
                    r("WhenChanged", date_text(d.last_sync, DtKind::Local)),
                    r("WhenCreated", date_text(d.when_created, DtKind::Local)),
                    r("WhenChangedUTC", date_text(d.last_sync, DtKind::Utc)),
                    r("WhenCreatedUTC", date(d.when_created, DtKind::Utc)),
                    r(
                        "Name",
                        s(format!("{}\u{00A7}{}", d.device_type, d.device_id)),
                    ),
                    r("Identity", s(identity)),
                    r("IsValid", Val::Bool(true)),
                    r("ObjectState", s("Unchanged")),
                ]
            })
            .collect();
        for (d, row) in devices.iter().zip(&rows) {
            if d.first_sync > world.window_start() {
                c.log()
                    .notice("Device found that was first synced inside investigation window");
                c.log().notice(format!("DeviceID: {}", d.device_id));
                let w = c.omft.write(
                    tree,
                    "_Investigate_MobileDevice",
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
        let w = c.omft.write(
            tree,
            "MobileDevices",
            Some(upn),
            Art::raw("hawk.user.mobile_devices"),
            &rows,
            Formats::CSV_JSON,
            false,
            false,
        )?;
        register(
            tree,
            &w,
            "mobile_devices",
            |i| Some(keys::mobile_device(upn, &devices[i].device_id)),
            |i| {
                Some(Evidence::MobileDevice {
                    mailbox: devices[i].mailbox.clone(),
                    device_id: devices[i].device_id.clone(),
                })
            },
        );
    }
    c.log().info(format!(
        "Completed collection of mobile devices attached to {upn} inbox from Exchange Online."
    ));
    Ok(())
}
