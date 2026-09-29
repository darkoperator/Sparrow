//! `Start-HawkTenantInvestigation` (research hawk layouts §1.2, §3, §5, §6): the session
//! header, the nineteen tenant collectors in the orchestrator's order, and the summary.

use super::omft::{Art, Formats, HawkVersion, Written};
use super::{
    Ctx, additional_properties, date, date_text, model, one_of, opt, r, raw_rows, register,
    register_flags, register_ual, s, simple_rows, text_of,
};
use crate::Result;
use crate::events::{RecordType, Ual};
use crate::keys;
use crate::ps::{DateEvidence, DtKind, Encoding, Host, Row, Val, convert_to_json, export_csv};
use crate::rng::stream;
use crate::story::Evidence;
use crate::tree::Tree;
use crate::world::{CredKind, GrantKind, User, World};
use chrono::{DateTime, Duration, NaiveTime, Utc};
use regex::Regex;
use serde_json::{Value, json};
use uuid::Uuid;

/// `Test-LicenseType`: (tier, retention days) from the subscribed SKU names (case-insensitive
/// substring regexes; the first matching family wins).
pub fn licence_tier(world: &World) -> (&'static str, i64) {
    let skus: Vec<&str> = world.licence.skus.iter().map(|s| s.sku.as_str()).collect();
    let any = |p: &str| {
        let re = Regex::new(&format!("(?i){p}")).expect("valid regex");
        skus.iter().any(|s| re.is_match(s))
    };
    if any(
        "ENTERPRISEPREMIUM|SPE_E5|DEVELOPERPACK_E5|M365_E5|SPE_G5|ENTERPRISEPREMIUM_GOV|M365_G5|MICROSOFT365_G5",
    ) {
        (if any("_G5|_GOV") { "G5" } else { "E5" }, 365)
    } else if any(
        "ENTERPRISEPACK|M365_E3|DEVELOPERPACK_E3|SPE_G3|ENTERPRISEPACK_GOV|M365_G3|MICROSOFT365_G3",
    ) {
        (if any("_G3|_GOV") { "G3" } else { "E3" }, 180)
    } else {
        ("Unknown", 90)
    }
}

/// Hawk's `EndDate`: the day after the last day the analyst entered, at 00:00 UTC.
fn hawk_end(c: &Ctx<'_>) -> DateTime<Utc> {
    c.world.window_end()
}

/// `Write-HawkConfigurationComplete`.
fn configuration_complete(c: &mut Ctx<'_>, host: Host) {
    let (start, end) = (c.world.window_start(), hawk_end(c));
    let path = c.omft.file_path.clone();
    let tenant = c.world.tenant.folder_name.clone();
    let log = c.log();
    let bar = "=".repeat(68);
    log.info(&bar);
    log.info("Configuration Complete!");
    log.info("Your Hawk environment is now set up with the following settings:");
    log.info(format!("Hawk Version: {}", super::HAWK_VERSION));
    log.info(format!("File Path   : {path}"));
    log.info(format!(
        "Start Date  : {}",
        host.culture_date(start, DtKind::Unspecified)
    ));
    log.info(format!(
        "End Date    : {}",
        host.culture_date(end, DtKind::Unspecified)
    ));
    log.info(format!("Tenant Name : {tenant}"));
    log.info("Happy Hunting! \u{1F985}");
    log.info(&bar);
}

/// The interactive `Initialize-HawkGlobalObject` of the first session (research §3.1): the
/// analyst enters the window's first day and its last day as dates.
fn interactive_header(c: &mut Ctx<'_>) {
    let (tier, max_days) = licence_tier(c.world);
    let start = c.world.window_start();
    let collected = c.world.collected_at();
    let path = c.omft.file_path.clone();
    let log = c.log();
    log.info(format!("Hawk output directory created at: {path}"));
    log.action("Setting up Application Insights");
    log.action("Initializing Application Insights");
    log.action("Checking for latest version online");
    log.tick(1, 3);
    log.info(format!("Found Version {} Online", super::HAWK_VERSION));
    log.info("Latest Version Installed");
    log.action("Skipping Upgrade");
    log.action("Testing Graph Connection");
    log.tick(1, 3);
    log.action("Detecting M365 license type to determine maximum log retention period");
    log.info(format!("M365 License type detected: {tier}"));
    log.action(format!("Max log retention: {max_days} days"));
    log.prompt("Please specify the first day of the search window:");
    log.prompt(format!(" Enter a number of days to go back (1-{max_days})"));
    log.prompt(" OR enter a date in MM/DD/YYYY format");
    log.prompt(" Default is 90 days back: ");
    log.tick(8, 40);
    if start < collected - Duration::days(max_days) {
        log.warning(format!(
            "The date entered exceeds your license retention period of {max_days} days."
        ));
        log.prompt("Press ENTER to proceed or type 'R' to re-enter the date:");
        log.tick(2, 8);
    }
    // "Start Date: ${StartDate}Z": string interpolation is culture-invariant.
    log.info(format!(
        "Start Date: {}Z",
        start.format("%m/%d/%Y %H:%M:%S")
    ));
    log.prompt("Please specify the last day of the search window:");
    log.prompt(" Enter a number of days to go back from today (1-365)");
    log.prompt(" OR enter a specific date in MM/DD/YYYY format");
    log.prompt(" Default is today's date:");
    log.tick(5, 30);
    let host = c.tenant_host;
    configuration_complete(c, host);
}

/// A later session's `Start-HawkUserInvestigation -StartDate -EndDate -FilePath` (the
/// non-interactive path: no licence check, no prompts).
pub(super) fn non_interactive_header(c: &mut Ctx<'_>) {
    let path = c.omft.file_path.clone();
    let log = c.log();
    log.info(format!("Hawk output directory created at: {path}"));
    log.action("Setting up Application Insights");
    log.action("Initializing Application Insights");
    log.action("Checking for latest version online");
    log.tick(1, 3);
    log.info(format!("Found Version {} Online", super::HAWK_VERSION));
    log.info("Latest Version Installed");
    log.action("Skipping Upgrade");
    log.action("Testing Graph Connection");
    log.tick(1, 3);
    let host = c.user_host;
    configuration_complete(c, host);
}

/// `Write-HawkInvestigationSummary`.
pub(super) fn summary(c: &mut Ctx<'_>, started: DateTime<Utc>, users: Option<Vec<String>>) {
    let path = c.omft.file_path.clone();
    let tenant = c.world.tenant.folder_name.clone();
    let log = c.log();
    log.tick(0, 2);
    let d = log.now() - started;
    let (h, m, sec) = (
        d.num_hours() % 24,
        d.num_minutes() % 60,
        d.num_seconds() % 60,
    );
    let mut parts = Vec::new();
    if h > 0 {
        parts.push(format!("{h} hours"));
    }
    if m > 0 {
        parts.push(format!("{m} minutes"));
    }
    if sec > 0 || parts.is_empty() {
        parts.push(format!("{sec} seconds"));
    }
    let bar = "=".repeat(73);
    log.info(&bar);
    match &users {
        None => log.info(format!(
            "Tenant Investigation complete for tenant: {tenant}"
        )),
        Some(u) if u.len() == 1 => {
            log.info(format!("User Investigation complete for user: '{}'", u[0]))
        }
        Some(u) => {
            log.info("User Investigation complete for users:");
            for upn in u {
                log.info(format!("* {upn}"));
            }
        }
    }
    log.info(format!("Total run time: {}", parts.join(", ")));
    log.info(format!("Please review investigation files at: {path}"));
    if users.is_none() {
        log.info("To investigate specific users, run: Start-HawkUserInvestigation");
    }
    log.info(&bar);
}

/// `Out-LogFile "Running <cmdlet>." -Action` before each collector.
// source-derived (no 3.1 source): Hawk 3 logs this Hawk 4.0 line too.
pub(super) fn running(c: &mut Ctx<'_>, cmdlet: &str) {
    let log = c.log();
    log.tick(1, 3);
    log.action(format!("Running {cmdlet}."));
}

/// Start-HawkTenantInvestigation.
pub(super) fn investigate(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    interactive_header(c);
    let started = c.log().now();
    c.log().action("Starting Tenant Investigation.");
    running(c, "Get-HawkTenantConfiguration");
    configuration(c, tree)?;
    running(c, "Get-HawkTenantEDiscoveryConfiguration");
    ediscovery_configuration(c, tree)?;
    running(c, "Get-HawkTenantEDiscoveryLog");
    ediscovery_log(c, tree)?;
    running(c, "Get-HawkTenantAdminInboxRuleCreation");
    admin_rules(c, tree, &ADMIN_RULE_STEPS[0])?;
    running(c, "Get-HawkTenantInboxRuleModification");
    admin_rules(c, tree, &ADMIN_RULE_STEPS[1])?;
    running(c, "Get-HawkTenantAdminInboxRuleRemoval");
    admin_rules(c, tree, &ADMIN_RULE_STEPS[2])?;
    running(c, "Get-HawkTenantAdminMailboxPermissionChange");
    permission_changes(c, tree)?;
    running(c, "Get-HawkTenantAdminEmailForwardingChange");
    forwarding_changes(c, tree)?;
    running(c, "Get-HawkTenantDomainActivity");
    domain_activity(c, tree)?;
    running(c, "Get-HawkTenantRBACChange");
    rbac_changes(c, tree)?;
    running(c, "Get-HawkTenantEntraIDAuditLog");
    entra_audit_log(c, tree)?;
    running(c, "Get-HawkTenantEntraIDAppAuditLog");
    app_audit_log(c, tree, "Entra_ID_Application_Audit")?;
    running(c, "Get-HawkTenantEXOAdmin");
    exo_admins(c, tree)?;
    running(c, "Get-HawkTenantConsentGrant");
    consent_grants(c, tree)?;
    running(c, "Get-HawkTenantRiskyUsers");
    risky_users(c, tree)?;
    running(c, "Get-HawkTenantRiskDetections");
    risk_detections(c, tree)?;
    running(c, "Get-HawkTenantEntraIDAdmin");
    entra_admins(c, tree)?;
    running(c, "Get-HawkTenantAppAndSPNCredentialDetail");
    credentials(c, tree)?;
    running(c, "Get-HawkTenantEntraIDUser");
    entra_users(c, tree)?;
    summary(c, started, None);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Exchange Online configuration

/// `DC=` components of the tenant's Exchange Online directory partition.
fn exo_dn(world: &World) -> String {
    format!(
        "CN={},CN=Microsoft Exchange Hosted Organizations,DC=NAMPR04A001,DC=prod,DC=outlook,DC=example",
        world.tenant.initial_domain
    )
}

fn organization_id(world: &World) -> String {
    format!(
        "NAMPR04A001.prod.outlook.example/Microsoft Exchange Hosted Organizations/{} - NAMPR04A001.prod.outlook.example/ConfigurationUnits/{}/Configuration",
        world.tenant.initial_domain, world.tenant.initial_domain
    )
}

fn server(world: &World, label: &str) -> String {
    let mut rng = stream(world.seed, &format!("hawk/server/{label}"));
    crate::ual::server_name(&mut rng)
}

/// `WhenChanged`, `WhenCreated` (host local), `WhenChangedUTC`, `WhenCreatedUTC`.
fn when(changed: DateTime<Utc>, created: DateTime<Utc>) -> Vec<(String, Val)> {
    vec![
        r("WhenChanged", date_text(changed, DtKind::Local)),
        r("WhenCreated", date_text(created, DtKind::Local)),
        r("WhenChangedUTC", date_text(changed, DtKind::Utc)),
        r("WhenCreatedUTC", date_text(created, DtKind::Utc)),
    ]
}

pub(super) fn admin_audit_log_config(world: &World) -> Row {
    let a = &world.audit;
    let created = world.tenant.created;
    let name = "Admin Audit Log Settings";
    let mut row = vec![
        r("AdminDisplayName", s("")),
        r("AdminAuditLogEnabled", Val::Bool(a.admin_audit_log_enabled)),
        r("LogLevel", s(a.log_level.clone())),
        r("TestCmdletLoggingEnabled", Val::Bool(false)),
        r("AdminAuditLogCmdlets", Val::Raw(json!(["*"]))),
        r("AdminAuditLogParameters", Val::Raw(json!(["*"]))),
        r("AdminAuditLogExcludedCmdlets", Val::Raw(json!([]))),
        r(
            "AdminAuditLogAgeLimit",
            s(a.admin_audit_log_age_limit.clone()),
        ),
        r("LoadBalancerCount", Val::Int(3)),
        r("RefreshInterval", Val::Int(10)),
        r("PartitionInfo", Val::Raw(json!([]))),
        r(
            "UnifiedAuditLogIngestionEnabled",
            Val::Bool(a.ual_ingestion_enabled),
        ),
        r(
            "UnifiedAuditLogFirstOptInDate",
            date_text(created + Duration::days(1), DtKind::Utc),
        ),
        r("Name", s(name)),
        r(
            "DistinguishedName",
            s(format!(
                "CN={name},CN=Global Settings,CN=Configuration,{}",
                exo_dn(world)
            )),
        ),
        r("Identity", s(name)),
        r(
            "ObjectCategory",
            s(
                "NAMPR04A001.prod.outlook.example/Configuration/Schema/ms-Exch-Admin-Audit-Log-Config",
            ),
        ),
        r(
            "ObjectClass",
            Val::Raw(json!(["top", "msExchAdminAuditLogConfig"])),
        ),
    ];
    row.extend(when(world.collected_at() - Duration::days(20), created));
    row.extend([
        r("OrganizationId", s(organization_id(world))),
        r("Id", s(name)),
        r("OriginatingServer", s(server(world, "config"))),
        r("IsValid", Val::Bool(true)),
        r("ObjectState", s("Unchanged")),
    ]);
    row
}

pub(super) fn org_config(world: &World) -> Row {
    let a = &world.audit;
    let created = world.tenant.created;
    let name = world.tenant.initial_domain.clone();
    let mut row = vec![
        r("DisplayName", s(world.tenant.name.clone())),
        r("AuditDisabled", Val::Bool(a.org_audit_disabled)),
        r("OAuth2ClientProfileEnabled", Val::Bool(true)),
        r("ActivityBasedAuthenticationTimeoutEnabled", Val::Bool(true)),
        r("ActivityBasedAuthenticationTimeoutInterval", s("06:00:00")),
        r("CustomerLockBoxEnabled", Val::Bool(false)),
        r("AutoExpandingArchiveEnabled", Val::Bool(false)),
        r("BookingsEnabled", Val::Bool(true)),
        r("FocusedInboxOn", Val::Bool(true)),
        r("MailTipsAllTipsEnabled", Val::Bool(true)),
        r("MailTipsExternalRecipientsTipsEnabled", Val::Bool(false)),
        r("PublicFoldersEnabled", s("Local")),
        r("SendFromAliasEnabled", Val::Bool(false)),
        r("SmtpActionableMessagesEnabled", Val::Bool(true)),
        r("EwsEnabled", Val::Null),
        r("DefaultAuthenticationPolicy", Val::Null),
        r("IsDehydrated", Val::Bool(false)),
        r("IsMixedMode", Val::Bool(false)),
        r("MaxConcurrentMigrations", Val::Int(300)),
        r("Name", s(name.clone())),
        r("DistinguishedName", s(exo_dn(world))),
        r("Identity", s(name.clone())),
        r(
            "ObjectCategory",
            s(
                "NAMPR04A001.prod.outlook.example/Configuration/Schema/ms-Exch-Organization-Container",
            ),
        ),
        r(
            "ObjectClass",
            Val::Raw(json!(["top", "container", "msExchOrganizationContainer"])),
        ),
    ];
    row.extend(when(world.collected_at() - Duration::days(35), created));
    row.extend([
        r("OrganizationId", s(organization_id(world))),
        r("Guid", s(world.tenant.tenant_id.to_string())),
        r("OriginatingServer", s(server(world, "config"))),
        r("IsValid", Val::Bool(true)),
        r("ObjectState", s("Unchanged")),
    ]);
    row
}

pub(super) fn remote_domain_row(world: &World, d: &crate::world::RemoteDomain) -> Row {
    let mut row = vec![
        r("AllowedOOFType", s(d.allowed_ooo_type.clone())),
        r("AutoForwardEnabled", Val::Bool(d.auto_forward_enabled)),
        r("AutoReplyEnabled", Val::Bool(true)),
        r("CharacterSet", Val::Null),
        r("ContentType", s("MimeHtmlText")),
        r("DeliveryReportEnabled", Val::Bool(true)),
        r("DisplaySenderName", Val::Bool(true)),
        r("DomainName", s(d.domain.clone())),
        r("IsInternal", Val::Bool(false)),
        r("LineWrapSize", s("Unlimited")),
        r("MeetingForwardNotificationEnabled", Val::Bool(false)),
        r("Name", s(d.name.clone())),
        r("TargetDeliveryDomain", Val::Bool(false)),
        r("TNEFEnabled", Val::Null),
        r("TrustedMailInboundEnabled", Val::Bool(false)),
        r("TrustedMailOutboundEnabled", Val::Bool(false)),
        r("UseSimpleDisplayName", Val::Bool(false)),
        r("AdminDisplayName", s("")),
        r(
            "DistinguishedName",
            s(format!(
                "CN={},CN=Internet Message Formats,CN=Global Settings,CN=Configuration,{}",
                d.name,
                exo_dn(world)
            )),
        ),
        r("Identity", s(d.name.clone())),
    ];
    row.extend(when(d.when_changed, world.tenant.created));
    row.extend([
        r("OrganizationId", s(organization_id(world))),
        r("Id", s(d.name.clone())),
        r("IsValid", Val::Bool(true)),
        r("ObjectState", s("Unchanged")),
    ]);
    row
}

pub(super) fn transport_rule_row(world: &World, t: &crate::world::TransportRule) -> Row {
    let list = |v: &[String]| {
        if v.is_empty() {
            Val::Null
        } else {
            Val::Raw(json!(v))
        }
    };
    let typed = |name: &str, items: Value| {
        Val::Model(
            format!("Microsoft.Exchange.MessagingPolicies.Rules.Tasks.{name}[]"),
            items,
        )
    };
    let mut actions = Vec::new();
    if !t.blind_copy_to.is_empty() {
        actions.push("BlindCopyToAction");
    }
    if !t.redirect_to.is_empty() {
        actions.push("RedirectMessageAction");
    }
    if !t.copy_to.is_empty() {
        actions.push("CopyToAction");
    }
    if !t.add_to_recipients.is_empty() {
        actions.push("AddToRecipientAction");
    }
    if actions.is_empty() {
        actions.push("ApplyHtmlDisclaimerAction");
    }
    let mut row = vec![
        r("Priority", Val::Int(t.priority.into())),
        r("DlpPolicy", s("")),
        r("DlpPolicyId", s(Uuid::nil().to_string())),
        r("Comments", s("")),
        r("ManuallyModified", Val::Bool(false)),
        r("ActivationDate", Val::Null),
        r("ExpiryDate", Val::Null),
        r("Description", s(t.description.clone())),
        r(
            "RuleVersion",
            Val::Raw(json!({"Major": 15, "Minor": 0, "Build": 5, "Revision": 2,
                "MajorRevision": 0, "MinorRevision": 2})),
        ),
        r(
            "Conditions",
            typed("TransportRulePredicate", json!(["SentToScopePredicate"])),
        ),
        r("Exceptions", Val::Null),
        r(
            "Actions",
            typed(
                "TransportRuleAction",
                Value::Array(actions.iter().map(|a| json!(a)).collect()),
            ),
        ),
        r("State", s(t.state.clone())),
        r("Mode", s(t.mode.clone())),
        r("RuleErrorAction", s("Ignore")),
        r("SenderAddressLocation", s("Header")),
        r("RuleSubType", s("None")),
        r("UseLegacyRegex", Val::Bool(false)),
        r("SentToScope", s("NotInOrganization")),
        r("RedirectMessageTo", list(&t.redirect_to)),
        r("BlindCopyTo", list(&t.blind_copy_to)),
        r("CopyTo", list(&t.copy_to)),
        r("AddToRecipients", list(&t.add_to_recipients)),
        r("LastModifiedBy", s(t.created_by.clone())),
        r("RejectMessageEnhancedStatusCode", Val::Null),
        r("Guid", s(t.guid.to_string())),
        r("ImmutableId", s(t.guid.to_string())),
        r("Name", s(t.name.clone())),
        r("Identity", s(t.name.clone())),
        r(
            "DistinguishedName",
            s(format!(
                "CN={},CN=TransportVersioned,CN=Rules,CN=Transport Settings,CN=Configuration,{}",
                t.name,
                exo_dn(world)
            )),
        ),
    ];
    row.extend(when(t.when_changed, t.when_changed));
    row.extend([
        r("OrganizationId", s(organization_id(world))),
        r("IsValid", Val::Bool(true)),
        r("ObjectState", s("Unchanged")),
    ]);
    row
}

pub(super) fn transport_config(world: &World) -> Row {
    let name = "Transport Settings";
    let mut row = vec![
        r("AddressBookPolicyRoutingEnabled", Val::Bool(false)),
        r("AllowLegacyTLSClients", Val::Bool(false)),
        r("ClearCategories", Val::Bool(true)),
        r("ConvertDisclaimerWrapperToEml", Val::Bool(false)),
        r("DSNConversionMode", s("UseExchangeDSNs")),
        r("ExternalDelayDsnEnabled", Val::Bool(true)),
        r("ExternalPostmasterAddress", Val::Null),
        r("InternalSMTPServers", Val::Raw(json!([]))),
        r("JournalingReportNdrTo", s("<>")),
        r("MaxReceiveSize", s("36 MB (37,748,736 bytes)")),
        r("MaxRecipientEnvelopeLimit", s("Unlimited")),
        r("MaxSendSize", s("35 MB (36,700,160 bytes)")),
        r("SmtpClientAuthenticationDisabled", Val::Bool(true)),
        r("TLSReceiveDomainSecureList", Val::Raw(json!([]))),
        r("TLSSendDomainSecureList", Val::Raw(json!([]))),
        r(
            "TransportRuleMinProductVersion",
            Val::Raw(json!({"Major": 14, "Minor": 0, "Build": 0, "Revision": 0,
                "MajorRevision": 0, "MinorRevision": 0})),
        ),
        r("VoicemailJournalingEnabled", Val::Bool(true)),
        r("Name", s(name)),
        r("AdminDisplayName", s("")),
        r(
            "DistinguishedName",
            s(format!("CN={name},CN=Configuration,{}", exo_dn(world))),
        ),
        r("Identity", s(name)),
    ];
    row.extend(when(
        world.collected_at() - Duration::days(60),
        world.tenant.created,
    ));
    row.extend([
        r("OrganizationId", s(organization_id(world))),
        r(
            "Guid",
            s(stream(world.seed, "hawk/transportconfig")
                .uuid()
                .to_string()),
        ),
        r("IsValid", Val::Bool(true)),
        r("ObjectState", s("Unchanged")),
    ]);
    row
}

/// Every property of a Format-List object is one `tenant_settings` row of `source`.
pub(super) fn register_settings(tree: &mut Tree<'_>, w: &Written, rows: &[Row], source: &str) {
    for part in w.parts() {
        for row in rows {
            for (k, _) in row {
                tree.row(
                    &part.rel,
                    "tenant_settings",
                    keys::tenant_setting(source, k),
                );
            }
        }
    }
}

/// Get-HawkTenantConfiguration. Hawk 3.1 also writes each file as CliXml (`-xml`; research
/// §7.1).
pub(super) fn configuration(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    // Progress lines are Hawk 4.0 wording (`*_v4`: not logged by Hawk 3). Hawk 3 keeps the
    // notices, which feed `_Investigate.txt`; source-derived (no 3.1 source): their wording.
    let world = c.world;
    let xml = c.omft.version == HawkVersion::V3;
    let with_xml = |f: Formats| if xml { f.and_xml() } else { f };
    let log = c.log();
    log.action_v4("Initiating collection of tenant configuration settings from Exchange Online.");
    log.action_v4("Gathering Tenant Configuration Information");
    log.action_v4("Gathering Admin Audit Log");
    let rows = vec![admin_audit_log_config(world)];
    let w = c.omft.write(
        tree,
        "AdminAuditLogConfig",
        None,
        Art::raw("hawk.tenant.admin_audit_log_config"),
        &rows,
        with_xml(Formats::TXT),
        false,
        false,
    )?;
    register_settings(tree, &w, &rows, "admin_audit_log_config");
    register(
        tree,
        &w,
        "audit_config",
        |_| Some(keys::audit_config()),
        |_| Some(Evidence::AuditConfig),
    );
    c.log().action_v4("Gathering Organization Configuration");
    let rows = vec![org_config(world)];
    let w = c.omft.write(
        tree,
        "OrgConfig",
        None,
        Art::raw("hawk.tenant.org_config"),
        &rows,
        with_xml(Formats::TXT),
        false,
        false,
    )?;
    register_settings(tree, &w, &rows, "organization_config");
    register(
        tree,
        &w,
        "audit_config",
        |_| Some(keys::audit_config()),
        |_| Some(Evidence::AuditConfig),
    );
    c.log().action_v4("Gathering Remote Domains");
    let domains = &world.remote_domains;
    let rows: Vec<Row> = domains
        .iter()
        .map(|d| remote_domain_row(world, d))
        .collect();
    let w = c.omft.write(
        tree,
        "RemoteDomain",
        None,
        Art::raw("hawk.tenant.remote_domain"),
        &rows,
        with_xml(Formats::CSV_JSON),
        false,
        false,
    )?;
    register(
        tree,
        &w,
        "remote_domains",
        |i| Some(keys::remote_domain(&domains[i].domain)),
        |_| None,
    );
    c.log().action_v4("Gathering Transport Rules");
    let rules = &world.transport_rules;
    let rows: Vec<Row> = rules.iter().map(|t| transport_rule_row(world, t)).collect();
    let w = c.omft.write(
        tree,
        "TransportRules",
        None,
        Art::raw("hawk.tenant.transport_rules"),
        &rows,
        with_xml(Formats::CSV_JSON),
        false,
        false,
    )?;
    register(
        tree,
        &w,
        "transport_rules",
        |i| Some(keys::transport_rule(&rules[i].name)),
        |i| Some(Evidence::TransportRule(rules[i].name.clone())),
    );
    c.log().action_v4("Gathering Transport Configuration");
    let rows = vec![transport_config(world)];
    let w = c.omft.write(
        tree,
        "TransportConfig",
        None,
        Art::raw("hawk.tenant.transport_config"),
        &rows,
        with_xml(Formats::CSV_JSON),
        false,
        false,
    )?;
    register_settings(tree, &w, &rows, "transport_config");
    c.log()
        .info_v4("Completed collection of tenant configuration settings from Exchange Online.");
    Ok(())
}

/// A Get-ManagementRoleEntry object.
pub(super) fn role_entry(world: &World, role: &str, cmdlet: &str, params: &[&str]) -> Row {
    let identity = format!("{role}\\{cmdlet}");
    let dn = format!(
        "CN={cmdlet},CN={role},CN=Roles,CN=RBAC,CN=Configuration,{}",
        exo_dn(world)
    );
    let guid = stream(world.seed, &format!("hawk/roleentry/{identity}")).uuid();
    let mut row = vec![
        r("Name", s(cmdlet)),
        r("Role", s(role)),
        r("Type", s("Cmdlet")),
        r("Parameters", Val::Raw(json!(params))),
        r(
            "PSSnapinName",
            s("Microsoft.Exchange.Management.PowerShell.E2010"),
        ),
        r("Identity", s(identity.clone())),
        r("Id", s(identity)),
        r("IsValid", Val::Bool(true)),
        r("DistinguishedName", s(dn)),
        r(
            "ObjectCategory",
            s("NAMPR04A001.prod.outlook.example/Configuration/Schema/ms-Exch-Role"),
        ),
        r("ObjectClass", Val::Raw(json!(["top", "msExchRole"]))),
    ];
    row.extend(when(world.tenant.created, world.tenant.created));
    row.extend([
        r("ExchangeObjectId", s(guid.to_string())),
        r(
            "OrganizationalUnitRoot",
            s(world.tenant.initial_domain.clone()),
        ),
        r("OrganizationId", s(organization_id(world))),
        r("Guid", s(guid.to_string())),
        r("OriginatingServer", s(server(world, "config"))),
        r("ObjectState", s("Unchanged")),
    ]);
    row
}

/// A Get-ManagementRoleAssignment object assigning `role` to role group `group`.
pub(super) fn role_assignment(world: &World, role: &str, group: &str) -> Row {
    let name = format!("{role}-{group}");
    let guid = stream(world.seed, &format!("hawk/roleassignment/{name}")).uuid();
    let mut row = vec![
        r("DataObject", Val::Null),
        r("User", s(group)),
        r("App", Val::Null),
        r("AssignmentMethod", s("Direct")),
        r("Identity", s(name.clone())),
        r("EffectiveUserName", s("All Group Members")),
        r("AssignmentChain", Val::Null),
        r("RoleAssigneeType", s("RoleGroup")),
        r("RoleAssignee", s(group)),
        r("Role", s(role)),
        r("RoleAssignmentDelegationType", s("Regular")),
        r("CustomRecipientWriteScope", Val::Null),
        r("CustomConfigWriteScope", Val::Null),
        r("CustomResourceScope", Val::Null),
        r("RecipientReadScope", s("Organization")),
        r("ConfigReadScope", s("OrganizationConfig")),
        r("RecipientWriteScope", s("Organization")),
        r("ConfigWriteScope", s("OrganizationConfig")),
        r("Enabled", Val::Bool(true)),
        r("RoleAssigneeName", s(group)),
        r("Id", s(name.clone())),
        r("IsValid", Val::Bool(true)),
        r("Name", s(name.clone())),
        r(
            "DistinguishedName",
            s(format!(
                "CN={name},CN=Role Assignments,CN=RBAC,CN=Configuration,{}",
                exo_dn(world)
            )),
        ),
        r(
            "ObjectCategory",
            s("NAMPR04A001.prod.outlook.example/Configuration/Schema/ms-Exch-Role-Assignment"),
        ),
        r(
            "ObjectClass",
            Val::Raw(json!(["top", "msExchRoleAssignment"])),
        ),
    ];
    row.extend(when(world.tenant.created, world.tenant.created));
    row.extend([
        r("ExchangeObjectId", s(guid.to_string())),
        r(
            "OrganizationalUnitRoot",
            s(world.tenant.initial_domain.clone()),
        ),
        r("OrganizationId", s(organization_id(world))),
        r("Guid", s(guid.to_string())),
        r("OriginatingServer", s(server(world, "config"))),
        r("ObjectState", s("Unchanged")),
    ]);
    row
}

/// A collector's own `ConvertTo-Json | Out-File` and `Export-Csv -NoTypeInformation` (default
/// encodings) into `Tenant/` (no leading backslash: the plain `Tenant` folder).
pub(super) fn write_direct(
    c: &mut Ctx<'_>,
    tree: &mut Tree<'_>,
    name: &str,
    art: Art,
    rows: &[Row],
    json: bool,
    csv: bool,
) -> Result<Written> {
    let host = c.omft.host;
    let mut out = Written::default();
    if json {
        let rel = format!("Tenant/{name}.json");
        let r = convert_to_json(&host, rows, false);
        let before = tree.write(
            &super::omft::spec(&rel, Encoding::out_file_default(host.edition), art, None),
            &format!("{}{}", r.text, host.newline),
        )?;
        out.json = Some(super::omft::Part {
            rel,
            spans: r
                .spans
                .into_iter()
                .map(|(a, b)| (a + before, b + before))
                .collect(),
        });
    }
    if csv {
        let rel = format!("Tenant/{name}.csv");
        let mut ev = DateEvidence::default();
        let r = export_csv(&host, rows, &mut ev);
        tree.write(
            &super::omft::spec(&rel, Encoding::export_csv_default(host.edition), art, None),
            &r.text,
        )?;
        if ev.culture_dates > 0 {
            tree.date_evidence(&rel, ev);
        }
        out.csv = Some(super::omft::Part {
            rel,
            spans: r.spans,
        });
    }
    c.omft.created("Tenant");
    Ok(out)
}

/// The role entries holding New-MailboxSearch or Search-Mailbox (one entry per role).
fn ediscovery_role_entries(world: &World) -> Vec<Row> {
    vec![
        role_entry(
            world,
            "Mailbox Import Export",
            "Search-Mailbox",
            &["Identity", "SearchQuery", "TargetMailbox", "TargetFolder"],
        ),
        role_entry(
            world,
            "Mailbox Search",
            "New-MailboxSearch",
            &[
                "Name",
                "SourceMailboxes",
                "SearchQuery",
                "StartDate",
                "EndDate",
            ],
        ),
    ]
}

/// Every role entry of `rows` is one `tenant_settings` row (`exchange_role_entry`).
pub(super) fn register_role_entries(tree: &mut Tree<'_>, w: &Written, rows: &[Row]) {
    for part in w.parts() {
        for row in rows {
            let id = text_of(row, "Identity").unwrap_or_default();
            tree.row(
                &part.rel,
                "tenant_settings",
                keys::tenant_setting("exchange_role_entry", &id),
            );
        }
    }
}

/// Get-HawkTenantEDiscoveryConfiguration: the roles holding New-MailboxSearch or
/// Search-Mailbox (one entry per role) and their non-delegating assignments. Hawk 4 writes them
/// directly as `EDiscoveryRoles` and `CustomEDiscoveryRoles`; Hawk 3.1 through
/// Out-MultipleFileType (with CliXml) as `EDiscoveryRoles` and `EDiscoveryRoleAssignments`
/// (research §7.2).
pub(super) fn ediscovery_configuration(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    // Progress lines are Hawk 4.0 wording (`*_v4`: not logged by Hawk 3). Hawk 3 keeps the
    // notices, which feed `_Investigate.txt`; source-derived (no 3.1 source): their wording.
    let world = c.world;
    let v3 = c.omft.version == HawkVersion::V3;
    let write = |c: &mut Ctx<'_>, tree: &mut Tree<'_>, name: &str, art: Art, rows: &[Row]| {
        if v3 {
            c.omft.write(
                tree,
                name,
                None,
                art,
                rows,
                Formats::CSV_JSON.and_xml(),
                false,
                false,
            )
        } else {
            write_direct(c, tree, name, art, rows, true, true)
        }
    };
    c.log()
        .action_v4("Initiating collection of eDiscovery configuration data from Exchange Online.");
    c.omft.created("Tenant");
    c.log()
        .action_v4("Gathering all Exchange Online role entries with eDiscovery cmdlets");
    let entries = ediscovery_role_entries(world);
    c.log().info_v4(format!(
        "Found {} Roles with E-Discovery Rights",
        entries.len()
    ));
    let w = write(
        c,
        tree,
        "EDiscoveryRoles",
        Art::raw("hawk.tenant.ediscovery_roles"),
        &entries,
    )?;
    register_role_entries(tree, &w, &entries);
    let assignments: Vec<Row> = world
        .exchange_role_assignments
        .iter()
        .map(|a| role_assignment(world, &a.role, &a.group))
        .collect();
    c.log().info_v4(format!(
        "Found {} Role Assignments for these Roles",
        assignments.len()
    ));
    let (name, art) = if v3 {
        (
            "EDiscoveryRoleAssignments",
            Art::raw("hawk.tenant.ediscovery_role_assignments"),
        )
    } else {
        (
            "CustomEDiscoveryRoles",
            Art::raw("hawk.tenant.ediscovery_roles"),
        )
    };
    let w = write(c, tree, name, art, &assignments)?;
    register(
        tree,
        &w,
        "role_assignments",
        |i| {
            world
                .exchange_role_assignments
                .get(i)
                .map(|a| keys::role("exchange_ediscovery", &a.role, &a.group))
        },
        |_| None,
    );
    c.log()
        .info_v4("Completed collection of eDiscovery configuration data from Exchange Online.");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Unified audit log searches

/// Writes `Simple_<name>` then `<name>` for a search result and returns the Simple rows.
/// `notice` passes `-Notice` to both calls. The Simple file is derived from the raw one
/// (research §4); tenant and user folders have their own artifacts.
pub(super) fn simple_and_raw(
    c: &mut Ctx<'_>,
    tree: &mut Tree<'_>,
    simple_prefix: &str,
    raw_prefix: &str,
    user: Option<&str>,
    records: &[Ual],
    notice: bool,
) -> Result<Vec<Row>> {
    let nl = c.omft.host.newline;
    let raw = raw_rows(records, nl);
    let label = format!("{}/{simple_prefix}", user.unwrap_or("Tenant"));
    let simple = simple_rows(c.world, &raw, records, &label);
    let (simple_art, raw_art) = match user {
        None => (
            Art::derived("hawk.tenant.simple_ual"),
            Art::raw("hawk.tenant.raw_ual"),
        ),
        Some(_) => (
            Art::derived("hawk.user.simple_ual"),
            Art::raw("hawk.user.raw_ual"),
        ),
    };
    let w = c.omft.write(
        tree,
        simple_prefix,
        user,
        simple_art,
        &simple,
        Formats::CSV_JSON,
        false,
        notice,
    )?;
    register_ual(tree, &w, records);
    let w = c.omft.write(
        tree,
        raw_prefix,
        user,
        raw_art,
        &raw,
        Formats::CSV_JSON,
        false,
        notice,
    )?;
    register_ual(tree, &w, records);
    Ok(simple)
}

/// Get-HawkTenantEDiscoveryLog (H01).
fn ediscovery_log(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    c.log()
        .action("Initiating collection of eDiscovery configuration data from Exchange Online.");
    let found = c.search("Search-UnifiedAuditLog -RecordType 'Discovery'", |u| {
        u.record_type == RecordType::Discovery
    });
    if found.is_empty() {
        c.log()
            .info("Get-HawkTenantEDiscoveryLog completed successfully");
        c.log().action("No eDiscovery Logs found");
    } else {
        c.log().notice("eDiscovery Logs have been found.");
        c.log().notice(
            "Please review these eDiscoveryLogs.csv to validate the activity is legitimate.",
        );
        c.log().action("Writing parsed eDiscovery log data");
        simple_and_raw(
            c,
            tree,
            "Simple_eDiscoveryLogs",
            "eDiscoveryLogs",
            None,
            &found,
            false,
        )?;
    }
    c.log()
        .info("Completed collection of eDiscovery logs from Exchange Online.");
    Ok(())
}

/// `Test-SuspiciousInboxRule` on a Simple record (H02): `Param_ForwardTo`,
/// `Param_ForwardAsAttachmentTo`, `Param_RedirectTo` or `Param_DeleteMessage` non-empty
/// (the text `False` is non-empty), or `Param_MoveToFolder` `Deleted Items`.
pub fn suspicious_admin_rule(row: &Row) -> bool {
    let set = |k: &str| text_of(row, k).is_some_and(|v| !v.is_empty());
    set("Param_ForwardTo")
        || set("Param_ForwardAsAttachmentTo")
        || set("Param_RedirectTo")
        || set("Param_DeleteMessage")
        || text_of(row, "Param_MoveToFolder")
            .is_some_and(|v| v.eq_ignore_ascii_case("Deleted Items"))
}

struct AdminRuleStep {
    operation: &'static str,
    initiating: &'static str,
    searching: Option<&'static str>,
    searched: Option<&'static str>,
    found: &'static str,
    writing: Option<&'static str>,
    simple: &'static str,
    raw: &'static str,
    investigate: &'static str,
    events: &'static str,
    none: [&'static str; 2],
    completed: &'static str,
}

const ADMIN_RULE_STEPS: [AdminRuleStep; 3] = [
    AdminRuleStep {
        operation: "New-InboxRule",
        initiating: "Initiating collection of admin inbox rule creation events from the UAL.",
        searching: None,
        searched: Some("Searching Unified Audit Log for inbox rule creation events."),
        found: "admin inbox rule changes in Unified Audit Log.",
        writing: Some("Writing parsed admin inbox rule creation data."),
        simple: "Simple_Admin_Inbox_Rules_Creation",
        raw: "Admin_Inbox_Rules_Creation",
        investigate: "_Investigate_Admin_Inbox_Rules_Creation",
        events: "inbox rule creation events.",
        none: [
            "Completed collection of admin inbox rule creation events from the UAL.",
            "No admin inbox rule creation events found in audit logs",
        ],
        completed: "Completed collection of admin inbox rule creation events from the UAL.",
    },
    AdminRuleStep {
        operation: "Set-InboxRule",
        initiating: "Initiating collection of admin inbox rule modification events from the UAL.",
        searching: Some("Searching audit logs for inbox rule modification events"),
        searched: None,
        found: "admin inbox rule modifications in audit logs",
        writing: Some("Writing parsed admin inbox rule modification data"),
        simple: "Simple_Admin_Inbox_Rules_Modification",
        raw: "Admin_Inbox_Rules_Modification",
        investigate: "_Investigate_Admin_Inbox_Rules_Modification",
        events: "inbox rule modification events",
        none: [
            "Get-HawkTenantAdminInboxRuleModification completed successfully",
            "No inbox rule modifications found in audit logs",
        ],
        completed: "Completed collection of admin inbox rule modification events from the UAL.",
    },
    AdminRuleStep {
        operation: "Remove-InboxRule",
        initiating: "Initiating collection of admin inbox rule removal events from the UAL.",
        searching: Some("Searching audit logs for inbox rule removals"),
        searched: None,
        found: "admin inbox rule removals in audit logs",
        writing: None,
        simple: "Simple_Admin_Inbox_Rules_Removal",
        raw: "Admin_Inbox_Rules_Removal",
        investigate: "_Investigate_Admin_Inbox_Rules_Removal",
        events: "inbox rule removal events",
        none: [
            "Get-HawkTenantAdminInboxRuleRemoval completed successfully",
            "No inbox rule removals found in audit logs",
        ],
        completed: "Completed collection of admin inbox rule removal events from the UAL.",
    },
];

/// Get-HawkTenantAdminInboxRule{Creation,Modification,Removal} (H02).
fn admin_rules(c: &mut Ctx<'_>, tree: &mut Tree<'_>, step: &AdminRuleStep) -> Result<()> {
    c.log().action(step.initiating);
    c.omft.created("Tenant");
    if let Some(m) = step.searching {
        c.log().action(m);
    }
    let op = step.operation;
    let found = c.search(
        &format!("Search-UnifiedAuditLog -RecordType ExchangeAdmin -Operations '{op}'"),
        |u| u.record_type == RecordType::ExchangeAdmin && u.operation.eq_ignore_ascii_case(op),
    );
    if let Some(m) = step.searched {
        c.log().action(m);
    }
    if found.is_empty() {
        c.log().info(step.none[0]);
        c.log().action(step.none[1]);
    } else {
        c.log()
            .info(format!("Found {} {}", found.len(), step.found));
        if let Some(m) = step.writing {
            c.log().action(m);
        }
        let simple = simple_and_raw(c, tree, step.simple, step.raw, None, &found, false)?;
        let flagged: Vec<Row> = simple.into_iter().filter(suspicious_admin_rule).collect();
        if !flagged.is_empty() {
            c.log()
                .notice(format!("Found {} {}", flagged.len(), step.events));
            c.log().notice("Please verify this activity is legitimate.");
            let w = c.omft.write(
                tree,
                step.investigate,
                None,
                Art::raw("hawk.investigate_file"),
                &flagged,
                Formats::CSV_JSON,
                false,
                true,
            )?;
            register_flags(tree, &w);
        }
    }
    c.log().info(step.completed);
    Ok(())
}

/// Get-HawkTenantAdminMailboxPermissionChange (H03).
fn permission_changes(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    c.log()
        .action("Initiating collection of mailbox permission changes from the UAL.");
    c.omft.created("Tenant");
    c.log()
        .action("Searching audit logs for mailbox permission changes");
    let ops = [
        "Add-MailboxPermission",
        "Add-RecipientPermission",
        "Add-ADPermission",
    ];
    let found = c.search(
        "Search-UnifiedAuditLog -RecordType ExchangeAdmin -Operations 'Add-MailboxPermission','Add-RecipientPermission','Add-ADPermission'",
        |u| u.record_type == RecordType::ExchangeAdmin && one_of(&u.operation, &ops),
    );
    if found.is_empty() {
        c.log()
            .info("Get-HawkTenantAdminMailBoxPermissionChange completed successfully");
        c.log()
            .action("No mailbox permission changes found in audit logs");
    } else {
        c.log().info(format!(
            "Found {} mailbox permission changes in audit logs",
            found.len()
        ));
        let simple = simple_and_raw(
            c,
            tree,
            "Simple_Mailbox_Permission_Change",
            "Mailbox_Permission_Change",
            None,
            &found,
            false,
        )?;
        let access = Regex::new("(?i)FullAccess|SendAs").expect("valid regex");
        let flagged: Vec<Row> = simple
            .into_iter()
            .filter(|row| {
                let op = text_of(row, "Operation").unwrap_or_default();
                let grant = text_of(row, "Param_AccessRights").is_some_and(|v| access.is_match(&v))
                    || op.eq_ignore_ascii_case("Add-ADPermission")
                    || op.to_lowercase().contains("add-recipientpermission");
                let system = text_of(row, "UserId").is_some_and(|v| {
                    v.eq_ignore_ascii_case("NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)")
                }) && text_of(row, "ObjectId")
                    .is_some_and(|v| v.to_lowercase().contains("discoverysearchmailbox"))
                    && text_of(row, "Param_User")
                        .is_some_and(|v| v.to_lowercase().contains("discovery management"));
                grant && !system
            })
            .collect();
        if !flagged.is_empty() {
            c.log().notice(format!(
                "Found {} mailbox permission changes",
                flagged.len()
            ));
            c.log().notice("Please verify this activity is legitimate.");
            let w = c.omft.write(
                tree,
                "_Investigate_Mailbox_Permission_Change",
                None,
                Art::raw("hawk.investigate_file"),
                &flagged,
                Formats::CSV_JSON,
                false,
                true,
            )?;
            register_flags(tree, &w);
        }
    }
    c.log()
        .info("Completed collection of mailbox permission changes from the UAL.");
    Ok(())
}

/// The names of AuditData's `Parameters`.
fn parameter_names(u: &Ual) -> Vec<String> {
    u.audit
        .get("Parameters")
        .and_then(Value::as_array)
        .map(|ps| {
            ps.iter()
                .filter_map(|p| p.get("Name").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Get-HawkTenantAdminEmailForwardingChange (H04): mailbox changes with a forwarding
/// parameter, written with `-Notice`; `Forwarding_Recipients` never materializes in 4.0.
fn forwarding_changes(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    c.log()
        .action("Initiating collection of email forwarding configuration changes from the UAL.");
    c.log()
        .action("Collecting email forwarding configuration changes from the UAL.");
    c.omft.created("Tenant");
    let ops = [
        "Set-Mailbox",
        "Set-MailUser",
        "Set-RemoteMailbox",
        "Enable-RemoteMailbox",
    ];
    let command = "Search-UnifiedAuditLog -RecordType ExchangeAdmin -Operations @(\n    'Set-Mailbox',\n    'Set-MailUser',\n    'Set-RemoteMailbox',\n    'Enable-RemoteMailbox'\n)";
    let all = c.search(command, |u| {
        u.record_type == RecordType::ExchangeAdmin && one_of(&u.operation, &ops)
    });
    c.log()
        .info("Completed collection of email forwarding configuration changes from the UAL.");
    c.log()
        .action("Filtering results for forwarding changes...");
    let names = [
        "ForwardingAddress",
        "ForwardingSMTPAddress",
        "ExternalEmailAddress",
        "PrimarySmtpAddress",
        "RedirectTo",
        "DeliverToMailboxAndForward",
        "DeliverToAndForward",
    ];
    let changes: Vec<Ual> = all
        .iter()
        .filter(|u| parameter_names(u).iter().any(|n| one_of(n, &names)))
        .cloned()
        .collect();
    c.log().info("Completed filtering for forwarding changes.");
    if changes.is_empty() {
        c.log()
            .info("Get-HawkTenantAdminEmailForwardingChange completed successfully");
        c.log()
            .action("No forwarding changes found in filtered results");
        c.log().action(format!(
            "Retrieved {} total operations, but none involved forwarding changes",
            all.len()
        ));
    } else {
        c.log().info(format!(
            "Found {} change(s) to user email forwarding.",
            changes.len()
        ));
        simple_and_raw(
            c,
            tree,
            "Simple_Forwarding_Changes",
            "Forwarding_Changes",
            None,
            &changes,
            true,
        )?;
        c.log()
            .action("Beginning detailed analysis of forwarding changes...");
        c.log().info("Completed processing forwarding changes");
    }
    c.log()
        .info("Completed collection of email forwarding configuration changes from the UAL.");
    Ok(())
}

/// Get-HawkTenantDomainActivity (H05): Hawk's operation names never match Microsoft's
/// (`Update Domain` vs `Update domain.`), so real domain events leave no file.
fn domain_activity(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    c.log()
        .action("Initiating collection of domain configuration changes from the UAL.");
    let ops = [
        "Set-AcceptedDomain",
        "Add-FederatedDomain",
        "Update Domain",
        "Add verified domain",
        "Add unverified domain",
        "remove unverified domain",
    ];
    let found = c.search(
        "Search-UnifiedAuditLog -RecordType 'AzureActiveDirectory' -Operations 'Set-AcceptedDomain','Add-FederatedDomain','Update Domain','Add verified domain', 'Add unverified domain', 'remove unverified domain'",
        |u| u.record_type == RecordType::AzureActiveDirectory && one_of(&u.operation, &ops),
    );
    if found.is_empty() {
        c.log()
            .info("Get-HawkTenantDomainActivity completed successfully");
        c.log().action("No Domain configuration changes found.");
    } else {
        c.log().notice("Domain configuration changes found.");
        c.log().notice(
            "Please review these Domain_Changes_Audit to ensure any changes are legitimate.",
        );
        let nl = c.omft.host.newline;
        let n = found.len();
        for (i, u) in found.iter().enumerate() {
            let one = std::slice::from_ref(u);
            let raw = vec![super::raw_row(u, i, n, nl)];
            let w = c.omft.write(
                tree,
                "Domain_Changes_Audit",
                None,
                Art::raw("hawk.tenant.raw_ual"),
                &raw,
                Formats::CSV,
                true,
                false,
            )?;
            register_ual(tree, &w, one);
            let parsed = vec![super::expanded_row(u)];
            let w = c.omft.write(
                tree,
                "Domain_Changes_Audit",
                None,
                Art::raw("hawk.tenant.raw_ual"),
                &parsed,
                Formats::JSON,
                true,
                false,
            )?;
            register_ual(tree, &w, one);
        }
    }
    c.log()
        .info("Completed collection of domain configuration changes from the UAL.");
    Ok(())
}

pub(super) const RBAC_OPERATIONS: [&str; 16] = [
    "New-ManagementRole",
    "Remove-ManagementRole",
    "New-ManagementRoleAssignment",
    "Remove-ManagementRoleAssignment",
    "Set-ManagementRoleAssignment",
    "New-ManagementScope",
    "Remove-ManagementScope",
    "Set-ManagementScope",
    "New-ManagementRoleEntry",
    "Remove-ManagementRoleEntry",
    "Set-ManagementRoleEntry",
    "New-RoleGroup",
    "Remove-RoleGroup",
    "Set-RoleGroup",
    "Add-RoleGroupMember",
    "Remove-RoleGroupMember",
];

/// Get-HawkTenantRBACChange.
fn rbac_changes(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    c.omft.created("Tenant");
    c.log()
        .action("Initiating collection of RBAC Changes from the UAL.");
    let command = format!(
        "Search-UnifiedAuditLog -RecordType ExchangeAdmin -Operations '{}'",
        RBAC_OPERATIONS.join("','")
    );
    let found = c.search(&command, |u| {
        u.record_type == RecordType::ExchangeAdmin && one_of(&u.operation, &RBAC_OPERATIONS)
    });
    if found.is_empty() {
        c.log()
            .info("Get-HawkTenantRbacChange completed successfully");
        c.log().action("No RBAC changes found.");
    } else {
        c.log().info(format!(
            "Found {} changes made to Roles-Based Access Control",
            found.len()
        ));
        simple_and_raw(
            c,
            tree,
            "Simple_RBAC_Changes",
            "RBAC_Changes",
            None,
            &found,
            false,
        )?;
    }
    c.log()
        .info("Completed collection of RBAC configuration changes from the UAL.");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Microsoft Graph

fn graph_user_ref(world: &World, upn: &str) -> Value {
    let u = world.user_by_upn(upn);
    json!({
        "DisplayName": u.map(|u| u.display_name.clone()),
        "Id": u.map(|u| u.object_id.to_string()),
        "IPAddress": Value::Null,
        "UserPrincipalName": upn,
        "AdditionalProperties": {},
    })
}

/// A `MicrosoftGraphDirectoryAudit` (Get-MgAuditLogDirectoryAudit).
fn directory_audit_row(world: &World, a: &crate::events::DirAudit) -> Row {
    let by = &a.initiated_by;
    let user = match &by.upn {
        Some(upn) => {
            let mut u = graph_user_ref(world, upn);
            u["IPAddress"] = json!(by.ip.map(|ip| ip.to_string()).unwrap_or_default());
            if let Some(id) = by.user_id {
                u["Id"] = json!(id.to_string());
            }
            u
        }
        None => Value::Null,
    };
    let app = match (&by.app_id, &by.app_name) {
        (None, None) => Value::Null,
        (id, name) => json!({
            "AppId": id.map(|u| u.to_string()),
            "DisplayName": name,
            "ServicePrincipalId": Value::Null,
            "ServicePrincipalName": Value::Null,
            "AdditionalProperties": {},
        }),
    };
    let targets: Vec<Value> = a
        .targets
        .iter()
        .map(|t| {
            json!({
                "DisplayName": t.display_name,
                "GroupType": Value::Null,
                "Id": t.id,
                "ModifiedProperties": t.modified.iter().map(|(n, old, new)| json!({
                    "DisplayName": n, "NewValue": new, "OldValue": old, "AdditionalProperties": {},
                })).collect::<Vec<_>>(),
                "Type": t.kind,
                "UserPrincipalName": t.upn,
                "AdditionalProperties": {},
            })
        })
        .collect();
    let details: Vec<Value> = a
        .additional_details
        .iter()
        .map(|(k, v)| json!({"Key": k, "Value": v, "AdditionalProperties": {}}))
        .collect();
    vec![
        r("ActivityDateTime", date(a.time, DtKind::Utc)),
        r("ActivityDisplayName", s(a.activity.clone())),
        r(
            "AdditionalDetails",
            model("IMicrosoftGraphKeyValue[]", Value::Array(details)),
        ),
        r("Category", s(a.category.clone())),
        r("CorrelationId", s(a.correlation_id.to_string())),
        r("Id", s(a.id.clone())),
        r(
            "InitiatedBy",
            model(
                "MicrosoftGraphAuditActivityInitiator1",
                json!({"App": app, "User": user, "AdditionalProperties": {}}),
            ),
        ),
        r("LoggedByService", s(a.logged_by_service.clone())),
        r("OperationType", s(a.operation_type.clone())),
        r("Result", s(a.result.clone())),
        r("ResultReason", s(a.result_reason.clone())),
        r(
            "TargetResources",
            model("IMicrosoftGraphTargetResource[]", Value::Array(targets)),
        ),
        r("AdditionalProperties", additional_properties()),
    ]
}

/// Get-HawkTenantEntraIDAuditLog: the last 30 days before the run, whatever the window.
fn entra_audit_log(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let world = c.world;
    c.log()
        .action("Initiating collection of Entra ID audit events from Microsoft Graph.");
    c.omft.created("Tenant");
    // `(Get-Date).AddDays(-30).Date`, host local, printed with a literal `Z`.
    let local = c.local_now();
    let from = (local - Duration::days(30))
        .date_naive()
        .and_time(NaiveTime::MIN)
        .and_utc();
    let to = local;
    if world.window_start() < from {
        c.log().info(
            "Note: Entra ID audit logs are only available for the past 30 days. Earlier dates will be ignored.",
        );
    }
    c.log().action("Retrieving audit logs for the past 30 days");
    c.log().tick(1, 5);
    let mut audits: Vec<crate::events::DirAudit> = world
        .directory_audits()
        .into_iter()
        .filter(|a| a.time >= from && a.time <= to)
        .collect();
    audits.sort_by(|a, b| (b.time, &b.id).cmp(&(a.time, &a.id)));
    if audits.is_empty() {
        c.log()
            .info("Get-HawkTenantEntraIDAuditLog completed successfully");
        c.log()
            .action("No audit logs found for the specified time period");
    } else {
        c.log()
            .info(format!("Found {} audit log entries", audits.len()));
        let rows: Vec<Row> = audits
            .iter()
            .map(|a| directory_audit_row(world, a))
            .collect();
        let w = c.omft.write(
            tree,
            "EntraIDAuditLogs",
            None,
            Art::raw("hawk.tenant.entra_audit"),
            &rows,
            Formats::CSV_JSON,
            false,
            false,
        )?;
        register(
            tree,
            &w,
            "directory_audits",
            |i| Some(keys::dir_audit(&audits[i].id)),
            |i| Some(Evidence::DirAudit(audits[i].id.clone())),
        );
    }
    c.log()
        .info("Completed collection of Entra ID audit events from Microsoft Graph.");
    Ok(())
}

/// The value of AuditData `ExtendedProperties` entry `name` (`-eq`, case-insensitive).
fn extended(u: &Ual, name: &str) -> Val {
    u.audit
        .get("ExtendedProperties")
        .and_then(Value::as_array)
        .and_then(|eps| {
            eps.iter().find(|e| {
                e.get("Name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
            })
        })
        .and_then(|e| e.get("Value"))
        .map_or(Val::Null, super::json_val)
}

/// Get-HawkTenantEntraIDAppAuditLog (H06): one appended call per event; the 10 projected
/// columns carry no time (`env_time` is not an ExtendedProperties entry), which Sparrow
/// reports as not supported.
pub(super) fn app_audit_log(c: &mut Ctx<'_>, tree: &mut Tree<'_>, prefix: &str) -> Result<()> {
    // Progress lines are Hawk 4.0 wording (`*_v4`: not logged by Hawk 3). Hawk 3 keeps the
    // notices, which feed `_Investigate.txt`; source-derived (no 3.1 source): their wording.
    c.log().action_v4("Gathering Tenant information");
    c.log()
        .action_v4("Initiating collection of Entra ID application audit events from the UAL.");
    let ops = ["Add OAuth2PermissionGrant.", "Consent to application."];
    let found = c.search(
        "Search-UnifiedAuditLog -RecordType 'AzureActiveDirectory' -Operations 'Add OAuth2PermissionGrant.','Consent to application.' ",
        |u| u.record_type == RecordType::AzureActiveDirectory && one_of(&u.operation, &ops),
    );
    if found.is_empty() {
        c.log()
            .info_v4("Get-HawkTenantEntraIDAppAuditLog completed successfully");
        c.log()
            .action_v4("No Application related events found in the search time frame.");
    } else {
        c.log().notice("Application Rights Activity found.");
        c.log().notice(format!(
            "Please review these {prefix}.csv to ensure any changes are legitimate.",
        ));
        let text = |u: &Ual, k: &str| u.audit.get(k).map_or(Val::Null, super::json_val);
        // A parsed artifact, but without `env_time` Sparrow finds no time and reports the
        // shape not supported (set below).
        let app_art = Art::raw("hawk.tenant.entra_app_audit");
        let mut rels = Vec::new();
        let mut timed = false;
        for u in &found {
            let env_time = extended(u, "env_time");
            timed |= !matches!(&env_time, Val::Null)
                && !matches!(&env_time, Val::Str(s) if s.is_empty());
            let row = vec![
                r("Id", text(u, "Id")),
                r("Operation", text(u, "Operation")),
                r("ResultStatus", text(u, "ResultStatus")),
                r("Workload", text(u, "Workload")),
                r("ClientIP", text(u, "ClientIP")),
                r("UserID", text(u, "UserId")),
                r("ActorUPN", extended(u, "actorUPN")),
                r("targetName", extended(u, "targetName")),
                r("env_time", env_time),
                r("correlationId", extended(u, "correlationId")),
            ];
            let w = c.omft.write(
                tree,
                prefix,
                None,
                app_art,
                &[row],
                Formats::CSV_JSON,
                true,
                false,
            )?;
            if timed {
                register_ual(tree, &w, std::slice::from_ref(u));
            }
            rels.extend(w.parts().map(|p| p.rel.clone()));
        }
        if !timed {
            rels.sort();
            rels.dedup();
            for rel in rels {
                tree.expect_status(&rel, "not_supported");
            }
        }
    }
    c.log()
        .info_v4("Completed collection of Entra ID application audit events from the UAL.");
    Ok(())
}

/// Get-HawkTenantEXOAdmin: one row per role group member.
pub(super) fn exo_admins(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    // Progress lines are Hawk 4.0 wording (`*_v4`: not logged by Hawk 3). Hawk 3 keeps the
    // notices, which feed `_Investigate.txt`; source-derived (no 3.1 source): their wording.
    let world = c.world;
    c.log()
        .action_v4("Initiating collection of Exchange Online Admins.");
    let group = format!(
        "TenantAdmins_{}",
        stream(world.seed, "hawk/tenantadmins").digits(8)
    );
    let mut members: Vec<(String, String, Option<String>, &str)> = Vec::new();
    if let Some(a) = world.admins.first() {
        members.push((
            "Organization Management".into(),
            a.upn.clone(),
            Some(a.upn.clone()),
            "UserMailbox",
        ));
    }
    members.push((
        "Organization Management".into(),
        group.clone(),
        None,
        "Group",
    ));
    if let Some(a) = world.admins.get(1) {
        members.push((
            "Recipient Management".into(),
            a.upn.clone(),
            Some(a.upn.clone()),
            "UserMailbox",
        ));
    }
    let rows: Vec<Row> = members
        .iter()
        .map(|(g, m, _, t)| {
            vec![
                r("ExchangeAdminGroup", s(g.clone())),
                r("Members", s(m.clone())),
                r("RecipientType", s(*t)),
            ]
        })
        .collect();
    let w = c.omft.write(
        tree,
        "ExchangeOnlineAdministrators",
        None,
        Art::raw("hawk.tenant.exo_admins"),
        &rows,
        Formats::CSV_JSON,
        false,
        false,
    )?;
    register(
        tree,
        &w,
        "role_assignments",
        |i| Some(keys::role("exchange_rbac", &members[i].0, &members[i].1)),
        |_| None,
    );
    c.log()
        .info_v4("Completed exporting Exchange Online Admins.");
    Ok(())
}

/// One `Get-AzureADPSPermission` row and what keys and delivers it.
pub(super) struct GrantRow {
    pub row: Row,
    pub key: String,
    pub evidence: Option<Evidence>,
    consent_type: Option<String>,
    permission: String,
}

/// `Get-AzureADPSPermission`: every delegated grant scope, then every application
/// permission, with Hawk's `ConsentGrantRiskCategory` column (empty for now).
pub(super) fn grant_rows(world: &World) -> Vec<GrantRow> {
    let sp = |app: Uuid| world.apps.iter().find(|a| a.app_id == app);
    let mut out = Vec::new();
    for kind in [GrantKind::Delegated, GrantKind::Application] {
        for g in world.grants.iter().filter(|g| g.kind == kind) {
            let (Some(client), Some(resource)) = (sp(g.client_app_id), sp(g.resource_app_id))
            else {
                continue;
            };
            let principal = g.principal.as_deref().and_then(|p| world.user_by_upn(p));
            for scope in g.scope.split(' ').filter(|x| !x.is_empty()) {
                let client_id = client.sp_object_id.to_string();
                let resource_id = resource.sp_object_id.to_string();
                let principal_id = principal.map(|p| p.object_id.to_string());
                let mut row = vec![
                    r(
                        "PermissionType",
                        s(if kind == GrantKind::Delegated {
                            "Delegated"
                        } else {
                            "Application"
                        }),
                    ),
                    r("ClientObjectId", s(client_id.clone())),
                    r("ClientDisplayName", s(client.display_name.clone())),
                    r("ResourceObjectId", s(resource_id.clone())),
                    r("ResourceDisplayName", s(resource.display_name.clone())),
                    r("Permission", s(scope)),
                ];
                let consent_type = (kind == GrantKind::Delegated).then(|| g.consent_type.clone());
                if kind == GrantKind::Delegated {
                    row.extend([
                        r("ConsentType", s(g.consent_type.clone())),
                        r("PrincipalObjectId", opt(principal_id.clone())),
                        r(
                            "PrincipalDisplayName",
                            opt(principal.map(|p| p.display_name.clone())),
                        ),
                    ]);
                }
                row.push(r("ConsentGrantRiskCategory", s("")));
                out.push(GrantRow {
                    row,
                    key: keys::oauth_grant(
                        &client_id,
                        &resource_id,
                        scope,
                        principal_id.as_deref(),
                    ),
                    evidence: Some(Evidence::Grant {
                        client_app_id: g.client_app_id,
                        scope: scope.to_string(),
                        principal: g.principal.clone(),
                    }),
                    consent_type,
                    permission: scope.to_string(),
                });
            }
        }
    }
    out
}

/// Hawk's `ConsentGrantRiskCategory` (H07): `Broad-Scope Grant` for `AllPrincipals` or a
/// permission containing `all`, then per pattern `Extremely Dangerous`, then per pattern
/// `High Risk`, each assignment overwriting the last (`^User\.` catches `User.Read`). Returns
/// Hawk's three counts: grants per category test, a grant counted once per matching pattern.
fn categorize(grants: &mut [GrantRow]) -> (usize, usize, usize) {
    fn set(g: &mut GrantRow, cat: &str) {
        if let Some(slot) = g
            .row
            .iter_mut()
            .find(|(k, _)| k == "ConsentGrantRiskCategory")
        {
            slot.1 = s(cat);
        }
    }
    let all = Regex::new("(?i)all").expect("valid regex");
    let mut broad = 0;
    for g in grants.iter_mut() {
        if g.consent_type.as_deref() == Some("AllPrincipals") || all.is_match(&g.permission) {
            set(g, "Broad-Scope Grant");
            broad += 1;
        }
    }
    let mut count = |pats: &[&str], cat: &str| {
        let mut n = 0;
        for p in pats {
            let re = Regex::new(&format!("(?i){p}")).expect("valid regex");
            for g in grants.iter_mut() {
                if re.is_match(&g.permission) {
                    set(g, cat);
                    n += 1;
                }
            }
        }
        n
    };
    let ed = count(
        &[
            r"^AppRoleAssignment\.ReadWrite\.All$",
            r"^RoleManagement\.ReadWrite\.Directory$",
        ],
        "Extremely Dangerous",
    );
    let hr = count(
        &[
            r"^BitlockerKey\.Read\.All$",
            r"^Chat\.",
            r"^Directory\.ReadWrite\.All$",
            r"^eDiscovery\.",
            r"^Files\.",
            r"^MailboxSettings\.ReadWrite$",
            r"^Mail\.ReadWrite$",
            r"^Mail\.Send$",
            r"^Sites\.",
            r"^User\.",
        ],
        "High Risk",
    );
    (broad, ed, hr)
}

/// Get-HawkTenantConsentGrant (H07): categories in Hawk's order, the last match winning
/// (`^User\.` makes nearly every tenant `High Risk`).
fn consent_grants(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let world = c.world;
    c.log()
        .action("Initiating collection of OAuth / Application Grants from Microsoft Graph.");
    let mut grants = grant_rows(world);
    let (broad, ed, hr) = categorize(&mut grants);
    let mut flag = false;
    if broad > 0 {
        c.log().notice(format!(
            "Found {broad} broad-scoped grants ('AllPrincipals' or '*.All')"
        ));
        flag = true;
    }
    if ed > 0 {
        c.log()
            .notice(format!("Found {ed} Extremely Dangerous Grant(s)"));
        flag = true;
    }
    if hr > 0 {
        c.log().notice(format!("Found {hr} High Risk Grant(s)"));
        flag = true;
    }
    let url = "https://learn.microsoft.example/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants";
    if flag {
        c.log()
            .notice("Please verify these grants are legitimate / required.");
        c.log()
            .notice("For more information on understanding these results results, visit");
        c.log().notice(url);
        let flagged: Vec<Row> = grants
            .iter()
            .filter(|g| text_of(&g.row, "ConsentGrantRiskCategory").is_some_and(|v| !v.is_empty()))
            .map(|g| g.row.clone())
            .collect();
        let w = c.omft.write(
            tree,
            "_Investigate_Consent_Grants",
            None,
            Art::raw("hawk.investigate_file"),
            &flagged,
            Formats::CSV_JSON,
            false,
            true,
        )?;
        register_flags(tree, &w);
    } else {
        c.log().info("To review this data follow:");
        c.log().info(url);
    }
    let rows: Vec<Row> = grants.iter().map(|g| g.row.clone()).collect();
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
    c.log()
        .info("Completed collection of OAuth / Application Grants from Microsoft Graph.");
    Ok(())
}

/// Graph's refusal of Identity Protection data without Entra ID P2.
const P2_REFUSED: &str = "Your tenant is not licensed for this feature.";

fn capitalized(level: &str) -> String {
    let mut ch = level.chars();
    match ch.next() {
        Some(f) => format!("{}{}", f.to_uppercase(), ch.as_str().to_lowercase()),
        None => String::new(),
    }
}

/// Group-Object RiskLevel sorted high, medium, low, none (others last).
fn level_groups<'a>(levels: impl Iterator<Item = &'a str>) -> Vec<(String, usize)> {
    let mut groups: Vec<(String, usize)> = Vec::new();
    for l in levels {
        match groups.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(l)) {
            Some(g) => g.1 += 1,
            None => groups.push((l.to_string(), 1)),
        }
    }
    let rank = |n: &str| match n.to_lowercase().as_str() {
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "none" => 4,
        _ => 0,
    };
    groups.sort_by_key(|(n, _)| rank(n));
    groups
}

/// Get-HawkTenantRiskyUsers (H08, H09).
fn risky_users(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let world = c.world;
    c.log()
        .action("Initiating collection of Risky Users from Entra ID.");
    c.omft.created("Tenant");
    c.log().action("Retrieving current risky users");
    c.log().tick(1, 3);
    if !world.licence.p2() {
        c.log()
            .error(format!("Error retrieving risky users: {P2_REFUSED}"));
        c.log()
            .info("Completed collection of Risky Users from Entra ID.");
        return Ok(());
    }
    let users: Vec<crate::world::RiskyUser> = world.risky_users().into_values().collect();
    if users.is_empty() {
        c.log().info("No risky users found");
        c.log()
            .info("Completed collection of Risky Users from Entra ID.");
        return Ok(());
    }
    c.log()
        .info(format!("Total risky users found: {}", users.len()));
    for (name, n) in level_groups(users.iter().map(|u| u.level.as_str())) {
        c.log().info(format!(
            "- {n} users at Risk Level '{}'",
            capitalized(&name)
        ));
    }
    let row = |u: &crate::world::RiskyUser| -> Row {
        vec![
            r("History", Val::Null),
            r("Id", s(u.user_id.to_string())),
            r("IsDeleted", Val::Bool(false)),
            r("IsProcessing", Val::Bool(false)),
            r("RiskDetail", s(u.detail.clone())),
            r("RiskLastUpdatedDateTime", date(u.updated, DtKind::Utc)),
            r("RiskLevel", s(u.level.clone())),
            r("RiskState", s(u.state.clone())),
            r("UserDisplayName", s(u.display_name.clone())),
            r("UserPrincipalName", s(u.upn.clone())),
            r("AdditionalProperties", additional_properties()),
        ]
    };
    let rows: Vec<Row> = users.iter().map(row).collect();
    let w = c.omft.write(
        tree,
        "RiskyUsers",
        None,
        Art::raw("hawk.tenant.risky_users"),
        &rows,
        Formats::CSV_JSON,
        false,
        false,
    )?;
    register(
        tree,
        &w,
        "risky_users",
        |i| Some(keys::risky_user(users[i].user_id)),
        |i| Some(Evidence::RiskyUser(users[i].upn.clone())),
    );
    let compromised: Vec<&crate::world::RiskyUser> = users
        .iter()
        .filter(|u| u.state.eq_ignore_ascii_case("confirmedCompromised"))
        .collect();
    if !compromised.is_empty() {
        c.log().notice(format!(
            "Found {} confirmed compromised accounts",
            compromised.len()
        ));
        c.log()
            .notice("Details in _Investigate_Compromised_Users files");
        let rows: Vec<Row> = compromised.iter().map(|u| row(u)).collect();
        let w = c.omft.write(
            tree,
            "_Investigate_Compromised_Users",
            None,
            Art::raw("hawk.investigate_file"),
            &rows,
            Formats::JSON,
            false,
            true,
        )?;
        register_flags(tree, &w);
    }
    let mut flagged: Vec<&crate::world::RiskyUser> = Vec::new();
    let mut counts = [0usize; 3];
    for (i, (level, found, wording)) in [
        (
            "high",
            "High",
            "High Risk users requiring immediate investigation",
        ),
        (
            "medium",
            "Medium",
            "Medium Risk users requiring investigation",
        ),
        ("low", "Low", "Low Risk users for review"),
    ]
    .iter()
    .enumerate()
    {
        let at: Vec<&crate::world::RiskyUser> = users
            .iter()
            .filter(|u| u.level.eq_ignore_ascii_case(level))
            .collect();
        if at.is_empty() {
            continue;
        }
        counts[i] = at.len();
        c.log().notice(format!("Found {} {wording}", at.len()));
        for u in &at {
            c.log()
                .notice(format!("{found} Risk user detected: {}", u.upn));
            c.log()
                .notice(format!("Risk Level: {}, Risk State: {}", u.level, u.state));
        }
        flagged.extend(at);
    }
    if !flagged.is_empty() {
        c.log().notice(format!(
            "Found risky users: {} High, {} Medium, {} Low",
            counts[0], counts[1], counts[2]
        ));
        let rows: Vec<Row> = flagged.iter().map(|u| row(u)).collect();
        let w = c.omft.write(
            tree,
            "_Investigate_Risky_Users",
            None,
            Art::raw("hawk.investigate_file"),
            &rows,
            Formats::CSV_JSON,
            false,
            true,
        )?;
        register_flags(tree, &w);
    }
    c.log()
        .info("Completed collection of Risky Users from Entra ID.");
    Ok(())
}

fn graph_location(loc: &crate::world::Location) -> Value {
    json!({
        "City": loc.city,
        "CountryOrRegion": loc.country_iso,
        "GeoCoordinates": {"Altitude": Value::Null, "Latitude": loc.lat, "Longitude": loc.lon,
            "AdditionalProperties": {}},
        "State": loc.state,
        "AdditionalProperties": {},
    })
}

/// A `MicrosoftGraphRiskDetection`: the original object (`AdditionalInfo` JSON text).
fn risk_detection_row(d: &crate::events::RiskDetection) -> Row {
    vec![
        r("Activity", s(d.activity.clone())),
        r("ActivityDateTime", date(d.activity_time, DtKind::Utc)),
        r("AdditionalInfo", s(d.additional_info.clone())),
        r(
            "CorrelationId",
            opt(d.correlation_id.map(|x| x.to_string())),
        ),
        r("DetectedDateTime", date(d.detected, DtKind::Utc)),
        r("DetectionTimingType", s(d.timing.clone())),
        r("IPAddress", opt(d.ip.map(|ip| ip.to_string()))),
        r("Id", s(d.id.clone())),
        r("LastUpdatedDateTime", date(d.updated, DtKind::Utc)),
        r(
            "Location",
            match &d.location {
                Some(l) => model("MicrosoftGraphSignInLocation", graph_location(l)),
                None => Val::Null,
            },
        ),
        r("RequestId", opt(d.request_id.map(|x| x.to_string()))),
        r("RiskDetail", s(d.detail.clone())),
        r("RiskEventType", s(d.event_type.clone())),
        r("RiskLevel", s(d.level.clone())),
        r("RiskState", s(d.state.clone())),
        r("Source", s(d.source.clone())),
        r("TokenIssuerType", s(d.token_issuer_type.clone())),
        r("UserDisplayName", s(d.user_display.clone())),
        r("UserId", s(d.user_id.to_string())),
        r("UserPrincipalName", s(d.user.clone())),
        r("AdditionalProperties", additional_properties()),
    ]
}

/// `Convert-HawkRiskData`: every property but `AdditionalInfo`, then one
/// `AdditionalInfo_<Key>` per item (arrays joined with `|`).
fn converted_risk_row(d: &crate::events::RiskDetection) -> Row {
    let mut row: Row = risk_detection_row(d)
        .into_iter()
        .filter(|(k, _)| k != "AdditionalInfo")
        .collect();
    if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&d.additional_info) {
        for item in items {
            let Some(key) = item.get("Key").and_then(Value::as_str) else {
                continue;
            };
            let v = match item.get("Value") {
                Some(Value::Array(a)) => s(a
                    .iter()
                    .map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_string))
                    .collect::<Vec<_>>()
                    .join("|")),
                Some(Value::String(t)) => s(t.clone()),
                Some(Value::Null) | None => Val::Null,
                Some(other) => s(other.to_string()),
            };
            let name = format!("AdditionalInfo_{key}");
            match row.iter_mut().find(|(k, _)| *k == name) {
                Some(slot) => slot.1 = v,
                None => row.push((name, v)),
            }
        }
    }
    row
}

/// Get-HawkTenantRiskDetections (H10, H11).
fn risk_detections(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let world = c.world;
    c.log()
        .action("Initiating collection of Risk Detection events from Entra ID.");
    c.omft.created("Tenant");
    c.log().action("Retrieving risk detections");
    c.log().tick(1, 3);
    if !world.licence.p2() {
        c.log()
            .error(format!("Error retrieving risk detections: {P2_REFUSED}"));
        c.log()
            .info("Completed collection of Risk Detection events from Entra ID.");
        return Ok(());
    }
    let dets = world.risk_detections();
    if dets.is_empty() {
        c.log().info("No risk detections found");
        c.log()
            .info("Completed collection of Risk Detection events from Entra ID.");
        return Ok(());
    }
    c.log()
        .info(format!("Total risk detections found: {}", dets.len()));
    let converted: Vec<Row> = dets.iter().map(converted_risk_row).collect();
    let original: Vec<Row> = dets.iter().map(risk_detection_row).collect();
    let key = |i: usize| Some(keys::risk(&dets[i].id));
    let ev = |i: usize| Some(Evidence::Risk(dets[i].id.clone()));
    let w = c.omft.write(
        tree,
        "Risk_Detections",
        None,
        Art::raw("hawk.tenant.risk_detections"),
        &converted,
        Formats::CSV,
        false,
        false,
    )?;
    register(tree, &w, "risk_detections", key, ev);
    let w = c.omft.write(
        tree,
        "Risk_Detections",
        None,
        Art::raw("hawk.tenant.risk_detections"),
        &original,
        Formats::JSON,
        false,
        false,
    )?;
    register(tree, &w, "risk_detections", key, ev);
    for (name, n) in level_groups(dets.iter().map(|d| d.level.as_str())) {
        c.log().info(format!(
            "- {n} Risk Detections at Risk Level '{}'",
            capitalized(&name)
        ));
    }
    let confirmed: Vec<Row> = dets
        .iter()
        .zip(&converted)
        .filter(|(d, _)| d.state.eq_ignore_ascii_case("confirmedCompromised"))
        .map(|(_, r)| r.clone())
        .collect();
    let at_level = |d: &crate::events::RiskDetection, l: &str| d.level.eq_ignore_ascii_case(l);
    let other: Vec<(&crate::events::RiskDetection, &Row)> = dets
        .iter()
        .zip(&converted)
        .filter(|(d, _)| {
            !d.state.eq_ignore_ascii_case("confirmedCompromised")
                && ["high", "medium", "low"].iter().any(|l| at_level(d, l))
        })
        .collect();
    if !confirmed.is_empty() {
        c.log().notice(format!(
            "Found {} confirmed compromised risk detections",
            confirmed.len()
        ));
        c.log()
            .notice("Details in _Investigate_Confirmed_Compromised_Risk_Detection files");
        let w = c.omft.write(
            tree,
            "_Investigate_Confirmed_Compromised_Risk_Detection",
            None,
            Art::raw("hawk.investigate_file"),
            &confirmed,
            Formats::CSV_JSON,
            false,
            true,
        )?;
        register_flags(tree, &w);
    }
    if !other.is_empty() {
        let n = |l: &str| other.iter().filter(|(d, _)| at_level(d, l)).count();
        c.log().notice(format!(
            "Found risk detections: {} High, {} Medium, {} Low",
            n("high"),
            n("medium"),
            n("low")
        ));
        c.log()
            .notice("Details in _Investigate_Risk_Detection.csv/json");
        let rows: Vec<Row> = other.iter().map(|(_, r)| (*r).clone()).collect();
        let w = c.omft.write(
            tree,
            "_Investigate_Risk_Detection",
            None,
            Art::raw("hawk.investigate_file"),
            &rows,
            Formats::CSV_JSON,
            false,
            true,
        )?;
        register_flags(tree, &w);
    }
    c.log()
        .info("Completed collection of Risk Detection events from Entra ID.");
    Ok(())
}

/// Get-HawkTenantEntraIDAdmin: the activated directory roles and their active members
/// (`No Members` for a role with none).
fn entra_admins(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let world = c.world;
    c.log()
        .action("Initiating collection of Microsoft Entra ID Administrators from Microsoft Graph.");
    let now = world.collected_at();
    let mut roles: Vec<String> = Vec::new();
    for a in &world.roles {
        if !roles.contains(&a.role) {
            roles.push(a.role.clone());
        }
    }
    c.log()
        .info(format!("Retrieved {} directory roles", roles.len()));
    let mut rows = Vec::new();
    let mut keys_: Vec<String> = Vec::new();
    for role in &roles {
        let members: Vec<&User> = world
            .roles
            .iter()
            .filter(|a| &a.role == role && a.kind != "PIM Eligible")
            .filter(|a| a.start.is_none_or(|t| t <= now) && a.end.is_none_or(|t| t > now))
            .filter_map(|a| world.user_by_upn(&a.principal))
            .collect();
        if members.is_empty() {
            rows.push(vec![
                r("AdminGroupName", s(role.clone())),
                r("Members", s("No Members")),
                r("MemberType", s("None")),
                r("ObjectId", Val::Null),
            ]);
            keys_.push(keys::role("entra_directory", role, ""));
        }
        for m in members {
            rows.push(vec![
                r("AdminGroupName", s(role.clone())),
                r("Members", s(m.upn.clone())),
                r("MemberType", s("User")),
                r("ObjectId", s(m.object_id.to_string())),
            ]);
            keys_.push(keys::role("entra_directory", role, &m.upn));
        }
    }
    if rows.is_empty() {
        c.log().info("Get-HawkTenantEntraID completed");
        c.log().action("No administrator roles found or accessible");
    } else {
        let w = c.omft.write(
            tree,
            "EntraIDAdministrators",
            None,
            Art::raw("hawk.tenant.entra_admins"),
            &rows,
            Formats::CSV_JSON,
            false,
            false,
        )?;
        register(
            tree,
            &w,
            "role_assignments",
            |i| Some(keys_[i].clone()),
            |_| None,
        );
        c.log()
            .info("Successfully exported Microsoft Entra ID Administrators data");
    }
    c.log()
        .info("Completed collection of Microsoft Entra ID Administrators from Microsoft Graph.");
    Ok(())
}

/// Get-HawkTenantAppAndSPNCredentialDetail: one appended CSV row per credential
/// (Out-MultipleFileType) and one JSON array per file (`ConvertTo-Json | Out-File`, into the
/// plain `Tenant` folder). Hawk 3.1 appends the JSON per credential too, so its files are
/// concatenated objects (capture survey §2d). Service principals and applications sorted by
/// display name, key credentials before password credentials.
pub(super) fn credentials(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    // Progress lines are Hawk 4.0 wording (`*_v4`: not logged by Hawk 3). Hawk 3 keeps the
    // notices, which feed `_Investigate.txt`; source-derived (no 3.1 source): their wording.
    let world = c.world;
    let v3 = c.omft.version == HawkVersion::V3;
    let per_record = if v3 { Formats::CSV_JSON } else { Formats::CSV };
    c.log()
        .action_v4("Initiating collection of application and service principal credentials.");
    c.omft.created("Tenant");
    c.log().action_v4("Collecting Entra ID Service Principals");
    c.log()
        .action_v4("Collecting Entra ID Registered Applications");
    let mut apps: Vec<&crate::world::App> = world.apps.iter().collect();
    apps.sort_by_key(|a| a.display_name.to_lowercase());
    for (label, prefix, on_sp) in [
        (
            "Exporting Service Principal Certificate and Password details",
            "SPNCertsAndSecrets",
            true,
        ),
        (
            "Exporting Registered Applications Certificate and Password details",
            "ApplicationCertsAndSecrets",
            false,
        ),
    ] {
        c.log().action_v4(label);
        let mut rows: Vec<Row> = Vec::new();
        let mut keyed: Vec<(String, Evidence)> = Vec::new();
        for app in &apps {
            let object_id = if on_sp {
                app.sp_object_id
            } else {
                app.object_id
            };
            let creds = app
                .credentials
                .iter()
                .filter(|k| k.on_service_principal == on_sp);
            let (certs, passwords): (Vec<_>, Vec<_>) =
                creds.partition(|k| k.kind == CredKind::Certificate);
            for k in certs.into_iter().chain(passwords) {
                let cert = k.kind == CredKind::Certificate;
                let row = vec![
                    r("AppName", s(app.display_name.clone())),
                    r("AppObjectID", s(object_id.to_string())),
                    r("KeyID", s(k.key_id.to_string())),
                    r("StartDate", date(k.start, DtKind::Utc)),
                    r("EndDate", date(k.end, DtKind::Utc)),
                    r(
                        "KeyType",
                        if cert {
                            s("AsymmetricX509Cert")
                        } else {
                            Val::Null
                        },
                    ),
                    r(
                        "CredType",
                        s(if cert {
                            "X509Certificate"
                        } else {
                            "PasswordSecret"
                        }),
                    ),
                ];
                let w = c.omft.write(
                    tree,
                    prefix,
                    None,
                    Art::raw("hawk.tenant.app_credentials"),
                    std::slice::from_ref(&row),
                    per_record,
                    true,
                    false,
                )?;
                let key = keys::app_credential(object_id, k.key_id);
                let ev = Evidence::Credential {
                    app_object_id: app.object_id,
                    key_id: k.key_id,
                    on_service_principal: on_sp,
                };
                register(
                    tree,
                    &w,
                    "app_credentials",
                    |_| Some(key.clone()),
                    |_| Some(ev.clone()),
                );
                rows.push(row);
                keyed.push((key, ev));
            }
        }
        if !rows.is_empty() && !v3 {
            let w = write_direct(
                c,
                tree,
                prefix,
                Art::raw("hawk.tenant.app_credentials"),
                &rows,
                true,
                false,
            )?;
            register(
                tree,
                &w,
                "app_credentials",
                |i| Some(keyed[i].0.clone()),
                |i| Some(keyed[i].1.clone()),
            );
        }
    }
    c.log().info_v4(
        "Completed collection of application and service principal credentials from Microsoft Graph.",
    );
    Ok(())
}

/// Get-HawkTenantEntraIDUser: every user, sorted by UPN.
fn entra_users(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let world = c.world;
    c.log()
        .action("Initiating collection of users from Entra ID.");
    let mut people: Vec<&User> = world.all_people().collect();
    people.sort_by_key(|u| u.upn.to_lowercase());
    let rows: Vec<Row> = people
        .iter()
        .map(|u| {
            vec![
                r("UserPrincipalName", s(u.upn.clone())),
                r("DisplayName", s(u.display_name.clone())),
                r("Id", s(u.object_id.to_string())),
                r("AccountEnabled", Val::Bool(true)),
                r("CreatedDateTime", date(u.created, DtKind::Utc)),
                r("DeletedDateTime", Val::Null),
                r(
                    "LastPasswordChangeDateTime",
                    date(u.last_password_change, DtKind::Utc),
                ),
                r("Mail", s(u.upn.clone())),
            ]
        })
        .collect();
    let w = c.omft.write(
        tree,
        "EntraIDUsers",
        None,
        Art::raw("hawk.tenant.entra_users"),
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
    c.log().info("Completed collection of users from Entra ID.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::load;

    #[test]
    fn licence_tier_follows_test_license_type() {
        let tier = |scenario: &str| {
            let w = World::build(&load(scenario).unwrap(), 1).unwrap();
            licence_tier(&w)
        };
        assert_eq!(tier("bec-aitm"), ("E5", 365)); // SPE_E5
        assert_eq!(tier("hawk-investigate"), ("E5", 365)); // ENTERPRISEPREMIUM
        assert_eq!(tier("bec-o365-no-p1"), ("E3", 180)); // ENTERPRISEPACK
        // SPE_E3 is not in Hawk's E3 list.
        assert_eq!(tier("bec-e3-audit-gaps"), ("Unknown", 90));
        assert_eq!(tier("business-basic"), ("Unknown", 90));
    }

    #[test]
    fn admin_rule_test_flags_delete_message_false_like_hawk() {
        let row = |k: &str, v: Val| -> Row { vec![r("Operation", s("New-InboxRule")), r(k, v)] };
        assert!(suspicious_admin_rule(&row(
            "Param_DeleteMessage",
            s("False")
        )));
        assert!(suspicious_admin_rule(&row(
            "Param_ForwardTo",
            s("x@fabrikam.test")
        )));
        assert!(suspicious_admin_rule(&row(
            "Param_MoveToFolder",
            s("deleted items")
        )));
        assert!(!suspicious_admin_rule(&row(
            "Param_MoveToFolder",
            s("Vendors")
        )));
        assert!(!suspicious_admin_rule(&row("Param_RedirectTo", s(""))));
        assert!(!suspicious_admin_rule(&row("Param_RedirectTo", Val::Null)));
    }

    fn grant(permission: &str, consent_type: Option<&str>) -> GrantRow {
        GrantRow {
            row: vec![
                r("Permission", s(permission)),
                r("ConsentGrantRiskCategory", s("")),
            ],
            key: String::new(),
            evidence: None,
            consent_type: consent_type.map(str::to_string),
            permission: permission.to_string(),
        }
    }

    #[test]
    fn consent_categories_last_match_wins_and_counts_per_pattern() {
        let mut g = vec![
            grant("User.Read", Some("AllPrincipals")),
            grant("AppRoleAssignment.ReadWrite.All", None),
            grant("Calendars.Read", Some("Principal")),
            grant("Mail.Send", Some("Principal")),
            grant("offline_access", Some("Principal")),
        ];
        let counts = categorize(&mut g);
        // Broad: the AllPrincipals grant and the permission containing "All".
        assert_eq!(counts, (2, 1, 2));
        let cat = |i: usize| text_of(&g[i].row, "ConsentGrantRiskCategory").unwrap_or_default();
        assert_eq!(cat(0), "High Risk", "^User\\. overwrites Broad-Scope");
        assert_eq!(cat(1), "Extremely Dangerous");
        assert_eq!(cat(2), "");
        assert_eq!(cat(3), "High Risk");
        assert_eq!(cat(4), "");
    }

    #[test]
    fn risk_levels_group_high_medium_low_none() {
        let groups = level_groups(["low", "none", "High", "low", "medium"].into_iter());
        assert_eq!(
            groups,
            vec![
                ("High".to_string(), 1),
                ("medium".to_string(), 1),
                ("low".to_string(), 2),
                ("none".to_string(), 1),
            ]
        );
    }
}
