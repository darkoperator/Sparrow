//! Synthetic Hawk 4.x and 3.x captures holding the Phase 2b identity, configuration and
//! state artifacts, in the encodings real captures use. Invented tenant, users, ids and
//! addresses only.

use crate::fixtures::{csv_line, ps_json, ps51_dates, ual, utf8_bom, utf16le_bom, write};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub const ALICE: &str = "alice@contoso.example";
pub const BOB: &str = "bob@contoso.example";
pub const ALICE_ID: &str = "11111111-1111-4111-8111-111111111111";
pub const BOB_ID: &str = "22222222-2222-4222-8222-222222222222";
pub const CAROL_ID: &str = "66666666-6666-4666-8666-666666666666";
pub const APP_ID: &str = "33333333-3333-4333-8333-333333333333";
pub const GRAPH_ID: &str = "44444444-4444-4444-8444-444444444444";
pub const DETECTION_ID: &str = "55555555-5555-4555-8555-555555555555";
pub const HAWK4_STATE_STAMP: &str = "20260920_090000";
pub const HAWK3_STATE_ROOT: &str = "capture-hawk3-state";

/// Format-List of one object as Out-File writes it: names padded, blank lines around.
fn format_list(fields: &[(&str, &str)]) -> String {
    let width = fields.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut s = String::from("\r\n\r\n");
    for (k, v) in fields {
        s.push_str(&format!("{k:<width$} : {v}\r\n"));
    }
    s.push_str("\r\n\r\n");
    s
}

fn inbox_rule(owner: &str, identity: u64, name: &str, forward: bool) -> Value {
    json!({
        "Description": "If the message:\r\n\tincludes 'invoice' in the subject or body\r\n",
        "Enabled": true, "Identity": format!("{owner}\\{identity}"), "InError": false, "Name": name,
        "Priority": 1, "RuleIdentity": identity, "BodyContainsWords": [], "From": null,
        "HasAttachment": false, "SubjectContainsWords": [],
        "SubjectOrBodyContainsWords": if forward { json!(["invoice", "payment"]) } else { json!([]) },
        "CopyToFolder": null, "DeleteMessage": forward,
        "ForwardAsAttachmentTo": null,
        "ForwardTo": if forward { json!(["\"x\" [SMTP:x@fabrikam.example]"]) } else { Value::Null },
        "MarkAsRead": false, "MoveToFolder": if forward { Value::Null } else { json!("RSS Feeds") },
        "RedirectTo": null, "SoftDeleteMessage": false, "StopProcessingRules": forward,
        "MailboxOwnerId": owner
    })
}

fn role_assignment(role: &str, assignee: &str, kind: &str, user: &str, created: &str) -> Value {
    json!({
        "DataObject": null, "User": user, "AssignmentMethod": "Direct",
        "Identity": format!("{role}-{assignee}"), "EffectiveUserName": user, "RoleAssigneeType": kind,
        "RoleAssignee": assignee, "Role": role, "RoleAssignmentDelegationType": "Regular",
        "Enabled": true, "RoleAssigneeName": assignee, "Name": format!("{role}-{assignee}"),
        "WhenCreatedUTC": created
    })
}

fn credential(app: &str, key: &str, cert: bool, start: &str, end: &str) -> Value {
    json!({
        "AppName": if app == APP_ID { "Mail Helper" } else { "Contoso Sync" }, "AppObjectID": app,
        "KeyID": key, "StartDate": start, "EndDate": end,
        "KeyType": if cert { json!("AsymmetricX509Cert") } else { Value::Null },
        "CredType": if cert { "X509Certificate" } else { "PasswordSecret" }
    })
}

fn grant(permission: &str, principal: Option<&str>, risk: &str) -> Value {
    json!({
        "PermissionType": "Delegated", "ClientObjectId": APP_ID, "ClientDisplayName": "Mail Helper",
        "ResourceObjectId": GRAPH_ID, "ResourceDisplayName": "Microsoft Graph", "Permission": permission,
        "ConsentType": if principal.is_some() { "Principal" } else { "AllPrincipals" },
        "PrincipalObjectId": principal, "PrincipalDisplayName": principal.map(|_| "Alice"),
        "ConsentGrantRiskCategory": risk
    })
}

const MAILBOX_INFO: &str = concat!(
    "\r\n\r\n",
    "Alias                     : alice\r\n",
    "DisplayName               : Alice\r\n",
    "EmailAddresses            : {SMTP:alice@contoso.example, smtp:alice@contoso.onmicrosoft.example,\r\n",
    "                            SIP:alice@contoso.example}\r\n",
    "ExternalDirectoryObjectId : 11111111-1111-4111-8111-111111111111\r\n",
    "Guid                      : 99999999-9999-4999-8999-999999999999\r\n",
    "PrimarySmtpAddress        : alice@contoso.example\r\n",
    "RecipientType             : UserMailbox\r\n",
    "RecipientTypeDetails      : UserMailbox\r\n",
    "UserPrincipalName         : alice@contoso.example\r\n",
    "\r\n\r\n",
);

const AUTO_REPLY: &str = concat!(
    "\r\n\r\n",
    "AutoReplyState   : Enabled\r\n",
    "EndTime          : 9/30/2026 5:00:00 PM\r\n",
    "ExternalAudience : All\r\n",
    "ExternalMessage  : <html><body>Out of office\r\n",
    "                   until October.</body></html>\r\n",
    "\r\n",
    "InternalMessage  : <html><body>Away\r\n",
    "\r\n",
    "                   back soon</body></html>\r\n",
    "StartTime        : 9/24/2026 8:00:00 AM\r\n",
    "MailboxOwnerId   : alice\r\n",
    "\r\n\r\n",
);

const ADMIN_AUDIT_LOG_CONFIG_H3: &str = concat!(
    "\r\n\r\n",
    "AdminAuditLogAgeLimit           : 90.00:00:00\r\n",
    "AdminAuditLogCmdlets            : {*}\r\n",
    "AdminAuditLogEnabled            : True\r\n",
    "AdminAuditLogExcludedCmdlets    : {Set-MailboxAuditBypassAssociation, New-MailboxAuditBypass\r\n",
    "                                  , Set-Foo}\r\n",
    "LogLevel                        : None\r\n",
    "UnifiedAuditLogIngestionEnabled : True\r\n",
    "\r\n\r\n",
);

pub fn hawk4_state_tree(base: &Path) -> PathBuf {
    hawk4_state_tree_at(base, HAWK4_STATE_STAMP, "smtp:x@fabrikam.example")
}

/// Hawk 4.x capture `Hawk_Contoso_Ltd_<stamp>`: Tenant/ written by PowerShell 7 (UTF-8, ISO
/// dates), the user folder by Windows PowerShell 5.1 (UTF-8 BOM JSON with `\/Date(ms)\/`,
/// UTF-16LE TXT). `forwarding` is alice's ForwardingSmtpAddress.
pub fn hawk4_state_tree_at(base: &Path, stamp: &str, forwarding: &str) -> PathBuf {
    let root = base.join(format!("Hawk_Contoso_Ltd_{stamp}"));
    let tenant =
        |rel: &str, v: &Value| write(&root, &format!("Tenant/{rel}"), ps_json(v).as_bytes());
    let user = |rel: &str, bytes: &[u8]| write(&root, &format!("{ALICE}/{rel}"), bytes);
    let ps51 = |v: &Value| utf8_bom(&ps51_dates(&ps_json(v)));

    write(
        &root,
        "Hawk.log",
        &utf16le_bom("[2026-09-20 09:00:00Z] - [INFO]   - Hawk Version: 4.0\r\n"),
    );
    write(
        &root,
        "_Investigate.txt",
        format!(
            "[2026-09-20 09:05:00Z] - [INVESTIGATE] - Found 1 inbox rules requiring investigation for {ALICE}\r\n\
             [2026-09-20 09:05:01Z] - [INVESTIGATE] - Additional Information: C:\\Hawk\\Hawk_Contoso_Ltd_{stamp}\\{ALICE}\\_Investigate_InboxRules_alice.json\r\n"
        )
        .as_bytes(),
    );

    tenant(
        "EntraIDUsers.json",
        &json!([
            {"UserPrincipalName": ALICE, "DisplayName": "Alice", "Id": ALICE_ID, "AccountEnabled": true,
             "CreatedDateTime": "2025-01-15T08:00:00Z", "DeletedDateTime": null,
             "LastPasswordChangeDateTime": "2026-09-18T07:30:00Z", "Mail": ALICE},
            {"UserPrincipalName": BOB, "DisplayName": "Bob", "Id": BOB_ID, "AccountEnabled": true,
             "CreatedDateTime": "2025-02-01T08:00:00Z", "DeletedDateTime": null,
             "LastPasswordChangeDateTime": null, "Mail": BOB}
        ]),
    );
    write(
        &root,
        "Tenant/EntraIDUsers.csv",
        (csv_line(&[
            "UserPrincipalName",
            "DisplayName",
            "Id",
            "AccountEnabled",
            "CreatedDateTime",
        ]) + &csv_line(&[ALICE, "Alice", ALICE_ID, "True", "1/15/2025 8:00:00 AM"])
            + &csv_line(&[BOB, "Bob", BOB_ID, "True", "2/1/2025 8:00:00 AM"]))
            .as_bytes(),
    );
    tenant(
        "EntraIDAdministrators.json",
        &json!([
            {"AdminGroupName": "Global Administrator", "Members": ALICE, "MemberType": "User", "ObjectId": ALICE_ID},
            {"AdminGroupName": "Exchange Administrator", "Members": "No Members", "MemberType": "None", "ObjectId": null},
            {"AdminGroupName": "Application Administrator", "Members": "Contoso Sync",
             "MemberType": "servicePrincipal", "ObjectId": APP_ID}
        ]),
    );
    tenant(
        "ExchangeOnlineAdministrators.json",
        &json!([
            {"ExchangeAdminGroup": "Organization Management", "Members": ALICE, "RecipientType": "UserMailbox"}
        ]),
    );
    tenant(
        "CustomEDiscoveryRoles.json",
        &json!([role_assignment(
            "Mailbox Search",
            "Discovery Management",
            "RoleGroup",
            "Discovery Management",
            "2026-09-01T08:00:00Z"
        )]),
    );
    tenant(
        "EDiscoveryRoles.json",
        &json!([
            {"Name": "New-MailboxSearch", "Role": "Mailbox Search", "Type": "Cmdlet",
             "Parameters": ["Name", "SourceMailboxes"], "Identity": "Mailbox Search\\New-MailboxSearch"},
            {"Name": "New-ComplianceSearch", "Role": "Mailbox Search", "Type": "Cmdlet",
             "Parameters": [], "Identity": "Mailbox Search\\New-ComplianceSearch"}
        ]),
    );
    let risky_grant = grant("Mail.Read", Some(ALICE_ID), "High Risk");
    tenant(
        "Consent_Grants.json",
        &json!([risky_grant.clone(), grant("User.Read", None, "")]),
    );
    tenant("_Investigate_Consent_Grants.json", &risky_grant);
    tenant(
        "ApplicationCertsAndSecrets.json",
        &json!([credential(
            APP_ID,
            "aaaaaaaa-0000-4000-8000-000000000001",
            false,
            "2026-09-15T10:00:00Z",
            "2027-09-15T10:00:00Z"
        )]),
    );
    tenant(
        "SPNCertsAndSecrets.json",
        &json!([credential(
            GRAPH_ID,
            "bbbbbbbb-0000-4000-8000-000000000001",
            true,
            "2026-01-01T00:00:00Z",
            "2028-01-01T00:00:00Z"
        )]),
    );
    let risky = json!({
        "Id": ALICE_ID, "IsDeleted": false, "IsProcessing": false, "RiskDetail": "none",
        "RiskLastUpdatedDateTime": "2026-09-01T10:05:00Z", "RiskLevel": "high", "RiskState": "atRisk",
        "UserDisplayName": "Alice", "UserPrincipalName": ALICE, "History": null, "AdditionalProperties": {}
    });
    tenant("RiskyUsers.json", &risky);
    tenant("_Investigate_Risky_Users.json", &risky);
    tenant(
        "Risk_Detections.json",
        &json!({
            "Activity": "signin", "ActivityDateTime": "2026-09-01T09:58:00Z",
            "AdditionalInfo": "[{\"Key\":\"userAgent\",\"Value\":\"python-requests/2.31\"}]",
            "CorrelationId": "c0000000-0000-4000-8000-00000000000c", "DetectedDateTime": "2026-09-01T10:00:00Z",
            "DetectionTimingType": "realtime", "Id": DETECTION_ID, "IPAddress": "203.0.113.50",
            "LastUpdatedDateTime": "2026-09-01T10:05:00Z",
            "Location": {"City": "Lisbon", "CountryOrRegion": "PT", "State": "Lisboa",
                         "GeoCoordinates": {"Altitude": null, "Latitude": 38.7, "Longitude": -9.1}},
            "RequestId": "r0000000-0000-4000-8000-00000000000r", "RiskDetail": "none",
            "RiskEventType": "anonymizedIPAddress", "RiskLevel": "high", "RiskState": "atRisk",
            "Source": "IdentityProtection", "TokenIssuerType": "AzureAD", "UserDisplayName": "Alice",
            "UserId": ALICE_ID, "UserPrincipalName": ALICE, "AdditionalProperties": {}
        }),
    );
    write(
        &root,
        "Tenant/Risk_Detections.csv",
        (csv_line(&[
            "Id",
            "RiskLevel",
            "DetectedDateTime",
            "Location",
            "AdditionalInfo_userAgent",
        ]) + &csv_line(&[
            DETECTION_ID,
            "high",
            "9/21/2026 10:00:00 AM",
            "Microsoft.Graph.PowerShell.Models.MicrosoftGraphSignInLocation",
            "python-requests/2.31",
        ]))
            .as_bytes(),
    );
    write(
        &root,
        "Tenant/AdminAuditLogConfig.txt",
        format_list(&[
            ("AdminAuditLogAgeLimit", "90.00:00:00"),
            ("AdminAuditLogEnabled", "True"),
            ("LogLevel", "None"),
            ("Name", "Admin Audit Log Settings"),
            ("UnifiedAuditLogIngestionEnabled", "False"),
        ])
        .as_bytes(),
    );
    write(
        &root,
        "Tenant/OrgConfig.txt",
        format_list(&[
            ("AuditDisabled", "False"),
            ("MailTipsAllTipsEnabled", "True"),
            ("Name", "Contoso"),
        ])
        .as_bytes(),
    );
    tenant(
        "TransportConfig.json",
        &json!({
            "SmtpClientAuthenticationDisabled": true, "ExternalDelayDsnEnabled": false,
            "TransportRuleMinProductVersion": {"Major": 15, "Minor": 0}
        }),
    );
    tenant(
        "TransportRules.json",
        &json!([{
            "Name": "External redirect", "Guid": "88888888-8888-4888-8888-888888888888", "State": "Enabled",
            "Mode": "Enforce", "Priority": 0, "CreatedBy": "Admin", "LastModifiedBy": "Admin",
            "WhenChanged": "2026-09-01T12:00:00+02:00",
            "Description": "Redirect the message to 'x@fabrikam.example'",
            "Conditions": ["Microsoft.Exchange.MessagingPolicies.Rules.Tasks.SentToPredicate"],
            "Exceptions": null,
            "Actions": ["Microsoft.Exchange.MessagingPolicies.Rules.Tasks.RedirectMessageAction"],
            "RedirectMessageTo": ["x@fabrikam.example"], "BlindCopyTo": null, "CopyTo": null,
            "AddToRecipients": null, "RuleVersion": {"Major": 15, "Minor": 0, "Build": 5, "Revision": 0}
        }]),
    );
    tenant(
        "RemoteDomain.json",
        &json!({
            "DomainName": "*", "Name": "Default", "AutoForwardEnabled": true, "AllowedOOFType": "External",
            "WhenChanged": "2026-09-01T10:00:00Z"
        }),
    );
    let raw_rule = ual::raw_record(
        "ExchangeAdmin",
        "2026-09-01T10:00:05",
        "New-InboxRule",
        &ual::rule(),
    );
    tenant(
        "Admin_Inbox_Rules_Creation.json",
        &json!([raw_rule.clone()]),
    );
    tenant("_Investigate_Admin_Inbox_Rules_Creation.json", &raw_rule);

    let forwarding_report = ps51(&json!({
        "DisplayName": "Alice", "UserPrincipalName": ALICE, "PrimarySmtpAddress": ALICE,
        "ForwardingSmtpAddress": forwarding, "ForwardingAddress": null,
        "DeliverToMailboxAndForward": false, "WhenChangedUTC": "/Date(1788343200000)/"
    }));
    write(
        &root,
        "Tenant/User_ForwardingReport.json",
        &forwarding_report,
    );
    user("ForwardingReport_alice.json", &forwarding_report);
    let forward_rule = inbox_rule("alice", 1111, ".", true);
    user(
        "InboxRules_alice.json",
        &ps51(&json!([
            forward_rule.clone(),
            inbox_rule("alice", 2222, "Newsletters", false)
        ])),
    );
    user("_Investigate_InboxRules_alice.json", &ps51(&forward_rule));
    user(
        "SweepRules_alice.json",
        &ps51(&json!({
            "Name": "Old bank mail", "RuleId": "sweep-1", "Enabled": true, "SourceFolder": "alice:\\Inbox",
            "DestinationFolder": "alice:\\Deleted Items", "Sender": "\"Bank\" [SMTP:bank@fabrikam.example]",
            "KeepForDays": 3, "MailboxOwnerId": "alice", "Identity": "alice\\sweep-1"
        })),
    );
    let device = json!({
        "FriendlyName": "", "DeviceId": "ABCDEF0123456789", "DeviceOS": "iOS 19.0", "DeviceType": "iPhone",
        "DeviceUserAgent": "Apple-iPhone17C1/2301.1", "DeviceModel": "iPhone17C1",
        "FirstSyncTime": "/Date(1788256800000)/", "UserDisplayName": "Alice",
        "DeviceAccessState": "Allowed", "DeviceAccessStateReason": "Global", "ClientType": "EAS",
        "IsManaged": false, "IsCompliant": false, "IsDisabled": false,
        "WhenCreatedUTC": "/Date(1788256800000)/",
        "Identity": "alice\\ExchangeActiveSyncDevices\\iPhone-ABCDEF0123456789"
    });
    user("MobileDevices_alice.json", &ps51(&device));
    user("_Investigate_MobileDevice_alice.json", &ps51(&device));
    user("Mailbox_Info_alice.txt", &utf16le_bom(MAILBOX_INFO));
    user(
        "CAS_Mailbox_Info_alice.txt",
        &utf16le_bom(&format_list(&[
            ("ActiveSyncEnabled", "True"),
            ("DisplayName", "Alice"),
            ("EwsEnabled", "True"),
            ("ImapEnabled", "False"),
            ("MAPIEnabled", "True"),
            ("OWAEnabled", "True"),
            ("PopEnabled", "True"),
            ("PrimarySmtpAddress", ALICE),
        ])),
    );
    user("AutoReply_alice.txt", &utf16le_bom(AUTO_REPLY));
    root
}

/// Hawk 3.1.0 capture from Windows PowerShell 5.1: JSON/TXT/log UTF-16LE with BOM and
/// `\/Date(ms)\/`, CSV UTF-8 with BOM and culture dates. Folder name is not `Hawk_<t>_<ts>`.
pub fn hawk3_state_tree(base: &Path) -> PathBuf {
    let root = base.join(HAWK3_STATE_ROOT);
    let json16 = |rel: &str, v: &Value| write(&root, rel, &utf16le_bom(&ps51_dates(&ps_json(v))));
    let csv8 = |rel: &str, text: &str| write(&root, rel, &utf8_bom(text));

    write(
        &root,
        "Hawk.log",
        &utf16le_bom("[9/24/2026 2:15:00 PM] - *** Version 3.1.0 ***\r\n"),
    );
    write(
        &root,
        "_Investigate.txt",
        &utf16le_bom(&format!(
            "[9/24/2026 2:20:00 PM] - ## Impersonation ## - Found accounts with ApplicationImpersonation rights\r\n\
             Additional Information: C:\\Hawk\\{HAWK3_STATE_ROOT}\\Tenant\\_Investigate_Impersonation_Rights.csv\r\n"
        )),
    );
    json16(
        "Tenant/AzureADUsers.json",
        &json!([
            {"UserPrincipalname": BOB, "ObjectID": BOB_ID, "UserType": "Member",
             "DateCreated": "9/24/2025 8:00:00 AM", "UserStateChangedOn": null, "DirSyncEnabled": true},
            {"UserPrincipalname": "carol@contoso.example", "ObjectID": CAROL_ID, "UserType": "Guest",
             "DateCreated": null, "UserStateChangedOn": "2026-09-02T10:00:00Z", "DirSyncEnabled": null}
        ]),
    );
    csv8(
        "Tenant/AzureADUsers.csv",
        &(csv_line(&[
            "UserPrincipalname",
            "ObjectID",
            "UserType",
            "DateCreated",
            "UserStateChangedOn",
            "DirSyncEnabled",
        ]) + &csv_line(&[BOB, BOB_ID, "Member", "9/24/2025 8:00:00 AM", "", "True"])),
    );
    json16(
        "Tenant/AzureADAdministrators.json",
        &json!([{"AdminGroupName": "Company Administrator", "Members": BOB}]),
    );
    json16(
        "Tenant/EDiscoveryRoleAssignments.json",
        &json!([role_assignment(
            "Mailbox Search",
            "Discovery Management",
            "RoleGroup",
            "Discovery Management",
            "/Date(1788256800000)/"
        )]),
    );
    let impersonation = utf16le_bom(&ps51_dates(&ps_json(&role_assignment(
        "ApplicationImpersonation",
        "svc-sync",
        "User",
        "svc-sync@contoso.example",
        "/Date(1788433200000)/",
    ))));
    write(&root, "Tenant/Impersonation_Rights.json", &impersonation);
    write(
        &root,
        "Tenant/_Investigate_Impersonation_Rights.json",
        &impersonation,
    );
    let impersonation_csv = utf8_bom(
        &(csv_line(&[
            "User",
            "Role",
            "RoleAssignee",
            "RoleAssigneeName",
            "RoleAssigneeType",
            "Enabled",
            "WhenCreatedUTC",
        ]) + &csv_line(&[
            "svc-sync@contoso.example",
            "ApplicationImpersonation",
            "svc-sync",
            "svc-sync",
            "User",
            "True",
            "9/3/2026 11:00:00 AM",
        ])),
    );
    write(&root, "Tenant/Impersonation_Rights.csv", &impersonation_csv);
    write(
        &root,
        "Tenant/_Investigate_Impersonation_Rights.csv",
        &impersonation_csv,
    );
    json16(
        "Tenant/Impersonation_Roles.json",
        &json!({
            "Name": "*", "Role": "ApplicationImpersonation", "Type": "Cmdlet", "Parameters": [],
            "Identity": "ApplicationImpersonation\\*"
        }),
    );
    let concatenated = format!(
        "{}\r\n{}\r\n",
        ps_json(&credential(
            APP_ID,
            "aaaaaaaa-0000-4000-8000-000000000001",
            false,
            "/Date(1788256800000)/",
            "/Date(1819792800000)/"
        )),
        ps_json(&credential(
            APP_ID,
            "aaaaaaaa-0000-4000-8000-000000000002",
            true,
            "/Date(1788256800000)/",
            "/Date(1819792800000)/"
        )),
    );
    write(
        &root,
        "Tenant/ApplicationCertsAndSecrets.json",
        &utf16le_bom(&ps51_dates(&concatenated)),
    );
    let header = [
        "PermissionType",
        "ClientObjectId",
        "ClientDisplayName",
        "ResourceObjectId",
        "ResourceDisplayName",
        "Permission",
        "ConsentType",
        "PrincipalObjectId",
        "PrincipalDisplayName",
    ];
    csv8(
        "Tenant/Consent_Grants.csv",
        &(csv_line(&header)
            + &csv_line(&[
                "Delegated",
                APP_ID,
                "Mail Helper",
                GRAPH_ID,
                "Microsoft Graph",
                "Mail.Read",
                "Principal",
                BOB_ID,
                "Bob",
            ])
            + &csv_line(&[
                "Application",
                APP_ID,
                "Mail Helper",
                GRAPH_ID,
                "Microsoft Graph",
                "Mail.Send",
                "",
                "",
                "",
            ])),
    );
    let bob_rule = utf16le_bom(&ps_json(&inbox_rule("bob", 3333, "Move", false)));
    write(&root, "Tenant/All_InboxRules.json", &bob_rule);
    write(&root, &format!("{BOB}/InboxRules_bob.json"), &bob_rule);
    write(
        &root,
        "Tenant/AdminAuditLogConfig.txt",
        &utf16le_bom(ADMIN_AUDIT_LOG_CONFIG_H3),
    );
    write(
        &root,
        "Tenant/OrgConfig.txt",
        &utf16le_bom(&format_list(&[
            ("AuditDisabled", "True"),
            ("Name", "Contoso"),
        ])),
    );
    write(
        &root,
        "Tenant/_Investigate_New_InboxRules.txt",
        format_list(&[
            ("ObjectModified", "contoso.example/bob/Move"),
            ("CmdletName", "New-InboxRule"),
            ("CmdletParameters", "{Name, MoveToFolder}"),
            ("Caller", "admin@contoso.example"),
            ("RunDate", "9/24/2026 8:00:00 AM"),
        ])
        .as_bytes(),
    );
    let forwarding = utf8_bom(
        &(csv_line(&[
            "DisplayName",
            "UserPrincipalName",
            "PrimarySmtpAddress",
            "ForwardingSmtpAddress",
            "ForwardingAddress",
            "DeliverToMailboxAndForward",
            "WhenChangedUTC",
        ]) + &csv_line(&["Bob", BOB, BOB, "", "", "False", "9/24/2026 8:00:00 AM"])),
    );
    write(&root, "Tenant/User_ForwardingReport.csv", &forwarding);
    write(
        &root,
        &format!("{BOB}/ForwardingReport_bob.csv"),
        &forwarding,
    );
    write(
        &root,
        &format!("{BOB}/Mailbox_Info_bob.txt"),
        &utf16le_bom(&format_list(&[
            ("DisplayName", "Bob"),
            ("PrimarySmtpAddress", BOB),
            ("RecipientTypeDetails", "SharedMailbox"),
            ("UserPrincipalName", BOB),
        ])),
    );
    json16(
        &format!("{BOB}/MobileDevices_bob.json"),
        &json!({
            "DeviceId": "FEDCBA9876543210", "DeviceType": "Android", "DeviceModel": "Pixel 12",
            "DeviceOS": "Android 17", "DeviceUserAgent": "Android-Mail/2026.09", "ClientType": "EAS",
            "FirstSyncTime": "/Date(1788256800000)/", "DeviceAccessState": "Allowed",
            "IsManaged": false, "IsCompliant": false, "IsDisabled": false
        }),
    );
    root
}
