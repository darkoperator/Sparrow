//! A synthetic Microsoft-Extractor-Suite Output root shaped like a real multi-run collection
//! (docs/superpowers/research/2026-09-25-invictus-sample-survey.md §1): several runs of the
//! same cmdlets, byte-identical repeats, a Merged copy, sign-in pages written in the same
//! second, 0-byte exports, empty run folders, MailItemsAccessed files overlapping the raw
//! UAL, and the nested Mailbox Audit Log UAL run. Invented tenant, users, ids and addresses.

use crate::fixtures::{csv_line, ps_json, utf8_bom, write};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub const INVICTUS_ROOT: &str = "INV_OUTPUT";
pub const ALICE: &str = "alice@contoso.example";
pub const BOB: &str = "bob@contoso.example";
pub const ID_1: &str = "11111111-1111-4111-8111-111111111111";
pub const ID_2: &str = "22222222-2222-4222-8222-222222222222";
pub const ID_3: &str = "33333333-3333-4333-8333-333333333333";
pub const MIA_1: &str = "44444444-4444-4444-8444-444444444444";
pub const S1: &str = "a1a1a1a1-1111-4111-8111-111111111111";
pub const S2: &str = "a2a2a2a2-2222-4222-8222-222222222222";
pub const S3: &str = "a3a3a3a3-3333-4333-8333-333333333333";
pub const AUDIT_1: &str = "Directory_0e0e0e0e-0000-4000-8000-000000000001_ABCDE_1";
pub const TRACE_1: &str = "0e0e0e0e-0000-4000-8000-000000000011";
pub const TRACE_2: &str = "0e0e0e0e-0000-4000-8000-000000000012";
pub const MIA_IP: &str = "2001:db8::10";

pub const UAL_WINDOW: &str =
    "UnifiedAuditLog/20260910-100000/UAL-20260801000000-20260901000000.csv";
pub const UAL_MERGED: &str = "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv";
pub const SIGNIN_PAGE: &str = "EntraID/20260910-100100-SignInLogs/interactiveUser & nonInteractiveUser/20260910100105-interactiveUser-nonInteractiveUser-SignInLogs.json";
pub const SP_PAGE: &str = "EntraID/20260910-100100-SignInLogs/servicePrincipal/20260910100110-servicePrincipal-SignInLogs.json";
pub const AUDIT_PAGE: &str = "EntraID/20260910-100200-AuditLogs/20260910100205-AuditLogs.json";
pub const EMPTY_OAUTH: &str =
    "EntraID/20260910-100300-OAuthPermissions/20260910-100300-OAuthPermissions.csv";
pub const EMPTY_USERS: &str = "Users/20260910-100300/20260910-100300-Users.csv";
pub const STATUS_EARLY: &str =
    "Audit Status/20260910-100400/20260910-100400-MailboxAuditStatus.csv";
pub const STATUS_LATE: &str = "Audit Status/20260910-110400/20260910-110400-MailboxAuditStatus.csv";
pub const PERMS_1: &str =
    "Mailbox Permissions/20260910-100500/20260910-100500-MailboxPermissions.csv";
pub const PERMS_2: &str =
    "Mailbox Permissions/20260910-110500/20260910-110500-MailboxPermissions.csv";
pub const TRACE_FILE_1: &str = "MessageTrace/20260910-100600/20260910-100600-MessageTrace.csv";
pub const TRACE_FILE_2: &str = "MessageTrace/20260910-110600/20260910-110600-MessageTrace.csv";
pub const SESSIONS: &str = "MailItemsAccessed/20260910-100700/20260910-100700-Sessions.csv";
pub const MESSAGE_IDS: &str = "MailItemsAccessed/20260910-100800/20260910-100800-MessageIDs.csv";
pub const SECURITY_DEFAULTS: &str =
    "Licenses/20260910-101000/20260910-101000-EntraSecurityDefaults.csv";
pub const NESTED_UAL: &str = "Mailbox Audit Log/20260910-101200/UnifiedAuditLog/20260910-101201/UAL-20260801000000-20260901000000.csv";
/// Run folders the cmdlet created without writing a file.
pub const EMPTY_RUN_DIRS: &[&str] = &[
    "EntraID/20260910-100100-SignInLogs/managedIdentity",
    "MailItemsAccessed/20260910-100900",
    "Rules/20260910-101100",
];

const RAW_HEADER: &[&str] = &[
    "RecordType",
    "CreationDate",
    "UserIds",
    "Operations",
    "AuditData",
    "ResultIndex",
    "ResultCount",
    "AuditSearchRequestMetadata",
    "Identity",
    "IsValid",
    "ObjectState",
];

fn audit(id: &str, time: &str, op: &str, record_type: i64) -> Value {
    json!({
        "CreationTime": time, "Id": id, "Operation": op,
        "OrganizationId": "0e0e0e0e-0000-4000-8000-00000000000a", "RecordType": record_type,
        "ResultStatus": "True", "UserKey": "1003200000000001", "UserType": 2, "Version": 1,
        "Workload": "Exchange", "ClientIP": "203.0.113.10", "UserId": ALICE, "ObjectId": ALICE
    })
}

fn mia_record() -> Value {
    json!({
        "CreationTime": "2026-08-20T10:00:00", "Id": MIA_1, "Operation": "MailItemsAccessed",
        "OrganizationId": "0e0e0e0e-0000-4000-8000-00000000000a", "RecordType": 50,
        "ResultStatus": "Succeeded", "UserKey": "1003200000000001", "UserType": 0, "Version": 1,
        "Workload": "Exchange", "UserId": ALICE, "ClientIPAddress": MIA_IP,
        "MailboxOwnerUPN": ALICE, "OperationCount": 2,
        "OperationProperties": [{"Name": "MailAccessType", "Value": "Bind"}],
        "Folders": [{"Path": "\\Inbox", "FolderItems": [
            {"InternetMessageId": "<i1@contoso.example>", "SizeInBytes": 1000},
            {"InternetMessageId": "<i2@contoso.example>", "SizeInBytes": 2000}
        ]}]
    })
}

fn raw_row(record_type: &str, a: &Value) -> String {
    csv_line(&[
        record_type,
        "8/20/2026 10:00:00 AM",
        ALICE,
        a["Operation"].as_str().expect("operation"),
        &a.to_string(),
        "1",
        "4",
        "{\n  \"moreRecordsAvailable\": false\n}",
        a["Id"].as_str().expect("id"),
        "True",
        "Unchanged",
    ])
}

fn ual_window() -> Vec<u8> {
    let set_mailbox = audit(ID_1, "2026-09-01T10:20:00", "Set-Mailbox", 1);
    utf8_bom(&format!(
        "{}{}{}{}{}",
        csv_line(RAW_HEADER),
        raw_row("ExchangeAdmin", &set_mailbox),
        raw_row(
            "ExchangeAdmin",
            &audit(ID_2, "2026-09-01T10:21:00", "New-InboxRule", 1)
        ),
        raw_row("ExchangeAdmin", &set_mailbox),
        raw_row("ExchangeItemAggregated", &mia_record()),
    ))
}

fn signin(id: &str, event_type: &str, interactive: bool) -> Value {
    let user = event_type != "servicePrincipal";
    json!({
        "id": id, "createdDateTime": "2026-09-01T10:20:00Z",
        "userDisplayName": if user { "Alice" } else { "" },
        "userPrincipalName": if user { ALICE } else { "" },
        "userId": if user { "0e0e0e0e-0000-4000-8000-0000000000a1" } else { "" },
        "appId": "0e0e0e0e-0000-4000-8000-0000000000b1", "appDisplayName": "Contoso App",
        "ipAddress": "203.0.113.10", "clientAppUsed": if user { "Browser" } else { "" },
        "userAgent": if user { "Mozilla/5.0" } else { "" },
        "correlationId": "0e0e0e0e-0000-4000-8000-0000000000c1",
        "conditionalAccessStatus": "notApplied", "isInteractive": interactive,
        "signInEventTypes": [event_type], "riskDetail": "hidden",
        "riskLevelAggregated": "hidden", "riskLevelDuringSignIn": "hidden", "riskState": "none",
        "riskEventTypes_v2": [], "resourceDisplayName": "Microsoft Graph",
        "resourceId": "00000003-0000-0000-c000-000000000000",
        "status": {"errorCode": 0, "failureReason": "Other.", "additionalDetails": null},
        "deviceDetail": {"deviceId": "", "displayName": "", "operatingSystem": "Windows10",
                         "browser": "Edge 140.0.0", "isCompliant": false, "isManaged": false,
                         "trustType": ""},
        "location": {"city": "Springfield", "state": "Ohio", "countryOrRegion": "US",
                     "geoCoordinates": {"altitude": null, "latitude": 39.9, "longitude": -82.9}},
        "mfaDetail": null, "authenticationDetails": [], "sessionId": "0e0e0e0e-0000-4000-8000-0000000000d1"
    })
}

fn audit_log() -> Value {
    json!([{
        "id": AUDIT_1, "category": "UserManagement",
        "correlationId": "0e0e0e0e-0000-4000-8000-0000000000e1", "result": "success",
        "resultReason": "", "activityDisplayName": "Update user",
        "activityDateTime": "2026-09-01T10:25:00.123456Z", "loggedByService": "Core Directory",
        "operationType": "Update",
        "initiatedBy": {"app": null, "user": {"id": "0e0e0e0e-0000-4000-8000-0000000000a1",
            "displayName": "Alice", "userPrincipalName": ALICE, "ipAddress": "203.0.113.10"}},
        "targetResources": [{"id": "0e0e0e0e-0000-4000-8000-0000000000a2", "displayName": "Bob",
            "type": "User", "userPrincipalName": BOB, "modifiedProperties": []}],
        "additionalDetails": []
    }])
}

const STATUS_HEADER: &[&str] = &[
    "UserPrincipalName",
    "DisplayName",
    "RecipientTypeDetails",
    "AuditEnabled",
    "AuditBypassEnabled",
    "DefaultAuditSet",
    "OwnerAuditActions",
    "OwnerAuditActionsCount",
    "DelegateAuditActions",
    "DelegateAuditActionsCount",
    "AdminAuditActions",
    "AdminAuditActionsCount",
    "EffectiveAuditState",
];

fn status_file(bob_bypassed: bool) -> String {
    let row = |upn: &str, name: &str, bypass: bool| {
        csv_line(&[
            upn,
            name,
            "UserMailbox",
            "True",
            if bypass { "True" } else { "False" },
            "Admin, Delegate, Owner",
            "Create, MailItemsAccessed, Send",
            "3",
            "Create",
            "1",
            "Create, Send",
            "2",
            if bypass {
                "Bypassed"
            } else {
                "Enabled (Organization Policy)"
            },
        ])
    };
    format!(
        "{}{}{}",
        csv_line(STATUS_HEADER),
        row(ALICE, "Alice", false),
        row(BOB, "Bob", bob_bypassed)
    )
}

fn permissions_file() -> String {
    format!(
        "{}{}{}",
        csv_line(&[
            "UserPrincipalName",
            "DisplayName",
            "RecipientTypeDetails",
            "FullAccessUsers",
            "FullAccessPermissions",
            "SendAsUsers",
            "SendAsPermissions",
            "SendOnBehalfUsers",
            "CalendarUsers",
            "CalendarPermissions",
            "InboxUsers",
            "InboxPermissions",
            "FullAccessCount",
            "SendAsCount",
            "SendOnBehalfCount",
            "CalendarPermissionCount",
            "InboxPermissionCount",
        ]),
        csv_line(&[
            ALICE,
            "Alice",
            "UserMailbox",
            "Bob (bob@contoso.example)",
            "Bob (bob@contoso.example) - Rights: FullAccess, Deny: False, Inheritance: All",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "1",
            "0",
            "0",
            "0",
            "0",
        ]),
        csv_line(&[
            BOB,
            "Bob",
            "UserMailbox",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "0",
            "0",
            "0",
            "0",
            "0",
        ])
    )
}

fn trace_file() -> String {
    let header = [
        "MessageTraceId",
        "MessageId",
        "Received",
        "SenderAddress",
        "RecipientAddress",
        "FromIP",
        "ToIP",
        "Subject",
        "Status",
        "Size",
    ];
    format!(
        "{}{}{}",
        csv_line(&header),
        csv_line(&[
            TRACE_1,
            "<m1@contoso.example>",
            "9/1/2026 10:20:00 AM",
            "mallory@fabrikam.example",
            ALICE,
            "198.51.100.7",
            "",
            "Updated bank details",
            "Delivered",
            "2048"
        ]),
        csv_line(&[
            TRACE_2,
            "<m2@contoso.example>",
            "8/15/2026 2:00:00 PM",
            ALICE,
            "carol@fabrikam.example",
            "",
            "",
            "Re: invoice",
            "Delivered",
            "4096"
        ])
    )
}

/// Returns the Output root.
pub fn invictus_output_tree(base: &Path) -> PathBuf {
    let root = base.join(INVICTUS_ROOT);
    let window = ual_window();
    write(&root, UAL_WINDOW, &window);
    write(&root, UAL_MERGED, &window);
    // Two pages in the same second: two arrays in one file.
    let pages = format!(
        "{}\r\n{}\r\n",
        ps_json(&json!([signin(S1, "interactiveUser", true)])),
        ps_json(&json!([signin(S2, "nonInteractiveUser", false)]))
    );
    write(&root, SIGNIN_PAGE, pages.as_bytes());
    write(
        &root,
        SP_PAGE,
        ps_json(&json!([signin(S3, "servicePrincipal", false)])).as_bytes(),
    );
    write(&root, AUDIT_PAGE, ps_json(&audit_log()).as_bytes());
    write(&root, EMPTY_OAUTH, b"");
    write(&root, EMPTY_USERS, b"");
    write(&root, STATUS_EARLY, status_file(false).as_bytes());
    write(&root, STATUS_LATE, status_file(true).as_bytes());
    write(&root, PERMS_1, permissions_file().as_bytes());
    write(&root, PERMS_2, permissions_file().as_bytes());
    write(&root, TRACE_FILE_1, trace_file().as_bytes());
    write(&root, TRACE_FILE_2, trace_file().as_bytes());
    let sessions = format!(
        "\"TimeStamp\",\"User\",\"Action\",\"SessionId\",\"ClientIP\",\"MailAccessType\",\"IsThrottled\",\"OperationCount\"\r\n\
         \"8/20/2026 10:00:00 AM\",\"{ALICE}\",\"MailItemsAccessed\",,\"{MIA_IP}\",\"Bind\",,\"2\"\r\n\
         \"8/20/2026 10:05:00 AM\",\"{ALICE}\",\"MailItemsAccessed\",,\"{MIA_IP}\",\"Bind\",,\"1\"\r\n"
    );
    write(&root, SESSIONS, &utf8_bom(&sessions));
    let ids = format!(
        "\"Timestamp\",\"User\",\"IPaddress\",\"SessionID\",\"MailAccessType\",\"FolderPath\",\"InternetMessageId\",\"SizeInBytes\"\r\n\
         \"8/20/2026 10:00:00 AM\",\"{ALICE}\",\"{MIA_IP}\",,\"Bind\",,\"<i1@contoso.example>\",\"1000\"\r\n\
         \"8/20/2026 10:05:00 AM\",\"{ALICE}\",\"{MIA_IP}\",,\"Bind\",,\"<i9@contoso.example>\",\"900\"\r\n"
    );
    write(&root, MESSAGE_IDS, &utf8_bom(&ids));
    write(
        &root,
        SECURITY_DEFAULTS,
        format!(
            "{}{}",
            csv_line(&[
                "SecurityDefaultsEnabled",
                "HasPremiumLicense",
                "RecommendedState",
                "AlignedWithRecommendations",
                "CheckDate"
            ]),
            csv_line(&["No", "No", "Enabled", "No", "2026-09-10 10:10:00"])
        )
        .as_bytes(),
    );
    write(
        &root,
        NESTED_UAL,
        &utf8_bom(&format!(
            "{}{}",
            csv_line(RAW_HEADER),
            raw_row(
                "ExchangeItem",
                &audit(ID_3, "2026-09-01T11:00:00", "HardDelete", 2)
            )
        )),
    );
    for d in EMPTY_RUN_DIRS {
        std::fs::create_dir_all(root.join(d)).expect("create empty run folder");
    }
    write(&root, ".DS_Store", b"junk");
    root
}

/// The AllRoles export of [`roles_tree`].
pub const ROLES_ALL: &str = "Roles/20260910-100500/20260910-100500-AllRoles.csv";

/// A Microsoft-Extractor-Suite `Output` root whose only artifact is an AllRoles export with one
/// real role member and, when `lost`, the row Get-Roles.ps1 writes when Get-MgUser fails for a
/// member (Get-Roles.ps1:134-165): the parser rejects it as a record the collector lost.
/// Returns the Output root.
pub fn roles_tree(base: &Path, lost: bool) -> PathBuf {
    let root = base.join("Output");
    let mut body = csv_line(&[
        "Role",
        "UserName",
        "UserId",
        "DisplayName",
        "Department",
        "JobTitle",
        "AccountEnabled",
        "CreatedDateTime",
        "LastInteractiveSignIn",
        "LastNonInteractiveSignIn",
        "DaysSinceLastSignIn",
    ]);
    body.push_str(&csv_line(&[
        "User Administrator",
        ALICE,
        "0e0e0e0e-0000-4000-8000-0000000000a1",
        "Alice Example",
        "Finance",
        "Analyst",
        "True",
        "6/27/2025 11:05:39 AM",
        "",
        "",
        "No sign-in data",
    ]));
    if lost {
        let e = "Error retrieving data";
        body.push_str(&csv_line(&[
            "Bob Example",
            BOB,
            "0e0e0e0e-0000-4000-8000-0000000000b1",
            "Bob Example",
            e,
            e,
            e,
            e,
            e,
            e,
            e,
        ]));
    }
    write(&root, ROLES_ALL, body.as_bytes());
    write(&root, "LogFile.txt", b"2026-09-10 10:00:00: Starting\r\n");
    root
}
