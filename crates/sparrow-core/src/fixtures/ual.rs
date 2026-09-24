//! Synthetic AuditData records shared by the capture fixtures (invented tenant and users).

use crate::fixtures::csv_line;
use serde_json::{Value, json};

pub const ORG_ID: &str = "c9c9c9c9-0000-4000-8000-000000000001";
pub const ID_RULE: &str = "a1111111-1111-4111-8111-111111111111";
pub const ID_MIA: &str = "a2222222-2222-4222-8222-222222222222";
pub const ID_LOGIN: &str = "a3333333-3333-4333-8333-333333333333";
pub const ID_FILE: &str = "a4444444-4444-4444-8444-444444444444";
pub const ID_SHARE: &str = "a5555555-5555-4555-8555-555555555555";
pub const ID_SEARCH: &str = "a6666666-6666-4666-8666-666666666666";
pub const ID_SEND: &str = "a7777777-7777-4777-8777-777777777777";
pub const ID_H3_ITEM: &str = "b3333333-3333-4333-8333-333333333333";
pub const ID_H3_EDISC_1: &str = "b1111111-1111-4111-8111-111111111111";
pub const ID_H3_EDISC_2: &str = "b1111111-1111-4111-8111-111111111112";
pub const ID_H3_APP_1: &str = "b2222222-2222-4222-8222-222222222221";
pub const ID_H3_APP_2: &str = "b2222222-2222-4222-8222-222222222222";

/// Header of a Purview (Microsoft 365) audit log search export.
pub const PURVIEW_HEADER: &str = "RecordId,CreationDate,RecordType,Operation,UserId,AuditData,AssociatedAdminUnits,AssociatedAdminUnitsNames\r\n";

/// New-InboxRule that forwards and hides finance mail (ExchangeAdmin, RecordType 1).
pub fn rule() -> Value {
    json!({
        "CreationTime": "2026-09-01T10:00:00", "Id": ID_RULE, "Operation": "New-InboxRule",
        "OrganizationId": ORG_ID, "RecordType": 1, "ResultStatus": "True",
        "UserKey": "10030000A1B2C3D4", "UserType": 2, "Version": 1, "Workload": "Exchange",
        "ClientIP": "[2001:DB8::5]:443", "ObjectId": "alice@contoso.example\\Move to RSS",
        "UserId": "alice@contoso.example", "AppId": "", "ClientAppId": "", "ExternalAccess": false,
        "OrganizationName": "contoso.example", "OriginatingServer": "SRV01 (15.20.0.0)",
        "Parameters": [
            {"Name": "Name", "Value": "Move to RSS"},
            {"Name": "SubjectOrBodyContainsWords", "Value": "invoice;payment"},
            {"Name": "MoveToFolder", "Value": "RSS Feeds"},
            {"Name": "ForwardTo", "Value": "x@fabrikam.example"}
        ],
        "SessionId": "11112222-3333-4444-5555-666677778888"
    })
}

/// MailItemsAccessed bind of two messages (RecordType 50).
pub fn mail_items_accessed() -> Value {
    json!({
        "AppAccessContext": {
            "AADSessionId": "aaaa0000-0000-4000-8000-00000000000a",
            "ClientAppId": "00000002-0000-0ff1-ce00-000000000000"
        },
        "CreationTime": "2026-09-01T10:05:00", "Id": ID_MIA, "Operation": "MailItemsAccessed",
        "OrganizationId": ORG_ID, "RecordType": 50, "ResultStatus": "Succeeded",
        "UserKey": "10030000A1B2C3D4", "UserType": 0, "Version": 1, "Workload": "Exchange",
        "ClientIPAddress": "203.0.113.10", "UserId": "alice@contoso.example",
        "ClientInfoString": "Client=OWA;Mozilla/5.0 (Windows NT 10.0) python-requests/2.31",
        "MailboxOwnerUPN": "alice@contoso.example",
        "OperationProperties": [
            {"Name": "MailAccessType", "Value": "Bind"},
            {"Name": "IsThrottled", "Value": "False"}
        ],
        "Folders": [{
            "Id": "LgAAAA1", "Path": "\\Inbox",
            "FolderItems": [
                {"InternetMessageId": "<m1@contoso.example>", "SizeInBytes": 1024},
                {"InternetMessageId": "<m2@contoso.example>", "SizeInBytes": 2048}
            ]
        }],
        "OperationCount": 2
    })
}

/// Entra ID STS logon (RecordType 15) from an automation user agent.
pub fn login() -> Value {
    json!({
        "CreationTime": "2026-09-01T09:59:00", "Id": ID_LOGIN, "Operation": "UserLoggedIn",
        "OrganizationId": ORG_ID, "RecordType": 15, "ResultStatus": "Success",
        "UserKey": "alice-key", "UserType": 0, "Version": 1, "Workload": "AzureActiveDirectory",
        "ClientIP": "", "ActorIpAddress": "203.0.113.10", "UserId": "alice@contoso.example",
        "ApplicationId": "4765445b-32c6-49b0-83e6-1d93765276ca",
        "ExtendedProperties": [
            {"Name": "UserAgent", "Value": "axios/1.6.0"},
            {"Name": "RequestType", "Value": "OAuth2:Token"}
        ]
    })
}

/// OneDrive download of a OneNote lure (RecordType 6).
pub fn file_download() -> Value {
    json!({
        "CreationTime": "2026-09-01T10:10:00", "Id": ID_FILE, "Operation": "FileDownloaded",
        "OrganizationId": ORG_ID, "RecordType": 6, "UserKey": "i:0h.f|membership|alice",
        "UserType": 0, "Version": 1, "Workload": "OneDrive", "ClientIP": "203.0.113.10",
        "UserId": "alice@contoso.example",
        "SiteUrl": "https://contoso-my.sharepoint.com/personal/alice_contoso_example/",
        "SourceRelativeUrl": "Documents", "SourceFileName": "Invoice 2026.one",
        "SourceFileExtension": "one", "ItemType": "File",
        "ListId": "d1d1d1d1-0000-4000-8000-000000000001",
        "ListItemUniqueId": "d2d2d2d2-0000-4000-8000-000000000002",
        "ApplicationDisplayName": "OneDrive for Business", "UserAgent": "Mozilla/5.0"
    })
}

/// Anyone-link on the lure (RecordType 14).
pub fn anonymous_link() -> Value {
    json!({
        "CreationTime": "2026-09-01T10:12:00", "Id": ID_SHARE, "Operation": "AnonymousLinkCreated",
        "OrganizationId": ORG_ID, "RecordType": 14, "UserType": 0, "Version": 1,
        "Workload": "OneDrive", "ClientIP": "203.0.113.10", "UserId": "alice@contoso.example",
        "SiteUrl": "https://contoso-my.sharepoint.com/personal/alice_contoso_example/",
        "SourceFileName": "Invoice 2026.one", "ItemType": "File",
        "EventData": "<Type>Edit</Type>", "TargetUserOrGroupType": "Guest",
        "TargetUserOrGroupName": "Anyone"
    })
}

/// Mailbox search for payment terms (RecordType 101).
pub fn search() -> Value {
    json!({
        "CreationTime": "2026-09-01T10:15:00", "Id": ID_SEARCH, "Operation": "SearchQueryInitiated",
        "OrganizationId": ORG_ID, "RecordType": 101, "UserType": 0, "Version": 1,
        "Workload": "Exchange", "ClientIP": "203.0.113.10", "UserId": "alice@contoso.example",
        "QueryText": "wire transfer", "QuerySource": "Owa"
    })
}

/// Hawk 3 `Exchange_UAL_Audit` record: client-side inbox rule change (RecordType 2).
pub fn h3_update_inbox_rules() -> Value {
    json!({
        "CreationTime": "2026-09-02T08:05:00", "Id": ID_H3_ITEM, "Operation": "UpdateInboxRules",
        "OrganizationId": ORG_ID, "RecordType": 2, "ResultStatus": "Succeeded",
        "UserKey": "10030000B0B0B0B0", "UserType": 0, "Version": 1, "Workload": "Exchange",
        "ClientIP": "198.51.100.7", "UserId": "bob@contoso.example",
        "ClientIPAddress": "198.51.100.7", "ClientInfoString": "Client=MSExchangeRPC",
        "MailboxOwnerUPN": "bob@contoso.example",
        "Item": {"Id": "RgAAAA1", "ParentFolder": {"Path": "\\Inbox"}},
        "OperationProperties": [
            {"Name": "RuleName", "Value": "."},
            {"Name": "RuleActions", "Value": "MoveToFolder"}
        ]
    })
}

/// Raw Search-UnifiedAuditLog record wrapping `audit` (AuditData as an embedded JSON string).
pub fn raw_record(record_type: &str, creation_date: &str, operation: &str, audit: &Value) -> Value {
    json!({
        "RecordType": record_type, "CreationDate": creation_date, "UserIds": audit["UserId"],
        "Operations": operation, "AuditData": audit.to_string(), "ResultIndex": 1,
        "ResultCount": 1, "Identity": audit["Id"], "IsValid": true, "ObjectState": "Unchanged"
    })
}

/// One Purview export row for `audit`.
pub fn purview_row(creation_date: &str, audit: &Value) -> String {
    let text = |k: &str| audit[k].as_str().unwrap_or_default().to_string();
    let fields = [
        text("Id"),
        creation_date.to_string(),
        audit["RecordType"].to_string(),
        text("Operation"),
        text("UserId"),
        audit.to_string(),
        String::new(),
        String::new(),
    ];
    csv_line(&fields.iter().map(String::as_str).collect::<Vec<_>>())
}
