use serde_json::{Value, json};
use sparrow_core::normalize::ual::*;
use sparrow_core::normalize::ual_shape::*;
use sparrow_core::readers::time::{DateOrder, Precision};

const ID: &str = "A1111111-1111-4111-8111-111111111111";

fn input(v: Value, lossy: bool, flattened: bool) -> AuditInput {
    let map = v.as_object().unwrap().clone();
    let shape = detect_shape(map.keys().map(String::as_str), flattened);
    to_audit(shape, &map, lossy).unwrap()
}

fn record(v: Value, lossy: bool) -> UalRecord {
    normalize_audit(&input(v, lossy, false), Some(DateOrder::MonthFirst)).unwrap()
}

#[test]
fn typed_columns_from_an_exchange_admin_record() {
    let r = record(
        json!({
            "CreationTime": "2026-09-01T10:00:00", "Id": ID, "Operation": "New-InboxRule",
            "OrganizationId": "C9C9C9C9-0000-4000-8000-000000000001", "RecordType": 1,
            "ResultStatus": "True", "UserKey": "10030000A1B2C3D4", "UserType": 2, "Workload": "Exchange",
            "ClientIP": "[2001:DB8::5]:443", "ObjectId": "alice@contoso.example\\Move to RSS",
            "UserId": "Alice@Contoso.example", "AppId": "", "SessionId": "s-1",
            "Parameters": [
                {"Name": "ForwardTo", "Value": "x@fabrikam.example"},
                {"Name": "MoveToFolder", "Value": "RSS Feeds"}
            ]
        }),
        false,
    );
    assert_eq!(r.record_id, "a1111111-1111-4111-8111-111111111111");
    assert!(!r.synthetic_id);
    assert_eq!(r.event_time, "2026-09-01T10:00:00+00:00");
    assert!(r.time_tz_assumed);
    assert_eq!(r.time_precision, Precision::Second);
    assert_eq!(r.record_type, Some(1));
    assert_eq!(r.record_type_name.as_deref(), Some("ExchangeAdmin"));
    assert_eq!(r.workload.as_deref(), Some("Exchange"));
    assert_eq!(r.operation.as_deref(), Some("New-InboxRule"));
    assert_eq!(r.result_status.as_deref(), Some("True"));
    assert_eq!(r.user_upn.as_deref(), Some("alice@contoso.example"));
    assert_eq!(r.user_type, Some(2));
    assert_eq!(r.user_key.as_deref(), Some("10030000A1B2C3D4"));
    assert_eq!(r.client_ip.as_deref(), Some("2001:db8::5"));
    assert_eq!(r.app_id, None);
    assert_eq!(r.session_id.as_deref(), Some("s-1"));
    assert_eq!(
        r.object_id.as_deref(),
        Some("alice@contoso.example\\Move to RSS")
    );
    assert_eq!(
        r.organization_id.as_deref(),
        Some("c9c9c9c9-0000-4000-8000-000000000001")
    );
    assert_eq!(
        r.parameters,
        vec![
            ("ForwardTo".to_string(), "x@fabrikam.example".to_string()),
            ("MoveToFolder".to_string(), "RSS Feeds".to_string())
        ]
    );
    assert_eq!(r.completeness, Completeness::Full);
    assert!(r.mail_items.is_empty());
    assert!(r.file_event.is_none() && r.sharing.is_none() && r.search.is_none());
    let back: Value = serde_json::from_str(&r.audit_data).unwrap();
    assert_eq!(back["Operation"], "New-InboxRule");
}

#[test]
fn outer_record_type_name_and_creation_date_are_fallbacks() {
    let map = json!({
        "RecordType": "ExchangeItemGroup", "CreationDate": "2026-09-01T10:00:00",
        "AuditData": "{\"Id\":\"b1111111-1111-4111-8111-111111111111\",\"Operation\":\"HardDelete\"}"
    });
    let i = to_audit(UalShape::Raw, map.as_object().unwrap(), false).unwrap();
    assert_eq!(event_time_text(&i).as_deref(), Some("2026-09-01T10:00:00"));
    let r = normalize_audit(&i, None).unwrap();
    assert_eq!(r.record_type, Some(3));
    assert_eq!(r.record_type_name.as_deref(), Some("ExchangeItemGroup"));
    assert_eq!(r.event_time, "2026-09-01T10:00:00+00:00");
}

#[test]
fn mail_items_accessed_rows() {
    let r = record(
        json!({
            "CreationTime": "2026-09-01T10:05:00", "Id": ID, "Operation": "MailItemsAccessed",
            "RecordType": 50, "Workload": "Exchange", "UserId": "alice@contoso.example",
            "MailboxOwnerUPN": "Alice@contoso.example", "ClientIPAddress": "203.0.113.10",
            "ClientInfoString": "Client=OWA;python-requests/2.31",
            "AppAccessContext": {"AADSessionId": "sess-9", "ClientAppId": "app-9"},
            "OperationProperties": [
                {"Name": "MailAccessType", "Value": "Bind"},
                {"Name": "IsThrottled", "Value": "False"}
            ],
            "OperationCount": 2,
            "Folders": [
                {"Path": "\\Inbox", "FolderItems": [
                    {"InternetMessageId": "<m1@contoso.example>", "SizeInBytes": 1024},
                    {"InternetMessageId": "<m2@contoso.example>", "SizeInBytes": 2048}
                ]},
                {"Path": "\\Archive", "FolderItems": []}
            ]
        }),
        false,
    );
    assert_eq!(r.mail_items.len(), 3);
    assert_eq!(r.mail_items[0].access_type, Some("bind"));
    assert_eq!(r.mail_items[0].is_throttled, Some(false));
    assert_eq!(r.mail_items[0].operation_count, Some(2));
    assert_eq!(r.mail_items[1].item_ordinal, 1);
    assert_eq!(
        r.mail_items[1].internet_message_id.as_deref(),
        Some("<m2@contoso.example>")
    );
    assert_eq!(r.mail_items[1].size_bytes, Some(2048));
    assert_eq!(r.mail_items[1].folder_path.as_deref(), Some("\\Inbox"));
    assert_eq!(r.mail_items[2].folder_path.as_deref(), Some("\\Archive"));
    assert_eq!(r.mail_items[2].internet_message_id, None);
    assert_eq!(r.session_id.as_deref(), Some("sess-9"));
    assert_eq!(r.client_app_id.as_deref(), Some("app-9"));
    assert_eq!(r.mailbox_upn.as_deref(), Some("alice@contoso.example"));
    assert_eq!(r.client_ip.as_deref(), Some("203.0.113.10"));
    assert_eq!(
        r.user_agent.as_deref(),
        Some("Client=OWA;python-requests/2.31")
    );
    assert!(
        r.parameters
            .contains(&("MailAccessType".to_string(), "Bind".to_string()))
    );
}

#[test]
fn csv_mail_items_record_is_partial_with_one_row() {
    let r = record(
        json!({
            "CreationTime": "2026-09-01T10:05:00", "Id": ID, "Operation": "MailItemsAccessed",
            "Folders": "System.Object[]", "AppAccessContext": "@{AADSessionId=x}"
        }),
        true,
    );
    assert_eq!(r.completeness, Completeness::Partial);
    assert_eq!(r.mail_items.len(), 1);
    assert_eq!(r.mail_items[0].folder_path, None);
    assert_eq!(r.mail_items[0].access_type, None);
    assert_eq!(r.session_id, None);
}

#[test]
fn sts_logon_user_agent_from_extended_properties() {
    let r = record(
        json!({
            "CreationTime": "2026-09-01T09:59:00", "Id": ID, "Operation": "UserLoggedIn",
            "RecordType": 15, "Workload": "AzureActiveDirectory", "ClientIP": "",
            "ActorIpAddress": "203.0.113.10", "UserId": "alice@contoso.example",
            "ApplicationId": "4765445b-32c6-49b0-83e6-1d93765276ca",
            "ExtendedProperties": [
                {"Name": "UserAgent", "Value": "axios/1.6.0"},
                {"Name": "RequestType", "Value": "OAuth2:Token"}
            ]
        }),
        false,
    );
    assert_eq!(r.client_ip.as_deref(), Some("203.0.113.10"));
    assert_eq!(r.user_agent.as_deref(), Some("axios/1.6.0"));
    assert_eq!(
        r.app_id.as_deref(),
        Some("4765445b-32c6-49b0-83e6-1d93765276ca")
    );
    assert_eq!(
        r.record_type_name.as_deref(),
        Some("AzureActiveDirectoryStsLogon")
    );
}

#[test]
fn onenote_file_event_and_sharing_links() {
    let file = record(
        json!({
            "CreationTime": "2026-09-01T10:10:00", "Id": ID, "Operation": "FileDownloaded",
            "RecordType": 6, "Workload": "OneDrive", "UserId": "alice@contoso.example",
            "SiteUrl": "https://contoso-my.sharepoint.com/personal/alice_contoso_example/",
            "SourceRelativeUrl": "Documents", "SourceFileName": "Invoice 2026.one", "ItemType": "File",
            "ListId": "d1d1d1d1-0000-4000-8000-000000000001",
            "ListItemUniqueId": "d2d2d2d2-0000-4000-8000-000000000002",
            "ApplicationDisplayName": "OneDrive for Business"
        }),
        false,
    );
    let fe = file.file_event.unwrap();
    assert_eq!(fe.workload.as_deref(), Some("OneDrive"));
    assert_eq!(fe.file_name.as_deref(), Some("Invoice 2026.one"));
    assert_eq!(fe.file_ext.as_deref(), Some("one"));
    assert_eq!(fe.relative_url.as_deref(), Some("Documents"));
    assert_eq!(fe.item_type, "file");
    assert!(fe.is_onenote);
    assert_eq!(
        fe.list_item_id.as_deref(),
        Some("d2d2d2d2-0000-4000-8000-000000000002")
    );

    let anon = record(
        json!({
            "CreationTime": "2026-09-01T10:12:00", "Id": ID, "Operation": "AnonymousLinkCreated",
            "Workload": "OneDrive", "SourceFileName": "Invoice 2026.one", "ItemType": "File",
            "EventData": "<Type>Edit</Type>", "TargetUserOrGroupType": "Guest",
            "TargetUserOrGroupName": "Anyone"
        }),
        false,
    );
    let s = anon.sharing.unwrap();
    assert_eq!(s.link_type, "anonymous");
    assert_eq!(s.permission, Some("edit"));
    assert_eq!(s.is_external, Some(true));
    assert_eq!(s.target_user.as_deref(), Some("Anyone"));
    assert_eq!(s.target_email, None);
    assert!(anon.file_event.is_some());

    let secure = record(
        json!({
            "CreationTime": "2026-09-01T10:13:00", "Id": ID, "Operation": "AddedToSecureLink",
            "Workload": "SharePoint", "TargetUserOrGroupName": "Eve@Fabrikam.example",
            "TargetUserOrGroupType": "Member"
        }),
        false,
    );
    let s = secure.sharing.unwrap();
    assert_eq!(s.link_type, "specific_people");
    assert_eq!(s.target_email.as_deref(), Some("eve@fabrikam.example"));
    assert_eq!(s.permission, None);
    assert_eq!(s.is_external, Some(false));
    assert!(secure.file_event.is_none());
}

#[test]
fn search_query_events() {
    let ex = record(
        json!({
            "CreationTime": "2026-09-01T10:15:00", "Id": ID, "Operation": "SearchQueryInitiated",
            "Workload": "Exchange", "QueryText": "wire transfer", "QuerySource": "Owa"
        }),
        false,
    );
    let s = ex.search.unwrap();
    assert_eq!(s.workload, "exchange");
    assert_eq!(s.query_text.as_deref(), Some("wire transfer"));
    assert_eq!(s.scope.as_deref(), Some("Owa"));
    let sp = record(
        json!({"CreationTime": "2026-09-01T10:16:00", "Id": ID, "Operation": "SharepointSearchQueryInitiated", "Workload": "SharePoint"}),
        false,
    );
    let s = sp.search.unwrap();
    assert_eq!(s.workload, "sharepoint");
    assert_eq!(s.query_text, None);
}

#[test]
fn flattened_params_and_culture_time() {
    let i = input(
        json!({
            "CreationTime": "9/14/2026 3:04:05 PM", "Id": ID, "Operation": "Send",
            "Param_Subject": "hi", "ClientIP": "203.0.113.10:51000"
        }),
        true,
        true,
    );
    let r = normalize_audit(&i, Some(DateOrder::MonthFirst)).unwrap();
    assert_eq!(r.event_time, "2026-09-14T15:04:05+00:00");
    assert_eq!(
        r.parameters,
        vec![("Subject".to_string(), "hi".to_string())]
    );
    assert_eq!(r.client_ip.as_deref(), Some("203.0.113.10"));
    assert_eq!(r.completeness, Completeness::Partial);
}

#[test]
fn minute_precision_from_converted_authentication_logs() {
    let r = record(
        json!({"CreationTime": "9/1/2026 9:59 AM", "Id": ID, "Operation": "UserLoggedIn"}),
        true,
    );
    assert_eq!(r.time_precision, Precision::Minute);
    assert_eq!(r.event_time, "2026-09-01T09:59:00+00:00");
}

#[test]
fn missing_or_invalid_id_gets_a_stable_synthetic_id() {
    let a = record(
        json!({"CreationTime": "2026-09-02T08:00:00", "Id": "not-a-guid", "Operation": "SearchCreated", "Workload": "SecurityComplianceCenter"}),
        true,
    );
    let b = record(
        json!({"Workload": "SecurityComplianceCenter", "Operation": "SearchCreated", "Id": "not-a-guid", "CreationTime": "2026-09-02T08:00:00"}),
        true,
    );
    let c = record(
        json!({"CreationTime": "2026-09-02T08:00:00", "Id": "not-a-guid", "Operation": "SearchExported", "Workload": "SecurityComplianceCenter"}),
        true,
    );
    assert!(a.synthetic_id);
    assert_eq!(a.record_id, b.record_id);
    assert_ne!(a.record_id, c.record_id);
}

#[test]
fn missing_or_ambiguous_time_is_an_error() {
    let no_time = input(
        json!({"Id": ID, "Operation": "x", "CreationTime": ""}),
        false,
        false,
    );
    assert!(
        normalize_audit(&no_time, None)
            .unwrap_err()
            .contains("no CreationTime")
    );
    let ambiguous = input(
        json!({"Id": ID, "Operation": "x", "CreationTime": "6/12/2026 10:00:00 AM"}),
        false,
        false,
    );
    assert!(
        normalize_audit(&ambiguous, None)
            .unwrap_err()
            .contains("--culture")
    );
}
