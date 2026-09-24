//! Synthetic Hawk 4.x capture with no Hawk.log (found by content). The Tenant/ folder was
//! written by PowerShell 7 (UTF-8, ISO dates) and the user folder by Windows PowerShell 5.1
//! (UTF-8 BOM, `\/Date(ms)\/`). The analyst added Purview and message trace exports.

use crate::fixtures::{csv_line, ps_json, ps51_dates, ual, utf8_bom, utf16le_no_bom, write};
use serde_json::json;
use std::path::{Path, PathBuf};

pub const HAWK4_ROOT_NAME: &str = "capture-hawk4";
pub const HAWK4_PURVIEW: &str = "0f8fad5b-d9cb-469f-a165-70867728950e.csv";
pub const HAWK4_MTSUMMARY: &str = "MTSummary_Message trace report - _2026-09-10T141500.000Z__7c9e6679-7425-40de-944b-e07fc1f90ae7.csv";
pub const ALICE: &str = "alice@contoso.example";

/// EAC message trace summary report (header + one row), before UTF-16 encoding.
pub const MTSUMMARY_TEXT: &str = concat!(
    "\"origin_timestamp_utc\",\"sender_address\",\"recipient_status\",\"message_subject\",\"total_bytes\",",
    "\"message_id\",\"network_message_id\",\"original_client_ip\",\"directionality\",\"connector_id\",\"delivery_priority\"\r\n",
    "\"2026-09-01T10:20:00.0000000Z\",\"alice@contoso.example\",\"x@fabrikam.example##Delivered\",",
    "\"Updated bank details\",\"2048\",\"<m3@contoso.example>\",\"0e0e0e0e-0000-4000-8000-000000000003\",",
    "\"203.0.113.10\",\"Originating\",\"\",\"Normal\"\r\n",
);

pub fn hawk4_tree(base: &Path) -> PathBuf {
    let root = base.join(HAWK4_ROOT_NAME);
    let rule = ual::rule();

    let raw_rule = ual::raw_record(
        "ExchangeAdmin",
        "2026-09-01T10:00:05",
        "New-InboxRule",
        &rule,
    );
    write(
        &root,
        "Tenant/Admin_Inbox_Rules_Creation.json",
        ps_json(&json!([raw_rule])).as_bytes(),
    );
    let csv = csv_line(&[
        "RecordType",
        "CreationDate",
        "UserIds",
        "Operations",
        "AuditData",
        "ResultIndex",
        "ResultCount",
    ]) + &csv_line(&[
        "ExchangeAdmin",
        "9/1/2026 10:00:05 AM",
        ALICE,
        "New-InboxRule",
        &rule.to_string(),
        "1",
        "1",
    ]);
    write(
        &root,
        "Tenant/Admin_Inbox_Rules_Creation.csv",
        csv.as_bytes(),
    );
    let simple = json!([{
        "CreationTime": "2026-09-01T10:00:00", "Workload": "Exchange", "RecordType": 1,
        "Operation": "New-InboxRule", "Id": ual::ID_RULE, "UserId": ALICE,
        "Param_ForwardTo": "x@fabrikam.example"
    }]);
    write(
        &root,
        "Tenant/Simple_Admin_Inbox_Rules_Creation.json",
        ps_json(&simple).as_bytes(),
    );
    write(
        &root,
        "Tenant/EntraIDUsers.json",
        ps_json(&json!([{"UserPrincipalName": ALICE}])).as_bytes(),
    );

    let u = |f: &str| format!("{ALICE}/{f}");
    write(
        &root,
        &u("MailItemsAccessed_alice@contoso.example_alice@contoso.example.json"),
        &utf8_bom(&ps_json(&ual::mail_items_accessed())),
    );
    let raw_login = ual::raw_record(
        "AzureActiveDirectoryStsLogon",
        "/Date(1788256740000)/",
        "UserLoggedIn",
        &ual::login(),
    );
    write(
        &root,
        &u("Raw_Authentication_Logs_alice@contoso.example.json"),
        &utf8_bom(&ps51_dates(&ps_json(&raw_login))),
    );
    let converted = json!({
        "CreationTime": "9/1/2026 9:59 AM", "UserId": ALICE, "Workload": "AzureActiveDirectory",
        "ClientIP": "203.0.113.10", "Id": ual::ID_LOGIN, "Operation": "UserLoggedIn"
    });
    write(
        &root,
        &u("Converted_Authentication_Logs_alice@contoso.example.json"),
        &utf8_bom(&ps_json(&converted)),
    );
    let send = csv_line(&[
        "CreationTime",
        "Id",
        "Operation",
        "OrganizationId",
        "RecordType",
        "ResultStatus",
        "UserKey",
        "UserType",
        "Version",
        "Workload",
        "ClientIP",
        "UserId",
        "Item_Subject",
        "Item_InternetMessageId",
        "MailboxOwnerUPN",
    ]) + &csv_line(&[
        "9/14/2026 3:04:05 PM",
        ual::ID_SEND,
        "Send",
        ual::ORG_ID,
        "2",
        "Succeeded",
        "10030000A1B2C3D4",
        "0",
        "1",
        "Exchange",
        "203.0.113.10:51000",
        ALICE,
        "Updated bank details",
        "<m3@contoso.example>",
        ALICE,
    ]);
    write(
        &root,
        &u("ExchangeItem_Simple_alice@contoso.example.csv"),
        &utf8_bom(&send),
    );
    write(
        &root,
        &u("InboxRules_alice@contoso.example.json"),
        &utf8_bom(&ps_json(
            &json!({"Name": "Move to RSS", "MoveToFolder": "RSS Feeds"}),
        )),
    );

    let mut purview = ual::PURVIEW_HEADER.to_string();
    for a in [
        &rule,
        &ual::file_download(),
        &ual::anonymous_link(),
        &ual::search(),
    ] {
        purview.push_str(&ual::purview_row("2026-09-01T10:00:00.0000000Z", a));
    }
    write(&root, HAWK4_PURVIEW, purview.as_bytes());
    write(&root, HAWK4_MTSUMMARY, &utf16le_no_bom(MTSUMMARY_TEXT));
    root
}
