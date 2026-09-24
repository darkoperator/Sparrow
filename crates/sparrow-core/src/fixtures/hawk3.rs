//! Synthetic Hawk 3.1.0 capture from Windows PowerShell 5.1: JSON/log UTF-16LE with BOM,
//! CSV UTF-8 with BOM. Folder name is not `Hawk_<tenant>_<ts>`.

use crate::fixtures::{csv_line, ps_json, ps51_dates, ual, utf8_bom, utf16le_bom, write};
use serde_json::json;
use std::path::{Path, PathBuf};

pub const HAWK3_ROOT_NAME: &str = "capture-hawk3";
pub const HAWK3_PURVIEW: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301.csv";
pub const BOB: &str = "bob@contoso.example";

pub fn hawk3_tree(base: &Path) -> PathBuf {
    let root = base.join(HAWK3_ROOT_NAME);
    write(
        &root,
        "Hawk.log",
        &utf16le_bom(concat!(
            "[9/10/2026 2:15:00 PM] - *** Version 3.1.0 ***\r\n",
            "[9/10/2026 2:15:01 PM] - ## Tenant ## - Starting tenant investigation\r\n",
        )),
    );
    let admin = json!([{
        "ObjectModified": "contoso.example/Role Assignments/ApplicationImpersonation-svc",
        "CmdletName": "New-ManagementRoleAssignment",
        "CmdletParameters": [{"Name": "Role", "Value": "ApplicationImpersonation"}],
        "ModifiedProperties": [], "Caller": "admin@contoso.example", "ExternalAccess": false,
        "Succeeded": true, "Error": "", "RunDate": "/Date(1788336000000)/",
        "OriginatingServer": "SRV01", "ClientIP": "198.51.100.7", "SessionId": "s-3",
        "AppId": null, "ClientAppId": null, "Identity": {}, "IsValid": true, "ObjectState": "Unchanged"
    }]);
    write(
        &root,
        "Tenant/RBAC_Changes.json",
        &utf16le_bom(&ps51_dates(&ps_json(&admin))),
    );
    let simple = csv_line(&[
        "Caller",
        "Cmdlet",
        "FullCommand",
        "RunDate(UTC)",
        "ObjectModified",
    ]) + &csv_line(&[
        "admin@contoso.example",
        "New-ManagementRoleAssignment",
        "New-ManagementRoleAssignment -Role ApplicationImpersonation -User svc",
        "9/2/2026 8:00:00 AM",
        "svc",
    ]);
    write(&root, "Tenant/Simple_RBAC_Changes.csv", &utf8_bom(&simple));
    let ediscovery = csv_line(&[
        "CreationTime",
        "Id",
        "Operation",
        "Workload",
        "UserId",
        "Case",
        "CaseID",
        "Cmdlet",
    ]) + &csv_line(&[
        "9/2/2026 8:00:00 AM",
        ual::ID_H3_EDISC_1,
        "SearchCreated",
        "SecurityComplianceCenter",
        "admin@contoso.example",
        "Case 1",
        "e1e1e1e1-0000-4000-8000-000000000001",
        "New-ComplianceSearch",
    ]) + &csv_line(&[
        "9/15/2026 8:30:00 AM",
        ual::ID_H3_EDISC_2,
        "SearchExported",
        "SecurityComplianceCenter",
        "admin@contoso.example",
        "Case 1",
        "e1e1e1e1-0000-4000-8000-000000000001",
        "New-ComplianceSearchAction",
    ]);
    write(&root, "Tenant/eDiscoveryLogs.csv", &utf8_bom(&ediscovery));
    // Real Hawk captures write `env_time: null` in every application audit record.
    let app = |id: &str| {
        ps_json(&json!({
            "Id": id, "Operation": "Consent to application.", "ResultStatus": "Success",
            "Workload": "AzureActiveDirectory", "ClientIP": null, "UserId": "alice@contoso.example",
            "ActorUPN": "alice@contoso.example", "targetName": "Invoice Viewer", "env_time": null,
            "correlationId": "f0f0f0f0-0000-4000-8000-000000000001"
        }))
    };
    // Concatenated pretty-printed objects without separators or an enclosing array.
    write(
        &root,
        "Tenant/Azure_Application_Audit.json",
        &utf16le_bom(&format!(
            "{}\r\n{}\r\n",
            app(ual::ID_H3_APP_1),
            app(ual::ID_H3_APP_2)
        )),
    );
    write(
        &root,
        "Tenant/XML/RBAC_Changes.xml",
        &utf16le_bom(
            "<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"></Objs>\r\n",
        ),
    );

    let b = |f: &str| format!("{BOB}/{f}");
    let item = ual::h3_update_inbox_rules();
    write(
        &root,
        &b("Exchange_UAL_Audit_bob@contoso.example.json"),
        &utf16le_bom(&ps_json(&json!([item]))),
    );
    let item_csv = csv_line(&[
        "CreationTime",
        "Id",
        "Operation",
        "OrganizationId",
        "RecordType",
        "ResultStatus",
        "UserId",
        "ClientIPAddress",
        "MailboxOwnerUPN",
        "Item",
        "OperationProperties",
    ]) + &csv_line(&[
        "2026-09-02T08:05:00",
        ual::ID_H3_ITEM,
        "UpdateInboxRules",
        ual::ORG_ID,
        "2",
        "Succeeded",
        BOB,
        "198.51.100.7",
        BOB,
        "@{Id=RgAAAA1}",
        "System.Object[]",
    ]);
    write(
        &root,
        &b("Exchange_UAL_Audit_bob@contoso.example.csv"),
        &utf8_bom(&item_csv),
    );
    write(
        &root,
        &b("Exchange_Mailbox_Audit_bob@contoso.example.json"),
        &utf16le_bom(&ps51_dates(&ps_json(&json!([{
            "Operation": "HardDelete", "LogonType": "Owner", "LastAccessed": "/Date(1788336000000)/"
        }])))),
    );
    let purview = ual::PURVIEW_HEADER.to_string() + &ual::purview_row("9/2/2026 8:05:00 AM", &item);
    write(&root, &b(HAWK3_PURVIEW), purview.as_bytes());

    let psf = csv_line(&[
        "ComputerName",
        "File",
        "FunctionName",
        "Level",
        "Line",
        "Message",
        "ModuleName",
        "Runspace",
        "Tags",
        "TargetObject",
        "Timestamp",
        "Type",
        "Username",
    ]) + &csv_line(&[
        "WS01",
        "Start-HawkTenantInvestigation.ps1",
        "Out-LogFile",
        "Host",
        "12",
        "Starting",
        "HAWK",
        "1",
        "",
        "",
        "2026-09-02 08:00:00.123",
        "Information",
        "CONTOSO\\analyst",
    ]);
    write(&root, "2026-09-02_logs.csv", &utf8_bom(&psf));
    write(
        &root,
        "tenant_analysis.log",
        b"2026-09-10 14:20:00,123 - INFO - analysis started\r\n",
    );
    root
}
