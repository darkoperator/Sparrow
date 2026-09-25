use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use std::path::{Path, PathBuf};

const ALICE_ID: &str = "11111111-1111-4111-8111-111111111111";
const BOB_ID: &str = "22222222-2222-4222-8222-222222222222";
const CAROL_ID: &str = "66666666-6666-4666-8666-666666666666";
const SP_ID: &str = "33333333-3333-4333-8333-333333333333";

fn capture(base: &Path) -> PathBuf {
    let root = base.join("cap");
    fixtures::write(&root, "Hawk.log", fixtures::HAWK_LOG.as_bytes());
    root
}

fn json_file(root: &Path, rel: &str, v: &Value) {
    fixtures::write(root, rel, fixtures::ps_json(v).as_bytes());
}

fn ingest(base: &Path) -> (Case, IngestReport) {
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        base,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    (case, report)
}

fn row<'r>(report: &'r IngestReport, rel: &str) -> &'r FileReport {
    report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .find(|f| f.rel_path == rel)
        .unwrap_or_else(|| panic!("no report row for {rel}"))
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn text(case: &Case, sql: &str) -> String {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn hawk3_and_hawk4_user_lists_load_into_users() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    json_file(
        &root,
        "Tenant/EntraIDUsers.json",
        &json!([
            {"UserPrincipalName": "Alice@Contoso.example", "DisplayName": "Alice", "Id": ALICE_ID,
             "AccountEnabled": true, "CreatedDateTime": "2025-01-15T08:00:00Z", "DeletedDateTime": null,
             "LastPasswordChangeDateTime": "2026-09-18T07:30:00Z", "Mail": "Alice@Contoso.example"},
            {"UserPrincipalName": "bob@contoso.example", "DisplayName": "Bob", "Id": BOB_ID,
             "AccountEnabled": false, "CreatedDateTime": "2025-02-01T08:00:00Z", "DeletedDateTime": null,
             "LastPasswordChangeDateTime": null, "Mail": null}
        ]),
    );
    fixtures::write(
        &root,
        "Tenant/EntraIDUsers.csv",
        (fixtures::csv_line(&["UserPrincipalName", "Id"])
            + &fixtures::csv_line(&["alice@contoso.example", ALICE_ID]))
            .as_bytes(),
    );
    let azuread = json!([
        {"UserPrincipalname": "carol@contoso.example", "ObjectID": CAROL_ID, "UserType": "Guest",
         "DateCreated": "9/24/2025 8:00:00 AM", "UserStateChangedOn": "2026-09-02T10:00:00Z",
         "DirSyncEnabled": null},
        {"UserPrincipalname": "dave@contoso.example", "ObjectID": "77777777-7777-4777-8777-777777777777",
         "UserType": "Member", "DateCreated": "1/2/2024 9:00:00 PM", "UserStateChangedOn": null,
         "DirSyncEnabled": true}
    ]);
    fixtures::write(
        &root,
        "Tenant/AzureADUsers.json",
        &fixtures::utf16le_bom(&fixtures::ps_json(&azuread)),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        row(&report, "Tenant/EntraIDUsers.json").status,
        FileStatus::Parsed
    );
    assert_eq!(
        row(&report, "Tenant/EntraIDUsers.csv").status,
        FileStatus::SkippedSuperseded
    );
    assert_eq!(count(&case, "SELECT count(*) FROM users"), 4);
    assert_eq!(
        text(
            &case,
            &format!("SELECT upn || '|' || mail FROM users WHERE record_key = '{ALICE_ID}'")
        ),
        "alice@contoso.example|alice@contoso.example"
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT epoch(last_password_change)::BIGINT FROM users WHERE user_id = '{ALICE_ID}'"
            )
        ),
        1_789_716_600
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM users WHERE user_id = '{BOB_ID}' AND NOT account_enabled"
            )
        ),
        1
    );
    assert_eq!(
        text(
            &case,
            &format!("SELECT user_type FROM users WHERE record_key = '{CAROL_ID}'")
        ),
        "Guest"
    );
    assert_eq!(
        count(
            &case,
            &format!("SELECT epoch(created)::BIGINT FROM users WHERE record_key = '{CAROL_ID}'")
        ),
        1_758_700_800
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM users WHERE upn = 'dave@contoso.example' AND on_prem_sync"
        ),
        1
    );
    let alice_line: i64 = count(
        &case,
        &format!(
            "SELECT rs.line_start FROM record_sources rs WHERE rs.table_name = 'users' AND rs.record_key = '{ALICE_ID}'"
        ),
    );
    assert_eq!(alice_line, 2);
}

#[test]
fn user_without_id_or_upn_is_a_record_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    json_file(
        &root,
        "Tenant/EntraIDUsers.json",
        &json!([
            {"UserPrincipalName": "alice@contoso.example", "Id": ALICE_ID},
            {"DisplayName": "nobody"}
        ]),
    );
    let (_case, report) = ingest(dir.path());
    let f = row(&report, "Tenant/EntraIDUsers.json");
    assert_eq!(
        (f.status, f.records_read, f.records_loaded, f.records_error),
        (FileStatus::Parsed, 2, 1, 1)
    );
}

#[test]
fn entra_and_exchange_admins_become_role_assignments() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    json_file(
        &root,
        "Tenant/EntraIDAdministrators.json",
        &json!([
            {"AdminGroupName": "Global Administrator", "Members": "alice@contoso.example",
             "MemberType": "User", "ObjectId": ALICE_ID},
            {"AdminGroupName": "Exchange Administrator", "Members": "No Members",
             "MemberType": "None", "ObjectId": null},
            {"AdminGroupName": "Application Administrator", "Members": "Contoso Sync",
             "MemberType": "servicePrincipal", "ObjectId": SP_ID}
        ]),
    );
    json_file(
        &root,
        "Tenant/ExchangeOnlineAdministrators.json",
        &json!([
            {"ExchangeAdminGroup": "Organization Management", "Members": "alice@contoso.example",
             "RecipientType": "UserMailbox"},
            {"ExchangeAdminGroup": "Discovery Management", "Members": "Compliance Officer",
             "RecipientType": "MailUniversalSecurityGroup"}
        ]),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM role_assignments"), 5);
    assert_eq!(
        text(
            &case,
            "SELECT principal_id FROM role_assignments WHERE record_key = 'entra_directory|global administrator|alice@contoso.example'"
        ),
        ALICE_ID
    );
    assert_eq!(
        text(
            &case,
            "SELECT principal_type FROM role_assignments WHERE record_key = 'entra_directory|exchange administrator|'"
        ),
        "none"
    );
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT principal_name FROM role_assignments WHERE record_key = 'entra_directory|application administrator|{SP_ID}'"
            )
        ),
        "Contoso Sync"
    );
    assert_eq!(
        text(
            &case,
            "SELECT CAST(source AS VARCHAR) || '|' || principal_type FROM role_assignments WHERE record_key = 'exchange_rbac|organization management|alice@contoso.example'"
        ),
        "exchange_rbac|UserMailbox"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM role_assignments WHERE record_key = 'exchange_rbac|discovery management|compliance officer'"
        ),
        1
    );
}

#[test]
fn role_entries_go_to_tenant_settings_and_assignments_to_role_assignments() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    json_file(
        &root,
        "Tenant/EDiscoveryRoles.json",
        &json!([
            {"Name": "New-MailboxSearch", "Role": "Mailbox Search", "Type": "Cmdlet",
             "Parameters": ["Name", "SourceMailboxes"], "Identity": "Mailbox Search\\New-MailboxSearch"},
            {"Name": "New-ComplianceSearch", "Role": "Mailbox Search", "Type": "Cmdlet",
             "Parameters": [], "Identity": "Mailbox Search\\New-ComplianceSearch"}
        ]),
    );
    let assignment = |role: &str, assignee: &str, kind: &str, user: &str, created: &str| {
        json!({
            "DataObject": null, "User": user, "AssignmentMethod": "Direct", "Identity": format!("{role}-{assignee}"),
            "EffectiveUserName": user, "RoleAssigneeType": kind, "RoleAssignee": assignee, "Role": role,
            "RoleAssignmentDelegationType": "Regular", "Enabled": true, "RoleAssigneeName": assignee,
            "Name": format!("{role}-{assignee}"), "WhenCreatedUTC": created
        })
    };
    json_file(
        &root,
        "Tenant/CustomEDiscoveryRoles.json",
        &json!([assignment(
            "Mailbox Search",
            "Discovery Management",
            "RoleGroup",
            "Discovery Management",
            "2026-09-01T08:00:00Z"
        )]),
    );
    json_file(
        &root,
        "Tenant/Impersonation_Rights.json",
        &assignment(
            "ApplicationImpersonation",
            "svc-sync",
            "User",
            "svc-sync@contoso.example",
            "2026-09-03T11:00:00Z",
        ),
    );
    json_file(
        &root,
        "Tenant/Impersonation_Roles.json",
        &json!(
            {"Name": "*", "Role": "ApplicationImpersonation", "Type": "Cmdlet", "Parameters": [],
             "Identity": "ApplicationImpersonation\\*"}
        ),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM tenant_settings WHERE source = 'exchange_role_entry'"
        ),
        3
    );
    assert_eq!(
        text(
            &case,
            "SELECT value->>'$.cmdlet' FROM tenant_settings WHERE record_key = '1|exchange_role_entry|mailbox search\\new-mailboxsearch'"
        ),
        "New-MailboxSearch"
    );
    assert_eq!(
        text(
            &case,
            "SELECT principal_type || '|' || assignment_type || '|' || enabled FROM role_assignments WHERE record_key = 'exchange_ediscovery|mailbox search|discovery management'"
        ),
        "RoleGroup|active|true"
    );
    assert_eq!(
        text(
            &case,
            "SELECT principal_upn FROM role_assignments WHERE record_key = 'exchange_rbac|applicationimpersonation|svc-sync@contoso.example'"
        ),
        "svc-sync@contoso.example"
    );
    assert_eq!(
        count(
            &case,
            "SELECT epoch(start_time)::BIGINT FROM role_assignments WHERE record_key = 'exchange_rbac|applicationimpersonation|svc-sync@contoso.example'"
        ),
        1_788_433_200
    );
}

#[test]
fn unknown_role_file_shape_is_not_supported() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    json_file(&root, "Tenant/EDiscoveryRoles.json", &json!([{"Foo": 1}]));
    let (_case, report) = ingest(dir.path());
    let f = row(&report, "Tenant/EDiscoveryRoles.json");
    assert_eq!(f.status, FileStatus::NotSupported);
    assert!(
        f.warnings.iter().any(|w| w.contains("role")),
        "{:?}",
        f.warnings
    );
}

#[test]
fn user_list_without_user_principal_names_is_not_supported() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    json_file(
        &root,
        "Tenant/EntraIDUsers.json",
        &json!([{"GroupName": "Sales", "Members": 3}]),
    );
    let (case, report) = ingest(dir.path());
    let f = row(&report, "Tenant/EntraIDUsers.json");
    assert_eq!(f.status, FileStatus::NotSupported, "{f:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM users"), 0);
}
