use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use std::path::{Path, PathBuf};

const ALICE: &str = "alice@contoso.example";

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

fn inbox_rule(owner: &str, identity: u64, name: &str, extra: Value) -> Value {
    let mut v = json!({
        "Description": "If the message:\r\n\tincludes 'invoice'\r\nTake the following actions:\r\n\tforward\r\n",
        "Enabled": true, "Identity": format!("{owner}\\{identity}"), "InError": false, "Name": name,
        "Priority": 1, "RuleIdentity": identity, "BodyContainsWords": [], "From": null,
        "HasAttachment": false, "SubjectContainsWords": [], "SubjectOrBodyContainsWords": [],
        "CopyToFolder": null, "DeleteMessage": false, "ForwardAsAttachmentTo": null, "ForwardTo": null,
        "MarkAsRead": false, "MoveToFolder": null, "RedirectTo": null, "SoftDeleteMessage": false,
        "StopProcessingRules": false, "MailboxOwnerId": owner
    });
    for (k, val) in extra.as_object().unwrap() {
        v[k] = val.clone();
    }
    v
}

#[test]
fn inbox_rules_load_with_forwarding_and_conditions() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rules = json!([
        inbox_rule(
            "alice",
            1111,
            ".",
            json!({
                "ForwardTo": ["\"x\" [SMTP:x@fabrikam.example]"], "DeleteMessage": true,
                "SubjectOrBodyContainsWords": ["invoice", "payment"], "StopProcessingRules": true
            })
        ),
        inbox_rule(
            "alice",
            2222,
            "Newsletters",
            json!({
                "MoveToFolder": "RSS Feeds", "From": ["\"News\" [SMTP:news@fabrikam.example]"], "Priority": 2
            })
        )
    ]);
    fixtures::write(
        &root,
        &format!("{ALICE}/InboxRules_alice.json"),
        &fixtures::utf8_bom(&fixtures::ps_json(&rules)),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM inbox_rules"), 2);
    assert_eq!(
        text(
            &case,
            "SELECT forward_to[1] || '|' || delete_message || '|' || len(subject_or_body_contains) || '|' || mailbox_upn || '|' || priority FROM inbox_rules WHERE record_key = 'inbox|alice|1111'"
        ),
        "\"x\" [SMTP:x@fabrikam.example]|true|2|alice@contoso.example|1"
    );
    assert_eq!(
        text(
            &case,
            "SELECT move_to_folder || '|' || from_addresses[1] FROM inbox_rules WHERE record_key = 'inbox|alice|2222'"
        ),
        "RSS Feeds|\"News\" [SMTP:news@fabrikam.example]"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM inbox_rules WHERE record_key = 'inbox|alice|2222' AND forward_to IS NULL"
        ),
        1
    );
}

#[test]
fn tenant_and_user_copies_of_a_rule_are_one_row() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    // Hawk 3.x writes Tenant/All_InboxRules byte-identical to the user's InboxRules file.
    let bytes = fixtures::utf16le_bom(&fixtures::ps_json(&inbox_rule(
        "bob",
        3333,
        "Move",
        json!({}),
    )));
    fixtures::write(&root, "Tenant/All_InboxRules.json", &bytes);
    fixtures::write(&root, "bob@contoso.example/InboxRules_bob.json", &bytes);
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM inbox_rules"), 1);
    assert_eq!(
        text(&case, "SELECT mailbox_upn FROM inbox_rules"),
        "bob@contoso.example"
    );
    let tenant = row(&report, "Tenant/All_InboxRules.json");
    assert_eq!((tenant.records_loaded, tenant.records_duplicate), (0, 1));
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'inbox_rules' AND record_key = 'inbox|bob|3333'"
        ),
        2
    );
}

#[test]
fn sweep_rules_load_as_kind_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    json_file(
        &root,
        &format!("{ALICE}/SweepRules_alice.json"),
        &json!({
            "Name": "Old bank mail", "RuleId": "sweep-1", "Enabled": true,
            "SourceFolder": "alice:\\Inbox", "DestinationFolder": "alice:\\Deleted Items",
            "Sender": "\"Bank\" [SMTP:bank@fabrikam.example]", "KeepForDays": 3, "KeepLatest": null,
            "MailboxOwnerId": "alice", "Identity": "alice\\sweep-1"
        }),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        text(
            &case,
            "SELECT CAST(kind AS VARCHAR) || '|' || move_to_folder || '|' || source_folder || '|' || from_addresses[1] FROM inbox_rules WHERE record_key = 'sweep|alice|sweep-1'"
        ),
        "sweep|alice:\\Deleted Items|alice:\\Inbox|\"Bank\" [SMTP:bank@fabrikam.example]"
    );
}

#[test]
fn mobile_devices_transport_rules_and_remote_domains_load() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let device = json!({
        "FriendlyName": "", "DeviceId": "ABCDEF0123456789", "DeviceImei": "", "DeviceOS": "iOS 19.0",
        "DeviceType": "iPhone", "DeviceUserAgent": "Apple-iPhone17C1/2301.1", "DeviceModel": "iPhone17C1",
        "FirstSyncTime": "/Date(1788256800000)/", "UserDisplayName": "Alice",
        "DeviceAccessState": "Allowed", "DeviceAccessStateReason": "Global", "ClientType": "EAS",
        "IsManaged": false, "IsCompliant": false, "IsDisabled": false,
        "WhenCreatedUTC": "/Date(1788256800000)/",
        "Identity": "alice\\ExchangeActiveSyncDevices\\iPhone-ABCDEF0123456789"
    });
    fixtures::write(
        &root,
        &format!("{ALICE}/MobileDevices_alice.json"),
        &fixtures::utf8_bom(&fixtures::ps51_dates(&fixtures::ps_json(&device))),
    );
    json_file(
        &root,
        "Tenant/TransportRules.json",
        &json!([{
            "Name": "External redirect", "Guid": "88888888-8888-4888-8888-888888888888", "State": "Enabled",
            "Mode": "Enforce", "Priority": 0, "CreatedBy": "Admin", "LastModifiedBy": "Admin",
            "WhenChanged": "2026-09-01T12:00:00+02:00",
            "Description": "If the message...\r\nTake the following actions:\r\nRedirect the message to 'x@fabrikam.example'",
            "Conditions": ["Microsoft.Exchange.MessagingPolicies.Rules.Tasks.SentToPredicate"],
            "Exceptions": null,
            "Actions": ["Microsoft.Exchange.MessagingPolicies.Rules.Tasks.RedirectMessageAction"],
            "RedirectMessageTo": ["x@fabrikam.example"], "BlindCopyTo": null, "CopyTo": null,
            "AddToRecipients": null, "RuleVersion": {"Major": 15, "Minor": 0, "Build": 5, "Revision": 0}
        }]),
    );
    json_file(
        &root,
        "Tenant/RemoteDomain.json",
        &json!({
            "DomainName": "*", "Name": "Default", "AutoForwardEnabled": true, "AllowedOOFType": "External",
            "WhenChanged": "2026-09-01T10:00:00Z"
        }),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        text(
            &case,
            "SELECT model || '|' || client_type || '|' || epoch(first_sync)::BIGINT FROM mobile_devices WHERE record_key = 'alice@contoso.example|abcdef0123456789'"
        ),
        "iPhone17C1|EAS|1788256800"
    );
    assert_eq!(
        text(
            &case,
            "SELECT redirect_to[1] || '|' || json_array_length(conditions) || '|' || epoch(when_changed)::BIGINT FROM transport_rules WHERE record_key = 'external redirect'"
        ),
        "x@fabrikam.example|1|1788256800"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM transport_rules WHERE exceptions IS NULL"
        ),
        1
    );
    assert_eq!(
        text(
            &case,
            "SELECT name || '|' || auto_forward_enabled FROM remote_domains WHERE record_key = '*'"
        ),
        "Default|true"
    );
}

#[test]
fn rule_without_mailbox_or_identity_is_a_record_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    json_file(
        &root,
        "Tenant/All_InboxRules.json",
        &json!([{"Enabled": true, "ForwardTo": null}]),
    );
    let (_case, report) = ingest(dir.path());
    let f = row(&report, "Tenant/All_InboxRules.json");
    assert_eq!(
        (f.status, f.records_read, f.records_error),
        (FileStatus::Parsed, 1, 1)
    );
}

#[test]
fn rule_files_of_another_shape_are_not_supported() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    json_file(
        &root,
        "Tenant/All_InboxRules.json",
        &json!([{"Name": "x", "Enabled": true}]),
    );
    json_file(
        &root,
        &format!("{ALICE}/SweepRules_alice.json"),
        &json!([{"Name": "x", "Enabled": true, "ForwardTo": null}]),
    );
    let (case, report) = ingest(dir.path());
    for rel in [
        "Tenant/All_InboxRules.json".to_string(),
        format!("{ALICE}/SweepRules_alice.json"),
    ] {
        assert_eq!(row(&report, &rel).status, FileStatus::NotSupported, "{rel}");
    }
    assert_eq!(count(&case, "SELECT count(*) FROM inbox_rules"), 0);
}
