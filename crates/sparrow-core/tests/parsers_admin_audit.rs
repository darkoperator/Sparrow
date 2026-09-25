use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::normalize::fields::Rec;
use sparrow_core::parsers::admin_audit::{admin_audit_key, short_object, simple_caller};
use sparrow_core::readers::time::DateOrder;
use std::path::{Path, PathBuf};

const R1_OBJECT: &str = "contoso.example/Users/alice\\Rule1";
const SIMPLE_HEADER: &[&str] = &[
    "Caller",
    "Cmdlet",
    "FullCommand",
    "RunDate(UTC)",
    "ObjectModified",
];

fn capture(base: &Path) -> PathBuf {
    let root = base.join("cap");
    fixtures::write(&root, "Hawk.log", fixtures::HAWK_LOG.as_bytes());
    root
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

/// One Search-AdminAuditLog record as Windows PowerShell 5.1 ConvertTo-Json writes it.
fn full(object: &str, cmdlet: &str, run_ms: u64, forward: &str) -> Value {
    json!({
        "ObjectModified": object, "CmdletName": cmdlet,
        "CmdletParameters": [{"Name": "Identity", "Value": object}, {"Name": "ForwardTo", "Value": forward}],
        "ModifiedProperties": [], "Caller": "Admin@contoso.example", "ExternalAccess": false,
        "Succeeded": true, "Error": "", "RunDate": format!("/Date({run_ms})/"),
        "OriginatingServer": "SRV01", "ClientIP": "198.51.100.7:4433", "SessionId": "s-3",
        "AppId": null, "ClientAppId": null, "Identity": {"ObjectId": "x"}, "IsValid": true,
        "ObjectState": "Unchanged"
    })
}

fn ps51(root: &Path, rel: &str, v: &Value) {
    fixtures::write(
        root,
        rel,
        &fixtures::utf16le_bom(&fixtures::ps51_dates(&fixtures::ps_json(v))),
    );
}

fn simple_row(cmdlet: &str, run_utc: &str, object: &str) -> String {
    csv_line(&[
        "admin@contoso.example",
        cmdlet,
        &format!("{cmdlet} -Identity {object} -ForwardTo x@fabrikam.example"),
        run_utc,
        object,
    ])
}

#[test]
fn full_json_records_load_with_parameters() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let mut set = full(
        R1_OBJECT,
        "Set-InboxRule",
        1789373100000,
        "y@fabrikam.example",
    );
    set["ModifiedProperties"] = json!([{"Name": "ForwardTo", "OldValue": "x@fabrikam.example", "NewValue": "y@fabrikam.example"}]);
    ps51(
        &root,
        "Tenant/New_InboxRules.json",
        &json!([
            full(
                R1_OBJECT,
                "New-InboxRule",
                1789372800000,
                "x@fabrikam.example"
            ),
            set
        ]),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(row(&report, "Tenant/New_InboxRules.json").records_loaded, 2);
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 0);
    assert_eq!(
        text(
            &case,
            "SELECT caller || '|' || cmdlet || '|' || parameters['ForwardTo'] || '|' || parameters['Identity'] || '|' ||
                    succeeded || '|' || client_ip || '|' || data_completeness || '|' || time_tz_assumed || '|' ||
                    epoch(run_time)::BIGINT
             FROM admin_audit_events WHERE cmdlet = 'New-InboxRule'"
        ),
        "admin@contoso.example|New-InboxRule|x@fabrikam.example|contoso.example/Users/alice\\Rule1|true|198.51.100.7|full|false|1789372800"
    );
    assert_eq!(
        text(
            &case,
            "SELECT modified_properties->>'$[0].NewValue' FROM admin_audit_events WHERE cmdlet = 'Set-InboxRule'"
        ),
        "y@fabrikam.example"
    );
}

#[test]
fn csv_full_form_alone_loads_partial_rows_with_local_times() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let csv = csv_line(&[
        "ObjectModified",
        "CmdletName",
        "CmdletParameters",
        "ModifiedProperties",
        "Caller",
        "Succeeded",
        "RunDate",
    ]) + &csv_line(&[
        R1_OBJECT,
        "Set-InboxRule",
        "System.Collections.ArrayList",
        "System.Collections.ArrayList",
        "admin@contoso.example",
        "True",
        "9/14/2026 8:05:00 AM",
    ]);
    fixtures::write(
        &root,
        "Tenant/Set_InboxRules.csv",
        &fixtures::utf8_bom(&csv),
    );
    let (case, report) = ingest(dir.path());
    let f = row(&report, "Tenant/Set_InboxRules.csv");
    assert_eq!(
        (f.status, f.records_loaded),
        (FileStatus::Parsed, 1),
        "{f:#?}"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM admin_audit_events WHERE parameters IS NULL AND modified_properties IS NULL
               AND time_tz_assumed AND data_completeness = 'partial' AND epoch(run_time)::BIGINT = 1789373100"
        ),
        1
    );
}

#[test]
fn simple_summary_alone_loads_partial_rows() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = "Tenant/Simple_Mailbox_Permissions.csv";
    let csv = csv_line(SIMPLE_HEADER)
        + &simple_row("Add-MailboxPermission", "9/14/2026 8:00:00 AM", "bob");
    fixtures::write(&root, rel, &fixtures::utf8_bom(&csv));
    let (case, report) = ingest(dir.path());
    let f = row(&report, rel);
    assert_eq!(
        (f.status, f.records_loaded),
        (FileStatus::Parsed, 1),
        "{f:#?}"
    );
    assert!(
        f.warnings.iter().any(|w| w.contains("five-column")),
        "{:?}",
        f.warnings
    );
    assert_eq!(
        text(
            &case,
            "SELECT full_command || '|' || object_modified || '|' || data_completeness || '|' || time_tz_assumed || '|' ||
                    epoch(run_time)::BIGINT FROM admin_audit_events"
        ),
        "Add-MailboxPermission -Identity bob -ForwardTo x@fabrikam.example|bob|partial|false|1789372800"
    );
}

#[test]
fn simple_summary_is_superseded_by_the_full_file_and_its_flag_links() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    ps51(
        &root,
        "Tenant/New_InboxRules.json",
        &json!([full(
            R1_OBJECT,
            "New-InboxRule",
            1789372800000,
            "x@fabrikam.example"
        )]),
    );
    let simple =
        csv_line(SIMPLE_HEADER) + &simple_row("New-InboxRule", "9/14/2026 8:00:00 AM", "Rule1");
    fixtures::write(
        &root,
        "Tenant/Simple_New_InboxRule.csv",
        &fixtures::utf8_bom(&simple),
    );
    fixtures::write(
        &root,
        "Tenant/_Investigate_Simple_New_InboxRule.csv",
        &fixtures::utf8_bom(&simple),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        row(&report, "Tenant/Simple_New_InboxRule.csv").status,
        FileStatus::SkippedSuperseded
    );
    assert_eq!(count(&case, "SELECT count(*) FROM admin_audit_events"), 1);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collector_flags WHERE linked_table = 'admin_audit_events'
               AND linked_key IN (SELECT record_key FROM admin_audit_events)"
        ),
        1
    );
}

#[test]
fn user_changes_in_admin_audit_form_load_from_the_user_folder() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let bob = "bob@contoso.example";
    ps51(
        &root,
        &format!("{bob}/User_Changes_{bob}.json"),
        &json!([full(
            "contoso.example/Users/bob",
            "Set-Mailbox",
            1789376400000,
            "z@fabrikam.example"
        )]),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 0);
    assert_eq!(
        text(
            &case,
            "SELECT parameters['ForwardTo'] FROM admin_audit_events WHERE cmdlet = 'Set-Mailbox'"
        ),
        "z@fabrikam.example"
    );
}

#[test]
fn every_copy_of_an_admin_command_gets_one_key() {
    let key = |v: Value| {
        admin_audit_key(
            &Rec::new(v.as_object().unwrap(), true),
            Some(DateOrder::MonthFirst),
        )
    };
    let from_json = key(json!({
        "CmdletName": "New-InboxRule", "ObjectModified": R1_OBJECT,
        "Caller": "admin@contoso.example", "RunDate": "/Date(1789372800123)/"
    }));
    let from_summary = key(json!({
        "Caller": "admin@contoso.example", "Cmdlet": "New-InboxRule", "FullCommand": "x",
        "RunDate(UTC)": "9/14/2026 8:00:00 AM", "ObjectModified": "Rule1"
    }));
    let from_format_list = key(json!({
        "CmdletName": "New-InboxRule", "ObjectModified": R1_OBJECT,
        "Caller": "Admin@Contoso.example", "RunDate": "9/14/2026 8:00:00 AM"
    }));
    assert!(from_json.is_some());
    assert_eq!(from_json, from_summary);
    assert_eq!(from_json, from_format_list);
    let a_second_later = key(json!({
        "CmdletName": "New-InboxRule", "ObjectModified": R1_OBJECT,
        "Caller": "admin@contoso.example", "RunDate": "/Date(1789372801000)/"
    }));
    assert_ne!(from_json, a_second_later);
    assert_eq!(key(json!({"RunDate": "/Date(1)/"})), None);
}

#[test]
fn hawk_caller_and_object_shortening() {
    assert_eq!(simple_caller(None), "***");
    assert_eq!(simple_caller(Some("  ")), "***");
    assert_eq!(
        simple_caller(Some("admin@contoso.example")),
        "admin@contoso.example"
    );
    let behalf = simple_caller(Some("x/y/z/admin\" on behalf of \"tenant/helpdesk\""));
    assert_eq!(behalf, "admin on behalf of helpdesk");
    assert_eq!(simple_caller(Some(&behalf)), behalf);
    assert_eq!(short_object(Some(R1_OBJECT)), "Rule1");
    assert_eq!(short_object(Some("Rule1")), "Rule1");
    assert_eq!(short_object(None), "");
}

/// Add-MailboxPermission on `victim` by the same caller in the same second, granting `user`.
fn grant(user: &str) -> Value {
    json!({
        "ObjectModified": "victim", "CmdletName": "Add-MailboxPermission",
        "CmdletParameters": [{"Name": "Identity", "Value": "victim"}, {"Name": "User", "Value": user},
                             {"Name": "AccessRights", "Value": "FullAccess"}],
        "ModifiedProperties": [], "Caller": "Admin@contoso.example", "ExternalAccess": false,
        "Succeeded": true, "Error": "", "RunDate": "/Date(1789372800000)/",
        "OriginatingServer": "SRV01", "ClientIP": "198.51.100.7", "SessionId": "s-3",
        "AppId": null, "ClientAppId": null
    })
}

#[test]
fn commands_differing_only_in_parameters_stay_separate_rows() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = "Tenant/RBAC_Changes.json";
    ps51(&root, rel, &json!([grant("a"), grant("b")]));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let f = row(&report, rel);
    assert_eq!((f.records_loaded, f.records_duplicate), (2, 0), "{f:#?}");
    assert!(
        f.warnings.iter().any(|w| w.starts_with(
            "1 admin audit commands share a second, cmdlet, object and caller but differ in parameters"
        )),
        "{:?}",
        f.warnings
    );
    assert_eq!(
        text(
            &case,
            "SELECT string_agg(parameters['User'], ',' ORDER BY parameters['User']) FROM admin_audit_events"
        ),
        "a,b"
    );
    // The first keeps the base key; the second gets it suffixed with its parameters' hash.
    let base = text(
        &case,
        "SELECT record_key FROM admin_audit_events WHERE parameters['User'] = 'a'",
    );
    let other = text(
        &case,
        "SELECT record_key FROM admin_audit_events WHERE parameters['User'] = 'b'",
    );
    assert_eq!(base.len(), 64);
    assert_eq!(other.len(), 64 + 13);
    assert!(other.starts_with(&format!("{base}#")), "{base} {other}");
}

#[test]
fn identical_commands_merge_into_one_row() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = "Tenant/RBAC_Changes.json";
    ps51(&root, rel, &json!([grant("a"), grant("a")]));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let f = row(&report, rel);
    assert_eq!((f.records_loaded, f.records_duplicate), (1, 1), "{f:#?}");
    assert!(
        !f.warnings
            .iter()
            .any(|w| w.contains("differ in parameters")),
        "{:?}",
        f.warnings
    );
    assert_eq!(count(&case, "SELECT count(*) FROM admin_audit_events"), 1);
}

#[test]
fn a_command_differing_from_a_stored_one_in_parameters_gets_its_own_row() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    ps51(&root, "Tenant/RBAC_Changes.json", &json!([grant("a")]));
    ps51(&root, "Tenant/Set_InboxRules.json", &json!([grant("b")]));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM admin_audit_events"), 2);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM admin_audit_events WHERE contains(record_key, '#')"
        ),
        1
    );
    assert_eq!(
        text(
            &case,
            "SELECT string_agg(parameters['User'], ',' ORDER BY parameters['User']) FROM admin_audit_events"
        ),
        "a,b"
    );
}
