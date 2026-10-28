//! The Entra admin center audit log download (CSV and JSON): classification, parsing into
//! `directory_audits`, de-duplication of CSV rows (no audit id), completeness and availability.

use chrono::TimeZone;
use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::discovery::Tool::{Hawk, Invictus, PortalExport};
use sparrow_core::discovery::registry::Registry;
use sparrow_core::fixtures::{self, csv_line, utf8_bom};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::profile::availability::compute;
use sparrow_core::profile::{ProfileOptions, refresh};
use sparrow_core::verify::verify_record;
use std::path::{Path, PathBuf};

const CSV_REL: &str = "AuditLogs_2026-10-23.csv";
const T0: &str = "2026-10-23T18:47:17.7839777+00:00";
const T0_EPOCH: i64 = 1792781237;
const CORR: &str = "C0C0C0C0-0000-4000-8000-0000000000B1";

/// The portal CSV's 86 columns, in Microsoft's order.
fn columns() -> Vec<String> {
    let mut c: Vec<String> = [
        "Date (UTC)",
        "CorrelationId",
        "Service",
        "Category",
        "Activity",
        "Result",
        "ResultReason",
        "User Agent",
        "ActorType",
        "ActorDisplayName",
        "ActorObjectId",
        "ActorUserPrincipalName",
        "IPAddress",
        "ActorHomeTenantId",
        "ActorHomeTenantName",
        "ActorServicePrincipalId",
        "ActorServicePrincipalName",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for n in 1..=3 {
        for f in ["Type", "DisplayName", "ObjectId", "UserPrincipalName"] {
            c.push(format!("Target{n}{f}"));
        }
        for m in 1..=5 {
            for f in ["Name", "OldValue", "NewValue"] {
                c.push(format!("Target{n}ModifiedProperty{m}{f}"));
            }
        }
    }
    for k in 1..=6 {
        c.push(format!("AdditionalDetail{k}Key"));
        c.push(format!("AdditionalDetail{k}Value"));
    }
    c
}

type Cells = Vec<(String, String)>;

fn cells(pairs: &[(&str, &str)]) -> Cells {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// A portal CSV (BOM, every field quoted). `reverse` writes the columns in the opposite order.
fn portal_csv(rows: &[Cells], reverse: bool) -> Vec<u8> {
    let mut cols = columns();
    assert_eq!(cols.len(), 86);
    if reverse {
        cols.reverse();
    }
    let line = |f: &dyn Fn(&str) -> String| {
        let fields: Vec<String> = cols.iter().map(|c| f(c)).collect();
        csv_line(&fields.iter().map(String::as_str).collect::<Vec<_>>())
    };
    let mut out = line(&|c| c.to_string());
    for r in rows {
        out += &line(&|c| {
            r.iter()
                .find(|(k, _)| k == c)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        });
    }
    utf8_bom(&out)
}

fn user_row() -> Cells {
    cells(&[
        ("Date (UTC)", T0),
        ("CorrelationId", CORR),
        ("Service", "Core Directory"),
        ("Category", "UserManagement"),
        ("Activity", "Reset password (by admin)"),
        ("Result", "success"),
        ("User Agent", "Mozilla/5.0"),
        ("ActorType", "User"),
        ("ActorObjectId", "AAAAAAAA-1111-4111-8111-111111111111"),
        ("ActorUserPrincipalName", "Admin@Contoso.example"),
        ("IPAddress", "203.0.113.7"),
        ("Target1Type", "User"),
        ("Target1DisplayName", "Alice"),
        ("Target1ObjectId", "11111111-1111-4111-8111-111111111111"),
        ("Target1UserPrincipalName", "Alice@Contoso.example"),
        (
            "Target1ModifiedProperty1Name",
            "Included Updated Properties",
        ),
        ("Target1ModifiedProperty1OldValue", "\"\""),
        ("Target1ModifiedProperty1NewValue", "\"PasswordProfile\""),
        ("Target1ModifiedProperty2Name", "StrongAuthenticationMethod"),
        ("Target1ModifiedProperty2OldValue", "[]"),
        ("Target1ModifiedProperty2NewValue", "[{\"MethodType\":6}]"),
        ("AdditionalDetail1Key", "User-Agent"),
        ("AdditionalDetail1Value", "Mozilla/5.0"),
        ("AdditionalDetail2Key", "Reason"),
        ("AdditionalDetail2Value", "Helpdesk ticket"),
    ])
}

fn app_row() -> Cells {
    cells(&[
        ("Date (UTC)", "2026-10-23T19:01:02.5000000+00:00"),
        ("CorrelationId", "C0C0C0C0-0000-4000-8000-0000000000B2"),
        ("Service", "Device Registration Service"),
        ("Category", "Device"),
        ("Activity", "Delete Windows Hello for Business credential"),
        ("Result", "success"),
        ("ActorType", "Application"),
        ("ActorDisplayName", "Microsoft Substrate Management"),
        (
            "ActorServicePrincipalId",
            "BBBBBBBB-2222-4222-8222-222222222222",
        ),
        ("Target1Type", "Other"),
        ("Target1DisplayName", "Workstation 7"),
    ])
}

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

fn json_of(case: &Case, sql: &str) -> Value {
    serde_json::from_str(&text(case, sql)).unwrap()
}

// ---- classification ----

fn csv_head() -> Vec<u8> {
    portal_csv(&[], false)
}

fn graph_audit_json() -> String {
    json!([{
        "id": "Directory_0E0E0E0E-0000-4000-8000-0000000000F1_ABCDE_1",
        "category": "UserManagement",
        "correlationId": CORR,
        "result": "success",
        "resultReason": "",
        "activityDisplayName": "Disable account",
        "activityDateTime": "2026-10-23T18:47:17.7839777Z",
        "loggedByService": "Core Directory",
        "operationType": "Update",
        "initiatedBy": {"user": {"id": "AAAAAAAA-1111-4111-8111-111111111111",
            "displayName": "Admin", "userPrincipalName": "Admin@Contoso.example",
            "ipAddress": "203.0.113.7"}},
        "targetResources": [{"id": "11111111-1111-4111-8111-111111111111", "displayName": "Alice",
            "type": "User", "userPrincipalName": "Alice@Contoso.example",
            "modifiedProperties": [{"displayName": "AccountEnabled", "oldValue": "[true]",
                "newValue": "[false]"}]}],
        "additionalDetails": [{"key": "User-Agent", "value": "Mozilla/5.0"}]
    }])
    .to_string()
}

fn artifact(tool: sparrow_core::discovery::Tool, rel: &str, head: &[u8]) -> Option<&'static str> {
    Registry::builtin()
        .classify_with_head(tool, rel, Some(head))
        .map(|c| c.artifact_id)
}

#[test]
fn portal_csv_header_is_entra_audit_whatever_the_name_or_tool() {
    let head = csv_head();
    for (tool, rel) in [
        (PortalExport, "export.csv"),
        (Hawk, "Tenant/whatever.csv"),
        (Invictus, "misc/x.csv"),
    ] {
        let c = Registry::builtin()
            .classify_with_head(tool, rel, Some(&head))
            .unwrap();
        assert_eq!(
            (c.artifact_id, c.target),
            ("portal.entra_audit", "directory_audits")
        );
    }
}

#[test]
fn signin_and_ual_portal_headers_are_unaffected() {
    let signins = "\u{feff}Date (UTC),Request ID,User agent,Correlation ID,User ID,Incoming token type,Application ID ,Incoming token type\n";
    assert_eq!(
        artifact(PortalExport, "s.csv", signins.as_bytes()),
        Some("portal.entra_signins")
    );
    let ual = "RecordId,CreationDate,RecordType,Operation,UserId,AuditData\r\n";
    assert_eq!(
        artifact(PortalExport, "u.csv", ual.as_bytes()),
        Some("portal.ual")
    );
    // A header with only some of the audit columns is not the audit export.
    let partial = "Date (UTC),CorrelationId,Activity,Result\r\n";
    assert_eq!(artifact(PortalExport, "p.csv", partial.as_bytes()), None);
}

#[test]
fn portal_json_in_a_bare_folder_is_entra_audit() {
    let json = graph_audit_json();
    for tool in [PortalExport, Hawk, Invictus] {
        assert_eq!(
            artifact(tool, "AuditLogs.json", json.as_bytes()),
            Some("portal.entra_audit"),
            "{tool:?}"
        );
    }
    // After a BOM and whitespace, with the keys in another case, and cut off mid-record.
    let pascal = json.replace("activityDateTime", "ActivityDateTime");
    let spaced = format!("\u{feff}\r\n  {pascal}");
    assert_eq!(
        artifact(PortalExport, "a.json", spaced.as_bytes()),
        Some("portal.entra_audit")
    );
    // A first element cut off by the end of the head is not classified (see the sniff tests below).
    let cut = &json.as_bytes()[..json.find("additionalDetails").unwrap()];
    assert_eq!(artifact(PortalExport, "a.json", cut), None);
    let c = Registry::builtin()
        .classify_with_head(PortalExport, "a.json", Some(json.as_bytes()))
        .unwrap();
    assert_eq!(c.target, "directory_audits");
}

#[test]
fn path_patterns_win_for_json() {
    let json = graph_audit_json();
    assert_eq!(
        artifact(
            Invictus,
            "EntraID/20260910-100200-AuditLogs/20260910100200-AuditLogs.json",
            json.as_bytes()
        ),
        Some("inv.entra_audit")
    );
    assert_eq!(
        artifact(
            Invictus,
            "EntraID/20260910-100200-AuditLogs/Merged/AuditLogs-Combined.json",
            json.as_bytes()
        ),
        Some("inv.entra_audit.merged")
    );
    assert_eq!(
        artifact(Hawk, "Tenant/EntraIDAuditLogs.json", json.as_bytes()),
        Some("hawk.tenant.entra_audit")
    );
}

#[test]
fn other_json_is_not_entra_audit() {
    let signins = json!([{"id": "x", "createdDateTime": "2026-10-23T18:47:17Z",
        "userPrincipalName": "alice@contoso.example", "ipAddress": "203.0.113.7"}])
    .to_string();
    assert_eq!(artifact(PortalExport, "s.json", signins.as_bytes()), None);
    // An object (not an array) holding the audit keys is not the download.
    let object = format!(
        "{{\"activityDateTime\":1,\"loggedByService\":2,\"targetResources\":[], \"x\":{}}}",
        "1"
    );
    assert_eq!(artifact(PortalExport, "o.json", object.as_bytes()), None);
    // An array missing one of the three keys.
    let two = graph_audit_json().replace("loggedByService", "logged");
    assert_eq!(artifact(PortalExport, "t.json", two.as_bytes()), None);
}

// ---- parsing ----

#[test]
fn csv_user_actor_row_maps_every_column() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, CSV_REL, &portal_csv(&[user_row()], false));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let f = row(&report, CSV_REL);
    assert_eq!(f.artifact_id.as_deref(), Some("portal.entra_audit"));
    assert_eq!(
        (f.status, f.records_loaded),
        (FileStatus::Parsed, 1),
        "{f:#?}"
    );
    assert_eq!(count(&case, "SELECT count(*) FROM directory_audits"), 1);
    assert_eq!(
        text(
            &case,
            "SELECT concat_ws('|', activity, category, coalesce(operation_type, '-'), result,
                    coalesce(result_reason, '-'), logged_by_service, initiated_by_upn, initiated_by_user_id,
                    coalesce(initiated_by_app_id, '-'), coalesce(initiated_by_app_name, '-'), initiated_by_ip,
                    correlation_id, time_tz_assumed, data_completeness)
             FROM directory_audits"
        ),
        "Reset password (by admin)|UserManagement|-|success|-|Core Directory|admin@contoso.example|\
         aaaaaaaa-1111-4111-8111-111111111111|-|-|203.0.113.7|c0c0c0c0-0000-4000-8000-0000000000b1|false|partial"
    );
    assert_eq!(
        count(&case, "SELECT epoch_us(event_time) FROM directory_audits"),
        T0_EPOCH * 1_000_000 + 783_977
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM directory_audits WHERE audit_id IS NULL AND record_key LIKE 'csvrow:%'
               AND length(record_key) = 7 + 64"
        ),
        1
    );
    assert_eq!(
        json_of(
            &case,
            "SELECT CAST(targets AS VARCHAR) FROM directory_audits"
        ),
        json!([{
            "type": "User", "displayName": "Alice",
            "id": "11111111-1111-4111-8111-111111111111",
            "userPrincipalName": "Alice@Contoso.example",
            "modifiedProperties": [
                {"displayName": "Included Updated Properties", "oldValue": "\"\"",
                 "newValue": "\"PasswordProfile\""},
                {"displayName": "StrongAuthenticationMethod", "oldValue": "[]",
                 "newValue": "[{\"MethodType\":6}]"}
            ]
        }])
    );
    assert_eq!(
        json_of(
            &case,
            "SELECT CAST(modified_properties AS VARCHAR) FROM directory_audits"
        ),
        json!([
            {"target": "Alice@Contoso.example", "property": "Included Updated Properties",
             "old": "\"\"", "new": "\"PasswordProfile\""},
            {"target": "Alice@Contoso.example", "property": "StrongAuthenticationMethod",
             "old": "[]", "new": "[{\"MethodType\":6}]"}
        ])
    );
    assert_eq!(
        json_of(
            &case,
            "SELECT CAST(additional_details AS VARCHAR) FROM directory_audits"
        ),
        json!([{"key": "User-Agent", "value": "Mozilla/5.0"},
               {"key": "Reason", "value": "Helpdesk ticket"}])
    );
    // raw: the non-empty cells only, as {column: value}.
    let raw = json_of(&case, "SELECT CAST(raw AS VARCHAR) FROM directory_audits");
    let raw = raw.as_object().unwrap();
    assert_eq!(raw.len(), user_row().len());
    assert_eq!(raw["Date (UTC)"], T0);
    assert_eq!(raw["Target1ModifiedProperty1OldValue"], "\"\"");
    assert!(!raw.contains_key("ResultReason"));
    assert!(!raw.contains_key("Target2Type"));
}

#[test]
fn csv_application_actor_row_has_no_upn_app_id_or_ip() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, CSV_REL, &portal_csv(&[app_row()], false));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        text(
            &case,
            "SELECT concat_ws('|', initiated_by_app_name, coalesce(initiated_by_upn, '-'),
                    coalesce(initiated_by_app_id, '-'), coalesce(initiated_by_ip, '-'),
                    coalesce(initiated_by_user_id, '-'), activity, logged_by_service)
             FROM directory_audits"
        ),
        "Microsoft Substrate Management|-|-|-|-|Delete Windows Hello for Business credential|\
         Device Registration Service"
    );
    assert_eq!(
        json_of(
            &case,
            "SELECT CAST(targets AS VARCHAR) FROM directory_audits"
        ),
        json!([{"type": "Other", "displayName": "Workstation 7", "modifiedProperties": []}])
    );
    // No properties: modified_properties and additional_details stay NULL.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM directory_audits
             WHERE modified_properties IS NULL AND additional_details IS NULL"
        ),
        1
    );
    // The service principal id is kept only in raw.
    assert_eq!(
        text(
            &case,
            "SELECT raw->>'$.ActorServicePrincipalId' FROM directory_audits"
        ),
        "BBBBBBBB-2222-4222-8222-222222222222"
    );
}

#[test]
fn same_row_in_two_files_with_different_column_order_is_one_row_two_sightings() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, "AuditLogs_a.csv", &portal_csv(&[user_row()], false));
    fixtures::write(&root, "AuditLogs_b.csv", &portal_csv(&[user_row()], true));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let (a, b) = (
        row(&report, "AuditLogs_a.csv"),
        row(&report, "AuditLogs_b.csv"),
    );
    assert_eq!((a.records_loaded, a.records_duplicate), (1, 0), "{a:#?}");
    assert_eq!((b.records_loaded, b.records_duplicate), (0, 1), "{b:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM directory_audits"), 1);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources s JOIN directory_audits d ON d.record_key = s.record_key
             WHERE s.table_name = 'directory_audits'"
        ),
        2
    );
}

#[test]
fn same_row_twice_in_one_file_is_one_row_and_a_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        CSV_REL,
        &portal_csv(&[user_row(), app_row(), user_row()], false),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let f = row(&report, CSV_REL);
    assert_eq!(
        (f.records_read, f.records_loaded, f.records_duplicate),
        (3, 2, 1),
        "{f:#?}"
    );
    assert_eq!(count(&case, "SELECT count(*) FROM directory_audits"), 2);
    // Both sightings of the repeated row are kept.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'directory_audits'"
        ),
        3
    );
}

#[test]
fn rows_that_differ_in_one_cell_are_two_rows() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let mut other = user_row();
    other.push(("ResultReason".into(), "second try".into()));
    fixtures::write(&root, CSV_REL, &portal_csv(&[user_row(), other], false));
    let (case, _) = ingest(dir.path());
    assert_eq!(
        count(
            &case,
            "SELECT count(DISTINCT record_key) FROM directory_audits"
        ),
        2
    );
}

#[test]
fn three_targets_with_five_properties_each_load_all_fifteen() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let mut r = cells(&[
        ("Date (UTC)", T0),
        ("CorrelationId", CORR),
        ("Activity", "Update user"),
        ("Result", "success"),
        ("ActorType", "User"),
        ("ActorUserPrincipalName", "admin@contoso.example"),
    ]);
    for n in 1..=3 {
        r.push((format!("Target{n}Type"), "User".into()));
        r.push((
            format!("Target{n}UserPrincipalName"),
            format!("user{n}@contoso.example"),
        ));
        for m in 1..=5 {
            r.push((
                format!("Target{n}ModifiedProperty{m}Name"),
                format!("P{n}{m}"),
            ));
            r.push((
                format!("Target{n}ModifiedProperty{m}OldValue"),
                format!("\"o{n}{m}\""),
            ));
            r.push((
                format!("Target{n}ModifiedProperty{m}NewValue"),
                format!("\"n{n}{m}\""),
            ));
        }
    }
    fixtures::write(&root, CSV_REL, &portal_csv(&[r], false));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        count(
            &case,
            "SELECT json_array_length(modified_properties) FROM directory_audits"
        ),
        15
    );
    assert_eq!(
        count(
            &case,
            "SELECT json_array_length(targets) FROM directory_audits"
        ),
        3
    );
    assert_eq!(
        text(
            &case,
            "SELECT modified_properties->>'$[14].target' || '|' || (modified_properties->>'$[14].property') || '|' ||
                    (modified_properties->>'$[14].new') || '|' || (modified_properties->>'$[0].target')
             FROM directory_audits"
        ),
        "user3@contoso.example|P35|\"n35\"|user1@contoso.example"
    );
}

#[test]
fn empty_targets_and_nameless_properties_are_left_out() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let mut r = user_row();
    // Target 2 is empty; target 3 has only a property with no name (and values) which is dropped,
    // but its type keeps the target.
    r.extend(cells(&[
        ("Target3Type", "Group"),
        ("Target3ModifiedProperty1OldValue", "\"x\""),
        ("Target3ModifiedProperty1NewValue", "\"y\""),
        ("AdditionalDetail4Value", "orphan value"),
    ]));
    fixtures::write(&root, CSV_REL, &portal_csv(&[r], false));
    let (case, _) = ingest(dir.path());
    let targets = json_of(
        &case,
        "SELECT CAST(targets AS VARCHAR) FROM directory_audits",
    );
    let targets = targets.as_array().unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(
        targets[1],
        json!({"type": "Group", "modifiedProperties": []})
    );
    assert_eq!(
        count(
            &case,
            "SELECT json_array_length(additional_details) FROM directory_audits"
        ),
        2
    );
}

#[test]
fn quoted_cell_with_comma_and_newline_survives() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let mut r = user_row();
    r.retain(|(k, _)| k != "Target1DisplayName");
    r.push((
        "Target1DisplayName".into(),
        "Smith, Alice\nOps \"HQ\"".into(),
    ));
    fixtures::write(&root, CSV_REL, &portal_csv(&[r, app_row()], false));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM directory_audits"), 2);
    assert_eq!(
        text(
            &case,
            "SELECT targets->>'$[0].displayName' FROM directory_audits WHERE initiated_by_upn IS NOT NULL"
        ),
        "Smith, Alice\nOps \"HQ\""
    );
}

#[test]
fn portal_json_is_keyed_by_id_and_full() {
    let dir = tempfile::tempdir().unwrap();
    // A bare folder holding only the download: a portal_export collection.
    let folder = dir.path().join("downloads");
    fixtures::write(&folder, "AuditLogs.json", graph_audit_json().as_bytes());
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let f = row(&report, "AuditLogs.json");
    assert_eq!(f.artifact_id.as_deref(), Some("portal.entra_audit"));
    assert_eq!(
        (f.status, f.records_loaded),
        (FileStatus::Parsed, 1),
        "{f:#?}"
    );
    assert_eq!(
        text(
            &case,
            "SELECT concat_ws('|', record_key, audit_id, activity, operation_type, initiated_by_upn,
                    initiated_by_ip, data_completeness) FROM directory_audits"
        ),
        "directory_0e0e0e0e-0000-4000-8000-0000000000f1_abcde_1|\
         directory_0e0e0e0e-0000-4000-8000-0000000000f1_abcde_1|Disable account|Update|\
         admin@contoso.example|203.0.113.7|full"
    );
    assert_eq!(text(&case, "SELECT tool FROM collections"), "portal_export");
}

#[test]
fn csv_and_json_copies_of_one_event_are_separate_rows() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, CSV_REL, &portal_csv(&[user_row()], false));
    fixtures::write(&root, "AuditLogs.json", graph_audit_json().as_bytes());
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        text(
            &case,
            "SELECT string_agg(CAST(data_completeness AS VARCHAR), ',' ORDER BY data_completeness)
             FROM directory_audits"
        ),
        "full,partial"
    );
}

#[test]
fn verify_succeeds_on_a_csv_row() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, CSV_REL, &portal_csv(&[user_row(), app_row()], false));
    let (case, _) = ingest(dir.path());
    let key = text(
        &case,
        "SELECT record_key FROM directory_audits WHERE initiated_by_upn IS NOT NULL",
    );
    assert!(key.starts_with("csvrow:"));
    let v = verify_record(&case, "directory_audits", &key, None).unwrap();
    assert!(v.ok, "{v:#?}");
    assert_eq!(v.sightings.len(), 1);
}

#[test]
fn availability_shows_entra_audit_for_a_case_holding_only_the_portal_csv() {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("downloads");
    fixtures::write(
        &folder,
        CSV_REL,
        &portal_csv(&[user_row(), app_row()], false),
    );
    let (mut case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(text(&case, "SELECT tool FROM collections"), "portal_export");
    let as_of = chrono::Utc.with_ymd_and_hms(2026, 10, 30, 0, 0, 0).unwrap();
    refresh(
        &mut case,
        &ProfileOptions {
            as_of: Some(as_of),
            ..Default::default()
        },
    )
    .unwrap();
    let rows = compute(case.conn(), as_of).unwrap();
    let r = rows
        .iter()
        .find(|r| r.evidence == "directory_audits")
        .expect("directory_audits row");
    assert_eq!(r.status, "collected", "{r:?}");
    assert_eq!(r.rows, 2);
}

// ---- round 2 ----

#[test]
fn csv_keys_cannot_collide_through_newlines_in_values() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let base = |activity: &str, category: Option<&str>| {
        let mut r = cells(&[
            ("Date (UTC)", T0),
            ("CorrelationId", CORR),
            ("Activity", activity),
            ("Result", "success"),
        ]);
        if let Some(c) = category {
            r.push(("Category".into(), c.into()));
        }
        r
    };
    fixtures::write(
        &root,
        CSV_REL,
        &portal_csv(
            &[
                base("reset\ncategory=UserManagement", None),
                base("reset", Some("UserManagement")),
            ],
            false,
        ),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM directory_audits"), 2);
}

#[test]
fn json_sniff_checks_object_keys_not_substrings() {
    let strings =
        json!([{"fields": ["activityDateTime", "loggedByService", "targetResources"]}]).to_string();
    assert_eq!(artifact(PortalExport, "f.json", strings.as_bytes()), None);
    // Keys on a later element only.
    let later =
        json!([{"x": 1}, {"activityDateTime": 1, "loggedByService": 2, "targetResources": []}])
            .to_string();
    assert_eq!(artifact(PortalExport, "l.json", later.as_bytes()), None);
    // First element is not an object.
    assert_eq!(
        artifact(PortalExport, "n.json", b"[1, \"activityDateTime\"]"),
        None
    );
    // First element cut off by the end of the head.
    let json = graph_audit_json();
    let cut = &json.as_bytes()[..json.find("loggedByService").unwrap() + 5];
    assert_eq!(artifact(PortalExport, "c.json", cut), None);
    // Unparseable.
    assert_eq!(
        artifact(PortalExport, "b.json", b"[{\"activityDateTime\" 1"),
        None
    );
}

#[test]
fn json_sniff_accepts_a_good_first_element_with_a_truncated_second() {
    let one = graph_audit_json();
    let element = one
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let two = format!("[{element},{element}]");
    let cut = &two.as_bytes()[..element.len() + 1 + 40];
    assert!(std::str::from_utf8(cut).is_ok());
    assert_eq!(
        artifact(PortalExport, "t.json", cut),
        Some("portal.entra_audit")
    );
}

#[test]
fn classify_file_gives_a_pattern_owned_json_its_path_id() {
    let dir = tempfile::tempdir().unwrap();
    let rel = "Tenant/EntraIDAuditLogs.json";
    fixtures::write(dir.path(), rel, graph_audit_json().as_bytes());
    let c = Registry::builtin()
        .classify_file(Hawk, rel, &dir.path().join(rel))
        .unwrap();
    assert_eq!(c.artifact_id, "hawk.tenant.entra_audit");
    fixtures::write(dir.path(), "bare.json", graph_audit_json().as_bytes());
    let c = Registry::builtin()
        .classify_file(PortalExport, "bare.json", &dir.path().join("bare.json"))
        .unwrap();
    assert_eq!(c.artifact_id, "portal.entra_audit");
}

const HAWK_A1: &str = "Directory_0E0E0E0E-0000-4000-8000-000000000001_ABCDE_1";

fn hawk_audit_csv() -> String {
    csv_line(&[
        "ActivityDateTime",
        "ActivityDisplayName",
        "AdditionalDetails",
        "Category",
        "CorrelationId",
        "Id",
        "InitiatedBy",
        "LoggedByService",
        "OperationType",
        "Result",
        "ResultReason",
        "TargetResources",
    ]) + &csv_line(&[
        "2026-10-23T18:47:17Z",
        "Update user",
        "System.Collections.Generic.List`1[Microsoft.Graph.PowerShell.Models.MicrosoftGraphKeyValue]",
        "UserManagement",
        "d0d0d0d0-0000-4000-8000-000000000001",
        HAWK_A1,
        "Microsoft.Graph.PowerShell.Models.MicrosoftGraphAuditActivityInitiator",
        "Core Directory",
        "Update",
        "success",
        "",
        "Microsoft.Graph.PowerShell.Models.MicrosoftGraphTargetResource",
    ])
}

#[test]
fn hawk_csv_first_then_json_twin_stays_partial_with_both_sightings() {
    let mut case = Case::in_memory().unwrap();
    let run = |case: &mut Case, name: &str, rel: &str, bytes: &[u8]| {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("cap");
        fixtures::write(&root, "Hawk.log", fixtures::HAWK_LOG.as_bytes());
        fixtures::write(&root, rel, bytes);
        let report = ingest_path(
            case,
            base.path(),
            &ParserRegistry::builtin(),
            &IngestOptions::default(),
        )
        .unwrap();
        assert!(!report.has_errors(), "{name}: {report:#?}");
        assert_eq!(
            row(&report, rel).records_loaded + row(&report, rel).records_duplicate,
            1,
            "{name}"
        );
    };
    run(
        &mut case,
        "csv",
        "Tenant/EntraIDAuditLogs.csv",
        hawk_audit_csv().as_bytes(),
    );
    let json = json!([{
        "Id": HAWK_A1, "ActivityDateTime": "2026-10-23T18:47:17Z", "ActivityDisplayName": "Update user",
        "Category": "UserManagement", "CorrelationId": "d0d0d0d0-0000-4000-8000-000000000001",
        "LoggedByService": "Core Directory", "OperationType": "Update", "Result": "success",
        "InitiatedBy": {"User": {"UserPrincipalName": "admin@contoso.example"}},
        "TargetResources": [{"Id": "1", "UserPrincipalName": "alice@contoso.example",
            "ModifiedProperties": [{"DisplayName": "AccountEnabled", "OldValue": "[true]", "NewValue": "[false]"}]}],
        "AdditionalDetails": []
    }]);
    run(
        &mut case,
        "json",
        "Tenant/EntraIDAuditLogs.json",
        fixtures::ps_json(&json).as_bytes(),
    );
    assert_eq!(count(&case, "SELECT count(*) FROM collections"), 2);
    assert_eq!(count(&case, "SELECT count(*) FROM directory_audits"), 1);
    // The row stays as first loaded: still partial. The JSON copy only filled columns that were NULL.
    assert_eq!(
        text(
            &case,
            "SELECT CAST(data_completeness AS VARCHAR) FROM directory_audits"
        ),
        "partial"
    );
    assert_eq!(
        text(&case, "SELECT initiated_by_upn FROM directory_audits"),
        "admin@contoso.example"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'directory_audits'"
        ),
        2
    );
}

#[test]
fn portal_csv_with_a_dotted_user_agent_is_not_a_placeholder_and_warns_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let mut r = user_row();
    r.retain(|(k, _)| k != "User Agent");
    r.push(("User Agent".into(), "Microsoft.OData.Client/7.12.5".into()));
    r.push((
        "Target1ModifiedProperty3Name".into(),
        "Microsoft.Graph.PowerShell.Models.X".into(),
    ));
    fixtures::write(&root, CSV_REL, &portal_csv(&[r], false));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let f = row(&report, CSV_REL);
    assert_eq!(f.records_loaded, 1);
    assert!(f.warnings.is_empty(), "{:?}", f.warnings);
    assert_eq!(
        text(
            &case,
            "SELECT raw->>'$.\"User Agent\"' FROM directory_audits"
        ),
        "Microsoft.OData.Client/7.12.5"
    );
}

#[test]
fn a_folder_holding_only_the_portal_csv_resolves_to_the_home_tenant_of_its_user_actors() {
    const HOME: &str = "bbbbbbbb-0000-4000-8000-000000000002";
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("downloads");
    let mut user = user_row();
    user.push(("ActorHomeTenantId".into(), HOME.to_uppercase()));
    // An application actor's home tenant is not evidence.
    let mut app = app_row();
    app.push((
        "ActorHomeTenantId".into(),
        "cccccccc-0000-4000-8000-000000000003".into(),
    ));
    fixtures::write(&folder, CSV_REL, &portal_csv(&[user, app], false));
    let (mut case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(text(&case, "SELECT tenant_key FROM collections"), HOME);
    assert_eq!(
        text(&case, "SELECT tenant_id_source FROM tenant"),
        "directory_audit_actor_home_tenant"
    );
}
