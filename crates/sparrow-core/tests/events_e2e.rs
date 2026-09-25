use sparrow_core::Case;
use sparrow_core::discovery::Tool;
use sparrow_core::fixtures::events::{
    ALICE, AUDIT_1, BOB, PORTAL_SIGNIN_HEADER, PORTAL_SIGNINS_CSV, SIGNIN_1, SIGNIN_3, TRACE_1,
    hawk3_events_tree, hawk4_events_tree, portal_signin_row,
};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::verify::verify_record;
use std::path::Path;

fn ingest_into(case: &mut Case, path: &Path) -> IngestReport {
    ingest_path(
        case,
        path,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap()
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

fn assert_clean(report: &IngestReport) {
    let bad: Vec<_> = report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .filter(|f| matches!(f.status, FileStatus::NotSupported | FileStatus::Error))
        .map(|f| (&f.rel_path, f.status, &f.warnings))
        .collect();
    assert!(bad.is_empty(), "{bad:#?}");
    assert!(!report.has_errors(), "{report:#?}");
}

/// Every flag naming `table` points at an existing row.
fn assert_flags_resolve(case: &Case, table: &str, expected: i64) {
    assert_eq!(
        count(
            case,
            &format!(
                "SELECT count(*) FROM collector_flags WHERE linked_table = '{table}'
                   AND linked_key IN (SELECT record_key FROM {table})"
            )
        ),
        expected,
        "{table} links"
    );
    assert_eq!(
        count(
            case,
            &format!(
                "SELECT count(*) FROM collector_flags WHERE linked_table = '{table}'
                   AND (linked_key IS NULL OR linked_key NOT IN (SELECT record_key FROM {table}))"
            )
        ),
        0,
        "{table} unresolved"
    );
}

#[test]
fn hawk4_events_capture_loads_merges_and_links() {
    let dir = tempfile::tempdir().unwrap();
    hawk4_events_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_into(&mut case, dir.path());
    assert_clean(&report);
    let u = |f: &str| format!("{ALICE}/{f}");
    for (rel, status) in [
        (
            u(&format!("Entra_Sign_In_Log_{ALICE}_{ALICE}.csv")),
            FileStatus::SkippedSuperseded,
        ),
        (
            "Tenant/EntraIDAuditLogs.csv".to_string(),
            FileStatus::SkippedSuperseded,
        ),
        (PORTAL_SIGNINS_CSV.to_string(), FileStatus::Parsed),
    ] {
        assert_eq!(row(&report, &rel).status, status, "{rel}");
    }
    for (table, n) in [
        ("signins", 3),
        ("directory_audits", 2),
        ("message_trace", 1),
        ("collector_flags", 1),
    ] {
        assert_eq!(
            count(&case, &format!("SELECT count(*) FROM {table}")),
            n,
            "{table}"
        );
    }
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT session_id || '|' || risk_level_during || '|' || epoch(event_time)::BIGINT || '|' || time_tz_assumed
                 FROM signins WHERE record_key = '{SIGNIN_1}'"
            )
        ),
        "sess-1|none|1788255000|false"
    );
    assert_flags_resolve(&case, "signins", 1);
    let v = verify_record(&case, "signins", SIGNIN_1, None).unwrap();
    assert!(v.ok, "{v:#?}");
    assert_eq!(v.sightings.len(), 2);
    let v = verify_record(&case, "directory_audits", &AUDIT_1.to_lowercase(), None).unwrap();
    assert!(v.ok, "{v:#?}");
    let trace_key = "0e0e0e0e-0000-4000-8000-000000000003|x@fabrikam.example";
    let v = verify_record(&case, "message_trace", trace_key, None).unwrap();
    assert!(v.ok, "{v:#?}");

    let again = ingest_into(&mut case, dir.path());
    assert!(
        again
            .collections
            .iter()
            .flat_map(|c| &c.files)
            .all(|f| f.status != FileStatus::Parsed && f.status != FileStatus::Error),
        "{again:#?}"
    );
    assert_eq!(count(&case, "SELECT count(*) FROM signins"), 3);
}

#[test]
fn hawk3_events_capture_loads_and_links() {
    let dir = tempfile::tempdir().unwrap();
    hawk3_events_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_into(&mut case, dir.path());
    assert_clean(&report);
    for (rel, status) in [
        ("Tenant/New_InboxRules.csv", FileStatus::SkippedSuperseded),
        (
            "Tenant/Simple_New_InboxRule.csv",
            FileStatus::SkippedSuperseded,
        ),
        ("Tenant/New_InboxRules.json", FileStatus::Parsed),
        ("2026-09-14_logs.csv", FileStatus::Parsed),
    ] {
        assert_eq!(row(&report, rel).status, status, "{rel}");
    }
    for (table, n) in [
        ("admin_audit_events", 3),
        ("message_trace", 2),
        ("mailbox_audit_legacy", 1),
        ("collector_flags", 2),
    ] {
        assert_eq!(
            count(&case, &format!("SELECT count(*) FROM {table}")),
            n,
            "{table}"
        );
    }
    assert_flags_resolve(&case, "admin_audit_events", 2);
    assert_eq!(
        text(
            &case,
            "SELECT parameters['ForwardTo'] FROM admin_audit_events WHERE cmdlet = 'Set-Mailbox'"
        ),
        "z@fabrikam.example"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collection_log l JOIN source_files s ON s.file_id = l.file_id
             WHERE s.rel_path = 'Hawk.log' AND l.ts IS NOT NULL AND l.tz_assumed"
        ),
        2
    );
    assert_eq!(text(&case, "SELECT tool_version FROM collections"), "3.1.0");
    assert_eq!(
        text(
            &case,
            "SELECT mailbox_upn || '|' || array_to_string(subjects, ',') FROM mailbox_audit_legacy"
        ),
        format!("{BOB}|Invoice 42")
    );
    let key = format!("{TRACE_1}|x@fabrikam.example");
    let v = verify_record(&case, "message_trace", &key, None).unwrap();
    assert!(v.ok, "{v:#?}");
}

#[test]
fn portal_xlsx_beside_a_hawk_capture_joins_its_signins() {
    let dir = tempfile::tempdir().unwrap();
    hawk4_events_tree(dir.path());
    let mut wb = rust_xlsxwriter::Workbook::new();
    let ws = wb.add_worksheet();
    let rows = [
        PORTAL_SIGNIN_HEADER
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        portal_signin_row(
            SIGNIN_1,
            "2026-09-01T09:30:00Z",
            "Lagos, Lagos, NG",
            "No",
            "sess-1",
        ),
        portal_signin_row(
            SIGNIN_3,
            "2026-09-01T11:00:00Z",
            "Seattle, Washington, US",
            "Yes",
            "sess-3",
        ),
    ];
    for (r, cells) in rows.iter().enumerate() {
        for (c, v) in cells.iter().enumerate() {
            if !v.is_empty() {
                ws.write_string(r as u32, c as u16, v).unwrap();
            }
        }
    }
    let name = "InteractiveSignins_2026-09-01_2026-09-10.xlsx";
    sparrow_core::fixtures::write(
        &dir.path().join("exports"),
        name,
        &wb.save_to_buffer().unwrap(),
    );
    let mut case = Case::in_memory().unwrap();
    let report = ingest_into(&mut case, dir.path());
    assert_clean(&report);
    assert_eq!(report.collections.len(), 2);
    assert_eq!(report.collections[1].tool, Tool::PortalExport);
    let f = row(&report, name);
    assert_eq!((f.records_loaded, f.records_duplicate), (0, 2), "{f:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM signins"), 3);
    let v = verify_record(&case, "signins", SIGNIN_3, None).unwrap();
    assert!(v.ok, "{v:#?}");
    assert_eq!(v.sightings.len(), 2);
}
