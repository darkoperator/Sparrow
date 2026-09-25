use sparrow_core::Case;
use sparrow_core::discovery::Tool;
use sparrow_core::fixtures::hawk3::{BOB, HAWK3_PURVIEW, hawk3_tree};
use sparrow_core::fixtures::hawk4::{ALICE, HAWK4_MTSUMMARY, HAWK4_PURVIEW, hawk4_tree};
use sparrow_core::fixtures::portal::{PORTAL_MTSUMMARY, PORTAL_PURVIEW, portal_tree};
use sparrow_core::fixtures::ual;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::verify::verify_record;
use std::path::Path;

fn ingest_into(case: &mut Case, base: &Path) -> IngestReport {
    ingest_path(
        case,
        base,
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

#[test]
fn hawk4_capture_loads_ual_with_dedup_superseding_and_provenance() {
    let dir = tempfile::tempdir().unwrap();
    hawk4_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_into(&mut case, dir.path());
    assert_eq!(report.collections.len(), 1);
    assert_eq!(report.collections[0].tool, Tool::Hawk);
    assert!(!report.has_errors(), "{report:#?}");

    let u = |f: &str| format!("{ALICE}/{f}");
    let expect = [
        ("Tenant/Admin_Inbox_Rules_Creation.json", FileStatus::Parsed),
        (
            "Tenant/Admin_Inbox_Rules_Creation.csv",
            FileStatus::SkippedSuperseded,
        ),
        (
            "Tenant/Simple_Admin_Inbox_Rules_Creation.json",
            FileStatus::SkippedSuperseded,
        ),
        ("Tenant/EntraIDUsers.json", FileStatus::Parsed),
        (HAWK4_MTSUMMARY, FileStatus::Parsed),
    ];
    for (rel, status) in expect {
        assert_eq!(row(&report, rel).status, status, "{rel}");
    }
    assert_eq!(
        row(
            &report,
            &u("Converted_Authentication_Logs_alice@contoso.example.json")
        )
        .status,
        FileStatus::SkippedSuperseded
    );
    assert_eq!(
        row(&report, &u("ExchangeItem_Simple_alice@contoso.example.csv")).status,
        FileStatus::Parsed
    );
    assert_eq!(
        row(
            &report,
            &u("Raw_Authentication_Logs_alice@contoso.example.json")
        )
        .status,
        FileStatus::Parsed
    );
    let p = row(&report, HAWK4_PURVIEW);
    assert_eq!(p.artifact_id.as_deref(), Some("portal.ual"));
    assert_eq!((p.records_loaded, p.records_duplicate), (3, 1));
    assert_eq!(
        row(&report, HAWK4_MTSUMMARY).artifact_id.as_deref(),
        Some("portal.message_trace")
    );

    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 7);
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM record_sources WHERE table_name = 'ual_events' AND record_key = '{}'",
                ual::ID_RULE
            )
        ),
        2
    );
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT CAST(data_completeness AS VARCHAR) FROM ual_events WHERE record_id = '{}'",
                ual::ID_SEND
            )
        ),
        "partial"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE data_completeness = 'partial'"
        ),
        1
    );
    let (upn, ip, fwd, rt, t): (String, String, String, String, String) = case
        .conn()
        .query_row(
            "SELECT user_upn, client_ip, parameters['ForwardTo'], record_type_name, CAST(event_time AS VARCHAR)
             FROM ual_events WHERE record_id = ?",
            [ual::ID_RULE],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(
        (
            upn.as_str(),
            ip.as_str(),
            fwd.as_str(),
            rt.as_str(),
            t.as_str()
        ),
        (
            "alice@contoso.example",
            "2001:db8::5",
            "x@fabrikam.example",
            "ExchangeAdmin",
            "2026-09-01 10:00:00+00"
        )
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mail_items_accessed WHERE access_type = 'bind'"
        ),
        2
    );
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT user_agent FROM ual_events WHERE record_id = '{}'",
                ual::ID_LOGIN
            )
        ),
        "axios/1.6.0"
    );
    assert_eq!(
        count(&case, "SELECT count(*) FROM file_events WHERE is_onenote"),
        2
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM sharing_events WHERE link_type = 'anonymous' AND is_external"
        ),
        1
    );
    assert_eq!(
        text(&case, "SELECT query_text FROM search_queries"),
        "wire transfer"
    );
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT CAST(event_time AS VARCHAR) || ' ' || client_ip FROM ual_events WHERE record_id = '{}'",
                ual::ID_SEND
            )
        ),
        "2026-09-14 15:04:05+00 203.0.113.10"
    );
    let (start, end): (i64, i64) = case
        .conn()
        .query_row(
            "SELECT rs.line_start, rs.line_end FROM record_sources rs
             JOIN source_files sf ON sf.file_id = rs.file_id
             WHERE sf.rel_path = ? AND rs.record_key = ?",
            [HAWK4_PURVIEW, ual::ID_RULE],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((start, end), (2, 2));
    let v = verify_record(&case, "ual_events", ual::ID_RULE, None).unwrap();
    assert!(v.ok, "{v:?}");
    assert_eq!(v.sightings.len(), 2);

    let again = ingest_into(&mut case, dir.path());
    assert!(
        again
            .collections
            .iter()
            .flat_map(|c| &c.files)
            .all(|f| f.status != FileStatus::Parsed && f.status != FileStatus::Error),
        "{again:#?}"
    );
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 7);
}

#[test]
fn hawk3_capture_is_found_by_content_and_loads_ual_shapes() {
    let dir = tempfile::tempdir().unwrap();
    hawk3_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_into(&mut case, dir.path());
    assert_eq!(report.collections.len(), 1);
    assert_eq!(report.collections[0].tool, Tool::Hawk);
    assert!(report.collections[0].root.ends_with("capture-hawk3"));
    assert!(!report.has_errors(), "{report:#?}");

    let rbac = row(&report, "Tenant/RBAC_Changes.json");
    assert_eq!(rbac.status, FileStatus::NotSupported);
    assert!(rbac.warnings[0].contains("Search-AdminAuditLog"));
    assert_eq!(
        row(&report, "Tenant/Simple_RBAC_Changes.csv").status,
        FileStatus::NotSupported
    );
    let ed = row(&report, "Tenant/eDiscoveryLogs.csv");
    assert_eq!((ed.status, ed.records_loaded), (FileStatus::Parsed, 2));
    let app = row(&report, "Tenant/Azure_Application_Audit.json");
    assert_eq!(
        (app.status, app.records_loaded),
        (FileStatus::NotSupported, 0)
    );
    assert!(
        app.warnings.iter().any(|w| w.contains("no timestamps")),
        "{:?}",
        app.warnings
    );
    let b = |f: &str| format!("{BOB}/{f}");
    assert_eq!(
        row(&report, &b("Exchange_UAL_Audit_bob@contoso.example.json")).records_loaded,
        1
    );
    assert_eq!(
        row(&report, &b("Exchange_UAL_Audit_bob@contoso.example.csv")).status,
        FileStatus::SkippedSuperseded
    );
    assert_eq!(row(&report, &b(HAWK3_PURVIEW)).records_duplicate, 1);
    assert_eq!(
        row(
            &report,
            &b("Exchange_Mailbox_Audit_bob@contoso.example.json")
        )
        .status,
        FileStatus::Parsed
    );
    let psf = row(&report, "2026-09-02_logs.csv");
    assert_eq!(
        (psf.artifact_id.as_deref(), psf.status),
        (Some("hawk.psframework_log"), FileStatus::Parsed)
    );
    assert_eq!(
        row(&report, "tenant_analysis.log").status,
        FileStatus::Unrecognized
    );
    assert_eq!(
        row(&report, "Tenant/XML/RBAC_Changes.xml").status,
        FileStatus::NotSupported
    );

    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 3);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE data_completeness = 'partial'"
        ),
        2
    );
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT CAST(event_time AS VARCHAR) FROM ual_events WHERE record_id = '{}'",
                ual::ID_H3_EDISC_2
            )
        ),
        "2026-09-15 08:30:00+00"
    );
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT parameters['RuleActions'] FROM ual_events WHERE record_id = '{}'",
                ual::ID_H3_ITEM
            )
        ),
        "MoveToFolder"
    );
    let v = verify_record(&case, "ual_events", ual::ID_H3_ITEM, None).unwrap();
    assert!(v.ok, "{v:?}");
    assert_eq!(v.sightings.len(), 2);
}

#[test]
fn standalone_portal_folder_joins_cross_collection_dedup() {
    let dir = tempfile::tempdir().unwrap();
    hawk4_tree(dir.path());
    portal_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_into(&mut case, dir.path());
    assert_eq!(report.collections.len(), 2);
    assert_eq!(report.collections[1].tool, Tool::PortalExport);
    let p = row(&report, PORTAL_PURVIEW);
    assert_eq!(
        (p.status, p.records_loaded, p.records_duplicate),
        (FileStatus::Parsed, 0, 1)
    );
    assert_eq!(
        row(&report, PORTAL_MTSUMMARY).status,
        FileStatus::DuplicateFile
    );
    assert_eq!(row(&report, "notes.txt").status, FileStatus::Unrecognized);
    let v = verify_record(&case, "ual_events", ual::ID_RULE, None).unwrap();
    assert!(v.ok, "{v:?}");
    assert_eq!(v.sightings.len(), 3);
}

#[test]
fn full_purview_copy_upgrades_a_partial_row_from_an_earlier_ingest() {
    let dir = tempfile::tempdir().unwrap();
    let hawk = dir.path().join("hawk");
    sparrow_core::fixtures::write(
        &hawk,
        "Hawk.log",
        sparrow_core::fixtures::HAWK_LOG.as_bytes(),
    );
    let simple = format!(
        "{ALICE}/Simple_MailItemsAccessed_alice@contoso.example_alice@contoso.example.json"
    );
    let flat = serde_json::json!([{
        "CreationTime": "2026-09-01T10:05:00", "Id": ual::ID_MIA, "Operation": "MailItemsAccessed",
        "RecordType": 50, "Workload": "Exchange", "UserId": "alice@contoso.example",
        "ClientIPAddress": "203.0.113.10", "MailboxOwnerUPN": "alice@contoso.example"
    }]);
    sparrow_core::fixtures::write(&hawk, &simple, flat.to_string().as_bytes());
    let mut case = Case::in_memory().unwrap();
    let first = ingest_into(&mut case, &hawk);
    assert!(!first.has_errors(), "{first:#?}");
    assert_eq!(row(&first, &simple).records_loaded, 1);
    let mia_where = format!("WHERE record_id = '{}'", ual::ID_MIA);
    assert_eq!(
        text(
            &case,
            &format!("SELECT CAST(data_completeness AS VARCHAR) FROM ual_events {mia_where}")
        ),
        "partial"
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM mail_items_accessed {mia_where} AND internet_message_id IS NULL"
            )
        ),
        1
    );

    let exports = dir.path().join("exports");
    let purview = ual::PURVIEW_HEADER.to_string()
        + &ual::purview_row("2026-09-01T10:05:00.0000000Z", &ual::mail_items_accessed());
    sparrow_core::fixtures::write(&exports, PORTAL_PURVIEW, purview.as_bytes());
    let second = ingest_into(&mut case, &exports);
    assert!(!second.has_errors(), "{second:#?}");
    let f = row(&second, PORTAL_PURVIEW);
    assert_eq!((f.status, f.records_loaded), (FileStatus::Parsed, 1));
    assert!(
        f.warnings
            .iter()
            .any(|w| w.contains("replaced partial rows")),
        "{:?}",
        f.warnings
    );

    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 1);
    assert_eq!(
        text(
            &case,
            &format!("SELECT CAST(data_completeness AS VARCHAR) FROM ual_events {mia_where}")
        ),
        "full"
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM mail_items_accessed {mia_where} AND internet_message_id IS NOT NULL"
            )
        ),
        2
    );
    assert_eq!(
        count(
            &case,
            &format!("SELECT count(*) FROM mail_items_accessed {mia_where}")
        ),
        2
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM record_sources WHERE table_name = 'ual_events' AND record_key = '{}'",
                ual::ID_MIA
            )
        ),
        2
    );
}
