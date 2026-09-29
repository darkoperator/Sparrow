#[path = "common/synth.rs"]
mod synth;

use sparrow_core::Case;
use sparrow_core::fixtures::csv_line;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileStatus, IngestOptions, ingest_path};
use sparrow_synth::options::PsEdition;
use synth::*;

#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn graph_quickual_and_legacy_audit_load() {
    for ps in [PsEdition::Ps7, PsEdition::Ps51] {
        let g = builtin("bec-aitm", ps);
        let status = |suffix: &str| {
            g.manifest
                .files
                .iter()
                .find(|f| f.rel_path.ends_with(suffix))
                .unwrap()
                .status
                .clone()
        };
        assert_eq!(status("-victims-UnifiedAuditLog.json"), "parsed");
        assert_eq!(status("-victims-UnifiedAuditLog.csv"), "parsed");
        assert_eq!(status("-empty-UnifiedAuditLog.json"), "parsed");
        assert_eq!(status("New-InboxRule.json"), "parsed");
        assert_eq!(status("UAL-Operations-Combined.csv"), "skipped_superseded");
        // Every Get-UALGraph / QuickUAL record is also in the Get-UAL windows: no new rows, extra sightings.
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM ual_events WHERE data_completeness = 'partial'"
            ),
            0
        );
        assert!(
            count(
                &g.case,
                "SELECT count(*) FROM record_sources rs JOIN source_files sf USING (file_id) WHERE sf.artifact_type = 'inv.ual.graph'"
            ) > 0
        );
        assert!(count(&g.case, "SELECT count(*) FROM mailbox_audit_legacy") > 0);
        check_green(&g);
    }
}

#[test]
fn lone_bracket_graph_json_is_an_empty_export_with_the_expected_warning() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("Output");
    std::fs::create_dir_all(root.join("UnifiedAuditLog/20260910-100000")).unwrap();
    std::fs::write(
        root.join("UnifiedAuditLog/20260910-100000/20260910100100-empty-UnifiedAuditLog.json"),
        b"[\r\n",
    )
    .unwrap();
    std::fs::write(
        root.join("LogFile.txt"),
        b"2026-09-10 10:00:00: Starting\r\n",
    )
    .unwrap();
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path.ends_with("-empty-UnifiedAuditLog.json"))
        .unwrap();
    assert_eq!(f.status, FileStatus::Parsed);
    assert_eq!(f.records_read, 0);
    assert!(
        f.warnings
            .iter()
            .any(|w| w == "Get-UALGraph found no results (the file holds only \"[\")")
    );
}

#[test]
fn an_unrelated_csv_in_the_triage_root_is_not_supported_and_loads_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("Output");
    std::fs::create_dir_all(root.join("Triage1")).unwrap();
    std::fs::write(
        root.join("Triage1/analyst notes.csv"),
        "author,note\r\nanalyst,seen\r\n",
    )
    .unwrap();
    std::fs::write(
        root.join("LogFile.txt"),
        b"2026-09-10 10:00:00: Starting\r\n",
    )
    .unwrap();
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path.ends_with("analyst notes.csv"))
        .unwrap();
    assert_eq!(f.artifact_id.as_deref(), Some("inv.quickual.operation"));
    assert_eq!(f.status, FileStatus::NotSupported);
    assert_eq!((f.records_read, f.records_loaded), (0, 0));
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 0);
}

#[test]
fn invictus_legacy_mailbox_audit_csv_uses_the_existing_parser() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("Output");
    std::fs::create_dir_all(root.join("Mailbox Audit Log/20260910-100000-Legacy")).unwrap();
    let rel = "Mailbox Audit Log/20260910-100000-Legacy/202609101000-mailboxAuditLog-alice@contoso.example.csv";
    let body = format!(
        "{}{}",
        csv_line(&[
            "Operation",
            "OperationResult",
            "LogonType",
            "ClientIPAddress",
            "MailboxOwnerUPN",
            "ItemSubject",
            "ItemInternetMessageId",
            "SessionId",
            "MailboxGuid",
            "LastAccessed",
        ]),
        csv_line(&[
            "SendAs",
            "Succeeded",
            "Delegate",
            "198.51.100.7",
            "Alice@contoso.example",
            "Updated bank details",
            "<m2@contoso.example>",
            "s-2",
            "99999999-9999-4999-8999-999999999999",
            "9/14/2026 9:00:00 AM",
        ])
    );
    std::fs::write(root.join(rel), body).unwrap();
    std::fs::write(
        root.join("LogFile.txt"),
        b"2026-09-10 10:00:00: Starting\r\n",
    )
    .unwrap();
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == rel)
        .unwrap();
    assert_eq!(f.artifact_id.as_deref(), Some("inv.mailbox_audit_legacy"));
    assert_eq!(f.status, FileStatus::Parsed);
    assert_eq!(f.records_loaded, 1);
    assert_eq!(
        text(
            &case,
            "SELECT mailbox_upn || '|' || operation || '|' || logon_type FROM mailbox_audit_legacy"
        ),
        "alice@contoso.example|SendAs|Delegate"
    );
}
