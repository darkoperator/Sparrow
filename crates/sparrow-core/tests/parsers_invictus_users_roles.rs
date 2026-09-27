#[path = "common/synth.rs"]
mod synth;

use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileStatus, IngestOptions, ingest_path};
use sparrow_synth::options::PsEdition;
use synth::*;

#[test]
fn users_and_roles_load() {
    for ps in [PsEdition::Ps7, PsEdition::Ps51] {
        let g = builtin("bec-aitm", ps); // m365_e5: P1 and P2
        assert_eq!(count(&g.case, "SELECT count(*) FROM users"), 13);
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM users WHERE upn LIKE 'admin@%' AND account_enabled"
            ),
            1
        );
        assert!(
            count(
                &g.case,
                "SELECT count(*) FROM role_assignments WHERE source = 'entra_directory' AND role_name = 'Global Administrator'"
            ) >= 1
        );
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM role_assignments WHERE source = 'entra_pim' AND assignment_type = 'PIM Eligible'"
            ),
            0
        ); // bec-aitm has one admin
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM role_assignments WHERE source = 'entra_pim' AND assignment_type = 'PIM Active' AND end_time IS NOT NULL"
            ),
            1
        );
        check_green(&g);
    }
}

#[test]
fn no_p1_leaves_an_empty_users_run_and_no_p2_no_pim() {
    let g = builtin("bec-o365-no-p1", PsEdition::Ps7);
    assert_eq!(count(&g.case, "SELECT count(*) FROM users"), 0); // Users is the only Microsoft-Extractor-Suite user source
    assert!(g.manifest.empty_dirs.iter().any(|d| d.contains("/Users/")));
    check_green(&g);
}

#[test]
fn bom_only_csv_is_an_empty_export() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("Output");
    std::fs::create_dir_all(root.join("Users/20260910-100000")).unwrap();
    std::fs::write(
        root.join("Users/20260910-100000/20260910-100000-Users.csv"),
        [0xEF, 0xBB, 0xBF],
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
        .find(|f| f.rel_path.ends_with("Users.csv"))
        .unwrap();
    assert_eq!(f.status, FileStatus::Parsed);
    assert_eq!(f.records_read, 0);
    assert!(
        f.warnings
            .iter()
            .any(|w| w == sparrow_core::ingest::EMPTY_FILE_WARNING)
    );
}

#[test]
fn allroles_error_rows_are_a_lookup_failure() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("Output");
    let rel = "Roles/20260910-100500/20260910-100500-AllRoles.csv";
    let body = format!(
        "{}{}{}",
        csv_line(&[
            "Role",
            "UserName",
            "UserId",
            "DisplayName",
            "Department",
            "JobTitle",
            "AccountEnabled",
            "CreatedDateTime",
            "LastInteractiveSignIn",
            "LastNonInteractiveSignIn",
            "DaysSinceLastSignIn",
        ]),
        csv_line(&[
            "User Administrator",
            "alice@contoso.example",
            "0e0e0e0e-0000-4000-8000-0000000000a1",
            "Alice Example",
            "Engineering",
            "Analyst",
            "True",
            "6/27/2025 11:05:39 AM",
            "",
            "",
            "No sign-in data",
        ]),
        // The collector's bug: the failed lookup row carries the user's display name in Role.
        csv_line(&[
            "Bob Example",
            "",
            "",
            "Error retrieving data",
            "Error retrieving data",
            "Error retrieving data",
            "Error retrieving data",
            "Error retrieving data",
            "",
            "",
            "Error retrieving data",
        ]),
    );
    fixtures::write(&root, rel, body.as_bytes());
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
    assert_eq!(f.status, FileStatus::Parsed);
    assert_eq!(f.records_read, 2);
    assert_eq!(f.records_error, 1);
    assert_eq!(
        f.records_loaded, 1,
        "the one real member loads; the error row does not"
    );
    let msg: String = case
        .conn()
        .query_row("SELECT error FROM parse_errors", [], |r| r.get(0))
        .unwrap();
    assert!(msg.contains("Error retrieving data"), "{msg}");
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM role_assignments WHERE source = 'entra_directory' AND role_name = 'User Administrator'"
        ),
        1
    );
}
