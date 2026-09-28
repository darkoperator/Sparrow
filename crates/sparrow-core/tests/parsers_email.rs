//! Task 22: exported e-mail headers (.eml) and Hawk message-header exports. The two tests are
//! the plan's, unchanged.

#[path = "common/synth.rs"]
mod synth;

use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::options::{Collector, GenerateOptions, PsEdition};
use sparrow_synth::scenario::load;
use sparrow_synth::testing::ingest_generated;
use std::path::Path;
use synth::*;

#[test]
fn eml_headers_show_the_spoof_and_the_clean_message() {
    let g = builtin("bec-aitm", PsEdition::Ps7);
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM email_artifacts WHERE source = 'eml'"
        ),
        2
    );
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM email_artifacts WHERE NOT p1_p2_match AND spf = 'fail' AND dmarc = 'fail' AND auth_as = 'Anonymous'"
        ),
        1
    );
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM email_artifacts WHERE p1_p2_match AND spf = 'pass'"
        ),
        1
    );
    check_green(&g);
}

#[test]
fn hawk_header_exports_load_with_findings() {
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(
        &load("hawk-investigate").unwrap(),
        &GenerateOptions::new(Collector::Hawk4, 3),
        dir.path(),
    )
    .unwrap();
    let case = ingest_generated(dir.path(), &m);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM email_artifacts WHERE source = 'hawk_message_header' AND json_array_length(findings) >= 3"
        ),
        2
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM email_artifacts WHERE NOT p1_p2_match"
        ),
        1
    );
    let r = sparrow_synth::check::check(&m, &case).unwrap();
    assert!(r.ok, "{:#?}", r.problems);
}

/// A minimal Hawk root recognizable by content (`Tenant/OrgConfig.txt`) plus `files` (path,
/// content) under it.
fn hawk_case(dir: &Path, files: &[(&str, String)]) -> Case {
    let root = dir.join("Hawk_Test_20260101_000000");
    fixtures::write(&root, "Tenant/OrgConfig.txt", b"AuditDisabled : False\r\n");
    for (rel, body) in files {
        fixtures::write(&root, rel, body.as_bytes());
    }
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        dir,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert!(!report.has_errors(), "{report:#?}");
    case
}

fn header_csv(message_id: &str) -> String {
    [
        csv_line(&["Header", "Value"]),
        csv_line(&["From", "\"Alice Example\" <alice@contoso.example>"]),
        csv_line(&["Return-Path", "<alice@contoso.example>"]),
        csv_line(&["Message-ID", message_id]),
        csv_line(&["Subject", "Quarterly update"]),
        csv_line(&["Date", "Wed, 10 Sep 2026 10:00:00 +0000"]),
        csv_line(&[
            "Received",
            "from a.prod.outlook.example by b.prod.outlook.example with Microsoft SMTP Server; Wed, 10 Sep 2026 10:00:00 +0000",
        ]),
        csv_line(&[
            "Authentication-Results",
            "spf=pass smtp.mailfrom=contoso.example; dkim=pass header.d=contoso.example; dmarc=pass header.from=contoso.example",
        ]),
        csv_line(&["X-MS-Exchange-Organization-AuthAs", "Internal"]),
        csv_line(&["X-MS-Exchange-Organization-AuthMechanism", "06"]),
    ]
    .concat()
}

fn findings_csv() -> String {
    [
        csv_line(&["Rule", "Value", "Conclusion", "More Information"]),
        csv_line(&[
            "P1 P2 Match",
            "From: \"Alice Example\" <alice@contoso.example>;  Return-Path: <alice@contoso.example>",
            "P1 and P2 Header match",
            "",
        ]),
        csv_line(&[
            "Authentication Method",
            "Internal",
            "Method used to authenticate",
            "https://docs.example.test/header-firewall",
        ]),
        csv_line(&[
            "Authentication Mechanism",
            "06",
            "04 = Credentials Used; 06 = SMTP Authentication",
            "https://docs.example.test/header-firewall",
        ]),
        csv_line(&[
            "Submitting Host",
            "a.prod.outlook.example",
            "Submitted from Office 365",
            "Warning - This might have originated from one of your clients",
        ]),
    ]
    .concat()
}

#[test]
fn hawk_header_and_findings_merge_into_one_message_id_row() {
    let dir = tempfile::tempdir().unwrap();
    let case = hawk_case(
        dir.path(),
        &[
            (
                "invoice.msg/Message_Header_invoice.msg.csv",
                header_csv("<MixedCase@contoso.example>"),
            ),
            (
                "invoice.msg/Message_Header_Findings_invoice.msg.csv",
                findings_csv(),
            ),
        ],
    );
    // One row, keyed by the lower-case Message-ID, original case kept in the column.
    assert_eq!(count(&case, "SELECT count(*) FROM email_artifacts"), 1);
    assert_eq!(
        text(&case, "SELECT record_key FROM email_artifacts"),
        "mixedcase@contoso.example"
    );
    assert_eq!(
        text(&case, "SELECT message_id FROM email_artifacts"),
        "MixedCase@contoso.example"
    );
    // The findings file filled the row and both files are cited in record_sources.
    assert_eq!(
        count(
            &case,
            "SELECT json_array_length(findings) FROM email_artifacts"
        ),
        4
    );
    assert!(
        text(
            &case,
            "SELECT CAST(p1_p2_match AS VARCHAR) FROM email_artifacts"
        ) == "true"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'email_artifacts'"
        ),
        2
    );
}

#[test]
fn findings_without_a_header_key_by_subject_and_warn() {
    let dir = tempfile::tempdir().unwrap();
    let case = hawk_case(
        dir.path(),
        &[(
            "invoice.msg/Message_Header_Findings_invoice.msg.csv",
            findings_csv(),
        )],
    );
    assert_eq!(
        text(&case, "SELECT record_key FROM email_artifacts"),
        "hawk|invoice.msg"
    );
    let warnings = text(
        &case,
        "SELECT CAST(warnings AS VARCHAR) FROM source_files WHERE artifact_type = 'hawk.message.header_findings'",
    );
    assert!(
        warnings.contains("no ingested Message_Header_invoice.msg.csv"),
        "{warnings}"
    );
}

/// The ordering rule (not the file-name sort) decides: the header parses first even when the
/// findings name sorts before it (`Zebra`, where `F` < `Z`), and either way when it sorts after.
#[test]
fn header_parses_before_findings_whatever_the_names_sort_as() {
    for subject in ["Apple.msg", "Zebra.msg"] {
        let dir = tempfile::tempdir().unwrap();
        let case = hawk_case(
            dir.path(),
            &[
                (
                    &format!("{subject}/Message_Header_{subject}.csv"),
                    header_csv("<abc@contoso.example>"),
                ),
                (
                    &format!("{subject}/Message_Header_Findings_{subject}.csv"),
                    findings_csv(),
                ),
            ],
        );
        assert_eq!(
            text(&case, "SELECT record_key FROM email_artifacts"),
            "abc@contoso.example",
            "{subject}: the header file must be parsed first"
        );
    }
}
