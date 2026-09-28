#[path = "common/synth.rs"]
mod synth;

use sparrow_core::Case;
use sparrow_core::fixtures::csv_line;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_synth::options::PsEdition;
use synth::*;

#[test]
fn exchange_and_graph_rules_load_with_parsed_recipients_and_folders() {
    for ps in [PsEdition::Ps7, PsEdition::Ps51] {
        let g = builtin("bec-aitm", ps);
        // The victim's hiding rule: name ".", RSS Feeds, finance words.
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM inbox_rules WHERE name = '.' AND move_to_folder = 'RSS Feeds' AND source = 'exo'"
            ),
            1
        );
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM inbox_rules WHERE name = '.' AND source = 'graph'"
            ),
            1
        );
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM inbox_rules WHERE list_contains(forward_to, 'invoices@exfil-mail.test') AND source = 'exo'"
            ),
            1
        );
        assert!(
            count(
                &g.case,
                "SELECT count(*) FROM inbox_rules WHERE description LIKE 'If the message:%'"
            ) >= 1
        );
        // The generator's AP rule also forwards to an internal user whose display name is
        // "Last, First", so the EXO export really carries a quoted, comma-bearing display name
        // (the parser strips the display form and keeps one address per recipient).
        let comma_display =
            "regexp_matches(json_extract_string(raw, '$.ForwardTo'), '\"[^\"]*,[^\"]*\" \\[SMTP:')";
        assert!(
            count(
                &g.case,
                &format!(
                    "SELECT count(*) FROM inbox_rules WHERE source = 'exo' AND {comma_display}"
                )
            ) >= 1
        );
        assert_eq!(
            count(
                &g.case,
                &format!(
                    "SELECT len(forward_to) FROM inbox_rules WHERE source = 'exo' AND {comma_display}"
                )
            ),
            2
        );
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM transport_rules WHERE name = 'Journal copy'"
            ),
            1
        );
        check_green(&g);
    }
}

#[test]
fn exo_recipients_with_commas_and_quotes_in_display_names_stay_separate_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("Output");
    std::fs::create_dir_all(root.join("Rules/20260910-100000")).unwrap();
    let rel = "Rules/20260910-100000/20260910-100000-MailboxRules.csv";
    let body = format!(
        "{}{}",
        csv_line(&[
            "UserName",
            "RuleName",
            "Enabled",
            "Priority",
            "RuleIdentity",
            "StopProcessingRules",
            "CopyToFolder",
            "MoveToFolder",
            "RedirectTo",
            "ForwardTo",
            "ForwardAsAttachmentTo",
            "ApplyCategory",
            "MarkImportance",
            "MarkAsRead",
            "DeleteMessage",
            "SoftDeleteMessage",
            "From",
            "SubjectContainsWords",
            "SubjectOrBodyContainsWords",
            "BodyContainsWords",
            "HasAttachment",
            "Description",
            "InError",
            "ErrorType",
        ]),
        csv_line(&[
            "alice@contoso.example",
            "AP",
            "True",
            "0",
            "1111",
            "False",
            "",
            "",
            "",
            // Two recipients whose display names hold a comma, and one with a doubled quote.
            "\"Doe, Jane\" [SMTP:jane@contoso.example], \"Smith, John\" [SMTP:john@contoso.example], \"Doe \"\"Q\"\" Smith\" [SMTP:q@contoso.example]",
            "",
            "",
            "",
            "False",
            "False",
            "False",
            "",
            "",
            "",
            "",
            "False",
            "If the message:\r\n\tFrom 'billing@vendor.example'\r\nTake the following actions:\r\n\tForward the message to jane@contoso.example\r\n",
            "False",
            "None",
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
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        count(
            &case,
            "SELECT len(forward_to) FROM inbox_rules WHERE record_key = 'inbox|alice@contoso.example|1111'"
        ),
        3
    );
    for addr in [
        "jane@contoso.example",
        "john@contoso.example",
        "q@contoso.example",
    ] {
        assert_eq!(
            count(
                &case,
                &format!(
                    "SELECT count(*) FROM inbox_rules WHERE record_key = 'inbox|alice@contoso.example|1111' AND list_contains(forward_to, '{addr}')"
                )
            ),
            1,
            "{addr}"
        );
    }
}
