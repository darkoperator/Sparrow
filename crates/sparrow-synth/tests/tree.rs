use sparrow_synth::manifest::Manifest;
use sparrow_synth::ps::{DateEvidence, Encoding};
use sparrow_synth::story::Evidence;
use sparrow_synth::tree::{CulturePolicy, FileSpec, MemSink, Tree};
use std::collections::BTreeSet;
use uuid::Uuid;

fn status(out: &sparrow_synth::tree::TreeOutcome, rel: &str) -> String {
    out.files
        .iter()
        .find(|f| f.rel_path == rel)
        .unwrap_or_else(|| panic!("{rel}"))
        .status
        .clone()
}

#[test]
fn statuses_replay_sparrows_rules() {
    let mut sink = MemSink::default();
    let mut t = Tree::new(
        &mut sink,
        "Hawk_T_20260910_141500",
        BTreeSet::new(),
        CulturePolicy::Never,
    );
    let raw = FileSpec::new(
        "Tenant/RBAC_Changes.json",
        Some("hawk.tenant.raw_ual"),
        Encoding::Utf8,
    );
    t.write(&raw, "[]").unwrap();
    t.write(
        &FileSpec::new(
            "Tenant/RBAC_Changes.csv",
            Some("hawk.tenant.raw_ual"),
            Encoding::Utf8,
        ),
        "\"a\"\r\n",
    )
    .unwrap();
    t.write(
        &FileSpec::new(
            "Tenant/Simple_RBAC_Changes.json",
            Some("hawk.tenant.simple_ual"),
            Encoding::Utf8,
        )
        .derived(),
        "[]",
    )
    .unwrap();
    // Byte-identical copy for the same artifact and subject: duplicate. (The copy sorts after
    // the original: Sparrow processes by path, and " (copy)" would sort first.)
    let fw = |rel: &str| {
        FileSpec::new(rel, Some("hawk.user.forwarding"), Encoding::Utf8)
            .subject("alice@t.example".into())
    };
    t.write(&fw("alice@t.example/ForwardingReport_alice.json"), "{}")
        .unwrap();
    t.write(
        &fw("alice@t.example/ForwardingReport_alice_copy.json"),
        "{}",
    )
    .unwrap();
    t.write(
        &FileSpec::new("notes/readme.bin", None, Encoding::Utf8),
        "x",
    )
    .unwrap();
    t.write(
        &FileSpec::new(
            "Tenant/Hawk_Help.txt",
            Some("hawk.tenant.help"),
            Encoding::Utf8,
        ),
        "help",
    )
    .unwrap();
    t.dir("empty").unwrap();
    let out = t.finish().unwrap();
    assert_eq!(status(&out, "Tenant/RBAC_Changes.json"), "parsed");
    assert_eq!(
        status(&out, "Tenant/RBAC_Changes.csv"),
        "skipped_superseded"
    );
    assert_eq!(
        status(&out, "Tenant/Simple_RBAC_Changes.json"),
        "skipped_superseded"
    );
    assert_eq!(
        status(&out, "alice@t.example/ForwardingReport_alice_copy.json"),
        "duplicate_file"
    );
    assert_eq!(status(&out, "notes/readme.bin"), "unrecognized");
    assert_eq!(status(&out, "Tenant/Hawk_Help.txt"), "not_supported");
    assert_eq!(out.empty_dirs, vec!["empty"]);
    assert!(
        sink.files
            .contains_key("Hawk_T_20260910_141500/Tenant/RBAC_Changes.json")
    );
}

#[test]
fn merged_is_superseded_unless_a_sibling_failed() {
    let mut sink = MemSink::default();
    let mut t = Tree::new(&mut sink, "Output", BTreeSet::new(), CulturePolicy::Never);
    let w = FileSpec::new(
        "UnifiedAuditLog/20260910-100000/UAL-20260801000000-20260802000000.csv",
        Some("inv.ual.window"),
        Encoding::Utf8,
    );
    t.write(&w, "\"RecordType\"\r\n").unwrap();
    let m = FileSpec::new(
        "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv",
        Some("inv.ual.merged"),
        Encoding::Utf8,
    )
    .derived();
    t.write(&m, "\"RecordType\"\r\n\"x\"\r\n").unwrap();
    let out = t.finish().unwrap();
    assert_eq!(
        status(
            &out,
            "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv"
        ),
        "skipped_superseded"
    );
}

/// The QuickUAL combined export is redundant only when every `inv.quickual.operation` file in
/// its triage root parsed; otherwise it is the only copy of the failed operation's records.
fn quickual_combined(operations: &[(&str, Option<&'static str>)], unrelated: bool) -> String {
    let mut sink = MemSink::default();
    let mut t = Tree::new(&mut sink, "Output", BTreeSet::new(), CulturePolicy::Never);
    for (rel, status) in operations {
        let spec = FileSpec::new(rel, Some("inv.quickual.operation"), Encoding::Utf8);
        t.write(&spec, &format!("{rel}\r\n")).unwrap();
        if let Some(s) = status {
            t.expect_status(rel, s);
        }
    }
    if unrelated {
        let rel = "Triage1/202609101000-UserApplications.csv";
        let spec = FileSpec::new(rel, Some("inv.user_applications"), Encoding::Utf8);
        t.write(&spec, &format!("{rel}\r\n")).unwrap();
    }
    let rel = "Triage1/UAL-Operations-Combined.csv";
    let combined = FileSpec::new(rel, Some("inv.quickual.combined"), Encoding::Utf8).derived();
    t.write(&combined, &format!("{rel}\r\n")).unwrap();
    let out = t.finish().unwrap();
    status(&out, rel)
}

#[test]
fn quickual_combined_is_superseded_when_every_operation_file_parsed() {
    let s = quickual_combined(
        &[
            ("Triage1/New-InboxRule.json", None),
            ("Triage1/Set-Mailbox.csv", None),
        ],
        false,
    );
    assert_eq!(s, "skipped_superseded");
}

#[test]
fn quickual_combined_is_parsed_when_an_operation_file_failed() {
    let s = quickual_combined(
        &[
            ("Triage1/New-InboxRule.json", None),
            ("Triage1/Set-Mailbox.csv", Some("error")),
        ],
        false,
    );
    assert_eq!(s, "parsed");
}

#[test]
fn quickual_combined_is_parsed_when_only_an_unrelated_file_parsed() {
    let s = quickual_combined(&[], true);
    assert_eq!(s, "parsed");
}

#[test]
fn rows_deliveries_lines_and_boms() {
    let id = Uuid::from_u128(7);
    let tracked: BTreeSet<Evidence> = [Evidence::Ual(id)].into_iter().collect();
    let mut sink = MemSink::default();
    let mut t = Tree::new(&mut sink, "R", tracked, CulturePolicy::Never);
    let spec = FileSpec::new(
        "Tenant/RBAC_Changes.csv",
        Some("hawk.tenant.raw_ual"),
        Encoding::Utf8Bom,
    );
    let off1 = t.write(&spec, "\"h\"\r\n\"a\"\r\n").unwrap();
    let off2 = t.write(&spec, "\"b\"\r\n").unwrap();
    assert_eq!((off1, off2), (0, 2));
    t.row(
        "Tenant/RBAC_Changes.csv",
        "ual_events",
        sparrow_synth::keys::ual(id),
    );
    t.deliver(
        &Evidence::Ual(id),
        "ual_events",
        "Tenant/RBAC_Changes.csv",
        (off2 + 1, off2 + 1),
    );
    t.date_evidence(
        "Tenant/RBAC_Changes.csv",
        DateEvidence {
            culture_dates: 2,
            decisive: 1,
        },
    );
    let out = t.finish().unwrap();
    let bytes = &sink.files["R/Tenant/RBAC_Changes.csv"];
    assert_eq!(&bytes[..3], &[0xEF, 0xBB, 0xBF]);
    assert_eq!(
        bytes.iter().filter(|b| **b == 0xEF).count(),
        1,
        "BOM only once"
    );
    assert_eq!(out.tables["ual_events"].rows, 1);
    assert_eq!(out.tables["ual_events"].keys, vec![id.to_string()]);
    let d = &out.delivered[&Evidence::Ual(id)];
    assert_eq!((d[0].1.line_start, d[0].1.line_end), (3, 3));
}

#[test]
fn all_ambiguous_file_fails_without_a_proving_file() {
    let mut sink = MemSink::default();
    let mut t = Tree::new(&mut sink, "R", BTreeSet::new(), CulturePolicy::Never);
    let spec = FileSpec::new(
        "a@t.example/Message_Trace_a.csv",
        Some("hawk.user.message_trace"),
        Encoding::Utf8,
    );
    t.write(&spec, "\"Received\"\r\n\"04/09/2026 10:00:00\"\r\n")
        .unwrap();
    t.date_evidence(
        "a@t.example/Message_Trace_a.csv",
        DateEvidence {
            culture_dates: 1,
            decisive: 0,
        },
    );
    let out = t.finish().unwrap();
    assert_eq!(status(&out, "a@t.example/Message_Trace_a.csv"), "error");
    let mut sink = MemSink::default();
    let mut t = Tree::new(
        &mut sink,
        "R",
        BTreeSet::new(),
        CulturePolicy::Given("en-GB".into()),
    );
    t.write(&spec, "\"Received\"\r\n\"04/09/2026 10:00:00\"\r\n")
        .unwrap();
    t.date_evidence(
        "a@t.example/Message_Trace_a.csv",
        DateEvidence {
            culture_dates: 1,
            decisive: 0,
        },
    );
    assert_eq!(
        status(&t.finish().unwrap(), "a@t.example/Message_Trace_a.csv"),
        "parsed"
    );
}

#[test]
fn manifest_round_trips() {
    let text = r#"{"format":1,"generator":"g","scenario":"s","options":{"collector":"portal","ps":"7","culture":"en-US","seed":1,"ual_format":"csv","signin_export":"csv","hawk_mixed_editions":false,"non_windows":false,"invictus_licence_list":true,"ual_rows":null,"signins":null},"root":"P","geoip_dir":null,"ingest_culture":null,"window_start":"2026-08-01T00:00:00Z","window_end":"2026-08-11T00:00:00Z","collected_at":"2026-08-12T00:00:00Z","licence_profile":"m365_e5","audit_profile":"default","files":[],"empty_dirs":[],"tables":{},"tenant":{"tenant_id":"x","name":null,"domains":[]},"capabilities":{},"evidence":{},"storylines":[],"rules":[]}"#;
    let m = Manifest::from_json(text).unwrap();
    assert_eq!(Manifest::from_json(&m.to_json_pretty()).unwrap(), m);
}

fn ambiguous(t: &mut Tree, rel: &str, artifact: &'static str) {
    let spec = FileSpec::new(rel, Some(artifact), Encoding::Utf8);
    t.write(&spec, "\"Received\"\r\n\"04/09/2026 10:00:00\"\r\n")
        .unwrap();
    t.date_evidence(
        rel,
        DateEvidence {
            culture_dates: 1,
            decisive: 0,
        },
    );
}

#[test]
fn a_decisive_file_proves_the_order_and_a_deferred_json_still_supersedes_its_csv() {
    let mut sink = MemSink::default();
    let mut t = Tree::new(&mut sink, "R", BTreeSet::new(), CulturePolicy::Never);
    ambiguous(&mut t, "Tenant/Admin_Audit.json", "hawk.tenant.admin_audit");
    let csv = FileSpec::new(
        "Tenant/Admin_Audit.csv",
        Some("hawk.tenant.admin_audit"),
        Encoding::Utf8,
    );
    t.write(
        &csv,
        "\"Received\"\r\n\"04/09/2026 10:00:00\"\r\n\"04/10/2026 10:00:00\"\r\n",
    )
    .unwrap();
    t.date_evidence(
        &csv.rel,
        DateEvidence {
            culture_dates: 2,
            decisive: 0,
        },
    );
    let proof = FileSpec::new(
        "a@t.example/Message_Trace_a.csv",
        Some("hawk.user.message_trace"),
        Encoding::Utf8,
    );
    t.write(&proof, "\"Received\"\r\n\"25/09/2026 10:00:00\"\r\n")
        .unwrap();
    t.date_evidence(
        &proof.rel,
        DateEvidence {
            culture_dates: 1,
            decisive: 1,
        },
    );
    let out = t.finish().unwrap();
    assert_eq!(status(&out, "Tenant/Admin_Audit.json"), "parsed");
    assert_eq!(status(&out, "Tenant/Admin_Audit.csv"), "skipped_superseded");
    assert_eq!(status(&out, "a@t.example/Message_Trace_a.csv"), "parsed");
    assert_eq!(out.ingest_culture, None);
}

#[test]
fn auto_culture_is_added_only_when_nothing_proves_the_order() {
    let mut sink = MemSink::default();
    let mut t = Tree::new(
        &mut sink,
        "R",
        BTreeSet::new(),
        CulturePolicy::Auto("en-GB".into()),
    );
    ambiguous(
        &mut t,
        "a@t.example/Message_Trace_a.csv",
        "hawk.user.message_trace",
    );
    let out = t.finish().unwrap();
    assert_eq!(status(&out, "a@t.example/Message_Trace_a.csv"), "parsed");
    assert_eq!(out.ingest_culture.as_deref(), Some("en-GB"));

    let mut sink = MemSink::default();
    let mut t = Tree::new(
        &mut sink,
        "R",
        BTreeSet::new(),
        CulturePolicy::Auto("en-GB".into()),
    );
    ambiguous(
        &mut t,
        "a@t.example/Message_Trace_a.csv",
        "hawk.user.message_trace",
    );
    let proof = FileSpec::new(
        "b@t.example/Message_Trace_b.csv",
        Some("hawk.user.message_trace"),
        Encoding::Utf8,
    );
    t.write(&proof, "\"Received\"\r\n\"25/09/2026 10:00:00\"\r\n")
        .unwrap();
    t.date_evidence(
        &proof.rel,
        DateEvidence {
            culture_dates: 1,
            decisive: 1,
        },
    );
    let out = t.finish().unwrap();
    assert_eq!(status(&out, "a@t.example/Message_Trace_a.csv"), "parsed");
    assert_eq!(out.ingest_culture, None);
}

#[test]
fn derived_counterparts_merged_failures_and_deliberate_statuses() {
    let mut sink = MemSink::default();
    let mut t = Tree::new(&mut sink, "R", BTreeSet::new(), CulturePolicy::Never);
    let u = |rel: &str, a: &'static str| FileSpec::new(rel, Some(a), Encoding::Utf8);
    t.write(
        &u("a@t.example/ExchangeItem_Logs_a.csv", "hawk.user.raw_ual"),
        "\"x\"\r\n",
    )
    .unwrap();
    t.write(
        &u(
            "a@t.example/ExchangeItem_Simple_a.csv",
            "hawk.user.simple_ual",
        )
        .derived(),
        "\"y\"\r\n",
    )
    .unwrap();
    // A failed sibling keeps the Merged copy.
    t.write(
        &u("UAL/r/UAL-1.csv", "inv.ual.window").status("error"),
        "broken",
    )
    .unwrap();
    t.write(
        &u("UAL/r/Merged/UAL-Combined.csv", "inv.ual.merged").derived(),
        "\"z\"\r\n",
    )
    .unwrap();
    t.row("UAL/r/Merged/UAL-Combined.csv", "ual_events", "k1".into());
    t.row("UAL/r/UAL-1.csv", "ual_events", "k2".into());
    let out = t.finish().unwrap();
    assert_eq!(
        status(&out, "a@t.example/ExchangeItem_Simple_a.csv"),
        "skipped_superseded"
    );
    assert_eq!(status(&out, "UAL/r/UAL-1.csv"), "error");
    assert_eq!(status(&out, "UAL/r/Merged/UAL-Combined.csv"), "parsed");
    assert_eq!(
        out.tables["ual_events"].keys,
        vec!["k1"],
        "only parsed files load rows"
    );
}

#[test]
fn dir_sink_truncates_files_from_an_earlier_run() {
    let dir = tempfile::tempdir().unwrap();
    for text in ["first run, longer", "second"] {
        let mut sink = sparrow_synth::tree::DirSink::new(dir.path());
        let mut t = Tree::new(&mut sink, "R", BTreeSet::new(), CulturePolicy::Never);
        let spec = FileSpec::new("Tenant/x.txt", None, Encoding::Utf8);
        t.write(&spec, text).unwrap();
        t.write(&spec, "!").unwrap();
        t.dir("empty").unwrap();
        t.finish().unwrap();
    }
    let got = std::fs::read_to_string(dir.path().join("R/Tenant/x.txt")).unwrap();
    assert_eq!(got, "second!");
    assert!(dir.path().join("R/empty").is_dir());
}

#[test]
fn counterpart_stems_zero_byte_files_and_utf16_chunks() {
    let mut sink = MemSink::default();
    let mut t = Tree::new(&mut sink, "R", BTreeSet::new(), CulturePolicy::Never);
    let u = |rel: &str, a: &'static str| FileSpec::new(rel, Some(a), Encoding::Utf8);
    // Simple_X → Xs (Hawk 3 Simple_New_InboxRule pairs with New_InboxRules).
    t.write(
        &u("Tenant/New_InboxRules.csv", "hawk.tenant.raw_ual"),
        "\"a\"\r\n",
    )
    .unwrap();
    t.write(
        &u("Tenant/Simple_New_InboxRule.csv", "hawk.tenant.simple_ual").derived(),
        "\"b\"\r\n",
    )
    .unwrap();
    // Converted_Authentication_Logs_U → Raw_Authentication_Logs_U.
    t.write(
        &u(
            "a@t.example/Raw_Authentication_Logs_a.csv",
            "hawk.user.raw_auth",
        ),
        "\"c\"\r\n",
    )
    .unwrap();
    t.write(
        &u(
            "a@t.example/Converted_Authentication_Logs_a.csv",
            "hawk.user.converted_auth",
        )
        .derived(),
        "\"d\"\r\n",
    )
    .unwrap();
    // 0-byte files are parsed, never duplicates of each other.
    let empty = |rel: &str| u(rel, "hawk.user.inbox_rules").subject("a@t.example".into());
    t.write(&empty("a@t.example/InboxRules_a.csv"), "").unwrap();
    t.write(&empty("a@t.example/InboxRules_a2.csv"), "")
        .unwrap();
    // UTF-16LE with BOM: the BOM only on the first chunk.
    let w16 = FileSpec::new("Tenant/Hawk_Help.txt", None, Encoding::Utf16LeBom);
    assert_eq!(t.write(&w16, "a\r\n").unwrap(), 0);
    assert_eq!(t.write(&w16, "b\r\n").unwrap(), 1);
    let out = t.finish().unwrap();
    assert_eq!(
        status(&out, "Tenant/Simple_New_InboxRule.csv"),
        "skipped_superseded"
    );
    assert_eq!(
        status(&out, "a@t.example/Converted_Authentication_Logs_a.csv"),
        "skipped_superseded"
    );
    assert_eq!(status(&out, "a@t.example/InboxRules_a.csv"), "parsed");
    assert_eq!(status(&out, "a@t.example/InboxRules_a2.csv"), "parsed");
    let mut want = vec![0xFF, 0xFE];
    want.extend("a\r\nb\r\n".encode_utf16().flat_map(|c| c.to_le_bytes()));
    assert_eq!(sink.files["R/Tenant/Hawk_Help.txt"], want);
}

#[test]
fn an_unrecognized_csv_twin_is_superseded_first() {
    let mut sink = MemSink::default();
    let mut t = Tree::new(&mut sink, "R", BTreeSet::new(), CulturePolicy::Never);
    t.write(
        &FileSpec::new("Tenant/X.json", Some("hawk.tenant.raw_ual"), Encoding::Utf8),
        "[]",
    )
    .unwrap();
    t.write(
        &FileSpec::new("Tenant/X.csv", None, Encoding::Utf8),
        "\"a\"\r\n",
    )
    .unwrap();
    assert_eq!(
        status(&t.finish().unwrap(), "Tenant/X.csv"),
        "skipped_superseded"
    );
}

#[test]
fn a_large_table_of_cid_keys_is_refused() {
    let mut sink = MemSink::default();
    let mut t = Tree::new(&mut sink, "R", BTreeSet::new(), CulturePolicy::Never);
    let spec = FileSpec::new(
        "Tenant/TransportRules.csv",
        Some("hawk.tenant.transport_rules"),
        Encoding::Utf8,
    );
    t.write(&spec, "x\r\n").unwrap();
    for i in 0..5001 {
        t.row(
            "Tenant/TransportRules.csv",
            "transport_rules",
            sparrow_synth::keys::transport_rule(&format!("rule {i}")),
        );
    }
    let err = t.finish().unwrap_err().to_string();
    assert!(
        err.contains("transport_rules") && err.contains("{cid}"),
        "{err}"
    );
}

#[test]
fn a_raw_window_retried_for_its_dates_still_supersedes_the_merged_copy() {
    // Sparrow retries deferred raw files before it processes any derived file.
    let mut sink = MemSink::default();
    let mut t = Tree::new(&mut sink, "Output", BTreeSet::new(), CulturePolicy::Never);
    let run = "P/UnifiedAuditLog/20260910-100000";
    ambiguous(
        &mut t,
        &format!("{run}/UAL-20260809000000-20260810000000.csv"),
        "inv.ual.window",
    );
    for (rel, derived) in [
        (
            format!("{run}/UAL-20260815000000-20260816000000.csv"),
            false,
        ),
        (format!("{run}/Merged/UAL-Combined.csv"), true),
    ] {
        let mut spec = FileSpec::new(
            &rel,
            Some(if derived {
                "inv.ual.merged"
            } else {
                "inv.ual.window"
            }),
            Encoding::Utf8,
        );
        if derived {
            spec = spec.derived();
        }
        t.write(
            &spec,
            &format!("\"CreationTime\"\r\n\"8/15/2026 10:00:00 AM\"\r\n{derived}\r\n"),
        )
        .unwrap();
        t.date_evidence(
            &rel,
            DateEvidence {
                culture_dates: 1,
                decisive: 1,
            },
        );
    }
    let out = t.finish().unwrap();
    assert_eq!(
        status(
            &out,
            &format!("{run}/UAL-20260809000000-20260810000000.csv")
        ),
        "parsed"
    );
    assert_eq!(
        status(&out, &format!("{run}/Merged/UAL-Combined.csv")),
        "skipped_superseded"
    );
}

#[test]
fn a_raw_file_takes_its_order_from_a_derived_file_when_no_raw_file_proves_it() {
    let mut sink = MemSink::default();
    let mut t = Tree::new(&mut sink, "Output", BTreeSet::new(), CulturePolicy::Never);
    let window = "P/UnifiedAuditLog/20260910-100000/UAL-20260809000000-20260810000000.csv";
    ambiguous(&mut t, window, "inv.ual.window");
    let sessions = "P/MailItemsAccessed/20260910-100700/20260910-100700-Sessions.csv";
    let spec = FileSpec::new(sessions, Some("inv.mia.sessions"), Encoding::Utf8).derived();
    t.write(&spec, "\"TimeStamp\"\r\n\"8/15/2026 10:05:00 AM\"\r\n")
        .unwrap();
    t.date_evidence(
        sessions,
        DateEvidence {
            culture_dates: 1,
            decisive: 1,
        },
    );
    let out = t.finish().unwrap();
    assert_eq!(status(&out, window), "parsed");
    assert_eq!(status(&out, sessions), "parsed");
    assert_eq!(out.ingest_culture, None);
}
