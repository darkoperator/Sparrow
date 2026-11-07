#[path = "common/manifest.rs"]
mod manifest;

use manifest::{M, U, invictus_dir, write_text};
use serde_json::json;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::{Case, discovery};
use std::path::Path;

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

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn text(case: &Case, sql: &str) -> Option<String> {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn manifest_warnings(report: &IngestReport) -> Vec<String> {
    report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .filter(|f| f.rel_path.ends_with(".mesmanifest"))
        .flat_map(|f| f.warnings.clone())
        .collect()
}

fn sample() -> M {
    M::run("Get-UALGraph", "partial")
        .param("StartDate", json!("2026-09-01T00:00:00Z"))
        .unit(
            U::new(
                &["ual"],
                "2026-09-01T00:00:00Z",
                "2026-09-02T00:00:00Z",
                "partial",
            )
            .users(&["  Alice@Example.COM ", "bob@example.com"])
            .records(5, "UAL-1.json")
            .gap(
                "2026-09-01T06:00:00Z",
                "2026-09-01T07:00:00Z",
                "retries_exhausted",
            )
            .gap(
                "2026-09-01T09:00:00Z",
                "2026-09-01T10:00:00Z",
                "cap_exceeded",
            ),
        )
        .unit(U::new(
            &["signins"],
            "2026-09-01T00:00:00Z",
            "2026-09-02T00:00:00Z",
            "complete",
        ))
}

#[test]
fn a_manifest_is_discovered_and_stored() {
    let tmp = tempfile::tempdir().unwrap();
    let root = invictus_dir(tmp.path());
    let m = sample();
    m.write(&root);
    let (case, _) = ingest(tmp.path());
    assert_eq!(count(&case, "SELECT count(*) FROM manifest_runs"), 1);
    assert_eq!(
        text(&case, "SELECT status FROM manifest_runs").as_deref(),
        Some("partial")
    );
    assert_eq!(
        text(&case, "SELECT cmdlet FROM manifest_runs").as_deref(),
        Some("Get-UALGraph")
    );
    assert!(
        case.conn()
            .query_row("SELECT supported FROM manifest_runs", [], |r| r
                .get::<_, bool>(0))
            .unwrap()
    );
    assert_eq!(
        text(&case, "SELECT tool_version FROM manifest_runs").as_deref(),
        Some("4.1.0.1")
    );
    assert_eq!(count(&case, "SELECT count(*) FROM manifest_units"), 2);
    assert_eq!(count(&case, "SELECT count(*) FROM manifest_gaps"), 2);
    assert_eq!(
        text(
            &case,
            "SELECT CAST(user_ids AS VARCHAR) FROM manifest_units WHERE unit_id = 'u-0001'"
        )
        .as_deref(),
        Some(r#"["alice@example.com","bob@example.com"]"#)
    );
    assert_eq!(
        text(
            &case,
            "SELECT CAST(user_ids AS VARCHAR) FROM manifest_units WHERE unit_id = 'u-0002'"
        ),
        None
    );
    assert_eq!(
        text(
            &case,
            "SELECT unit_key FROM manifest_units WHERE unit_id = 'u-0002'"
        )
        .unwrap(),
        format!("{}/u-0002", m.run_id())
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM manifest_gaps WHERE widened AND gap_key IS NOT NULL"
        ),
        0
    );
    for (table, n) in [
        ("manifest_runs", 1),
        ("manifest_units", 2),
        ("manifest_gaps", 2),
    ] {
        assert_eq!(
            count(
                &case,
                &format!("SELECT count(*) FROM record_sources WHERE table_name = '{table}'")
            ),
            n,
            "{table}"
        );
    }
}

#[test]
fn the_same_manifest_twice_is_one_run() {
    let tmp = tempfile::tempdir().unwrap();
    let root = invictus_dir(tmp.path());
    let m = sample();
    m.write(&root);
    // The same content saved with other bytes (compact instead of indented), in a second folder.
    let compact =
        serde_json::to_string(&serde_json::from_str::<serde_json::Value>(&m.json()).unwrap())
            .unwrap();
    write_text(&root, "Copy", &m.run_id(), &compact);
    let (case, report) = ingest(tmp.path());
    assert_eq!(count(&case, "SELECT count(*) FROM manifest_runs"), 1);
    assert_eq!(count(&case, "SELECT count(*) FROM manifest_units"), 2);
    assert_eq!(count(&case, "SELECT count(*) FROM manifest_gaps"), 2);
    for (table, n) in [
        ("manifest_runs", 2),
        ("manifest_units", 4),
        ("manifest_gaps", 4),
    ] {
        assert_eq!(
            count(
                &case,
                &format!("SELECT count(*) FROM record_sources WHERE table_name = '{table}'")
            ),
            n,
            "{table}"
        );
    }
    assert!(
        manifest_warnings(&report).is_empty(),
        "{:?}",
        manifest_warnings(&report)
    );
}

#[test]
fn a_byte_identical_copy_is_a_duplicate_file() {
    let tmp = tempfile::tempdir().unwrap();
    let root = invictus_dir(tmp.path());
    let m = sample();
    let p = m.write(&root);
    let copy = root.join("Copy");
    std::fs::create_dir_all(&copy).unwrap();
    std::fs::copy(&p, copy.join(p.file_name().unwrap())).unwrap();
    let (case, _) = ingest(tmp.path());
    assert_eq!(count(&case, "SELECT count(*) FROM manifest_runs"), 1);
    assert_eq!(count(&case, "SELECT count(*) FROM manifest_units"), 2);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM source_files WHERE status = 'duplicate_file'"
        ),
        1
    );
}

#[test]
fn the_same_run_id_with_other_content_keeps_the_first() {
    let tmp = tempfile::tempdir().unwrap();
    let root = invictus_dir(tmp.path());
    let a = sample();
    a.write(&root);
    let b = M::run("Get-MailboxAuditLog", "failed").set("run_id", json!(a.run_id()));
    write_text(&root, "Other", &a.run_id(), &b.json());
    let (case, report) = ingest(tmp.path());
    assert_eq!(count(&case, "SELECT count(*) FROM manifest_runs"), 1);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'manifest_runs'"
        ),
        2
    );
    assert!(
        manifest_warnings(&report)
            .iter()
            .any(|w| w.contains("different content")),
        "{:?}",
        manifest_warnings(&report)
    );
    // Whichever file was read first wins; both are never mixed.
    let status = text(&case, "SELECT status FROM manifest_runs").unwrap();
    let units = count(&case, "SELECT count(*) FROM manifest_units");
    assert!(
        (status == "partial" && units == 2) || (status == "failed" && units == 0),
        "{status} {units}"
    );
}

#[test]
fn an_unsupported_schema_is_recorded_not_fatal() {
    let tmp = tempfile::tempdir().unwrap();
    let root = invictus_dir(tmp.path());
    let m = sample().set("schema", json!("mes-collection-manifest/2"));
    m.write(&root);
    let (case, report) = ingest(tmp.path());
    assert_eq!(count(&case, "SELECT count(*) FROM manifest_runs"), 1);
    assert!(
        !case
            .conn()
            .query_row("SELECT supported FROM manifest_runs", [], |r| r
                .get::<_, bool>(0))
            .unwrap()
    );
    assert_eq!(count(&case, "SELECT count(*) FROM manifest_units"), 0);
    assert_eq!(count(&case, "SELECT count(*) FROM manifest_gaps"), 0);
    let f = report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .find(|f| f.rel_path.ends_with(".mesmanifest"))
        .unwrap();
    assert_ne!(f.status, FileStatus::Error);
    assert!(
        f.warnings.iter().any(|w| w.contains("unsupported")),
        "{:?}",
        f.warnings
    );
}

#[test]
fn malformed_json_rejects_only_that_file() {
    let tmp = tempfile::tempdir().unwrap();
    let root = invictus_dir(tmp.path());
    sample().write(&root);
    write_text(
        &root,
        "Broken",
        "11111111-2222-3333-4444-555555555555",
        "{ not json",
    );
    let (case, report) = ingest(tmp.path());
    let bad = report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .find(|f| f.rel_path.contains("Broken"))
        .unwrap();
    assert_ne!(bad.status, FileStatus::Parsed);
    assert_eq!(count(&case, "SELECT count(*) FROM manifest_runs"), 1);
    assert_eq!(count(&case, "SELECT count(*) FROM collection_log"), 1);
}

#[test]
fn bad_and_zoneless_times() {
    let tmp = tempfile::tempdir().unwrap();
    let root = invictus_dir(tmp.path());
    let m = M::run("Get-UALGraph", "partial")
        // reversed range, with a gap that must widen to nothing (unit range is bad too)
        .unit(
            U::new(
                &["ual"],
                "2026-09-02T00:00:00Z",
                "2026-09-01T00:00:00Z",
                "partial",
            )
            .gap("nope", "2026-09-01T07:00:00Z", "aborted"),
        )
        // unparseable
        .unit(U::new(&["ual"], "yesterday", "today", "complete"))
        // zone-less: UTC with a warning
        .unit(U::new(
            &["signins"],
            "2026-09-01T00:00:00",
            "2026-09-02T00:00:00",
            "complete",
        ))
        // good unit with one bad gap (widened) and one good gap
        .unit(
            U::new(
                &["ual"],
                "2026-09-03T00:00:00Z",
                "2026-09-04T00:00:00Z",
                "partial",
            )
            .gap("garbage", "2026-09-03T05:00:00Z", "retries_exhausted")
            .gap(
                "2026-09-03T08:00:00Z",
                "2026-09-03T09:00:00Z",
                "cap_exceeded",
            ),
        );
    m.write(&root);
    let (case, report) = ingest(tmp.path());
    let q = |u: &str, col: &str| {
        text(
            &case,
            &format!("SELECT CAST({col} AS VARCHAR) FROM manifest_units WHERE unit_id = '{u}'"),
        )
    };
    assert_eq!(
        (q("u-0001", "start_at"), q("u-0001", "end_at")),
        (None, None)
    );
    assert_eq!(
        (q("u-0002", "start_at"), q("u-0002", "end_at")),
        (None, None)
    );
    assert!(
        q("u-0003", "start_at")
            .unwrap()
            .starts_with("2026-09-01 00:00:00")
    );
    assert!(
        q("u-0003", "end_at")
            .unwrap()
            .starts_with("2026-09-02 00:00:00")
    );
    let g = |ord: i64, col: &str| {
        text(
            &case,
            &format!(
                "SELECT CAST({col} AS VARCHAR) FROM manifest_gaps WHERE gap_key LIKE '%/u-0004/{ord}'"
            ),
        )
    };
    assert!(g(0, "start_at").unwrap().starts_with("2026-09-03 00:00:00"));
    assert!(g(0, "end_at").unwrap().starts_with("2026-09-04 00:00:00"));
    assert_eq!(g(0, "widened").as_deref(), Some("true"));
    assert_eq!(g(1, "widened").as_deref(), Some("false"));
    assert!(g(1, "start_at").unwrap().starts_with("2026-09-03 08:00:00"));
    // The gap of the unit with a bad range keeps NULL times.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM manifest_gaps WHERE gap_key LIKE '%/u-0001/0' AND start_at IS NULL AND end_at IS NULL AND NOT widened"
        ),
        1
    );
    let w = manifest_warnings(&report).join("\n");
    assert!(w.contains("zone"), "{w}");
    assert!(w.contains("u-0001"), "{w}");
    assert!(w.contains("u-0002"), "{w}");
}

#[test]
fn narrowed_and_mia_only_are_derived() {
    let tmp = tempfile::tempdir().unwrap();
    let root = invictus_dir(tmp.path());
    let r = ("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z");
    let mk = |s: &[&str]| U::new(s, r.0, r.1, "complete");
    M::run("Get-UALGraph", "complete")
        .unit(mk(&["mail_items_accessed"]).operations(&["mailitemsaccessed"])) // 1
        .unit(mk(&["ual"]).ips(&["1.2.3.4"])) // 2
        .unit(mk(&["ual"]).empty_other_filters()) // 3
        .unit(mk(&["ual"]).operations(&["MailItemsAccessed", "Send"])) // 4
        .unit(mk(&["ual"]).other("Foo", json!("x"))) // 5
        .unit(mk(&["message_trace"]).direction("sender")) // 6
        .unit(
            mk(&["ual"])
                .operations(&["MailItemsAccessed"])
                .ips(&["1.2.3.4"]),
        ) // 7
        .unit(mk(&["ual"])) // 8
        .write(&root);
    let (case, _) = ingest(tmp.path());
    let flags: Vec<(String, bool, bool)> = {
        let mut st = case
            .conn()
            .prepare("SELECT unit_id, narrowed, mia_only FROM manifest_units ORDER BY unit_id")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|x| x.unwrap())
            .collect()
    };
    let want = [
        (false, true),
        (true, false),
        (false, false),
        (true, false),
        (true, false),
        (false, false),
        (true, false),
        (false, false),
    ];
    assert_eq!(flags.len(), want.len());
    for (i, (u, n, m)) in flags.iter().enumerate() {
        assert_eq!((*n, *m), want[i], "{u}");
    }
    assert_eq!(
        text(
            &case,
            "SELECT direction FROM manifest_units WHERE unit_id = 'u-0006'"
        )
        .as_deref(),
        Some("sender")
    );
}

#[test]
fn the_manifest_is_discovered_as_invictus() {
    let tmp = tempfile::tempdir().unwrap();
    let root = invictus_dir(tmp.path());
    sample().write(&root);
    let found = discovery::discover_collections(tmp.path()).unwrap();
    assert_eq!(found.len(), 1);
}

#[test]
fn malformed_user_ids_vouch_nobody() {
    let tmp = tempfile::tempdir().unwrap();
    let root = invictus_dir(tmp.path());
    let r = ("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z");
    let mut m = M::run("Get-UALGraph", "complete");
    for _ in 0..4 {
        m = m.unit(U::new(&["ual"], r.0, r.1, "complete"));
    }
    let mut doc: serde_json::Value = serde_json::from_str(&m.json()).unwrap();
    let units = doc["units"].as_array_mut().unwrap();
    units[0]["scope"]["user_ids"] = json!({"a": 1});
    units[1]["scope"]["user_ids"] = json!("Bob@Example.com");
    units[2]["scope"]["user_ids"] = json!(["A@x.com", 5, null]);
    // units[3]: null, tenant-wide
    write_text(&root, "UnifiedAuditLog", &m.run_id(), &doc.to_string());
    let (case, report) = ingest(tmp.path());
    let ids = |u: &str| {
        text(
            &case,
            &format!("SELECT CAST(user_ids AS VARCHAR) FROM manifest_units WHERE unit_id = '{u}'"),
        )
    };
    assert_eq!(ids("u-0001").as_deref(), Some("[]"));
    assert_eq!(ids("u-0002").as_deref(), Some("[]"));
    assert_eq!(ids("u-0003").as_deref(), Some(r#"["a@x.com"]"#));
    assert_eq!(ids("u-0004"), None);
    let w = manifest_warnings(&report).join("\n");
    assert!(w.contains("u-0001") && w.contains("not a list"), "{w}");
    assert!(w.contains("u-0003") && w.contains("not text"), "{w}");
}

#[test]
fn only_a_boolean_true_means_output_written() {
    let tmp = tempfile::tempdir().unwrap();
    let root = invictus_dir(tmp.path());
    let r = ("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z");
    let mut m = M::run("Get-UALGraph", "complete");
    for _ in 0..4 {
        m = m.unit(U::new(&["ual"], r.0, r.1, "complete"));
    }
    let mut doc: serde_json::Value = serde_json::from_str(&m.json()).unwrap();
    let units = doc["units"].as_array_mut().unwrap();
    units[0]["output_written"] = json!("false");
    units[1]["output_written"] = json!(1);
    units[2]["output_written"] = json!(true);
    units[3].as_object_mut().unwrap().remove("output_written"); // absent: never vouches
    write_text(&root, "UnifiedAuditLog", &m.run_id(), &doc.to_string());
    let (case, report) = ingest(tmp.path());
    let ow = |u: &str| {
        case.conn()
            .query_row(
                &format!("SELECT output_written FROM manifest_units WHERE unit_id = '{u}'"),
                [],
                |r| r.get::<_, bool>(0),
            )
            .unwrap()
    };
    assert_eq!(
        [ow("u-0001"), ow("u-0002"), ow("u-0003"), ow("u-0004")],
        [false, false, true, false]
    );
    let w = manifest_warnings(&report).join("\n");
    assert!(w.contains("u-0001") && w.contains("output_written"), "{w}");
    assert!(w.contains("u-0004") && w.contains("missing"), "{w}");
}

#[test]
fn manifest_text_in_warnings_is_escaped() {
    let tmp = tempfile::tempdir().unwrap();
    let root = invictus_dir(tmp.path());
    let r = ("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z");
    let mut doc: serde_json::Value = serde_json::from_str(
        &M::run("Get-UALGraph", "complete")
            .unit(U::new(&["ual"], r.0, r.1, "complete"))
            .json(),
    )
    .unwrap();
    doc["units"][0]["unit_id"] = json!("u\u{202e}evil\nFORGED");
    doc["units"][0]["scope"]["user_ids"] = json!("x");
    doc["schema"] = json!("mes-collection-manifest/9\u{202e}\u{1b}[31m");
    write_text(
        &root,
        "UnifiedAuditLog",
        "11111111-2222-3333-4444-555555555555",
        &doc.to_string(),
    );
    let (_, report) = ingest(tmp.path());
    let w = manifest_warnings(&report);
    assert!(!w.is_empty());
    for line in &w {
        assert!(
            !line.chars().any(|c| c.is_control() || c == '\u{202e}'),
            "{line:?}"
        );
    }
}
