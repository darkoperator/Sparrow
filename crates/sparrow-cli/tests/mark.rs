//! `sparrow mark flag|tag` through the binary: the rows and value flags it writes, what `sparrow events` then shows, the
//! refusals, and that a refused write leaves no audit row.

mod events_common;

use events_common::{build, json, run};
use serde_json::Value;
use sparrow_core::Case;
use std::path::Path;

fn audit_rows(path: &Path) -> i64 {
    let c = Case::open_read_only(path).unwrap();
    c.conn()
        .query_row("SELECT count(*) FROM audit_trail", [], |r| r.get(0))
        .unwrap()
}

fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    (tmp, path)
}

/// The `flag` and `tags` columns (the last two) of each event line, keyed by line order.
fn flag_tags(case: &str, extra: &[&str]) -> Vec<(String, String)> {
    let mut args = vec!["events", "--case", case];
    args.extend_from_slice(extra);
    let r = run(&args);
    assert_eq!(r.code, 0, "{}", r.err);
    r.out
        .lines()
        .skip(1)
        .map(|l| {
            let cols: Vec<&str> = l.split("  ").collect();
            (
                cols[cols.len() - 2].to_string(),
                cols[cols.len() - 1].to_string(),
            )
        })
        .collect()
}

#[test]
fn mark_flag_value_then_events_shows_flag() {
    let (_tmp, path) = setup();
    let case = path.to_str().unwrap();
    let before = audit_rows(&path);

    let r = run(&[
        "mark",
        "flag",
        "--case",
        case,
        "--value",
        "ip=203.0.113.45",
        "--level",
        "malicious",
        "--agent",
        "triage",
        "--analyst",
        "carlos",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.trim_end().ends_with(
            "value flag malicious on ip=203.0.113.45 (decided by agent:triage for analyst:carlos, pending review)"
        ),
        "{}",
        r.out
    );
    // One audit row for the action, not one per event (the malicious IP also adds an indicator, with its own row).
    let flag_rows: i64 = Case::open_read_only(&path)
        .unwrap()
        .conn()
        .query_row(
            "SELECT count(*) FROM audit_trail WHERE object_type = 'value_flag'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(flag_rows, 1);
    assert!(audit_rows(&path) > before);

    // The two events from that IP show the agent's flag; the rest are unflagged. Newest first: x1, s1, u2, u1.
    let flags = flag_tags(case, &[]);
    let flags: Vec<&str> = flags.iter().map(|(f, _)| f.as_str()).collect();
    assert_eq!(flags, ["-", "-", "malicious (ai)", "malicious (ai)"]);
    let r = run(&["events", "--case", case, "--flag", "malicious"]);
    assert_eq!(
        r.out.lines().next(),
        Some("total 2  showing 2 from offset 0")
    );
    assert_eq!(
        run(&["events", "--case", case, "--flag", "suspicious"])
            .out
            .lines()
            .next(),
        Some("total 0  showing 0 from offset 0")
    );

    // A value flag covers a row that arrives later.
    Case::create_or_open(&path)
        .unwrap()
        .conn()
        .execute(
            "INSERT INTO events (source_table, record_key, source, event_time, category, ip) \
             VALUES ('ual_events', 'late', 'ual', CAST('2026-09-02 09:00:00+00' AS TIMESTAMPTZ), 'other', '203.0.113.45')",
            [],
        )
        .unwrap();
    assert_eq!(
        run(&["events", "--case", case, "--flag", "malicious"])
            .out
            .lines()
            .next(),
        Some("total 3  showing 3 from offset 0")
    );

    // Clearing the value flag takes the flag off every row.
    let v = json(&[
        "--json",
        "mark",
        "flag",
        "--case",
        case,
        "--value",
        "ip=203.0.113.45",
        "--level",
        "clear",
        "--agent",
        "triage",
    ]);
    assert_eq!(v["actor"], "agent:triage");
    assert_eq!(
        run(&["events", "--case", case, "--flag", "malicious"])
            .out
            .lines()
            .next(),
        Some("total 0  showing 0 from offset 0")
    );
}

#[test]
fn mark_flag_scope_limits_the_value_flag() {
    let (_tmp, path) = setup();
    let case = path.to_str().unwrap();
    // The /24 holds u1 and u2 (session S1) and nothing else; a scope on the other session (s1) matches none of them.
    let r = run(&[
        "mark",
        "flag",
        "--case",
        case,
        "--value",
        "ip_prefix=203.0.113.0/24",
        "--scope",
        "session=4F1C8D3E-1111-4222-8333-444455559A2E",
        "--level",
        "suspicious",
        "--agent",
        "triage",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    let flags = flag_tags(case, &[]);
    let flags: Vec<&str> = flags.iter().map(|(f, _)| f.as_str()).collect();
    assert_eq!(flags, ["-", "-", "suspicious (ai)", "suspicious (ai)"]);
    // Scoped to the other session, the same prefix flags nothing more.
    let r = run(&[
        "mark",
        "flag",
        "--case",
        case,
        "--value",
        "ip_prefix=198.51.100.0/24",
        "--scope",
        "session=4f1c8d3e-1111-4222-8333-444455559a2e",
        "--level",
        "malicious",
        "--agent",
        "triage",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    let flags = flag_tags(case, &[]);
    let flags: Vec<&str> = flags.iter().map(|(f, _)| f.as_str()).collect();
    assert_eq!(flags, ["-", "-", "suspicious (ai)", "suspicious (ai)"]);
}

#[test]
fn mark_rows_flag_tag_and_remove() {
    let (_tmp, path) = setup();
    let case = path.to_str().unwrap();
    let r = run(&[
        "mark",
        "flag",
        "--case",
        case,
        "--row",
        "ual_events:u1",
        "--row",
        "signins:s1",
        "--level",
        "suspicious",
        "--agent",
        "triage",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("flag suspicious on 2 row(s)"), "{}", r.out);
    let r = run(&[
        "mark",
        "tag",
        "--case",
        case,
        "--row",
        "ual_events:u1",
        "--tag",
        " AI:Forwarding ",
        "--agent",
        "triage",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.contains("tag ai:forwarding added to 1 row(s)"),
        "{}",
        r.out
    );

    // Newest first: x1, s1, u2, u1.
    let got = flag_tags(case, &[]);
    assert_eq!(
        got,
        [
            ("-".to_string(), "-".to_string()),
            ("suspicious (ai)".to_string(), "-".to_string()),
            ("-".to_string(), "-".to_string()),
            (
                "suspicious (ai)".to_string(),
                "ai:forwarding (ai)".to_string()
            ),
        ]
    );
    let r = run(&["events", "--case", case, "--where", "tag=ai:forwarding"]);
    assert_eq!(
        r.out.lines().next(),
        Some("total 1  showing 1 from offset 0")
    );

    let r = run(&[
        "mark",
        "tag",
        "--case",
        case,
        "--row",
        "ual_events:u1",
        "--tag",
        "ai:forwarding",
        "--remove",
        "--agent",
        "triage",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.contains("tag ai:forwarding removed from 1 row(s)"),
        "{}",
        r.out
    );
    assert_eq!(flag_tags(case, &["--where", "tag=ai:forwarding"]), []);

    let r = run(&[
        "mark",
        "flag",
        "--case",
        case,
        "--row",
        "ual_events:u1",
        "--level",
        "clear",
        "--agent",
        "triage",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(
        run(&["events", "--case", case, "--flag", "suspicious"])
            .out
            .lines()
            .next(),
        Some("total 1  showing 1 from offset 0")
    );
}

#[test]
fn mark_on_read_only_case_refuses_without_audit_row() {
    let (_tmp, path) = setup();
    let case = path.to_str().unwrap();
    let before = audit_rows(&path);
    // Another process holds the case for writing: every mark write refuses like any other write (exit 4).
    let writer = Case::create_or_open(&path).unwrap();
    for args in [
        vec![
            "mark",
            "flag",
            "--case",
            case,
            "--row",
            "ual_events:u1",
            "--level",
            "suspicious",
            "--agent",
            "triage",
        ],
        vec![
            "mark",
            "flag",
            "--case",
            case,
            "--value",
            "ip=203.0.113.45",
            "--level",
            "malicious",
            "--agent",
            "triage",
        ],
        vec![
            "mark",
            "tag",
            "--case",
            case,
            "--row",
            "ual_events:u1",
            "--tag",
            "ai:x",
            "--agent",
            "triage",
        ],
    ] {
        let mut a = vec!["--json"];
        a.extend(args.iter().copied());
        let r = run(&a);
        assert_eq!(r.code, 4, "{args:?}: {}", r.err);
        let v: Value = serde_json::from_str(&r.out).unwrap();
        assert!(
            v["error"].as_str().unwrap().contains("another writer"),
            "{v}"
        );
    }
    drop(writer);
    assert_eq!(audit_rows(&path), before);
    // Nothing was flagged or tagged.
    assert_eq!(
        run(&["events", "--case", case, "--flag", "suspicious"])
            .out
            .lines()
            .next(),
        Some("total 0  showing 0 from offset 0")
    );
    // A case file that is missing is refused the same way as for the other write commands.
    let r = run(&[
        "mark",
        "tag",
        "--case",
        path.with_file_name("nope.duckdb").to_str().unwrap(),
        "--row",
        "ual_events:u1",
        "--tag",
        "ai:x",
        "--agent",
        "triage",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("not found"), "{}", r.err);
}

#[test]
fn agent_new_plain_tag_refused() {
    let (_tmp, path) = setup();
    let case = path.to_str().unwrap();
    let before = audit_rows(&path);
    let r = run(&[
        "mark",
        "tag",
        "--case",
        case,
        "--row",
        "ual_events:u1",
        "--tag",
        "confirmed-bec",
        "--agent",
        "triage",
    ]);
    assert_eq!(r.code, 5, "{}", r.err);
    assert!(r.err.contains("ai:"), "{}", r.err);
    assert_eq!(audit_rows(&path), before);
    assert_eq!(flag_tags(case, &["--where", "tag=confirmed-bec"]), []);
}

#[test]
fn mark_arguments_are_checked() {
    let (_tmp, path) = setup();
    let case = path.to_str().unwrap();
    let before = audit_rows(&path);
    let flag = |extra: &[&'static str]| {
        let mut a = vec!["mark", "flag", "--case", case];
        a.extend_from_slice(extra);
        run(&a)
    };
    // (result, exit code, a fragment of the message). Clap refusals exit 1; a bad value is `Invalid` (1); a bad row
    // reference, or a row the case lacks, is an agent-decision error (5).
    let cases = [
        (flag(&["--level", "suspicious"]), 1, "--row <ROWS>|--value"),
        (
            flag(&[
                "--row",
                "ual_events:u1",
                "--value",
                "ip=203.0.113.45",
                "--level",
                "suspicious",
            ]),
            1,
            "cannot be used with",
        ),
        (
            flag(&[
                "--row",
                "ual_events:u1",
                "--scope",
                "account=a",
                "--level",
                "suspicious",
            ]),
            1,
            "--scope goes with --value",
        ),
        (
            flag(&["--row", "ual_events:u1", "--level", "bad"]),
            1,
            "unknown flag level \"bad\"",
        ),
        (
            flag(&["--value", "host=a", "--level", "suspicious"]),
            1,
            "unknown flag value kind \"host\"",
        ),
        (
            flag(&[
                "--value",
                "ip=203.0.113.45",
                "--scope",
                "asn=1",
                "--level",
                "suspicious",
            ]),
            1,
            "unknown scope kind \"asn\"",
        ),
        (
            flag(&["--value", "ip", "--level", "suspicious"]),
            1,
            "--value is KIND=VALUE",
        ),
        (
            flag(&["--row", "nokey", "--level", "suspicious"]),
            5,
            "<table>:<record_key>",
        ),
        (
            flag(&["--row", "ual_events:nope", "--level", "suspicious"]),
            5,
            "unknown event ual_events:nope",
        ),
        (
            run(&["mark", "tag", "--case", case, "--tag", "ai:x"]),
            1,
            "--row",
        ),
    ];
    for (i, (r, code, fragment)) in cases.iter().enumerate() {
        assert_eq!(r.code, *code, "case {i}: {}", r.err);
        assert!(r.err.contains(fragment), "case {i}: {}", r.err);
        assert_eq!(r.out, "", "case {i}");
    }
    assert_eq!(audit_rows(&path), before);
}

#[cfg(unix)]
#[test]
fn mark_on_a_read_only_file_refuses_without_audit_row() {
    use std::os::unix::fs::PermissionsExt;
    let (_tmp, path) = setup();
    let case = path.to_str().unwrap();
    let before = audit_rows(&path);
    let original = std::fs::metadata(&path).unwrap().permissions();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
    let r = run(&[
        "mark",
        "flag",
        "--case",
        case,
        "--row",
        "ual_events:u1",
        "--level",
        "suspicious",
        "--agent",
        "triage",
    ]);
    std::fs::set_permissions(&path, original).unwrap();
    if r.code == 0 {
        eprintln!("skipping: a 0444 file is still writable (running as root?)");
        return;
    }
    // Same exit code and kind of message as any other failure to open the case for writing.
    assert_eq!(r.code, 1, "{}", r.err);
    assert!(r.err.contains("Permission denied"), "{}", r.err);
    assert_eq!(r.out, "");
    assert_eq!(audit_rows(&path), before);
    assert_eq!(
        run(&["events", "--case", case, "--flag", "suspicious"])
            .out
            .lines()
            .next(),
        Some("total 0  showing 0 from offset 0")
    );
}
