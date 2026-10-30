//! `sparrow events` and `sparrow entity` through the binary on a small synthetic case (contoso.example).
//!
//! The case has four `events` rows, inserted directly:
//!   u1 10:00:00 ual Send        jdoe  203.0.113.45  no device  session 4f1c…9a2e
//!   u2 10:05:00 ual MailItemsAccessed  jdoe  203.0.113.45  no device  session 4f1c…9a2e
//!   s1 10:10:00 signin_interactive UserLoggedIn  jdoe  198.51.100.7  device JDOE-LAPTOP  session 7a7a…0b0b
//!   x1 11:00:00 ual Send  other  192.0.2.9  nothing else

mod events_common;

use events_common::{DEVICE, S1, build, json, run};
use serde_json::Value;

#[test]
fn events_text_output_exact_lines() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    // The sign-in is the evidence of two open findings: the last column lists their rules.
    {
        let case = sparrow_core::Case::create_or_open(&path).unwrap();
        for (id, rule) in [("F2", "SPW-MAIL-005"), ("F1", "SPW-ID-004")] {
            case.conn()
                .execute(
                    "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, \
                     severity, title, status, created_by, created_at, updated_at) \
                     VALUES (?, ?, 'contoso', ?, 1, 'x', 'high', 't', 'new', 'rule', now(), now())",
                    [id, id, rule],
                )
                .unwrap();
            case.conn()
                .execute(
                    "INSERT INTO finding_evidence (finding_id, source_table, record_key, role, added_run_id) \
                     VALUES (?, 'signins', 's1', 'trigger', 1)",
                    [id],
                )
                .unwrap();
        }
    }
    let case = path.to_str().unwrap();
    let r = run(&["events", "--case", case, "--user", "JDoe@Contoso.example"]);
    assert_eq!(r.code, 0, "{}", r.err);
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(
        lines,
        [
            "total 3  showing 3 from offset 0",
            "2026-09-01T10:10:00Z  signin_interactive  UserLoggedIn  jdoe@contoso.example  198.51.100.7  JDOE-LAPTOP  7a7a…0b0b  -  -  SPW-ID-004,SPW-MAIL-005",
            "2026-09-01T10:05:00Z  ual  MailItemsAccessed  jdoe@contoso.example  203.0.113.45  -  4f1c…9a2e  -  -  -",
            "2026-09-01T10:00:00Z  ual  Send  jdoe@contoso.example  203.0.113.45  -  4f1c…9a2e  -  -  -",
        ]
    );
    let r = run(&["events", "--case", case, "--where", "rule=spw-id-004"]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.starts_with("total 1  "), "{}", r.out);
    // A filter box narrows the same way as in the grid; the header counts what matches, not what is shown.
    let r = run(&[
        "events",
        "--case",
        case,
        "--where",
        "operation=Send",
        "--limit",
        "1",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(
        r.out.lines().collect::<Vec<_>>(),
        [
            "total 2  showing 1 from offset 0",
            "2026-09-01T11:00:00Z  ual  Send  other@contoso.example  192.0.2.9  -  -  -  -  -",
        ]
    );
    // An excluding-only list means everything except; a lone `!` is refused, never "everything".
    let r = run(&["events", "--case", case, "--where", "operation=!Send"]);
    assert_eq!(
        r.out.lines().next(),
        Some("total 2  showing 2 from offset 0")
    );
    let r = run(&["events", "--case", case, "--where", "operation=!"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("Operation filter"), "{}", r.err);
    assert_eq!(r.out, "");
}

#[test]
fn events_json_shape() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let case = path.to_str().unwrap();
    let v = json(&[
        "--json",
        "events",
        "--case",
        case,
        "--ip",
        "203.0.113.45",
        "--limit",
        "1",
        "--offset",
        "1",
    ]);
    assert_eq!(v["total"], 2);
    assert_eq!(v["total_capped"], false);
    assert_eq!(v["offset"], 1);
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(r["record_key"], "u1");
    assert_eq!(r["source_table"], "ual_events");
    assert_eq!(r["source"], "ual");
    assert_eq!(r["operation"], "Send");
    assert_eq!(r["actor_upn"], "jdoe@contoso.example");
    assert_eq!(r["ip"], "203.0.113.45");
    assert_eq!(r["entra_session_id"], S1);
    assert!(
        r["event_time"]
            .as_str()
            .unwrap()
            .starts_with("2026-09-01T10:00:00")
    );
    assert_eq!(r["flag"], Value::Null);
    assert_eq!(r["tags"], serde_json::json!([]));
    assert_eq!(r["finding_count"], 0);
}

#[test]
fn events_csv_written() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let case = path.to_str().unwrap();
    let out = tmp.path().join("events.csv");
    let r = run(&[
        "events",
        "--case",
        case,
        "--user",
        "jdoe@contoso.example",
        "--csv",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.out, format!("wrote 3 rows to {}\n", out.display()));
    let text = std::fs::read_to_string(&out).unwrap();
    let lines: Vec<&str> = text.trim_start_matches('\u{feff}').lines().collect();
    assert_eq!(lines.len(), 4, "{text}");
    assert!(
        lines[1].starts_with("2026-09-01T10:10:00Z,signin_interactive,UserLoggedIn,"),
        "{}",
        lines[1]
    );
    // --json prints the count too.
    let v = json(&[
        "--json",
        "events",
        "--case",
        case,
        "--csv",
        out.to_str().unwrap(),
    ]);
    assert_eq!(v["rows"], 4);
}

#[test]
fn entity_json_has_tiles_and_pivots() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let case = path.to_str().unwrap();
    let v = json(&[
        "--json",
        "entity",
        "--case",
        case,
        "--user",
        "JDoe@contoso.example",
    ]);
    assert_eq!(
        v["summary"]["entity"],
        serde_json::json!({ "account": "jdoe@contoso.example" })
    );
    assert_eq!(v["summary"]["events"], 3);
    assert_eq!(v["summary"]["distinct"]["ips"], 2);
    assert_eq!(v["summary"]["distinct"]["sessions"], 2);
    assert_eq!(v["summary"]["distinct"]["devices"], 1);
    // An account has IP, device and session pivots, no account or device-change pivot.
    let pivots = v["pivots"].as_object().unwrap();
    assert_eq!(
        pivots.keys().cloned().collect::<Vec<_>>(),
        ["devices", "ips", "sessions"]
    );
    assert_eq!(pivots["ips"]["total"], 2);
    let ips = pivots["ips"]["rows"].as_array().unwrap();
    assert_eq!(ips.len(), 2);
    assert_eq!(ips[0]["value"], "203.0.113.45");
    assert_eq!(ips[0]["count"], 2);
    assert_eq!(ips[1]["value"], "198.51.100.7");
    assert_eq!(pivots["sessions"]["total"], 2);
    assert_eq!(v["findings"], serde_json::json!([]));

    let r = run(&["entity", "--case", case, "--ip", "203.0.113.45"]);
    assert_eq!(r.code, 0, "{}", r.err);
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(lines[0], "ip 203.0.113.45");
    assert_eq!(
        lines[1],
        "events 2  first 2026-09-01T10:00:00Z  last 2026-09-01T10:05:00Z"
    );
    assert!(lines.contains(&"accounts (1)"), "{}", r.out);
    assert!(lines.contains(&"findings (0)"), "{}", r.out);
    let r = run(&["entity", "--case", case, "--user", "jdoe@contoso.example"]);
    assert_eq!(r.code, 0, "{}", r.err);
    let lines: Vec<&str> = r.out.lines().collect();
    assert!(
        lines.contains(
            &format!("  {DEVICE}  1  2026-09-01T10:10:00Z..2026-09-01T10:10:00Z  JDOE-LAPTOP")
                .as_str()
        ),
        "{}",
        r.out
    );
    assert!(
        lines.contains(&"  198.51.100.7  1  2026-09-01T10:10:00Z..2026-09-01T10:10:00Z"),
        "{}",
        r.out
    );
    // Exactly one entity is required.
    assert_eq!(run(&["entity", "--case", case]).code, 1);
    assert_eq!(
        run(&[
            "entity",
            "--case",
            case,
            "--user",
            "a",
            "--ip",
            "203.0.113.45"
        ])
        .code,
        1
    );
}

#[test]
fn csv_with_offset_or_limit_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let case = path.to_str().unwrap();
    let out = tmp.path().join("e.csv");
    // Supplied is what counts, not the value: the defaults (0, 200) are refused too.
    for extra in [
        ["--offset", "1"],
        ["--offset", "0"],
        ["--limit", "5"],
        ["--limit", "200"],
    ] {
        let r = run(&[
            "events",
            "--case",
            case,
            "--csv",
            out.to_str().unwrap(),
            extra[0],
            extra[1],
        ]);
        assert_eq!(r.code, 1, "{extra:?}");
        assert!(
            r.err.contains("--csv") && r.err.contains("--offset or --limit"),
            "{}",
            r.err
        );
        assert!(!out.exists(), "{extra:?}");
    }
    // Without either, it writes.
    assert_eq!(
        run(&["events", "--case", case, "--csv", out.to_str().unwrap()]).code,
        0
    );
}

#[test]
fn device_option_takes_an_id_and_where_takes_a_name() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let case = path.to_str().unwrap();
    let first = |r: &events_common::Run| r.out.lines().next().unwrap().to_string();
    // The name is not an entity id: no rows.
    let r = run(&["events", "--case", case, "--device", "JDOE-LAPTOP"]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(first(&r), "total 0  showing 0 from offset 0");
    // The same name in the field filter finds the sign-in row.
    let r = run(&["events", "--case", case, "--where", "device=JDOE-LAPTOP"]);
    assert_eq!(first(&r), "total 1  showing 1 from offset 0");
    assert!(r.out.contains("UserLoggedIn"), "{}", r.out);
    // The id works as an entity.
    let r = run(&["events", "--case", case, "--device", DEVICE]);
    assert_eq!(first(&r), "total 1  showing 1 from offset 0");
}
