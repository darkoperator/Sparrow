//! `sparrow coverage` through the binary on a small synthetic case (contoso.example): the exact text for one
//! account, the JSON shape, `--user` and that the command writes nothing.
//!
//! The case: tenant `t1`, one collection. carol has a finding first seen 2026-06-16 (window 2026-05-17..2026-07-31),
//! three UAL rows from a capped export (06-12 08:00, 06-12 09:00, 06-14 08:00), one interactive sign-in on 06-11 and
//! nothing else; bob's single UAL row on 07-31 makes 07-31 the tenant's last event.

use assert_cmd::Command;
use duckdb::params;
use serde_json::Value;
use sparrow_core::Case;

struct Run {
    code: i32,
    out: String,
    err: String,
}

fn run(args: &[&str]) -> Run {
    let out = Command::cargo_bin("sparrow")
        .unwrap()
        .args(args)
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap(),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn build(path: &std::path::Path) {
    let case = Case::create_or_open(path).unwrap();
    let c = case.conn();
    c.execute_batch(
        r##"INSERT INTO collections (tool, root_path, sparrow_version, tenant_key) VALUES ('invictus', '/x/t1', 't', 't1');
         INSERT INTO source_files (collection_id, rel_path, size_bytes, sha256, status, warnings)
             VALUES (1, 'cap.csv', 1, 'a', 'parsed', CAST('["row count equals known export cap 1000000 — results likely truncated"]' AS JSON)),
                    (1, 'ok.json', 1, 'b', 'parsed', NULL);
         INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, title,
                               actor_upn, first_seen, created_by, created_at, updated_at)
             VALUES ('f1', 'fp1', 't1', 'SPW-ID-004', 1, 'x', 'high', 't', 'carol@contoso.example',
                     CAST('2026-06-16 12:00:00+00' AS TIMESTAMPTZ), 'rule', now(), now());
         INSERT INTO account_rollup (tenant_key, upn, worst_severity, finding_count, by_severity, stages, rules,
                                     addresses, addresses_total, addresses_truncated, computed_run_id)
             VALUES ('t1', 'carol@contoso.example', 'high', 1, '{}', '[]', '[]', '[]', 0, false, 1);
         INSERT INTO signins (record_key, collection_id, event_time, event_type, user_upn)
             VALUES ('s1', 1, CAST('2026-06-11 09:00:00+00' AS TIMESTAMPTZ), 'interactive', 'carol@contoso.example');
         INSERT INTO record_sources VALUES ('signins', 's1', 2, 0, 1, 1, 0, 1, 'h');"##,
    )
    .unwrap();
    for (n, at, user, file) in [
        (1, "2026-06-12 08:00:00", "carol@contoso.example", 1),
        (2, "2026-06-12 09:00:00", "carol@contoso.example", 1),
        (3, "2026-06-14 08:00:00", "carol@contoso.example", 1),
        (4, "2026-07-31 08:00:00", "bob@contoso.example", 2),
    ] {
        let id = format!("00000000-0000-4000-8000-{n:012}");
        c.execute(
            "INSERT INTO ual_events (record_id, collection_id, event_time, time_tz_assumed, time_precision, \
                 organization_id, workload, operation, user_upn, audit_data, data_completeness, synthetic_id) \
             VALUES (CAST(? AS UUID), 1, CAST(? AS TIMESTAMPTZ), false, 'second', \
                 CAST('c9c9c9c9-0000-4000-8000-000000000001' AS UUID), 'Exchange', 'Send', ?, '{}', 'full', false)",
            params![id, format!("{at}+00"), user],
        )
        .unwrap();
        c.execute(
            "INSERT INTO record_sources VALUES ('ual_events', ?, ?, 0, 1, 1, 0, 1, 'h')",
            params![id, file],
        )
        .unwrap();
    }
}

#[test]
fn coverage_through_the_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let case = path.to_str().unwrap();
    let rows_before = |sql: &str| -> i64 {
        let c = Case::open_read_only(&path).unwrap();
        c.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    };
    let audit_before = rows_before("SELECT count(*) FROM audit_trail");

    // ---- text, one account: the exact lines of the source block, then the requests ----
    let r = run(&["coverage", "--case", case]);
    assert_eq!(r.code, 0, "{}", r.err);
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(
        &lines[..8],
        [
            "carol@contoso.example  t1  window 2026-05-17..2026-07-31",
            "  ual  rows 3  2026-06-12..2026-06-14  2 days  SAMPLED",
            "  signins_interactive  rows 1  2026-06-11..2026-06-11  1 day",
            "  signins_noninteractive  absent",
            "  mail_items_accessed  absent",
            "  message_trace  absent",
            "  entra_audit  absent",
            "  mailbox_audit  absent",
        ],
        "{}",
        r.out
    );
    assert_eq!(
        lines[8],
        "  Request: ual  2026-05-17..2026-07-31  (before, sampled, after)"
    );
    assert_eq!(
        lines[9],
        "    console: Purview portal > Audit > Search: Users = carol@contoso.example, date range 2026-05-17 to 2026-07-31, Search, then Export (a per-user search stays under the 1,000,000-row cap)"
    );
    assert_eq!(lines[10], "    hawk: - (no matching command)");
    assert_eq!(
        lines[11],
        "    invictus: Get-UAL -UserIds carol@contoso.example -StartDate 2026-05-17 -EndDate 2026-08-01"
    );
    // One account, with a request per source that has a gap (seven sources, all with gaps), four lines each.
    assert_eq!(lines.len(), 8 + 7 * 4, "{}", r.out);

    // ---- JSON ----
    let r = run(&[
        "--json",
        "coverage",
        "--case",
        case,
        "--user",
        "CAROL@contoso.example",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(v["warnings"], serde_json::json!([]));
    let accounts = v["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    let a = &accounts[0];
    assert_eq!(a["upn"], "carol@contoso.example");
    assert_eq!(
        a["window"],
        serde_json::json!({"start": "2026-05-17", "end": "2026-07-31"})
    );
    let ual = &a["sources"][0];
    assert_eq!(ual["source"], "ual");
    assert_eq!(ual["rows"], 3);
    assert_eq!(ual["days"], 2);
    assert_eq!(ual["sampled"], true);
    assert_eq!(ual["first"], "2026-06-12T08:00:00.000000Z");
    assert_eq!(
        ual["gaps"],
        serde_json::json!([
            {"from": "2026-05-17", "to": "2026-06-11", "reason": "before"},
            {"from": "2026-06-12", "to": "2026-06-14", "reason": "sampled"},
            {"from": "2026-06-15", "to": "2026-07-31", "reason": "after"},
        ])
    );
    let req = &v["requests"][0];
    assert_eq!(req["source"], "ual");
    assert_eq!(req["hawk"], Value::Null);
    assert_eq!(
        req["reasons"],
        serde_json::json!(["before", "sampled", "after"])
    );

    // ---- --user for someone with no evidence; --tenant that does not exist ----
    let r = run(&[
        "coverage",
        "--case",
        case,
        "--user",
        "nobody@contoso.example",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.starts_with(
            "nobody@contoso.example  t1  window 2026-06-11..2026-07-31\n  ual  absent\n"
        ),
        "{}",
        r.out
    );
    let r = run(&[
        "coverage",
        "--case",
        case,
        "--tenant",
        "nope",
        "--user",
        "bob@contoso.example",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("no tenant"), "{}", r.err);

    // Read-only: the audit trail did not move.
    assert_eq!(
        rows_before("SELECT count(*) FROM audit_trail"),
        audit_before
    );
}
