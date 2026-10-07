//! `sparrow accounts` is discoverable from the commands an agent runs first: `summary` and `capabilities` carry a
//! `next` array, `summary` the top three accounts (or why they are unavailable), the command list names `accounts`
//! first among the read commands and `finding list --help` points to it. The outputs only GAIN keys.

use assert_cmd::Command;
use serde_json::Value;
use sparrow_synth::options::{Collector, GenerateOptions};

fn sparrow(args: &[&str]) -> std::process::Output {
    Command::cargo_bin("sparrow")
        .unwrap()
        .args(args)
        .output()
        .unwrap()
}

fn json(args: &[&str]) -> Value {
    let mut a = vec!["--json"];
    a.extend_from_slice(args);
    let o = sparrow(&a);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{a:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{a:?}: {e}"))
}

fn text(args: &[&str]) -> String {
    let o = sparrow(args);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

#[test]
fn summary_and_capabilities_point_to_accounts_and_only_gain_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let case_path = tmp.path().join("case.duckdb");
    let case = case_path.to_str().unwrap();
    let cache = sparrow_synth::test_cache!();
    let scenario = sparrow_synth::scenario::load("bec-aitm").unwrap();
    let tree = cache
        .tree(&scenario, &GenerateOptions::new(Collector::Invictus, 17))
        .unwrap();
    // Exit 2 is the deliberate AllRoles row, as the end-to-end tests know.
    let ingest = sparrow(&["ingest", tree.dir.to_str().unwrap(), "--case", case]);
    assert!(matches!(ingest.status.code(), Some(0) | Some(2)));

    let first = format!(
        "sparrow accounts --case {case} --json: one row per account with findings (stages, first suspicious time, addresses worth a look)"
    );

    // ---- summary: the existing keys stay, `next` and `top_accounts` are added ----
    let s = json(&["summary", "--case", case]);
    for k in [
        "profile_evaluated_at",
        "stale",
        "stale_collections",
        "tables",
        "tenants",
    ] {
        assert!(s.get(k).is_some(), "summary lost {k}");
    }
    assert_eq!(
        keys(&s),
        [
            "next",
            "profile_evaluated_at",
            "stale",
            "stale_collections",
            "tables",
            "tenants",
            "top_accounts"
        ],
        "{s}"
    );
    assert_eq!(s["next"][0], first.as_str());
    let all = json(&["accounts", "--case", case]);
    let want: Vec<&Value> = all["accounts"].as_array().unwrap().iter().take(3).collect();
    assert_eq!(want.len(), 3, "the case has at least three accounts");
    let top = s["top_accounts"].as_array().unwrap();
    assert_eq!(top.len(), 3);
    for (row, acc) in top.iter().zip(&want) {
        assert_eq!(
            keys(row),
            [
                "addresses_total",
                "first_suspicious",
                "stages",
                "tenant_key",
                "upn",
                "worst_severity"
            ],
            "{row}"
        );
        for k in [
            "upn",
            "tenant_key",
            "worst_severity",
            "stages",
            "first_suspicious",
            "addresses_total",
        ] {
            assert_eq!(row[k], acc[k], "{k} of {}", acc["upn"]);
        }
    }
    assert!(s.get("top_accounts_unavailable").is_none());

    // ---- capabilities: only `next`, and no account data ----
    let c = json(&["capabilities", "--case", case]);
    assert_eq!(
        keys(&c),
        ["as_of", "next", "stale", "stale_collections", "tenants"],
        "{c}"
    );
    assert_eq!(c["next"][0], first.as_str());
    assert!(c.get("top_accounts").is_none());

    // ---- plain output: an Accounts block and Next: lines at the end ----
    let plain = text(&["summary", "--case", case]);
    let at = plain.find("Accounts").expect("an Accounts block");
    assert!(
        plain[at..].contains(top[0]["upn"].as_str().unwrap()),
        "{plain}"
    );
    let next = plain.rfind("Next:").expect("Next: lines");
    assert!(
        next > at && plain[next..].contains("sparrow accounts --case"),
        "{plain}"
    );
    let plain_caps = text(&["capabilities", "--case", case]);
    assert!(
        plain_caps.contains("Next:")
            && plain_caps.rfind("Next:").unwrap() > plain_caps.find("evidence:").unwrap()
    );
    assert!(
        !plain_caps.contains("Accounts"),
        "capabilities stays about evidence"
    );

    // ---- a case that was never enriched: the reason, no rows ----
    {
        let c = sparrow_core::Case::create_or_open(&case_path).unwrap();
        c.conn()
            .execute_batch(
                "DELETE FROM finding_facts; DELETE FROM account_rollup; \
                 DELETE FROM case_meta WHERE key IN ('enrichment_run_id', 'enrichment_error');",
            )
            .unwrap();
    }
    let s = json(&["summary", "--case", case]);
    assert!(s.get("top_accounts").is_none(), "{s}");
    let why = s["top_accounts_unavailable"].as_str().unwrap();
    let accounts_reason = json(&["accounts", "--case", case])["warnings"][0]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        why, accounts_reason,
        "the same reason `sparrow accounts` gives"
    );
    assert!(why.contains("`sparrow detect`"), "{why}");
    assert_eq!(s["next"][0], first.as_str());
    let plain = text(&["summary", "--case", case]);
    assert!(
        plain.contains("Accounts: unavailable")
            && plain.contains("sparrow detect")
            && plain.contains("Next:"),
        "{plain}"
    );
}

#[test]
fn help_lists_accounts_first_among_the_read_commands_and_finding_list_points_to_it() {
    let help = text(&["--help"]);
    let line = |name: &str| {
        help.lines()
            .position(|l| l.trim_start().starts_with(&format!("{name} ")))
            .unwrap_or_else(|| panic!("{name} not in the command list:\n{help}"))
    };
    let accounts = line("accounts");
    for read in [
        "capabilities",
        "summary",
        "finding",
        "timeline",
        "pivot",
        "query",
    ] {
        assert!(accounts < line(read), "accounts must come before {read}");
    }
    let l = help.lines().nth(accounts).unwrap();
    assert!(l.contains("Start triage here"), "{l}");
    // The write commands before it are not read commands.
    assert!(line("ingest") < accounts && line("profile") < accounts);
    let list = text(&["finding", "list", "--help"]);
    assert!(list.contains("sparrow accounts"), "{list}");
}
