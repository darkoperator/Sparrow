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
    // Exit 6 is the deliberate AllRoles row the collector lost, as the end-to-end tests know.
    let ingest = sparrow(&["ingest", tree.dir.to_str().unwrap(), "--case", case]);
    assert!(matches!(ingest.status.code(), Some(0) | Some(6)));

    let first = serde_json::json!({
        "command": format!("sparrow accounts --case '{case}' --json"),
        "about": "one row per account with findings (stages, first suspicious time, addresses worth a look)",
    });

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
    assert_eq!(s["next"][0], first);
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
    assert_eq!(c["next"][0], first);
    assert!(c.get("top_accounts").is_none());

    // ---- plain output: an Accounts block and Next: lines at the end ----
    let plain = text(&["summary", "--case", case]);
    let at = plain.find("Accounts").expect("an Accounts block");
    assert!(
        plain[at..].contains(top[0]["upn"].as_str().unwrap()),
        "{plain}"
    );
    let next = plain.rfind("Next:").expect("Next: lines");
    assert!(next > at, "{plain}");
    // `Next: <command>` on one line, the about text on its own indented line.
    let lines: Vec<&str> = plain[next..].lines().collect();
    assert_eq!(
        lines[0],
        format!("Next: sparrow accounts --case '{case}' --json"),
        "{plain}"
    );
    assert_eq!(
        lines[1],
        "  one row per account with findings (stages, first suspicious time, addresses worth a look)"
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
    assert_eq!(s["next"][0], first);
    let plain = text(&["summary", "--case", case]);
    assert!(
        plain.contains("Accounts: unavailable")
            && plain.contains("sparrow detect")
            && plain.contains("Next: sparrow accounts"),
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

/// A case path with a space, a single quote and `;` (and one with a control character): the `next` command is
/// shell-quoted so that running it executes `sparrow accounts` on that very case, in JSON and in plain output.
#[test]
fn the_next_command_is_shell_quoted_and_runs_on_an_odd_case_path() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = sparrow_synth::test_cache!();
    let scenario = sparrow_synth::scenario::load("bec-aitm").unwrap();
    let tree = cache
        .tree(&scenario, &GenerateOptions::new(Collector::Invictus, 17))
        .unwrap();
    let odd = tmp.path().join("my case's; touch pwned.duckdb");
    let case = odd.to_str().unwrap();
    let ingest = sparrow(&["ingest", tree.dir.to_str().unwrap(), "--case", case]);
    assert!(matches!(ingest.status.code(), Some(0) | Some(6)));

    // The binary's directory on PATH, so `sparrow ...` in the command resolves like an installed one.
    let bin = assert_cmd::cargo::cargo_bin("sparrow");
    let path = format!(
        "{}:{}",
        bin.parent().unwrap().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let expected = json(&["accounts", "--case", case]);

    for cmd in ["summary", "capabilities"] {
        let v = json(&[cmd, "--case", case]);
        let next = &v["next"][0];
        let command = next["command"].as_str().unwrap();
        assert!(
            !command.contains('\n') && command.starts_with("sparrow accounts --case '"),
            "{command}"
        );
        assert!(
            next["about"]
                .as_str()
                .unwrap()
                .starts_with("one row per account")
        );
        // Run through `sh -c`: it executes `sparrow accounts` on that case, and nothing else.
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("PATH", &path)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let got: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(got["accounts"], expected["accounts"], "{cmd}");
        assert!(
            !tmp.path().join("pwned.duckdb").exists(),
            "the `;` was executed"
        );
        // Plain output: `Next: <command>` (the same command), then the about text.
        let plain = text(&[cmd, "--case", case]);
        let line = plain.lines().find(|l| l.starts_with("Next: ")).unwrap();
        assert_eq!(line, format!("Next: {command}"));
    }
}

/// The same account name in two tenants stays two distinguishable lines in `summary`, and a name with a control
/// character cannot spoof output: tenant and UPN go through `display_safe_line` like `sparrow accounts`.
#[test]
fn plain_top_accounts_show_the_tenant_and_neutralise_control_characters() {
    let tmp = tempfile::tempdir().unwrap();
    let case_path = tmp.path().join("case.duckdb");
    let case = case_path.to_str().unwrap();
    let cache = sparrow_synth::test_cache!();
    let scenario = sparrow_synth::scenario::load("bec-aitm").unwrap();
    let tree = cache
        .tree(&scenario, &GenerateOptions::new(Collector::Invictus, 17))
        .unwrap();
    let ingest = sparrow(&["ingest", tree.dir.to_str().unwrap(), "--case", case]);
    assert!(matches!(ingest.status.code(), Some(0) | Some(6)));
    let ranked = json(&["accounts", "--case", case]);
    let upn0 = ranked["accounts"][0]["upn"].as_str().unwrap().to_string();
    let upn1 = ranked["accounts"][1]["upn"].as_str().unwrap().to_string();
    {
        let c = sparrow_core::Case::create_or_open(&case_path).unwrap();
        // The top account again in a second tenant (same UPN, same ranking keys), and the next account renamed
        // with a newline and an escape character in its name.
        c.conn()
            .execute(
                "INSERT INTO account_rollup SELECT 'second-tenant', upn, worst_severity, finding_count, by_severity, stages, first_suspicious, rules, addresses, addresses_total, addresses_truncated, computed_run_id FROM account_rollup WHERE upn = ?",
                [&upn0],
            )
            .unwrap();
        c.conn()
            .execute(
                "UPDATE account_rollup SET upn = 'evil' || chr(10) || 'Next: rm -rf /' || chr(27) || '[31m' WHERE upn = ?",
                [&upn1],
            )
            .unwrap();
    }
    let json_top = json(&["summary", "--case", case])["top_accounts"].clone();
    let plain = text(&["summary", "--case", case]);
    let at = plain.find("Accounts (top").unwrap();
    let block: Vec<&str> = plain[at..].lines().take_while(|l| !l.is_empty()).collect();
    // One line per account, each starting with its tenant and UPN.
    assert_eq!(
        block.len() - 1,
        json_top.as_array().unwrap().len(),
        "{block:?}"
    );
    for (line, row) in block[1..].iter().zip(json_top.as_array().unwrap()) {
        let tenant = row["tenant_key"].as_str().unwrap();
        assert!(
            line.trim_start().starts_with(tenant),
            "tenant first: {line}"
        );
    }
    // The same UPN in two tenants is two lines, told apart by the tenant.
    let same: Vec<&&str> = block[1..]
        .iter()
        .filter(|l| l.contains(upn0.as_str()))
        .collect();
    assert_eq!(same.len(), 2, "{block:?}");
    assert!(
        same.iter()
            .any(|l| l.trim_start().starts_with("second-tenant")),
        "{same:?}"
    );
    // The control characters are escaped, never raw: no line of the output starts with the attacker's text
    // and no escape character reaches the terminal.
    assert!(
        !plain.contains('\u{1b}'),
        "an escape character reached the output"
    );
    assert!(plain.lines().all(|l| !l.starts_with("Next: rm")), "{plain}");
    assert!(
        plain.contains("\\u{000A}"),
        "the newline is shown escaped: {plain}"
    );
}
