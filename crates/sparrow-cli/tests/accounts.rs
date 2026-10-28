//! `sparrow accounts`, the `facts` and evidence `context` of `finding show`, and the `addresses` section of
//! `pivot user` (agent accuracy T4), through the binary on a generated bec-aitm case. One test builds and
//! reads the case; the pre-feature and failed-enrichment variants are made from the same file.

use assert_cmd::Command;
use serde_json::Value;
use sparrow_synth::options::{Collector, GenerateOptions};

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
        code: out.status.code().expect("sparrow was killed by a signal"),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn json(args: &[&str]) -> Value {
    let mut a = vec!["--json"];
    a.extend_from_slice(args);
    let r = run(&a);
    assert_eq!(r.code, 0, "sparrow {a:?}\nstderr: {}", r.err);
    serde_json::from_str(&r.out)
        .unwrap_or_else(|e| panic!("sparrow {a:?} printed no JSON ({e}): {}", r.out))
}

#[test]
fn the_readers_of_the_enrichment_tables_through_the_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let case_path = tmp.path().join("case.duckdb");
    let case = case_path.to_str().unwrap();
    let cache = sparrow_synth::test_cache!();
    let scenario = sparrow_synth::scenario::load("bec-aitm").unwrap();
    let tree = cache
        .tree(&scenario, &GenerateOptions::new(Collector::Invictus, 17))
        .unwrap();
    // The ingest exits 6 for the deliberate AllRoles row the collector lost, as the end-to-end test knows.
    let ingest = run(&["ingest", tree.dir.to_str().unwrap(), "--case", case]);
    assert!(ingest.code == 0 || ingest.code == 6, "{}", ingest.err);

    // ---- accounts: JSON shape, order, limit, tenant ----
    let all = json(&["accounts", "--case", case]);
    let accounts = all["accounts"].as_array().unwrap();
    assert!(accounts.len() >= 2, "{all}");
    assert_eq!(all["total"].as_u64().unwrap(), accounts.len() as u64);
    assert_eq!(all["truncated"], false);
    assert_eq!(all["warnings"], serde_json::json!([]));
    let rank = |s: &str| {
        ["critical", "high", "medium", "low", "info"]
            .iter()
            .position(|x| *x == s)
            .unwrap()
    };
    let ranks: Vec<usize> = accounts
        .iter()
        .map(|a| rank(a["worst_severity"].as_str().unwrap()))
        .collect();
    assert!(
        ranks.windows(2).all(|w| w[0] <= w[1]),
        "worst severity first: {ranks:?}"
    );
    let top = &accounts[0];
    for key in [
        "tenant_key",
        "upn",
        "worst_severity",
        "finding_count",
        "by_severity",
        "stages",
        "first_suspicious",
        "rules",
        "addresses",
        "addresses_total",
        "addresses_truncated",
    ] {
        assert!(top.get(key).is_some(), "{key} missing in {top}");
    }
    let upn = top["upn"].as_str().unwrap().to_string();
    let limited = json(&["accounts", "--case", case, "--limit", "1"]);
    assert_eq!(limited["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(limited["accounts"][0]["upn"], top["upn"]);
    assert_eq!(limited["total"], all["total"]);
    assert_eq!(limited["truncated"], true);
    let tenant = top["tenant_key"].as_str().unwrap();
    let t = json(&["accounts", "--case", case, "--tenant", tenant]);
    assert_eq!(t["total"], all["total"]);
    let none = json(&["accounts", "--case", case, "--tenant", "no-such-tenant"]);
    assert_eq!(
        (
            none["total"].as_u64(),
            none["accounts"].as_array().map(Vec::len)
        ),
        (Some(0), Some(0))
    );
    assert_eq!(
        none["warnings"],
        serde_json::json!([]),
        "an unknown tenant is not 'facts unavailable'"
    );

    // ---- accounts: plain text ----
    let plain = run(&["accounts", "--case", case, "--limit", "2"]);
    assert_eq!(plain.code, 0, "{}", plain.err);
    assert!(
        plain.out.contains(&upn) && plain.out.contains("stages "),
        "{}",
        plain.out
    );
    assert!(
        plain
            .out
            .contains(&format!("2 of {} accounts", all["total"])),
        "{}",
        plain.out
    );
    assert!(plain.err.is_empty(), "{}", plain.err);

    // ---- finding show: facts on a persistence finding, context on every evidence row ----
    let findings = json(&["finding", "list", "--case", case, "--user", &upn]);
    let list = findings["findings"].as_array().unwrap();
    let mut with_facts = None;
    for f in list {
        let id = f["finding_id"].as_str().unwrap();
        let d = json(&["finding", "show", id, "--case", case]);
        for e in d["evidence"].as_array().unwrap() {
            assert!(
                e.as_object().unwrap().contains_key("context"),
                "context key missing: {e}"
            );
        }
        if d.get("facts").is_some() {
            assert!(d.get("facts_unavailable").is_none());
            assert_eq!(d["facts"]["facts_version"], 1);
            assert!(
                d["facts"]["actor_ips"].is_array() && d["facts"]["other_signals"]["total"].is_u64()
            );
            with_facts = Some(id.to_string());
        } else {
            assert!(d.get("facts_unavailable").is_none(), "{id}: {d}");
        }
    }
    let with_facts = with_facts.expect("the top account has a persistence finding with facts");
    let human = run(&["finding", "show", &with_facts, "--case", case]);
    assert_eq!(human.code, 0, "{}", human.err);
    assert!(human.out.contains("facts (window start"), "{}", human.out);
    assert!(
        !human.out.to_lowercase().contains("malicious")
            && !human.out.to_lowercase().contains("benign")
    );

    // ---- stored facts are shown whatever rules the reader loads (a --rules override without the stage) ----
    {
        let d = json(&["finding", "show", &with_facts, "--case", case]);
        let rule_id = d["finding"]["rule_id"].as_str().unwrap().to_string();
        let builtin = find_rule_file(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules"),
            &rule_id,
        );
        let text = std::fs::read_to_string(&builtin).unwrap();
        let unstaged: String = text
            .lines()
            .filter(|l| !l.starts_with("stage:"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_ne!(unstaged, text, "{rule_id} declares a stage");
        let dir = tmp.path().join("rules");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{rule_id}.yaml")), unstaged).unwrap();
        let o = json(&[
            "finding",
            "show",
            &with_facts,
            "--case",
            case,
            "--rules",
            dir.to_str().unwrap(),
        ]);
        assert_eq!(o["facts"], d["facts"], "{o}");
        assert!(o.get("facts_unavailable").is_none());
    }

    // ---- pivot user: the addresses section ----
    let p = json(&["pivot", "user", &upn, "--case", case]);
    let section = p["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "addresses")
        .expect("an addresses section");
    assert!(section.get("unavailable").is_none(), "{section}");
    assert_eq!(
        section["total"].as_u64().unwrap(),
        top["addresses_total"].as_u64().unwrap()
    );
    assert!(!section["rows"].as_array().unwrap().is_empty());

    // ---- exports: --rules/--data and the env vars are accepted, unloadable rules never abort an export ----
    let report = tmp.path().join("r.md");
    let r = run(&[
        "export",
        "report",
        "--case",
        case,
        "--out",
        report.to_str().unwrap(),
        "--rules",
        "/nonexistent/rules",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    let md = std::fs::read_to_string(&report).unwrap();
    assert!(
        md.contains("## Accounts") && md.contains("| Tenant | Account |"),
        "{md}"
    );
    let r = run(&[
        "export",
        "report",
        "--case",
        case,
        "--out",
        report.to_str().unwrap(),
        "--reviewed-only",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    let md = std::fs::read_to_string(&report).unwrap();
    assert!(
        md.contains("Account roll-up omitted")
            && md.contains("Evidence coverage omitted")
            && !md.contains("| Tenant | Account |"),
        "{md}"
    );
    let xlsx = tmp.path().join("w.xlsx");
    let bad_env = Command::cargo_bin("sparrow")
        .unwrap()
        .env("SPARROW_RULES", "/nonexistent/rules")
        .args([
            "export",
            "workbook",
            "--case",
            case,
            "--out",
            xlsx.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        bad_env.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&bad_env.stderr)
    );
    assert!(xlsx.is_file());

    // ---- a case detected before the feature: empty list, warning, facts_unavailable (Review Focus 1) ----
    {
        let c = sparrow_core::Case::create_or_open(&case_path).unwrap();
        c.conn()
            .execute_batch(
                "DELETE FROM finding_facts; DELETE FROM account_rollup; \
                 DELETE FROM case_meta WHERE key IN ('enrichment_run_id', 'enrichment_error');",
            )
            .unwrap();
    }
    let page = json(&["accounts", "--case", case]);
    assert_eq!(page["accounts"], serde_json::json!([]));
    assert_eq!(page["total"], 0);
    let w = page["warnings"][0].as_str().unwrap();
    assert!(w.contains("`sparrow detect`"), "{w}");
    let plain = run(&["accounts", "--case", case]);
    assert_eq!(plain.code, 0);
    assert!(
        plain.err.contains("`sparrow detect`") && plain.out.contains("0 of 0 accounts"),
        "{} / {}",
        plain.err,
        plain.out
    );
    let d = json(&["finding", "show", &with_facts, "--case", case]);
    assert!(
        d["facts_unavailable"]
            .as_str()
            .unwrap()
            .contains("`sparrow detect`"),
        "{d}"
    );
    assert!(d.get("facts").is_none());
    let human = run(&["finding", "show", &with_facts, "--case", case]);
    assert!(human.out.contains("facts unavailable:"), "{}", human.out);
    let p = json(&["pivot", "user", &upn, "--case", case]);
    let section = p["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "addresses")
        .unwrap();
    assert_eq!(section["rows"], serde_json::json!([]));
    assert!(
        section["unavailable"]
            .as_str()
            .is_some_and(|u| u.contains("`sparrow detect`")),
        "{section}"
    );
    let plain = run(&["pivot", "user", &upn, "--case", case]);
    assert_eq!(plain.code, 0, "{}", plain.err);
    assert!(
        plain.out.contains("addresses unavailable: ") && plain.out.contains("`sparrow detect`"),
        "{}",
        plain.out
    );

    // Not current and the rules unloadable (the env var): the export succeeds and says why.
    let bad_env = Command::cargo_bin("sparrow")
        .unwrap()
        .env("SPARROW_RULES", "/nonexistent/rules")
        .args([
            "export",
            "report",
            "--case",
            case,
            "--out",
            report.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        bad_env.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&bad_env.stderr)
    );
    let md = std::fs::read_to_string(&report).unwrap();
    assert!(
        md.contains("## Accounts") && md.contains("sparrow detect"),
        "{md}"
    );
    // The workbook carries the facts of every finding: the family findings say why they are unavailable.
    let bad_env = Command::cargo_bin("sparrow")
        .unwrap()
        .env("SPARROW_RULES", "/nonexistent/rules")
        .args([
            "export",
            "workbook",
            "--case",
            case,
            "--out",
            xlsx.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        bad_env.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&bad_env.stderr)
    );
    let mut wb: calamine::Xlsx<_> = calamine::open_workbook(&xlsx).unwrap();
    let range = calamine::Reader::worksheet_range(&mut wb, "Findings").unwrap();
    let head: Vec<String> = range
        .rows()
        .next()
        .unwrap()
        .iter()
        .map(|c| c.to_string())
        .collect();
    let col = head.iter().position(|h| h == "Facts").unwrap();
    assert!(
        range.rows().skip(1).any(|r| {
            let t = r[col].to_string();
            t.starts_with("{\"facts_unavailable\":") && t.contains("rules could not be loaded")
        }),
        "no Facts cell says why it is unavailable"
    );

    // ---- detection builds it again ----
    let d = run(&["detect", "--case", case]);
    assert_eq!(d.code, 0, "{}", d.err);
    let again = json(&["accounts", "--case", case]);
    assert_eq!(again["total"], all["total"]);
    assert_eq!(again["warnings"], serde_json::json!([]));
}

/// The plain-text block of each account: its header line and the indented lines under it.
fn blocks(out: &str) -> Vec<(String, Vec<String>)> {
    let mut v: Vec<(String, Vec<String>)> = Vec::new();
    for l in out.lines() {
        if l.starts_with("  ") {
            v.last_mut()
                .expect("a block header first")
                .1
                .push(l.to_string());
        } else if l.contains(" findings)") {
            v.push((l.to_string(), Vec::new()));
        }
    }
    v
}

#[test]
fn each_account_shows_its_signin_coverage_and_the_never_a_signin_note_only_when_it_has_one() {
    let tmp = tempfile::tempdir().unwrap();
    let case_path = tmp.path().join("case.duckdb");
    let case = case_path.to_str().unwrap();
    let cache = sparrow_synth::test_cache!();
    let scenario = sparrow_synth::scenario::load("bec-aitm").unwrap();
    let tree = cache
        .tree(&scenario, &GenerateOptions::new(Collector::Invictus, 17))
        .unwrap();
    let ingest = run(&["ingest", tree.dir.to_str().unwrap(), "--case", case]);
    assert!(ingest.code == 0 || ingest.code == 6, "{}", ingest.err);

    // Both accounts first have sign-ins; the second then loses every sign-in of its own, as if they had
    // never been collected, and detection rebuilds the roll-up.
    let before = json(&["accounts", "--case", case]);
    let accounts = before["accounts"].as_array().unwrap();
    assert!(accounts.len() >= 2, "{before}");
    let (covered, bare) = (&accounts[0], &accounts[1]);
    let (covered_upn, bare_upn) = (
        covered["upn"].as_str().unwrap().to_string(),
        bare["upn"].as_str().unwrap().to_string(),
    );
    for a in [covered, bare] {
        assert!(
            a["signins_first"].is_string() && a["signins_last"].is_string(),
            "{a}"
        );
    }
    {
        let c = sparrow_core::Case::create_or_open(&case_path).unwrap();
        c.conn()
            .execute(
                "DELETE FROM signins WHERE lower(user_upn) = ?",
                [bare_upn.as_str()],
            )
            .unwrap();
    }
    let d = run(&["detect", "--case", case]);
    assert_eq!(d.code, 0, "{}", d.err);

    let after = json(&["accounts", "--case", case]);
    let find = |upn: &str| {
        after["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["upn"] == upn)
            .unwrap_or_else(|| panic!("{upn} missing in {after}"))
            .clone()
    };
    let (covered, bare) = (find(&covered_upn), find(&bare_upn));
    assert!(bare["signins_first"].is_null() && bare["signins_last"].is_null());
    assert!(
        bare["addresses"]
            .as_array()
            .unwrap()
            .iter()
            .all(|x| !x["reasons"]
                .as_array()
                .unwrap()
                .contains(&"acts_without_signin".into())),
        "an account with no sign-ins has no acts_without_signin: {bare}"
    );
    let shown = |t: &Value| {
        let t = t.as_str().unwrap();
        chrono::DateTime::parse_from_rfc3339(t)
            .unwrap()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    };
    let want_covered = format!(
        "sign-ins {} to {}",
        shown(&covered["signins_first"]),
        shown(&covered["signins_last"])
    );

    let plain = run(&["accounts", "--case", case]);
    assert_eq!(plain.code, 0, "{}", plain.err);
    let all = blocks(&plain.out);
    let block = |upn: &str| {
        all.iter()
            .find(|(h, _)| h.contains(upn))
            .unwrap_or_else(|| panic!("{upn} missing in {}", plain.out))
    };
    let note = "(never a sign-in of this account)";

    let (head, lines) = block(&covered_upn);
    let stages_line = &lines[0];
    assert!(
        stages_line.contains("first suspicious") && stages_line.ends_with(&want_covered),
        "{stages_line} / {want_covered}"
    );
    assert!(!head.contains("no sign-ins collected"));
    // The covered account has an address that never signed it in: the note is printed on exactly those.
    assert!(
        covered["addresses"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["in_user_signins"] == false),
        "the covered account lists an address outside its sign-ins"
    );
    let noted = lines.iter().filter(|l| l.ends_with(note)).count();
    let expected = covered["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .take(5)
        .filter(|x| x["in_user_signins"] == false)
        .count();
    assert_eq!(noted, expected, "{lines:#?}");
    assert!(noted >= 1);

    let (_, lines) = block(&bare_upn);
    assert!(
        lines[0].ends_with("no sign-ins collected") && !lines[0].contains("sign-ins 20"),
        "{}",
        lines[0]
    );
    assert!(
        lines.len() >= 2,
        "the uncovered account still lists an address for another reason: {lines:#?}"
    );
    assert!(
        lines.iter().all(|l| !l.contains(note)),
        "no note on an account without sign-ins: {lines:#?}"
    );
}

/// `<dir>/**/<id>.yaml`.
fn find_rule_file(dir: &std::path::Path, id: &str) -> std::path::PathBuf {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            let f = p.join(format!("{id}.yaml"));
            if f.is_file() {
                return f;
            }
        }
    }
    panic!("no rule file for {id} under {}", dir.display())
}
