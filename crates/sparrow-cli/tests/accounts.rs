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
    // The ingest stops at exit 2 for the deliberate AllRoles row, as the end-to-end test knows.
    let ingest = run(&["ingest", tree.dir.to_str().unwrap(), "--case", case]);
    assert!(ingest.code == 0 || ingest.code == 2, "{}", ingest.err);

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

    // ---- pivot user: the addresses section ----
    let p = json(&["pivot", "user", &upn, "--case", case]);
    let section = p["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "addresses")
        .expect("an addresses section");
    assert_eq!(
        section["total"].as_u64().unwrap(),
        top["addresses_total"].as_u64().unwrap()
    );
    assert!(!section["rows"].as_array().unwrap().is_empty());

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

    // ---- detection builds it again ----
    let d = run(&["detect", "--case", case]);
    assert_eq!(d.code, 0, "{}", d.err);
    let again = json(&["accounts", "--case", case]);
    assert_eq!(again["total"], all["total"]);
    assert_eq!(again["warnings"], serde_json::json!([]));
}
