use assert_cmd::Command;
use predicates::str::contains;
use serde_json::Value;
use sparrow_core::fixtures;

fn sparrow() -> Command {
    Command::cargo_bin("sparrow").unwrap()
}

fn json_out(cmd: &mut Command, expected_code: i32) -> Value {
    let out = cmd.output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(expected_code),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn prints_version() {
    sparrow()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains("sparrow 0.1.0"));
}

#[test]
fn discover_lists_collections_and_classifications() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    fixtures::invictus_tree(dir.path());
    let v = json_out(sparrow().args(["--json", "discover"]).arg(dir.path()), 0);
    let cols = v["collections"].as_array().unwrap();
    assert_eq!(cols.len(), 2);
    assert_eq!(cols[0]["tool"], "hawk");
    let files = cols[0]["files"].as_array().unwrap();
    let log = files.iter().find(|f| f["rel_path"] == "Hawk.log").unwrap();
    assert_eq!(log["artifact_id"], "hawk.log");
    let unknown = files
        .iter()
        .find(|f| f["rel_path"] == "notes/random.bin")
        .unwrap();
    assert!(unknown["artifact_id"].is_null());
}

#[test]
fn ingest_then_reingest_then_verify_then_schema() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let case = dir.path().join("case.duckdb");

    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(dir.path())
            .arg("--case")
            .arg(&case)
            .args(["--culture", "en-US"]),
        0,
    );
    let files = v["collections"][0]["files"].as_array().unwrap();
    assert_eq!(
        files.iter().find(|f| f["rel_path"] == "Hawk.log").unwrap()["status"],
        "parsed"
    );

    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(dir.path())
            .arg("--case")
            .arg(&case),
        0,
    );
    let files = v["collections"][0]["files"].as_array().unwrap();
    // Task 10 controller ruling: on re-ingest, previously `parsed` files report
    // `duplicate_file`; files that were `not_supported` / `unrecognized` are retried
    // and report that status again, not `duplicate_file`.
    assert_eq!(
        files.iter().find(|f| f["rel_path"] == "Hawk.log").unwrap()["status"],
        "duplicate_file",
        "{files:?}"
    );
    assert!(
        files
            .iter()
            .all(|f| f["status"] != "parsed" && f["status"] != "error"),
        "{files:?}"
    );

    let file_id = v["collections"][0]["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rel_path"] == "Hawk.log")
        .unwrap()["file_id"]
        .as_i64()
        .unwrap();
    let key = format!("{file_id}:8");
    let v = json_out(
        sparrow()
            .args(["--json", "verify", "collection_log", &key, "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(v["ok"], true);
    assert!(
        v["sightings"][0]["source_ref"]
            .as_str()
            .unwrap()
            .ends_with("Hawk.log:9-10")
    );

    let v = json_out(
        sparrow()
            .args(["--json", "schema", "source_files", "--case"])
            .arg(&case),
        0,
    );
    let t = &v["tables"][0];
    assert_eq!(t["table"], "source_files");
    assert!(t["comment"].as_str().unwrap().contains("SHA-256"));
    assert!(
        t["columns"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "sha256")
    );
}

#[test]
fn ingest_with_file_errors_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(dir.path())
            .arg("--case")
            .arg(&case)
            .args(["--max-file-size", "10"]),
        2,
    );
    assert!(
        v["collections"][0]["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["status"] == "error")
    );
}

#[test]
fn bad_culture_and_missing_path_exit_1_with_message() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("case.duckdb");
    sparrow()
        .arg("ingest")
        .arg(dir.path())
        .arg("--case")
        .arg(&case)
        .args(["--culture", "xx-YY"])
        .assert()
        .code(1)
        .stderr(contains("error:"))
        .stderr(contains("unsupported culture"));
    sparrow()
        .arg("ingest")
        .arg(dir.path().join("does-not-exist"))
        .arg("--case")
        .arg(&case)
        .assert()
        .code(1)
        .stderr(contains("error:"));
}

#[test]
fn human_output_for_ingest_mentions_statuses() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    sparrow()
        .arg("ingest")
        .arg(dir.path())
        .arg("--case")
        .arg(&case)
        .assert()
        .success()
        .stdout(contains("Hawk.log"))
        .stdout(contains("parsed"))
        .stdout(contains("unrecognized"));
}

#[cfg(unix)]
#[test]
fn discover_lists_unreadable_directories_as_errors() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::hawk_tree(dir.path());
    let locked = root.join("alice@contoso.example");
    let original = std::fs::metadata(&locked).unwrap().permissions();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&locked).is_ok() {
        std::fs::set_permissions(&locked, original).unwrap();
        eprintln!("skipping: chmod 000 directory is still readable (running as root?)");
        return;
    }
    let out = sparrow()
        .args(["--json", "discover"])
        .arg(dir.path())
        .output()
        .unwrap();
    std::fs::set_permissions(&locked, original).unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let files = v["collections"][0]["files"].as_array().unwrap();
    let e = files
        .iter()
        .find(|f| f["rel_path"] == "alice@contoso.example")
        .unwrap();
    assert!(e["artifact_id"].is_null());
    assert!(
        e["error"]
            .as_str()
            .unwrap()
            .contains("alice@contoso.example")
    );
    assert!(files.iter().any(|f| f["rel_path"] == "Hawk.log"));
}

#[test]
fn outdated_case_needs_upgrade_then_schema_works() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("old.duckdb");
    {
        let conn = duckdb::Connection::open(&case).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name VARCHAR NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp);",
        )
        .unwrap();
    }
    sparrow()
        .args(["schema", "--case"])
        .arg(&case)
        .assert()
        .code(1)
        .stderr(contains("sparrow upgrade"));
    let v = json_out(
        sparrow().args(["--json", "upgrade", "--case"]).arg(&case),
        0,
    );
    assert_eq!(v["from"], 0);
    assert!(v["to"].as_u64().unwrap() >= 2);
    sparrow()
        .args(["schema", "--case"])
        .arg(&case)
        .assert()
        .success()
        .stdout(contains("source_files"));
    sparrow()
        .args(["upgrade", "--case"])
        .arg(&case)
        .assert()
        .success();
}

#[test]
fn upgrade_refuses_to_create_a_missing_case() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("nope.duckdb");
    sparrow()
        .args(["upgrade", "--case"])
        .arg(&case)
        .assert()
        .code(1)
        .stderr(contains("not found"));
    assert!(!case.exists());
}

#[test]
fn ingest_hawk4_capture_and_verify_a_ual_record() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    fixtures::hawk4::hawk4_tree(&evidence);
    let case = dir.path().join("case.duckdb");
    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&evidence)
            .arg("--case")
            .arg(&case),
        0,
    );
    let files = v["collections"][0]["files"].as_array().unwrap();
    assert!(
        files
            .iter()
            .any(|f| f["rel_path"] == fixtures::hawk4::HAWK4_PURVIEW
                && f["artifact_id"] == "portal.ual"
                && f["status"] == "parsed")
    );
    let v = json_out(
        sparrow()
            .args([
                "--json",
                "verify",
                "ual_events",
                fixtures::ual::ID_RULE,
                "--case",
            ])
            .arg(&case),
        0,
    );
    assert_eq!(v["ok"], true);
    assert_eq!(v["sightings"].as_array().unwrap().len(), 2);
}

#[test]
fn fatal_errors_are_json_on_stdout_with_json_flag() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("case.duckdb");
    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(dir.path())
            .arg("--case")
            .arg(&case)
            .args(["--culture", "xx-YY"]),
        1,
    );
    assert!(
        v["error"].as_str().unwrap().contains("unsupported culture"),
        "{v}"
    );
}

#[test]
fn ingest_of_a_folder_without_collections_does_not_create_the_case() {
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let case = dir.path().join("case.duckdb");
    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&empty)
            .arg("--case")
            .arg(&case),
        1,
    );
    assert!(v["error"].as_str().unwrap().contains("no Hawk"));
    assert!(!case.exists());
}

#[test]
fn case_inside_the_evidence_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::hawk_tree(dir.path());
    let case = root.join("case.duckdb");
    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(dir.path())
            .arg("--case")
            .arg(&case),
        1,
    );
    assert!(v["error"].as_str().unwrap().contains("inside the evidence"));
    assert!(!case.exists());
}

#[test]
fn schema_of_an_unknown_table_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("case.duckdb");
    sparrow_core::Case::create_or_open(&case).unwrap();
    let v = json_out(
        sparrow()
            .args(["--json", "schema", "nope", "--case"])
            .arg(&case),
        1,
    );
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("no table named 'nope'")
    );
}

#[test]
fn ingest_runs_the_profile_and_profile_reruns_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::hawk_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    let out = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&root)
            .arg("--case")
            .arg(&case),
        0,
    );
    assert!(
        out["profile"]["capabilities"].as_u64().unwrap() >= 11,
        "{out}"
    );
    let out = json_out(
        sparrow().args(["--json", "profile", "--case"]).arg(&case),
        0,
    );
    assert!(out["capabilities"].as_u64().unwrap() >= 11, "{out}");
}

#[test]
fn usage_errors_exit_1_and_are_json_with_the_flag() {
    let v = json_out(sparrow().args(["--json", "ingest"]), 1);
    assert!(v["error"].as_str().unwrap().contains("required"));
    sparrow().args(["ingest"]).assert().code(1);
    sparrow().args(["--help"]).assert().success();
}

#[test]
fn tenant_domains_add_list_remove() {
    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::hawk_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    sparrow()
        .args(["ingest"])
        .arg(&root)
        .arg("--case")
        .arg(&case)
        .assert()
        .success();
    let added = json_out(
        sparrow()
            .args([
                "--json",
                "tenant",
                "domains",
                "add",
                "contoso-legacy.example",
                "--case",
            ])
            .arg(&case),
        0,
    );
    assert!(
        added["note"].as_str().is_some_and(|n| n
            .contains("identities' external/internal kind updates on the next `sparrow profile`")),
        "{added}"
    );
    let listed = json_out(
        sparrow()
            .args(["--json", "tenant", "domains", "list", "--case"])
            .arg(&case),
        0,
    );
    assert!(
        listed["domains"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["domain"] == "contoso-legacy.example" && d["source"] == "analyst"),
        "{listed}"
    );
    let text = sparrow()
        .args([
            "tenant",
            "domains",
            "remove",
            "contoso-legacy.example",
            "--case",
        ])
        .arg(&case)
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("remove contoso-legacy.example"), "{text}");
    assert!(
        text.contains("note: tenant_domains is updated now; identities' external/internal kind updates on the next `sparrow profile`"),
        "{text}"
    );
    let listed = json_out(
        sparrow()
            .args(["--json", "tenant", "domains", "list", "--case"])
            .arg(&case),
        0,
    );
    assert!(
        !listed["domains"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["domain"] == "contoso-legacy.example"),
        "{listed}"
    );
}

#[test]
fn capabilities_json_lists_tenants_capabilities_and_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::invictus::invictus_output_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    sparrow()
        .args(["ingest"])
        .arg(&root)
        .arg("--case")
        .arg(&case)
        .assert()
        .success();
    let out = json_out(
        sparrow()
            .args(["--json", "capabilities", "--case"])
            .arg(&case),
        0,
    );
    let t = &out["tenants"][0];
    assert_eq!(
        t["tenant_id"], "0e0e0e0e-0000-4000-8000-00000000000a",
        "{out}"
    );
    let ev = |id: &str| {
        t["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["evidence"] == id)
            .cloned()
            .unwrap()
    };
    assert_eq!(ev("signins")["status"], "collected", "{out}");
    assert_eq!(
        ev("users")["status"],
        "collected",
        "empty Users export: ran, nothing found: {out}"
    );
    assert_ne!(
        ev("licenses")["status"],
        "collected",
        "the Licenses folder holds only EntraSecurityDefaults (audit_config): {out}"
    );
    assert!(
        t["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "entra_id_p1")
    );

    let text = sparrow()
        .args(["capabilities", "--case"])
        .arg(&case)
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("evidence:"), "{text}");
    assert!(text.contains("signins"), "{text}");
}

#[test]
fn capabilities_without_a_profile_asks_for_one() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("case.duckdb");
    drop(sparrow_core::Case::create_or_open(&case).unwrap());
    sparrow()
        .args(["capabilities", "--case"])
        .arg(&case)
        .assert()
        .failure()
        .stderr(predicates::str::contains("sparrow profile --case"));
}

#[test]
fn summary_json_reports_tenant_licences_coverage_and_gaps() {
    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::events::hawk4_events_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    sparrow()
        .args(["ingest"])
        .arg(&root)
        .arg("--case")
        .arg(&case)
        .assert()
        .success();

    let out = json_out(
        sparrow().args(["--json", "summary", "--case"]).arg(&case),
        0,
    );
    let t = &out["tenants"][0];
    assert!(t["tenant_key"].as_str().is_some(), "{out}");
    assert_eq!(t["tenant_name"], "contoso_ltd", "{out}");
    assert!(
        t["licenses"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == "E5 (low, Hawk.log)"),
        "{out}"
    );
    assert!(!t["gaps"].as_array().unwrap().is_empty(), "{out}");
    let ual = out["tables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tc| tc["table"] == "ual_events")
        .unwrap();
    assert!(ual["rows"].as_i64().is_some(), "{out}");

    let text = sparrow()
        .args(["summary", "--case"])
        .arg(&case)
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("tenant "), "{text}");
    assert!(text.contains("licences:"), "{text}");
    assert!(text.contains("collections:"), "{text}");
    assert!(text.contains("coverage:"), "{text}");
    assert!(text.contains("top actors:"), "{text}");
    assert!(text.contains("gaps:"), "{text}");
}

#[test]
fn summary_without_a_profile_asks_for_one() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("case.duckdb");
    drop(sparrow_core::Case::create_or_open(&case).unwrap());
    sparrow()
        .args(["summary", "--case"])
        .arg(&case)
        .assert()
        .failure()
        .stderr(predicates::str::contains("sparrow profile --case"));
}

#[test]
fn capabilities_and_summary_warn_when_the_profile_is_stale() {
    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::events::hawk4_events_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    sparrow()
        .args(["ingest"])
        .arg(&root)
        .arg("--case")
        .arg(&case)
        .assert()
        .success();
    for cmd in ["capabilities", "summary"] {
        let out = json_out(sparrow().args(["--json", cmd, "--case"]).arg(&case), 0);
        assert_eq!(out["stale"], false, "{cmd}: {out}");
        assert_eq!(
            out["stale_collections"],
            serde_json::json!([]),
            "{cmd}: {out}"
        );
    }

    // A collection loaded without a profile run (e.g. the profile failed after the ingest).
    let id: i64 = {
        let c = sparrow_core::Case::create_or_open(&case).unwrap();
        c.conn()
            .query_row(
                "INSERT INTO collections (tool, root_path, sparrow_version)
                 VALUES ('hawk', '/later', 't') RETURNING collection_id",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    for cmd in ["capabilities", "summary"] {
        let out = json_out(sparrow().args(["--json", cmd, "--case"]).arg(&case), 0);
        assert_eq!(out["stale"], true, "{cmd}: {out}");
        assert_eq!(
            out["stale_collections"],
            serde_json::json!([id]),
            "{cmd}: {out}"
        );
        assert_eq!(out["tenants"].as_array().unwrap().len(), 1, "{cmd}: {out}");

        let text = sparrow().args([cmd, "--case"]).arg(&case).output().unwrap();
        assert!(text.status.success(), "{cmd}");
        let text = String::from_utf8_lossy(&text.stdout);
        assert!(
            text.contains(&format!(
                "profile is stale: 1 collections not profiled; run `sparrow profile --case {}`",
                case.display()
            )),
            "{cmd}: {text}"
        );
        assert!(
            text.contains("tenant "),
            "{cmd}: data still printed: {text}"
        );
    }
}

#[test]
fn ingest_enriches_ips_from_geoip_dir() {
    use sparrow_core::fixtures::mmdb::{asn, city, write_mmdb};

    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::events::hawk4_events_tree(dir.path());
    let case = dir.path().join("case.duckdb");

    let geo = tempfile::tempdir().unwrap();
    let city_db = write_mmdb(
        "GeoLite2-City",
        1_790_000_000,
        &[(
            "203.0.113.0".parse().unwrap(),
            24,
            city("NG", "Nigeria", "Lagos", 6.45, 3.39),
        )],
    );
    let asn_db = write_mmdb(
        "GeoLite2-ASN",
        1_790_100_000,
        &[(
            "203.0.113.0".parse().unwrap(),
            24,
            asn(14061, "DIGITALOCEAN-ASN"),
        )],
    );
    std::fs::write(geo.path().join("GeoLite2-City.mmdb"), city_db).unwrap();
    std::fs::write(geo.path().join("GeoLite2-ASN.mmdb"), asn_db).unwrap();

    let out = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&root)
            .arg("--case")
            .arg(&case)
            .arg("--geoip-dir")
            .arg(geo.path()),
        0,
    );
    assert!(
        out["profile"]["ip_intel"]["geolocated"].as_u64().unwrap() > 0,
        "{out}"
    );

    let conn = duckdb::Connection::open(&case).unwrap();
    let country_iso: String = conn
        .query_row(
            "SELECT country_iso FROM ip_intel WHERE ip = '203.0.113.10'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(country_iso, "NG");
}

#[test]
fn invictus_tree_end_to_end_through_the_profile_commands() {
    use sparrow_core::fixtures::mmdb::{asn, city, write_mmdb};

    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::invictus::invictus_output_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    let geo = tempfile::tempdir().unwrap();
    let net: std::net::IpAddr = "203.0.113.0".parse().unwrap();
    std::fs::write(
        geo.path().join("GeoLite2-City.mmdb"),
        write_mmdb(
            "GeoLite2-City",
            1_790_000_000,
            &[(net, 24, city("NG", "Nigeria", "Lagos", 6.45, 3.39))],
        ),
    )
    .unwrap();
    std::fs::write(
        geo.path().join("GeoLite2-ASN.mmdb"),
        write_mmdb(
            "GeoLite2-ASN",
            1_790_100_000,
            &[(net, 24, asn(14061, "DIGITALOCEAN-ASN"))],
        ),
    )
    .unwrap();

    let ingest = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&root)
            .arg("--case")
            .arg(&case)
            .arg("--geoip-dir")
            .arg(geo.path()),
        0,
    );
    assert_eq!(ingest["profile"]["tenants"], 1, "{ingest}");

    let caps = json_out(
        sparrow()
            .args(["--json", "capabilities", "--case"])
            .arg(&case),
        0,
    );
    let tenant = &caps["tenants"][0];
    assert_eq!(
        tenant["tenant_key"], "0e0e0e0e-0000-4000-8000-00000000000a",
        "{caps}"
    );
    assert!(
        tenant["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "entra_id_p1" && c["status"] == "licensed"),
        "{caps}"
    );
    assert!(
        tenant["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["evidence"] == "signins" && e["status"] == "collected"),
        "{caps}"
    );

    let summary = json_out(
        sparrow().args(["--json", "summary", "--case"]).arg(&case),
        0,
    );
    assert_eq!(summary["tenants"].as_array().unwrap().len(), 1, "{summary}");

    let profile = json_out(
        sparrow()
            .args(["--json", "profile", "--case"])
            .arg(&case)
            .arg("--geoip-dir")
            .arg(geo.path()),
        0,
    );
    assert_eq!(profile["tenants"], 1, "{profile}");

    let domains = json_out(
        sparrow()
            .args(["--json", "tenant", "domains", "list", "--case"])
            .arg(&case),
        0,
    );
    assert!(
        domains["domains"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["domain"] == "contoso.example"),
        "{domains}"
    );

    let schema = json_out(
        sparrow()
            .args(["--json", "schema", "--case"])
            .arg(&case)
            .arg("timeline"),
        0,
    );
    let tables = schema["tables"].as_array().unwrap();
    assert_eq!(tables.len(), 1, "{schema}");
    assert_eq!(tables[0]["table"], "timeline");
    assert_eq!(tables[0]["kind"], "view");
}

#[test]
fn synth_generates_then_checks_a_case() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tree");
    let v = json_out(
        sparrow()
            .args([
                "--json",
                "synth",
                "--scenario",
                "bec-aitm",
                "--collector",
                "portal",
                "--seed",
                "4",
                "--out",
            ])
            .arg(&out),
        0,
    );
    let root = out.join(v["root"].as_str().unwrap());
    let case = dir.path().join("case.duckdb");
    sparrow()
        .args(["ingest"])
        .arg(&root)
        .arg("--case")
        .arg(&case)
        .arg("--geoip-dir")
        .arg(out.join("geoip"))
        .assert()
        .success();
    let r = json_out(
        sparrow()
            .args(["--json", "synth", "check", "--manifest"])
            .arg(out.join("manifest.json"))
            .arg("--case")
            .arg(&case),
        0,
    );
    assert_eq!(r["ok"], true, "{r}");
}

#[test]
fn synth_rejects_unknown_scenario_and_collector() {
    let dir = tempfile::tempdir().unwrap();
    sparrow()
        .args([
            "synth",
            "--scenario",
            "nope",
            "--collector",
            "portal",
            "--out",
        ])
        .arg(dir.path().join("x"))
        .assert()
        .code(1)
        .stderr(contains("nope"));
    sparrow()
        .args([
            "synth",
            "--scenario",
            "bec-aitm",
            "--collector",
            "hawk9",
            "--out",
        ])
        .arg(dir.path().join("y"))
        .assert()
        .failure();
}

#[test]
fn synth_refuses_scale_knobs_until_they_land() {
    let dir = tempfile::tempdir().unwrap();
    sparrow()
        .args([
            "synth",
            "--scenario",
            "bec-aitm",
            "--collector",
            "portal",
            "--ual-rows",
            "10",
            "--out",
        ])
        .arg(dir.path().join("x"))
        .assert()
        .code(1)
        .stderr(contains("scale knobs"));
}

#[test]
fn synth_coverage_reports_every_rule() {
    let v = json_out(sparrow().args(["--json", "synth", "coverage"]), 0);
    assert_eq!(v["rules"].as_array().unwrap().len(), 31);
    assert_eq!(v["ok"], true);
}
