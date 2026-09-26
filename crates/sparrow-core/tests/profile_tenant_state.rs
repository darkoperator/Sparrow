//! Tenant-wide state that is keyed per collection (transport rules, remote domains): captures
//! of different tenants in one case never merge, the `*_current` views keep each tenant's own
//! newest rows, and `state_absent_in_newer` still reports a rule a tenant's newer capture lost.

use chrono::{TimeZone, Utc};
use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_core::profile::{ProfileOptions, refresh};
use std::path::{Path, PathBuf};

/// A minimal Hawk capture `Hawk_<tenant>_<stamp>` holding the tenant's remote domain `*` and
/// the named transport rules.
fn hawk(base: &Path, tenant: &str, stamp: &str, auto_forward: bool, rules: &[&str]) -> PathBuf {
    let root = base.join(format!("Hawk_{tenant}_{stamp}"));
    fixtures::write(
        &root,
        "Hawk.log",
        &fixtures::utf16le_bom("[2026-09-20 09:00:00Z] - [INFO]   - Hawk Version: 4.0\r\n"),
    );
    let rules: Vec<Value> = rules
        .iter()
        .map(|name| {
            json!({
                "Name": name, "Guid": "88888888-8888-4888-8888-888888888888", "State": "Enabled",
                "Mode": "Enforce", "Priority": 0, "CreatedBy": "Admin", "LastModifiedBy": "Admin",
                "WhenChanged": "2026-09-01T12:00:00Z", "Description": "d",
                "RedirectMessageTo": null, "BlindCopyTo": null, "CopyTo": null, "AddToRecipients": null
            })
        })
        .collect();
    fixtures::write(
        &root,
        "Tenant/TransportRules.json",
        fixtures::ps_json(&json!(rules)).as_bytes(),
    );
    fixtures::write(
        &root,
        "Tenant/RemoteDomain.json",
        fixtures::ps_json(&json!({
            "DomainName": "*", "Name": "Default", "AutoForwardEnabled": auto_forward,
            "AllowedOOFType": "External", "WhenChanged": "2026-09-01T10:00:00Z"
        }))
        .as_bytes(),
    );
    root
}

fn ingest(case: &mut Case, path: &Path) {
    let report = ingest_path(
        case,
        path,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert!(!report.has_errors(), "{report:#?}");
}

fn profile(case: &mut Case) {
    let opts = ProfileOptions {
        as_of: Some(Utc.with_ymd_and_hms(2026, 9, 25, 0, 0, 0).unwrap()),
        ..Default::default()
    };
    refresh(case, &opts).unwrap();
}

fn strings(case: &Case, sql: &str) -> Vec<String> {
    case.conn()
        .prepare(sql)
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn cid(case: &Case, stamp: &str) -> i64 {
    case.conn()
        .query_row(
            &format!("SELECT collection_id FROM collections WHERE root_path LIKE '%{stamp}'"),
            [],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn two_tenants_keep_their_own_remote_domains_and_transport_rules() {
    let dir = tempfile::tempdir().unwrap();
    let contoso = hawk(
        dir.path(),
        "Contoso",
        "20260910_090000",
        true,
        &["External redirect"],
    );
    let fabrikam = hawk(
        dir.path(),
        "Fabrikam",
        "20260920_090000",
        false,
        &["Journal", "Disclaimer"],
    );
    let mut case = Case::in_memory().unwrap();
    ingest(&mut case, &contoso);
    ingest(&mut case, &fabrikam);
    profile(&mut case);

    let (c1, c2) = (cid(&case, "20260910_090000"), cid(&case, "20260920_090000"));
    assert_eq!(
        strings(
            &case,
            "SELECT record_key || '=' || auto_forward_enabled FROM remote_domains ORDER BY 1"
        ),
        vec![format!("{c1}|*=true"), format!("{c2}|*=false")],
        "one '*' row per collection"
    );
    assert_eq!(
        strings(
            &case,
            "SELECT tenant_key || '=' || auto_forward_enabled FROM remote_domains_current ORDER BY 1"
        ),
        vec!["name:contoso=true", "name:fabrikam=false"],
        "each tenant shows its own '*' policy"
    );
    assert_eq!(
        strings(
            &case,
            "SELECT tenant_key || '=' || name FROM transport_rules_current ORDER BY 1"
        ),
        vec![
            "name:contoso=External redirect",
            "name:fabrikam=Disclaimer",
            "name:fabrikam=Journal"
        ]
    );
    // Sightings follow the per-collection keys.
    assert_eq!(
        strings(
            &case,
            "SELECT DISTINCT split_part(record_key, '|', 1) FROM record_sources
             WHERE table_name IN ('transport_rules', 'remote_domains') ORDER BY 1"
        ),
        vec![c1.to_string(), c2.to_string()]
    );
    // evidence_availability counts each tenant's own rules.
    assert_eq!(
        strings(
            &case,
            "SELECT tenant_key || '=' || rows || '/' || status FROM evidence_availability
             WHERE evidence = 'transport_rules' ORDER BY 1"
        ),
        vec!["name:contoso=1/collected", "name:fabrikam=2/collected"]
    );
}

#[test]
fn transport_rule_removed_in_the_tenants_newer_capture_is_listed() {
    let dir = tempfile::tempdir().unwrap();
    let old = hawk(
        dir.path(),
        "Contoso",
        "20260910_090000",
        true,
        &["Keep", "Removed"],
    );
    // Another tenant's capture, newer than both of Contoso's, still has a rule named "Removed":
    // it must neither hide Contoso's removal nor be listed itself.
    let other = hawk(
        dir.path(),
        "Fabrikam",
        "20260925_090000",
        true,
        &["Removed"],
    );
    let new = hawk(dir.path(), "Contoso", "20260920_090000", false, &["Keep"]);
    let mut case = Case::in_memory().unwrap();
    ingest(&mut case, &old);
    ingest(&mut case, &other);
    ingest(&mut case, &new);
    profile(&mut case);

    let (c_old, c_new) = (cid(&case, "20260910_090000"), cid(&case, "20260920_090000"));
    assert_eq!(
        strings(
            &case,
            "SELECT table_name || ':' || record_key || '>' || absent_from_collection_id
             FROM state_absent_in_newer ORDER BY 1"
        ),
        vec![format!("transport_rules:{c_old}|removed>{c_new}")],
        "only Contoso's removed rule; the kept rule and the '*' remote domain are held by the newer capture"
    );
}
