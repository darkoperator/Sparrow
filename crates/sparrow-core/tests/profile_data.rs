use sparrow_core::Case;
use sparrow_core::data::{DataDirs, capabilities};
use sparrow_core::profile::{ProfileOptions, refresh};

const REQUIRED: &[&str] = &[
    "ual_standard",
    "audit_premium",
    "entra_signin_logs",
    "entra_audit_logs",
    "entra_id_p1",
    "identity_protection",
    "mdo_p1",
    "mdo_p2",
    "message_trace",
    "mailbox_audit_legacy",
    "exchange_admin_audit",
];

#[test]
fn builtin_capabilities_cover_the_spec_list_and_cite_sources() {
    let caps = capabilities(&DataDirs::default()).unwrap();
    for id in REQUIRED {
        let c = caps
            .iter()
            .find(|c| c.id == *id)
            .unwrap_or_else(|| panic!("missing {id}"));
        assert!(c.sources.iter().all(|s| s.starts_with("https://")), "{id}");
        assert!(!c.sources.is_empty(), "{id}");
        assert_eq!(c.as_of.len(), 10, "{id}: as_of is yyyy-mm-dd");
    }
    let premium = caps.iter().find(|c| c.id == "audit_premium").unwrap();
    assert_eq!(
        premium.unlocked_by_service_plans,
        vec!["M365_ADVANCED_AUDITING"]
    );
    assert_eq!(premium.retention_days, Some(365));
}

#[test]
fn an_external_file_overrides_by_id_and_adds_new_ids() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("capabilities.yaml"),
        "version: 1\ncapabilities:\n  - id: ual_standard\n    title: Audit (Standard), local policy\n    baseline: true\n    retention_days: 365\n    notes: tenant bought 1-year retention\n    sources: [https://learn.microsoft.com/en-us/purview/audit-solutions-overview]\n    as_of: 2026-09-25\n  - id: local_siem\n    title: Local SIEM copy\n    notes: exported daily\n    sources: [https://example.test/siem]\n    as_of: 2026-09-25\n",
    )
    .unwrap();
    let dirs = DataDirs {
        data: Some(dir.path().to_path_buf()),
        rules: Vec::new(),
    };
    let caps = capabilities(&dirs).unwrap();
    let std_ = caps.iter().find(|c| c.id == "ual_standard").unwrap();
    assert_eq!(std_.retention_days, Some(365));
    assert!(caps.iter().any(|c| c.id == "local_siem"));
    assert!(
        caps.iter().any(|c| c.id == "audit_premium"),
        "built-ins stay"
    );
}

#[test]
fn a_bad_external_file_names_the_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("capabilities.yaml"),
        "capabilities: [ {id: x, bogus: 1} ]",
    )
    .unwrap();
    let err = capabilities(&DataDirs {
        data: Some(dir.path().to_path_buf()),
        rules: Vec::new(),
    })
    .unwrap_err()
    .to_string();
    assert!(err.contains("capabilities.yaml"), "{err}");
}

#[test]
fn refresh_loads_the_capabilities_table_and_is_repeatable() {
    let mut case = Case::in_memory().unwrap();
    let opts = ProfileOptions::default();
    let first = refresh(&mut case, &opts).unwrap();
    let again = refresh(&mut case, &opts).unwrap();
    assert_eq!(first.capabilities, again.capabilities);
    let n: i64 = case
        .conn()
        .query_row("SELECT count(*) FROM capabilities", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n as usize, first.capabilities);
    let origin: String = case
        .conn()
        .query_row(
            "SELECT origin FROM capabilities WHERE capability_id = 'audit_premium'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(origin, "builtin");
}

#[test]
fn operation_catalog_keys_ignore_case_and_trailing_dots() {
    use sparrow_core::data::{operation_catalog, operation_key};
    assert_eq!(
        operation_key(" Consent to application. "),
        "consent to application"
    );
    let ops = operation_catalog(&DataDirs::default()).unwrap();
    assert!(
        ops.iter()
            .any(|o| o.operation == "New-InboxRule" && o.mitre.contains(&"T1564.008".to_string()))
    );
}

/// The data tables are written inside the profile's single transaction: a profile that fails
/// later leaves `capabilities` and `operation_catalog` as they were.
#[test]
fn a_failed_profile_leaves_the_data_tables_untouched() {
    let mut case = Case::in_memory().unwrap();
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let n = |case: &Case, t: &str| -> i64 {
        case.conn()
            .query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
            .unwrap()
    };
    assert!(n(&case, "capabilities") > 0);
    case.conn()
        .execute_batch(
            "DELETE FROM capabilities; DELETE FROM operation_catalog;
             DROP TABLE evidence_availability;",
        )
        .unwrap();
    assert!(refresh(&mut case, &ProfileOptions::default()).is_err());
    assert_eq!(n(&case, "capabilities"), 0);
    assert_eq!(n(&case, "operation_catalog"), 0);
}
