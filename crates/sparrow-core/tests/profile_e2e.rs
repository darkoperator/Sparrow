//! Task 12: the profile step end to end on the collector fixture trees (Microsoft-Extractor-Suite
//! Output root, Hawk 4 event and state captures), with a pinned `as_of` and a synthetic GeoIP dir.

use chrono::{DateTime, TimeZone, Utc};
use duckdb::params;
use sparrow_core::Case;
use sparrow_core::fixtures::events::hawk4_events_tree;
use sparrow_core::fixtures::invictus::{ALICE, invictus_output_tree};
use sparrow_core::fixtures::mmdb::{asn, city, write_mmdb};
use sparrow_core::fixtures::state::hawk4_state_tree;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_core::profile::availability::EVIDENCE;
use sparrow_core::profile::capabilities::{TenantCapability, tenant_capabilities};
use sparrow_core::profile::{ProfileOptions, refresh};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

const INV_TENANT: &str = "0e0e0e0e-0000-4000-8000-00000000000a";
/// `fixtures::ual::ORG_ID`, the OrganizationId of the Hawk state tree's UAL rows.
const HAWK_TENANT: &str = "c9c9c9c9-0000-4000-8000-000000000001";
const INV_ALICE_ID: &str = "0e0e0e0e-0000-4000-8000-0000000000a1";
const INV_ALICE_PUID: &str = "1003200000000001";
const INV_APP_ID: &str = "0e0e0e0e-0000-4000-8000-0000000000b1";

fn as_of() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 25, 0, 0, 0).unwrap()
}

/// Synthetic GeoIP dir: 203.0.113.0/24 resolves to Lagos, NG on DigitalOcean.
fn geoip_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let net: IpAddr = "203.0.113.0".parse().unwrap();
    let city_db = write_mmdb(
        "GeoLite2-City",
        1_790_000_000,
        &[(net, 24, city("NG", "Nigeria", "Lagos", 6.45, 3.39))],
    );
    let asn_db = write_mmdb(
        "GeoLite2-ASN",
        1_790_100_000,
        &[(net, 24, asn(14061, "DIGITALOCEAN-ASN"))],
    );
    std::fs::write(dir.path().join("GeoLite2-City.mmdb"), city_db).unwrap();
    std::fs::write(dir.path().join("GeoLite2-ASN.mmdb"), asn_db).unwrap();
    dir
}

/// A loaded case plus the temp dirs its evidence and GeoIP files live in.
struct Loaded {
    _evidence: tempfile::TempDir,
    geoip: tempfile::TempDir,
    case: Case,
}

impl Loaded {
    fn refresh(&mut self) {
        let opts = ProfileOptions {
            geoip_dir: Some(self.geoip.path().to_path_buf()),
            as_of: Some(as_of()),
            ..Default::default()
        };
        refresh(&mut self.case, &opts).unwrap();
    }
}

/// Writes the fixture trees into one folder, ingests it and runs the profile step once.
fn load(trees: &[fn(&Path) -> PathBuf]) -> Loaded {
    let evidence = tempfile::tempdir().unwrap();
    for tree in trees {
        tree(evidence.path());
    }
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        evidence.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert!(!report.has_errors(), "{report:#?}");
    let mut loaded = Loaded {
        _evidence: evidence,
        geoip: geoip_dir(),
        case,
    };
    loaded.refresh();
    loaded
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn capability(case: &Case, tenant: &str, id: &str) -> TenantCapability {
    tenant_capabilities(case.conn(), tenant)
        .unwrap()
        .into_iter()
        .find(|c| c.capability_id == id)
        .unwrap_or_else(|| panic!("no capability {id} for {tenant}"))
}

/// (status, rows, reason, remediation) of one `evidence_availability` row.
fn evidence(case: &Case, tenant: &str, id: &str) -> (String, i64, String, Option<String>) {
    case.conn()
        .query_row(
            "SELECT CAST(status AS VARCHAR), rows, reason, remediation FROM evidence_availability
             WHERE tenant_key = ? AND evidence = ?",
            params![tenant, id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap_or_else(|e| panic!("no evidence row {id} for {tenant}: {e}"))
}

fn identity_of(case: &Case, alias_type: &str, alias: &str) -> String {
    case.conn()
        .query_row(
            "SELECT identity_id FROM identity_aliases WHERE alias_type = ? AND alias = ?",
            params![alias_type, alias.to_lowercase()],
            |r| r.get(0),
        )
        .unwrap_or_else(|e| panic!("no alias {alias_type}:{alias}: {e}"))
}

#[test]
fn invictus_output_root_profile() {
    let l = load(&[invictus_output_tree]);
    let case = &l.case;

    // Tenant.
    assert_eq!(count(case, "SELECT count(*) FROM tenant"), 1);
    let (key, source): (String, String) = case
        .conn()
        .query_row("SELECT tenant_key, tenant_id_source FROM tenant", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(key, INV_TENANT);
    assert_eq!(source, "ual_organization_id");
    assert_eq!(
        count(
            case,
            "SELECT count(*) FROM tenant_domains
             WHERE domain = 'contoso.example' AND source = 'derived_upn'"
        ),
        1
    );

    // Capabilities.
    let p1 = capability(case, INV_TENANT, "entra_id_p1");
    assert_eq!(
        (p1.status.as_str(), p1.confidence.as_deref()),
        ("licensed", Some("high")),
        "{p1:?}"
    );
    assert!(p1.basis.contains("Microsoft Graph"), "{p1:?}");
    assert!(
        p1.basis.contains("disagrees") && p1.basis.contains("HasPremiumLicense = No"),
        "{p1:?}"
    );
    let idp = capability(case, INV_TENANT, "identity_protection");
    assert_eq!(
        (idp.status.as_str(), idp.confidence.as_deref()),
        ("not_licensed", Some("high")),
        "{idp:?}"
    );
    assert!(idp.basis.contains("hidden"), "{idp:?}");

    // Evidence availability.
    assert_eq!(
        count(
            case,
            &format!(
                "SELECT count(*) FROM evidence_availability WHERE tenant_key = '{INV_TENANT}'"
            )
        ),
        EVIDENCE.len() as i64
    );
    for id in ["signins", "directory_audits", "message_trace", "ual"] {
        let (status, rows, reason, _) = evidence(case, INV_TENANT, id);
        assert_eq!(status, "collected", "{id}: {reason}");
        assert!(rows > 0, "{id}");
    }
    // Bob's mailbox bypasses auditing in the newer Audit Status run, so MailItemsAccessed is
    // partial rather than collected (Task 6: mailboxes not auditing the action).
    let (status, rows, reason, _) = evidence(case, INV_TENANT, "mail_items_accessed");
    assert_eq!((status.as_str(), rows), ("partial", 3), "{reason}");
    assert!(
        reason.contains("1 of 2 mailboxes do not audit MailItemsAccessed"),
        "{reason}"
    );
    for (id, file) in [
        ("users", "Users.csv"),
        ("oauth_grants", "OAuthPermissions.csv"),
    ] {
        let (status, rows, reason, _) = evidence(case, INV_TENANT, id);
        assert_eq!((status.as_str(), rows), ("collected", 0), "{id}: {reason}");
        assert!(
            reason.contains("returned no records") && reason.contains(file),
            "{id}: {reason}"
        );
    }
    let (status, _, reason, _) = evidence(case, INV_TENANT, "risk_detections");
    assert_eq!(status, "not_licensed", "{reason}");
    let (status, _, _, remediation) = evidence(case, INV_TENANT, "mailbox_audit_legacy");
    assert_eq!(status, "available_not_collected");
    assert!(
        remediation
            .as_deref()
            .is_some_and(|r| r.contains("Get-MailboxAuditLogLegacy")),
        "{remediation:?}"
    );
    // The Security Defaults export in Licenses/ is not a licence list.
    let (status, _, reason, _) = evidence(case, INV_TENANT, "licenses");
    assert_eq!(status, "available_not_collected", "{reason}");

    // Timeline: UAL + sign-ins + audits + message trace + parent-less MailItemsAccessed rows.
    let expected: i64 = [
        "SELECT count(*) FROM ual_events",
        "SELECT count(*) FROM signins",
        "SELECT count(*) FROM directory_audits",
        "SELECT count(*) FROM message_trace",
        "SELECT count(*) FROM mail_items_accessed WHERE record_id IS NULL",
    ]
    .iter()
    .map(|sql| count(case, sql))
    .sum();
    assert_eq!(expected, 5 + 3 + 1 + 2 + 1);
    assert_eq!(count(case, "SELECT count(*) FROM timeline"), expected);
    assert_eq!(
        count(
            case,
            "SELECT count(*) FROM timeline WHERE source_refs IS NULL OR len(source_refs) = 0"
        ),
        0
    );
    assert_eq!(
        count(
            case,
            "SELECT count(*) FROM timeline WHERE source_table = 'signins' AND ip_country = 'NG'"
        ),
        3
    );

    // Identities: alice's UPN, object id and UAL PUID resolve to one identity.
    let alice = identity_of(case, "upn", ALICE);
    assert_eq!(identity_of(case, "object_id", INV_ALICE_ID), alice);
    assert_eq!(identity_of(case, "puid", INV_ALICE_PUID), alice);
    // Every UAL row of hers (4 raw records carrying the PUID, 1 synthetic Sessions.csv row
    // without one) resolves to that identity through each identifier it carries.
    assert_eq!(
        count(
            case,
            &format!("SELECT count(*) FROM ual_events WHERE lower(user_upn) = '{ALICE}'")
        ),
        5
    );
    assert_eq!(
        count(
            case,
            &format!(
                "SELECT count(*) FROM ual_events u
                 JOIN identity_aliases a
                   ON (a.alias_type = 'upn' AND a.alias = lower(u.user_upn))
                   OR (a.alias_type = 'puid' AND a.alias = lower(u.user_key))
                 WHERE lower(u.user_upn) = '{ALICE}' AND a.identity_id <> '{alice}'"
            )
        ),
        0
    );
    assert_eq!(
        count(
            case,
            &format!(
                "SELECT count(*) FROM ual_events u
                 JOIN identity_aliases a ON a.alias_type = 'puid' AND a.alias = lower(u.user_key)
                 WHERE a.identity_id = '{alice}'"
            )
        ),
        4
    );
    let (kind, tenant): (String, String) = case
        .conn()
        .query_row(
            "SELECT CAST(kind AS VARCHAR), tenant_key FROM identities WHERE identity_id = ?",
            params![identity_of(case, "app_id", INV_APP_ID)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (kind.as_str(), tenant.as_str()),
        ("service_principal", INV_TENANT)
    );
}

#[test]
fn hawk4_capture_profile() {
    let l = load(&[hawk4_events_tree, hawk4_state_tree]);
    let case = &l.case;

    assert_eq!(count(case, "SELECT count(*) FROM tenant"), 1);
    let (key, name): (String, String) = case
        .conn()
        .query_row("SELECT tenant_key, tenant_name FROM tenant", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(key, HAWK_TENANT);
    assert_eq!(name, "contoso_ltd");

    // Hawk.log "M365 License type detected: E5" (low) and visible sign-in risk (high).
    let audit = capability(case, HAWK_TENANT, "audit_premium");
    assert_eq!(
        (audit.status.as_str(), audit.confidence.as_deref()),
        ("licensed", Some("low")),
        "{audit:?}"
    );
    assert!(audit.basis.contains("E5"), "{audit:?}");
    let idp = capability(case, HAWK_TENANT, "identity_protection");
    assert_eq!(
        (idp.status.as_str(), idp.confidence.as_deref()),
        ("licensed", Some("high")),
        "{idp:?}"
    );

    // The Hawk.log lines decide what ran: the licence line is the tenant's only licence
    // evidence, and the per-user sign-in line makes the sign-ins a one-user collection.
    let (status, rows, reason, _) = evidence(case, HAWK_TENANT, "licenses");
    assert_eq!((status.as_str(), rows), ("collected", 1), "{reason}");
    let (status, _, reason, _) = evidence(case, HAWK_TENANT, "signins");
    assert_eq!(status, "partial", "{reason}");
    assert!(
        reason.contains("Hawk collected it for 1 users of 2"),
        "{reason}"
    );

    let (status, _, reason, remediation) = evidence(case, HAWK_TENANT, "ual");
    assert_eq!(status, "partial", "{reason}");
    assert!(reason.contains("selected operations only"), "{reason}");
    assert!(
        remediation
            .as_deref()
            .is_some_and(|r| r.starts_with("Hawk:")),
        "{remediation:?}"
    );
    // The state capture reports UnifiedAuditLogIngestionEnabled False.
    let (status, _, reason, _) = evidence(case, HAWK_TENANT, "mail_items_accessed");
    assert_eq!(status, "not_enabled", "{reason}");
}

#[test]
fn two_tenants_in_one_case_stay_apart() {
    // The Hawk state tree's UAL row carries fixtures::ual::ORG_ID, not the Invictus tenant id,
    // and none of its record ids collide with the Invictus tree's. (Both trees name
    // alice@contoso.example, so UPN-keyed state rows and identities are not compared here.)
    let l = load(&[invictus_output_tree, hawk4_state_tree]);
    let case = &l.case;

    let tenants: Vec<String> = {
        let mut stmt = case
            .conn()
            .prepare("SELECT tenant_key FROM tenant ORDER BY tenant_key")
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(tenants, [INV_TENANT, HAWK_TENANT]);
    assert_eq!(
        count(
            case,
            "SELECT count(*) FROM collections WHERE tenant_key IS NULL"
        ),
        0
    );
    assert_eq!(
        count(case, "SELECT count(DISTINCT tenant_key) FROM collections"),
        2
    );

    // Each tenant's audit configuration comes from its own collection.
    type AuditRow = (Option<bool>, Option<String>, Option<bool>, Option<bool>);
    let audit = |tenant: &str| -> AuditRow {
        case.conn()
            .query_row(
                "SELECT unified_audit_log_ingestion_enabled, admin_audit_log_age_limit,
                        audit_disabled, security_defaults_enabled
                 FROM tenant_audit_config WHERE tenant_key = ?",
                params![tenant],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap()
    };
    assert_eq!(count(case, "SELECT count(*) FROM tenant_audit_config"), 2);
    assert_eq!(audit(INV_TENANT), (None, None, Some(false), Some(false)));
    assert_eq!(
        audit(HAWK_TENANT),
        (
            Some(false),
            Some("90.00:00:00".to_string()),
            Some(false),
            None
        )
    );

    // Evidence is judged per tenant.
    for t in [INV_TENANT, HAWK_TENANT] {
        assert_eq!(
            count(
                case,
                &format!("SELECT count(*) FROM evidence_availability WHERE tenant_key = '{t}'")
            ),
            EVIDENCE.len() as i64,
            "{t}"
        );
    }
    assert_eq!(evidence(case, INV_TENANT, "signins").0, "collected");
    assert_eq!(
        evidence(case, HAWK_TENANT, "signins").0,
        "available_not_collected"
    );
    assert_eq!(
        evidence(case, HAWK_TENANT, "app_credentials").0,
        "collected"
    );
    assert_eq!(
        evidence(case, INV_TENANT, "app_credentials").0,
        "available_not_collected"
    );
    assert_eq!(evidence(case, INV_TENANT, "ual").1, 5);
    assert_eq!(evidence(case, HAWK_TENANT, "ual").1, 1);
    // UAL ingestion is off only in the Hawk tenant.
    let (status, _, reason, _) = evidence(case, HAWK_TENANT, "search_queries");
    assert_eq!(status, "not_enabled", "{reason}");
    let (status, _, reason, _) = evidence(case, INV_TENANT, "search_queries");
    assert_eq!(status, "collected", "{reason}");
    // Capabilities too: the Invictus sign-ins hide risk; the Hawk tenant has no sign-ins.
    assert_eq!(
        capability(case, INV_TENANT, "identity_protection").status,
        "not_licensed"
    );
    assert_eq!(
        capability(case, HAWK_TENANT, "identity_protection").status,
        "unknown"
    );
}

/// Every row of `relation` as text, sorted and joined.
fn snapshot(case: &Case, relation: &str) -> String {
    case.conn()
        .query_row(
            &format!(
                "SELECT coalesce(string_agg(CAST(t AS VARCHAR), chr(10) ORDER BY CAST(t AS VARCHAR)), '')
                 FROM ({relation}) t"
            ),
            [],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn profile_is_idempotent() {
    let mut l = load(&[invictus_output_tree, hawk4_events_tree, hawk4_state_tree]);
    let relations = [
        "SELECT * FROM tenant",
        "SELECT * FROM tenant_domains",
        "SELECT * FROM tenant_capabilities",
        "SELECT * FROM identities",
        "SELECT * FROM identity_aliases",
        "SELECT * FROM ip_intel",
        "SELECT * EXCLUDE (evaluated_at) FROM evidence_availability",
        "SELECT collection_id, tenant_key FROM collections",
    ];
    let first: Vec<String> = relations.iter().map(|r| snapshot(&l.case, r)).collect();
    for (r, s) in relations.iter().zip(&first) {
        assert!(!s.is_empty(), "{r} is empty");
    }
    l.refresh();
    let second: Vec<String> = relations.iter().map(|r| snapshot(&l.case, r)).collect();
    for ((r, a), b) in relations.iter().zip(&first).zip(&second) {
        assert_eq!(a, b, "{r} changed on the second refresh");
    }
}
