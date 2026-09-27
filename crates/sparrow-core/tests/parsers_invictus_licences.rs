#[path = "common/synth.rs"]
mod synth;

use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_synth::options::PsEdition;
use sparrow_synth::scenario::load;
use std::path::Path;
use synth::*;

#[test]
fn tenant_licences_load_with_trimmed_plans() {
    for ps in [PsEdition::Ps7, PsEdition::Ps51] {
        let g = builtin("bec-o365-no-p1", ps); // o365_e3: "ATP_ENTERPRISE " with a trailing space
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM licenses WHERE source = 'invictus_tenant_licenses' AND confidence = 'high'"
            ),
            1
        );
        assert_eq!(
            text(
                &g.case,
                "SELECT array_to_string(list_sort(service_plans), ',') FROM licenses WHERE sku_part_number = 'ENTERPRISEPACK'"
            ),
            "ATP_ENTERPRISE,EXCHANGE_S_ENTERPRISE,SHAREPOINTENTERPRISE,TEAMS1"
        );
        assert_eq!(
            text(
                &g.case,
                "SELECT capability_status FROM licenses WHERE sku_part_number = 'ENTERPRISEPACK'"
            ),
            "Enabled"
        );
        check_green(&g);
    }
}

#[test]
fn blank_plan_elements_are_dropped_and_the_profile_runs() {
    let mut s = load("business-basic").unwrap();
    s.tenant.licence_profile = "business_premium".into(); // SPB has a blank plan name
    let g = invictus(&s, PsEdition::Ps7, 3);
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM (SELECT unnest(service_plans) AS x FROM licenses) WHERE trim(x) = ''"
        ),
        0
    );
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM tenant_capabilities WHERE capability_id = 'entra_id_p1' AND status = 'licensed' AND confidence = 'high'"
        ),
        1
    );
    check_green(&g);
}

#[test]
fn user_licences_skip_unlicensed_users() {
    let g = builtin("bec-aitm", PsEdition::Ps7);
    let users = count(&g.case, "SELECT count(DISTINCT upn) FROM user_licenses");
    assert!(users > 0);
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM user_licenses WHERE lower(sku_part_number) = 'none'"
        ),
        0
    );
}

#[test]
fn high_confidence_list_decides_capabilities() {
    let g = builtin("hawk-investigate", PsEdition::Ps7); // o365_e5
    let status = |id: &str| {
        text(
            &g.case,
            &format!(
                "SELECT status || '/' || confidence FROM tenant_capabilities WHERE capability_id = '{id}'"
            ),
        )
    };
    assert_eq!(status("audit_premium"), "licensed/high");
    assert_eq!(status("entra_id_p1"), "not_licensed/high");
    assert_eq!(status("mdo_p2"), "licensed/high");
}

const USER_LICENCES_REL: &str = "Licenses/20260910-100500/20260910-100500-UserLicenses.csv";

fn ingest_hand_written(base: &Path) -> (Case, IngestReport) {
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        base,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    (case, report)
}

fn file_row<'r>(report: &'r IngestReport, rel: &str) -> &'r FileReport {
    report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .find(|f| f.rel_path == rel)
        .unwrap_or_else(|| panic!("no report row for {rel}"))
}

/// A `SkuPartNumber` of None or blank is skipped and counted before the UPN is examined, so a
/// row the collector writes without a licence does not become a parse error when its UPN is
/// empty too.
#[test]
fn a_none_or_blank_sku_is_counted_before_the_upn_is_checked() {
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "{}{}{}{}",
        csv_line(&["DisplayName", "UserPrincipalName", "SkuPartNumber"]),
        csv_line(&["Alice", "alice@contoso.example", "SPE_E5"]),
        csv_line(&["Bob", "", "None"]),
        csv_line(&["Carol", "", ""]),
    );
    fixtures::write(&dir.path().join("OUT"), USER_LICENCES_REL, body.as_bytes());
    let (case, report) = ingest_hand_written(dir.path());
    let f = file_row(&report, USER_LICENCES_REL);
    assert_eq!(f.status, FileStatus::Parsed, "{report:#?}");
    assert_eq!(f.records_error, 0, "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM user_licenses"), 1);
    assert!(
        f.warnings
            .iter()
            .any(|w| w.contains("1 users have no licence (SkuPartNumber None)")),
        "{:?}",
        f.warnings
    );
    assert!(
        f.warnings.iter().any(|w| w.contains("1 rows name no SKU")),
        "{:?}",
        f.warnings
    );
}
