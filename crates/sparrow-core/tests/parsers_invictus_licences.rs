#[path = "common/synth.rs"]
mod synth;

use sparrow_synth::options::PsEdition;
use sparrow_synth::scenario::load;
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
