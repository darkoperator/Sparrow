//! Task 18: Microsoft-Extractor-Suite risky users, risk detections, security alerts and
//! secure score (research state layouts §9-§11). The two tests are the plan's, unchanged.

#[path = "common/synth.rs"]
mod synth;

use sparrow_synth::options::{Culture, PsEdition};
use sparrow_synth::scenario::load;
use sparrow_synth::world::World;
use synth::*;

#[test]
fn risk_with_p2_loads_and_without_p2_is_not_licensed() {
    let g = builtin("bec-aitm", PsEdition::Ps7);
    assert!(
        count(
            &g.case,
            "SELECT count(*) FROM risk_detections WHERE risk_event_type = 'anomalousToken' AND risk_level = 'high'"
        ) >= 1
    );
    assert!(
        count(
            &g.case,
            "SELECT count(*) FROM risky_users WHERE risk_state = 'confirmedCompromised'"
        ) >= 1
    );
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM risk_detections WHERE location.city IS NOT NULL"
        ),
        count(
            &g.case,
            "SELECT count(*) FROM risk_detections WHERE activity = 'signin'"
        )
    );
    check_green(&g);
    let g = builtin("bec-e3-audit-gaps", PsEdition::Ps7);
    assert_eq!(count(&g.case, "SELECT count(*) FROM risk_detections"), 0);
    check_green(&g); // manifest: risk_detections evidence {not_licensed}
}

#[test]
fn alerts_and_secure_score_load_in_every_culture() {
    for (ps, culture) in [
        (PsEdition::Ps7, Culture::EnUs),
        (PsEdition::Ps51, Culture::DeDe),
    ] {
        let s = load("bec-aitm").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut o = sparrow_synth::options::GenerateOptions::new(
            sparrow_synth::options::Collector::Invictus,
            9,
        );
        o.ps = ps;
        o.culture = culture;
        let m = sparrow_synth::generate::generate_to_dir(&s, &o, dir.path()).unwrap();
        let case = sparrow_synth::testing::ingest_generated(dir.path(), &m);
        assert_eq!(count(&case, "SELECT count(*) FROM secure_score"), 8);
        assert_eq!(
            count(
                &case,
                "SELECT count(*) FROM secure_score WHERE current_score IS NULL OR max_score IS NULL"
            ),
            0
        );
        assert_eq!(
            count(
                &case,
                "SELECT count(*) FROM security_alerts WHERE len(affected_users) = 1 AND severity = 'informational'"
            ),
            1
        );
        assert_eq!(count(&case, "SELECT count(*) FROM security_alerts"), 1);
        let r = sparrow_synth::check::check(&m, &case).unwrap();
        assert!(r.ok, "{culture:?}: {:#?}", r.problems);
    }
}

/// The SecurityAlerts detail fields are world values, not blanks: LastModifiedDateTime,
/// ClosedDateTime, AzureTenantId (the world tenant id), Confidence, Vendor and SubProvider
/// (SubProvider has no column, so the parser keeps it in `raw`). Risk detections carry the
/// world's TokenIssuerType instead of a hard-coded string.
#[test]
fn alert_and_risk_detail_fields_load() {
    let world = World::build(&load("bec-aitm").unwrap(), 17).unwrap();
    let alert = &world.alerts[0];
    let g = builtin("bec-aitm", PsEdition::Ps7);
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM security_alerts
             WHERE last_modified IS NOT NULL AND closed_time IS NOT NULL
               AND azure_tenant_id IS NOT NULL AND confidence IS NOT NULL AND vendor IS NOT NULL"
        ),
        1
    );
    assert_eq!(
        text(
            &g.case,
            "SELECT epoch(last_modified)::BIGINT || '|' || epoch(closed_time)::BIGINT || '|' ||
                    azure_tenant_id || '|' || confidence || '|' || vendor || '|' ||
                    (raw->>'SubProvider')
             FROM security_alerts"
        ),
        format!(
            "{}|{}|{}|{}|{}|{}",
            alert.last_modified.timestamp(),
            alert.closed_time.timestamp(),
            alert.azure_tenant_id,
            alert.confidence,
            alert.vendor,
            alert.sub_provider
        )
    );
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM risk_detections WHERE token_issuer_type = 'AzureAD'"
        ),
        count(&g.case, "SELECT count(*) FROM risk_detections")
    );
    assert!(count(&g.case, "SELECT count(*) FROM risk_detections") > 0);
    check_green(&g);
}
