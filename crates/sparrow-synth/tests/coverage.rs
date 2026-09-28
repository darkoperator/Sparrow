use sparrow_synth::coverage::report;
use sparrow_synth::options::Collector;

#[test]
fn coverage_has_no_gaps() {
    let r = report(1).unwrap();
    assert_eq!(r.rules.len(), 31);
    assert!(r.ok, "{}", r.gaps.join("\n"));
}

#[test]
fn the_report_names_collectors_and_profiles() {
    let r = report(1).unwrap();
    let aitm = r.rules.iter().find(|x| x.id == "SPW-ID-004").unwrap();
    for c in Collector::ALL {
        assert!(aitm.collectors_hit.contains(c), "{c:?}");
    }
    let risky = r.rules.iter().find(|x| x.id == "SPW-HAWK-012").unwrap();
    assert!(
        risky
            .not_applicable
            .iter()
            .any(|e| e.licence_profile == "m365_e3")
    );
    let text = r.to_text();
    assert!(text.contains("SPW-MAIL-003") && text.contains("look-alike:"));
}
