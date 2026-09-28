//! Task 22: exported e-mail headers (.eml) and Hawk message-header exports. The two tests are
//! the plan's, unchanged.

#[path = "common/synth.rs"]
mod synth;

use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::options::{Collector, GenerateOptions, PsEdition};
use sparrow_synth::scenario::load;
use sparrow_synth::testing::ingest_generated;
use synth::*;

#[test]
fn eml_headers_show_the_spoof_and_the_clean_message() {
    let g = builtin("bec-aitm", PsEdition::Ps7);
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM email_artifacts WHERE source = 'eml'"
        ),
        2
    );
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM email_artifacts WHERE NOT p1_p2_match AND spf = 'fail' AND dmarc = 'fail' AND auth_as = 'Anonymous'"
        ),
        1
    );
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM email_artifacts WHERE p1_p2_match AND spf = 'pass'"
        ),
        1
    );
    check_green(&g);
}

#[test]
fn hawk_header_exports_load_with_findings() {
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(
        &load("hawk-investigate").unwrap(),
        &GenerateOptions::new(Collector::Hawk4, 3),
        dir.path(),
    )
    .unwrap();
    let case = ingest_generated(dir.path(), &m);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM email_artifacts WHERE source = 'hawk_message_header' AND json_array_length(findings) >= 3"
        ),
        2
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM email_artifacts WHERE NOT p1_p2_match"
        ),
        1
    );
    let r = sparrow_synth::check::check(&m, &case).unwrap();
    assert!(r.ok, "{:#?}", r.problems);
}
