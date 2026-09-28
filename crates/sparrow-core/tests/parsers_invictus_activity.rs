//! Task 20: Microsoft-Extractor-Suite Azure activity logs and directory activity logs. The test
//! is the plan's, unchanged.

#[path = "common/synth.rs"]
mod synth;

use sparrow_synth::options::PsEdition;
use synth::*;

#[test]
fn activity_logs_in_every_directory_activity_form_load_once() {
    for ps in [PsEdition::Ps7, PsEdition::Ps51] {
        let g = builtin("bec-aitm", ps);
        let n = count(&g.case, "SELECT count(*) FROM azure_activity");
        assert!(n > 0);
        // Four sources (ActivityLog + three DirectoryActivityLogs forms) of the same events: rows
        // deduplicate by eventDataId, sightings do not.
        let sightings = count(
            &g.case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'azure_activity'",
        );
        assert_eq!(sightings, 4 * n);
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM azure_activity WHERE operation_name IS NULL OR ip IS NULL"
            ),
            0
        );
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM timeline WHERE source_table = 'azure_activity'"
            ),
            n
        );
        check_green(&g);
    }
}
