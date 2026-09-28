//! Task 20: Microsoft-Extractor-Suite Azure activity logs and directory activity logs. The
//! sightings assertion is the architect-approved correction from the task20-fix brief: the
//! three DirectoryActivityLogs outputs are one PowerShell session, so on PS7 the `.JSON` and
//! `.jsonl` are byte-identical and the later one is `duplicate_file`.

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
        // Four collector files (ActivityLog + the three DirectoryActivityLogs outputs) carry the
        // same events: rows deduplicate by eventDataId. The three DirectoryActivityLogs outputs
        // are cmdlet calls in ONE PowerShell session, so they share one key order per tree. On
        // PS 5.1 `.JSON` is Windows-1252 and `.jsonl` is UTF-8 with a BOM, so both parse; on PS7
        // both are UTF-8 with no BOM and hold the same `ConvertTo-Json` array, so the later
        // `.jsonl` is byte-identical and the ingest marks it duplicate_file. Architect-approved
        // correction to the plan's blanket 4*n (task20-fix brief).
        let expected = match ps {
            PsEdition::Ps7 => 3 * n,
            PsEdition::Ps51 => 4 * n,
        };
        let sightings = count(
            &g.case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'azure_activity'",
        );
        assert_eq!(sightings, expected);
        if ps == PsEdition::Ps7 {
            assert_eq!(
                text(
                    &g.case,
                    "SELECT CAST(status AS VARCHAR) FROM source_files
                     WHERE artifact_type = 'inv.directory_activity' AND rel_path LIKE '%.jsonl'"
                ),
                "duplicate_file"
            );
        }
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
