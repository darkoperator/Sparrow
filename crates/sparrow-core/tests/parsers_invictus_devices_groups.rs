#[path = "common/synth.rs"]
mod synth;

use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::options::{Collector, GenerateOptions, PsEdition};
use sparrow_synth::scenario::load;
use sparrow_synth::testing::ingest_generated;
use synth::*;

#[test]
fn devices_and_groups_load() {
    for ps in [PsEdition::Ps7, PsEdition::Ps51] {
        let g = builtin("bec-aitm", ps);
        // One laptop per user and a phone for every second user (12 users).
        assert_eq!(count(&g.case, "SELECT count(*) FROM devices"), 18);
        assert_eq!(count(&g.case, "SELECT count(*) FROM groups"), 3);
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM groups WHERE is_dynamic AND membership_rule LIKE '%Sales%'"
            ),
            1
        );
        assert_eq!(
            text(
                &g.case,
                "SELECT array_to_string(group_types, ',') FROM groups WHERE display_name = 'All Staff'"
            ),
            "Unified"
        );
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM group_members WHERE group_name = 'Finance'"
            ),
            3
        );
        check_green(&g);
    }
}

#[test]
fn json_written_to_a_csv_path_is_read_as_json() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = GenerateOptions::new(Collector::Invictus, 5);
    o.invictus_devices_json = true;
    let m = generate_to_dir(&load("bec-aitm").unwrap(), &o, dir.path()).unwrap();
    let case = ingest_generated(dir.path(), &m);
    assert_eq!(count(&case, "SELECT count(*) FROM devices"), 18);
    let r = sparrow_synth::check::check_without_detection(&m, &case).unwrap();
    assert!(r.ok, "{:#?}", r.problems);
}

/// Groups.csv (the earlier run) supplies `is_assignable_to_role`; the DynamicGroups run (later
/// stamp) does not export it, so the dynamic group must keep the Get-Groups value.
#[test]
fn a_dynamic_group_keeps_the_groups_csv_columns_it_lacks() {
    let g = builtin("bec-aitm", PsEdition::Ps7);
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM groups WHERE display_name = 'Dynamic Sales' AND is_assignable_to_role = false"
        ),
        1
    );
    // The columns the dynamic file does supply still load.
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM groups WHERE display_name = 'Dynamic Sales' AND is_dynamic AND membership_rule LIKE '%Sales%'"
        ),
        1
    );
    check_green(&g);
}

/// The hand-written variant also covers `expiration` and `proxy_addresses`, which the generated
/// Get-Groups export leaves empty.
#[test]
fn dynamic_groups_do_not_clear_the_groups_columns_they_lack() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("OUT");
    let gid = "0e0e0e0e-0000-4000-8000-0000000000c1";
    let groups = format!(
        "{}{}",
        csv_line(&[
            "GroupId",
            "DisplayName",
            "Description",
            "Mail",
            "MailEnabled",
            "MailNickname",
            "SecurityEnabled",
            "GroupTypes",
            "CreatedDateTime",
            "RenewedDateTime",
            "ExpirationDateTime",
            "Visibility",
            "OnPremisesSyncEnabled",
            "OnPremisesLastSyncDateTime",
            "SecurityIdentifier",
            "IsManagementRestricted",
            "MembershipRule",
            "MembershipRuleProcessingState",
            "Classification",
            "HideFromAddressLists",
            "HideFromOutlookClients",
            "IsAssignableToRole",
            "PreferredDataLocation",
            "ProxyAddresses",
        ]),
        csv_line(&[
            gid,
            "Dynamic Sales",
            "",
            "",
            "False",
            "",
            "True",
            "DynamicMembership",
            "2026-01-15 00:00:00",
            "",
            "2026-06-15 12:00:00",
            "",
            "",
            "",
            "",
            "",
            "user.department -eq \"Sales\"",
            "On",
            "",
            "",
            "",
            "True",
            "",
            "SMTP:dyn@contoso.example",
        ]),
    );
    fixtures::write(
        &root,
        "Groups/20260910-100000/20260910-100000-Groups.csv",
        groups.as_bytes(),
    );
    let dynamic = format!(
        "{}{}",
        csv_line(&[
            "GroupId",
            "DisplayName",
            "Description",
            "Mail",
            "MailEnabled",
            "MailNickname",
            "SecurityEnabled",
            "GroupTypes",
            "CreatedDateTime",
            "RenewedDateTime",
            "MembershipRule",
            "MembershipRuleProcessingState",
            "OnPremisesSyncEnabled",
            "SecurityIdentifier",
            "Classification",
            "Visibility",
        ]),
        csv_line(&[
            gid,
            "Dynamic Sales",
            "",
            "",
            "False",
            "",
            "True",
            "DynamicMembership",
            "2026-01-15 00:00:00",
            "",
            "user.department -eq \"Sales\"",
            "On",
            "",
            "",
            "",
            "",
        ]),
    );
    // The DynamicGroups run is stamped later than the Groups run.
    fixtures::write(
        &root,
        "Groups/20260910-110000/20260910-110000-DynamicGroups.csv",
        dynamic.as_bytes(),
    );
    std::fs::write(
        root.join("LogFile.txt"),
        b"2026-09-10 10:00:00: Starting\r\n",
    )
    .unwrap();
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM groups WHERE group_id = '{gid}' AND is_assignable_to_role"
            )
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM groups WHERE group_id = '{gid}' AND list_contains(proxy_addresses, 'SMTP:dyn@contoso.example')"
            )
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            &format!("SELECT epoch(expiration)::BIGINT FROM groups WHERE group_id = '{gid}'")
        ),
        1781524800 // 2026-06-15T12:00:00Z
    );
}
