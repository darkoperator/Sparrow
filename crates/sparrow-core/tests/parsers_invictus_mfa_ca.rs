#[path = "common/synth.rs"]
mod synth;

use sparrow_synth::options::PsEdition;
use synth::*;

#[test]
fn mfa_files_fill_one_row_per_user() {
    for ps in [PsEdition::Ps7, PsEdition::Ps51] {
        let g = builtin("bec-aitm", ps);
        assert_eq!(count(&g.case, "SELECT count(*) FROM mfa_registration"), 13);
        // The last user has only a password: not registered, and MFAstatus Disabled.
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM mfa_registration WHERE NOT is_mfa_registered AND mfa_status = 'Disabled' AND method_password"
            ),
            1
        );
        // The victim registered a second authenticator after the AiTM sign-in.
        assert!(
            count(
                &g.case,
                "SELECT count(*) FROM mfa_registration WHERE list_contains(methods, 'microsoftAuthenticatorPush') AND method_authenticator_app"
            ) >= 1
        );
        check_green(&g);
    }
}

#[test]
fn ca_policies_split_lists_and_drop_placeholders() {
    let g = builtin("bec-aitm", PsEdition::Ps7);
    assert_eq!(count(&g.case, "SELECT count(*) FROM ca_policies"), 2);
    assert_eq!(
        text(
            &g.case,
            "SELECT array_to_string(built_in_controls, ',') FROM ca_policies WHERE display_name = 'Require MFA for admins'"
        ),
        "mfa"
    );
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM ca_policies WHERE session_controls->>'$.sign_in_frequency' IS NOT NULL"
        ),
        0
    );
    assert_eq!(
        text(
            &g.case,
            "SELECT state FROM ca_policies WHERE display_name = 'Block legacy authentication'"
        ),
        "enabledForReportingButNotEnforced"
    );
}

#[test]
fn without_p1_there_are_no_ca_policies_and_no_registration_details() {
    let g = builtin("bec-o365-no-p1", PsEdition::Ps7);
    assert_eq!(count(&g.case, "SELECT count(*) FROM ca_policies"), 0);
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM mfa_registration WHERE is_mfa_registered IS NOT NULL"
        ),
        0
    );
    assert!(
        count(
            &g.case,
            "SELECT count(*) FROM mfa_registration WHERE mfa_status IS NOT NULL"
        ) > 0
    );
    check_green(&g);
}

/// The `lastUpdatedDateTime` cells of the UserRegistrationDetails file, in row order.
fn registration_last_updated(g: &Generated) -> Vec<String> {
    let f = g
        .manifest
        .files
        .iter()
        .find(|f| f.artifact_id.as_deref() == Some("inv.mfa.registration"))
        .expect("registration file");
    let path = g.dir.join(&g.manifest.root).join(&f.rel_path);
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines = text.lines();
    let header = lines.next().unwrap();
    let index = header
        .split(',')
        .position(|h| h.trim_matches('"') == "lastUpdatedDateTime")
        .expect("lastUpdatedDateTime column");
    lines
        .map(|line| {
            line.split(',')
                .nth(index)
                .unwrap()
                .trim_matches('"')
                .to_string()
        })
        .collect()
}

/// A REST `Invoke-MgGraphRequest` date stays ISO on PS 5.1 and renders culture on PS7; both
/// editions load the same instant (the reports API's lastUpdatedDateTime).
#[test]
fn rest_origin_dates_render_by_edition_and_load_the_same_instant() {
    let ps7 = builtin("bec-aitm", PsEdition::Ps7);
    let ps51 = builtin("bec-aitm", PsEdition::Ps51);
    let iso = registration_last_updated(&ps51);
    let culture = registration_last_updated(&ps7);
    assert_eq!(iso.len(), 13);
    assert_eq!(culture.len(), 13);
    assert!(
        iso.iter().all(|v| v.contains('T') && v.ends_with('Z')),
        "{iso:?}"
    );
    assert!(
        culture
            .iter()
            .all(|v| !v.contains('T') && !v.ends_with('Z')),
        "{culture:?}"
    );
    let epochs = |g: &Generated| -> Vec<i64> {
        let mut stmt = g
            .case
            .conn()
            .prepare(
                "SELECT epoch(last_updated)::BIGINT FROM mfa_registration
                 WHERE last_updated IS NOT NULL ORDER BY 1",
            )
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<i64>, _>>()
            .unwrap()
    };
    let loaded = epochs(&ps7);
    assert!(!loaded.is_empty());
    assert_eq!(loaded, epochs(&ps51));
}

/// The two MFA files fill one row's disjoint columns: the later UserRegistrationDetails file
/// must not clear AuthenticationMethods' `mfa_status` or `method_*` flags.
#[test]
fn the_two_mfa_files_keep_each_others_columns() {
    let g = builtin("bec-aitm", PsEdition::Ps7);
    assert!(
        count(
            &g.case,
            "SELECT count(*) FROM mfa_registration WHERE method_authenticator_app AND mfa_status = 'Enabled' AND is_mfa_registered"
        ) >= 1
    );
    check_green(&g);
}
