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
