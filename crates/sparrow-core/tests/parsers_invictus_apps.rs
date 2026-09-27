#[path = "common/synth.rs"]
mod synth;

use sparrow_synth::options::PsEdition;
use synth::*;

#[test]
fn delegated_first_header_drops_application_columns_but_rows_load() {
    let g = builtin("bec-aitm", PsEdition::Ps7);
    // Mail Organizer Plus consent: five delegated scopes for the victim.
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM oauth_grants WHERE client_name = 'Mail Organizer Plus' AND permission_type = 'delegated'"
        ),
        5
    );
    assert!(
        count(
            &g.case,
            "SELECT count(*) FROM oauth_grants WHERE permission_type = 'application'"
        ) >= 1
    );
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM oauth_grants WHERE lower(permission) = 'offline_access' AND principal_id IS NOT NULL"
        ),
        1
    );
    check_green(&g);
}

#[test]
fn applications_from_three_runs_and_the_triage_root() {
    for ps in [PsEdition::Ps7, PsEdition::Ps51] {
        let g = builtin("bec-aitm", ps);
        assert!(
            count(
                &g.case,
                "SELECT count(*) FROM applications WHERE display_name = 'Helpdesk Portal' AND association_type IS NULL"
            ) >= 1
        );
        assert!(
            count(
                &g.case,
                "SELECT count(*) FROM applications WHERE association_type = 'Owner'"
            ) >= 1
        );
        let runs = count(
            &g.case,
            "SELECT count(DISTINCT run_stamp) FROM collector_runs WHERE component = 'EntraID' AND run_label IN ('OAuthPermissions', 'ServicePrincipals', 'AppRegistrations')",
        );
        assert_eq!(runs, 3);
        check_green(&g);
    }
}
