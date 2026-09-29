#[path = "common/synth.rs"]
mod synth;

use sparrow_synth::options::PsEdition;
use sparrow_synth::scenario::load;
use sparrow_synth::world::World;
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

/// ServicePrincipals (earlier) supplies `enabled`/`owner_org_id`; AppRegistrations (later)
/// supplies `object_id`/`created`. The later file must not clear the earlier one's columns.
#[test]
fn service_principals_and_app_registrations_keep_each_others_columns() {
    let g = builtin("bec-aitm", PsEdition::Ps7);
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM applications WHERE display_name = 'Helpdesk Portal'
               AND association_type IS NULL AND enabled AND owner_org_id IS NOT NULL
               AND object_id IS NOT NULL AND created IS NOT NULL"
        ),
        1
    );
    check_green(&g);
}

/// The world assigns Helpdesk Portal to users 1 and 3 and Payroll Sync to user 2. The
/// collector's `$processedAppIds` is created once before the user loop and keyed `SP_<spId>`
/// for assignments (TriageFunctions.ps1:91,177), so each service principal yields exactly one
/// Assignment row, attributed to the first victim in `-UserIds` order.
#[test]
fn app_role_assignments_load_and_dedupe_per_service_principal() {
    let world = World::build(&load("bec-aitm").unwrap(), 17).unwrap();
    let g = builtin("bec-aitm", PsEdition::Ps7);
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM applications WHERE association_type = 'Assignment'"
        ),
        2
    );
    assert_eq!(
        text(
            &g.case,
            "SELECT associated_user FROM applications
             WHERE display_name = 'Helpdesk Portal' AND association_type = 'Assignment'"
        ),
        world.user(1).upn
    );
    assert_eq!(
        text(
            &g.case,
            "SELECT associated_user FROM applications
             WHERE display_name LIKE '%Payroll Sync' AND association_type = 'Assignment'"
        ),
        world.user(2).upn
    );
    check_green(&g);
}

/// `oauth_grants.created` is the client service principal's `createdDateTime`
/// (Get-OAuthPermissions.ps1:229 for delegated rows, :358 for application rows), not the app
/// registration's creation.
#[test]
fn oauth_grant_created_is_the_service_principal_creation() {
    let world = World::build(&load("bec-aitm").unwrap(), 17).unwrap();
    let helpdesk = world
        .apps
        .iter()
        .find(|a| a.display_name == "Helpdesk Portal")
        .unwrap();
    assert_ne!(helpdesk.sp_created, helpdesk.created);
    let g = builtin("bec-aitm", PsEdition::Ps7);
    assert_eq!(
        count(
            &g.case,
            &format!(
                "SELECT count(*) FROM oauth_grants WHERE client_name = 'Helpdesk Portal'
                   AND epoch(created)::BIGINT = {}",
                helpdesk.sp_created.timestamp()
            )
        ),
        1
    );
    check_green(&g);
}
