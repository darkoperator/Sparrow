//! The per-tenant spray-source relation (`spray_sources`): one definition every rule shares, and
//! the structural tenant scope that keeps a tenant's sources from another tenant's rules.

#[path = "common/detect.rs"]
mod detect;

use detect::{insert_row, run};
use serde_json::json;
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::detect::compile::{CaseSchema, compile};
use sparrow_core::detect::rule::Rule;
use sparrow_core::profile::spray;
use std::collections::BTreeMap;

const T1: &str = "t1";
const T2: &str = "t2";

fn tenant(case: &Case, key: &str) {
    insert_row(case, "tenant", key, json!({"tenant_key": key}));
    detect::collection_of(case, key);
}

fn rebuild(case: &Case) -> usize {
    let codes = spray::credential_failure_codes(&DataDirs::default()).unwrap();
    spray::rebuild(case.conn(), &codes).unwrap()
}

/// An interactive sign-in (the credential failures a spray produces are interactive).
fn signin(case: &Case, t: &str, upn: &str, ip: &str, code: i64, time: &str) {
    insert_row(
        case,
        "signins",
        t,
        json!({"user_upn": upn, "ip": ip, "error_code": code, "event_time": time,
               "is_interactive": true}),
    );
}

fn sources(case: &Case) -> Vec<(String, String, i64, i64)> {
    let mut st = case
        .conn()
        .prepare("SELECT tenant_key, ip, users_targeted, failures FROM spray_sources ORDER BY 1, 2")
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn spray(case: &Case, t: &str, ip: &str, users: usize, code: i64) {
    for u in 0..users {
        signin(
            case,
            t,
            &format!("u{u}@contoso.example"),
            ip,
            code,
            "2026-03-01T10:00:00Z",
        );
    }
}

#[test]
fn a_source_fails_five_users_who_never_succeed_from_it_and_outnumber_the_successes() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    // Five users failing: a source; four: not. No ip_intel row exists for any address.
    spray(&case, T1, "198.51.100.1", 5, 50126);
    spray(&case, T1, "198.51.100.2", 4, 50126);
    // An MFA prompt (50074) or a Conditional Access block (53003) is not a credential failure,
    // however many users see it.
    spray(&case, T1, "198.51.100.3", 8, 50074);
    spray(&case, T1, "198.51.100.8", 8, 53003);
    // The office NAT: six users mistype a password and sign in successfully a minute later, with
    // other users succeeding too: the mistyping users are not failed-only.
    spray(&case, T1, "198.51.100.4", 6, 50126);
    for u in 0..10 {
        signin(
            &case,
            T1,
            &format!("u{u}@contoso.example"),
            "198.51.100.4",
            0,
            "2026-03-01T10:05:00Z",
        );
    }
    // An address that also signs one of its six failing users in is still a source: five failed-only
    // users outnumber the one success.
    spray(&case, T1, "198.51.100.5", 6, 50053);
    signin(
        &case,
        T1,
        "u0@contoso.example",
        "198.51.100.5",
        0,
        "2026-03-02T10:00:00Z",
    );
    // A sign-in without a result code is not a failure.
    for u in 0..6 {
        insert_row(
            &case,
            "signins",
            T1,
            json!({"user_upn": format!("v{u}@contoso.example"), "ip": "198.51.100.6",
                   "event_time": "2026-03-01T10:00:00Z"}),
        );
    }
    assert_eq!(rebuild(&case), 2);
    assert_eq!(
        sources(&case),
        vec![
            (T1.to_string(), "198.51.100.1".to_string(), 5, 5),
            (T1.to_string(), "198.51.100.5".to_string(), 6, 6),
        ]
    );
    // The columns: 198.51.100.5 has six sprayed users, five failed-only and one taken over a day later.
    let mut st = case
        .conn()
        .prepare(
            "SELECT ip, failed_only_users, success_users, sprayed_users, takeover_users
             FROM spray_sources ORDER BY ip",
        )
        .unwrap();
    let cols: Vec<(String, i64, i64, i64, i64)> = st
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        cols,
        vec![
            ("198.51.100.1".to_string(), 5, 0, 5, 0),
            ("198.51.100.5".to_string(), 5, 1, 6, 1)
        ]
    );
    // A rebuild replaces, never appends.
    rebuild(&case);
    assert_eq!(sources(&case).len(), 2);
}

/// A source that sprayed tenant A is invisible to tenant B's rules, even when tenant B has
/// sign-ins from the same address: the rule connection shows a rule only its own tenant's rows.
#[test]
fn a_tenants_spray_sources_are_invisible_to_another_tenants_rules() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1);
    tenant(&case, T2);
    spray(&case, T1, "198.51.100.1", 6, 50126);
    // Tenant B: one successful user from the same address, no failures.
    signin(
        &case,
        T2,
        "b@fabrikam.example",
        "198.51.100.1",
        0,
        "2026-03-01T10:00:00Z",
    );
    rebuild(&case);
    assert_eq!(sources(&case).len(), 1);

    let rule: Rule = serde_norway::from_str(
        "id: SPW-T-001\ntitle: t\nversion: 1\nstatus: experimental\nseverity: low\nanalyst_guidance: g\n\
         sql: |\n  SELECT ip AS record_key, 'signins' AS source_table, first_failure AS event_time,\n         CAST(NULL AS VARCHAR) AS actor_upn, ip FROM spray_sources\n\
         group_by: [ip]\ntests:\n  - name: p\n    records: []\n    expect_hits: 1\n  - name: n\n    records: []\n    expect_hits: 0\n",
    )
    .unwrap();
    let schema = CaseSchema::of(case.conn()).unwrap();
    let compiled = compile(&rule, &BTreeMap::new(), &schema).unwrap();
    let a = run(&mut case, &compiled, T1, &BTreeMap::new()).unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].record_key, "198.51.100.1");
    let b = run(&mut case, &compiled, T2, &BTreeMap::new()).unwrap();
    assert!(b.is_empty(), "{b:?}");
}

/// An unknown result (NULL error_code) is never a failure and never counts as a success that excuses
/// a source: only KNOWN successes (error_code 0) are success users.
#[test]
fn unknown_results_neither_fail_nor_excuse() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    spray(&case, T1, "198.51.100.7", 6, 50126);
    for u in 0..30 {
        insert_row(
            &case,
            "signins",
            T1,
            json!({"user_upn": format!("x{u}@contoso.example"), "ip": "198.51.100.7",
                   "event_time": "2026-02-01T09:00:00Z"}),
        );
    }
    assert_eq!(rebuild(&case), 1);
    assert_eq!(sources(&case)[0].1, "198.51.100.7");
}

#[allow(clippy::too_many_arguments)]
fn app_signin(
    case: &Case,
    t: &str,
    upn: &str,
    ip: &str,
    app: &str,
    day: &str,
    interactive: bool,
    code: Option<i64>,
) {
    let mut row = json!({"user_upn": upn, "ip": ip, "app_id": app, "is_interactive": interactive,
                         "event_time": format!("2026-02-{day}T09:00:00Z")});
    if let Some(c) = code {
        row["error_code"] = json!(c);
    }
    insert_row(case, "signins", t, row);
}

fn services(case: &Case) -> Vec<(String, String, i64)> {
    let mut st = case
        .conn()
        .prepare("SELECT tenant_key, app_id, asn FROM cloud_services ORDER BY 1, 2, 3")
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Rebuild the spray sources first (the cloud-service disqualification reads them), then the services.
fn cloud(case: &Case) -> usize {
    rebuild(case);
    let codes = spray::credential_failure_codes(&DataDirs::default()).unwrap();
    sparrow_core::profile::cloud_services::rebuild(case.conn(), &codes).unwrap()
}

fn intel(case: &Case, t: &str, ip: &str, asn: i64, hosting: bool) {
    insert_row(
        case,
        "ip_intel",
        t,
        json!({"ip": ip, "asn": asn, "is_hosting": hosting, "is_microsoft": false,
               "is_private": false}),
    );
}

/// A tenant-wide cloud service, per (application, ASN): at least 5 users on at least 3 days from one
/// hosting ASN, and those sign-ins are at least 80% of the application's known successes. Interactive
/// and non-interactive sign-ins both count (the portal export records a connector's backend as
/// interactive). Per tenant: the same application is judged on each tenant's own sign-ins.
#[test]
fn a_cloud_service_is_five_users_three_days_and_eighty_percent_from_one_hosting_asn() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    tenant(&case, T2);
    intel(&case, T1, "203.0.113.1", 14061, true);
    intel(&case, T1, "203.0.113.2", 16509, true);
    intel(&case, T1, "198.51.100.5", 7922, false);
    let svc = "C0C0C0C0-0000-4000-8000-0000000000C1";
    let (four, two, mixed, unknown, split) = (
        "c0c0c0c0-0000-4000-8000-0000000000c2",
        "c0c0c0c0-0000-4000-8000-0000000000c3",
        "c0c0c0c0-0000-4000-8000-0000000000c4",
        "c0c0c0c0-0000-4000-8000-0000000000c5",
        "c0c0c0c0-0000-4000-8000-0000000000c6",
    );
    for day in ["01", "02", "03"] {
        for u in 0..6 {
            let upn = format!("u{u}@contoso.example");
            // The service, in both tenants (an upper-case id is stored lower-case). Its backend rows are
            // interactive for some users and non-interactive for others.
            app_signin(
                &case,
                T1,
                &upn,
                "203.0.113.1",
                svc,
                day,
                u % 2 == 0,
                Some(0),
            );
            app_signin(&case, T2, &upn, "203.0.113.1", svc, day, true, Some(0));
            // Only four users: not a service.
            if u < 4 {
                app_signin(&case, T1, &upn, "203.0.113.1", four, day, true, Some(0));
            }
            // Only two days: not a service.
            if day != "03" {
                app_signin(&case, T1, &upn, "203.0.113.1", two, day, true, Some(0));
            }
            // One hosting sign-in against three from an ordinary ISP: below 80%.
            app_signin(&case, T1, &upn, "203.0.113.1", mixed, day, true, Some(0));
            for _ in 0..3 {
                app_signin(&case, T1, &upn, "198.51.100.5", mixed, day, true, Some(0));
            }
            // An unknown result is never a known success.
            app_signin(&case, T1, &upn, "203.0.113.1", unknown, day, true, None);
            // Two hosting ASNs share the app evenly: neither reaches 80% of the app's sign-ins.
            let ip = if u % 2 == 0 {
                "203.0.113.1"
            } else {
                "203.0.113.2"
            };
            app_signin(&case, T1, &upn, ip, split, day, true, Some(0));
        }
    }
    assert_eq!(cloud(&case), 2);
    // Established from the whole case (no prefix), for ASN 14061.
    assert_eq!(
        services(&case),
        vec![
            (T1.to_string(), svc.to_lowercase(), 14061),
            (T2.to_string(), svc.to_lowercase(), 14061),
        ]
    );
}

/// The same application from a second hosting ASN is not covered by the first ASN's profile: a
/// row exists only for the ASN that meets the thresholds, so a rule excuses nothing from the other.
#[test]
fn a_service_is_established_for_its_own_asn_only() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    intel(&case, T1, "203.0.113.1", 14061, true);
    intel(&case, T1, "203.0.113.2", 16509, true);
    let app = "c0c0c0c0-0000-4000-8000-0000000000d1";
    for day in ["01", "02", "03", "04"] {
        for u in 0..6 {
            app_signin(
                &case,
                T1,
                &format!("u{u}@contoso.example"),
                "203.0.113.1",
                app,
                day,
                true,
                Some(0),
            );
        }
        // A few sign-ins from another hosting ASN stay under both the user and the share limits.
        app_signin(
            &case,
            T1,
            "x@contoso.example",
            "203.0.113.2",
            app,
            day,
            true,
            Some(0),
        );
    }
    assert_eq!(cloud(&case), 1);
    assert_eq!(services(&case)[0].2, 14061);
}

/// A few interactive sign-ins from a hosting ASN do not make a service: below five users it is a VPS
/// login, not a connector.
#[test]
fn a_hosting_asn_with_few_users_is_no_service() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    intel(&case, T1, "203.0.113.1", 14061, true);
    let app = "c0c0c0c0-0000-4000-8000-0000000000d2";
    for day in ["01", "02", "03", "04"] {
        for u in 0..4 {
            app_signin(
                &case,
                T1,
                &format!("u{u}@contoso.example"),
                "203.0.113.1",
                app,
                day,
                true,
                Some(0),
            );
        }
    }
    assert_eq!(cloud(&case), 0);
}

/// A proxy that sprays 20 users and takes over five of them (successes on three later days) stays a
/// source: 15 failed-only users outnumber the 5 taken accounts.
#[test]
fn a_proxy_that_took_over_a_few_accounts_stays_a_source() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    spray(&case, T1, "198.51.100.9", 20, 50126);
    for day in ["02", "03", "04"] {
        for u in 0..5 {
            signin(
                &case,
                T1,
                &format!("u{u}@contoso.example"),
                "198.51.100.9",
                0,
                &format!("2026-03-{day}T09:00:00Z"),
            );
        }
    }
    assert_eq!(rebuild(&case), 1);
    assert_eq!(sources(&case)[0].1, "198.51.100.9");
}

/// An office NAT whose five departed or disabled accounts keep failing (50057, 50034, 50055) while 23
/// other users sign in successfully: the failed-only users are five, the successes 23, so it is not a
/// source. The same five stale accounts failing from an address nobody succeeds from is one.
#[test]
fn stale_accounts_behind_an_office_nat_do_not_make_it_a_source() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    for (u, code) in [(0, 50057), (1, 50034), (2, 50055), (3, 50057), (4, 50034)] {
        for ip in ["198.51.100.30", "198.51.100.31"] {
            signin(
                &case,
                T1,
                &format!("old{u}@contoso.example"),
                ip,
                code,
                "2026-03-01T10:00:00Z",
            );
        }
    }
    for u in 0..23 {
        signin(
            &case,
            T1,
            &format!("w{u}@contoso.example"),
            "198.51.100.30",
            0,
            "2026-03-01T10:00:00Z",
        );
    }
    assert_eq!(rebuild(&case), 1);
    assert_eq!(sources(&case)[0].1, "198.51.100.31");
}

/// The new columns are per tenant: another tenant's successes from the same address neither excuse the
/// address nor count as this tenant's success users.
#[test]
fn failed_only_and_success_users_are_counted_per_tenant() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    tenant(&case, T2);
    spray(&case, T1, "198.51.100.40", 6, 50126);
    spray(&case, T2, "198.51.100.40", 6, 50126);
    for u in 0..30 {
        signin(
            &case,
            T2,
            &format!("u{u}@contoso.example"),
            "198.51.100.40",
            0,
            "2026-03-02T10:00:00Z",
        );
    }
    assert_eq!(rebuild(&case), 1);
    let (t, ip, ..) = sources(&case).remove(0);
    assert_eq!((t.as_str(), ip.as_str()), (T1, "198.51.100.40"));
    let (fo, su): (i64, i64) = case
        .conn()
        .query_row(
            "SELECT failed_only_users, success_users FROM spray_sources",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((fo, su), (6, 0));
}

/// Only INTERACTIVE rows with a code of the shared credential-failure list are spray failures:
/// token-refresh errors (70043, 50173), a Conditional Access block (53003), and non-interactive rows
/// are not, so a secure web gateway or VPN egress with many of them is no spray source, and a
/// conference network with two or three mistyped passwords stays under the threshold.
#[test]
fn only_interactive_credential_failures_count() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    // A web gateway: CA blocks and token-refresh errors for many users, few successes.
    for (u, code) in [
        (0, 53003),
        (1, 70043),
        (2, 50173),
        (3, 53003),
        (4, 70043),
        (5, 50173),
    ] {
        signin(
            &case,
            T1,
            &format!("g{u}@contoso.example"),
            "198.51.100.20",
            code,
            "2026-03-01T10:00:00Z",
        );
    }
    signin(
        &case,
        T1,
        "g0@contoso.example",
        "198.51.100.20",
        0,
        "2026-03-01T11:00:00Z",
    );
    // Credential failures that are not interactive.
    for u in 0..6 {
        insert_row(
            &case,
            "signins",
            T1,
            json!({"user_upn": format!("n{u}@contoso.example"), "ip": "198.51.100.21",
                   "error_code": 50126, "event_time": "2026-03-01T10:00:00Z",
                   "is_interactive": false}),
        );
    }
    // A conference network: three users mistype.
    spray(&case, T1, "198.51.100.22", 3, 50126);
    // A real spray, with the allow-list's other codes (unknown user, invalid password, lockout).
    for (u, code) in [
        (0, 50034),
        (1, 50126),
        (2, 50053),
        (3, 50056),
        (4, 50064),
        (5, 50126),
    ] {
        signin(
            &case,
            T1,
            &format!("s{u}@contoso.example"),
            "198.51.100.23",
            code,
            "2026-03-01T10:00:00Z",
        );
    }
    assert_eq!(rebuild(&case), 1);
    assert_eq!(sources(&case)[0].1, "198.51.100.23");
}

/// No prefix: a connector that was already in use when the capture started is established from the
/// whole case, exactly the three days it was seen (the capture window cuts its history), and the
/// relation carries no establishing day.
#[test]
fn a_connector_in_use_since_before_the_window_is_established_from_the_whole_case() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    intel(&case, T1, "203.0.113.1", 14061, true);
    let app = "c0c0c0c0-0000-4000-8000-0000000000e1";
    for day in ["01", "02", "03"] {
        for u in 0..5 {
            app_signin(
                &case,
                T1,
                &format!("u{u}@contoso.example"),
                "203.0.113.1",
                app,
                day,
                true,
                Some(0),
            );
        }
    }
    assert_eq!(cloud(&case), 1);
    assert_eq!(
        services(&case),
        vec![(T1.to_string(), app.to_string(), 14061)]
    );
    let columns: i64 = case
        .conn()
        .query_row(
            "SELECT count(*) FROM duckdb_columns() WHERE table_name = 'cloud_services'
               AND column_name = 'established_day'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(columns, 0);
}

/// A portal sign-in file whose name does not say interactive or non-interactive leaves
/// `is_interactive` NULL. A credential failure with an unknown kind counts as interactive (a ROPC spray
/// is interactive), and an explicit non-interactive row still does not.
#[test]
fn a_credential_failure_of_unknown_kind_counts_as_interactive() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    for u in 0..6 {
        insert_row(
            &case,
            "signins",
            T1,
            json!({"user_upn": format!("u{u}@contoso.example"), "ip": "198.51.100.50",
                   "error_code": 50126, "event_time": "2026-03-01T10:00:00Z"}),
        );
        insert_row(
            &case,
            "signins",
            T1,
            json!({"user_upn": format!("u{u}@contoso.example"), "ip": "198.51.100.51",
                   "error_code": 50126, "event_time": "2026-03-01T10:00:00Z",
                   "is_interactive": false}),
        );
    }
    assert_eq!(rebuild(&case), 1);
    assert_eq!(sources(&case)[0].1, "198.51.100.50");
}

/// An office whose mistypes are spread over the whole window, day one included: ten users sign in on
/// many days and eight of them mistype once or twice on various days and then succeed. None is
/// failed-only, so the address is not a source however the failures are spread.
#[test]
fn mistypes_spread_across_the_window_do_not_make_an_office_a_source() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    for day in 1..=20 {
        for u in 0..10 {
            signin(
                &case,
                T1,
                &format!("u{u}@contoso.example"),
                "198.51.100.60",
                0,
                &format!("2026-03-{day:02}T09:{u:02}:00Z"),
            );
        }
    }
    for u in 0..8 {
        for k in 0..(1 + u % 2) {
            let day = 1 + (u * 3 + k * 7) % 20;
            signin(
                &case,
                T1,
                &format!("u{u}@contoso.example"),
                "198.51.100.60",
                50126,
                &format!("2026-03-{day:02}T08:30:00Z"),
            );
        }
    }
    assert_eq!(rebuild(&case), 0);
}

/// A source of the real median size: six sprayed users, two of them taken over hours later. Each taken
/// account moves a user from failed-only to success, but a takeover is not an excuse: the sprayed
/// users stay six and the excusing users (successes minus the late takeovers) none.
#[test]
fn takeovers_hours_later_do_not_remove_a_source() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    spray(&case, T1, "198.51.100.70", 6, 50126);
    for u in 0..2 {
        signin(
            &case,
            T1,
            &format!("u{u}@contoso.example"),
            "198.51.100.70",
            0,
            "2026-03-01T13:00:00Z",
        );
    }
    assert_eq!(rebuild(&case), 1);
    let (fo, su, sp, tk): (i64, i64, i64, i64) = case
        .conn()
        .query_row(
            "SELECT failed_only_users, success_users, sprayed_users, takeover_users FROM spray_sources",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!((fo, su, sp, tk), (4, 2, 6, 2));
}

/// A typo user (a failure, then a success two minutes later) is excused, and so is a user who signed in
/// from the address days before the failure (it was already theirs). Neither is a sprayed user, so six
/// such users make no source.
#[test]
fn typo_corrections_and_earlier_successes_excuse_a_user() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    for u in 0..3 {
        let upn = format!("u{u}@contoso.example");
        signin(
            &case,
            T1,
            &upn,
            "198.51.100.71",
            50126,
            "2026-03-05T10:00:00Z",
        );
        signin(&case, T1, &upn, "198.51.100.71", 0, "2026-03-05T10:02:00Z");
    }
    for u in 3..6 {
        let upn = format!("u{u}@contoso.example");
        signin(&case, T1, &upn, "198.51.100.71", 0, "2026-03-01T10:00:00Z");
        signin(
            &case,
            T1,
            &upn,
            "198.51.100.71",
            50126,
            "2026-03-05T10:00:00Z",
        );
    }
    assert_eq!(rebuild(&case), 0);
    // The same six failing without those successes are a spray.
    spray(&case, T1, "198.51.100.72", 6, 50126);
    assert_eq!(rebuild(&case), 1);
    // A success 31 minutes after the failure is not a typo correction.
    signin(
        &case,
        T1,
        "u0@contoso.example",
        "198.51.100.72",
        0,
        "2026-03-01T10:31:00Z",
    );
    assert_eq!(rebuild(&case), 1);
    let tk: i64 = case
        .conn()
        .query_row("SELECT takeover_users FROM spray_sources", [], |r| r.get(0))
        .unwrap();
    assert_eq!(tk, 1);
}

/// The new relation columns are per tenant: another tenant's takeover successes from the same address
/// neither excuse nor count.
#[test]
fn sprayed_and_takeover_users_are_counted_per_tenant() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    tenant(&case, T2);
    spray(&case, T1, "198.51.100.73", 6, 50126);
    spray(&case, T2, "198.51.100.73", 6, 50126);
    for u in 0..6 {
        signin(
            &case,
            T2,
            &format!("u{u}@contoso.example"),
            "198.51.100.73",
            0,
            "2026-03-01T10:02:00Z",
        );
    }
    // Tenant 2's users all typo-corrected: no source there. Tenant 1 keeps its six sprayed users.
    assert_eq!(rebuild(&case), 1);
    let (t, sp, tk, su): (String, i64, i64, i64) = case
        .conn()
        .query_row(
            "SELECT tenant_key, sprayed_users, takeover_users, success_users FROM spray_sources",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!((t.as_str(), sp, tk, su), (T1, 6, 0, 0));
}

/// Five accounts taken from a spray and used from one VPS to one application on three days would
/// qualify as a cloud service by the counts alone. They do not: their users were sprayed (a credential
/// failure from a spray source of the tenant), so the (app, ASN) is disqualified.
#[test]
fn accounts_taken_from_a_spray_do_not_make_a_cloud_service() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    intel(&case, T1, "203.0.113.1", 14061, true);
    let app = "c0c0c0c0-0000-4000-8000-0000000000f1";
    // The spray: a router fails against the six users (a source), the VPS then uses five of them.
    spray(&case, T1, "198.51.100.80", 6, 50126);
    for day in ["03", "04", "05"] {
        for u in 0..5 {
            app_signin(
                &case,
                T1,
                &format!("u{u}@contoso.example"),
                "203.0.113.1",
                app,
                day,
                true,
                Some(0),
            );
        }
    }
    assert_eq!(cloud(&case), 0);
    // The same sign-ins by users nobody sprayed (a connector) qualify.
    for day in ["03", "04", "05"] {
        for u in 0..5 {
            app_signin(
                &case,
                T1,
                &format!("c{u}@contoso.example"),
                "203.0.113.1",
                "c0c0c0c0-0000-4000-8000-0000000000f2",
                day,
                true,
                Some(0),
            );
        }
    }
    assert_eq!(cloud(&case), 1);
    assert_eq!(services(&case)[0].1, "c0c0c0c0-0000-4000-8000-0000000000f2");
}

/// Three users' credential failures to the application from the ASN disqualify it, with no spray
/// anywhere: wrong passwords typed on the VPS before the accounts worked. An interactive row and a row
/// of unknown kind count; a Conditional Access block (not a credential failure), a failure to another
/// application and a failure from another ASN do not, even from three users.
#[test]
fn credential_failures_from_the_asn_disqualify_the_service() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    intel(&case, T1, "203.0.113.1", 14061, true);
    intel(&case, T1, "203.0.113.2", 14061, true);
    intel(&case, T1, "203.0.113.3", 16509, true);
    let (a1, a2, a3, a4) = (
        "c0c0c0c0-0000-4000-8000-0000000000a1",
        "c0c0c0c0-0000-4000-8000-0000000000a2",
        "c0c0c0c0-0000-4000-8000-0000000000a3",
        "c0c0c0c0-0000-4000-8000-0000000000a4",
    );
    for app in [a1, a2, a3, a4] {
        connector_signins(&case, app, "203.0.113.1", 5);
    }
    let failing = ["x", "y", "z"].map(|w| format!("{w}@contoso.example"));
    for who in &failing {
        // a1: an interactive wrong password from the same ASN (another address of it).
        app_signin(&case, T1, who, "203.0.113.2", a1, "02", true, Some(50126));
        // a2: a row of unknown kind (NULL is_interactive) counts as interactive.
        insert_row(
            &case,
            "signins",
            T1,
            json!({"user_upn": who, "ip": "203.0.113.2", "app_id": a2,
                   "error_code": 50126, "event_time": "2026-02-02T09:00:00Z"}),
        );
        // a3: a Conditional Access block is not a credential failure.
        app_signin(&case, T1, who, "203.0.113.2", a3, "02", true, Some(53003));
        // a4: a credential failure from ANOTHER ASN.
        app_signin(&case, T1, who, "203.0.113.3", a4, "02", true, Some(50126));
    }
    assert_eq!(cloud(&case), 2);
    let got: Vec<String> = services(&case).into_iter().map(|r| r.1).collect();
    assert_eq!(got, vec![a3.to_string(), a4.to_string()]);
}

/// Six users (`n` users named `u0..`) of one application sign in from one hosting address on three
/// days: a service by the counts alone. The disqualifier tests add failures or sprays on top.
fn connector_signins(case: &Case, app: &str, ip: &str, users: usize) {
    for day in ["03", "04", "05"] {
        for u in 0..users {
            app_signin(
                case,
                T1,
                &format!("u{u}@contoso.example"),
                ip,
                app,
                day,
                true,
                Some(0),
            );
        }
    }
}

fn service_apps(case: &Case) -> Vec<String> {
    services(case).into_iter().map(|r| r.1).collect()
}

/// (b) Three DISTINCT users with an interactive credential failure to the application from the ASN
/// disqualify it. One stale account (a departed user's 50057 or 50034, retried by a device) or two
/// do not, however many times they fail; neither does a user failing three times, nor non-interactive
/// failures of three users.
#[test]
fn three_failing_users_disqualify_a_service_and_fewer_do_not() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    intel(&case, T1, "203.0.113.1", 14061, true);
    intel(&case, T1, "203.0.113.2", 14061, true);
    let apps: Vec<String> = (1..=8)
        .map(|k| format!("c0c0c0c0-0000-4000-8000-0000000001b{k}"))
        .collect();
    for app in &apps {
        connector_signins(&case, app, "203.0.113.1", 6);
    }
    // apps[0]: one departed account fails (disabled), twice. Still a service.
    for day in ["02", "03"] {
        app_signin(
            &case,
            T1,
            "gone@contoso.example",
            "203.0.113.2",
            &apps[0],
            day,
            true,
            Some(50057),
        );
    }
    // apps[1]: two users fail (an unknown user and a wrong password). Still a service.
    app_signin(
        &case,
        T1,
        "gone@contoso.example",
        "203.0.113.2",
        &apps[1],
        "02",
        true,
        Some(50034),
    );
    app_signin(
        &case,
        T1,
        "typo@contoso.example",
        "203.0.113.2",
        &apps[1],
        "02",
        true,
        Some(50126),
    );
    // apps[2]: three distinct users fail. Not a service.
    for who in ["gone", "typo", "old"] {
        app_signin(
            &case,
            T1,
            &format!("{who}@contoso.example"),
            "203.0.113.2",
            &apps[2],
            "02",
            true,
            Some(50126),
        );
    }
    // apps[3]: one user fails three times. One user: still a service.
    for day in ["01", "02", "03"] {
        app_signin(
            &case,
            T1,
            "gone@contoso.example",
            "203.0.113.2",
            &apps[3],
            day,
            true,
            Some(50126),
        );
    }
    // apps[4]: three users fail, non-interactively (not an interactive credential failure). Still a service.
    for who in ["gone", "typo", "old"] {
        app_signin(
            &case,
            T1,
            &format!("{who}@contoso.example"),
            "203.0.113.2",
            &apps[4],
            "02",
            false,
            Some(50126),
        );
    }
    // apps[5]: three users of the connector itself fail, by case: UPN case does not make them distinct users.
    for who in ["GONE", "gone", "Gone"] {
        app_signin(
            &case,
            T1,
            &format!("{who}@contoso.example"),
            "203.0.113.2",
            &apps[5],
            "02",
            true,
            Some(50126),
        );
    }
    // apps[6]: three users fail with a row of UNKNOWN kind (NULL is_interactive): counts as interactive.
    // Not a service.
    for who in ["gone", "typo", "old"] {
        insert_row(
            &case,
            "signins",
            T1,
            json!({"user_upn": format!("{who}@contoso.example"), "ip": "203.0.113.2",
                   "app_id": &apps[6], "error_code": 50126, "event_time": "2026-02-02T09:00:00Z"}),
        );
    }
    // apps[7]: two named users fail, and three failure rows carry no user name: those never count.
    // Still a service.
    for who in ["gone", "typo"] {
        app_signin(
            &case,
            T1,
            &format!("{who}@contoso.example"),
            "203.0.113.2",
            &apps[7],
            "02",
            true,
            Some(50126),
        );
    }
    for _ in 0..3 {
        insert_row(
            &case,
            "signins",
            T1,
            json!({"ip": "203.0.113.2", "app_id": &apps[7], "error_code": 50126,
                   "is_interactive": true, "event_time": "2026-02-02T09:00:00Z"}),
        );
    }
    assert_eq!(cloud(&case), 6);
    let mut want = vec![
        apps[0].clone(),
        apps[1].clone(),
        apps[3].clone(),
        apps[4].clone(),
        apps[5].clone(),
        apps[7].clone(),
    ];
    want.sort();
    assert_eq!(service_apps(&case), want);
}

/// (a) Sprayed users (a credential failure from a spray source) disqualify the pair when they make up
/// at least 20% of its users or when at least three of them are sprayed. A lone sprayed user among
/// many (a real tenant's connector) does not. Each application has users of its own (`a{k}u{n}`), so
/// "sprayed" is judged per application; the sprays are separate sources.
#[test]
fn sprayed_users_disqualify_a_service_from_twenty_percent_or_three_users() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    intel(&case, T1, "203.0.113.1", 14061, true);
    // (users, sprayed users, a service?)
    let table: [(usize, usize, bool); 7] = [
        (20, 1, true),  // 5%
        (6, 1, true),   // 16.7%
        (5, 1, false),  // exactly 20%
        (10, 2, false), // exactly 20%
        (11, 2, true),  // 18.2%, two sprayed
        (20, 3, false), // 15%, but three sprayed
        (40, 2, true),  // 5%
    ];
    let mut want = Vec::new();
    for (k, (users, sprayed, ok)) in table.into_iter().enumerate() {
        let app = format!("c0c0c0c0-0000-4000-8000-0000000001d{k}");
        for day in ["03", "04", "05"] {
            for u in 0..users {
                app_signin(
                    &case,
                    T1,
                    &format!("a{k}u{u}@contoso.example"),
                    "203.0.113.1",
                    &app,
                    day,
                    true,
                    Some(0),
                );
            }
        }
        // A spray source of its own fails the first `sprayed` users and six others, from an ordinary
        // address, and never sees them succeed.
        let ip = format!("198.51.100.{}", 100 + k);
        for u in 0..sprayed {
            signin(
                &case,
                T1,
                &format!("a{k}u{u}@contoso.example"),
                &ip,
                50126,
                "2026-03-01T10:00:00Z",
            );
        }
        for v in 0..(6 - sprayed.min(5)) {
            signin(
                &case,
                T1,
                &format!("v{k}x{v}@contoso.example"),
                &ip,
                50126,
                "2026-03-01T10:00:00Z",
            );
        }
        if ok {
            want.push(app);
        }
    }
    assert_eq!(
        rebuild(&case),
        7,
        "every spray is a source (six or more failed users each)"
    );
    cloud(&case);
    want.sort();
    assert_eq!(service_apps(&case), want);
    assert_eq!(want.len(), 4, "the table must exercise both outcomes");
}
