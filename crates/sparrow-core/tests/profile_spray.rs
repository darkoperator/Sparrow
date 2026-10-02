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
    // The new columns: 198.51.100.5 has five failed-only users (u0 also succeeded) and one success user.
    let mut st = case
        .conn()
        .prepare("SELECT ip, failed_only_users, success_users FROM spray_sources ORDER BY ip")
        .unwrap();
    let cols: Vec<(String, i64, i64)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        cols,
        vec![
            ("198.51.100.1".to_string(), 5, 0),
            ("198.51.100.5".to_string(), 5, 1)
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

fn services(case: &Case) -> Vec<(String, String, i64, i64)> {
    let mut st = case
        .conn()
        .prepare(
            "SELECT tenant_key, app_id, asn, established_day FROM cloud_services ORDER BY 1, 2, 3",
        )
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
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
    assert_eq!(
        sparrow_core::profile::cloud_services::rebuild(case.conn()).unwrap(),
        2
    );
    // Established at the end of the third day (2026-02-03): epoch day 20487, for ASN 14061.
    let day = 20487;
    assert_eq!(
        services(&case),
        vec![
            (T1.to_string(), svc.to_lowercase(), 14061, day),
            (T2.to_string(), svc.to_lowercase(), 14061, day),
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
    assert_eq!(
        sparrow_core::profile::cloud_services::rebuild(case.conn()).unwrap(),
        1
    );
    let rows = services(&case);
    assert_eq!(rows[0].2, 14061);
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
    assert_eq!(
        sparrow_core::profile::cloud_services::rebuild(case.conn()).unwrap(),
        0
    );
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
