//! The per-tenant spray-source relation (`spray_sources`): one definition every rule shares, and
//! the structural tenant scope that keeps a tenant's sources from another tenant's rules.

#[path = "common/detect.rs"]
mod detect;

use detect::{insert_row, run};
use serde_json::json;
use sparrow_core::Case;
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

fn signin(case: &Case, t: &str, upn: &str, ip: &str, code: i64, time: &str) {
    insert_row(
        case,
        "signins",
        t,
        json!({"user_upn": upn, "ip": ip, "error_code": code, "event_time": time}),
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
fn a_source_fails_against_five_users_and_is_not_regular_egress() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    // Five users failing: a source; four: not. No ip_intel row exists for any address.
    spray(&case, T1, "198.51.100.1", 5, 50126);
    spray(&case, T1, "198.51.100.2", 4, 50126);
    // Interrupts (an MFA prompt) are not failures, however many users see them.
    spray(&case, T1, "198.51.100.3", 8, 50074);
    // The office NAT: several users mistype a password on ordinary days, and the same address is
    // where at least five users signed in successfully on three distinct days.
    spray(&case, T1, "198.51.100.4", 6, 50126);
    for day in ["01", "02", "03"] {
        for u in 0..5 {
            signin(
                &case,
                T1,
                &format!("u{u}@contoso.example"),
                "198.51.100.4",
                0,
                &format!("2026-02-{day}T09:00:00Z"),
            );
        }
    }
    // An address that also signs one user in successfully is still a source.
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
    assert_eq!(spray::rebuild(case.conn()).unwrap(), 2);
    assert_eq!(
        sources(&case),
        vec![
            (T1.to_string(), "198.51.100.1".to_string(), 5, 5),
            (T1.to_string(), "198.51.100.5".to_string(), 6, 6),
        ]
    );
    // A rebuild replaces, never appends.
    spray::rebuild(case.conn()).unwrap();
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
    spray::rebuild(case.conn()).unwrap();
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

/// An unknown result (NULL error_code) is never a failure and never excuses a source as regular
/// egress: the exemption needs KNOWN successes.
#[test]
fn unknown_results_neither_fail_nor_excuse() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    spray(&case, T1, "198.51.100.7", 6, 50126);
    for day in ["01", "02", "03"] {
        for u in 0..5 {
            insert_row(
                &case,
                "signins",
                T1,
                json!({"user_upn": format!("u{u}@contoso.example"), "ip": "198.51.100.7",
                       "event_time": format!("2026-02-{day}T09:00:00Z")}),
            );
        }
    }
    assert_eq!(spray::rebuild(case.conn()).unwrap(), 1);
    assert_eq!(sources(&case)[0].1, "198.51.100.7");
}

fn app_signin(case: &Case, t: &str, upn: &str, ip: &str, app: &str, day: &str, code: Option<i64>) {
    let mut row = json!({"user_upn": upn, "ip": ip, "app_id": app,
                         "event_time": format!("2026-02-{day}T09:00:00Z")});
    if let Some(c) = code {
        row["error_code"] = json!(c);
    }
    insert_row(case, "signins", t, row);
}

fn services(case: &Case) -> Vec<(String, String)> {
    let mut st = case
        .conn()
        .prepare("SELECT tenant_key, app_id FROM cloud_services ORDER BY 1, 2")
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// A tenant-wide cloud service: at least 5 users on at least 3 days from hosting ASNs, and the
/// hosting sign-ins are at least 80% of the application's successful sign-ins. Per tenant: the same
/// application is judged on each tenant's own sign-ins.
#[test]
fn a_cloud_service_is_five_users_three_days_and_eighty_percent_hosting() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1);
    tenant(&case, T2);
    insert_row(
        &case,
        "ip_intel",
        T1,
        json!({"ip": "203.0.113.1", "asn": 14061, "is_hosting": true, "is_microsoft": false,
               "is_private": false}),
    );
    insert_row(
        &case,
        "ip_intel",
        T1,
        json!({"ip": "198.51.100.5", "asn": 7922, "is_hosting": false, "is_microsoft": false,
               "is_private": false}),
    );
    let svc = "C0C0C0C0-0000-4000-8000-0000000000C1";
    let (four, two, mixed, unknown) = (
        "c0c0c0c0-0000-4000-8000-0000000000c2",
        "c0c0c0c0-0000-4000-8000-0000000000c3",
        "c0c0c0c0-0000-4000-8000-0000000000c4",
        "c0c0c0c0-0000-4000-8000-0000000000c5",
    );
    for day in ["01", "02", "03"] {
        for u in 0..6 {
            let upn = format!("u{u}@contoso.example");
            // The service, in both tenants (an upper-case id is stored lower-case).
            app_signin(&case, T1, &upn, "203.0.113.1", svc, day, Some(0));
            app_signin(&case, T2, &upn, "203.0.113.1", svc, day, Some(0));
            // Only four users: not a service.
            if u < 4 {
                app_signin(&case, T1, &upn, "203.0.113.1", four, day, Some(0));
            }
            // Only two days: not a service.
            if day != "03" {
                app_signin(&case, T1, &upn, "203.0.113.1", two, day, Some(0));
            }
            // One hosting sign-in against three from an ordinary ISP: below 80%.
            app_signin(&case, T1, &upn, "203.0.113.1", mixed, day, Some(0));
            for _ in 0..3 {
                app_signin(&case, T1, &upn, "198.51.100.5", mixed, day, Some(0));
            }
            // An unknown result is never a known success.
            app_signin(&case, T1, &upn, "203.0.113.1", unknown, day, None);
        }
    }
    assert_eq!(
        sparrow_core::profile::cloud_services::rebuild(case.conn()).unwrap(),
        2
    );
    assert_eq!(
        services(&case),
        vec![
            (T1.to_string(), svc.to_lowercase()),
            (T2.to_string(), svc.to_lowercase()),
        ]
    );
}
