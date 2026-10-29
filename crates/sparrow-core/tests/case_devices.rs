//! Device containment (`case::devices`): the malicious-IP set, device sightings, suspect devices and their
//! lifecycle. Every case is built in the stored shape of its tables (sign-ins by the Graph/portal parsers, UAL
//! `audit_data` as the raw record) and detected with test rules under the real rule ids.

#[path = "common/detect.rs"]
mod detect;

use chrono::{DateTime, TimeZone, Utc};
use detect::{insert_row, insert_ual};
use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::case::actor::Actor;
use sparrow_core::case::devices::{self, SuspectReason};
use sparrow_core::case::indicators::{IndicatorType, Verdict, add_indicator, remove_indicator};
use sparrow_core::case::write::{FindingStatus, set_finding_status};
use sparrow_core::detect::load::{LoadedRule, RuleSet, rule_sha256};
use sparrow_core::detect::rule::Rule;
use sparrow_core::detect::run::{DetectOptions, run};
use std::collections::BTreeMap;

const T1: &str = "t1";
const ALICE: &str = "alice@contoso.example";
const BOB: &str = "bob@contoso.example";

const DEV_A: &str = "aaaaaaaa-0000-0000-0000-00000000000a";
const DEV_A_UPPER: &str = "AAAAAAAA-0000-0000-0000-00000000000A";

const IP_IOC: &str = "203.0.113.5";
const IP_HOST: &str = "198.51.100.7";
const IP_TRAVEL: &str = "192.0.2.44";

fn at(day: u32, h: u32, m: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, day, h, m, 0).unwrap()
}

fn iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339()
}

fn analyst() -> Actor {
    Actor::analyst("tester").unwrap()
}

fn rule_from(id: &str, body: &str) -> LoadedRule {
    let text = format!(
        "id: {id}\ntitle: title of {id}\nversion: 1\nstatus: experimental\nseverity: medium\nanalyst_guidance: g\n{body}\ntests:\n  - name: p\n    records: []\n    expect_hits: 1\n  - name: n\n    records: []\n    expect_hits: 0\n"
    );
    let rule: Rule = serde_norway::from_str(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
    let sha256 = rule_sha256(&rule, &BTreeMap::new(), &BTreeMap::new());
    LoadedRule {
        path: format!("test:{id}"),
        sha256,
        rule,
    }
}

/// A sign-in rule under a real rule id: it flags the sign-ins whose `app_name` is `app`.
fn signin_rule(id: &str, app: &str) -> LoadedRule {
    rule_from(
        id,
        &format!(
            "stage: suspicious_sign_in\nsql: |\n  SELECT s.record_key, 'signins' AS source_table, s.event_time, s.user_upn AS actor_upn, s.ip AS ip,\n         CAST(NULL AS JSON) AS context\n  FROM signins s WHERE s.app_name = '{app}'\ngroup_by: [actor_upn]"
        ),
    )
}

fn rules() -> RuleSet {
    RuleSet {
        rules: vec![
            signin_rule("SPW-ID-002", "HostingApp"),
            signin_rule("SPW-ID-003", "TravelApp"),
        ],
        lists: BTreeMap::new(),
        list_meta: BTreeMap::new(),
        warnings: vec![],
    }
}

fn detect_all(case: &mut Case) {
    let opts = DetectOptions {
        now: Some(at(28, 12, 0)),
        ..DetectOptions::default()
    };
    run(case, &rules(), &opts).unwrap();
}

fn tenant(case: &Case, key: &str, domain: &str) {
    insert_row(case, "tenant", key, json!({"tenant_key": key}));
    detect::collection_of(case, key);
    insert_row(
        case,
        "tenant_domains",
        key,
        json!({"tenant_key": key, "domain": domain, "source": "derived_upn", "rows_seen": 1}),
    );
}

fn device_struct(id: Option<&str>, name: Option<&str>) -> Value {
    json!({"device_id": id, "display_name": name, "os": null, "browser": null,
           "is_compliant": null, "is_managed": null, "trust_type": null})
}

/// A sign-in as the parsers store it (`device` is the struct; `ip` and `app_name` plain columns).
fn signin(
    case: &Case,
    t: &str,
    upn: &str,
    ip: &str,
    when: DateTime<Utc>,
    app: &str,
    device: Value,
) -> String {
    let key = format!(
        "si-{}",
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    insert_row(
        case,
        "signins",
        t,
        json!({"record_key": key, "user_upn": upn, "ip": ip, "event_time": iso(when),
               "error_code": 0, "event_type": "interactive", "is_interactive": true,
               "app_name": app, "device": device}),
    );
    key
}

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A UAL record, `audit_data` the raw record JSON. Returns its `record_id`.
fn ual(
    case: &Case,
    t: &str,
    operation: &str,
    upn: &str,
    ip: Option<&str>,
    when: DateTime<Utc>,
    audit_data: Value,
) -> String {
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id = format!("00000000-0000-4000-8000-{n:012x}");
    insert_ual(
        case,
        t,
        json!({"record_id": id, "event_time": iso(when), "workload": "AzureActiveDirectory",
               "operation": operation, "user_upn": upn, "client_ip": ip, "audit_data": audit_data}),
    );
    id
}

/// `DeviceProperties` as UAL stores it: a Name/Value array.
fn device_props(id: &str, name: &str) -> Value {
    json!([{"Name": "Id", "Value": id}, {"Name": "DisplayName", "Value": name},
           {"Name": "OS", "Value": "Windows10"}, {"Name": "TrustType", "Value": "0"}])
}

fn finding_id(case: &Case, rule: &str, actor: &str) -> String {
    case.conn()
        .query_row(
            "SELECT finding_id FROM findings WHERE rule_id = ? AND lower(actor_upn) = ?",
            [rule, actor],
            |r| r.get(0),
        )
        .unwrap_or_else(|e| panic!("no finding {rule} for {actor}: {e}"))
}

/// An indicator (IOC), a hosting-network sign-in finding (Alice) and a travel-leg finding (Bob).
fn malicious_case() -> Case {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1, "contoso.example");
    signin(
        &case,
        T1,
        ALICE,
        IP_HOST,
        at(1, 8, 0),
        "HostingApp",
        device_struct(None, None),
    );
    signin(
        &case,
        T1,
        BOB,
        IP_TRAVEL,
        at(2, 8, 0),
        "TravelApp",
        device_struct(None, None),
    );
    // A clean sign-in that no rule flags.
    signin(
        &case,
        T1,
        ALICE,
        "192.0.2.9",
        at(3, 8, 0),
        "Office 365",
        device_struct(None, None),
    );
    add_indicator(
        case.conn(),
        &analyst(),
        Some(T1),
        IndicatorType::Ip,
        IP_IOC,
        Verdict::Malicious,
        None,
    )
    .unwrap();
    detect_all(&mut case);
    case
}

#[test]
fn indicator_and_finding_ips_are_malicious() {
    let case = malicious_case();
    let map = devices::malicious_ips(case.conn(), None).unwrap();
    assert_eq!(
        map.keys().map(String::as_str).collect::<Vec<_>>(),
        [IP_TRAVEL, IP_HOST, IP_IOC]
    );
    assert_eq!(
        map[IP_IOC],
        [SuspectReason::Indicator {
            ip: IP_IOC.into(),
            verdict: "malicious".into()
        }]
    );
    assert_eq!(
        map[IP_HOST],
        [SuspectReason::Finding {
            ip: IP_HOST.into(),
            finding_id: finding_id(&case, "SPW-ID-002", ALICE),
            rule_id: "SPW-ID-002".into()
        }]
    );
    assert_eq!(
        map[IP_TRAVEL],
        [SuspectReason::TravelLeg {
            ip: IP_TRAVEL.into(),
            finding_id: finding_id(&case, "SPW-ID-003", BOB)
        }]
    );
    // A tenant filter keeps this tenant's rows (the indicator is tenant-scoped to T1); another tenant gets none.
    assert_eq!(
        devices::malicious_ips(case.conn(), Some(T1)).unwrap().len(),
        3
    );
    assert!(
        devices::malicious_ips(case.conn(), Some("t2"))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn false_positive_and_removed_indicator_do_not_count() {
    let case = malicious_case();
    assert_eq!(devices::malicious_ips(case.conn(), None).unwrap().len(), 3);
    for (rule, who) in [("SPW-ID-002", ALICE), ("SPW-ID-003", BOB)] {
        set_finding_status(
            case.conn(),
            &analyst(),
            &finding_id(&case, rule, who),
            FindingStatus::FalsePositive,
            Some("expected traffic"),
        )
        .unwrap();
    }
    let left = devices::malicious_ips(case.conn(), None).unwrap();
    assert_eq!(
        left.keys().map(String::as_str).collect::<Vec<_>>(),
        [IP_IOC]
    );
    let id: String = case
        .conn()
        .query_row("SELECT indicator_id FROM case_indicators", [], |r| r.get(0))
        .unwrap();
    assert!(remove_indicator(case.conn(), &analyst(), &id).unwrap());
    assert!(
        devices::malicious_ips(case.conn(), None)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn sightings_from_signins_and_ual() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1, "contoso.example");
    let si = signin(
        &case,
        T1,
        ALICE,
        IP_HOST,
        at(1, 8, 0),
        "Office 365",
        device_struct(Some(DEV_A_UPPER), None),
    );
    let ual_id = ual(
        &case,
        T1,
        "UserLoggedIn",
        ALICE,
        Some("192.0.2.9"),
        at(2, 9, 0),
        json!({"Operation": "UserLoggedIn", "DeviceProperties": device_props(DEV_A, "Workstation")}),
    );
    let got = devices::device_sightings(case.conn(), None).unwrap();
    assert_eq!(got.len(), 2, "{got:?}");
    assert!(got.iter().all(|s| s.device_id == DEV_A));
    assert!(got.iter().all(|s| s.tenant_key.as_deref() == Some(T1)));
    let s_si = got.iter().find(|s| s.source_table == "signins").unwrap();
    assert_eq!(s_si.record_key, si);
    assert_eq!(s_si.ip.as_deref(), Some(IP_HOST));
    assert_eq!(s_si.user_upn.as_deref(), Some(ALICE));
    assert_eq!(s_si.event_time, Some(at(1, 8, 0)));
    assert_eq!(s_si.activity, "Office 365");
    let s_ual = got.iter().find(|s| s.source_table == "ual_events").unwrap();
    assert_eq!(s_ual.record_key, ual_id);
    assert_eq!(s_ual.display_name.as_deref(), Some("Workstation"));
    assert_eq!(s_ual.os.as_deref(), Some("Windows10"));
    assert_eq!(s_ual.trust_type.as_deref(), Some("0"));
    assert_eq!(s_ual.activity, "UserLoggedIn");
    assert_eq!(s_ual.ip.as_deref(), Some("192.0.2.9"));
    // Another tenant filter sees nothing.
    assert!(
        devices::device_sightings(case.conn(), Some("t2"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        devices::device_sightings(case.conn(), Some(T1))
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn ual_device_properties_tolerates_missing_id() {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1, "contoso.example");
    let zero = "00000000-0000-0000-0000-000000000000";
    let shapes = [
        // Name/Value array with no Id.
        json!({"DeviceProperties": [{"Name": "DisplayName", "Value": "Workstation"}]}),
        // An empty Id.
        json!({"DeviceProperties": [{"Name": "Id", "Value": ""}]}),
        // DeviceProperties as an object, not an array.
        json!({"DeviceProperties": {"Id": DEV_A, "DisplayName": "Workstation"}}),
        // The all-zero GUID.
        json!({"DeviceProperties": device_props(zero, "Workstation")}),
        // The synth shape: OS and BrowserType only.
        json!({"DeviceProperties": [{"Name": "OS", "Value": "Windows10"}, {"Name": "BrowserType", "Value": "Edge"}]}),
        // Elements that are not Name/Value objects, and a scalar.
        json!({"DeviceProperties": ["x", 3, null]}),
        json!({"DeviceProperties": "none"}),
        // No DeviceProperties at all.
        json!({"Operation": "UserLoggedIn"}),
    ];
    for (i, shape) in shapes.iter().enumerate() {
        ual(
            &case,
            T1,
            "UserLoggedIn",
            ALICE,
            Some(IP_HOST),
            at(1, 8, i as u32),
            shape.clone(),
        );
    }
    // A record from another workload is not read, even when it carries a good DeviceProperties.
    insert_ual(
        &case,
        T1,
        json!({"workload": "Exchange", "operation": "MailItemsAccessed", "event_time": iso(at(2, 8, 0)),
               "audit_data": {"DeviceProperties": device_props(DEV_A, "Workstation")}}),
    );
    let got = devices::device_sightings(case.conn(), None).unwrap();
    assert!(got.is_empty(), "{got:?}");
}

// ---- Task 3: suspect devices -------------------------------------------------------------------------------------

use sparrow_core::case::devices::{Confidence, SuspectDevice};

const T2: &str = "t2";
const DEV_D: &str = "dddddddd-0000-0000-0000-00000000000d";
const DEV_E: &str = "eeeeeeee-0000-0000-0000-00000000000e";
const DEV_F: &str = "ffffffff-0000-0000-0000-00000000000f";
const DEV_T: &str = "77777777-0000-0000-0000-000000000007";
const IP_CLEAN: &str = "192.0.2.9";

/// Device `id` signs in from the hosting network (flagged by SPW-ID-002) as `upn`.
fn flagged_signin(case: &Case, t: &str, upn: &str, id: &str, when: DateTime<Utc>) {
    signin(
        case,
        t,
        upn,
        IP_HOST,
        when,
        "HostingApp",
        device_struct(Some(id), None),
    );
}

/// A UAL sign-in of device `id` named `name`, from `ip`.
fn named_sighting(
    case: &Case,
    t: &str,
    upn: &str,
    id: &str,
    name: &str,
    ip: &str,
    when: DateTime<Utc>,
) {
    ual(
        case,
        t,
        "UserLoggedIn",
        upn,
        Some(ip),
        when,
        json!({"Operation": "UserLoggedIn", "DeviceProperties": device_props(id, name)}),
    );
}

fn t1_case() -> Case {
    let case = Case::in_memory().unwrap();
    tenant(&case, T1, "contoso.example");
    case
}

fn suspects(case: &mut Case) -> Vec<SuspectDevice> {
    detect_all(case);
    devices::suspect_devices(case.conn(), None).unwrap()
}

fn ids(list: &[SuspectDevice]) -> Vec<&str> {
    list.iter().map(|d| d.device_id.as_str()).collect()
}

fn sorted_ids(list: &[SuspectDevice]) -> Vec<&str> {
    let mut v = ids(list);
    v.sort();
    v
}

#[test]
fn all_sightings_of_a_suspect_device_are_collected() {
    let mut case = t1_case();
    flagged_signin(&case, T1, ALICE, DEV_D, at(1, 8, 0));
    named_sighting(
        &case,
        T1,
        ALICE,
        DEV_D,
        "Workstation",
        IP_CLEAN,
        at(5, 9, 0),
    );
    // Device E is only ever seen from the clean address D also used: it must not be pulled in.
    named_sighting(&case, T1, BOB, DEV_E, "Laptop", IP_CLEAN, at(6, 9, 0));
    insert_row(
        &case,
        "ip_intel",
        T1,
        json!({"ip": IP_CLEAN, "asn": 64500, "asn_org": "Contoso ISP", "country_iso": "US", "is_hosting": false}),
    );
    let list = suspects(&mut case);
    // other_ips_do_not_pull_in_more_devices: E is not listed.
    assert_eq!(ids(&list), [DEV_D]);
    let d = &list[0];
    assert_eq!(d.tenant_key.as_deref(), Some(T1));
    assert_eq!(d.sightings.len(), 2);
    assert_eq!(
        d.sightings.iter().map(|s| s.event_time).collect::<Vec<_>>(),
        [Some(at(1, 8, 0)), Some(at(5, 9, 0))]
    );
    assert_eq!(d.sightings[0].source_table, "signins");
    assert_eq!(d.sightings[1].source_table, "ual_events");
    assert_eq!(d.malicious_ips, [IP_HOST]);
    assert_eq!(d.other_ips.len(), 1);
    let other = &d.other_ips[0];
    assert_eq!(other.ip, IP_CLEAN);
    assert_eq!(other.asn, Some(64500));
    assert_eq!(other.asn_org.as_deref(), Some("Contoso ISP"));
    assert_eq!(other.country_iso.as_deref(), Some("US"));
    assert_eq!(other.is_hosting, Some(false));
    assert_eq!(d.confidence, Confidence::High);
    assert_eq!(d.users, [ALICE]);
    assert_eq!(d.display_name.as_deref(), Some("Workstation"));
    assert_eq!(d.os.as_deref(), Some("Windows10"));
    assert_eq!(d.trust_type.as_deref(), Some("0"));
    assert_eq!(d.reasons.len(), 1);
    assert!(
        matches!(&d.reasons[0], SuspectReason::Finding { ip, rule_id, .. } if ip == IP_HOST && rule_id == "SPW-ID-002")
    );
}

#[test]
fn same_name_same_user_is_suspect() {
    let mut case = t1_case();
    flagged_signin(&case, T1, ALICE, DEV_D, at(1, 8, 0));
    named_sighting(
        &case,
        T1,
        ALICE,
        DEV_D,
        "Workstation",
        IP_CLEAN,
        at(2, 8, 0),
    );
    // F: same name (any case), same user, a clean address.
    named_sighting(
        &case,
        T1,
        ALICE,
        DEV_F,
        "WORKSTATION",
        "192.0.2.10",
        at(3, 8, 0),
    );
    // E: same user, another name: not linked.
    named_sighting(&case, T1, ALICE, DEV_E, "Laptop", "192.0.2.11", at(4, 8, 0));
    let list = suspects(&mut case);
    // Order is by last activity (F is the newer); the set is what matters here.
    assert_eq!(sorted_ids(&list), [DEV_D, DEV_F]);
    let f = list.iter().find(|d| d.device_id == DEV_F).unwrap();
    assert!(f.malicious_ips.is_empty());
    assert_eq!(
        f.reasons,
        [SuspectReason::SameName {
            name: "Workstation".into(),
            of_device_id: DEV_D.into()
        }]
    );
    assert_eq!(f.confidence, Confidence::High);
    assert_eq!(f.sightings.len(), 1);
}

/// D is a suspect "Workstation" of Alice's; `n` other users each have their own "Workstation".
fn with_namesakes(n: usize) -> Vec<SuspectDevice> {
    let mut case = t1_case();
    flagged_signin(&case, T1, ALICE, DEV_D, at(1, 8, 0));
    named_sighting(
        &case,
        T1,
        ALICE,
        DEV_D,
        "Workstation",
        IP_CLEAN,
        at(2, 8, 0),
    );
    for i in 0..n {
        named_sighting(
            &case,
            T1,
            &format!("user{i}@contoso.example"),
            &format!("{:08x}-0000-0000-0000-000000000099", 0x1000 + i),
            "Workstation",
            "192.0.2.12",
            at(3, 8, i as u32),
        );
    }
    suspects(&mut case)
}

#[test]
fn same_name_tenant_wide_respects_threshold() {
    assert_eq!(devices::SAME_NAME_TENANT_MAX, 3);
    // 4 other-user "Workstation"s (5 carry the name): none is added.
    assert_eq!(ids(&with_namesakes(4)), [DEV_D]);
    // 3 others make 4 carriers, over the limit of 3 distinct device ids (the suspect one counts).
    assert_eq!(ids(&with_namesakes(3)), [DEV_D]);
    // 2 others make 3 carriers: both are added, as SameName of D.
    let list = with_namesakes(2);
    assert_eq!(list.len(), 3, "{:?}", ids(&list));
    assert!(list.iter().any(|d| d.device_id == DEV_D));
    for d in list.iter().filter(|d| d.device_id != DEV_D) {
        assert!(d.malicious_ips.is_empty());
        assert_eq!(
            d.reasons,
            [SuspectReason::SameName {
                name: "Workstation".into(),
                of_device_id: DEV_D.into()
            }]
        );
        assert_eq!(d.users.len(), 1);
    }
}

#[test]
fn travel_leg_only_is_low_confidence() {
    let mut case = t1_case();
    // T is seen only on an impossible-travel leg; D (later in time) on the hosting network.
    signin(
        &case,
        T1,
        BOB,
        IP_TRAVEL,
        at(1, 8, 0),
        "TravelApp",
        device_struct(Some(DEV_T), None),
    );
    flagged_signin(&case, T1, ALICE, DEV_D, at(2, 8, 0));
    let list = suspects(&mut case);
    assert_eq!(ids(&list), [DEV_D, DEV_T]);
    assert_eq!(list[0].confidence, Confidence::High);
    let t = &list[1];
    assert_eq!(t.confidence, Confidence::Low);
    assert_eq!(t.malicious_ips, [IP_TRAVEL]);
    assert!(
        matches!(t.reasons.as_slice(), [SuspectReason::TravelLeg { ip, .. }] if ip == IP_TRAVEL)
    );
    // A device on both a travel leg and a hosting IP is High.
    signin(
        &case,
        T1,
        BOB,
        IP_TRAVEL,
        at(3, 8, 0),
        "TravelApp",
        device_struct(Some(DEV_D), None),
    );
    let list = devices::suspect_devices(case.conn(), None).unwrap();
    assert_eq!(ids(&list), [DEV_D, DEV_T]);
    assert_eq!(list[0].confidence, Confidence::High);
    assert_eq!(list[0].reasons.len(), 2);
}

#[test]
fn tenants_do_not_merge() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1, "contoso.example");
    tenant(&case, T2, "other.example");
    flagged_signin(&case, T1, ALICE, DEV_D, at(1, 8, 0));
    flagged_signin(&case, T2, "dave@other.example", DEV_D, at(2, 8, 0));
    let list = suspects(&mut case);
    assert_eq!(list.len(), 2);
    let mut tenants: Vec<_> = list.iter().map(|d| d.tenant_key.clone().unwrap()).collect();
    tenants.sort();
    assert_eq!(tenants, [T1, T2]);
    assert!(
        list.iter()
            .all(|d| d.sightings.len() == 1 && d.device_id == DEV_D)
    );
    let one = devices::suspect_devices(case.conn(), Some(T2)).unwrap();
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].tenant_key.as_deref(), Some(T2));
    assert_eq!(one[0].users, ["dave@other.example"]);
}

#[test]
fn inventory_row_overrides_sighting_attributes() {
    let mut case = t1_case();
    flagged_signin(&case, T1, ALICE, DEV_D, at(1, 8, 0));
    named_sighting(
        &case,
        T1,
        ALICE,
        DEV_D,
        "Workstation",
        IP_CLEAN,
        at(2, 8, 0),
    );
    insert_row(
        &case,
        "devices",
        T1,
        json!({"device_id": DEV_D, "object_id": "0b1b2b3b-0000-0000-0000-000000000001", "display_name": "Inventory Name",
               "os": "Windows 11", "trust_type": "AzureAd", "is_compliant": true, "is_managed": false,
               "collected_at": iso(at(10, 0, 0))}),
    );
    let list = suspects(&mut case);
    assert_eq!(ids(&list), [DEV_D]);
    let d = &list[0];
    assert_eq!(d.display_name.as_deref(), Some("Inventory Name"));
    assert_eq!(d.os.as_deref(), Some("Windows 11"));
    assert_eq!(d.trust_type.as_deref(), Some("AzureAd"));
    assert_eq!(
        d.object_id.as_deref(),
        Some("0b1b2b3b-0000-0000-0000-000000000001")
    );
    assert_eq!((d.is_compliant, d.is_managed), (Some(true), Some(false)));
}

// ---- Task 4: lifecycle and status ---------------------------------------------------------------------------------

use sparrow_core::case::devices::DeviceStatus;

const OID: &str = "0b1b2b3b-0000-0000-0000-0000000000a1";
const ADMIN: &str = "admin@contoso.example";

/// A device-management UAL record. `props` are `ModifiedProperties` as `(name, new value)`; `targets` are the
/// `Target` IDs. The values keep the CR/LF-wrapped array text the audit log writes.
fn device_event(
    case: &Case,
    op: &str,
    when: DateTime<Utc>,
    props: &[(&str, &str)],
    targets: &[&str],
) -> String {
    let props: Vec<Value> = props
        .iter()
        .map(|(n, v)| json!({"Name": n, "NewValue": format!("[\r\n  {v}\r\n]"), "OldValue": "[]"}))
        .collect();
    let targets: Vec<Value> = targets
        .iter()
        .map(|t| json!({"ID": t, "Type": 2}))
        .collect();
    ual(
        case,
        T1,
        op,
        ADMIN,
        Some("192.0.2.200"),
        when,
        json!({"Operation": op, "ModifiedProperties": props, "Target": targets}),
    )
}

fn quoted(id: &str) -> String {
    format!("\"{id}\"")
}

/// Device D flagged on the hosting network at 1 Mar 08:00; returns the sign-in's record key.
fn flagged_d(case: &Case) -> String {
    signin(
        case,
        T1,
        ALICE,
        IP_HOST,
        at(1, 8, 0),
        "HostingApp",
        device_struct(Some(DEV_D), None),
    )
}

fn only(list: &[SuspectDevice]) -> &SuspectDevice {
    assert_eq!(list.len(), 1, "{:?}", ids(list));
    &list[0]
}

fn new_collection(case: &Case, collected: DateTime<Utc>) -> i64 {
    detect::collection_of(case, T1);
    case.conn()
        .execute(
            "INSERT INTO collections (tool, root_path, sparrow_version, tenant_key, collected_at) \
             VALUES ('invictus', ?, 'test', ?, CAST(? AS TIMESTAMPTZ))",
            [
                &format!("/test/inv-{}", iso(collected)),
                T1,
                &iso(collected),
            ],
        )
        .unwrap();
    case.conn()
        .query_row("SELECT max(collection_id) FROM collections", [], |r| {
            r.get(0)
        })
        .unwrap()
}

fn inventory_row(case: &Case, collection: i64, collected: DateTime<Utc>, id: &str, extra: Value) {
    let mut row =
        json!({"device_id": id, "collection_id": collection, "collected_at": iso(collected)});
    for (k, v) in extra.as_object().unwrap() {
        row[k] = v.clone();
    }
    insert_row(case, "devices", T1, row);
}

#[test]
fn register_and_delete_via_modified_properties() {
    let mut case = t1_case();
    let si = flagged_d(&case);
    // Uppercase id inside the CR/LF-wrapped array, as the audit log writes it.
    let add = device_event(
        &case,
        "Add device.",
        at(1, 7, 0),
        &[("DeviceId", &quoted(&DEV_D.to_uppercase()))],
        &[],
    );
    let del = device_event(
        &case,
        "Delete device.",
        at(2, 9, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[],
    );
    let list = suspects(&mut case);
    let d = only(&list);
    let lc = &d.lifecycle;
    let reg = lc.registered.as_ref().expect("registered");
    assert_eq!(
        (reg.at, reg.source_table.as_str(), reg.record_key.as_str()),
        (at(1, 7, 0), "ual_events", add.as_str())
    );
    let rem = lc.removed.as_ref().expect("removed");
    assert_eq!(
        (rem.at, rem.source_table.as_str(), rem.record_key.as_str()),
        (at(2, 9, 0), "ual_events", del.as_str())
    );
    assert_eq!(lc.status, DeviceStatus::Removed);
    let last = lc.last_active.as_ref().unwrap();
    assert_eq!(
        (
            last.at,
            last.source_table.as_str(),
            last.record_key.as_str()
        ),
        (at(1, 8, 0), "signins", si.as_str())
    );
    assert!(lc.disabled.is_none());
}

#[test]
fn owner_event_resolves_through_object_id() {
    let mut case = t1_case();
    flagged_d(&case);
    // An update that carries both ids teaches the object id → device id map.
    device_event(
        &case,
        "Update device.",
        at(1, 7, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[&format!("Device_{OID}"), OID],
    );
    // An owner event carries only the object id and is not a registration.
    device_event(
        &case,
        "Add registered owner to device.",
        at(1, 7, 5),
        &[],
        &[&format!("Device_{OID}")],
    );
    // A delete carrying only the bare object id resolves through the map.
    let del = device_event(&case, "Delete device.", at(2, 9, 0), &[], &[OID]);
    // A delete of an object id nobody mapped is ignored.
    let stray = device_event(
        &case,
        "Delete device.",
        at(3, 9, 0),
        &[],
        &["99999999-0000-0000-0000-000000000099"],
    );
    let list = suspects(&mut case);
    let d = only(&list);
    assert!(d.lifecycle.registered.is_none());
    let rem = d
        .lifecycle
        .removed
        .as_ref()
        .expect("removed through the object id");
    assert_eq!(rem.record_key, del);
    assert_ne!(rem.record_key, stray);
    assert_eq!(d.lifecycle.status, DeviceStatus::Removed);
    assert_eq!(d.object_id.as_deref(), Some(OID));
}

#[test]
fn sighting_after_delete_is_active_after_removal() {
    let mut case = t1_case();
    flagged_d(&case);
    device_event(
        &case,
        "Delete device.",
        at(2, 9, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[],
    );
    // Device F: removed and never seen again.
    flagged_signin(&case, T1, BOB, DEV_F, at(1, 9, 0));
    device_event(
        &case,
        "Delete device.",
        at(2, 9, 0),
        &[("TargetId.DeviceId", &quoted(DEV_F))],
        &[],
    );
    // D comes back after its removal.
    let again = signin(
        &case,
        T1,
        ALICE,
        IP_CLEAN,
        at(3, 8, 0),
        "Office 365",
        device_struct(Some(DEV_D), None),
    );
    let list = suspects(&mut case);
    assert_eq!(ids(&list), [DEV_D, DEV_F]);
    assert_eq!(list[0].lifecycle.status, DeviceStatus::ActiveAfterRemoval);
    assert!(list[0].lifecycle.removed.is_some());
    assert_eq!(
        list[0].lifecycle.last_active.as_ref().unwrap().record_key,
        again
    );
    assert_eq!(list[1].lifecycle.status, DeviceStatus::Removed);
}

#[test]
fn disabled_then_reenabled_is_active() {
    let mut case = t1_case();
    flagged_d(&case);
    let off = device_event(
        &case,
        "Update device.",
        at(2, 9, 0),
        &[
            ("TargetId.DeviceId", &quoted(DEV_D)),
            ("AccountEnabled", "false"),
        ],
        &[],
    );
    let list = suspects(&mut case);
    let d = only(&list);
    assert_eq!(d.lifecycle.status, DeviceStatus::Disabled);
    assert_eq!(d.lifecycle.disabled.as_ref().unwrap().record_key, off);
    assert!(d.lifecycle.removed.is_none());
    // Enabled again later: no longer disabled.
    device_event(
        &case,
        "Update device.",
        at(2, 10, 0),
        &[
            ("TargetId.DeviceId", &quoted(DEV_D)),
            ("AccountEnabled", "true"),
        ],
        &[],
    );
    let list = devices::suspect_devices(case.conn(), None).unwrap();
    let d = only(&list);
    assert_ne!(d.lifecycle.status, DeviceStatus::Disabled);
    assert_eq!(d.lifecycle.status, DeviceStatus::Unknown);
    assert!(d.lifecycle.disabled.is_none());
    // A different case: disabled, then seen again, is not disabled either.
    let mut case = t1_case();
    flagged_d(&case);
    device_event(
        &case,
        "Update device.",
        at(2, 9, 0),
        &[
            ("TargetId.DeviceId", &quoted(DEV_D)),
            ("AccountEnabled", "false"),
        ],
        &[],
    );
    signin(
        &case,
        T1,
        ALICE,
        IP_CLEAN,
        at(2, 12, 0),
        "Office 365",
        device_struct(Some(DEV_D), None),
    );
    let list = suspects(&mut case);
    assert_eq!(only(&list).lifecycle.status, DeviceStatus::Unknown);
}

#[test]
fn absent_from_inventory_is_not_removed() {
    // The newest inventory is collected after D's last activity and does not list D.
    let mut case = t1_case();
    flagged_d(&case);
    let old = new_collection(&case, at(5, 0, 0));
    let new = new_collection(&case, at(10, 0, 0));
    inventory_row(&case, old, at(5, 0, 0), DEV_D, json!({}));
    inventory_row(&case, new, at(10, 0, 0), DEV_E, json!({}));
    let list = suspects(&mut case);
    let d = only(&list);
    assert_eq!(d.lifecycle.status, DeviceStatus::NotInLatestInventory);
    assert_eq!(d.lifecycle.latest_inventory_at, Some(at(10, 0, 0)));
    assert!(d.lifecycle.removed.is_none());

    // The newest inventory predates D's last activity: nothing can be said about D (it is in an older one).
    let mut case = t1_case();
    flagged_d(&case);
    let only_inv = new_collection(&case, at(1, 0, 0));
    inventory_row(&case, only_inv, at(1, 0, 0), DEV_E, json!({}));
    let list = suspects(&mut case);
    assert_eq!(only(&list).lifecycle.status, DeviceStatus::Unknown);
    assert_eq!(only(&list).lifecycle.latest_inventory_at, Some(at(1, 0, 0)));

    // Present in the newest inventory: active.
    let mut case = t1_case();
    flagged_d(&case);
    let inv = new_collection(&case, at(10, 0, 0));
    inventory_row(&case, inv, at(10, 0, 0), DEV_D, json!({}));
    let list = suspects(&mut case);
    assert_eq!(only(&list).lifecycle.status, DeviceStatus::Active);
}

#[test]
fn directory_audit_delete_counts() {
    let mut case = t1_case();
    flagged_d(&case);
    // The Graph shape the directory_audits parser stores: raw TargetResources and [{target, property, old, new}].
    insert_row(
        &case,
        "directory_audits",
        T1,
        json!({"record_key": "da-1", "event_time": iso(at(2, 9, 0)), "activity": "Delete device",
               "targets": [{"Id": OID, "DisplayName": "Workstation", "Type": "Device"}],
               "modified_properties": [{"target": "Workstation", "property": "TargetId.DeviceId",
                                        "old": null, "new": format!("[\r\n  \"{DEV_D}\"\r\n]")}]}),
    );
    let list = suspects(&mut case);
    let d = only(&list);
    assert_eq!(d.lifecycle.status, DeviceStatus::Removed);
    let rem = d.lifecycle.removed.as_ref().unwrap();
    assert_eq!(
        (rem.source_table.as_str(), rem.record_key.as_str(), rem.at),
        ("directory_audits", "da-1", at(2, 9, 0))
    );

    // An add recorded in directory_audits with only the object id resolves through the map built from it.
    let mut case = t1_case();
    flagged_d(&case);
    insert_row(
        &case,
        "directory_audits",
        T1,
        json!({"record_key": "da-add", "event_time": iso(at(1, 7, 0)), "activity": "Add device",
               "targets": [{"Id": OID, "DisplayName": "Workstation", "Type": "Device"}],
               "modified_properties": [{"target": "Workstation", "property": "DeviceId", "old": null, "new": quoted(DEV_D)}]}),
    );
    insert_row(
        &case,
        "directory_audits",
        T1,
        json!({"record_key": "da-del", "event_time": iso(at(2, 9, 0)), "activity": "Delete device.",
               "targets": [{"Id": OID, "DisplayName": "Workstation", "Type": "Device"}]}),
    );
    let list = suspects(&mut case);
    let d = only(&list);
    assert_eq!(
        d.lifecycle.registered.as_ref().unwrap().record_key,
        "da-add"
    );
    assert_eq!(d.lifecycle.removed.as_ref().unwrap().record_key, "da-del");
    assert_eq!(d.lifecycle.status, DeviceStatus::Removed);
}

#[test]
fn signin_only_device_is_unknown() {
    let mut case = t1_case();
    flagged_d(&case);
    let later = signin(
        &case,
        T1,
        ALICE,
        IP_HOST,
        at(4, 8, 0),
        "HostingApp",
        device_struct(Some(DEV_D), None),
    );
    let list = suspects(&mut case);
    let d = only(&list);
    let lc = &d.lifecycle;
    assert_eq!(lc.status, DeviceStatus::Unknown);
    let last = lc.last_active.as_ref().unwrap();
    assert_eq!(
        (last.at, last.record_key.as_str()),
        (at(4, 8, 0), later.as_str())
    );
    assert!(lc.registered.is_none() && lc.removed.is_none() && lc.disabled.is_none());
    assert!(lc.latest_inventory_at.is_none());
}

#[test]
fn name_and_time_never_match_events() {
    let mut case = t1_case();
    flagged_d(&case);
    named_sighting(
        &case,
        T1,
        ALICE,
        DEV_D,
        "Workstation",
        IP_CLEAN,
        at(1, 8, 0),
    );
    // E is a suspect too, with the same name, and is deleted and disabled in the same minute as D's sighting.
    flagged_signin(&case, T1, BOB, DEV_E, at(1, 8, 0));
    named_sighting(&case, T1, BOB, DEV_E, "Workstation", IP_CLEAN, at(1, 8, 0));
    device_event(
        &case,
        "Delete device.",
        at(1, 8, 0),
        &[("TargetId.DeviceId", &quoted(DEV_E))],
        &[],
    );
    device_event(
        &case,
        "Update device.",
        at(1, 8, 0),
        &[
            ("TargetId.DeviceId", &quoted(DEV_E)),
            ("AccountEnabled", "false"),
        ],
        &[],
    );
    let list = suspects(&mut case);
    assert_eq!(sorted_ids(&list), [DEV_D, DEV_E]);
    let d = list.iter().find(|d| d.device_id == DEV_D).unwrap();
    let e = list.iter().find(|d| d.device_id == DEV_E).unwrap();
    assert_eq!(e.lifecycle.status, DeviceStatus::Removed);
    assert!(e.lifecycle.disabled.is_some());
    assert_eq!(d.lifecycle.status, DeviceStatus::Unknown);
    assert!(
        d.lifecycle.removed.is_none()
            && d.lifecycle.disabled.is_none()
            && d.lifecycle.registered.is_none()
    );
}

#[test]
fn inventory_supplies_created_and_last_signin() {
    let mut case = t1_case();
    flagged_d(&case);
    let inv = new_collection(&case, at(10, 0, 0));
    inventory_row(
        &case,
        inv,
        at(10, 0, 0),
        DEV_D,
        json!({"object_id": OID, "created": iso(at(1, 0, 0)), "last_signin": iso(at(9, 6, 0))}),
    );
    // Disabled in the inventory itself.
    let list = suspects(&mut case);
    let d = only(&list);
    let reg = d.lifecycle.registered.as_ref().unwrap();
    assert_eq!(
        (reg.at, reg.source_table.as_str()),
        (at(1, 0, 0), "devices")
    );
    let last = d.lifecycle.last_active.as_ref().unwrap();
    assert_eq!(
        (last.at, last.source_table.as_str()),
        (at(9, 6, 0), "devices")
    );
    assert_eq!(d.lifecycle.status, DeviceStatus::Active);
    // The same row with enabled = false and nothing seen since: disabled.
    case.conn()
        .execute("UPDATE devices SET enabled = false", [])
        .unwrap();
    let list = devices::suspect_devices(case.conn(), None).unwrap();
    assert_eq!(only(&list).lifecycle.status, DeviceStatus::Disabled);
    assert_eq!(
        only(&list)
            .lifecycle
            .disabled
            .as_ref()
            .unwrap()
            .source_table,
        "devices"
    );
}

// ---- Round 1 fixes ------------------------------------------------------------------------------------------------

#[test]
fn evidence_of_one_tenant_does_not_flag_devices_of_another() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1, "contoso.example");
    tenant(&case, T2, "other.example");
    flagged_signin(&case, T1, ALICE, DEV_D, at(1, 8, 0));
    // The same address, unflagged, on a device of the other tenant.
    signin(
        &case,
        T2,
        "dave@other.example",
        IP_HOST,
        at(2, 8, 0),
        "Office 365",
        device_struct(Some(DEV_E), None),
    );
    let list = suspects(&mut case);
    assert_eq!(ids(&list), [DEV_D]);
    assert_eq!(list[0].tenant_key.as_deref(), Some(T1));
    // A tenantless indicator on that address applies to both tenants.
    add_indicator(
        case.conn(),
        &analyst(),
        None,
        IndicatorType::Ip,
        IP_HOST,
        Verdict::Malicious,
        None,
    )
    .unwrap();
    let list = devices::suspect_devices(case.conn(), None).unwrap();
    assert_eq!(sorted_ids(&list), [DEV_D, DEV_E]);
    let e = list.iter().find(|d| d.device_id == DEV_E).unwrap();
    assert_eq!(e.tenant_key.as_deref(), Some(T2));
    assert!(matches!(
        e.reasons.as_slice(),
        [SuspectReason::Indicator { .. }]
    ));
    // A tenant-scoped indicator stays in its tenant.
    let case = Case::in_memory().unwrap();
    tenant(&case, T1, "contoso.example");
    tenant(&case, T2, "other.example");
    signin(
        &case,
        T1,
        ALICE,
        IP_HOST,
        at(1, 8, 0),
        "Office 365",
        device_struct(Some(DEV_D), None),
    );
    signin(
        &case,
        T2,
        "dave@other.example",
        IP_HOST,
        at(2, 8, 0),
        "Office 365",
        device_struct(Some(DEV_E), None),
    );
    add_indicator(
        case.conn(),
        &analyst(),
        Some(T2),
        IndicatorType::Ip,
        IP_HOST,
        Verdict::Malicious,
        None,
    )
    .unwrap();
    let list = devices::suspect_devices(case.conn(), None).unwrap();
    assert_eq!(ids(&list), [DEV_E]);
}

#[test]
fn object_id_binds_only_to_the_device_target() {
    let mut case = t1_case();
    flagged_d(&case);
    flagged_signin(&case, T1, BOB, DEV_E, at(1, 9, 0));
    let oid_b = "0b1b2b3b-0000-0000-0000-0000000000b2";
    // An event for D that also lists another device's target: ambiguous, so it binds no object id.
    device_event(
        &case,
        "Update device.",
        at(1, 7, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[&format!("Device_{OID}"), &format!("Device_{oid_b}")],
    );
    // Object-id-only deletes of either id must not remove anything.
    device_event(&case, "Delete device.", at(2, 9, 0), &[], &[oid_b]);
    device_event(&case, "Delete device.", at(2, 9, 5), &[], &[OID]);
    let list = suspects(&mut case);
    assert_eq!(sorted_ids(&list), [DEV_D, DEV_E]);
    for d in &list {
        assert_eq!(d.lifecycle.status, DeviceStatus::Unknown, "{}", d.device_id);
        assert!(d.lifecycle.removed.is_none());
    }
    // The bare twin of the single Device_ target is the same id and resolves.
    let mut case = t1_case();
    flagged_d(&case);
    device_event(
        &case,
        "Update device.",
        at(1, 7, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[
            &format!("Device_{OID}"),
            OID,
            "99999999-0000-0000-0000-0000000000cc",
        ],
    );
    device_event(&case, "Delete device.", at(2, 9, 0), &[], &[OID]);
    assert_eq!(
        only(&suspects(&mut case)).lifecycle.status,
        DeviceStatus::Removed
    );
}

#[test]
fn conflicting_object_id_mapping_resolves_nothing() {
    let mut case = t1_case();
    flagged_d(&case);
    flagged_signin(&case, T1, BOB, DEV_E, at(1, 9, 0));
    // The same object id is bound to two different devices.
    device_event(
        &case,
        "Update device.",
        at(1, 7, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[&format!("Device_{OID}")],
    );
    device_event(
        &case,
        "Update device.",
        at(1, 7, 5),
        &[("TargetId.DeviceId", &quoted(DEV_E))],
        &[&format!("Device_{OID}")],
    );
    device_event(&case, "Delete device.", at(2, 9, 0), &[], &[OID]);
    let list = suspects(&mut case);
    assert_eq!(sorted_ids(&list), [DEV_D, DEV_E]);
    assert!(
        list.iter()
            .all(|d| d.lifecycle.removed.is_none() && d.lifecycle.status == DeviceStatus::Unknown)
    );
    // A conflict between an event and devices.object_id is dropped as well.
    let mut case = t1_case();
    flagged_d(&case);
    let inv = new_collection(&case, at(1, 1, 0));
    inventory_row(&case, inv, at(1, 1, 0), DEV_E, json!({"object_id": OID}));
    device_event(
        &case,
        "Update device.",
        at(1, 7, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[&format!("Device_{OID}")],
    );
    device_event(&case, "Delete device.", at(2, 9, 0), &[], &[OID]);
    let list = suspects(&mut case);
    assert!(only(&list).lifecycle.removed.is_none());
}

#[test]
fn enable_or_inventory_after_removal_is_active_after_removal() {
    let mut case = t1_case();
    flagged_d(&case);
    device_event(
        &case,
        "Delete device.",
        at(2, 9, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[],
    );
    let list = suspects(&mut case);
    assert_eq!(only(&list).lifecycle.status, DeviceStatus::Removed);
    device_event(
        &case,
        "Update device.",
        at(2, 10, 0),
        &[
            ("TargetId.DeviceId", &quoted(DEV_D)),
            ("AccountEnabled", "true"),
        ],
        &[],
    );
    let list = devices::suspect_devices(case.conn(), None).unwrap();
    assert_eq!(
        only(&list).lifecycle.status,
        DeviceStatus::ActiveAfterRemoval
    );
    assert!(only(&list).lifecycle.removed.is_some());
    // An inventory collected after the removal that lists the device.
    let mut case = t1_case();
    flagged_d(&case);
    device_event(
        &case,
        "Delete device.",
        at(2, 9, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[],
    );
    let inv = new_collection(&case, at(5, 0, 0));
    inventory_row(&case, inv, at(5, 0, 0), DEV_D, json!({}));
    assert_eq!(
        only(&suspects(&mut case)).lifecycle.status,
        DeviceStatus::ActiveAfterRemoval
    );
    // An inventory collected before the removal does not.
    let mut case = t1_case();
    flagged_d(&case);
    device_event(
        &case,
        "Delete device.",
        at(2, 9, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[],
    );
    let inv = new_collection(&case, at(1, 12, 0));
    inventory_row(&case, inv, at(1, 12, 0), DEV_D, json!({}));
    assert_eq!(
        only(&suspects(&mut case)).lifecycle.status,
        DeviceStatus::Removed
    );
}

#[test]
fn ual_device_properties_key_and_shape_variants() {
    let case = t1_case();
    let id = |n: u32| format!("{n:08x}-0000-0000-0000-000000000001");
    ual(
        &case,
        T1,
        "UserLoggedIn",
        ALICE,
        Some(IP_HOST),
        at(1, 8, 0),
        json!({"deviceproperties": [{"name": "id", "value": id(1)}, {"name": "displayname", "value": "Lower"}]}),
    );
    ual(
        &case,
        T1,
        "UserLoggedIn",
        ALICE,
        Some(IP_HOST),
        at(1, 8, 1),
        json!({"DEVICEPROPERTIES": [{"Name": "ID", "Value": id(2)}]}),
    );
    let text =
        json!([{"Name": "Id", "Value": id(3)}, {"Name": "DisplayName", "Value": "FromString"}])
            .to_string();
    ual(
        &case,
        T1,
        "UserLoggedIn",
        ALICE,
        Some(IP_HOST),
        at(1, 8, 2),
        json!({"DeviceProperties": text}),
    );
    let mut got = devices::device_sightings(case.conn(), None).unwrap();
    got.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    assert_eq!(
        got.iter().map(|s| s.device_id.clone()).collect::<Vec<_>>(),
        [id(1), id(2), id(3)]
    );
    assert_eq!(got[0].display_name.as_deref(), Some("Lower"));
    assert_eq!(got[2].display_name.as_deref(), Some("FromString"));
}

#[test]
fn untimed_malicious_sighting_still_lists_the_device() {
    let case = t1_case();
    add_indicator(
        case.conn(),
        &analyst(),
        Some(T1),
        IndicatorType::Ip,
        IP_HOST,
        Verdict::Malicious,
        None,
    )
    .unwrap();
    insert_row(
        &case,
        "signins",
        T1,
        json!({"record_key": "untimed-1", "user_upn": ALICE, "ip": IP_HOST, "event_time": null, "app_name": "Office 365",
               "device": device_struct(Some(DEV_D), None)}),
    );
    let list = devices::suspect_devices(case.conn(), None).unwrap();
    let d = only(&list);
    assert_eq!(d.sightings.len(), 1);
    assert_eq!(d.sightings[0].event_time, None);
    assert_eq!(d.malicious_ips, [IP_HOST]);
    assert!(d.lifecycle.last_active.is_none());
    // With a timed sighting too: last_active comes from it, and the untimed one sorts last.
    let later = signin(
        &case,
        T1,
        ALICE,
        IP_CLEAN,
        at(3, 8, 0),
        "Office 365",
        device_struct(Some(DEV_D), None),
    );
    let list = devices::suspect_devices(case.conn(), None).unwrap();
    let d = only(&list);
    assert_eq!(d.sightings.len(), 2);
    assert_eq!(d.sightings[0].record_key, later);
    assert_eq!(d.sightings[1].event_time, None);
    assert_eq!(d.lifecycle.last_active.as_ref().unwrap().record_key, later);
}

#[test]
fn id_less_event_naming_two_devices_resolves_nothing() {
    let mut case = t1_case();
    flagged_d(&case);
    flagged_signin(&case, T1, BOB, DEV_E, at(1, 9, 0));
    let oid_b = "0b1b2b3b-0000-0000-0000-0000000000b2";
    // Each object id is bound to its own device elsewhere.
    device_event(
        &case,
        "Update device.",
        at(1, 7, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[&format!("Device_{OID}")],
    );
    device_event(
        &case,
        "Update device.",
        at(1, 7, 5),
        &[("TargetId.DeviceId", &quoted(DEV_E))],
        &[&format!("Device_{oid_b}")],
    );
    // An id-less delete whose targets map to both: ambiguous, ignored.
    device_event(&case, "Delete device.", at(2, 9, 0), &[], &[OID, oid_b]);
    let list = suspects(&mut case);
    assert_eq!(sorted_ids(&list), [DEV_D, DEV_E]);
    for d in &list {
        assert!(d.lifecycle.removed.is_none(), "{}", d.device_id);
        assert_eq!(d.lifecycle.status, DeviceStatus::Unknown);
    }
    // Two targets that map to the same device still resolve.
    device_event(
        &case,
        "Delete device.",
        at(3, 9, 0),
        &[],
        &[OID, &format!("Device_{OID}")],
    );
    let list = devices::suspect_devices(case.conn(), None).unwrap();
    let d = list.iter().find(|d| d.device_id == DEV_D).unwrap();
    assert_eq!(d.lifecycle.status, DeviceStatus::Removed);
    let e = list.iter().find(|d| d.device_id == DEV_E).unwrap();
    assert_eq!(e.lifecycle.status, DeviceStatus::Unknown);
}

#[test]
fn untimed_sighting_after_delete_stays_removed() {
    let mut case = t1_case();
    flagged_d(&case);
    device_event(
        &case,
        "Delete device.",
        at(2, 9, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[],
    );
    insert_row(
        &case,
        "signins",
        T1,
        json!({"record_key": "untimed-2", "user_upn": ALICE, "ip": IP_CLEAN, "event_time": null, "app_name": "Office 365",
               "device": device_struct(Some(DEV_D), None)}),
    );
    let list = suspects(&mut case);
    let d = only(&list);
    assert_eq!(d.sightings.len(), 2);
    assert_eq!(d.lifecycle.status, DeviceStatus::Removed);
}

#[test]
fn unusual_ip_values_enrich_and_do_not_break_the_query() {
    let mut case = t1_case();
    let odd = "198.51.100.7' OR 1=1 --\u{e9}\"";
    flagged_d(&case);
    // The device also appears from an address with a quote and non-ASCII text, which ip_intel knows.
    signin(
        &case,
        T1,
        ALICE,
        odd,
        at(2, 8, 0),
        "Office 365",
        device_struct(Some(DEV_D), None),
    );
    insert_row(
        &case,
        "ip_intel",
        T1,
        json!({"ip": odd, "asn": 64501, "asn_org": "Odd \u{e9}", "country_iso": "FR", "is_hosting": false}),
    );
    // A decoy row that a broken literal list would have matched.
    insert_row(
        &case,
        "ip_intel",
        T1,
        json!({"ip": IP_CLEAN, "asn": 1, "asn_org": "Decoy"}),
    );
    let list = suspects(&mut case);
    let d = only(&list);
    assert_eq!(d.other_ips.len(), 1);
    assert_eq!(d.other_ips[0].ip, odd);
    assert_eq!(d.other_ips[0].asn, Some(64501));
    assert_eq!(d.other_ips[0].asn_org.as_deref(), Some("Odd \u{e9}"));
}

#[test]
fn id_less_event_with_an_unmapped_device_target_resolves_nothing() {
    let mut case = t1_case();
    flagged_d(&case);
    device_event(
        &case,
        "Update device.",
        at(1, 7, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[&format!("Device_{OID}")],
    );
    // One mapped target and one nobody has bound: ambiguous, ignored.
    device_event(
        &case,
        "Delete device.",
        at(2, 9, 0),
        &[],
        &[OID, "99999999-0000-0000-0000-000000000099"],
    );
    let list = suspects(&mut case);
    assert!(only(&list).lifecycle.removed.is_none());
    assert_eq!(only(&list).lifecycle.status, DeviceStatus::Unknown);
    // The bare/prefixed twin of the mapped target alone still resolves.
    let del = device_event(
        &case,
        "Delete device.",
        at(3, 9, 0),
        &[],
        &[OID, &format!("Device_{OID}")],
    );
    let list = devices::suspect_devices(case.conn(), None).unwrap();
    assert_eq!(only(&list).lifecycle.status, DeviceStatus::Removed);
    assert_eq!(
        only(&list).lifecycle.removed.as_ref().unwrap().record_key,
        del
    );
}

#[test]
fn real_event_target_shape_resolves_through_the_object_id() {
    let mut case = t1_case();
    flagged_d(&case);
    named_sighting(
        &case,
        T1,
        ALICE,
        DEV_D,
        "Workstation",
        IP_CLEAN,
        at(1, 8, 30),
    );
    // Bound by an earlier update that names the device id.
    device_event(
        &case,
        "Update device.",
        at(1, 7, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[&format!("Device_{OID}"), OID, "Device", "Workstation"],
    );
    // The id-less delete with the full real Target: Device_<oid>, <oid>, "Device", the display name.
    let del = device_event(
        &case,
        "Delete device.",
        at(2, 9, 0),
        &[],
        &[&format!("Device_{OID}"), OID, "Device", "Workstation"],
    );
    let list = suspects(&mut case);
    let d = only(&list);
    assert_eq!(d.lifecycle.status, DeviceStatus::Removed);
    assert_eq!(d.lifecycle.removed.as_ref().unwrap().record_key, del);
    assert_eq!(d.object_id.as_deref(), Some(OID));
}

// ---------------------------------------------------------------------------------------------------------------
// the analyst's device status (`case::device_status`)

use sparrow_core::Error;
use sparrow_core::case::audit;
use sparrow_core::case::device_status::{self, AnalystStatus};

/// (device_id, status, note, live) of every `device_analyst_status` row, in decision order.
fn status_rows(case: &Case) -> Vec<(String, String, Option<String>, bool)> {
    let mut st = case
        .conn()
        .prepare(
            "SELECT device_id, CAST(status AS VARCHAR), note, removed_at IS NULL FROM device_analyst_status \
             ORDER BY decision_id",
        )
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn audit_count(case: &Case) -> i64 {
    case.conn()
        .query_row("SELECT count(*) FROM audit_trail", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn analyst_status_set_replace_and_clear_are_audited_and_soft_deleted() {
    let case = t1_case();
    let a = analyst();
    // Any spelling of the id is stored lower case.
    let e1 = device_status::set_status(
        case.conn(),
        &a,
        &format!("  {}  ", DEV_A_UPPER),
        Some(AnalystStatus::Removed),
        Some("  wiped by IT on the 4th  "),
    )
    .unwrap();
    assert_eq!(
        (
            e1.action.as_str(),
            e1.object_type.as_str(),
            e1.object_id.as_str()
        ),
        ("set_device_status", "device_status", DEV_A)
    );
    assert_eq!(e1.actor, "analyst:tester");
    assert!(e1.before.is_none());
    let after = e1.after.as_ref().unwrap();
    assert_eq!(after["status"], "removed");
    assert_eq!(after["note"], "wiped by IT on the 4th");
    assert_eq!(after["decided_by"], "analyst:tester");
    let cur = device_status::current(case.conn(), DEV_A).unwrap().unwrap();
    assert_eq!(cur.status, AnalystStatus::Removed);
    assert_eq!(cur.note.as_deref(), Some("wiped by IT on the 4th"));
    assert_eq!(
        audit::ts_text(&cur.decided_at),
        e1.after.as_ref().unwrap()["decided_at"]
    );
    assert_eq!(audit::ts_text(&cur.decided_at), audit::ts_text(&e1.ts));

    // The same status and note again changes nothing and is refused.
    let same = device_status::set_status(
        case.conn(),
        &a,
        DEV_A,
        Some(AnalystStatus::Removed),
        Some("wiped by IT on the 4th"),
    )
    .unwrap_err();
    assert!(matches!(same, Error::Decision(_)), "{same}");

    // A new status closes the live row and adds one; the audit entry holds both.
    let e2 = device_status::set_status(case.conn(), &a, DEV_A, Some(AnalystStatus::Benign), None)
        .unwrap();
    assert_eq!(e2.before.as_ref().unwrap()["status"], "removed");
    assert_eq!(e2.after.as_ref().unwrap()["status"], "benign");
    assert!(e2.after.as_ref().unwrap()["note"].is_null());
    assert_eq!(
        status_rows(&case),
        [
            (
                DEV_A.into(),
                "removed".into(),
                Some("wiped by IT on the 4th".into()),
                false
            ),
            (DEV_A.into(), "benign".into(), None, true),
        ]
    );

    // Clear: no live row, the history stays; the audit entry's after is null.
    let e3 = device_status::set_status(case.conn(), &a, DEV_A, None, None).unwrap();
    assert_eq!(e3.action, "clear_device_status");
    assert_eq!(e3.before.as_ref().unwrap()["status"], "benign");
    assert!(e3.after.is_none());
    assert!(
        device_status::current(case.conn(), DEV_A)
            .unwrap()
            .is_none()
    );
    assert_eq!(status_rows(&case).iter().filter(|r| r.3).count(), 0);
    assert_eq!(status_rows(&case).len(), 2);
    let removed_by: Vec<Option<String>> = case
        .conn()
        .prepare("SELECT removed_by FROM device_analyst_status ORDER BY decision_id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        removed_by,
        [
            Some("analyst:tester".to_string()),
            Some("analyst:tester".to_string())
        ]
    );

    // Nothing left to clear; a note on a clear is refused.
    let before = audit_count(&case);
    let e = device_status::set_status(case.conn(), &a, DEV_A, None, None).unwrap_err();
    assert!(matches!(e, Error::Decision(_)), "{e}");
    let e = device_status::set_status(case.conn(), &a, DEV_A, None, Some("why")).unwrap_err();
    assert!(matches!(e, Error::Invalid(_)), "{e}");
    assert_eq!(audit_count(&case), before);
    assert!(audit::verify(case.conn()).unwrap().ok);
    let log = audit::log(case.conn(), Some(("device_status", DEV_A))).unwrap();
    assert_eq!(
        log.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(),
        [
            "set_device_status",
            "set_device_status",
            "clear_device_status"
        ]
    );
}

#[test]
fn analyst_status_refuses_agents_and_bad_input_and_writes_nothing() {
    let case = t1_case();
    let agent = Actor::agent("triage", Some("tester")).unwrap();
    let e = device_status::set_status(
        case.conn(),
        &agent,
        DEV_A,
        Some(AnalystStatus::ConfirmedAttacker),
        None,
    )
    .unwrap_err();
    assert!(matches!(e, Error::Decision(_)), "{e}");
    for id in ["", "   ", "dev\u{7}ice"] {
        let e = device_status::set_status(
            case.conn(),
            &analyst(),
            id,
            Some(AnalystStatus::Benign),
            None,
        )
        .unwrap_err();
        assert!(matches!(e, Error::Invalid(_)), "{id:?}: {e}");
    }
    let long = "x".repeat(16 * 1024 + 1);
    let e = device_status::set_status(
        case.conn(),
        &analyst(),
        DEV_A,
        Some(AnalystStatus::Benign),
        Some(&long),
    )
    .unwrap_err();
    assert!(matches!(e, Error::Decision(_)), "{e}");
    assert!(status_rows(&case).is_empty());
    assert_eq!(audit_count(&case), 0);
    assert!(AnalystStatus::parse("gone").is_err());
    assert_eq!(
        AnalystStatus::ALL.map(AnalystStatus::as_str),
        ["removed", "disabled", "confirmed_attacker", "benign"]
    );
}

#[test]
fn analyst_status_sits_next_to_the_computed_status_and_warns_on_a_later_sighting() {
    let mut case = t1_case();
    flagged_d(&case);
    flagged_signin(&case, T1, BOB, DEV_F, at(1, 9, 0));
    let list = suspects(&mut case);
    assert_eq!(sorted_ids(&list), [DEV_D, DEV_F]);
    assert!(
        list.iter()
            .all(|d| d.analyst.is_none() && !d.active_after_analyst_removal)
    );

    // Decided on 10 Mar, after every sighting so far.
    audit::test_clock::set(Some(at(10, 12, 0)));
    let a = analyst();
    device_status::set_status(
        case.conn(),
        &a,
        DEV_D,
        Some(AnalystStatus::Removed),
        Some("gone"),
    )
    .unwrap();
    device_status::set_status(case.conn(), &a, DEV_F, Some(AnalystStatus::Benign), None).unwrap();
    audit::test_clock::set(None);
    let list = suspects(&mut case);
    let d = list.iter().find(|d| d.device_id == DEV_D).unwrap();
    let f = list.iter().find(|d| d.device_id == DEV_F).unwrap();
    // The computed status is untouched: no removal event, no inventory.
    assert_eq!(d.lifecycle.status, DeviceStatus::Unknown);
    let da = d.analyst.as_ref().unwrap();
    assert_eq!(
        (da.status, da.note.as_deref()),
        (AnalystStatus::Removed, Some("gone"))
    );
    assert_eq!(da.decided_at, at(10, 12, 0));
    assert!(!d.active_after_analyst_removal);
    assert_eq!(f.analyst.as_ref().unwrap().status, AnalystStatus::Benign);

    // Both devices are seen again on 11 Mar: D (removed) warns, F (benign) does not.
    signin(
        &case,
        T1,
        ALICE,
        IP_CLEAN,
        at(11, 8, 0),
        "Office 365",
        device_struct(Some(DEV_D), None),
    );
    signin(
        &case,
        T1,
        BOB,
        IP_CLEAN,
        at(11, 8, 0),
        "Office 365",
        device_struct(Some(DEV_F), None),
    );
    let list = suspects(&mut case);
    let d = list.iter().find(|d| d.device_id == DEV_D).unwrap();
    let f = list.iter().find(|d| d.device_id == DEV_F).unwrap();
    assert_eq!(d.lifecycle.status, DeviceStatus::Unknown);
    assert!(d.active_after_analyst_removal);
    assert!(!f.active_after_analyst_removal);

    // Disabled warns the same way; a sighting exactly at the decision time does not.
    let dis = device_status::DeviceDecision {
        device_id: DEV_D.into(),
        status: AnalystStatus::Disabled,
        note: None,
        decided_by: "analyst:tester".into(),
        decided_at: at(11, 8, 0),
    };
    assert!(!dis.active_after(Some(at(11, 8, 0))));
    assert!(dis.active_after(Some(at(11, 8, 1))));
    assert!(!dis.active_after(None));
    let ca = device_status::DeviceDecision {
        status: AnalystStatus::ConfirmedAttacker,
        ..dis.clone()
    };
    assert!(!ca.active_after(Some(at(12, 0, 0))));
}

#[test]
fn analyst_status_matches_a_device_by_its_object_id() {
    let mut case = t1_case();
    flagged_d(&case);
    device_event(
        &case,
        "Update device.",
        at(1, 7, 0),
        &[("TargetId.DeviceId", &quoted(DEV_D))],
        &[&format!("Device_{OID}"), OID, "Device", "Workstation"],
    );
    device_status::set_status(
        case.conn(),
        &analyst(),
        OID,
        Some(AnalystStatus::ConfirmedAttacker),
        None,
    )
    .unwrap();
    let list = suspects(&mut case);
    let d = only(&list);
    assert_eq!(d.object_id.as_deref(), Some(OID));
    assert_eq!(
        d.analyst.as_ref().unwrap().status,
        AnalystStatus::ConfirmedAttacker
    );
    assert_eq!(d.analyst.as_ref().unwrap().device_id, OID);
}
