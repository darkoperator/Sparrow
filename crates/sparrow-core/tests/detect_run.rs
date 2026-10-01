#[path = "common/detect.rs"]
mod detect;
#[path = "common/synth.rs"]
mod synth;

use chrono::{DateTime, TimeZone, Utc};
use detect::{insert_row, insert_ual};
use serde_json::json;
use sha2::{Digest, Sha256};
use sparrow_core::Case;
use sparrow_core::case::indicators::{
    Actor, IndicatorType, Verdict, add_indicator, list_indicators, remove_indicator,
};
use sparrow_core::data::DataDirs;
use sparrow_core::detect::findings::fingerprint;
use sparrow_core::detect::load::{LoadedRule, RuleSet, load_rules, rule_sha256};
use sparrow_core::detect::rule::Rule;
use sparrow_core::detect::run::{DetectOptions, DetectReport, run, run_with_dirs};
use std::collections::BTreeMap;

const T1: &str = "t1";
const T2: &str = "t2";

fn now(day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, day, 12, 0, 0).unwrap()
}

fn opts(day: u32) -> DetectOptions {
    DetectOptions {
        now: Some(now(day)),
        ..DetectOptions::default()
    }
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

fn set_of(rules: Vec<LoadedRule>) -> RuleSet {
    RuleSet {
        rules,
        lists: BTreeMap::new(),
        list_meta: BTreeMap::new(),
        warnings: vec![],
    }
}

fn forwarding_rule(id: &str) -> LoadedRule {
    rule_from(
        id,
        "source: mailboxes\nmatch:\n  forwarding_smtp_address: {exists: true}\ngroup_by: [actor_upn]",
    )
}

fn tenant(case: &Case, key: &str) {
    insert_row(case, "tenant", key, json!({"tenant_key": key}));
    detect::collection_of(case, key);
}

fn mailbox(case: &Case, t: &str, upn: &str, fwd: &str) {
    insert_row(
        case,
        "mailboxes",
        t,
        json!({"upn": upn, "forwarding_smtp_address": fwd}),
    );
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn dump(case: &Case, sql: &str) -> Vec<String> {
    let mut st = case.conn().prepare(sql).unwrap();
    st.query_map([], |r| {
        let mut cols = Vec::new();
        for i in 0..r.as_ref().column_count() {
            cols.push(format!("{:?}", r.get::<_, duckdb::types::Value>(i)?));
        }
        Ok(cols.join("|"))
    })
    .unwrap()
    .map(|r| r.unwrap())
    .collect()
}

fn findings_dump(case: &Case) -> Vec<String> {
    dump(case, "SELECT * FROM findings ORDER BY finding_id")
}

fn evidence_dump(case: &Case) -> Vec<String> {
    dump(
        case,
        "SELECT * FROM finding_evidence ORDER BY finding_id, source_table, record_key",
    )
}

fn status_of(report: &DetectReport, rule: &str, tenant: &str) -> String {
    report
        .rules
        .iter()
        .find(|r| r.rule_id == rule && r.tenant_key == tenant)
        .unwrap_or_else(|| panic!("no run for {rule} {tenant}: {:?}", report.rules))
        .status
        .clone()
}

#[test]
fn hits_become_findings_with_trigger_evidence() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1);
    mailbox(&case, T1, "alice@contoso.example", "evil@example.net");
    mailbox(&case, T1, "bob@contoso.example", "");
    let set = set_of(vec![forwarding_rule("SPW-T-001")]);
    let report = run(&mut case, &set, &opts(2)).unwrap();
    assert_eq!(report.run_id, 1);
    assert_eq!(
        (
            report.findings_new,
            report.findings_updated,
            report.evidence_added
        ),
        (1, 0, 1)
    );
    assert_eq!(status_of(&report, "SPW-T-001", T1), "ran");
    assert_eq!(report.rules[0].hits, 1);

    let (fid, fp, actor, sev, title, status, by, rule_updated): (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        bool,
    ) = case
        .conn()
        .query_row(
            "SELECT finding_id, fingerprint, actor_upn, severity, title, CAST(status AS VARCHAR), \
                        CAST(created_by AS VARCHAR), rule_updated FROM findings",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            },
        )
        .unwrap();
    let expect_fp = fingerprint(
        "SPW-T-001",
        T1,
        &[Some("alice@contoso.example".to_string())],
    );
    assert_eq!(fp, expect_fp);
    assert_eq!(fid, &expect_fp[..16]);
    assert_eq!(actor, "alice@contoso.example");
    assert_eq!(
        (sev.as_str(), title.as_str()),
        ("medium", "title of SPW-T-001")
    );
    assert_eq!(
        (status.as_str(), by.as_str(), rule_updated),
        ("new", "rule", false)
    );
    let (src, role, run_id): (String, String, i64) = case
        .conn()
        .query_row(
            "SELECT source_table, CAST(role AS VARCHAR), added_run_id FROM finding_evidence WHERE finding_id = ?",
            [&fid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (src.as_str(), role.as_str(), run_id),
        ("mailboxes", "trigger", 1)
    );
    // The run log.
    let (rid, ver, status, hits): (i64, i32, String, i64) = case
        .conn()
        .query_row(
            "SELECT run_id, rule_version, CAST(status AS VARCHAR), hits FROM detection_runs",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!((rid, ver, status.as_str(), hits), (1, 1, "ran", 1));
    assert_eq!(
        count(&case, "SELECT epoch(created_at)::BIGINT FROM findings"),
        now(2).timestamp()
    );
}

#[test]
fn needs_geoip_without_geo_data_is_not_applicable() {
    let mut case = Case::in_memory().unwrap();
    let (has, bare, ips_absent, mixed) = ("has-geo", "no-geo", "no-ips", "mixed");
    for t in [has, bare, ips_absent, mixed] {
        tenant(&case, t);
    }
    let signin = |t: &str, ip: &str| {
        insert_row(
            &case,
            "signins",
            t,
            json!({"user_upn": "a@x.example", "ip": ip}),
        );
    };
    let intel = |ip: &str, extra: serde_json::Value| {
        let mut v = json!({"ip": ip, "is_microsoft": false, "is_private": false});
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        insert_row(&case, "ip_intel", "unused", v);
    };
    // ip_intel is shared: one row per distinct IP of the case. Each tenant is judged by its own IPs.
    signin(has, "203.0.113.1");
    intel(
        "203.0.113.1",
        json!({"asn": 14061, "latitude": 48.9, "longitude": 2.4}),
    );
    signin(bare, "203.0.113.2");
    intel("203.0.113.2", json!({}));
    // A tenant whose only sign-in has an ASN but no location, and one with a private address.
    signin(mixed, "10.0.0.1");
    intel("10.0.0.1", json!({"is_private": true}));
    signin(mixed, "203.0.113.3");
    intel("203.0.113.3", json!({"asn": 64500}));
    let geo = rule_from(
        "SPW-T-001",
        "needs_geoip: true\nsource: signins\nmatch:\n  user_upn: {eq: a@x.example}",
    );
    let plain = rule_from(
        "SPW-T-002",
        "source: signins\nmatch:\n  user_upn: {eq: a@x.example}",
    );
    let set = set_of(vec![geo, plain]);
    let report = run(&mut case, &set, &opts(2)).unwrap();
    let find = |rule: &str, t: &str| {
        report
            .rules
            .iter()
            .find(|r| r.rule_id == rule && r.tenant_key == t)
            .unwrap()
    };
    assert_eq!(find("SPW-T-001", has).status, "ran");
    assert_eq!(
        find("SPW-T-001", mixed).status,
        "ran",
        "an ASN alone is geo data"
    );
    for t in [bare, ips_absent] {
        let r = find("SPW-T-001", t);
        assert_eq!(r.status, "not_applicable", "{t}");
        assert_eq!(r.reason.as_deref(), Some("no GeoIP data"), "{t}");
    }
    // A rule that does not need GeoIP is unaffected.
    assert_eq!(find("SPW-T-002", bare).status, "ran");
    assert_eq!(find("SPW-T-002", ips_absent).status, "ran");
}

#[test]
fn unmet_requirement_is_not_applicable_not_empty() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1);
    tenant(&case, T2);
    // T1 lacks identity protection; T2 has ual disabled. Both hold matching evidence.
    insert_row(
        &case,
        "tenant_capabilities",
        T1,
        json!({"tenant_key": T1, "capability_id": "identity_protection", "status": "not_licensed"}),
    );
    insert_row(
        &case,
        "evidence_availability",
        T2,
        json!({"tenant_key": T2, "evidence": "ual", "status": "not_enabled"}),
    );
    for t in [T1, T2] {
        mailbox(&case, t, "alice@contoso.example", "evil@example.net");
    }
    let by_cap = rule_from(
        "SPW-T-001",
        "requires: [identity_protection]\nsource: mailboxes\nmatch:\n  forwarding_smtp_address: {exists: true}",
    );
    let by_evidence = rule_from(
        "SPW-T-002",
        "requires_evidence: [ual]\nsource: mailboxes\nmatch:\n  forwarding_smtp_address: {exists: true}",
    );
    let set = set_of(vec![by_cap, by_evidence]);
    let report = run(&mut case, &set, &opts(2)).unwrap();
    let reason = |rule: &str, t: &str| {
        report
            .rules
            .iter()
            .find(|r| r.rule_id == rule && r.tenant_key == t)
            .unwrap()
            .reason
            .clone()
    };
    assert_eq!(status_of(&report, "SPW-T-001", T1), "not_applicable");
    assert_eq!(
        reason("SPW-T-001", T1).as_deref(),
        Some("capability identity_protection is not_licensed")
    );
    assert_eq!(status_of(&report, "SPW-T-001", T2), "ran");
    assert_eq!(status_of(&report, "SPW-T-002", T2), "not_applicable");
    assert_eq!(
        reason("SPW-T-002", T2).as_deref(),
        Some("evidence ual is not_enabled")
    );
    assert_eq!(status_of(&report, "SPW-T-002", T1), "ran");
    // Not applicable is recorded, and it raised no finding for the tenant.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM detection_runs WHERE status = 'not_applicable'"
        ),
        2
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM findings WHERE tenant_key = 't1' AND rule_id = 'SPW-T-001'"
        ),
        0
    );
    assert_eq!(count(&case, "SELECT count(*) FROM findings"), 2);
}

#[test]
fn a_rule_error_is_recorded_and_other_rules_still_run() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1);
    mailbox(&case, T1, "alice@contoso.example", "evil@example.net");
    let broken = rule_from(
        "SPW-T-001",
        "source: mailboxes\nmatch:\n  no_such_column: {eq: x}",
    );
    let set = set_of(vec![broken, forwarding_rule("SPW-T-002")]);
    let report = run(&mut case, &set, &opts(2)).unwrap();
    assert_eq!(status_of(&report, "SPW-T-001", T1), "error");
    assert!(
        report.rules[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("no_such_column")
    );
    assert_eq!(status_of(&report, "SPW-T-002", T1), "ran");
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM findings WHERE rule_id = 'SPW-T-002'"
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM detection_runs WHERE status = 'error' AND reason LIKE '%no_such_column%'"
        ),
        1
    );
}

#[test]
fn rerun_is_a_no_op() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1);
    mailbox(&case, T1, "alice@contoso.example", "evil@example.net");
    mailbox(&case, T1, "carol@contoso.example", "evil@example.net");
    let set = set_of(vec![forwarding_rule("SPW-T-001")]);
    run(&mut case, &set, &opts(2)).unwrap();
    let (f, e) = (findings_dump(&case), evidence_dump(&case));
    let report = run(&mut case, &set, &opts(3)).unwrap();
    assert_eq!(
        (
            report.findings_new,
            report.findings_updated,
            report.evidence_added
        ),
        (0, 0, 0)
    );
    assert_eq!(
        findings_dump(&case),
        f,
        "findings unchanged, updated_at included"
    );
    assert_eq!(evidence_dump(&case), e);
    assert_eq!(count(&case, "SELECT count(*) FROM detection_runs"), 2);
    assert_eq!(report.run_id, 2);
}

#[test]
fn rerun_keeps_analyst_fields_and_flags_rule_updates() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1);
    mailbox(&case, T1, "alice@contoso.example", "evil@example.net");
    let v1 = rule_from(
        "SPW-T-001",
        "source: mailboxes\nmatch:\n  forwarding_smtp_address: {exists: true}\ngroup_by: [actor_upn]",
    );
    run(&mut case, &set_of(vec![v1]), &opts(2)).unwrap();
    // The analyst works the finding (Phase 7 does this through its own API; here by SQL).
    case.conn()
        .execute_batch(
            "UPDATE findings SET status = 'confirmed', assigned_to = 'analyst:sam', disposition_reason = 'real BEC'",
        )
        .unwrap();
    // A new mailbox row of the same actor appears in the evidence, and the rule text changes.
    insert_row(
        &case,
        "mailboxes",
        T1,
        json!({"upn": "alice@contoso.example", "forwarding_smtp_address": "second@example.net"}),
    );
    let mut v2 = rule_from(
        "SPW-T-001",
        "source: mailboxes\nmatch:\n  forwarding_smtp_address: {contains: example}\ngroup_by: [actor_upn]",
    );
    v2.rule.version = 2;
    v2.rule.title = "renamed rule".to_string();
    v2.sha256 = rule_sha256(&v2.rule, &BTreeMap::new(), &BTreeMap::new());
    let evidence_before = count(&case, "SELECT count(*) FROM finding_evidence");
    let report = run(&mut case, &set_of(vec![v2]), &opts(3)).unwrap();
    assert_eq!((report.findings_new, report.findings_updated), (0, 1));
    assert_eq!(
        count(&case, "SELECT count(*) FROM findings"),
        1,
        "no new finding, none deleted"
    );
    let (status, assigned, reason, rule_updated, version, title): (String, String, String, bool, i32, String) = case
        .conn()
        .query_row(
            "SELECT CAST(status AS VARCHAR), assigned_to, disposition_reason, rule_updated, rule_version, title FROM findings",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .unwrap();
    assert_eq!(
        (
            status.as_str(),
            assigned.as_str(),
            reason.as_str(),
            rule_updated,
            version,
            title.as_str()
        ),
        (
            "confirmed",
            "analyst:sam",
            "real BEC",
            true,
            2,
            "renamed rule"
        )
    );
    assert_eq!(
        count(&case, "SELECT count(*) FROM finding_evidence"),
        evidence_before + 1
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM finding_evidence WHERE added_run_id = 2"
        ),
        1
    );
    // rule_updated is never reset by a later identical run.
    run(&mut case, &set_of(vec![{
        let mut v = rule_from("SPW-T-001", "source: mailboxes\nmatch:\n  forwarding_smtp_address: {contains: example}\ngroup_by: [actor_upn]");
        v.rule.version = 2;
        v.rule.title = "renamed rule".to_string();
        v.sha256 = rule_sha256(&v.rule, &BTreeMap::new(), &BTreeMap::new());
        v
    }]), &opts(4)).unwrap();
    assert!(
        case.conn()
            .query_row("SELECT rule_updated FROM findings", [], |r| r
                .get::<_, bool>(0))
            .unwrap()
    );
}

#[test]
fn tenants_never_share_a_finding() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1);
    tenant(&case, T2);
    // The same actor in two tenants.
    mailbox(&case, T1, "alice@contoso.example", "evil@example.net");
    mailbox(&case, T2, "alice@contoso.example", "evil@example.net");
    insert_ual(
        &case,
        T2,
        json!({"record_id": "00000000-0000-0000-0000-000000000009", "operation": "X"}),
    );
    let set = set_of(vec![forwarding_rule("SPW-T-001")]);
    let report = run(&mut case, &set, &opts(2)).unwrap();
    assert_eq!(report.findings_new, 2);
    let ids = dump(
        &case,
        "SELECT tenant_key || ':' || finding_id FROM findings ORDER BY tenant_key",
    );
    assert_eq!(ids.len(), 2);
    assert_ne!(
        ids[0].split(':').nth(1),
        ids[1].split(':').nth(1),
        "fingerprints differ per tenant"
    );
    for (t, want) in [(T1, 1), (T2, 1)] {
        assert_eq!(
            count(
                &case,
                &format!(
                    "SELECT count(*) FROM finding_evidence e JOIN findings f USING (finding_id) WHERE f.tenant_key = '{t}'"
                )
            ),
            want
        );
    }
    // A correlation rule sees one tenant at a time: T2's UAL row never meets T1's mailbox.
    let cross = rule_from(
        "SPW-T-002",
        "sql: |\n  SELECT lower(CAST(u.record_id AS VARCHAR)) AS record_key, 'ual_events' AS source_table, u.event_time\n  FROM ual_events u, mailboxes m WHERE m.upn = 'alice@contoso.example'",
    );
    let report = run(&mut case, &set_of(vec![cross]), &opts(3)).unwrap();
    assert_eq!(
        report
            .rules
            .iter()
            .find(|r| r.tenant_key == T1)
            .unwrap()
            .hits,
        0
    );
    assert_eq!(
        report
            .rules
            .iter()
            .find(|r| r.tenant_key == T2)
            .unwrap()
            .hits,
        1
    );
}

fn ioc_rule() -> LoadedRule {
    rule_from(
        "SPW-T-010",
        "source: ual_events\nmatch:\n  client_ip: {in: \"@list:case_iocs.ip\"}\ngroup_by: [ip]",
    )
}

#[test]
fn case_ioc_list_feeds_rules() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1);
    insert_ual(
        &case,
        T1,
        json!({"record_id": "00000000-0000-0000-0000-000000000001", "client_ip": "203.0.113.7"}),
    );
    insert_ual(
        &case,
        T1,
        json!({"record_id": "00000000-0000-0000-0000-000000000002", "client_ip": "198.51.100.1"}),
    );
    let set = set_of(vec![ioc_rule()]);
    // No indicator yet: nothing.
    let report = run(&mut case, &set, &opts(2)).unwrap();
    assert_eq!(report.rules[0].hits, 0);
    let actor = Actor::analyst("sam").unwrap();
    let id = add_indicator(
        case.conn(),
        &actor,
        None,
        IndicatorType::Ip,
        "203.0.113.7",
        Verdict::Malicious,
        Some("c2"),
    )
    .unwrap();
    // A benign verdict is an allow-list marker rules do not read.
    add_indicator(
        case.conn(),
        &actor,
        Some(T1),
        IndicatorType::Ip,
        "198.51.100.1",
        Verdict::Benign,
        None,
    )
    .unwrap();
    let listed = list_indicators(case.conn(), Some(T1)).unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].added_by, "analyst:sam");
    let report = run(&mut case, &set, &opts(3)).unwrap();
    assert_eq!(report.rules[0].hits, 1);
    assert_eq!(report.findings_new, 1);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM finding_evidence WHERE record_key = '00000000-0000-0000-0000-000000000001'"
        ),
        1
    );
    // Adding the same indicator again updates it rather than duplicating.
    let again = add_indicator(
        case.conn(),
        &actor,
        None,
        IndicatorType::Ip,
        "203.0.113.7",
        Verdict::Suspicious,
        None,
    )
    .unwrap();
    assert_eq!(again, id);
    assert_eq!(list_indicators(case.conn(), None).unwrap().len(), 2);
}

#[test]
fn ioc_change_marks_rule_updated() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1);
    insert_ual(
        &case,
        T1,
        json!({"record_id": "00000000-0000-0000-0000-000000000001", "client_ip": "203.0.113.7"}),
    );
    let set = set_of(vec![ioc_rule()]);
    let actor = Actor::analyst("sam").unwrap();
    let id = add_indicator(
        case.conn(),
        &actor,
        None,
        IndicatorType::Ip,
        "203.0.113.7",
        Verdict::Malicious,
        None,
    )
    .unwrap();
    run(&mut case, &set, &opts(2)).unwrap();
    assert!(
        !case
            .conn()
            .query_row("SELECT rule_updated FROM findings", [], |r| r
                .get::<_, bool>(0))
            .unwrap()
    );
    let sha_before: String = case
        .conn()
        .query_row("SELECT rule_sha256 FROM findings", [], |r| r.get(0))
        .unwrap();
    // Same indicators, same run: still not flagged.
    run(&mut case, &set, &opts(3)).unwrap();
    assert!(
        !case
            .conn()
            .query_row("SELECT rule_updated FROM findings", [], |r| r
                .get::<_, bool>(0))
            .unwrap()
    );
    // Removing the indicator changes what the rule read: the finding stays and is flagged.
    assert!(remove_indicator(case.conn(), &actor, &id).unwrap());
    assert!(!remove_indicator(case.conn(), &actor, &id).unwrap());
    run(&mut case, &set, &opts(4)).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM findings"), 1);
    assert!(
        case.conn()
            .query_row("SELECT rule_updated FROM findings", [], |r| r
                .get::<_, bool>(0))
            .unwrap()
    );
    let sha_after: String = case
        .conn()
        .query_row("SELECT rule_sha256 FROM findings", [], |r| r.get(0))
        .unwrap();
    assert_ne!(sha_before, sha_after);
    assert_eq!(
        count(&case, "SELECT count(*) FROM finding_evidence"),
        1,
        "nothing deleted"
    );
}

#[test]
fn fingerprint_is_stable_and_order_independent() {
    let expect = |s: &[u8]| hex::encode(Sha256::digest(s));
    assert_eq!(
        fingerprint("R", "t", &[Some("a".into()), None, Some("b".into())]),
        expect(b"R\x1ft\x1fa\x1f\x00\x1fb")
    );
    assert_ne!(
        fingerprint("R", "t", &[Some("a".into())]),
        fingerprint("R", "u", &[Some("a".into())])
    );
    assert_ne!(
        fingerprint("R", "t", &[None]),
        fingerprint("R", "t", &[Some(String::new())]),
        "NULL and the empty string differ"
    );
    // The same evidence inserted in another order yields the same finding ids and evidence.
    let build = |order: &[(&str, &str)]| {
        let mut case = Case::in_memory().unwrap();
        tenant(&case, T1);
        for (upn, fwd) in order {
            mailbox(&case, T1, upn, fwd);
        }
        run(
            &mut case,
            &set_of(vec![forwarding_rule("SPW-T-001")]),
            &opts(2),
        )
        .unwrap();
        dump(
            &case,
            "SELECT finding_id, fingerprint, actor_upn FROM findings ORDER BY finding_id",
        )
    };
    let a = build(&[
        ("a@x.example", "e1@example.net"),
        ("b@x.example", "e2@example.net"),
    ]);
    let b = build(&[
        ("b@x.example", "e2@example.net"),
        ("a@x.example", "e1@example.net"),
    ]);
    assert_eq!(a, b);
    assert_eq!(a.len(), 2);
}

#[test]
fn ingest_runs_detection_after_profile() {
    let mut g = synth::builtin("bec-aitm", sparrow_synth::options::PsEdition::Ps7);
    let report = run_with_dirs(&mut g.case, &DataDirs::default(), &opts(2)).unwrap();
    assert!(count(&g.case, "SELECT count(*) FROM detection_runs") > 0);
    assert_eq!(
        count(
            &g.case,
            "SELECT count(*) FROM detection_runs WHERE status = 'error'"
        ),
        0,
        "{:?}",
        report
            .rules
            .iter()
            .filter(|r| r.status == "error")
            .collect::<Vec<_>>()
    );
    let set = load_rules(&DataDirs::default()).unwrap();
    let tenants = count(&g.case, "SELECT count(*) FROM tenant");
    assert_eq!(report.rules.len() as i64, tenants * set.rules.len() as i64);
    // A second run over the unchanged case changes nothing but the run log.
    let before = (findings_dump(&g.case), evidence_dump(&g.case));
    run_with_dirs(&mut g.case, &DataDirs::default(), &opts(3)).unwrap();
    assert_eq!((findings_dump(&g.case), evidence_dump(&g.case)), before);
}

#[test]
fn writer_is_not_locked_after_detect() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.duckdb");
    let mut case = Case::create_or_open(&path).unwrap();
    tenant(&case, T1);
    mailbox(&case, T1, "alice@contoso.example", "evil@example.net");
    let set = set_of(vec![forwarding_rule("SPW-T-001")]);
    let report = run(&mut case, &set, &opts(2)).unwrap();
    assert_eq!(report.findings_new, 1);
    // The case connection reads a CSV the way ingest does and keeps writing.
    let csv = dir.path().join("x.csv");
    std::fs::write(&csv, "a\n1\n2\n3\n").unwrap();
    assert_eq!(
        count(
            &case,
            &format!("SELECT count(*) FROM read_csv('{}')", csv.display())
        ),
        3
    );
    mailbox(&case, T1, "carol@contoso.example", "evil@example.net");
    let report = run(&mut case, &set, &opts(3)).unwrap();
    assert_eq!(report.findings_new, 1);
    assert_eq!(count(&case, "SELECT count(*) FROM findings"), 2);
    // A file case survives being reopened, findings included.
    drop(case);
    let case = Case::open_read_only(&path).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM findings"), 2);
}

#[test]
fn production_rule_cannot_read_files() {
    let dir = tempfile::tempdir().unwrap();
    let mut case = Case::create_or_open(&dir.path().join("case.duckdb")).unwrap();
    tenant(&case, T1);
    mailbox(&case, T1, "alice@contoso.example", "evil@example.net");
    let head = "SELECT 'x' AS record_key, 'mailboxes' AS source_table, now() AS event_time";
    let sneaky = |id: &str, from: &str| rule_from(id, &format!("sql: |\n  {head} FROM {from}"));
    let set = set_of(vec![
        sneaky("SPW-T-001", "read_csv('/etc/hosts')"),
        sneaky("SPW-T-002", "glob('/etc/*')"),
        sneaky("SPW-T-003", "main.mailboxes"),
        forwarding_rule("SPW-T-004"),
    ]);
    let report = run(&mut case, &set, &opts(2)).unwrap();
    for id in ["SPW-T-001", "SPW-T-002", "SPW-T-003"] {
        assert_eq!(status_of(&report, id, T1), "error", "{id}");
    }
    assert!(
        report.rules[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("read_csv")
    );
    assert!(
        report.rules[2]
            .reason
            .as_deref()
            .unwrap()
            .contains("schema-qualified")
    );
    assert_eq!(status_of(&report, "SPW-T-004", T1), "ran");
    assert_eq!(count(&case, "SELECT count(*) FROM findings"), 1);
}

#[test]
fn detection_never_writes_the_analyst_columns() {
    // No statement in the detection writer touches status, disposition_reason or assigned_to
    // outside the initial insert (which relies on the column default).
    let src: String = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/detect/findings.rs"
    ))
    .unwrap()
    .lines()
    .filter(|l| !l.trim_start().starts_with("//"))
    .collect::<Vec<_>>()
    .join("\n");
    for column in ["disposition_reason", "assigned_to"] {
        assert!(!src.contains(column), "findings.rs mentions {column}");
    }
    for stmt in src.split("tx.execute(").skip(1) {
        let sql = stmt.split("params!").next().unwrap();
        if sql.contains("UPDATE findings") {
            assert!(!sql.contains("status ="), "an UPDATE sets status: {sql}");
        }
    }
}

/// A rule with many hits (one finding each) merges completely, a re-run adds nothing, and the
/// report says where the time went (the phases the performance work reads).
#[test]
fn many_hits_merge_once_and_the_run_reports_its_phases() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1);
    for i in 0..1_300 {
        mailbox(
            &case,
            T1,
            &format!("u{i}@contoso.example"),
            "evil@example.net",
        );
    }
    let set = set_of(vec![rule_from(
        "SPW-T-002",
        "source: mailboxes\nmatch:\n  forwarding_smtp_address: {exists: true}\ngroup_by: [record_key]",
    )]);
    let first = run(&mut case, &set, &opts(2)).unwrap();
    assert_eq!(
        (
            first.findings_new,
            first.findings_updated,
            first.evidence_added
        ),
        (1_300, 0, 1_300)
    );
    assert_eq!(count(&case, "SELECT count(*) FROM findings"), 1_300);
    assert_eq!(count(&case, "SELECT count(*) FROM finding_evidence"), 1_300);
    let names: Vec<&str> = first.phases.iter().map(|p| p.name.as_str()).collect();
    for want in ["inputs", "plan (compile)", "rules (sum)", "merge"] {
        assert!(names.contains(&want), "{want} in {names:?}");
    }
    let before = (findings_dump(&case), evidence_dump(&case));
    let second = run(&mut case, &set, &opts(3)).unwrap();
    assert_eq!(
        (
            second.findings_new,
            second.findings_updated,
            second.evidence_added
        ),
        (0, 0, 0)
    );
    assert_eq!((findings_dump(&case), evidence_dump(&case)), before);
}

/// SPW-MAIL-005 raises one finding per (mailbox, UTC day): an attacker reading one mailbox from
/// several addresses on a day is one finding, and the next day is another.
#[test]
fn mail_005_groups_per_mailbox_and_day() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1);
    let mut n = 0;
    // (address, day): two spray-source addresses on 2026-03-01, one on 2026-03-02, five binds each.
    for (ip, day) in [
        ("203.0.113.9", "01"),
        ("203.0.113.10", "01"),
        ("203.0.113.9", "02"),
    ] {
        insert_row(
            &case,
            "spray_sources",
            T1,
            json!({"tenant_key": T1, "ip": ip, "users_targeted": 6, "failures": 12,
                   "first_failure": "2026-02-20T00:00:00Z", "last_failure": "2026-02-28T00:00:00Z"}),
        );
        for i in 0..5 {
            n += 1;
            let id = format!("00000000-0000-0000-0000-{n:012}");
            insert_ual(
                &case,
                T1,
                json!({"record_id": id, "operation": "MailItemsAccessed",
                       "user_upn": "victim@contoso.example", "mailbox_upn": "victim@contoso.example",
                       "client_ip": ip, "event_time": format!("2026-03-{day}T10:0{i}:00Z")}),
            );
            insert_row(
                &case,
                "mail_items_accessed",
                T1,
                json!({"record_id": id, "item_ordinal": 0, "access_type": "bind"}),
            );
        }
    }
    let rules = sparrow_core::detect::load::load_rules(&DataDirs::default()).unwrap();
    let rule = rules
        .rules
        .into_iter()
        .find(|r| r.rule.id == "SPW-MAIL-005")
        .unwrap();
    let set = RuleSet {
        rules: vec![rule],
        lists: BTreeMap::new(),
        list_meta: BTreeMap::new(),
        warnings: vec![],
    };
    let report = run(&mut case, &set, &opts(5)).unwrap();
    assert_eq!(report.rules[0].hits, 15, "{report:#?}");
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM findings WHERE rule_id = 'SPW-MAIL-005'"
        ),
        2
    );
}

/// SPW-ID-005 context: whether the user was sprayed uses the shared credential-failure list (an MFA
/// interrupt does not mark a user as sprayed), and the timing against the first failure is in the
/// context (a success before the spray is a hit too).
#[test]
fn id_005_context_uses_the_credential_failure_list_and_the_timing() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1);
    insert_row(
        &case,
        "spray_sources",
        T1,
        json!({"tenant_key": T1, "ip": "203.0.113.9", "users_targeted": 6, "failures": 12,
               "first_failure": "2026-03-10T00:00:00Z", "last_failure": "2026-03-11T00:00:00Z"}),
    );
    let sign = |upn: &str, code: i64, time: &str| {
        insert_row(
            &case,
            "signins",
            T1,
            json!({"user_upn": upn, "ip": "203.0.113.9", "error_code": code, "event_time": time,
                   "is_interactive": true}),
        );
    };
    // Three more users elsewhere: the rule needs sign-ins of at least five distinct users.
    for u in 0..3 {
        insert_row(
            &case,
            "signins",
            T1,
            json!({"user_upn": format!("p{u}@contoso.example"), "ip": "198.51.100.77",
                   "error_code": 0, "event_time": "2026-03-01T09:00:00Z"}),
        );
    }
    // a: failed with a credential code, then succeeded after the spray started: sprayed, after.
    sign("a@contoso.example", 50126, "2026-03-10T10:00:00Z");
    sign("a@contoso.example", 0, "2026-03-12T10:00:00Z");
    // b: only an MFA interrupt (50074) from the address, then a success BEFORE the spray: not sprayed.
    sign("b@contoso.example", 50074, "2026-03-01T10:00:00Z");
    sign("b@contoso.example", 0, "2026-03-01T10:05:00Z");
    let rules = sparrow_core::detect::load::load_rules(&DataDirs::default()).unwrap();
    let rule = rules
        .rules
        .into_iter()
        .find(|r| r.rule.id == "SPW-ID-005")
        .unwrap();
    let set = RuleSet {
        rules: vec![rule],
        lists: rules.lists,
        list_meta: rules.list_meta,
        warnings: vec![],
    };
    run(&mut case, &set, &opts(20)).unwrap();
    let ctx = |upn: &str| -> (bool, bool) {
        let c: String = case
            .conn()
            .query_row(
                "SELECT CAST(e.context AS VARCHAR) FROM findings f JOIN finding_evidence e USING (finding_id)
                 WHERE f.actor_upn = ? AND e.role = 'trigger'",
                [upn],
                |r| r.get(0),
            )
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&c).unwrap();
        (
            v["was_sprayed_user"].as_bool().unwrap(),
            v["before_first_failure"].as_bool().unwrap(),
        )
    };
    assert_eq!(ctx("a@contoso.example"), (true, false));
    assert_eq!(ctx("b@contoso.example"), (false, true));
}

/// A rule with a population threshold (SPW-ID-005 / SPW-ID-006 need sign-ins of 5 distinct users) is
/// `not_applicable` for a tenant whose sign-ins cover fewer, and says why: a per-user collection (Hawk's
/// investigated users) cannot show a spray, and the silence must not look like a clean result.
#[test]
fn a_population_threshold_is_not_applicable_below_five_signin_users() {
    let run_for = |users: usize| -> (String, Option<String>) {
        let mut case = Case::in_memory().unwrap();
        tenant(&case, T1);
        for u in 0..users {
            insert_row(
                &case,
                "signins",
                T1,
                json!({"user_upn": format!("u{u}@contoso.example"), "ip": "198.51.100.1",
                       "error_code": 0, "event_time": "2026-03-01T10:00:00Z"}),
            );
        }
        let rules = sparrow_core::detect::load::load_rules(&DataDirs::default()).unwrap();
        let rule = rules
            .rules
            .into_iter()
            .find(|r| r.rule.id == "SPW-ID-005")
            .unwrap();
        let set = RuleSet {
            rules: vec![rule],
            lists: rules.lists,
            list_meta: rules.list_meta,
            warnings: vec![],
        };
        let report = run(&mut case, &set, &opts(20)).unwrap();
        let r = &report.rules[0];
        (r.status.clone(), r.reason.clone())
    };
    let (status, reason) = run_for(4);
    assert_eq!(status, "not_applicable");
    assert!(
        reason
            .as_deref()
            .is_some_and(|r| r.contains("4 distinct users") && r.contains("5")),
        "{reason:?}"
    );
    assert_eq!(run_for(5).0, "ran");
}
