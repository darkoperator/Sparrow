#[path = "common/detect.rs"]
mod detect;

use detect::{Hit, insert_row, insert_ual, run};
use serde_json::json;
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::detect::compile::{CaseSchema, Compiled, compile, compile_with_meta};
use sparrow_core::detect::coverage::CoverageMatrix;
use sparrow_core::detect::lint::{LintIssue, LintSeverity, lint};
use sparrow_core::detect::load::{ListMeta, LoadedRule, RuleSet, load_rules};
use sparrow_core::detect::rule::Rule;
use std::collections::BTreeMap;

const T1: &str = "t1";
const T2: &str = "t2";
const R1: &str = "00000000-0000-0000-0000-000000000001";
const R2: &str = "00000000-0000-0000-0000-000000000002";
const R3: &str = "00000000-0000-0000-0000-000000000003";

fn rule_from(body: &str) -> Rule {
    let text = format!(
        "id: SPW-T-001\ntitle: t\nversion: 1\nstatus: experimental\nseverity: low\nanalyst_guidance: g\n{body}\ntests:\n  - name: p\n    records: []\n    expect_hits: 1\n  - name: n\n    records: []\n    expect_hits: 0\n"
    );
    serde_norway::from_str(&text).unwrap_or_else(|e| panic!("{e}\n{text}"))
}

fn match_rule(source: &str, cond: &str) -> Rule {
    let indented: String = cond.lines().map(|l| format!("  {l}\n")).collect();
    rule_from(&format!("source: {source}\nmatch:\n{indented}"))
}

fn no_lists() -> BTreeMap<String, Vec<String>> {
    BTreeMap::new()
}

fn compile_on(case: &Case, rule: &Rule) -> sparrow_core::Result<Compiled> {
    let schema = CaseSchema::of(case.conn()).unwrap();
    compile(rule, &no_lists(), &schema)
}

fn hits(case: &mut Case, rule: &Rule, tenant: &str) -> Vec<String> {
    let c = compile_on(case, rule).unwrap_or_else(|e| panic!("{e}"));
    run(case, &c, tenant, &BTreeMap::new())
        .unwrap_or_else(|e| panic!("{e}\n{}", c.sql))
        .into_iter()
        .map(|h| h.record_key)
        .collect()
}

fn ids(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn ops_case() -> Case {
    let case = Case::in_memory().unwrap();
    insert_ual(
        &case,
        T1,
        json!({"record_id": R1, "event_time": "2026-03-01T10:00:00Z", "operation": "New-InboxRule",
               "user_upn": "Alice@Contoso.example", "client_ip": "203.0.113.7",
               "mailbox_upn": "alice@contoso.example",
               "parameters": {"ForwardTo": "x@evil.example", "DeleteMessage": "True"},
               "audit_data": {"Foo": "bar", "Count": 5}}),
    );
    insert_ual(
        &case,
        T1,
        json!({"record_id": R2, "event_time": "2026-03-01T11:00:00Z", "operation": "Set-InboxRule",
               "user_upn": "bob@contoso.example", "client_ip": "198.51.100.9:443",
               "mailbox_upn": "carol@contoso.example",
               "parameters": {"DeleteMessage": "False"}, "audit_data": {"Foo": "baz", "Count": 2}}),
    );
    insert_ual(
        &case,
        T1,
        json!({"record_id": R3, "event_time": "2026-03-01T12:00:00Z", "operation": "MailItemsAccessed",
               "user_upn": "carol@contoso.example", "client_ip": "2001:db8::1", "audit_data": {}}),
    );
    case
}

#[test]
fn match_leaf_operators_compile_and_run() {
    let mut case = ops_case();
    let cases: &[(&str, &[&str])] = &[
        ("operation: {eq: new-inboxrule}", &[R1]),
        ("operation: {neq: New-InboxRule}", &[R2, R3]),
        ("parameters.ForwardTo: {neq: x@evil.example}", &[]),
        (
            "all:\n  - parameters.ForwardTo: {exists: false}\n  - operation: {neq: setinboxrule}",
            &[R2, R3],
        ),
        (
            "operation: {in: [set-inboxrule, MAILITEMSACCESSED]}",
            &[R2, R3],
        ),
        ("operation: {contains: INBOX}", &[R1, R2]),
        ("operation: {contains_any: [zzz, ITEMS]}", &[R3]),
        ("operation: {startswith: set}", &[R2]),
        ("operation: {endswith: RULE}", &[R1, R2]),
        ("operation: {regex: '^(New|Set)-'}", &[R1, R2]),
        ("operation: {regex: '^new-'}", &[]),
        ("client_ip: {cidr: 203.0.113.0/24}", &[R1]),
        (
            "client_ip: {cidr: [203.0.113.0/24, 198.51.100.0/24]}",
            &[R1, R2],
        ),
        ("event_time: {gt: '2026-03-01T10:30:00Z'}", &[R2, R3]),
        ("event_time: {gte: '2026-03-01T11:00:00Z'}", &[R2, R3]),
        ("event_time: {lt: '2026-03-01T11:00:00Z'}", &[R1]),
        ("event_time: {lte: '2026-03-01T11:00:00Z'}", &[R1, R2]),
        ("audit_data.$.Count: {gt: 3}", &[R1]),
        ("audit_data.$.Count: {lte: 2}", &[R2]),
        ("audit_data.$.Foo: {eq: BAR}", &[R1]),
        ("parameters.ForwardTo: {exists: true}", &[R1]),
        ("parameters.ForwardTo: {exists: false}", &[R2, R3]),
        ("audit_data.$.Foo: {exists: true}", &[R1, R2]),
        ("user_upn: {eq_field: mailbox_upn}", &[R1]),
        ("user_upn: {neq_field: mailbox_upn}", &[R2]),
        (
            "all:\n  - operation: {contains: rule}\n  - user_upn: {startswith: bob}",
            &[R2],
        ),
        (
            "any:\n  - operation: {eq: MailItemsAccessed}\n  - client_ip: {cidr: 203.0.113.7/32}",
            &[R1, R3],
        ),
        ("not:\n  operation: {contains: rule}", &[R3]),
        ("not:\n  parameters.DeleteMessage: {eq: 'True'}", &[R2]),
    ];
    for (cond, want) in cases {
        let got = hits(&mut case, &match_rule("ual_events", cond), T1);
        let mut want: Vec<String> = ids(want);
        want.sort();
        let mut got = got;
        got.sort();
        assert_eq!(got, want, "{cond}");
    }
}

#[test]
fn map_parameter_keys_are_case_insensitive() {
    let mut case = ops_case();
    for key in ["ForwardTo", "forwardto", "FORWARDTO"] {
        let got = hits(
            &mut case,
            &match_rule(
                "ual_events",
                &format!("parameters.{key}: {{contains: evil}}"),
            ),
            T1,
        );
        assert_eq!(got, ids(&[R1]), "{key}");
    }
}

#[test]
fn list_values_are_bound_not_interpolated() {
    let mut case = Case::in_memory().unwrap();
    let values = ["o'brien", "50%", "a_b", "back\\slash", "a.b"];
    let look_alikes = ["axb", "aXb", "500", "backXslash", "obrien"];
    for (i, v) in values.iter().chain(look_alikes.iter()).enumerate() {
        insert_ual(
            &case,
            T1,
            json!({"record_id": format!("00000000-0000-0000-0000-0000000001{i:02}"), "operation": v}),
        );
    }
    let lists = BTreeMap::from([(
        "kw".to_string(),
        values.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    )]);
    let schema = CaseSchema::of(case.conn()).unwrap();
    for op in ["in", "contains_any"] {
        let rule = match_rule("ual_events", &format!("operation: {{{op}: '@list:kw'}}"));
        let c = compile(&rule, &lists, &schema).unwrap();
        for v in values {
            assert!(!c.sql.contains(v), "{v} was interpolated into {}", c.sql);
        }
        assert!(c.lists.contains("kw"));
        let got = run(&mut case, &c, T1, &BTreeMap::new()).unwrap();
        let mut ops: Vec<String> = got.iter().map(|h| h.record_key.clone()).collect();
        ops.sort();
        assert_eq!(ops.len(), values.len(), "{op}: {ops:?}");
        // The five real values, none of the look-alikes.
        let expect: Vec<String> = (0..values.len())
            .map(|i| format!("00000000-0000-0000-0000-0000000001{i:02}"))
            .collect();
        assert_eq!(ops, expect, "{op}");
    }
    // A literal `in` list is bound too.
    let rule = match_rule("ual_events", "operation: {in: [\"o'brien\", \"50%\"]}");
    let c = compile(&rule, &no_lists(), &schema).unwrap();
    assert!(!c.sql.contains("o'brien"));
    assert_eq!(run(&mut case, &c, T1, &BTreeMap::new()).unwrap().len(), 2);
}

#[test]
fn case_sensitive_lists_compare_exactly() {
    let mut case = Case::in_memory().unwrap();
    insert_ual(&case, T1, json!({"record_id": R1, "operation": "BAV2ROPC"}));
    insert_ual(&case, T1, json!({"record_id": R2, "operation": "bav2ropc"}));
    let lists = BTreeMap::from([("ua".to_string(), vec!["BAV2ROPC".to_string()])]);
    let schema = CaseSchema::of(case.conn()).unwrap();
    let rule = match_rule("ual_events", "operation: {in: '@list:ua'}");
    let ci = compile(&rule, &lists, &schema).unwrap();
    assert_eq!(run(&mut case, &ci, T1, &BTreeMap::new()).unwrap().len(), 2);
    let meta = BTreeMap::from([(
        "ua".to_string(),
        ListMeta {
            case_sensitive: true,
        },
    )]);
    let cs = compile_with_meta(&rule, &lists, &meta, &schema).unwrap();
    let got = run(&mut case, &cs, T1, &BTreeMap::new()).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].record_key, R1);
}

#[test]
fn case_iocs_lists_are_run_time_parameters() {
    let mut case = ops_case();
    let rule = match_rule("ual_events", "client_ip: {in: '@list:case_iocs.ip'}");
    let c = compile_on(&case, &rule).unwrap();
    assert!(c.lists.contains("case_iocs.ip"));
    assert!(!c.params.iter().any(|(k, _)| k.starts_with("ioc_")));
    let iocs = BTreeMap::from([("ip".to_string(), vec!["203.0.113.7".to_string()])]);
    let got = run(&mut case, &c, T1, &iocs).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].record_key, R1);
    assert!(run(&mut case, &c, T1, &BTreeMap::new()).unwrap().is_empty());
}

#[test]
fn regex_is_only_used_by_the_regex_operator() {
    let mut case = Case::in_memory().unwrap();
    insert_ual(&case, T1, json!({"record_id": R1, "operation": "a.b"}));
    insert_ual(&case, T1, json!({"record_id": R2, "operation": "axb"}));
    for op in ["eq", "contains", "startswith", "endswith", "in"] {
        let value = if op == "in" { "[\"a.b\"]" } else { "\"a.b\"" };
        let got = hits(
            &mut case,
            &match_rule("ual_events", &format!("operation: {{{op}: {value}}}")),
            T1,
        );
        assert_eq!(got, ids(&[R1]), "{op} must match a.b literally");
    }
    let mut got = hits(
        &mut case,
        &match_rule("ual_events", "operation: {regex: 'a.b'}"),
        T1,
    );
    got.sort();
    assert_eq!(got, ids(&[R1, R2]));
}

#[test]
fn false_text_is_not_true() {
    let mut case = ops_case();
    for v in ["'True'", "true"] {
        let got = hits(
            &mut case,
            &match_rule(
                "ual_events",
                &format!("parameters.DeleteMessage: {{eq: {v}}}"),
            ),
            T1,
        );
        assert_eq!(got, ids(&[R1]), "{v}");
    }
}

#[test]
fn sources_union_keeps_the_output_contract() {
    let mut case = Case::in_memory().unwrap();
    insert_ual(
        &case,
        T1,
        json!({"record_id": "AAAAAAAA-0000-0000-0000-000000000001", "event_time": "2026-03-01T10:00:00Z",
               "operation": "New-InboxRule", "user_upn": "a@x.example", "client_ip": "203.0.113.1"}),
    );
    insert_row(
        &case,
        "admin_audit_events",
        T1,
        json!({"record_key": "aae-1", "run_time": "2026-03-01T09:00:00Z", "cmdlet": "New-InboxRule",
               "caller": "b@x.example", "client_ip": "203.0.113.2"}),
    );
    insert_row(
        &case,
        "admin_audit_events",
        T1,
        json!({"record_key": "aae-2", "run_time": "2026-03-01T09:30:00Z", "cmdlet": "Get-Mailbox"}),
    );
    let rule = rule_from(
        "sources:\n  - source: ual_events\n    match:\n      operation: {eq: new-inboxrule}\n  - source: admin_audit_events\n    match:\n      cmdlet: {eq: new-inboxrule}",
    );
    let c = compile_on(&case, &rule).unwrap();
    let got = run(&mut case, &c, T1, &BTreeMap::new()).unwrap();
    assert_eq!(
        got,
        vec![
            Hit {
                record_key: "aae-1".into(),
                source_table: "admin_audit_events".into(),
                event_epoch: Some(1_772_355_600),
                actor_upn: Some("b@x.example".into()),
                ip: Some("203.0.113.2".into()),
            },
            Hit {
                record_key: "aaaaaaaa-0000-0000-0000-000000000001".into(),
                source_table: "ual_events".into(),
                event_epoch: Some(1_772_359_200),
                actor_upn: Some("a@x.example".into()),
                ip: Some("203.0.113.1".into()),
            },
        ]
    );
    assert_eq!(
        c.tables.iter().cloned().collect::<Vec<_>>(),
        ids(&["admin_audit_events", "ual_events"])
    );
}

#[test]
fn tenant_filter_is_applied_to_every_source() {
    let mut case = Case::in_memory().unwrap();
    for (tenant, n) in [(T1, 1), (T2, 2)] {
        insert_ual(
            &case,
            tenant,
            json!({"record_id": format!("00000000-0000-0000-0000-00000000000{n}"), "operation": "New-InboxRule"}),
        );
        insert_row(
            &case,
            "admin_audit_events",
            tenant,
            json!({"record_key": format!("aae-{tenant}"), "cmdlet": "New-InboxRule"}),
        );
    }
    let rule = rule_from(
        "sources:\n  - source: ual_events\n    match:\n      operation: {eq: new-inboxrule}\n  - source: admin_audit_events\n    match:\n      cmdlet: {eq: new-inboxrule}",
    );
    let mut t1 = hits(&mut case, &rule, T1);
    t1.sort();
    assert_eq!(t1, ids(&["00000000-0000-0000-0000-000000000001", "aae-t1"]));
    let mut t2 = hits(&mut case, &rule, T2);
    t2.sort();
    assert_eq!(t2, ids(&["00000000-0000-0000-0000-000000000002", "aae-t2"]));
    assert!(hits(&mut case, &rule, "nobody").is_empty());
}

fn burst_case(events: &[i64]) -> Case {
    let case = Case::in_memory().unwrap();
    for (i, secs) in events.iter().enumerate() {
        let t = chrono::DateTime::from_timestamp(1_772_000_000 + secs, 0).unwrap();
        insert_ual(
            &case,
            T1,
            json!({"record_id": format!("00000000-0000-0000-0000-{i:012}"),
                   "event_time": t.to_rfc3339(), "operation": "MailItemsAccessed", "user_upn": "a@x.example"}),
        );
    }
    case
}

fn burst_rule() -> Rule {
    rule_from(
        "source: ual_events\nmatch:\n  operation: {eq: MailItemsAccessed}\ngroup_by: [actor_upn]\nthreshold:\n  group_by: [actor_upn]\n  window: 10m\n  count: '>= 50'",
    )
}

#[test]
fn threshold_counts_a_sliding_window() {
    // 49 events inside 10 minutes: no hit.
    let mut case = burst_case(&(0..49).map(|i| i * 10).collect::<Vec<_>>());
    assert!(hits(&mut case, &burst_rule(), T1).is_empty());
    // 50 events inside 10 minutes: every one of them is a hit.
    let mut case = burst_case(&(0..50).map(|i| i * 10).collect::<Vec<_>>());
    assert_eq!(hits(&mut case, &burst_rule(), T1).len(), 50);
    // 50 events spread over 11 minutes (13 s apart): never 50 within any 10 minutes.
    let mut case = burst_case(&(0..50).map(|i| i * 13).collect::<Vec<_>>());
    assert!(hits(&mut case, &burst_rule(), T1).is_empty());
    // A burst plus far-away stragglers: only the burst is a hit.
    let mut times: Vec<i64> = (0..50).map(|i| i * 5).collect();
    times.extend([10_000, 20_000]);
    let mut case = burst_case(&times);
    assert_eq!(hits(&mut case, &burst_rule(), T1).len(), 50);
}

#[test]
fn threshold_groups_do_not_mix() {
    let mut case = Case::in_memory().unwrap();
    for i in 0..60 {
        let t = chrono::DateTime::from_timestamp(1_772_000_000 + i * 5, 0).unwrap();
        let who = if i % 2 == 0 {
            "a@x.example"
        } else {
            "b@x.example"
        };
        insert_ual(
            &case,
            T1,
            json!({"record_id": format!("00000000-0000-0000-0000-{i:012}"),
                   "event_time": t.to_rfc3339(), "operation": "MailItemsAccessed", "user_upn": who}),
        );
    }
    // 30 per user: neither reaches 50, together they would.
    assert!(hits(&mut case, &burst_rule(), T1).is_empty());
}

fn sql_rule(sql: &str) -> Rule {
    let indented: String = sql.lines().map(|l| format!("  {l}\n")).collect();
    rule_from(&format!("sql: |\n{indented}"))
}

#[test]
fn sql_rule_must_be_a_single_select_with_contract_columns() {
    let mut case = Case::in_memory().unwrap();
    insert_ual(
        &case,
        T1,
        json!({"record_id": R1, "event_time": "2026-03-01T10:00:00Z", "operation": "X", "user_upn": "a@x.example"}),
    );
    let good = "SELECT lower(CAST(u.record_id AS VARCHAR)) AS record_key, 'ual_events' AS source_table, u.event_time, u.user_upn AS actor_upn\nFROM ual_events u JOIN collections c USING (collection_id)\nWHERE c.tenant_key = $tenant AND u.operation = 'X'";
    let c = compile_on(&case, &sql_rule(good)).unwrap_or_else(|e| panic!("{e}"));
    let got = run(&mut case, &c, T1, &BTreeMap::new()).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].actor_upn.as_deref(), Some("a@x.example"));
    assert_eq!(got[0].ip, None);

    let bad = [
        (
            "INSERT INTO ual_events (record_id) VALUES (gen_random_uuid()) -- $tenant",
            "not a SELECT",
        ),
        ("SELECT 1; SELECT 2 -- $tenant", "single"),
        (
            "SELECT 'x' AS source_table, now() AS event_time WHERE $tenant IS NOT NULL",
            "record_key",
        ),
        (
            "SELECT 'x' AS record_key, 'ual_events' AS source_table, 'notatime' AS event_time WHERE $tenant IS NOT NULL",
            "event_time",
        ),
        (
            "SELECT 'x' AS record_key, 'ual_events' AS source_table, now() AS event_time FROM nosuchtable WHERE $tenant IS NOT NULL",
            "nosuchtable",
        ),
    ];
    for (sql, want) in bad {
        let err = compile_on(&case, &sql_rule(sql)).unwrap_err().to_string();
        assert!(err.contains(want), "want {want:?} in {err:?} for {sql}");
    }
}

#[test]
fn sql_rule_sees_only_its_tenant_without_a_tenant_predicate() {
    let mut case = Case::in_memory().unwrap();
    insert_ual(&case, T1, json!({"record_id": R1, "operation": "X"}));
    insert_ual(&case, T2, json!({"record_id": R2, "operation": "X"}));
    // Not a single mention of the tenant: the scope is structural.
    let sql = "SELECT lower(CAST(record_id AS VARCHAR)) AS record_key, 'ual_events' AS source_table, event_time FROM ual_events";
    let c = compile_on(&case, &sql_rule(sql)).unwrap_or_else(|e| panic!("{e}"));
    assert!(!c.uses_tenant);
    let mut one = |t| {
        run(&mut case, &c, t, &BTreeMap::new())
            .unwrap()
            .into_iter()
            .map(|h| h.record_key)
            .collect::<Vec<_>>()
    };
    assert_eq!(one(T1), ids(&[R1]));
    assert_eq!(one(T2), ids(&[R2]));
    // A `WHERE $tenant IS NOT NULL` "filter" no longer leaks anything either.
    let c = compile_on(
        &case,
        &sql_rule(&format!("{sql} WHERE $tenant IS NOT NULL")),
    )
    .unwrap();
    assert!(c.uses_tenant);
    assert_eq!(run(&mut case, &c, T1, &BTreeMap::new()).unwrap().len(), 1);
    // Subqueries and joins over other tables are scoped too.
    let sql = "SELECT lower(CAST(u.record_id AS VARCHAR)) AS record_key, 'ual_events' AS source_table, u.event_time FROM ual_events u WHERE u.collection_id IN (SELECT collection_id FROM collections)";
    let c = compile_on(&case, &sql_rule(sql)).unwrap();
    assert_eq!(run(&mut case, &c, T2, &BTreeMap::new()).unwrap().len(), 1);
}

#[test]
fn sql_rules_cannot_name_base_tables_read_files_or_read_unscoped_tables() {
    let case = Case::in_memory().unwrap();
    let head = "SELECT 'x' AS record_key, 'ual_events' AS source_table, now() AS event_time";
    let cases = [
        (format!("{head} FROM main.ual_events"), "schema-qualified"),
        (
            format!("{head} FROM memory.main.ual_events"),
            "schema-qualified",
        ),
        (
            format!("{head} FROM temp.main.ual_events"),
            "schema-qualified",
        ),
        (format!("{head} FROM timeline"), "no tenant scope"),
        (format!("{head} FROM record_sources"), "no tenant scope"),
        (format!("{head} FROM read_csv('/etc/hosts')"), "read_csv"),
        (format!("{head} FROM read_json('/etc/hosts')"), "read_json"),
        (
            format!("{head} FROM read_parquet('/etc/x.parquet')"),
            "read_parquet",
        ),
        (format!("{head} FROM glob('/etc/*')"), "glob"),
        (
            format!("{head} FROM query_table('ual_events')"),
            "query_table",
        ),
        (format!("{head} FROM duckdb_tables()"), "duckdb_tables"),
        ("ATTACH '/tmp/zz.db' AS z".to_string(), "not a SELECT"),
        (
            "COPY ual_events TO '/tmp/zz.csv'".to_string(),
            "not a SELECT",
        ),
    ];
    for (sql, want) in cases {
        let err = compile_on(&case, &sql_rule(&sql)).unwrap_err().to_string();
        assert!(err.contains(want), "want {want:?} in {err:?} for {sql}");
    }
    // The allow-listed table functions and the global reference tables are fine.
    let ok = "SELECT CAST(i AS VARCHAR) AS record_key, 'ual_events' AS source_table, now() AS event_time FROM range(3) t(i), ip_intel";
    compile_on(&case, &sql_rule(ok)).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn sql_rule_lists_and_case_iocs_expand_to_bound_parameters() {
    let mut case = Case::in_memory().unwrap();
    insert_ual(
        &case,
        T1,
        json!({"record_id": R1, "operation": "New-InboxRule", "client_ip": "203.0.113.7"}),
    );
    insert_ual(
        &case,
        T1,
        json!({"record_id": R2, "operation": "Other", "client_ip": "203.0.113.8"}),
    );
    let lists = BTreeMap::from([("ops".to_string(), vec!["new-inboxrule".to_string()])]);
    let schema = CaseSchema::of(case.conn()).unwrap();
    let sql = "SELECT lower(CAST(u.record_id AS VARCHAR)) AS record_key, 'ual_events' AS source_table, u.event_time\nFROM ual_events u JOIN collections c USING (collection_id)\nWHERE c.tenant_key = $tenant AND list_contains(@list:ops, lower(u.operation))\n  AND (u.client_ip IN (SELECT unnest(@list:case_iocs.ip)) OR true)";
    let c = compile(&sql_rule(sql), &lists, &schema).unwrap_or_else(|e| panic!("{e}"));
    assert!(c.lists.contains("ops") && c.lists.contains("case_iocs.ip"));
    let got = run(&mut case, &c, T1, &BTreeMap::new()).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].record_key, R1);
    let err = compile(
        &sql_rule(&sql.replace("@list:ops", "@list:nope")),
        &lists,
        &schema,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("nope"), "{err}");
}

#[test]
fn unsupported_shapes_are_compile_errors() {
    let case = Case::in_memory().unwrap();
    let cases = [
        (
            match_rule("mail_items_accessed", "user_upn: {eq: a}"),
            "mail_items_accessed",
        ),
        (match_rule("nosuchtable", "a: {eq: a}"), "nosuchtable"),
        (match_rule("ual_events", "nosuchcol: {eq: a}"), "nosuchcol"),
        (
            match_rule("ual_events", "client_ip: {cidr: '2001:db8::/32'}"),
            "IPv6",
        ),
        (match_rule("ual_events", "operation: {regex: '('}"), "regex"),
        (
            match_rule("ual_events", "operation: {contains: ''}"),
            "empty",
        ),
        (
            match_rule("ual_events", "operation: {in: '@list:missing'}"),
            "missing",
        ),
        (match_rule("ual_events", "parameters: {eq: a}"), "MAP"),
        (
            match_rule("ual_events", "operation: {gt: abc}"),
            "operation",
        ),
    ];
    for (rule, want) in cases {
        let err = compile_on(&case, &rule).unwrap_err().to_string();
        assert!(err.contains(want), "want {want:?} in {err:?}");
    }
}

fn loaded(rule: Rule) -> LoadedRule {
    LoadedRule {
        path: format!("test:{}", rule.id),
        sha256: String::new(),
        rule,
    }
}

fn set_of(rules: Vec<Rule>) -> RuleSet {
    RuleSet {
        rules: rules.into_iter().map(loaded).collect(),
        lists: BTreeMap::new(),
        list_meta: BTreeMap::new(),
        warnings: vec![],
    }
}

fn with_id(mut r: Rule, id: &str) -> Rule {
    r.id = id.to_string();
    r
}

fn errors(issues: &[LintIssue]) -> Vec<String> {
    issues
        .iter()
        .filter(|i| i.severity == LintSeverity::Error)
        .map(|i| format!("{}: {}", i.rule_id, i.message))
        .collect()
}

#[test]
fn lint_rejects_unknown_column_and_list() {
    let case = Case::in_memory().unwrap();
    let schema = CaseSchema::of(case.conn()).unwrap();
    let mut no_tests = with_id(match_rule("ual_events", "operation: {eq: a}"), "SPW-T-006");
    no_tests.tests.clear();
    let mut only_positive = with_id(match_rule("ual_events", "operation: {eq: a}"), "SPW-T-007");
    only_positive.tests.truncate(1);
    let mut bad_group = with_id(match_rule("ual_events", "operation: {eq: a}"), "SPW-T-008");
    bad_group.group_by = vec!["operation".into()];
    let set = set_of(vec![
        with_id(match_rule("ual_events", "typo_col: {eq: a}"), "SPW-T-001"),
        with_id(
            match_rule("ual_events", "operation: {in: '@list:nope'}"),
            "SPW-T-002",
        ),
        with_id(match_rule("no_table", "a: {eq: a}"), "SPW-T-003"),
        with_id(
            match_rule("ual_events", "operation: {regex: '('}"),
            "SPW-T-004",
        ),
        with_id(sql_rule("SELECT 1 AS record_key"), "SPW-T-005"),
        no_tests,
        only_positive,
        bad_group,
        with_id(match_rule("ual_events", "operation: {eq: a}"), "SPW-T-009"),
        with_id(match_rule("ual_events", "operation: {eq: a}"), "SPW-T-009"),
    ]);
    let issues = errors(&lint(&set, &schema, None));
    let has = |id: &str, needle: &str| {
        assert!(
            issues
                .iter()
                .any(|m| m.starts_with(id) && m.contains(needle)),
            "{id} {needle}: {issues:#?}"
        )
    };
    has("SPW-T-001", "typo_col");
    has("SPW-T-002", "nope");
    has("SPW-T-003", "no_table");
    has("SPW-T-004", "regex");
    has("SPW-T-005", "record_key");
    has("SPW-T-006", "positive");
    has("SPW-T-006", "look-alike");
    has("SPW-T-007", "look-alike");
    has("SPW-T-008", "group_by");
    has("SPW-T-009", "duplicate");
    assert!(
        !issues
            .iter()
            .any(|m| m.starts_with("SPW-T-007") && m.contains("positive"))
    );
}

#[test]
fn lint_cross_checks_the_coverage_matrix() {
    let case = Case::in_memory().unwrap();
    let schema = CaseSchema::of(case.conn()).unwrap();
    let cov_rule = |id: &str, tables: &str, requires: &str| {
        format!(
            "  - id: {id}\n    title: t\n    category: mail\n    severity: high\n    hawk: null\n    logic: l\n    tables: {tables}\n    requires: {requires}\n    requires_evidence: []\n    needs_geoip: false\n    collectors: [hawk4]\n    positives: [a]\n    lookalikes: [b]\n"
        )
    };
    let text = format!(
        "version: 1\nrules:\n{}{}{}{}",
        cov_rule("SPW-T-001", "[ual_events]", "[]"),
        cov_rule("SPW-T-002", "[admin_audit_events, ual_events]", "[]"),
        cov_rule("SPW-T-003", "[ual_events]", "[exchange_audit]"),
        cov_rule("SPW-T-099", "[ual_events]", "[]"),
    );
    let cov = CoverageMatrix::from_yaml(&text).unwrap();
    let mut r1 = with_id(match_rule("ual_events", "operation: {eq: a}"), "SPW-T-001");
    r1.requires_evidence = vec!["ual".into()];
    let r2 = with_id(match_rule("ual_events", "operation: {eq: a}"), "SPW-T-002");
    let r3 = with_id(match_rule("ual_events", "operation: {eq: a}"), "SPW-T-003");
    let r4 = with_id(match_rule("ual_events", "operation: {eq: a}"), "SPW-T-004");
    let mut set = set_of(vec![r1, r2, r3, r4]);
    for r in &mut set.rules {
        r.path = format!("builtin:mail/{}.yaml", r.rule.id);
    }
    let issues = lint(&set, &schema, Some(&cov));
    let errs = errors(&issues);
    let has = |id: &str, needle: &str| {
        assert!(
            errs.iter().any(|m| m.starts_with(id) && m.contains(needle)),
            "{id} {needle}: {errs:#?}"
        )
    };
    has("SPW-T-001", "requires_evidence");
    has("SPW-T-002", "first");
    has("SPW-T-003", "requires");
    has("SPW-T-004", "no coverage entry");
    // A coverage entry with no rule file is an error, not a warning: the seed pack is
    // complete, so a gap is a mistake to fix, not a note for later.
    let warn: Vec<_> = issues
        .iter()
        .filter(|i| i.severity == LintSeverity::Warning)
        .collect();
    assert!(
        !warn.iter().any(|i| i.rule_id == "SPW-T-099"),
        "a coverage entry without a rule file is still only a warning"
    );
    has("SPW-T-099", "no rule file");
}

#[test]
fn builtin_rules_lint_clean() {
    let case = Case::in_memory().unwrap();
    let schema = CaseSchema::of(case.conn()).unwrap();
    let set = load_rules(&DataDirs::default()).unwrap();
    let cov = CoverageMatrix::builtin().unwrap();
    let issues = lint(&set, &schema, Some(&cov));
    assert_eq!(errors(&issues), Vec::<String>::new());
    assert!(set.rules.iter().any(|r| r.rule.id == "SPW-ID-010"));
}

#[test]
fn builtin_rules_without_a_stage_are_listed_by_lint() {
    let case = Case::in_memory().unwrap();
    let schema = CaseSchema::of(case.conn()).unwrap();
    let set = load_rules(&DataDirs::default()).unwrap();
    let cov = CoverageMatrix::builtin().unwrap();
    let issues = lint(&set, &schema, Some(&cov));
    let mut no_stage: Vec<&str> = issues
        .iter()
        .filter(|i| i.severity == LintSeverity::Warning && i.message.starts_with("no stage:"))
        .map(|i| i.rule_id.as_str())
        .collect();
    no_stage.sort();
    let mut want: Vec<&str> = set
        .rules
        .iter()
        .filter(|r| r.rule.stage.is_empty())
        .map(|r| r.rule.id.as_str())
        .collect();
    want.sort();
    assert_eq!(no_stage, want);
    assert_eq!(
        no_stage,
        [
            "SPW-CFG-001",
            "SPW-FILE-001",
            "SPW-FILE-002",
            "SPW-FILE-003",
            "SPW-HAWK-008",
            "SPW-HAWK-014",
            "SPW-HAWK-015",
            "SPW-ID-006",
            // Inbound mail is not a compromise stage (ruling R21, like SPW-HAWK-014).
            "SPW-MAIL-009"
        ]
    );
}

#[test]
fn shipped_rule_samples_pass_their_inline_tests() {
    let set = load_rules(&DataDirs::default()).unwrap();
    let results = sparrow_core::detect::test::run_inline_tests(&set, None).unwrap();
    assert!(results.len() >= 9, "{results:#?}");
    for r in &results {
        assert!(r.ok, "{r:#?}");
    }
    for id in ["SPW-HAWK-011", "SPW-ID-010", "SPW-MAIL-005"] {
        assert!(results.iter().any(|r| r.rule_id == id), "{id}");
    }
}

#[test]
fn hit_times_fall_back_like_the_timeline() {
    let mut case = Case::in_memory().unwrap();
    // Activity happened before the detection: the hit time is the activity time.
    insert_row(
        &case,
        "risk_detections",
        T1,
        json!({"record_key": "rd-1", "activity_time": "2026-03-01T09:00:00Z",
               "detected_time": "2026-03-01T10:00:00Z", "risk_level": "high"}),
    );
    insert_row(
        &case,
        "risk_detections",
        T1,
        json!({"record_key": "rd-2", "detected_time": "2026-03-01T10:30:00Z", "risk_level": "high"}),
    );
    insert_row(
        &case,
        "security_alerts",
        T1,
        json!({"record_key": "sa-1", "event_time": "2026-03-01T08:00:00Z",
               "created_time": "2026-03-01T11:00:00Z", "severity": "high"}),
    );
    insert_row(
        &case,
        "security_alerts",
        T1,
        json!({"record_key": "sa-2", "created_time": "2026-03-01T11:30:00Z", "severity": "high"}),
    );
    let mut epoch = |table: &str, col: &str| {
        let c = compile_on(&case, &match_rule(table, &format!("{col}: {{eq: high}}"))).unwrap();
        run(&mut case, &c, T1, &BTreeMap::new())
            .unwrap()
            .into_iter()
            .map(|h| (h.record_key, h.event_epoch.unwrap()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        epoch("risk_detections", "risk_level"),
        vec![
            ("rd-1".to_string(), 1_772_355_600),
            ("rd-2".to_string(), 1_772_361_000)
        ]
    );
    assert_eq!(
        epoch("security_alerts", "severity"),
        vec![
            ("sa-1".to_string(), 1_772_352_000),
            ("sa-2".to_string(), 1_772_362_800 + 1800)
        ]
    );
}

#[test]
fn cidr_validates_octets_and_normalises_mapped_addresses_and_ports() {
    let mut case = Case::in_memory().unwrap();
    let ips = [
        ("00000000-0000-0000-0000-0000000000a1", "203.0.113.5"),
        ("00000000-0000-0000-0000-0000000000a2", "203.0.113.999"),
        ("00000000-0000-0000-0000-0000000000a3", "::ffff:203.0.113.5"),
        ("00000000-0000-0000-0000-0000000000a4", "203.0.113.5:443"),
        (
            "00000000-0000-0000-0000-0000000000a5",
            "[::ffff:203.0.113.5]:443",
        ),
        ("00000000-0000-0000-0000-0000000000a6", "2001:db8::5"),
        ("00000000-0000-0000-0000-0000000000a7", "203.0.113.5.7"),
        ("00000000-0000-0000-0000-0000000000a8", "203.0.113"),
        ("00000000-0000-0000-0000-0000000000a9", "::FFFF:203.0.113.6"),
        ("00000000-0000-0000-0000-0000000000b0", "203.0.114.5"),
    ];
    for (id, ip) in ips {
        insert_ual(&case, T1, json!({"record_id": id, "client_ip": ip}));
    }
    let mut got = |cidr: &str| {
        let mut h = hits(
            &mut case,
            &match_rule("ual_events", &format!("client_ip: {{cidr: {cidr}}}")),
            T1,
        );
        h.sort();
        h.into_iter()
            .map(|k| k[k.len() - 2..].to_string())
            .collect::<Vec<_>>()
    };
    // 999 is not an address: it never becomes 203.0.114.243 or anything else.
    assert_eq!(got("203.0.113.5/32"), ["a1", "a3", "a4", "a5"]);
    assert_eq!(got("203.0.113.0/24"), ["a1", "a3", "a4", "a5", "a9"]);
    assert_eq!(got("203.0.114.0/24"), ["b0"]);
    assert_eq!(got("203.0.114.243/32"), Vec::<String>::new());
}

#[test]
fn absence_is_explicit_missing_values_never_match_a_negated_comparison() {
    let mut case = Case::in_memory().unwrap();
    insert_row(
        &case,
        "mailboxes",
        T1,
        json!({"upn": "fwd-ok@x.example", "forwarding_smtp_address": "approved@x.example"}),
    );
    insert_row(
        &case,
        "mailboxes",
        T1,
        json!({"upn": "fwd-bad@x.example", "forwarding_smtp_address": "evil@example.net"}),
    );
    insert_row(&case, "mailboxes", T1, json!({"upn": "none@x.example"}));
    let mut actors = |cond: &str| {
        let c = compile_on(&case, &match_rule("mailboxes", cond)).unwrap();
        run(&mut case, &c, T1, &BTreeMap::new())
            .unwrap()
            .into_iter()
            .filter_map(|h| h.actor_upn)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    };
    // "Forwards anywhere except the approved address" does not match a mailbox with no forwarding.
    let except = "all:\n  - forwarding_smtp_address: {exists: true}\n  - forwarding_smtp_address: {neq: approved@x.example}";
    assert_eq!(actors(except), ["fwd-bad@x.example"]);
    assert_eq!(
        actors("forwarding_smtp_address: {neq: approved@x.example}"),
        ["fwd-bad@x.example"]
    );
    assert_eq!(
        actors("not:\n  forwarding_smtp_address: {eq: approved@x.example}"),
        ["fwd-bad@x.example"]
    );
    // Absence is spelled out.
    assert_eq!(
        actors("forwarding_smtp_address: {exists: false}"),
        ["none@x.example"]
    );
    assert_eq!(
        actors(
            "any:\n  - forwarding_smtp_address: {exists: false}\n  - forwarding_smtp_address: {eq: evil@example.net}"
        ),
        ["fwd-bad@x.example", "none@x.example"]
    );
}

#[test]
fn lint_checks_the_emitted_source_tables_of_sql_rules() {
    let case = Case::in_memory().unwrap();
    let schema = CaseSchema::of(case.conn()).unwrap();
    let cov = |tables: &str| {
        CoverageMatrix::from_yaml(&format!(
            "version: 1\nrules:\n  - id: SPW-T-001\n    title: t\n    category: mail\n    severity: high\n    hawk: null\n    logic: l\n    tables: {tables}\n    requires: []\n    requires_evidence: []\n    needs_geoip: false\n    collectors: [hawk4]\n    positives: [a]\n    lookalikes: [b]\n"
        ))
        .unwrap()
    };
    let sql = "SELECT 'x' AS record_key, 'ual_events' AS source_table, now() AS event_time\nUNION ALL\nSELECT 'y', 'signins', now()";
    let mut set = set_of(vec![with_id(sql_rule(sql), "SPW-T-001")]);
    set.rules[0].path = "builtin:identity/SPW-T-001.yaml".into();
    let errs = |tables: &str| errors(&lint(&set, &schema, Some(&cov(tables))));
    assert_eq!(errs("[ual_events, signins]"), Vec::<String>::new());
    assert!(
        errs("[ual_events]")
            .iter()
            .any(|m| m.contains("emits source_table signins"))
    );
    assert!(
        errs("[admin_audit_events, ual_events, signins]")
            .iter()
            .any(|m| m.contains("first coverage table"))
    );
}

#[test]
fn sql_rule_source_table_must_be_a_static_literal() {
    let case = Case::in_memory().unwrap();
    let with = |expr: &str| {
        sql_rule(&format!(
            "SELECT 'x' AS record_key, {expr} AS source_table, now() AS event_time, operation FROM ual_events"
        ))
    };
    let ok = [
        ("'ual_events'", vec!["ual_events"]),
        (
            "CASE WHEN operation = 'a' THEN 'ual_events' ELSE 'signins' END",
            vec!["signins", "ual_events"],
        ),
        (
            "CASE WHEN operation = 'a' THEN 'ual_events' WHEN operation = 'b' THEN 'signins' ELSE 'mailboxes' END",
            vec!["mailboxes", "signins", "ual_events"],
        ),
    ];
    for (expr, want) in ok {
        let c = compile_on(&case, &with(expr)).unwrap_or_else(|e| panic!("{expr}: {e}"));
        assert_eq!(
            c.emitted_tables.iter().cloned().collect::<Vec<_>>(),
            want,
            "{expr}"
        );
    }
    let bad = [
        ("operation", "string literal"),
        ("lower(operation)", "string literal"),
        ("'ual_' || 'events'", "string literal"),
        (
            "CASE WHEN operation = 'a' THEN 'ual_events' ELSE operation END",
            "string literal",
        ),
        (
            "CASE WHEN operation = 'a' THEN 'ual_events' END",
            "string literal",
        ),
        ("CAST('ual_events' AS VARCHAR)", "string literal"),
        ("'nosuchtable'", "not a hit table"),
        ("CAST(NULL AS VARCHAR)", "string literal"),
    ];
    for (expr, want) in bad {
        let err = compile_on(&case, &with(expr)).unwrap_err().to_string();
        assert!(err.contains(want), "{expr}: want {want:?} in {err:?}");
    }
    // Lint reports it as an error, not a warning.
    let schema = CaseSchema::of(case.conn()).unwrap();
    let set = set_of(vec![with_id(with("operation"), "SPW-T-001")]);
    assert!(
        errors(&lint(&set, &schema, None))
            .iter()
            .any(|m| m.contains("string literal"))
    );
    // A UNION arm with a non-literal is rejected too.
    let sql = "SELECT 'x' AS record_key, 'ual_events' AS source_table, now() AS event_time\nUNION ALL\nSELECT 'y', operation, now() FROM ual_events";
    assert!(
        compile_on(&case, &sql_rule(sql))
            .unwrap_err()
            .to_string()
            .contains("string literal")
    );
}

#[test]
fn mia_item_volume_alone_is_a_burst() {
    let set = load_rules(&DataDirs::default()).unwrap();
    let rule = &set
        .rules
        .iter()
        .find(|r| r.rule.id == "SPW-MAIL-005")
        .unwrap()
        .rule;
    for (items, want) in [(99, 0), (100, 1)] {
        let mut case = Case::in_memory().unwrap();
        // The burst must come from a foreign network: a hosting ASN needs no sign-in history.
        insert_row(
            &case,
            "ip_intel",
            T1,
            json!({"ip": "203.0.113.9", "asn": 64500, "is_hosting": true,
                   "is_microsoft": false, "is_private": false}),
        );
        insert_ual(
            &case,
            T1,
            json!({"record_id": R1, "operation": "MailItemsAccessed", "user_upn": "v@x.example",
                   "client_ip": "203.0.113.9", "event_time": "2026-03-01T10:00:00Z"}),
        );
        for i in 0..items {
            insert_row(
                &case,
                "mail_items_accessed",
                T1,
                json!({"record_id": R1, "item_ordinal": i, "access_type": "bind"}),
            );
        }
        let schema = CaseSchema::of(case.conn()).unwrap();
        let c = compile_with_meta(rule, &set.lists, &set.list_meta, &schema).unwrap();
        assert_eq!(
            run(&mut case, &c, T1, &BTreeMap::new()).unwrap().len(),
            want,
            "{items} items"
        );
    }
}

/// SPW-MAIL-007's hit key is the UAL record id, so both the side-table path and the AuditData
/// path cite `ual_events` (search_queries is derived from it).
#[test]
fn search_hits_always_cite_the_ual_record() {
    let set = load_rules(&DataDirs::default()).unwrap();
    let rule = &set
        .rules
        .iter()
        .find(|r| r.rule.id == "SPW-MAIL-007")
        .unwrap()
        .rule;
    let mut case = Case::in_memory().unwrap();
    // Path 1: the text comes from the search_queries row.
    insert_ual(
        &case,
        T1,
        json!({"record_id": R1, "operation": "SearchQueryInitiatedExchange",
               "user_upn": "v@x.example", "event_time": "2026-03-01T10:00:00Z"}),
    );
    insert_row(
        &case,
        "search_queries",
        T1,
        json!({"record_id": R1, "workload": "exchange", "query_text": "invoice payment"}),
    );
    // Path 2: no side-table row; the text is read from the record's own AuditData.
    insert_ual(
        &case,
        T1,
        json!({"record_id": R2, "operation": "SearchQueryInitiatedExchange",
               "user_upn": "v@x.example", "event_time": "2026-03-01T11:00:00Z",
               "audit_data": {"QueryText": "bank details"}}),
    );
    let schema = CaseSchema::of(case.conn()).unwrap();
    let c = compile_with_meta(rule, &set.lists, &set.list_meta, &schema).unwrap();
    let hits = run(&mut case, &c, T1, &BTreeMap::new()).unwrap();
    let got: Vec<(&str, &str)> = hits
        .iter()
        .map(|h| (h.record_key.as_str(), h.source_table.as_str()))
        .collect();
    assert_eq!(got, vec![(R1, "ual_events"), (R2, "ual_events")]);
}
