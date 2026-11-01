//! Case notebooks: storage, who may write what, and the audit trail.

use sparrow_core::Case;
use sparrow_core::case::actor::Actor;
use sparrow_core::case::audit;
use sparrow_core::case::notebooks::{self, BUILTIN_ID};

fn case() -> (tempfile::TempDir, Case) {
    let dir = tempfile::tempdir().unwrap();
    let c = Case::create_or_open(&dir.path().join("case.duckdb")).unwrap();
    (dir, c)
}

fn analyst() -> Actor {
    Actor::analyst("carlos").unwrap()
}

fn agent() -> Actor {
    Actor::agent("claude", Some("carlos")).unwrap()
}

fn err(r: sparrow_core::Result<impl std::fmt::Debug>) -> String {
    r.unwrap_err().to_string()
}

#[test]
fn a_new_case_lists_only_the_builtin_notebook() {
    let (_d, c) = case();
    let l = notebooks::list(c.conn()).unwrap();
    assert_eq!(l.len(), 1);
    assert!(l[0].builtin);
    assert_eq!(l[0].notebook_id, BUILTIN_ID);
    assert_eq!(l[0].name, "Built-in");
}

#[test]
fn an_agent_can_create_and_add_and_the_query_records_who() {
    let (_d, c) = case();
    let (nb, _) = notebooks::create_notebook(c.conn(), &agent(), "Triage").unwrap();
    notebooks::add_query(c.conn(), &agent(), &nb, "-- Hosts\nSELECT '[ip]'").unwrap();
    let l = notebooks::list(c.conn()).unwrap();
    let t = l.iter().find(|n| n.notebook_id == nb).unwrap();
    assert!(!t.builtin);
    let q = &t.queries[0];
    assert_eq!(q.title, "Hosts");
    assert_eq!(q.placeholders, ["ip"]);
    assert_eq!(q.position, 1);
    assert_eq!(q.decided_by.as_deref(), Some("agent:claude"));
    assert_eq!(q.on_behalf_of.as_deref(), Some("analyst:carlos"));
    assert!(q.decided_at.is_some());
    let actions: Vec<String> = audit::log(c.conn(), None)
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    let i = actions.iter().position(|a| a == "create_notebook").unwrap();
    assert_eq!(actions[i + 1], "add_notebook_query");
}

#[test]
fn the_builtin_notebook_is_never_written() {
    let (_d, c) = case();
    let a = analyst();
    let m = err(notebooks::add_query(c.conn(), &a, BUILTIN_ID, "SELECT 1"));
    assert!(m.contains("the built-in notebook cannot be changed"), "{m}");
    for m in [
        err(notebooks::rename_notebook(c.conn(), &a, BUILTIN_ID, "x")),
        err(notebooks::rename_notebook(c.conn(), &a, "Built-in", "x")),
        err(notebooks::delete_notebook(c.conn(), &a, BUILTIN_ID)),
        err(notebooks::delete_notebook(c.conn(), &a, "built-in")),
        err(notebooks::add_query(c.conn(), &a, "Built-in", "SELECT 1")),
        err(notebooks::delete_query(c.conn(), &a, "builtin:anything")),
        err(notebooks::move_query(c.conn(), &a, "builtin:anything", 1)),
        err(notebooks::create_notebook(c.conn(), &a, "built-in")),
    ] {
        assert!(m.contains("the built-in notebook cannot be changed"), "{m}");
    }
}

#[test]
fn only_the_analyst_renames_reorders_and_deletes() {
    let (_d, c) = case();
    let (nb, _) = notebooks::create_notebook(c.conn(), &agent(), "Triage").unwrap();
    let mut ids = Vec::new();
    for n in 1..=3 {
        ids.push(
            notebooks::add_query(c.conn(), &agent(), &nb, &format!("SELECT {n}"))
                .unwrap()
                .0,
        );
    }
    let g = agent();
    for m in [
        err(notebooks::rename_notebook(c.conn(), &g, &nb, "New")),
        err(notebooks::move_query(c.conn(), &g, &ids[2], 1)),
        err(notebooks::delete_query(c.conn(), &g, &ids[0])),
        err(notebooks::delete_notebook(c.conn(), &g, &nb)),
    ] {
        assert!(m.contains("only the analyst can"), "{m}");
    }
    let a = analyst();
    notebooks::move_query(c.conn(), &a, &ids[2], 1).unwrap();
    let order = |c: &Case| -> Vec<(u32, String)> {
        let l = notebooks::list(c.conn()).unwrap();
        l.into_iter()
            .find(|n| n.notebook_id == nb)
            .unwrap()
            .queries
            .into_iter()
            .map(|q| (q.position, q.title))
            .collect()
    };
    assert_eq!(
        order(&c),
        [
            (1, "SELECT 3".to_string()),
            (2, "SELECT 1".to_string()),
            (3, "SELECT 2".to_string())
        ]
    );
    notebooks::delete_query(c.conn(), &a, &ids[0]).unwrap();
    assert_eq!(
        order(&c),
        [(1, "SELECT 3".to_string()), (2, "SELECT 2".to_string())]
    );
    notebooks::rename_notebook(c.conn(), &a, &nb, "Renamed").unwrap();
    assert!(notebooks::find_query(c.conn(), "renamed", "1").is_ok());
    notebooks::delete_notebook(c.conn(), &a, &nb).unwrap();
    assert_eq!(notebooks::list(c.conn()).unwrap().len(), 1);
}

#[test]
fn names_are_unique_and_queries_capped() {
    let (_d, c) = case();
    let a = analyst();
    let (nb, _) = notebooks::create_notebook(c.conn(), &a, "Triage").unwrap();
    assert!(err(notebooks::create_notebook(c.conn(), &a, "triage")).contains("already exists"));
    for n in 0..200 {
        notebooks::add_query(c.conn(), &a, &nb, &format!("SELECT {n}")).unwrap();
    }
    let m = err(notebooks::add_query(c.conn(), &a, &nb, "SELECT 201"));
    assert!(m.contains("limited to 200 queries"), "{m}");
}

#[test]
fn find_query_by_name_and_position() {
    let (_d, c) = case();
    let a = analyst();
    let (nb, _) = notebooks::create_notebook(c.conn(), &a, "Triage").unwrap();
    notebooks::add_query(c.conn(), &a, &nb, "SELECT 1").unwrap();
    let (q2, _) = notebooks::add_query(c.conn(), &a, &nb, "-- Two\nSELECT 2").unwrap();
    let q = notebooks::find_query(c.conn(), "TRIAGE", "2").unwrap();
    assert_eq!(q.sql, "-- Two\nSELECT 2");
    assert_eq!(q.notebook_id, nb);
    assert_eq!(
        notebooks::find_query(c.conn(), &nb, &q2)
            .unwrap()
            .summary
            .title,
        "Two"
    );
    assert!(err(notebooks::find_query(c.conn(), "nope", "1")).contains("unknown notebook"));
    assert!(err(notebooks::find_query(c.conn(), "Triage", "9")).contains("has no query"));
}

fn names(c: &Case) -> Vec<String> {
    notebooks::list(c.conn())
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .collect()
}

#[test]
fn export_then_import_round_trips_into_a_new_notebook() {
    let (_d, c) = case();
    let a = analyst();
    let (nb, _) = notebooks::create_notebook(c.conn(), &a, "Triage").unwrap();
    notebooks::add_query(c.conn(), &a, &nb, "-- One\nSELECT 1").unwrap();
    notebooks::add_query(c.conn(), &a, &nb, "SELECT 2").unwrap();
    let text = notebooks::export_text(c.conn(), "Triage", "0.1.0").unwrap();
    let (id, e) = notebooks::import_text(c.conn(), &agent(), &text).unwrap();
    assert_eq!(e.action, "import_notebook");
    let (_, name, qs) = notebooks::notebook_queries(c.conn(), &id).unwrap();
    assert_eq!(name, "Triage (2)");
    let sqls: Vec<&str> = qs.iter().map(|q| q.sql.as_str()).collect();
    assert_eq!(sqls, ["-- One\nSELECT 1", "SELECT 2"]);
    assert_eq!(qs[0].summary.decided_by.as_deref(), Some("agent:claude"));
    notebooks::import_text(c.conn(), &a, &text).unwrap();
    assert_eq!(
        names(&c),
        ["Built-in", "Triage", "Triage (2)", "Triage (3)"]
    );
}

#[test]
fn exporting_the_builtin_works_and_importing_it_makes_a_case_copy() {
    let (_d, c) = case();
    let text = notebooks::export_text(c.conn(), BUILTIN_ID, "0.1.0").unwrap();
    assert!(text.starts_with("-- sparrow notebook: Built-in\n"));
    let (id, _) = notebooks::import_text(c.conn(), &analyst(), &text).unwrap();
    let (_, name, qs) = notebooks::notebook_queries(c.conn(), &id).unwrap();
    assert_eq!(name, "Built-in (copy)");
    assert_eq!(qs.len(), 12);
}

#[test]
fn a_bad_import_writes_nothing() {
    let (_d, c) = case();
    let before = audit::log(c.conn(), None).unwrap().len();
    let marker = notebooks::MARKER;
    let big = format!(
        "-- sparrow notebook: x\n{marker}\nSELECT 1\n{marker}\n{}",
        "x".repeat(65_537)
    );
    assert!(notebooks::import_text(c.conn(), &analyst(), &big).is_err());
    let huge = format!(
        "-- sparrow notebook: x\n{marker}\n{}",
        "x".repeat(4 * 1024 * 1024)
    );
    let m = err(notebooks::import_text(c.conn(), &analyst(), &huge));
    assert!(m.contains("limited to 4 MiB"), "{m}");
    assert_eq!(names(&c), ["Built-in"]);
    assert_eq!(audit::log(c.conn(), None).unwrap().len(), before);
}

#[test]
fn case_values_are_found() {
    let (_d, c) = case();
    c.conn()
        .execute_batch(
            "INSERT INTO events (source_table, record_key, source, category, actor_upn, ip, ip_prefix, device_id)
             VALUES ('ual_events', 'k1', 'ual', 'other', 'jane@contoso.example', '203.0.113.7', '203.0.113.0/24',
                     '0f8fad5b-d9cb-469f-a165-70867728950e');
             INSERT INTO tenant_domains VALUES ('t1', 'contoso.example', 'derived_upn', 1);",
        )
        .unwrap();
    let q = |id: &str, sql: &str| (id.to_string(), sql.to_string());
    let hits = notebooks::case_values_in(
        c.conn(),
        &[
            q(
                "a",
                "-- By account\nSELECT * FROM events WHERE actor_upn = 'JANE@contoso.example'",
            ),
            q("b", "SELECT * FROM events WHERE ip LIKE '203.0.113.%'"),
            q(
                "c",
                "SELECT * FROM events WHERE device_id = '0F8FAD5B-D9CB-469F-A165-70867728950E'",
            ),
            q(
                "d",
                "SELECT '[account]', '198.51.100.9', 'bob@fabrikam.example'",
            ),
        ],
    )
    .unwrap();
    let by: std::collections::HashMap<&str, &Vec<String>> = hits
        .iter()
        .map(|h| (h.query_id.as_str(), &h.values))
        .collect();
    assert_eq!(hits.len(), 3, "{hits:?}");
    assert_eq!(
        by["a"],
        &vec![
            "contoso.example".to_string(),
            "jane@contoso.example".to_string()
        ]
    );
    assert_eq!(
        hits.iter().find(|h| h.query_id == "a").unwrap().title,
        "By account"
    );
    assert_eq!(by["b"], &vec!["203.0.113.0/24".to_string()]);
    assert_eq!(
        by["c"],
        &vec!["0f8fad5b-d9cb-469f-a165-70867728950e".to_string()]
    );
}

#[test]
fn builtin_queries_hold_no_case_values() {
    let (_d, c) = case();
    c.conn()
        .execute_batch(
            "INSERT INTO events (source_table, record_key, source, category, actor_upn, ip, ip_prefix)
             VALUES ('ual_events', 'k1', 'ual', 'other', 'jane@contoso.example', '203.0.113.7', '203.0.113.0/24');
             INSERT INTO tenant_domains VALUES ('t1', 'contoso.example', 'derived_upn', 1);",
        )
        .unwrap();
    let (_, _, qs) = notebooks::notebook_queries(c.conn(), BUILTIN_ID).unwrap();
    let pairs: Vec<(String, String)> = qs
        .into_iter()
        .map(|q| (q.summary.query_id, q.sql))
        .collect();
    assert!(
        notebooks::case_values_in(c.conn(), &pairs)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn repeated_imports_of_a_max_length_name_stay_unique() {
    let (_d, c) = case();
    let name = "n".repeat(500);
    let text = format!(
        "-- sparrow notebook: {name}\n{}\nSELECT 1\n",
        notebooks::MARKER
    );
    for _ in 0..3 {
        notebooks::import_text(c.conn(), &analyst(), &text).unwrap();
    }
    let n = names(&c);
    assert_eq!(n.len(), 4);
    assert!(n.iter().all(|x| x.chars().count() <= 500));
    assert!(n.iter().any(|x| x.ends_with(" (3)")));
}

#[test]
fn an_ip_merely_in_a_case_range_is_not_a_hit() {
    let (_d, c) = case();
    c.conn()
        .execute_batch(
            "INSERT INTO events (source_table, record_key, source, category, ip, ip_prefix) VALUES
             ('ual_events', 'k1', 'ual', 'other', '203.0.113.7', '203.0.113.0/24'),
             ('ual_events', 'k2', 'ual', 'other', '2001:db8:abcd::1', '2001:db8:abcd::/48');",
        )
        .unwrap();
    let q = |id: &str, sql: &str| (id.to_string(), sql.to_string());
    let hits = notebooks::case_values_in(
        c.conn(),
        &[
            q("v4", "SELECT 1 WHERE ip = '203.0.113.99'"),
            q("v6", "SELECT 1 WHERE ip = '2001:db8:abcd::99'"),
            q("cidr", "SELECT 1 WHERE ip_prefix = '203.0.113.0/24'"),
            q("v6p", "SELECT 1 WHERE ip LIKE '2001:db8:abcd:%'"),
            q("exact6", "SELECT 1 WHERE ip = '2001:db8:abcd::1'"),
        ],
    )
    .unwrap();
    let ids: Vec<&str> = hits.iter().map(|h| h.query_id.as_str()).collect();
    assert_eq!(ids, ["cidr", "v6p", "exact6"], "{hits:?}");
}

#[test]
fn a_new_notebook_with_a_refused_query_is_not_created() {
    let (_d, c) = case();
    let before = audit::log(c.conn(), None).unwrap().len();
    let big = "x".repeat(65_537);
    assert!(notebooks::create_notebook_with_query(c.conn(), &analyst(), "Mine", &big).is_err());
    assert_eq!(names(&c), ["Built-in"]);
    assert_eq!(audit::log(c.conn(), None).unwrap().len(), before);
    let (nb, q, _) =
        notebooks::create_notebook_with_query(c.conn(), &analyst(), "Mine", "SELECT 1").unwrap();
    assert_eq!(
        notebooks::find_query(c.conn(), &nb, &q).unwrap().sql,
        "SELECT 1"
    );
    // An existing name is refused, not added to.
    let m = err(notebooks::create_notebook_with_query(
        c.conn(),
        &analyst(),
        "mine",
        "SELECT 2",
    ));
    assert!(m.contains("already exists"), "{m}");
}

#[test]
fn the_builtin_id_is_reserved_as_a_name() {
    let (_d, c) = case();
    let a = analyst();
    for name in ["builtin", "BuiltIn", " builtin "] {
        let m = err(notebooks::create_notebook(c.conn(), &a, name));
        assert!(m.contains("is reserved"), "{name}: {m}");
    }
    let (nb, _) = notebooks::create_notebook(c.conn(), &a, "Triage").unwrap();
    let m = err(notebooks::rename_notebook(c.conn(), &a, &nb, "BUILTIN"));
    assert!(m.contains("is reserved"), "{m}");
    // A name means one notebook: any spelling of builtin is the built-in one.
    let (id, _, _) = notebooks::notebook_queries(c.conn(), "BUILTIN").unwrap();
    assert_eq!(id, BUILTIN_ID);
    // A shared file named builtin imports as a copy, as one named Built-in does.
    let text = format!(
        "-- sparrow notebook: builtin\n{}\nSELECT 1\n",
        notebooks::MARKER
    );
    let (id, _) = notebooks::import_text(c.conn(), &a, &text).unwrap();
    assert_eq!(
        notebooks::notebook_queries(c.conn(), &id).unwrap().1,
        "builtin (copy)"
    );
}
