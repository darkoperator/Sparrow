use sparrow_core::data::DataDirs;
use sparrow_core::detect::load::load_rules;

#[test]
fn builtin_rules_and_lists_load() {
    let set = load_rules(&DataDirs::default()).unwrap();
    assert!(set.rules.iter().any(|r| r.rule.id == "SPW-HAWK-011"));
    for l in [
        "finance_keywords",
        "hiding_folders",
        "risky_scopes",
        "suspicious_user_agents",
        "hosting_asns",
    ] {
        assert!(set.lists.contains_key(l), "{l}");
    }
    let ids: Vec<_> = set.rules.iter().map(|r| r.rule.id.clone()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
}

#[test]
fn a_custom_rule_replaces_the_builtin_with_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("mail")).unwrap();
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rules/hawk/SPW-HAWK-011.yaml"
    ))
    .unwrap()
    .replace("version: 1", "version: 9");
    std::fs::write(dir.path().join("mail/SPW-HAWK-011.yaml"), text).unwrap();
    let dirs = DataDirs {
        rules: vec![dir.path().to_path_buf()],
        ..DataDirs::default()
    };
    let set = load_rules(&dirs).unwrap();
    let r = set
        .rules
        .iter()
        .find(|r| r.rule.id == "SPW-HAWK-011")
        .unwrap();
    assert_eq!(r.rule.version, 9);
    assert!(
        set.warnings
            .iter()
            .any(|w| w.contains("replaces the built-in"))
    );
}

#[test]
fn editing_a_referenced_list_changes_the_rule_hash() {
    // A rule referencing @list:hiding_folders changes sha when the list changes.
    let set = load_rules(&DataDirs::default()).unwrap();
    let r = set
        .rules
        .iter()
        .find(|r| r.rule.id == "SPW-HAWK-011")
        .unwrap();
    let mut lists = set.lists.clone();
    let meta = set.list_meta.clone();
    let before = sparrow_core::detect::load::rule_sha256(&r.rule, &lists, &meta);
    lists.get_mut("hiding_folders").unwrap().push("Zzz".into());
    let after = sparrow_core::detect::load::rule_sha256(&r.rule, &lists, &meta);
    // SPW-HAWK-011 does not reference hiding_folders: unchanged. (Task 8's SPW-MAIL-003 test asserts the change.)
    assert_eq!(before, after);
}

#[test]
fn editing_hiding_folders_changes_the_rule_hash() {
    // SPW-MAIL-003 references @list:hiding_folders (and finance_keywords), so editing either list
    // is a rule change: the hash moves. A rule that does not reference the list is unaffected.
    let set = load_rules(&DataDirs::default()).unwrap();
    let mail003 = set
        .rules
        .iter()
        .find(|r| r.rule.id == "SPW-MAIL-003")
        .expect("SPW-MAIL-003 is built in");
    let hash = |lists: &std::collections::BTreeMap<String, Vec<String>>| {
        sparrow_core::detect::load::rule_sha256(&mail003.rule, lists, &set.list_meta)
    };
    assert_eq!(hash(&set.lists), mail003.sha256);

    let mut edited = set.lists.clone();
    edited.get_mut("hiding_folders").unwrap().push("Zzz".into());
    assert_ne!(hash(&set.lists), hash(&edited), "hiding_folders edit");

    let mut edited = set.lists.clone();
    edited
        .get_mut("finance_keywords")
        .unwrap()
        .push("zzz".into());
    assert_ne!(hash(&set.lists), hash(&edited), "finance_keywords edit");

    // SPW-HAWK-003 references no list.
    let hawk003 = set
        .rules
        .iter()
        .find(|r| r.rule.id == "SPW-HAWK-003")
        .expect("SPW-HAWK-003 is built in");
    let mut edited = set.lists.clone();
    edited.get_mut("hiding_folders").unwrap().push("Zzz".into());
    assert_eq!(
        hawk003.sha256,
        sparrow_core::detect::load::rule_sha256(&hawk003.rule, &edited, &set.list_meta)
    );
}

#[test]
fn a_list_named_inside_sql_text_is_part_of_the_rule_hash() {
    let text = "id: SPW-T-001\ntitle: t\nversion: 1\nstatus: experimental\nseverity: low\n\
                analyst_guidance: g\nsql: \"SELECT 1 FROM ual_events u WHERE u.user_agent IN (SELECT unnest(@list:hiding_folders))\"\n\
                tests:\n  - {name: a, records: [], expect_hits: 1}\n  - {name: b, records: [], expect_hits: 0}\n";
    let rule: sparrow_core::detect::rule::Rule = serde_norway::from_str(text).unwrap();
    let set = load_rules(&DataDirs::default()).unwrap();
    let hash = |lists: &std::collections::BTreeMap<String, Vec<String>>| {
        sparrow_core::detect::load::rule_sha256(&rule, lists, &set.list_meta)
    };
    let mut edited = set.lists.clone();
    edited.get_mut("hiding_folders").unwrap().push("Zzz".into());
    assert_ne!(hash(&set.lists), hash(&edited));
    let mut other = set.lists.clone();
    other
        .get_mut("finance_keywords")
        .unwrap()
        .push("zzz".into());
    assert_eq!(
        hash(&set.lists),
        hash(&other),
        "an unreferenced list is not part of the hash"
    );
}

#[test]
fn rule_schema_names_every_rule_field() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rules/schema/rule.schema.json"
    ))
    .unwrap();
    let schema: serde_json::Value = serde_json::from_str(&text).unwrap();
    let props = schema["properties"].as_object().unwrap();
    for field in [
        "id",
        "title",
        "version",
        "status",
        "severity",
        "confidence",
        "mitre",
        "tags",
        "requires",
        "requires_evidence",
        "needs_geoip",
        "source",
        "match",
        "sources",
        "sql",
        "group_by",
        "threshold",
        "analyst_guidance",
        "false_positives",
        "references",
        "author",
        "tests",
    ] {
        assert!(props.contains_key(field), "rule.schema.json lacks {field}");
    }
}

fn rule_text(cond: &str) -> String {
    format!(
        "id: SPW-X-1\ntitle: t\nversion: 1\nstatus: stable\nseverity: low\nsource: mailboxes\nmatch:\n{cond}\nanalyst_guidance: g\ntests:\n  - name: n\n    records: []\n    expect_hits: 0\n"
    )
}

fn load_custom(
    files: &[(&str, &str)],
) -> sparrow_core::Result<sparrow_core::detect::load::RuleSet> {
    let dir = tempfile::tempdir().unwrap();
    for (rel, text) in files {
        let p = dir.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
    let dirs = DataDirs {
        rules: vec![dir.path().to_path_buf()],
        ..DataDirs::default()
    };
    load_rules(&dirs)
}

#[test]
fn malformed_conditions_get_precise_errors() {
    let cases = [
        (
            "  upn: {eq: x, neq: y}",
            "SPW-X-1: match.upn: a leaf has exactly one operator, found 2",
        ),
        (
            "  all:\n    - upn: {eq: a}\n    - upn: {eq: a}\n    - parameters.ForwardTo: {eqq: x}",
            "SPW-X-1: match.all[2].parameters.ForwardTo: unknown operator \"eqq\"",
        ),
        (
            "  all: [{upn: {eq: a}}]\n  any: [{upn: {eq: b}}]",
            "SPW-X-1: match: all/any/not cannot be combined with other keys",
        ),
        (
            "  upn: {eq: a}\n  name: {eq: b}",
            "SPW-X-1: match: a leaf has exactly one field, found 2",
        ),
        (
            "  not:\n    upn: {}",
            "SPW-X-1: match.not.upn: a leaf has exactly one operator, found 0",
        ),
        (
            "  any:\n    - 5",
            "SPW-X-1: match.any[0]: a condition must be a map",
        ),
    ];
    for (cond, want) in cases {
        let err = load_custom(&[("mail/SPW-X-1.yaml", &rule_text(cond))])
            .unwrap_err()
            .to_string();
        assert!(err.contains(want), "want {want:?} in {err:?}");
    }
}

#[test]
fn flipping_case_sensitive_changes_the_rule_hash() {
    let list = |cs: bool| format!("name: kw\ndescription: d\ncase_sensitive: {cs}\nvalues: [a]\n");
    let rule = rule_text("  upn: {in: \"@list:kw\"}");
    let hash = |cs: bool| {
        let set =
            load_custom(&[("lists/kw.yaml", &list(cs)), ("mail/SPW-X-1.yaml", &rule)]).unwrap();
        set.rules
            .iter()
            .find(|r| r.rule.id == "SPW-X-1")
            .unwrap()
            .sha256
            .clone()
    };
    assert_ne!(hash(false), hash(true));
    assert_eq!(hash(true), hash(true));
}

#[test]
fn schema_leaf_is_one_field_one_operator() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rules/schema/rule.schema.json"
    ))
    .unwrap();
    let schema: serde_json::Value = serde_json::from_str(&text).unwrap();
    let leaf = &schema["$defs"]["cond"]["oneOf"][3];
    assert_eq!(leaf["minProperties"], 1);
    assert_eq!(leaf["maxProperties"], 1);
    assert_eq!(
        leaf["additionalProperties"]["$ref"], "#/$defs/op",
        "the operator schema applies to the field's value map"
    );
    let ops = schema["$defs"]["op"]["propertyNames"]["enum"]
        .as_array()
        .unwrap();
    for op in ["eq", "exists", "eq_field", "neq_field", "contains_any"] {
        assert!(ops.iter().any(|o| o == op), "{op}");
    }
    // Every built-in leaf has that shape.
    let set = load_rules(&DataDirs::default()).unwrap();
    for r in &set.rules {
        let v = serde_json::to_value(&r.rule).unwrap();
        fn walk(v: &serde_json::Value, id: &str) {
            if let Some(o) = v.as_object() {
                for (k, x) in o {
                    if ["match", "not"].contains(&k.as_str()) {
                        walk(x, id);
                    }
                    if ["all", "any", "sources"].contains(&k.as_str()) {
                        x.as_array().unwrap().iter().for_each(|c| walk(c, id));
                    }
                }
                let keys: Vec<_> = o.keys().map(String::as_str).collect();
                if !["all", "any", "not", "source", "sources", "match"]
                    .iter()
                    .any(|k| keys.contains(k))
                    && v.get("id").is_none()
                {
                    assert_eq!(o.len(), 1, "{id}: leaf with several fields");
                    let ops = o.values().next().unwrap().as_object().unwrap();
                    assert_eq!(ops.len(), 1, "{id}: leaf with several operators");
                }
            }
        }
        walk(&v, &r.rule.id);
    }
}

#[test]
fn rule_discovery_is_scoped() {
    let set = load_rules(&DataDirs::default()).unwrap();
    for r in &set.rules {
        let dir = r
            .path
            .trim_start_matches("builtin:")
            .split('/')
            .next()
            .unwrap();
        assert!(
            ["mail", "identity", "apps", "files", "config", "hawk"].contains(&dir),
            "{}",
            r.path
        );
    }
    let rule = rule_text("  upn: {eq: a}").replace("SPW-X-1", "SPW-X-2");
    let bogus = "not: a rule";
    let set = load_custom(&[
        ("schema/SPW-DRAFT.yaml", bogus),
        (
            "lists/SPW-LIST.yaml",
            "name: l\ndescription: d\nvalues: [a]\n",
        ),
        ("deep/er/SPW-X-2.yaml", &rule),
    ])
    .unwrap();
    assert!(set.rules.iter().any(|r| r.rule.id == "SPW-X-2"));
}
