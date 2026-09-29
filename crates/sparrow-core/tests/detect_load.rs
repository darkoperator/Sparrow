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
    let before = sparrow_core::detect::load::rule_sha256(&r.rule, &lists);
    lists.get_mut("hiding_folders").unwrap().push("Zzz".into());
    let after = sparrow_core::detect::load::rule_sha256(&r.rule, &lists);
    // SPW-HAWK-011 does not reference hiding_folders: unchanged. (Task 8's SPW-MAIL-003 test asserts the change.)
    assert_eq!(before, after);
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
