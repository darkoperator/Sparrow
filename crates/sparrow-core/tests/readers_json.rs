use serde_json::json;
use sparrow_core::readers::json_scan::*;
use sparrow_core::readers::text::LineIndex;

fn slice<'a>(text: &'a str, r: &JsonRecord) -> &'a str {
    &text[r.span.start..r.span.end]
}

#[test]
fn pretty_array_yields_one_record_per_element_with_exact_spans() {
    let text = "[\n    {\n        \"Id\": \"a\"\n    },\n    {\n        \"Id\": \"b\"\n    }\n]\n";
    let scan = scan_json(text);
    assert_eq!(scan.shape, JsonShape::Array);
    assert!(scan.errors.is_empty());
    assert_eq!(scan.records.len(), 2);
    assert_eq!(scan.records[0].ordinal, 0);
    assert_eq!(scan.records[1].value, json!({"Id": "b"}));
    let reparsed: serde_json::Value = serde_json::from_str(slice(text, &scan.records[1])).unwrap();
    assert_eq!(reparsed, scan.records[1].value);
    let idx = LineIndex::new(text);
    assert_eq!(idx.line_of(scan.records[1].span.start), 5);
    assert_eq!(idx.line_of(scan.records[1].span.end - 1), 7);
}

#[test]
fn bare_object_is_single_record() {
    let scan = scan_json("{\"a\": 1}");
    assert_eq!(scan.shape, JsonShape::SingleObject);
    assert_eq!(scan.records.len(), 1);
    assert_eq!(scan.records[0].value, json!({"a": 1}));
}

#[test]
fn concatenated_arrays_are_flattened_in_order() {
    let scan = scan_json("[{\"a\":1}]\r\n[{\"a\":2},{\"a\":3}]");
    assert_eq!(scan.shape, JsonShape::Concatenated);
    let values: Vec<_> = scan
        .records
        .iter()
        .map(|r| r.value["a"].as_i64().unwrap())
        .collect();
    assert_eq!(values, vec![1, 2, 3]);
    let ordinals: Vec<_> = scan.records.iter().map(|r| r.ordinal).collect();
    assert_eq!(ordinals, vec![0, 1, 2]);
}

#[test]
fn concatenated_bare_objects_like_jsonl() {
    let scan = scan_json("{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n");
    assert_eq!(scan.shape, JsonShape::Concatenated);
    assert_eq!(scan.records.len(), 3);
}

#[test]
fn empty_and_whitespace_only_input_is_empty() {
    for text in ["", "  \r\n\t "] {
        let scan = scan_json(text);
        assert_eq!(scan.shape, JsonShape::Empty);
        assert!(scan.records.is_empty());
        assert!(scan.errors.is_empty());
    }
}

#[test]
fn empty_array_has_no_records() {
    let scan = scan_json("[]");
    assert_eq!(scan.shape, JsonShape::Array);
    assert!(scan.records.is_empty());
    assert!(scan.errors.is_empty());
}

#[test]
fn truncated_array_keeps_prior_records() {
    let text = "[{\"a\":1},{\"b\":";
    let scan = scan_json(text);
    assert_eq!(scan.records.len(), 1);
    assert_eq!(scan.errors.len(), 1);
    assert_eq!(scan.errors[0].ordinal, 1);
    assert!(
        scan.errors[0].message.contains("end of input"),
        "{}",
        scan.errors[0].message
    );
    assert_eq!(scan.errors[0].span.end, text.len());
}

#[test]
fn invalid_element_is_reported_and_scanning_continues() {
    let scan = scan_json("[{\"a\":1},{\"a\":tru},{\"a\":3}]");
    let ordinals: Vec<_> = scan.records.iter().map(|r| r.ordinal).collect();
    assert_eq!(ordinals, vec![0, 2]);
    assert_eq!(scan.errors.len(), 1);
    assert_eq!(scan.errors[0].ordinal, 1);
}

#[test]
fn brackets_and_escaped_quotes_inside_strings_do_not_confuse_scanner() {
    let scan = scan_json(r#"[{"s":"a]b\"}{["},{"t":[1,{"u":"}"}]}]"#);
    assert!(scan.errors.is_empty(), "{:?}", scan.errors);
    assert_eq!(scan.records.len(), 2);
    assert_eq!(scan.records[0].value["s"], json!("a]b\"}{["));
}

#[test]
fn stray_closing_bracket_does_not_loop_forever() {
    let scan = scan_json("{\"a\":1} ] {\"a\":2}");
    assert_eq!(scan.records.len(), 2);
    assert_eq!(scan.errors.len(), 1);
}
